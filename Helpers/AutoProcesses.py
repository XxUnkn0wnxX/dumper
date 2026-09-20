"""Bounded ownership for full-auto local background processes.

Each object holds the ``Popen`` handle it created.  Metadata is diagnostic only;
it is never used to rediscover or signal a PID later.
"""

from __future__ import annotations

import argparse
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Mapping, Sequence
import uuid
import json
import io

from Helpers.CLI import defer_interrupts, ignore_interrupts


GRACE_SECONDS = 8.0
ESCALATION_SECONDS = 2.0
KILL_REAP_SECONDS = 0.25
_ROLE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,63}\Z")


class ProcessError(RuntimeError):
    """The automatic runner could not retain process ownership."""


def _platform_kind() -> str:
    return "windows" if platform.system() == "Windows" or os.name == "nt" else "posix"


def _atomic_write_json(path: Path, value: Mapping[str, Any]) -> None:
    encoded = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    descriptor = None
    try:
        descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "wb") as handle:
            descriptor = None
            handle.write(encoded)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
    except OSError as error:
        raise ProcessError(f"Could not publish owned-process metadata: {path}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
        try:
            temporary.unlink()
        except OSError:
            pass


def _private_session(session_dir: Path) -> Path:
    candidate = Path(session_dir).expanduser()
    try:
        candidate.mkdir(parents=True, exist_ok=True, mode=0o700)
        result = candidate.resolve(strict=True)
        os.chmod(result, 0o700)
    except OSError as error:
        raise ProcessError(f"Could not prepare process session directory: {candidate}") from error
    if not result.is_dir() or ".tmp" not in result.parts:
        raise ProcessError("Process session directory must be private and below .tmp.")
    if os.name == "posix" and stat.S_IMODE(result.stat().st_mode) & 0o077:
        raise ProcessError(f"Process session directory is not private: {result}")
    return result


def _validated_command(command: Sequence[str]) -> list[str]:
    if not isinstance(command, (list, tuple)) or not command or not command[0]:
        raise ProcessError("Process command must be a non-empty argument list.")
    if any(not isinstance(item, str) or "\x00" in item for item in command):
        raise ProcessError("Process command arguments must be strings without NUL bytes.")
    return list(command)


def _environment(environment: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(environment, Mapping):
        raise ProcessError("Process environment must be a string mapping.")
    merged = os.environ.copy()
    for key, value in environment.items():
        if (not isinstance(key, str) or not key or "=" in key or "\x00" in key
                or not isinstance(value, str) or "\x00" in value):
            raise ProcessError("Process environment contains an invalid key or value.")
        merged[key] = value
    return merged


def _open_log(log_path: Path) -> tuple[Path, io.BufferedWriter]:
    """Open one retained private regular-file log, truncating it for this run."""
    try:
        requested = Path(log_path).expanduser()
        parent = requested.parent.resolve(strict=True)
        path = parent / requested.name
        try:
            existing = os.lstat(path)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ProcessError(f"Process log must be a regular file: {path}")
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
        flags |= getattr(os, "O_NOFOLLOW", 0)
        flags |= getattr(os, "O_BINARY", 0)
        descriptor = os.open(path, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            else:
                os.chmod(path, 0o600)
        except OSError:
            pass
    except (TypeError, OSError) as error:
        raise ProcessError(f"Could not open process log: {log_path}") from error
    try:
        return (path, os.fdopen(descriptor, "wb"))
    except OSError as error:
        os.close(descriptor)
        raise ProcessError(f"Could not open process log: {path}") from error


def _wait(process: subprocess.Popen[Any], timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.05)
    return process.poll() is not None


def _wait_for_no_active_processes(active_count: Any, timeout: float = ESCALATION_SECONDS) -> None:
    """Require a Job Object query to reach zero without assuming CloseHandle is synchronous."""
    deadline = time.monotonic() + timeout
    while active_count() != 0:
        if time.monotonic() >= deadline:
            raise ProcessError("Windows Job Object still has active processes after bounded termination.")
        time.sleep(0.05)


def _send_posix_group(process: subprocess.Popen[Any], signum: int) -> bool:
    """Signal an owned session group only while its held leader still identifies it."""
    try:
        if os.getpgid(process.pid) == process.pid:
            os.killpg(process.pid, signum)
            return True
    except (OSError, ProcessLookupError):
        pass
    return False


def _stop_process(process: subprocess.Popen[Any], kind: str, *, tree_owned: bool = False) -> tuple[bool, str | None]:
    """Stop one held child, returning whether it reaped and any descendant gap."""
    if process.poll() is not None:
        return (True, None)
    gap: str | None = None
    if kind == "windows":
        try:
            process.send_signal(getattr(signal, "CTRL_BREAK_EVENT", signal.SIGINT))
        except OSError:
            if not tree_owned:
                gap = "Could not send Ctrl+Break to the owned Windows process group."
    elif not _send_posix_group(process, signal.SIGINT):
        # The held Popen child itself remains safe to signal, but its former
        # descendants cannot be identified without broad process discovery.
        gap = "Owned POSIX session leader was unavailable; only the held child can be stopped."
        try:
            process.send_signal(signal.SIGINT)
        except OSError:
            pass
    if _wait(process, GRACE_SECONDS):
        return (True, gap)

    if kind == "windows":
        # TerminateProcess/kill act on this held leader only.  A Job Object is
        # required to guarantee descendants; make that gap explicit instead
        # of presenting leader exit as tree cleanup.
        if not tree_owned:
            gap = gap or "Windows forced termination can confirm only the held leader, not descendants."
        try:
            process.terminate()
        except OSError:
            pass
    elif not _send_posix_group(process, signal.SIGTERM):
        try:
            process.terminate()
        except OSError:
            pass
    kill_wait = min(KILL_REAP_SECONDS, ESCALATION_SECONDS)
    if _wait(process, ESCALATION_SECONDS - kill_wait):
        return (True, gap)

    if kind == "windows":
        try:
            process.kill()
        except OSError:
            pass
    elif not _send_posix_group(process, signal.SIGKILL):
        try:
            process.kill()
        except OSError:
            pass
    return (_wait(process, kill_wait), gap)


class _WindowsJob:
    """A kill-on-close Job Object assigned before the gated target can spawn."""

    def __init__(self) -> None:
        if _platform_kind() != "windows":
            raise ProcessError("Windows Job Objects are unavailable on this platform.")
        try:
            import ctypes
            from ctypes import wintypes

            class BasicLimit(ctypes.Structure):
                _fields_ = [
                    ("PerProcessUserTimeLimit", ctypes.c_longlong),
                    ("PerJobUserTimeLimit", ctypes.c_longlong),
                    ("LimitFlags", wintypes.DWORD),
                    ("MinimumWorkingSetSize", ctypes.c_size_t),
                    ("MaximumWorkingSetSize", ctypes.c_size_t),
                    ("ActiveProcessLimit", wintypes.DWORD),
                    ("Affinity", ctypes.c_size_t),
                    ("PriorityClass", wintypes.DWORD),
                    ("SchedulingClass", wintypes.DWORD),
                ]

            class IoCounters(ctypes.Structure):
                _fields_ = [(name, ctypes.c_ulonglong) for name in (
                    "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                    "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
                )]

            class ExtendedLimit(ctypes.Structure):
                _fields_ = [
                    ("BasicLimitInformation", BasicLimit),
                    ("IoInfo", IoCounters),
                    ("ProcessMemoryLimit", ctypes.c_size_t),
                    ("JobMemoryLimit", ctypes.c_size_t),
                    ("PeakProcessMemoryUsed", ctypes.c_size_t),
                    ("PeakJobMemoryUsed", ctypes.c_size_t),
                ]

            class BasicAccounting(ctypes.Structure):
                _fields_ = [
                    ("TotalUserTime", ctypes.c_longlong),
                    ("TotalKernelTime", ctypes.c_longlong),
                    ("ThisPeriodTotalUserTime", ctypes.c_longlong),
                    ("ThisPeriodTotalKernelTime", ctypes.c_longlong),
                    ("TotalPageFaultCount", wintypes.DWORD),
                    ("TotalProcesses", wintypes.DWORD),
                    ("ActiveProcesses", wintypes.DWORD),
                    ("TotalTerminatedProcesses", wintypes.DWORD),
                ]

            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.CreateJobObjectW.argtypes = (wintypes.LPVOID, wintypes.LPCWSTR)
            kernel32.CreateJobObjectW.restype = wintypes.HANDLE
            kernel32.SetInformationJobObject.argtypes = (
                wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
            )
            kernel32.SetInformationJobObject.restype = wintypes.BOOL
            kernel32.OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
            kernel32.OpenProcess.restype = wintypes.HANDLE
            kernel32.AssignProcessToJobObject.argtypes = (wintypes.HANDLE, wintypes.HANDLE)
            kernel32.AssignProcessToJobObject.restype = wintypes.BOOL
            kernel32.QueryInformationJobObject.argtypes = (
                wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                ctypes.POINTER(wintypes.DWORD),
            )
            kernel32.QueryInformationJobObject.restype = wintypes.BOOL
            kernel32.TerminateJobObject.argtypes = (wintypes.HANDLE, wintypes.UINT)
            kernel32.TerminateJobObject.restype = wintypes.BOOL
            kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
            kernel32.CloseHandle.restype = wintypes.BOOL
            handle = kernel32.CreateJobObjectW(None, None)
            if not handle:
                raise OSError(ctypes.get_last_error(), "CreateJobObjectW failed")
            limits = ExtendedLimit()
            limits.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            if not kernel32.SetInformationJobObject(handle, 9, ctypes.byref(limits), ctypes.sizeof(limits)):
                kernel32.CloseHandle(handle)
                raise OSError(ctypes.get_last_error(), "SetInformationJobObject failed")
            self._kernel32 = kernel32
            self._handle = handle
            self._ctypes = ctypes
            self._wintypes = wintypes
            self._BasicAccounting = BasicAccounting
        except (AttributeError, OSError) as error:
            raise ProcessError(f"Could not create Windows kill-on-close Job Object: {error}") from error

    def assign(self, process: subprocess.Popen[Any]) -> None:
        access = 0x0001 | 0x0100 | 0x1000  # TERMINATE | SET_QUOTA | QUERY_LIMITED_INFORMATION
        process_handle = self._kernel32.OpenProcess(access, False, process.pid)
        if not process_handle:
            raise ProcessError("Could not open owned Windows worker for Job assignment.")
        try:
            if not self._kernel32.AssignProcessToJobObject(self._handle, process_handle):
                raise ProcessError("Could not assign owned Windows worker to its Job Object.")
        finally:
            self._kernel32.CloseHandle(process_handle)

    def active_count(self) -> int:
        info = self._BasicAccounting()
        returned = self._wintypes.DWORD()
        if not self._kernel32.QueryInformationJobObject(
                self._handle, 1, self._ctypes.byref(info), self._ctypes.sizeof(info), self._ctypes.byref(returned)):
            raise ProcessError("Could not query active processes in the owned Windows Job Object.")
        return int(info.ActiveProcesses)

    def close(self) -> None:
        handle = self._handle
        if not handle:
            return
        failure: ProcessError | None = None
        try:
            if self.active_count() > 0:
                if not self._kernel32.TerminateJobObject(handle, 1):
                    raise ProcessError("Could not terminate active processes in the owned Windows Job Object.")
                _wait_for_no_active_processes(self.active_count)
        except ProcessError as error:
            failure = error
        finally:
            self._handle = None
            if not self._kernel32.CloseHandle(handle) and failure is None:
                failure = ProcessError("Could not close the owned Windows Job Object.")
        if failure is not None:
            raise failure


class OwnedProcess:
    """One local background child whose ``Popen`` handle remains authoritative."""

    def __init__(self, role: str, process: subprocess.Popen[Any], metadata_path: Path, kind: str,
                 log_path: Path | None, job: _WindowsJob | None = None) -> None:
        self.role = role
        self.process = process
        self.metadata_path = metadata_path
        self.log_path = log_path
        self._kind = kind
        self._job = job
        self._posix_pgid = process.pid if kind == "posix" else None
        self._error: str | None = None

    @property
    def error(self) -> str | None:
        return self._error

    def poll(self) -> int | None:
        return self.process.poll()

    def close(self) -> bool:
        """Boundedly stop this handle's child/group without PID-file lookup."""
        with ignore_interrupts():
            stopped, gap = _stop_process(self.process, self._kind, tree_owned=self._job is not None)
            if self._job is not None:
                try:
                    # KILL_ON_JOB_CLOSE terminates every descendant that the
                    # gated worker spawned, including pip/adb helpers.
                    self._job.close()
                    self._job = None
                except ProcessError as error:
                    gap = str(error)
                stopped = _wait(self.process, KILL_REAP_SECONDS)
            if stopped and self._posix_pgid is not None:
                try:
                    # Probe only: after the leader is reaped this PID could be
                    # reused, so never send another real signal to the group.
                    os.killpg(self._posix_pgid, 0)
                    gap = "Owned POSIX leader exited while its stored process group remains live."
                except ProcessLookupError:
                    pass
                except PermissionError:
                    gap = "Could not verify that the owned POSIX process group is empty."
                except OSError:
                    pass
            if gap:
                self._error = gap
            if not stopped and self._error is None:
                self._error = "Owned process did not exit after bounded shutdown."
            return stopped and gap is None


def _read_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return value if isinstance(value, dict) else None


def _windows_worker_main(manifest_path: str) -> int:
    """Hold a gated Windows Job member until its owner assigns the Job Object."""
    manifest = _read_json(Path(manifest_path))
    if not isinstance(manifest, dict):
        return 125
    try:
        command = _validated_command(manifest["command"])
        cwd = Path(manifest["cwd"]).resolve(strict=True)
        environment = _environment(manifest["environment"])
        start_path = Path(manifest["start_path"])
        token = manifest["token"]
    except (KeyError, TypeError, OSError, ProcessError):
        return 125
    if not isinstance(token, str) or not cwd.is_dir():
        return 125
    stopped = False

    def request_stop(_signum: int, _frame: Any) -> None:
        nonlocal stopped
        stopped = True

    previous: list[tuple[int, Any]] = []
    for candidate in (signal.SIGINT, signal.SIGTERM, getattr(signal, "SIGBREAK", None)):
        if candidate is None:
            continue
        try:
            previous.append((candidate, signal.signal(candidate, request_stop)))
        except (OSError, ValueError):
            pass
    child: subprocess.Popen[Any] | None = None
    try:
        deadline = time.monotonic() + 20.0
        while time.monotonic() < deadline:
            if stopped:
                return 130
            start = _read_json(start_path)
            if start is not None and start.get("token") == token:
                break
            time.sleep(0.05)
        else:
            return 125
        child = subprocess.Popen(command, cwd=cwd, env=environment, stdin=subprocess.DEVNULL)
        while child.poll() is None:
            if stopped:
                # Ctrl+Break was already broadcast to the worker's process
                # group.  Give script cleanup time before its exact handle is
                # escalated; the enclosing Job protects descendants.
                if _wait(child, GRACE_SECONDS):
                    break
                try:
                    child.terminate()
                except OSError:
                    pass
                if not _wait(child, ESCALATION_SECONDS - KILL_REAP_SECONDS):
                    try:
                        child.kill()
                    except OSError:
                        pass
                    _wait(child, KILL_REAP_SECONDS)
                break
            time.sleep(0.05)
        returncode = child.poll()
        return returncode if isinstance(returncode, int) and returncode >= 0 else 130
    finally:
        for candidate, handler in reversed(previous):
            try:
                signal.signal(candidate, handler)
            except (OSError, ValueError):
                pass


def launch_process(
    role: str,
    command: list[str],
    cwd: Path,
    session_dir: Path,
    environment: dict[str, str],
    *,
    log_path: Path | None = None,
) -> OwnedProcess:
    """Start one non-UI local process and retain its exact ``Popen`` handle."""
    if not isinstance(role, str) or not _ROLE.fullmatch(role):
        raise ProcessError("Process role must contain 1-64 letters, digits, dots, underscores, or hyphens.")
    command = _validated_command(command)
    environment = _environment(environment)
    try:
        cwd = Path(cwd).expanduser().resolve(strict=True)
    except OSError as error:
        raise ProcessError(f"Process working directory is unavailable: {cwd}") from error
    if not cwd.is_dir():
        raise ProcessError(f"Process working directory is not a directory: {cwd}")
    session = _private_session(session_dir)
    kind = _platform_kind()
    metadata_path = session / f"{role}.pid.json"
    worker_manifest_path = session / f"{role}.worker.json"
    start_path = session / f"{role}.worker-start.json"
    process: subprocess.Popen[Any] | None = None
    owned: OwnedProcess | None = None
    log_handle: io.BufferedWriter | None = None
    job: _WindowsJob | None = None
    try:
        # A signal may arrive after Popen's side effect.  Defer it until the
        # returned handle is retained, close it, then let the caller unwind.
        with defer_interrupts():
            options: dict[str, Any] = {
                "cwd": cwd, "env": environment, "stdin": subprocess.DEVNULL,
            }
            resolved_log: Path | None = None
            if log_path is not None:
                resolved_log, log_handle = _open_log(log_path)
                options["stdout"] = log_handle
                options["stderr"] = subprocess.STDOUT
            if kind == "windows":
                options["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
            else:
                options["start_new_session"] = True
            launched_command: Sequence[str] = command
            if kind == "windows":
                token = uuid.uuid4().hex
                _atomic_write_json(worker_manifest_path, {
                    "version": 1,
                    "token": token,
                    "command": command,
                    "cwd": str(cwd),
                    "environment": environment,
                    "start_path": str(start_path),
                })
                launched_command = [
                    sys.executable, "-m", "Helpers.AutoProcesses", "--windows-worker", str(worker_manifest_path),
                ]
            try:
                process = subprocess.Popen(launched_command, **options)
            finally:
                if log_handle is not None:
                    log_handle.close()
                    log_handle = None
            if kind == "windows":
                job = _WindowsJob()
                job.assign(process)
                # The Job assignment completed while this worker was still
                # gated, before it could spawn the requested command tree.
                _atomic_write_json(start_path, {"token": token})
            owned = OwnedProcess(role, process, metadata_path, kind, resolved_log, job)
            _atomic_write_json(metadata_path, {
                "version": 1, "role": role, "pid": process.pid, "started_at": time.time(),
            })
    except KeyboardInterrupt:
        if log_handle is not None:
            log_handle.close()
        if owned is not None:
            owned.close()
        elif process is not None:
            _stop_process(process, kind)
            if job is not None:
                job.close()
        raise
    except Exception as error:
        if log_handle is not None:
            log_handle.close()
        if owned is not None:
            owned.close()
        elif process is not None:
            _stop_process(process, kind)
            if job is not None:
                job.close()
        if isinstance(error, ProcessError):
            raise
        raise ProcessError(f"Could not launch {role} process.") from error
    if owned is None:
        raise ProcessError(f"Could not retain ownership of {role} process.")
    return owned


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run a gated full-auto Windows process worker.")
    parser.add_argument("--windows-worker", metavar="MANIFEST")
    namespace = parser.parse_args(argv)
    if not namespace.windows_worker:
        parser.error("--windows-worker is required")
    return _windows_worker_main(namespace.windows_worker)


if __name__ == "__main__":
    raise SystemExit(main())
