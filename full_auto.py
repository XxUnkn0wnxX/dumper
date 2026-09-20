#!/usr/bin/env python3
"""Experimental guided capture using two owned background processes."""

import argparse
import hashlib
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import traceback
import uuid

from Helpers.AutoSession import MAX_ANDROID_API, MIN_ANDROID_API, marker_path, read_events
from Helpers.AutoProcesses import ProcessError, launch_process
from Helpers.AutoLogging import controller_logging, run_logged_subprocess
from Helpers.Browser import CHROME_PACKAGE
from Helpers.CLI import defer_interrupts, ignore_interrupts, prepare_terminal
from tools import setup_frida


ROOT = Path(__file__).resolve().parent
FINISH_DELAY = 3
POLL_INTERVAL = 0.25
PROBE_INTERVAL = 2
MAX_OUTPUT_FILE_BYTES = 16 * 1024 * 1024


class AutoError(RuntimeError):
    """A prerequisite or an owned child failed; manual operation remains available."""


# -----------------------------------------------------------------------------
# DEVICE AND RESULT CHECKS
# API coverage is a conservative outer limit. The dumper itself must still
# recognize the library's automatic signature before it reports hooks_ready.
# -----------------------------------------------------------------------------
def supported_target(adb, requested):
    device = setup_frida.select_device(setup_frida.list_adb_devices(adb), requested)
    api, abi, _architecture = setup_frida.validate_target(adb, device.serial, 'auto')
    if not MIN_ANDROID_API <= api <= MAX_ANDROID_API:
        raise AutoError(
            f'Full auto supports API {MIN_ANDROID_API}–{MAX_ANDROID_API}; this device reports API {api}. '
            'Use dump_keys.py manually with its advanced --cdm-version/--function-name options. '
            'See docs/dumper.md.'
        )
    if setup_frida.shell_property(adb, device.serial, 'sys.boot_completed') != '1':
        raise AutoError('Android has not finished booting. Wait for its home screen, then retry.')
    return device.serial, api, abi


def frida_responds(python, serial):
    """Use a fresh interpreter after setup may have changed the host package."""
    script = (
        'import frida, sys; '
        'device = frida.get_device_manager().get_device(sys.argv[1], timeout=1); '
        'parameters = device.query_system_parameters(); '
        'sys.exit(0 if device.type == "usb" and '
        'parameters.get("os", {}).get("id") == "android" else 1)'
    )
    try:
        result = run_logged_subprocess(
            [str(python), '-I', '-c', script, serial],
            stdin=subprocess.DEVNULL, capture_output=True,
            timeout=5, check=False,
        )
    except subprocess.TimeoutExpired:
        return False
    return result.returncode == 0


def verify_pair(event, serial, api):
    """Accept only the emitting child's completed pair, never a directory scan.

    The dumper verifies its two closed files before publishing this event. Read
    them again with a size bound and compare the announced digests before any
    shutdown is scheduled. Symlinks cannot redirect success to another folder.
    """
    if event.get('device_id') != serial or event.get('android_api') != str(api):
        raise AutoError('Saved-pair status does not match the selected Android device/API.')
    relative = event.get('path')
    if not isinstance(relative, str):
        raise AutoError('Saved-pair status has no output path.')
    directory = Path(relative)
    if directory.is_absolute() or '..' in directory.parts or not directory.parts or directory.parts[0] != 'key_dumps':
        raise AutoError('Saved-pair output is outside key_dumps/.')
    current = ROOT
    for component in directory.parts:
        current = current / component
        if current.is_symlink() or not current.is_dir():
            raise AutoError('Saved-pair directory is missing or contains a symbolic link.')
    for name, field in (('client_id.bin', 'client_sha256'), ('private_key.pem', 'key_sha256')):
        expected = event.get(field, '')
        if not isinstance(expected, str) or re.fullmatch(r'[0-9a-f]{64}', expected) is None:
            raise AutoError('Saved-pair status contains an invalid file digest.')
        target = current / name
        if target.is_symlink():
            raise AutoError(f'Saved-pair file {name} is a symbolic link.')
        descriptor = os.open(target, os.O_RDONLY | getattr(os, 'O_BINARY', 0) | getattr(os, 'O_NOFOLLOW', 0))
        with os.fdopen(descriptor, 'rb') as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= MAX_OUTPUT_FILE_BYTES:
                raise AutoError(f'Saved-pair file {name} is empty, oversized, or not regular.')
            content = handle.read(MAX_OUTPUT_FILE_BYTES + 1)
        if len(content) != info.st_size or hashlib.sha256(content).hexdigest() != expected:
            raise AutoError(f'Saved-pair file {name} is incomplete or changed after the dumper verified it.')
    return directory.as_posix()


# -----------------------------------------------------------------------------
# OWNED REMOTE PROCESS CLEANUP
# An unpredictable marker names just our launch. PID plus /proc start time is
# checked again before each signal; no name-wide kill or /proc scan is used.
# -----------------------------------------------------------------------------
def remote_ready_command(marker):
    quoted = shlex.quote(marker)
    return setup_frida.foreground_process_identity_command() + '\n' + rf'''
test -f {quoted} && ! test -L {quoted} || exit 1
IFS=' ' read -r frida_pid frida_start frida_extra < {quoted} || exit 1
case "$frida_pid" in ''|*[!0-9]*) exit 1 ;; esac
case "$frida_start" in ''|*[!0-9]*) exit 1 ;; esac
test "$frida_pid" -gt 1 && test -z "$frida_extra" || exit 1
frida_read_identity
test "$frida_current_start" = "$frida_start" || exit 1
frida_target=$(readlink "/proc/$frida_pid/exe" 2>/dev/null) || exit 1
test "$frida_target" = /data/local/tmp/frida-server
'''


def remote_cleanup_command(marker):
    quoted = shlex.quote(marker)
    return setup_frida.foreground_process_identity_command() + '\n' + rf'''
if ! test -e {quoted}; then exit 0; fi
if test -L {quoted}; then exit 2; fi
IFS=' ' read -r frida_pid frida_start frida_extra < {quoted} || exit 2
case "$frida_pid" in ''|*[!0-9]*) exit 2 ;; esac
case "$frida_start" in ''|*[!0-9]*) exit 2 ;; esac
test "$frida_pid" -gt 1 && test -z "$frida_extra" || exit 2
frida_owned() {{
    frida_read_identity
    test "$frida_current_start" = "$frida_start" || return 1
    frida_target=$(readlink "/proc/$frida_pid/exe" 2>/dev/null) || return 1
    case "$frida_target" in /data/local/tmp/frida-server|'/data/local/tmp/frida-server (deleted)') return 0 ;; esac
    return 1
}}
frida_read_identity
# A just-forked child can still be exec'ing the server. Preserve its record
# for the next cleanup attempt rather than forgetting a still-owned process.
if test "$frida_current_start" = "$frida_start" && ! frida_owned; then exit 3; fi
if frida_owned; then
    kill -INT "$frida_pid" 2>/dev/null
    frida_remaining=5
    while frida_owned && test "$frida_remaining" -gt 0; do
        sleep 1
        frida_remaining=$((frida_remaining - 1))
    done
    if frida_owned; then kill -KILL "$frida_pid" 2>/dev/null; fi
    frida_remaining=3
    while frida_owned && test "$frida_remaining" -gt 0; do
        sleep 1
        frida_remaining=$((frida_remaining - 1))
    done
    if frida_owned; then exit 3; fi
fi
rm -f {quoted}
'''


class AutoRun:
    """One controller invocation and the resources it alone is allowed to close."""

    def __init__(self, python, adb, serial, api, *, version=None, startup_timeout=600, initialize=False):
        self.python = Path(python)
        self.adb = adb
        self.serial = serial
        self.api = api
        self.version = version
        self.startup_timeout = startup_timeout
        self.initialize = initialize
        self.token = uuid.uuid4().hex
        self.directory = None
        self.log_directory = None
        self.processes = {}
        self.launch = None
        self.cleanup_ok = True

    def events(self, role):
        return read_events(self.directory, self.token, role)

    def remember_launch(self):
        for event in self.events('frida'):
            if event.get('event') != 'frida_launch':
                continue
            if (event.get('device_id') != self.serial or
                    event.get('root_mode') not in ('direct', 'su-c', 'su-0') or
                    event.get('marker') != marker_path(self.token)):
                raise AutoError('Frida launch status does not match this automatic session.')
            self.launch = event

    def start_process(self, role, arguments):
        environment = {
            'DUMPER_AUTO_DIRECTORY': str(self.directory),
            'DUMPER_AUTO_TOKEN': self.token,
            'DUMPER_AUTO_ROLE': role,
            'DUMPER_AUTO_ADB': self.adb or '',
            'PYTHONUNBUFFERED': '1',
        }
        # Remember ownership before delivering a Ctrl+C received during launch.
        with defer_interrupts():
            process = launch_process(
                role, [str(self.python), *arguments], ROOT, self.directory, environment,
                log_path=self.log_directory / f'{role}.log',
            )
            self.processes[role] = process
        print(f'{role.capitalize()} output: {(self.log_directory / f"{role}.log").relative_to(ROOT)}', flush=True)

    def check_processes(self):
        for role, process in self.processes.items():
            status = process.poll()
            if status is not None:
                detail = process.error or f'exit status {status}'
                raise AutoError(
                    f'The {role} process stopped before capture completed ({detail}). '
                    'Run the individual scripts for diagnostics; see docs/dumper.md.'
                )

    def prepare_environment(self):
        print('Checking the Python environment in the background...', flush=True)
        self.start_process('init', ['-m', 'Helpers.AutoInit'])
        deadline = time.monotonic() + self.startup_timeout
        process = self.processes['init']
        while process.poll() is None:
            if time.monotonic() >= deadline:
                raise AutoError('Initialization timed out. See logs/init.log; try python init.py manually.')
            time.sleep(POLL_INTERVAL)
        if process.poll() != 0:
            raise AutoError('Environment initialization failed. See logs/init.log; try python init.py manually.')
        ready = [event for event in self.events('init') if event.get('event') == 'environment_ready']
        if len(ready) != 1:
            raise AutoError('Initialization did not publish a valid environment. See logs/init.log.')
        for field in ('python', 'adb'):
            value = ready[0].get(field)
            if not isinstance(value, str) or not Path(value).is_absolute() or not Path(value).is_file():
                raise AutoError(f'Initialization returned an invalid {field} executable. See logs/init.log.')
        self.python = Path(ready[0]['python'])
        self.adb = ready[0]['adb']
        if not process.close():
            raise AutoError('Initialization finished, but its background process did not clean up.')
        del self.processes['init']
        self.serial, self.api, abi = supported_target(self.adb, self.serial)
        print(f'Experimental full auto: {self.serial} | API {self.api} | ABI {abi}', flush=True)

    def wait_for_frida(self):
        deadline = time.monotonic() + self.startup_timeout
        next_probe = 0
        while time.monotonic() < deadline:
            self.check_processes()
            self.remember_launch()
            if self.launch and time.monotonic() >= next_probe:
                # A marker proves the setup child launched its own server; a
                # fresh Frida query proves the endpoint actually responds.
                record = setup_frida.run_root(
                    self.adb, self.serial, self.launch['root_mode'],
                    remote_ready_command(marker_path(self.token)), 'Checking this session\'s Frida launch',
                    check=False, timeout=5,
                )
                if record.returncode == 0 and frida_responds(self.python, self.serial):
                    self.check_processes()
                    return
                next_probe = time.monotonic() + PROBE_INTERVAL
            time.sleep(POLL_INTERVAL)
        raise AutoError('Frida did not become ready before --startup-timeout. Try tools/setup_frida.py manually.')

    def wait_for_pair(self):
        hook_deadline = time.monotonic() + self.startup_timeout
        hooked_at = None
        warned = False
        while True:
            events = self.events('dumper')
            for event in events:
                if event.get('event') == 'hooks_ready' and hooked_at is None:
                    if (event.get('device_id') != self.serial or event.get('android_api') != str(self.api)
                            or not isinstance(event.get('hooked_libraries'), int) or event['hooked_libraries'] < 1):
                        raise AutoError('The dumper did not confirm valid automatic hooks on this device.')
                    hooked_at = time.monotonic()
                    print('Automatic hooks ready. Waiting for one complete key pair...', flush=True)
            for event in events:
                if event.get('event') == 'pair_saved' and hooked_at is not None:
                    return verify_pair(event, self.serial, self.api)
            # The dumper owns the 35-second warning and optional single refresh.
            # Mirror its event only; a second controller timer could refresh
            # twice or warn while the dumper is already writing the pair.
            for event in events:
                if event.get('event') == 'no_pair_yet' and hooked_at is not None and not warned:
                    if (event.get('device_id') != self.serial
                            or event.get('android_api') != str(self.api)):
                        raise AutoError('The dumper progress status does not match the selected Android device/API.')
                    refresh_hint = (
                        'The dumper is attempting one Chrome page refresh. '
                        if event.get('browser_refresh_requested') is True else ''
                    )
                    print(
                        'No pair saved yet. ' + refresh_hint
                        + 'Check Android for playback/permission prompts and press Play if needed. '
                        'Still waiting; Ctrl+C cancels. For advanced manual options see docs/dumper.md.',
                        flush=True,
                    )
                    warned = True
            self.check_processes()
            now = time.monotonic()
            if hooked_at is None and now >= hook_deadline:
                raise AutoError('Automatic hooks did not become ready. Try dump_keys.py manually; see docs/dumper.md.')
            time.sleep(POLL_INTERVAL)

    def stop_remote(self):
        if self.launch is None:
            return True
        try:
            result = setup_frida.run_root(
                self.adb, self.serial, self.launch['root_mode'],
                remote_cleanup_command(marker_path(self.token)),
                'Stopping this automatic session\'s Frida server', check=False, timeout=12,
            )
            return result.returncode == 0
        except (setup_frida.SetupError, OSError):
            return False

    def close_chrome(self):
        """Close the test browser on this device after both output files are safe."""
        print(f'Closing Chrome on {self.serial}...', flush=True)
        try:
            setup_frida.adb_command(
                self.adb, self.serial, 'shell', 'am', 'force-stop', CHROME_PACKAGE,
                purpose='Closing Chrome after capture', timeout=10,
            )
        except (setup_frida.SetupError, OSError) as error:
            # Browser shutdown must not skip owned process cleanup or turn a
            # successfully saved pair into a failed capture.
            print(
                f'Warning: could not close Chrome on {self.serial}: {error}. '
                'The saved pair is retained; continuing session cleanup.',
                file=sys.stderr, flush=True,
            )

    def cleanup(self):
        """Stop owned jobs before deleting their status and PID metadata."""
        if self.directory is None:
            return
        with ignore_interrupts():
            print('\nStopping this session\'s background processes and Frida server...', flush=True)
            initializer = self.processes.get('init')
            if initializer is not None:
                self.close_process(initializer)
            dumper = self.processes.get('dumper')
            if dumper is not None:
                self.close_process(dumper)
            try:
                self.remember_launch()
            except (ValueError, OSError, AutoError):
                self.cleanup_ok = False
            # Ask the remote server to stop first on an established session.
            # Repeat after closing the setup worker to cover cancellation while
            # that worker was still transitioning into its ADB handoff.
            if self.launch is not None:
                self.stop_remote()
            frida = self.processes.get('frida')
            if frida is not None:
                self.close_process(frida)
            try:
                self.remember_launch()
                self.cleanup_ok = self.stop_remote() and self.cleanup_ok
            except (ValueError, OSError, AutoError):
                self.cleanup_ok = False
            if self.cleanup_ok:
                try:
                    shutil.rmtree(self.directory)
                except OSError:
                    self.cleanup_ok = False
            if not self.cleanup_ok:
                print(
                    f'Warning: cleanup could not be fully confirmed. Session status retained at '
                    f'{self.directory.relative_to(ROOT)}. Check the device and the owned processes.',
                    file=sys.stderr, flush=True,
                )

    def close_process(self, process):
        try:
            self.cleanup_ok = process.close() and self.cleanup_ok
        except (ProcessError, OSError):
            # A failure stopping one process must not skip the other process or
            # the remote server. Keep evidence and report an incomplete cleanup.
            self.cleanup_ok = False

    def run(self):
        try:
            with defer_interrupts():
                (ROOT / '.tmp').mkdir(exist_ok=True)
                self.directory = Path(tempfile.mkdtemp(prefix='full-auto-', dir=ROOT / '.tmp'))
                self.log_directory = ROOT / 'logs'
                self.log_directory.mkdir(exist_ok=True, mode=0o700)
                print(f'Raw session logs: {self.log_directory.relative_to(ROOT)}', flush=True)
            if self.initialize:
                self.prepare_environment()
            setup = ['tools/setup_frida.py', '--non-interactive', '--device-id', self.serial, '--adb', self.adb]
            if self.version:
                setup.extend(['--ver', self.version])
            print('Starting Frida setup in the background...', flush=True)
            self.start_process('frida', setup)
            self.wait_for_frida()
            print('Frida is responding. Starting the dumper in the background...', flush=True)
            self.start_process('dumper', ['dump_keys.py', '--non-interactive', '--cdm-version', 'auto', '--device-id', self.serial])
            output = self.wait_for_pair()
            print(f'Both files are complete and verified: {output}. Finishing in {FINISH_DELAY}s...', flush=True)
            time.sleep(FINISH_DELAY)
            self.close_chrome()
        finally:
            self.cleanup()
        if not self.cleanup_ok:
            raise AutoError(f'The pair was saved at {output}, but cleanup needs attention.')
        return output


def positive_seconds(value):
    try:
        seconds = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError('must be a positive whole number of seconds') from error
    if seconds <= 0:
        raise argparse.ArgumentTypeError('must be a positive whole number of seconds')
    return seconds


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--device-id', '-s', help='ADB serial; required when multiple Android devices are online.')
    parser.add_argument('--adb', help='ADB executable override (otherwise PATH, then bundled ADB).')
    parser.add_argument('--ver', help='Exact Frida version; otherwise the setup helper selects the latest stable release.')
    parser.add_argument('--startup-timeout', type=positive_seconds, default=600, metavar='SECONDS',
                        help='Maximum wait for each startup stage (default: 600); capture itself has no timeout.')
    return parser


def run_controller(args):
    try:
        version = setup_frida.normalize_version(args.ver) if args.ver else None
        output = AutoRun(sys.executable, args.adb, args.device_id, None,
                         version=version, startup_timeout=args.startup_timeout, initialize=True).run()
        print(f'Success: saved client_id.bin and private_key.pem in {output}.', flush=True)
        return 0
    except KeyboardInterrupt:
        print('Cancelled; owned session cleanup has finished.', file=sys.stderr, flush=True)
        return 130
    except (AutoError, ProcessError, setup_frida.SetupError, OSError, ValueError) as error:
        print(f'error: {error}', file=sys.stderr, flush=True)
        return 1
    except Exception:
        # Print before the logging context closes so unexpected bugs retain
        # their complete traceback in both the terminal and controller log.
        traceback.print_exc()
        return 1


def main(argv=None):
    try:
        prepare_terminal()
        args = build_parser().parse_args(argv)
        with controller_logging(ROOT):
            return run_controller(args)
    except KeyboardInterrupt:
        print('\nCancelled.', file=sys.stderr, flush=True)
        return 130
    except OSError as error:
        print(f'error: {error}', file=sys.stderr, flush=True)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
