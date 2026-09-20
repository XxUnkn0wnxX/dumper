#!/usr/bin/env python3
"""Create pywidevine WVD files from captured key pairs.

The dumper writes ``client_id.bin`` and ``private_key.pem`` together.  This
tool keeps those source files unchanged and creates a WVDv2 file in a sibling
``WVD`` directory for every complete, valid pair.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field
import os
from pathlib import Path
import stat
import sys
import tempfile
from zlib import crc32


if __package__ in (None, ""):
    # Direct script execution starts with tools/ on sys.path.  The repository
    # helpers live one directory above it.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from Helpers.CLI import defer_interrupts, ignore_interrupts, prepare_terminal
from Helpers.WvdBootstrap import BootstrapError, bootstrap_wvd


ROOT = Path(__file__).resolve().parents[1]
KEY_DUMPS_ROOT = ROOT / "key_dumps"
WVD_DIRECTORY_NAME = "WVD"
CLIENT_ID_NAME = "client_id.bin"
PRIVATE_KEY_NAME = "private_key.pem"

# WVD stores both payloads behind unsigned 16-bit lengths.  The PEM limit is
# intentionally lower than a general-purpose file limit so a bad input cannot
# consume unbounded memory before RSA parsing rejects it.
MAX_WVD_FIELD_SIZE = 0xFFFF
MAX_PRIVATE_KEY_PEM_SIZE = 1024 * 1024
WVD_FIXED_SIZE = 11  # magic/version/type/security/flags plus two uint16 lengths


class GenerationError(RuntimeError):
    """The scan root or its directory structure cannot be used safely."""


class PairError(ValueError):
    """One candidate pair is incomplete, malformed, or unsafe."""


def _error_reason(error: OSError) -> str:
    """Return a concise OS reason without repeating an absolute path."""
    return error.strerror or str(error)


@dataclass
class GenerationSummary:
    """Counts and output paths from one scan."""

    generated: int = 0
    overwritten: int = 0
    skipped: int = 0
    failed: int = 0
    valid_pairs: int = 0
    output_paths: list[str] = field(default_factory=list)

    @property
    def success(self) -> bool:
        return self.valid_pairs > 0 and self.failed == 0 and self.skipped == 0


@dataclass(frozen=True)
class _Dependencies:
    Device: object
    DeviceTypes: object
    RSA: object
    ClientIdentification: object
    SignedDrmCertificate: object
    DrmCertificate: object
    unidecode: object


def _load_dependencies() -> _Dependencies:
    """Import optional WVD dependencies only after environment bootstrap."""
    try:
        from Crypto.PublicKey import RSA
        from pywidevine.device import Device, DeviceTypes
        from pywidevine.license_protocol_pb2 import (
            ClientIdentification,
            DrmCertificate,
            SignedDrmCertificate,
        )
        from unidecode import unidecode
    except ImportError as error:
        raise GenerationError(
            "WVD dependencies are unavailable; run this tool with the separate "
            ".venv-wvd environment (pywidevine 1.9.0)."
        ) from error
    return _Dependencies(
        Device=Device,
        DeviceTypes=DeviceTypes,
        RSA=RSA,
        ClientIdentification=ClientIdentification,
        SignedDrmCertificate=SignedDrmCertificate,
        DrmCertificate=DrmCertificate,
        unidecode=unidecode,
    )


def _lstat(path: Path) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise PairError(f"cannot inspect {path.name}: {_error_reason(error)}") from error


def _read_regular_file(path: Path, maximum: int, label: str) -> bytes:
    """Read one regular file without following a symlink or over-reading it."""
    try:
        mode = os.lstat(path).st_mode
    except OSError as error:
        raise PairError(f"cannot read {label}: {_error_reason(error)}") from error
    if stat.S_ISLNK(mode):
        raise PairError(f"refusing symlinked {label}")
    if not stat.S_ISREG(mode):
        raise PairError(f"{label} is not a regular file")

    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = None
    try:
        descriptor = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise PairError(f"{label} is not a regular file")
        chunks: list[bytes] = []
        total = 0
        while total <= maximum:
            chunk = os.read(descriptor, min(1024 * 1024, maximum + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
        if total > maximum:
            raise PairError(f"{label} exceeds the supported size limit")
        return b"".join(chunks)
    except PairError:
        raise
    except OSError as error:
        raise PairError(f"cannot read {label}: {_error_reason(error)}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)


def _strict_parse(message_type: object, payload: bytes, label: str) -> object:
    message = message_type()
    try:
        message.ParseFromString(payload)
        if message.SerializeToString() != payload:
            raise PairError(f"{label} contains a non-canonical protobuf payload")
    except PairError:
        raise
    except Exception as error:
        raise PairError(f"{label} is malformed") from error
    return message


def _enum_value(message: object, field: str) -> int:
    try:
        return int(getattr(message, field))
    except (AttributeError, TypeError, ValueError) as error:
        raise PairError(f"certificate {field} is invalid") from error


def _validate_pair(client_id_bytes: bytes, private_key_bytes: bytes,
                   dependencies: _Dependencies) -> tuple[bytes, str]:
    """Validate a captured pair and return a validated WVDv2 payload."""
    client_id = _strict_parse(
        dependencies.ClientIdentification, client_id_bytes, "client_id.bin",
    )
    if _enum_value(client_id, "type") != 1:  # DRM_DEVICE_CERTIFICATE
        raise PairError("client ID does not contain a DRM device certificate")
    token = bytes(getattr(client_id, "token", b""))
    if not token:
        raise PairError("client ID has no certificate token")

    signed_certificate = _strict_parse(
        dependencies.SignedDrmCertificate, token, "DRM certificate token",
    )
    certificate_bytes = bytes(getattr(signed_certificate, "drm_certificate", b""))
    if not certificate_bytes:
        raise PairError("DRM certificate token has no certificate")
    certificate = _strict_parse(
        dependencies.DrmCertificate, certificate_bytes, "DRM certificate",
    )
    if _enum_value(certificate, "type") != 2:  # DEVICE
        raise PairError("DRM certificate is not a DEVICE certificate")
    if _enum_value(certificate, "algorithm") != 1:  # RSA
        raise PairError("DRM certificate does not contain an RSA key")
    if int(getattr(certificate, "system_id", 0)) <= 0:
        raise PairError("DRM certificate has no valid system ID")
    certificate_public_key_bytes = bytes(getattr(certificate, "public_key", b""))
    if not certificate_public_key_bytes:
        raise PairError("DRM certificate has no public key")

    try:
        private_key = dependencies.RSA.import_key(private_key_bytes)
        certificate_public_key = dependencies.RSA.import_key(certificate_public_key_bytes)
    except Exception as error:
        raise PairError("private key or certificate public key is not valid RSA") from error
    try:
        has_private = private_key.has_private()
        same_public_key = (
            private_key.n == certificate_public_key.n
            and private_key.e == certificate_public_key.e
        )
        private_key_der = private_key.export_key(format="DER")
    except Exception as error:
        raise PairError("could not inspect the RSA key pair") from error
    if not has_private:
        raise PairError("private_key.pem does not contain a private key")
    if not same_public_key:
        raise PairError("private key does not match the certificate public key")
    if len(private_key_der) > MAX_WVD_FIELD_SIZE:
        raise PairError("private key exceeds the WVD size limit")

    try:
        device = dependencies.Device(
            type_=dependencies.DeviceTypes.ANDROID,
            security_level=3,
            flags=None,
            private_key=private_key_bytes,
            client_id=client_id_bytes,
        )
        payload = bytes(device.dumps())
        if len(payload) > WVD_FIXED_SIZE + MAX_WVD_FIELD_SIZE + MAX_WVD_FIELD_SIZE:
            raise PairError("generated WVD exceeds the supported size limit")
        roundtripped = dependencies.Device.loads(payload)
        if bytes(roundtripped.dumps()) != payload:
            raise PairError("generated WVD failed its round-trip check")
    except PairError:
        raise
    except Exception as error:
        raise PairError("pywidevine rejected the key pair") from error
    client_info: dict[str, str] = {}
    for entry in getattr(device.client_id, "client_info", ()):
        client_info[str(entry.name)] = str(entry.value)
    company_name = client_info.get("company_name", "")
    model_name = client_info.get("model_name", "")
    if not company_name.strip() or not model_name.strip():
        raise PairError("client ID is missing company_name or model_name metadata")

    # Keep pywidevine's create-device naming algorithm in sync so generated
    # files are recognizable beside files made by its CLI.  Metadata is
    # untrusted: after transliteration, reject anything that could become a
    # path component rather than silently writing outside the WVD directory.
    name = f"{company_name} {model_name}"
    if client_info.get("widevine_cdm_version"):
        name += f" {client_info['widevine_cdm_version']}"
    name += f" {crc32(payload).to_bytes(4, 'big').hex()}"
    try:
        name = str(dependencies.unidecode(name.strip().lower().replace(" ", "_")))
    except Exception as error:
        raise PairError("could not normalize device metadata") from error
    if (
        not name
        or "\x00" in name
        or "/" in name
        or "\\" in name
        or name in {".", ".."}
        or Path(name).name != name
        or any(ord(character) < 32 for character in name)
        or any(character in name for character in ':*?"<>|')
        or len(name) > 220
    ):
        raise PairError("device metadata produces an unsafe WVD filename")
    output_name = f"{name}_{device.system_id}_l{device.security_level}.wvd"
    return payload, output_name


def _candidate_direct_file(path: Path, name: str) -> bool:
    """Return whether a candidate has a named direct entry, including symlinks."""
    try:
        os.lstat(path / name)
    except FileNotFoundError:
        return False
    except OSError as error:
        raise PairError(f"cannot inspect {name}: {_error_reason(error)}") from error
    return True


def _iter_candidate_directories(root: Path) -> tuple[list[Path], list[tuple[Path, str]]]:
    """Walk regular directories in deterministic order without symlink traversal."""
    candidates: list[Path] = []
    scan_errors: list[tuple[Path, str]] = []
    pending = [root]
    while pending:
        current = pending.pop()
        try:
            entries = sorted(os.scandir(current), key=lambda entry: entry.name)
        except OSError as error:
            scan_errors.append((current, f"cannot scan directory: {_error_reason(error)}"))
            continue
        child_directories: list[Path] = []
        has_client = False
        has_private_key = False
        for entry in entries:
            entry_path = current / entry.name
            try:
                mode = entry.stat(follow_symlinks=False).st_mode
            except OSError as error:
                scan_errors.append(
                    (entry_path, f"cannot inspect directory entry: {_error_reason(error)}"),
                )
                continue
            if entry.name == CLIENT_ID_NAME:
                has_client = True
            elif entry.name == PRIVATE_KEY_NAME:
                has_private_key = True
            if stat.S_ISLNK(mode):
                # Existing WVD directories are intentionally outside the
                # scan.  Every other symlinked entry is rejected rather than
                # followed into an unrelated tree; named inputs are reported
                # by the candidate validator below.
                if (
                    entry.name not in {CLIENT_ID_NAME, PRIVATE_KEY_NAME}
                    and entry.name.casefold() != WVD_DIRECTORY_NAME.casefold()
                ):
                    scan_errors.append((entry_path, "refusing symlinked entry"))
                continue
            if stat.S_ISDIR(mode) and entry.name.casefold() != WVD_DIRECTORY_NAME.casefold():
                child_directories.append(entry_path)
        if has_client or has_private_key:
            candidates.append(current)
        pending.extend(reversed(child_directories))
    return candidates, scan_errors


def _ensure_output_directory(path: Path) -> None:
    try:
        current = os.lstat(path)
    except FileNotFoundError:
        try:
            path.mkdir(mode=0o700)
        except OSError as error:
            raise PairError(f"cannot create WVD directory: {_error_reason(error)}") from error
        current = _lstat(path)
    except OSError as error:
        raise PairError(f"cannot inspect WVD directory: {_error_reason(error)}") from error
    if stat.S_ISLNK(current.st_mode):
        raise PairError("refusing symlinked WVD directory")
    if not stat.S_ISDIR(current.st_mode):
        raise PairError("WVD output path is not a directory")


def _target_names(output_directory: Path, default_name: str) -> tuple[list[str], bool]:
    try:
        entries = sorted(os.scandir(output_directory), key=lambda entry: entry.name)
    except OSError as error:
        raise PairError(f"cannot inspect WVD directory: {_error_reason(error)}") from error
    names: list[str] = []
    for entry in entries:
        if not entry.name.casefold().endswith(".wvd"):
            continue
        target = output_directory / entry.name
        try:
            mode = entry.stat(follow_symlinks=False).st_mode
        except OSError as error:
            raise PairError(
                f"cannot inspect WVD target {entry.name}: {_error_reason(error)}",
            ) from error
        if stat.S_ISLNK(mode):
            raise PairError(f"refusing symlinked WVD target {entry.name}")
        if not stat.S_ISREG(mode):
            raise PairError(f"WVD target {entry.name} is not a regular file")
        names.append(entry.name)
    return (names, True) if names else ([default_name], False)


def _atomic_write(path: Path, payload: bytes) -> None:
    """Replace one target with a verified, same-directory temporary file."""
    try:
        existing = os.lstat(path)
    except FileNotFoundError:
        existing = None
    except OSError as error:
        raise PairError(
            f"cannot inspect WVD target {path.name}: {_error_reason(error)}",
        ) from error
    if existing is not None:
        if stat.S_ISLNK(existing.st_mode):
            raise PairError(f"refusing symlinked WVD target {path.name}")
        if not stat.S_ISREG(existing.st_mode):
            raise PairError(f"WVD target {path.name} is not a regular file")

    descriptor = None
    temporary_path: Path | None = None
    try:
        # Once mkstemp succeeds, defer Ctrl+C until both ownership variables
        # are assigned so the finally block can always remove our temp file.
        with defer_interrupts():
            descriptor, temporary_name = tempfile.mkstemp(
                prefix=".generate-wvd-", suffix=".tmp", dir=str(path.parent),
            )
            temporary_path = Path(temporary_name)
        mode = stat.S_IRUSR | stat.S_IWUSR
        if hasattr(os, "fchmod"):
            os.fchmod(descriptor, mode)
        else:
            os.chmod(temporary_path, mode)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = None
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        if _read_regular_file(temporary_path, len(payload), "temporary WVD") != payload:
            raise PairError("temporary WVD failed its readback check")
        os.replace(temporary_path, path)
        temporary_path = None
    except PairError:
        raise
    except OSError as error:
        raise PairError(
            f"cannot write WVD target {path.name}: {_error_reason(error)}",
        ) from error
    finally:
        # Protect both descriptor close and temporary unlink.  A second
        # Ctrl+C is delivered after this bounded cleanup, never halfway
        # through it.
        with defer_interrupts():
            if descriptor is not None:
                try:
                    os.close(descriptor)
                except OSError as error:
                    print(
                        "warning: could not close temporary WVD descriptor: "
                        f"{_error_reason(error)}",
                        file=sys.stderr,
                    )
            if temporary_path is not None:
                try:
                    temporary_path.unlink()
                except FileNotFoundError:
                    pass
                except OSError as error:
                    # The original output remains untouched if cleanup itself
                    # fails, but a retained private temporary must be visible.
                    print(
                        "warning: could not remove temporary WVD "
                        f"{temporary_path.name}: {_error_reason(error)}",
                        file=sys.stderr,
                    )


def _display_path(path: Path, root: Path) -> str:
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        relative = path.relative_to(root)
    return relative.as_posix()


def generate(root: Path | None = None) -> GenerationSummary:
    """Generate WVD files under ``root`` and return a batch summary.

    ``root`` is an injectable Python seam for tests.  The command line keeps
    the production root fixed at ``<repository>/key_dumps``.
    """
    root = KEY_DUMPS_ROOT if root is None else Path(root)
    try:
        root_mode = os.lstat(root).st_mode
    except FileNotFoundError:
        return GenerationSummary()
    except OSError as error:
        raise GenerationError(f"cannot inspect key-dumps root: {error}") from error
    if stat.S_ISLNK(root_mode):
        raise GenerationError("refusing symlinked key-dumps root")
    if not stat.S_ISDIR(root_mode):
        raise GenerationError("key-dumps root is not a directory")

    dependencies = _load_dependencies()
    candidates, scan_errors = _iter_candidate_directories(root)
    summary = GenerationSummary(skipped=len(scan_errors))
    for scan_path, scan_reason in scan_errors:
        print(
            f"Skipped: {_display_path(scan_path, root)}: {scan_reason}",
            file=sys.stderr,
        )
    for candidate in candidates:
        try:
            has_client = _candidate_direct_file(candidate, CLIENT_ID_NAME)
            has_private_key = _candidate_direct_file(candidate, PRIVATE_KEY_NAME)
            if not (has_client and has_private_key):
                summary.skipped += 1
                missing = []
                if not has_client:
                    missing.append(CLIENT_ID_NAME)
                if not has_private_key:
                    missing.append(PRIVATE_KEY_NAME)
                print(
                    f"Skipped: {_display_path(candidate, root)}: missing {', '.join(missing)}",
                    file=sys.stderr,
                )
                continue
            client_id_bytes = _read_regular_file(
                candidate / CLIENT_ID_NAME, MAX_WVD_FIELD_SIZE, CLIENT_ID_NAME,
            )
            private_key_bytes = _read_regular_file(
                candidate / PRIVATE_KEY_NAME, MAX_PRIVATE_KEY_PEM_SIZE, PRIVATE_KEY_NAME,
            )
            payload, default_name = _validate_pair(
                client_id_bytes, private_key_bytes, dependencies,
            )
        except PairError as error:
            summary.skipped += 1
            print(
                f"Skipped: {_display_path(candidate, root)}: {error}",
                file=sys.stderr,
            )
            continue

        summary.valid_pairs += 1
        try:
            output_directory = candidate / WVD_DIRECTORY_NAME
            _ensure_output_directory(output_directory)
            names, existed = _target_names(output_directory, default_name)
            for name in names:
                _atomic_write(output_directory / name, payload)
                if existed:
                    summary.overwritten += 1
                else:
                    summary.generated += 1
                output_path = _display_path(output_directory / name, root)
                summary.output_paths.append(output_path)
                action = "Replaced" if existed else "Created"
                print(f"{action}: {output_path}")
        except PairError as error:
            summary.failed += 1
            print(
                f"Failed: {_display_path(candidate, root)}: {error}",
                file=sys.stderr,
            )
        except KeyboardInterrupt:
            raise
        except Exception as error:
            summary.failed += 1
            print(
                f"Failed: {_display_path(candidate, root)}: {error}",
                file=sys.stderr,
            )
    return summary


# Explicit aliases make the Python seam discoverable without adding CLI flags.
generate_wvds = generate


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        description="Create WVDv2 files from captured Widevine key pairs.",
        epilog=(
            "Recursively scans key_dumps/ and writes each valid pair to its "
            "sibling WVD/ directory. Existing .wvd files there are refreshed "
            "in place by filename. The command uses the dedicated .venv-wvd "
            "environment, creates it when needed, and refuses another active "
            "virtual environment."
        ),
    )


def _print_summary(summary: GenerationSummary) -> None:
    if summary.valid_pairs == 0:
        print(
            (
                "No valid key pairs found in key_dumps/; skipped candidates "
                "were incomplete or invalid. Expected folders containing "
                if summary.skipped
                else "No key pairs found in key_dumps/; expected folders containing "
            )
            + "client_id.bin and private_key.pem.",
            file=sys.stderr,
        )
    print(
        "Summary: "
        f"generated={summary.generated}, "
        f"overwritten={summary.overwritten}, "
        f"skipped={summary.skipped}, "
        f"failed={summary.failed}."
    )


def main(argv: list[str] | None = None) -> int:
    """Run the fixed-root CLI; dependency bootstrap follows argument parsing."""
    parser = _parser()
    args = parser.parse_args(argv)
    del args
    try:
        prepare_terminal()
        bootstrap_wvd(Path(__file__), argv)
        summary = generate()
        _print_summary(summary)
        return 0 if summary.success else 1
    except BootstrapError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        with ignore_interrupts():
            print("\nStopped by user.", file=sys.stderr)
        return 130
    except OSError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    except GenerationError as error:
        print(f"error: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
