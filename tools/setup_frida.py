#!/usr/bin/env python3
"""Download, validate, and install a Frida server without starting it.

The tool deliberately limits itself to the server lifecycle: it selects one
online Android target, checks that its ABI and root access are suitable, then
places a verified server at /data/local/tmp/frida-server.  The interactive
shell it opens afterwards is for the operator to start the server manually.
"""

import argparse
from dataclasses import dataclass
import hashlib
from http.client import IncompleteRead
from importlib import metadata
import json
import lzma
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
from typing import Iterable
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import uuid


# ------------------------------------------------------------------------------
# REPOSITORY AND RELEASE CONSTANTS
# Downloads are always staged below the ignored tmp/ directory.  A temporary
# directory removes both the .xz archive and extracted executable after every
# success or failure, keeping release artefacts out of the working tree.
# ------------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = ROOT / 'tmp'
GITHUB_API = 'https://api.github.com/repos/frida/frida/releases'
REMOTE_DIRECTORY = '/data/local/tmp'
REMOTE_SERVER = f'{REMOTE_DIRECTORY}/frida-server'
DOWNLOAD_LIMIT = 256 * 1024 * 1024
UNPACKED_LIMIT = 512 * 1024 * 1024
TIMEOUT = 30
VERSION_PATTERN = re.compile(r'v?(\d+\.\d+\.\d+)\Z')

ARCHITECTURES = {
    'x86_64': {'abis': {'x86_64'}, 'elf_class': 2, 'machine': 62},
    'x86': {'abis': {'x86'}, 'elf_class': 1, 'machine': 3},
    'arm64': {'abis': {'arm64-v8a'}, 'elf_class': 2, 'machine': 183},
    'arm': {'abis': {'armeabi-v7a', 'armeabi'}, 'elf_class': 1, 'machine': 40},
}


class SetupError(RuntimeError):
    """A preflight, release, download, or deployment operation failed."""


@dataclass(frozen=True)
class AndroidDevice:
    """A row reported by ``adb devices -l``."""

    serial: str
    state: str
    details: str


@dataclass(frozen=True)
class Release:
    """The one validated server asset selected from the Frida release API."""

    version: str
    tag: str
    asset_name: str
    url: str
    size: int
    sha256: str | None


# ------------------------------------------------------------------------------
# HOST COMMANDS AND ADB DISCOVERY
# Commands are passed as argument lists, never through a host shell.  This also
# lets a serial number or local path remain a single literal argument.
# ------------------------------------------------------------------------------
def command_output(command: list[str], purpose: str, *, timeout: int = TIMEOUT,
                   capture: bool = True, check: bool = True) -> subprocess.CompletedProcess:
    """Run one local command and turn failures into contextual SetupError values."""
    try:
        result = subprocess.run(
            command,
            text=True,
            capture_output=capture,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SetupError(f'{purpose}: {error}') from error
    if check and result.returncode:
        detail = ((result.stdout or '') + (result.stderr or '')).strip()
        suffix = f': {detail}' if detail else ''
        raise SetupError(f'{purpose} failed (exit {result.returncode}){suffix}')
    return result


def resolve_adb(requested: str | None) -> str:
    """Find an explicit ADB executable, PATH ADB, or adbutils' bundled binary."""
    if requested:
        candidate = Path(requested).expanduser()
        has_path_component = os.sep in requested or (os.altsep is not None and os.altsep in requested)
        if has_path_component:
            if candidate.is_file() and (sys.platform.startswith('win') or os_access_executable(candidate)):
                return str(candidate.resolve())
            raise SetupError(f'--adb path is not an executable file: {requested}')
        resolved = shutil.which(requested)
        if resolved:
            return resolved
        raise SetupError(f'--adb executable was not found on PATH: {requested}')

    resolved = shutil.which('adb')
    if resolved:
        return resolved

    # adbutils is an optional convenience fallback.  It is inspected as package
    # data only; importing it could load unrelated Python dependencies.
    try:
        distribution = metadata.distribution('adbutils')
    except metadata.PackageNotFoundError:
        distribution = None
    if distribution is not None:
        for name in ('adb', 'adb.exe'):
            candidate = Path(distribution.locate_file(f'adbutils/binaries/{name}'))
            if candidate.is_file() and (sys.platform.startswith('win') or os_access_executable(candidate)):
                return str(candidate)

    raise SetupError(
        'Android Debug Bridge (adb) was not found. Install Android SDK Platform-Tools '
        '(Homebrew: brew install --cask android-platform-tools), put adb on PATH, or pass --adb.'
    )


def os_access_executable(path: Path) -> bool:
    """Keep the executable check in one seam so it is easy to test on each host."""
    return path.stat().st_mode & (stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH) != 0


def adb_command(adb: str, serial: str, *arguments: str, purpose: str,
                timeout: int = TIMEOUT, check: bool = True,
                capture: bool = True) -> subprocess.CompletedProcess:
    """Run an ADB command for the already-selected target only."""
    return command_output(
        [adb, '-s', serial, *arguments], purpose, timeout=timeout,
        check=check, capture=capture,
    )


def list_adb_devices(adb: str) -> list[AndroidDevice]:
    """Parse all complete rows from ``adb devices -l`` without guessing states."""
    result = command_output([adb, 'devices', '-l'], 'Listing Android devices')
    devices: list[AndroidDevice] = []
    for line in (result.stdout or '').splitlines():
        line = line.strip()
        if not line or line.startswith('List of devices attached') or line.startswith('*'):
            continue
        fields = line.split(maxsplit=2)
        if len(fields) >= 2:
            devices.append(AndroidDevice(
                serial=fields[0], state=fields[1], details=fields[2] if len(fields) == 3 else '',
            ))
    return devices


def select_device(devices: Iterable[AndroidDevice], requested: str | None) -> AndroidDevice:
    """Require exactly one online target unless the operator named one explicitly."""
    rows = list(devices)
    by_serial = {device.serial: device for device in rows}
    if requested:
        device = by_serial.get(requested)
        if device is None:
            known = ', '.join(f'{row.serial} ({row.state})' for row in rows) or 'none'
            raise SetupError(f'Android device {requested!r} was not reported by adb devices -l (reported: {known}).')
        if device.state != 'device':
            raise SetupError(f'Android device {requested!r} is {device.state!r}; connect and authorize it first.')
        return device

    eligible = [device for device in rows if device.state == 'device']
    if len(eligible) == 1:
        return eligible[0]
    if not eligible:
        known = ', '.join(f'{row.serial} ({row.state})' for row in rows) or 'none'
        raise SetupError(f'No online Android device was found (reported: {known}).')
    choices = ', '.join(device.serial for device in eligible)
    raise SetupError(f'Multiple online Android devices were found ({choices}); choose one with --device-id SERIAL.')


# ------------------------------------------------------------------------------
# TARGET PREFLIGHT AND ROOT ACCESS
# ABI is checked before a network transfer or remote upload.  Root modes retain
# the exact form that succeeded so later install and shell commands use it too.
# ------------------------------------------------------------------------------
def shell_property(adb: str, serial: str, property_name: str) -> str:
    result = adb_command(
        adb, serial, 'shell', 'getprop', property_name,
        purpose=f'Reading {property_name}',
    )
    return (result.stdout or '').strip()


def validate_target(adb: str, serial: str, architecture: str) -> tuple[int, str, str]:
    """Return Android SDK, primary ABI, and the exact resolved server architecture."""
    sdk_text = shell_property(adb, serial, 'ro.build.version.sdk')
    try:
        sdk = int(sdk_text)
    except ValueError as error:
        raise SetupError(f'Android reported an invalid ro.build.version.sdk value: {sdk_text!r}.') from error
    if sdk <= 0:
        raise SetupError(f'Android reported an invalid ro.build.version.sdk value: {sdk_text!r}.')
    abi = shell_property(adb, serial, 'ro.product.cpu.abi')
    detected = next((name for name, info in ARCHITECTURES.items() if abi in info['abis']), None)
    if architecture == 'auto':
        if detected is None:
            raise SetupError(
                f'Android primary ABI is {abi!r}, which is not supported by this tool. '
                'Pass a supported --arch only after confirming the target ABI.'
            )
        return sdk, abi, detected
    expected = ARCHITECTURES[architecture]['abis']
    if abi not in expected:
        guidance = f' Use --arch {detected}.' if detected else ' Choose an architecture that matches this device.'
        raise SetupError(
            f'Android primary ABI is {abi!r}, which does not match --arch {architecture}.{guidance}'
        )
    return sdk, abi, architecture


def root_command(mode: str, command: str) -> list[str]:
    """Wrap a remote script as one Android shell argument, with optional elevation."""
    if mode in ('direct', 'normal'):
        remote = shlex.join(['sh', '-c', command])
    elif mode == 'su-c':
        remote = shlex.join(['su', '-c', command])
    elif mode == 'su-0':
        remote = shlex.join(['su', '0', 'sh', '-c', command])
    else:
        raise SetupError(f'Unknown root mode: {mode}')
    # adb joins shell arguments before the Android shell parses them.  Passing
    # one carefully quoted string retains the command bound to ``-c``.
    return ['shell', remote]


def probe_existing_root(adb: str, serial: str) -> str | None:
    """Return an already-working root mechanism, without restarting adbd."""
    for mode in ('direct', 'su-c', 'su-0'):
        try:
            result = adb_command(
                adb, serial, *root_command(mode, 'id -u'),
                purpose=f'Checking root access ({mode})', check=False,
            )
        except SetupError:
            # Shell-only mode treats a failed optional probe as unavailable;
            # opening a normal adb shell remains useful on non-rooted targets.
            continue
        if result.returncode == 0 and (result.stdout or '').strip() == '0':
            return mode
    return None


def probe_root(adb: str, serial: str) -> str:
    """Require root for installation, falling back to ``adb root`` when supported."""
    existing = probe_existing_root(adb, serial)
    if existing:
        return existing

    print('No root shell was available; requesting adb root (this restarts adbd).', flush=True)
    result = adb_command(adb, serial, 'root', purpose='Requesting adb root', check=False)
    if result.returncode == 0:
        adb_command(adb, serial, 'wait-for-device', purpose='Waiting for adb root', timeout=45)
        result = adb_command(
            adb, serial, *root_command('direct', 'id -u'),
            purpose='Checking adb root', check=False,
        )
        if result.returncode == 0 and (result.stdout or '').strip() == '0':
            return 'direct'
    raise SetupError(
        'Root access is required to install Frida server in /data/local/tmp. '
        'Use a rooted device/emulator with su, or an image that supports adb root.'
    )


def run_root(adb: str, serial: str, mode: str, command: str, purpose: str,
             *, check: bool = True, capture: bool = True) -> subprocess.CompletedProcess:
    """Run one literal remote shell command through the verified root mechanism."""
    return adb_command(
        adb, serial, *root_command(mode, command), purpose=purpose,
        check=check, capture=capture,
    )


# ------------------------------------------------------------------------------
# RELEASE LOOKUP AND LOCAL FILE VALIDATION
# Only the public Frida release API and the expected GitHub asset path are
# accepted.  The downloaded server is checked before it can reach Android.
# ------------------------------------------------------------------------------
def normalize_version(value: str) -> str:
    match = VERSION_PATTERN.fullmatch(value)
    if not match:
        raise SetupError(f'--ver must be an exact X.Y.Z version (received {value!r}).')
    return match.group(1)


def fetch_json(url: str) -> dict:
    request = Request(url, headers={'Accept': 'application/vnd.github+json', 'User-Agent': 'dumper-frida-setup'})
    try:
        with urlopen(request, timeout=TIMEOUT) as response:
            return json.load(response)
    except HTTPError as error:
        if error.code == 403 and error.headers.get('X-RateLimit-Remaining') == '0':
            raise SetupError('GitHub API rate limit reached; retry later after the limit resets.') from error
        raise SetupError(f'GitHub release lookup failed with HTTP {error.code}: {error.reason}') from error
    except (URLError, TimeoutError, json.JSONDecodeError, IncompleteRead, UnicodeDecodeError) as error:
        raise SetupError(f'GitHub release lookup failed: {error}') from error


def release_for(version: str | None, architecture: str) -> Release:
    """Resolve exactly one non-draft, non-prerelease Frida server archive."""
    requested = normalize_version(version) if version else None
    endpoint = f'{GITHUB_API}/tags/{requested}' if requested else f'{GITHUB_API}/latest'
    document = fetch_json(endpoint)
    if not isinstance(document, dict) or document.get('draft') or document.get('prerelease'):
        raise SetupError('GitHub did not return a stable Frida release.')
    tag = document.get('tag_name')
    if not isinstance(tag, str):
        raise SetupError('GitHub release metadata has no usable tag name.')
    resolved_version = normalize_version(tag)
    if requested and resolved_version != requested:
        raise SetupError(f'GitHub returned tag {tag!r}, not requested version {requested}.')

    asset_name = f'frida-server-{resolved_version}-android-{architecture}.xz'
    assets = document.get('assets')
    if not isinstance(assets, list):
        raise SetupError('GitHub release metadata has no asset list.')
    asset = next((item for item in assets if isinstance(item, dict) and item.get('name') == asset_name), None)
    if asset is None:
        raise SetupError(f'Frida {resolved_version} has no Android {architecture} server asset ({asset_name}).')
    url = asset.get('browser_download_url')
    size = asset.get('size')
    if not isinstance(url, str) or not isinstance(size, int) or size <= 0:
        raise SetupError('GitHub asset metadata is incomplete.')
    expected_path = f'/frida/frida/releases/download/{tag}/{asset_name}'
    parsed = urlparse(url)
    if (parsed.scheme != 'https' or parsed.netloc != 'github.com' or parsed.path != expected_path
            or parsed.params or parsed.query or parsed.fragment):
        raise SetupError('GitHub asset URL did not match the expected official Frida release path.')
    digest = asset.get('digest')
    sha256 = None
    if digest is not None:
        if not isinstance(digest, str) or not re.fullmatch(r'sha256:([0-9a-fA-F]{64})', digest):
            raise SetupError('GitHub asset digest is not a valid SHA-256 value.')
        sha256 = digest.split(':', 1)[1].lower()
    return Release(resolved_version, tag, asset_name, url, size, sha256)


def download_asset(release: Release, destination: Path) -> None:
    """Stream a release archive with strict byte and optional SHA-256 checks."""
    if release.size > DOWNLOAD_LIMIT:
        raise SetupError(f'Frida archive is unexpectedly large ({release.size} bytes).')
    request = Request(release.url, headers={'User-Agent': 'dumper-frida-setup'})
    digest = hashlib.sha256()
    written = 0
    try:
        with urlopen(request, timeout=TIMEOUT) as response, destination.open('wb') as output:
            content_length = response.headers.get('Content-Length')
            if content_length and int(content_length) != release.size:
                raise SetupError('Frida download Content-Length did not match GitHub release metadata.')
            while True:
                block = response.read(1024 * 1024)
                if not block:
                    break
                written += len(block)
                if written > DOWNLOAD_LIMIT:
                    raise SetupError('Frida download exceeded the local safety limit.')
                digest.update(block)
                output.write(block)
    except (HTTPError, URLError, OSError, ValueError, IncompleteRead) as error:
        if isinstance(error, SetupError):
            raise
        raise SetupError(f'Downloading Frida server failed: {error}') from error
    if written != release.size:
        raise SetupError(f'Frida download size mismatch: expected {release.size}, received {written} bytes.')
    if release.sha256 and digest.hexdigest() != release.sha256:
        raise SetupError('Frida download SHA-256 did not match GitHub release metadata.')


def unpack_xz(archive: Path, destination: Path) -> None:
    """Extract one bounded XZ stream without executing or trusting its contents."""
    written = 0
    try:
        with lzma.open(archive, 'rb') as compressed, destination.open('wb') as output:
            while True:
                block = compressed.read(1024 * 1024)
                if not block:
                    break
                written += len(block)
                if written > UNPACKED_LIMIT:
                    raise SetupError('Unpacked Frida server exceeded the local safety limit.')
                output.write(block)
    except (OSError, EOFError, lzma.LZMAError) as error:
        if isinstance(error, SetupError):
            raise
        raise SetupError(f'Extracting Frida server failed: {error}') from error
    if not written:
        raise SetupError('Extracted Frida server is empty.')


def validate_elf(server: Path, architecture: str) -> None:
    """Confirm the extracted file is the requested Android ELF architecture."""
    try:
        with server.open('rb') as executable:
            header = executable.read(20)
    except OSError as error:
        raise SetupError(f'Could not read extracted Frida server: {error}') from error
    expected = ARCHITECTURES[architecture]
    if len(header) < 20 or header[:4] != b'\x7fELF':
        raise SetupError('Extracted Frida server is not an ELF executable.')
    elf_class = header[4]
    elf_data = header[5]
    machine = int.from_bytes(header[18:20], byteorder='little')
    if elf_data != 1 or elf_class != expected['elf_class'] or machine != expected['machine']:
        raise SetupError(
            f'Extracted Frida server ELF architecture does not match --arch {architecture}.'
        )


# ------------------------------------------------------------------------------
# ANDROID INSTALLATION AND OPTIONAL OPERATOR SHELL
# The unique staging name means a failed upload cannot damage a previous working
# /data/local/tmp/frida-server.  Only a verified staging binary is moved into
# place, and the script never executes it without the --version argument.
# ------------------------------------------------------------------------------
def remote_quote(*parts: str) -> str:
    """Build one remote sh command while preserving each literal path as an atom."""
    return shlex.join(list(parts))


def install_server(adb: str, serial: str, root_mode: str, server: Path,
                   version: str, *, staging_name: str | None = None) -> None:
    """Push and atomically publish a validated server without launching it."""
    staging = staging_name or f'{REMOTE_DIRECTORY}/.frida-server-{uuid.uuid4().hex}'
    cleanup_needed = False
    try:
        # Mark ownership before the command: an interrupted partial push can
        # still leave this unique remote path behind.
        cleanup_needed = True
        adb_command(adb, serial, 'push', str(server), staging, purpose='Uploading Frida server')
        verify = ' && '.join((
            remote_quote('chmod', '755', staging),
            remote_quote('chown', '0:0', staging),
            remote_quote(staging, '--version'),
        ))
        result = run_root(adb, serial, root_mode, verify, 'Preparing and validating staged Frida server')
        if (result.stdout or '').strip() != version:
            raise SetupError(
                f'Staged Frida server did not report expected version {version!r}; destination was not changed.'
            )
        run_root(
            adb, serial, root_mode,
            f'{remote_quote("test", "!", "-d", REMOTE_SERVER)} && {remote_quote("mv", staging, REMOTE_SERVER)}',
            'Installing Frida server',
        )
        cleanup_needed = False  # mv consumed the owned staging file.
    finally:
        if cleanup_needed:
            # Best effort only: do not touch the existing destination, running
            # server, or any path except the UUID-bearing staging file we made.
            try:
                run_root(
                    adb, serial, root_mode, remote_quote('rm', staging),
                    'Removing failed Frida staging file', check=False,
                )
            except SetupError as error:
                print(f'Warning: could not remove failed Frida staging file {staging}: {error}', file=sys.stderr)


def warn_frida_version(version: str) -> None:
    """Warn when the local Python bindings would reject this server version."""
    try:
        installed = metadata.version('frida')
    except metadata.PackageNotFoundError:
        print(
            f'Warning: Python package frida is not installed. Install frida=={version} '
            'in the environment used by dump_keys.py.',
            file=sys.stderr,
        )
        return
    if installed != version:
        print(
            f'Warning: installed Python frida is {installed}, but server is {version}. '
            f'Install matching bindings, for example: python -m pip install "frida=={version}"',
            file=sys.stderr,
        )


def open_device_shell(adb: str, serial: str, shell_mode: str) -> int:
    """Hand the user a selected-device shell in the install directory without starting Frida."""
    command = f'cd {shlex.quote(REMOTE_DIRECTORY)} && exec /system/bin/sh -i'
    shell_arguments = root_command(shell_mode, command)
    argv = [adb, '-s', serial, shell_arguments[0], '-t', shell_arguments[1]]
    # -t asks adb for a terminal.  Keep stdin/stdout/stderr inherited so this is
    # an actual operator shell rather than a captured subprocess.
    try:
        return subprocess.run(argv, check=False).returncode
    except KeyboardInterrupt:
        print('\nInteractive Android shell closed.', file=sys.stderr)
        return 130
    except OSError as error:
        raise SetupError(f'Opening interactive Android shell failed: {error}') from error


# ------------------------------------------------------------------------------
# COMMAND-LINE FLOW
# Argument parsing and read-only target checks happen before release transfer;
# the TTY check prevents an unattended default run from hanging after deploy.
# ------------------------------------------------------------------------------
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ver', help='Exact Frida release version, for example 16.3.3 (default: latest stable).')
    parser.add_argument('--arch', choices=('auto', *ARCHITECTURES), default='auto', help='Android server architecture (default: auto-detect primary ABI).')
    parser.add_argument('--device-id', '-s', help='ADB serial when more than one Android device is online.')
    parser.add_argument('--adb', help='ADB executable name or absolute/relative path.')
    shell_mode = parser.add_mutually_exclusive_group()
    shell_mode.add_argument('--no-shell', action='store_true', help='Install only; do not open the interactive root shell.')
    shell_mode.add_argument('--shell', action='store_true', help='Open an interactive selected-device shell only; do not install Frida.')
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.shell and (args.ver or args.arch != 'auto'):
        parser.error('--shell cannot be combined with --ver or an explicit --arch; it does not install Frida.')
    if args.ver:
        try:
            args.ver = normalize_version(args.ver)
        except SetupError as error:
            parser.error(str(error))
    if not args.no_shell and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        parser.error('the default interactive shell requires a TTY; use --no-shell for unattended installation.')

    try:
        adb = resolve_adb(args.adb)
        device = select_device(list_adb_devices(adb), args.device_id)
        if args.shell:
            # Shell-only deliberately stops here: no SDK/ABI read, release API,
            # download, staging directory, installation, or adb root fallback.
            root_mode = probe_existing_root(adb, device.serial)
            shell_mode = root_mode or 'normal'
            privilege = f'root via {root_mode}' if root_mode else 'normal adb-shell permissions'
            print(f'Opening /data/local/tmp on {device.serial} with {privilege}.', flush=True)
            return open_device_shell(adb, device.serial, shell_mode)
        sdk, abi, architecture = validate_target(adb, device.serial, args.arch)
        root_mode = probe_root(adb, device.serial)
        print(f'Using {device.serial}: Android SDK {sdk}, ABI {abi}, arch {architecture}, root via {root_mode}.', flush=True)

        release = release_for(args.ver, architecture)
        warn_frida_version(release.version)
        print(f'Downloading Frida {release.version} ({release.asset_name}).', flush=True)
        TMP_ROOT.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='frida-', dir=TMP_ROOT) as temporary:
            staging = Path(temporary)
            archive = staging / release.asset_name
            server = staging / 'frida-server'
            download_asset(release, archive)
            unpack_xz(archive, server)
            validate_elf(server, architecture)
            install_server(adb, device.serial, root_mode, server, release.version)

        print(f'Installed Frida server {release.version} at {REMOTE_SERVER} on {device.serial}.', flush=True)
        print('Start it manually with: ./frida-server', flush=True)
        if args.no_shell:
            return 0
        return open_device_shell(adb, device.serial, root_mode)
    except SetupError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print('\nCancelled.', file=sys.stderr)
        return 130
    except OSError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
