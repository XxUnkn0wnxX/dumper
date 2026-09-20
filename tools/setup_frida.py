#!/usr/bin/env python3
"""Install and run Frida server in the foreground on a rooted Android device.

Normal setup validates the selected Android ABI, obtains a verified Frida
archive from the local cache or official GitHub release, then replaces
/data/local/tmp/frida-server and runs it attached to this terminal. ``--shell``
reuses an existing installation; ``--no-shell`` has no follow-up root prompt.
"""

import argparse
from contextlib import contextmanager
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
import time
from typing import Iterable, NoReturn
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import Request, urlopen
import uuid

if __package__ in (None, ''):
    # Direct script execution starts with tools/ on sys.path, including when
    # called from another directory. Shared helpers live in Helpers/.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from Helpers.CLI import defer_interrupts, ignore_interrupts, prepare_terminal
from Helpers.Bootstrap import BootstrapError, bootstrap, running_in_virtual_environment
from Helpers.AutoSession import AutoSessionError, context as auto_context, emit_event, frida_marker
from Helpers.AutoLogging import log_captured_output, run_logged_subprocess


# ------------------------------------------------------------------------------
# REPOSITORY, CACHE, AND RELEASE CONSTANTS
# Extracted executables always live in an ignored temporary directory. Cache
# entries retain only validated official .xz archives plus integrity manifests;
# a temporary cache staging directory prevents partial downloads becoming hits.
# ------------------------------------------------------------------------------
ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = ROOT / '.tmp'
CACHE_ROOT = Path(__file__).resolve().parent / '.cache' / 'frida'
GITHUB_API = 'https://api.github.com/repos/frida/frida/releases'
REMOTE_DIRECTORY = '/data/local/tmp'
REMOTE_SERVER = f'{REMOTE_DIRECTORY}/frida-server'
DOWNLOAD_LIMIT = 256 * 1024 * 1024
UNPACKED_LIMIT = 512 * 1024 * 1024
TIMEOUT = 30
PIP_TIMEOUT = 240
PIP_CHECK_TIMEOUT = 60
STOP_TIMEOUT = 10
STOP_INTERVAL = 0.25
STAGING_CLEANUP_TIMEOUT = 3
FOREGROUND_STOP_TIMEOUT = 5
WINDOWS_CHILD_CLEANUP_TIMEOUT = 5
VERSION_PATTERN = re.compile(r'v?(\d+\.\d+\.\d+)\Z')
PACKAGE_NAME_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*\Z')
PACKAGE_VERSION_PATTERN = re.compile(r'[A-Za-z0-9][A-Za-z0-9.!+_-]*\Z')
PIP_ROUTING_ENVIRONMENT = ('PIP_TARGET', 'PIP_PREFIX', 'PIP_ROOT', 'PIP_USER', 'PIP_PYTHON')
PIP_ROUTING_OPTIONS = frozenset(('target', 'prefix', 'root', 'user', 'python'))
PIP_RESOLVER_ENVIRONMENT = ('PIP_NO_DEPS', 'PIP_USE_DEPRECATED', 'PIP_REQUIREMENT')
PIP_RESOLVER_OPTIONS = frozenset(('no-deps', 'use-deprecated', 'requirement'))

ARCHITECTURES = {
    'x86_64': {'abis': {'x86_64'}, 'elf_class': 2, 'machine': 62},
    'x86': {'abis': {'x86'}, 'elf_class': 1, 'machine': 3},
    'arm64': {'abis': {'arm64-v8a'}, 'elf_class': 2, 'machine': 183},
    'arm': {'abis': {'armeabi-v7a', 'armeabi'}, 'elf_class': 1, 'machine': 40},
}


class SetupError(RuntimeError):
    """A preflight, release, download, or deployment operation failed."""


class CacheError(SetupError):
    """A local Frida archive or its integrity manifest cannot be used."""


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


@dataclass(frozen=True)
class CachedArtifact:
    """A locally verified Frida archive ready for temporary extraction."""

    version: str
    architecture: str
    asset_name: str
    archive: Path


# ------------------------------------------------------------------------------
# HOST COMMANDS AND ADB DISCOVERY
# Commands are passed as argument lists, never through a host shell.  This also
# lets a serial number or local path remain a single literal argument.
# ------------------------------------------------------------------------------
def command_output(command: list[str], purpose: str, *, timeout: int = TIMEOUT,
                   capture: bool = True, check: bool = True) -> subprocess.CompletedProcess:
    """Run one local command and turn failures into contextual SetupError values."""
    try:
        result = run_logged_subprocess(
            command,
            text=True,
            capture_output=capture,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        log_captured_output(error)
        raise SetupError(
            f'{purpose} timed out after {timeout} seconds. '
            'The Android command did not finish; check the device/ADB connection, '
            'wait for a responsive home screen, and retry.'
        ) from error
    except OSError as error:
        raise SetupError(f'{purpose}: {error}') from error
    log_captured_output(result)
    if check and result.returncode:
        detail = ((result.stdout or '') + (result.stderr or '')).strip()
        suffix = f': {detail}' if detail else ''
        raise SetupError(f'{purpose} failed (exit {result.returncode}){suffix}')
    return result


def host_package_output(command: list[str], purpose: str, *, timeout: int) -> subprocess.CompletedProcess:
    """Run a host Python package command with host-specific failure guidance."""
    try:
        result = run_logged_subprocess(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        log_captured_output(error)
        raise SetupError(
            f'{purpose} timed out after {timeout} seconds. The host Python package operation did not finish; '
            'check the network and Python environment, then retry.'
        ) from error
    except OSError as error:
        raise SetupError(f'{purpose}: could not start the host Python package command: {error}') from error
    log_captured_output(result)
    if result.returncode:
        detail = ((result.stdout or '') + (result.stderr or '')).strip()
        if len(detail) > 12000 and os.environ.get('DUMPER_AUTO_LOGGING') != '1':
            detail = f'{detail[:12000]}\n... output truncated'
        suffix = f': {detail}' if detail else ''
        raise SetupError(f'{purpose} failed (exit {result.returncode}){suffix}')
    return result


def resolve_adb(requested: str | None) -> str:
    """Find an explicit ADB executable, PATH ADB, or adbutils' bundled binary."""
    if requested is None and auto_context() is not None:
        # Browser/version diagnostics in the dumper use the controller's exact
        # ADB selection too, including an executable with a custom filename.
        requested = os.environ.get('DUMPER_AUTO_ADB') or None
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

    # Main requirements install adbutils as the fallback on supported hosts.
    # Inspect package data only; importing it could load unrelated dependencies.
    try:
        distribution = metadata.distribution('adbutils')
    except metadata.PackageNotFoundError:
        distribution = None
    if distribution is not None:
        # The wheel owns companion files (including Windows DLLs), so execute
        # in place. Never copy a binary away from its packaged dependencies or
        # select another host platform's executable by its filename alone.
        name = 'adb.exe' if sys.platform.startswith('win') else 'adb'
        candidate = Path(distribution.locate_file(f'adbutils/binaries/{name}'))
        if candidate.is_file() and (sys.platform.startswith('win') or os_access_executable(candidate)):
            return str(candidate.resolve())

    raise SetupError(
        'Android Debug Bridge (adb) was not found. Install Android SDK Platform-Tools '
        '(Homebrew: brew install --cask android-platform-tools), put adb on PATH, or pass --adb. '
        'For the bundled ADB fallback on supported hosts, run '
        'python init.py using the same Python environment as this helper.'
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
    if mode == 'direct':
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
            # Keep probing other existing mechanisms. The caller either asks
            # adb root next or reports that root is required for this workflow.
            continue
        if result.returncode == 0 and (result.stdout or '').strip() == '0':
            return mode
    return None


def probe_root(adb: str, serial: str) -> str:
    """Require root for setup or shell access, trying ``adb root`` when supported."""
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
        'Root access is required to manage Frida server in /data/local/tmp and open its shell. '
        'For emulators, use a Google APIs debug image with ro.debuggable=1 (userdebug/eng) '
        'that supports adb root; Play Store production images are not suitable. '
        'For physical devices, use a rooted build with a working su command.'
    )


def run_root(adb: str, serial: str, mode: str, command: str, purpose: str,
             *, check: bool = True, capture: bool = True,
             timeout: int = TIMEOUT) -> subprocess.CompletedProcess:
    """Run one literal remote shell command through the verified root mechanism."""
    return adb_command(
        adb, serial, *root_command(mode, command), purpose=purpose,
        check=check, capture=capture, timeout=timeout,
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
    except (URLError, TimeoutError, OSError, json.JSONDecodeError, IncompleteRead, UnicodeDecodeError) as error:
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
# VALIDATED ARCHIVE CACHE
# Final cache files are official, versioned XZ archives only.  Their companion
# manifests record a locally calculated SHA-256 after download_asset has already
# checked GitHub's size and optional digest.  Every cache use rechecks that hash,
# then extracts and validates the ELF into an ignored temporary work directory.
# ------------------------------------------------------------------------------
def cache_manifest_path(asset_name: str) -> Path:
    """Return the companion manifest path without accepting nested filenames."""
    if Path(asset_name).name != asset_name:
        raise CacheError(f'Invalid Frida cache asset name: {asset_name!r}.')
    return CACHE_ROOT / f'{asset_name}.json'


def file_sha256(path: Path) -> str:
    """Hash a local archive in bounded chunks without loading it into memory."""
    digest = hashlib.sha256()
    try:
        with path.open('rb') as source:
            while True:
                block = source.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
    except OSError as error:
        raise CacheError(f'Could not read cached Frida archive {path.name}: {error}') from error
    return digest.hexdigest()


def cache_version_key(version: str) -> tuple[int, int, int]:
    """Sort stable X.Y.Z cache entries numerically rather than lexically."""
    return tuple(int(part) for part in normalize_version(version).split('.'))


def load_cached_artifact(asset_name: str, architecture: str,
                         release: Release | None = None) -> CachedArtifact:
    """Verify a cached archive, optionally against freshly fetched release metadata."""
    manifest_path = cache_manifest_path(asset_name)
    archive = CACHE_ROOT / asset_name
    try:
        document = json.loads(manifest_path.read_text(encoding='utf-8'))
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise CacheError(f'Cached Frida manifest for {asset_name} is unavailable or invalid: {error}') from error
    try:
        version = normalize_version(document['version'])
        manifest_architecture = document['architecture']
        manifest_asset = document['asset_name']
        expected_size = document['archive_size']
        expected_hash = document['archive_sha256']
        upstream_hash = document.get('upstream_sha256')
    except (KeyError, TypeError, SetupError) as error:
        raise CacheError(f'Cached Frida manifest for {asset_name} is incomplete.') from error
    expected_asset = f'frida-server-{version}-android-{architecture}.xz'
    if (manifest_architecture != architecture or manifest_asset != asset_name
            or asset_name != expected_asset or not isinstance(expected_size, int)
            or expected_size <= 0 or expected_size > DOWNLOAD_LIMIT
            or not isinstance(expected_hash, str)
            or not re.fullmatch(r'[0-9a-f]{64}', expected_hash)
            or (upstream_hash is not None and (
                not isinstance(upstream_hash, str) or not re.fullmatch(r'[0-9a-f]{64}', upstream_hash)
                or upstream_hash != expected_hash
            ))):
        raise CacheError(f'Cached Frida manifest for {asset_name} does not match its filename or architecture.')
    if release is not None and (
            release.asset_name != asset_name or release.version != version or release.size != expected_size
            or (release.sha256 is not None and expected_hash != release.sha256)):
        raise CacheError(f'Cached Frida archive {asset_name} does not match current GitHub release metadata.')
    try:
        actual_size = archive.stat().st_size
    except OSError as error:
        raise CacheError(f'Cached Frida archive {asset_name} is missing: {error}') from error
    if actual_size != expected_size:
        raise CacheError(
            f'Cached Frida archive {asset_name} has size {actual_size}, expected {expected_size}.',
        )
    if file_sha256(archive) != expected_hash:
        raise CacheError(f'Cached Frida archive {asset_name} failed its local SHA-256 check.')
    return CachedArtifact(version, architecture, asset_name, archive)


def materialize_cached_artifact(artifact: CachedArtifact, destination: Path) -> None:
    """Extract and verify a cache entry for this run without retaining a binary."""
    try:
        unpack_xz(artifact.archive, destination)
        validate_elf(destination, artifact.architecture)
    except SetupError as error:
        raise CacheError(f'Cached Frida archive {artifact.asset_name} cannot be extracted safely: {error}') from error


def cached_artifacts(architecture: str) -> list[CachedArtifact]:
    """Return metadata/hash-valid cache entries for an architecture, newest first."""
    if not CACHE_ROOT.is_dir():
        return []
    entries = []
    pattern = f'frida-server-*-android-{architecture}.xz.json'
    for manifest in CACHE_ROOT.glob(pattern):
        asset_name = manifest.name[:-5]
        try:
            entries.append(load_cached_artifact(asset_name, architecture))
        except CacheError:
            # A corrupt cache item is never selected. A later cache refresh can
            # replace it atomically; deleting it is unnecessary and riskier.
            continue
    return sorted(entries, key=lambda entry: cache_version_key(entry.version), reverse=True)


def materialize_highest_cached(architecture: str, destination: Path,
                               *, excluded_assets: frozenset[str] = frozenset()) -> CachedArtifact:
    """Find the newest cache item that also survives XZ/ELF and metadata exclusions."""
    for artifact in cached_artifacts(architecture):
        if artifact.asset_name in excluded_assets:
            continue
        try:
            materialize_cached_artifact(artifact, destination)
            return artifact
        except CacheError:
            continue
    raise CacheError(f'No valid cached Frida archive exists for Android {architecture}.')


@contextmanager
def scratch_directory(prefix: str, directory: Path):
    """Clean disposable files without masking cancellation or its exit status."""
    temporary = tempfile.TemporaryDirectory(prefix=prefix, dir=directory)
    try:
        yield Path(temporary.name)
    finally:
        # Only cleanup is shielded; network and device operations remain
        # interruptible. Never replace KeyboardInterrupt with a removal error.
        with defer_interrupts():
            try:
                temporary.cleanup()
            except OSError as error:
                print(f'Warning: temporary files remain in {temporary.name}: {error}', file=sys.stderr)


def cache_release(release: Release, architecture: str) -> CachedArtifact:
    """Download, validate, and atomically publish one official archive to cache."""
    CACHE_ROOT.mkdir(parents=True, exist_ok=True)
    with scratch_directory('download-', CACHE_ROOT) as staging:
        archive = staging / release.asset_name
        extracted = staging / 'frida-server'
        download_asset(release, archive)
        unpack_xz(archive, extracted)
        validate_elf(extracted, architecture)
        archive_hash = file_sha256(archive)
        manifest = {
            'version': release.version,
            'architecture': architecture,
            'asset_name': release.asset_name,
            'archive_size': archive.stat().st_size,
            'archive_sha256': archive_hash,
            'upstream_sha256': release.sha256,
        }
        manifest_staging = staging / f'{release.asset_name}.json'
        manifest_staging.write_text(json.dumps(manifest, sort_keys=True) + '\n', encoding='utf-8')
        # Same-filesystem replacements publish only fully checked files. A
        # crash between the two replacements yields an invalid cache entry,
        # which load_cached_artifact refuses rather than trusting partially.
        archive.replace(CACHE_ROOT / release.asset_name)
        manifest_staging.replace(cache_manifest_path(release.asset_name))
    return load_cached_artifact(release.asset_name, architecture)


def select_server_artifact(version: str | None, architecture: str, destination: Path) -> CachedArtifact:
    """Materialize pinned or latest Frida with defined cache/network fallback rules."""
    if version:
        asset_name = f'frida-server-{version}-android-{architecture}.xz'
        try:
            cached = load_cached_artifact(asset_name, architecture)
            materialize_cached_artifact(cached, destination)
            print(f'Using cached Frida {cached.version} for Android {architecture}.', flush=True)
            return cached
        except CacheError:
            # A pinned corrupt/missing cache may refresh exactly once, but may
            # never silently downgrade to a different requested version.
            release = release_for(version, architecture)
            print(f'Downloading Frida {release.version} for Android {architecture}.', flush=True)
            cached = cache_release(release, architecture)
            materialize_cached_artifact(cached, destination)
            return cached

    print('Checking latest stable Frida release...', flush=True)
    try:
        latest = release_for(None, architecture)
    except SetupError as metadata_error:
        try:
            cached = materialize_highest_cached(architecture, destination)
        except CacheError as cache_error:
            raise SetupError(
                f'Could not check the latest Frida release ({metadata_error}); {cache_error}'
            ) from metadata_error
        print(
            f'Warning: latest Frida metadata is unavailable ({metadata_error}); '
            f'using cached {cached.version} for Android {architecture}.',
            file=sys.stderr,
        )
        return cached

    try:
        cached = load_cached_artifact(latest.asset_name, architecture, latest)
        materialize_cached_artifact(cached, destination)
        print(f'Using cached Frida {cached.version} for Android {architecture}.', flush=True)
        return cached
    except CacheError:
        try:
            print(f'Downloading Frida {latest.version} for Android {architecture}.', flush=True)
            cached = cache_release(latest, architecture)
            materialize_cached_artifact(cached, destination)
            return cached
        except SetupError as download_error:
            try:
                # Fresh latest metadata rejected this same-name cache archive;
                # a failed refresh must not immediately reuse it as fallback.
                cached = materialize_highest_cached(
                    architecture, destination, excluded_assets=frozenset({latest.asset_name}),
                )
            except CacheError as cache_error:
                raise SetupError(
                    f'Could not download Frida {latest.version} ({download_error}); {cache_error}'
                ) from download_error
            print(
                f'Warning: Frida {latest.version} could not be downloaded ({download_error}); '
                f'using cached {cached.version} for Android {architecture}.',
                file=sys.stderr,
            )
            return cached


# ------------------------------------------------------------------------------
# ANDROID INSTALLATION AND OPTIONAL OPERATOR SHELL
# The unique staging name means a failed upload cannot damage a previous working
# /data/local/tmp/frida-server.  Only a verified staging binary is moved into
# place.  Process management is deliberately limited to executables whose
# /proc/PID/exe identity is the exact managed server path.
# ------------------------------------------------------------------------------
def remote_quote(*parts: str) -> str:
    """Build one remote sh command while preserving each literal path as an atom."""
    return shlex.join(list(parts))


def _managed_server_scan_command(*, include_deleted: bool = True,
                                 fail_if_found: bool = False) -> str:
    """Inspect all executable links with one ls process instead of one fork/PID.

    On a busy emulator, spawning readlink separately for hundreds of processes
    can exceed the command timeout. Android's ls reads the same /proc/PID/exe
    links in a batch. Parse only the stable link path/target suffix; ignore the
    variable owner, size and timestamp columns. No process-name matching is used.
    """
    managed = shlex.quote(REMOTE_SERVER)
    deleted = shlex.quote(f'{REMOTE_SERVER} (deleted)')
    patterns = f'{managed}|{deleted}' if include_deleted else managed
    action = 'exit 1' if fail_if_found else 'printf "%s\\n" "$pid"'
    # A disappearing PID or a kernel thread without exe makes ls return 1.
    # Larger failures (including a missing ls) must fail closed. The here-doc
    # keeps the loop in the current shell: exit 1 must stop the later mv/start,
    # not merely exit a pipeline's subshell and let deployment continue.
    return f'''frida_process_links=$(LC_ALL=C ls -ld /proc/[0-9]*/exe 2>/dev/null)
frida_scan_status=$?
if test "$frida_scan_status" -gt 1 || test -z "$frida_process_links"; then
    printf 'Could not inspect Android process executable links\\n' >&2
    exit 2
fi
frida_scanned_links=0
while IFS= read -r frida_process_entry; do
    case "$frida_process_entry" in
        *" /proc/"[0-9]*"/exe -> "*) ;;
        *) continue ;;
    esac
    frida_scanned_links=$((frida_scanned_links + 1))
    target=${{frida_process_entry#* -> }}
    case "$target" in
        {patterns})
            pid=${{frida_process_entry%%/exe -> *}}
            pid=${{pid##*/}}
            case "$pid" in ''|*[!0-9]*) exit 2 ;; esac
            if test "$pid" -le 1; then exit 2; fi
            {action}
            ;;
    esac
done <<__FRIDA_PROCESS_LINKS__
$frida_process_links
__FRIDA_PROCESS_LINKS__
if test "$frida_scanned_links" -eq 0; then
    printf 'Android process executable listing was unreadable\\n' >&2
    exit 2
fi
:'''


def managed_server_pids(adb: str, serial: str, root_mode: str,
                        *, include_deleted: bool = True) -> list[str]:
    """Return process IDs using the managed path, optionally including deleted maps."""
    command = _managed_server_scan_command(include_deleted=include_deleted)
    result = run_root(adb, serial, root_mode, command, 'Finding managed Frida server processes')
    pids = []
    for value in (result.stdout or '').split():
        if not re.fullmatch(r'[0-9]+', value) or int(value) <= 1:
            raise SetupError(f'Android returned an invalid managed Frida process ID: {value!r}.')
        pids.append(value)
    return sorted(set(pids), key=int)


def managed_server_absent_command() -> str:
    """Return a remote script which fails if any managed current/deleted daemon exists."""
    return _managed_server_scan_command(fail_if_found=True)


def terminate_managed_pid(adb: str, serial: str, root_mode: str, pid: str) -> None:
    """Recheck a PID's executable immediately before sending it SIGTERM."""
    if not re.fullmatch(r'[0-9]+', pid) or int(pid) <= 1:
        raise SetupError(f'Refusing to signal invalid process ID: {pid!r}.')
    managed = shlex.quote(REMOTE_SERVER)
    deleted = shlex.quote(f'{REMOTE_SERVER} (deleted)')
    process_exe = shlex.quote(f'/proc/{pid}/exe')
    command = (
        f'target=$(readlink {process_exe} 2>/dev/null) || exit 0; '
        f'case "$target" in {managed}|{deleted}) kill -TERM {pid};; esac'
    )
    run_root(adb, serial, root_mode, command, f'Stopping managed Frida server process {pid}')


def stop_managed_servers(adb: str, serial: str, root_mode: str,
                         *, timeout: float = STOP_TIMEOUT) -> None:
    """Gracefully stop exact managed-server processes without force killing them."""
    pids = managed_server_pids(adb, serial, root_mode)
    for pid in pids:
        terminate_managed_pid(adb, serial, root_mode, pid)
    if not pids:
        return

    deadline = time.monotonic() + timeout
    while True:
        remaining = managed_server_pids(adb, serial, root_mode)
        if not remaining:
            return
        if time.monotonic() >= deadline:
            raise SetupError(
                'Managed Frida server did not stop after SIGTERM '
                f'(remaining PID(s): {", ".join(remaining)}); destination was not replaced.'
            )
        time.sleep(STOP_INTERVAL)


def existing_server_state(adb: str, serial: str, root_mode: str) -> str:
    """Classify the managed path without following a symlink or executing it."""
    path = shlex.quote(REMOTE_SERVER)
    command = (
        f'if test -L {path}; then printf symlink; '
        f'elif test -d {path}; then printf directory; '
        f'elif test -f {path}; then '
        f'if test -x {path}; then printf executable; else printf non-executable; fi; '
        f'elif test -e {path}; then printf special; else printf missing; fi'
    )
    result = run_root(adb, serial, root_mode, command, 'Inspecting managed Frida server')
    state = (result.stdout or '').strip()
    if state not in {'missing', 'symlink', 'directory', 'non-executable', 'executable', 'special'}:
        raise SetupError(f'Android returned an unknown managed Frida server state: {state!r}.')
    return state


def validate_existing_server(adb: str, serial: str, root_mode: str) -> str:
    """Verify that an existing executable reports a normal Frida X.Y.Z version."""
    result = run_root(
        adb, serial, root_mode, remote_quote(REMOTE_SERVER, '--version'),
        'Validating existing Frida server',
    )
    version = (result.stdout or '').strip()
    try:
        return normalize_version(version)
    except SetupError as error:
        raise SetupError(f'Existing managed Frida server returned an invalid version: {version!r}.') from error


def prepare_existing_server(adb: str, serial: str, root_mode: str) -> str:
    """Prepare ``--shell`` to run an existing binary in the foreground.

    A missing binary with a still-running deleted executable is left alone: it
    cannot be safely reattached or relaunched.  The caller opens a root shell
    and reports that orphan state instead of signalling an unreplaceable file.
    """
    pids = managed_server_pids(adb, serial, root_mode)
    state = existing_server_state(adb, serial, root_mode)
    if state == 'missing':
        return 'orphan' if pids else 'missing'
    if state == 'symlink':
        raise SetupError(f'{REMOTE_SERVER} is a symlink; refuse to execute it.')
    if state == 'directory':
        raise SetupError(f'{REMOTE_SERVER} is a directory; remove or rename it before starting Frida.')
    if state == 'non-executable':
        raise SetupError(f'{REMOTE_SERVER} is not executable; reinstall Frida server or fix its permissions.')
    if state == 'special':
        raise SetupError(f'{REMOTE_SERVER} is not a regular executable file; refuse to execute it.')
    installed_version = validate_existing_server(adb, serial, root_mode)
    # The reported executable is the authoritative server selection in shell
    # mode. Synchronize before signalling it so an incompatible host never
    # starts a foreground server.
    ensure_host_frida_version(installed_version)
    # A foreground terminal cannot attach to an old daemon. Stop only process
    # paths proven to be this managed server, then recheck before terminal use.
    stop_managed_servers(adb, serial, root_mode)
    remaining = managed_server_pids(adb, serial, root_mode)
    if remaining:
        raise SetupError(
            'Managed Frida server remained after SIGTERM '
            f'(PID(s): {", ".join(remaining)}); cannot start a foreground server.'
        )
    return 'ready'


def root_shell_continuation(root_mode: str) -> str:
    """Keep a su parent alive so leaving its root prompt returns to ADB's shell."""
    if root_mode == 'direct':
        return 'exec /system/bin/sh -i'
    # This child is the operator's root prompt. Its last command's exit status
    # must not be mistaken for a failed setup when the operator leaves su.
    return '/system/bin/sh -i; exit 0'


def root_session_command(root_mode: str, command: str, *, interactive: bool) -> list[str]:
    """Wrap su sessions with the ordinary ADB shell to return to after exit."""
    shell_arguments = root_command(root_mode, command)
    if not interactive or root_mode == 'direct':
        return shell_arguments
    # Keep the unprivileged shell outside su. A caught INT preserves this
    # waiting shell while the foreground process receives Ctrl+C normally.
    # Setup/server failures still propagate without dropping into a prompt.
    outer_command = (
        "trap ':' INT; "
        f'{shell_arguments[1]}; frida_root_status=$?; trap - INT; '
        'if test "$frida_root_status" -ne 0; then exit "$frida_root_status"; fi; '
        f'cd {shlex.quote(REMOTE_DIRECTORY)} || exit $?; '
        'exec /system/bin/sh -i'
    )
    return ['shell', remote_quote('sh', '-c', outer_command)]


def foreground_process_identity_command() -> str:
    """Read a child incarnation using Android /proc, without scanning processes.

    Field 22 is the process start time. Remove the parenthesized command name
    first because it can contain spaces and closing parentheses. PID plus start
    time prevents shutdown from signalling a new process that reused the PID.
    """
    return r'''frida_read_identity() {
    frida_current_start=
    if ! IFS= read -r frida_proc_stat 2>/dev/null < "/proc/$frida_pid/stat"; then return; fi
    frida_proc_stat=${frida_proc_stat##*) }
    set -- $frida_proc_stat
    if test "$#" -lt 20; then return; fi
    case "$1" in Z|X) return ;; esac
    shift 19
    case "$1" in ''|*[!0-9]*) return ;; esac
    frida_current_start=$1
}'''


def supervised_server_command() -> str:
    """Keep terminal I/O attached while bounding shutdown after Ctrl+C.

    A normal foreground command makes Android mksh defer its INT trap until
    the command exits. Frida can hang during shutdown with clients attached.
    Keep job control disabled and use an interruptible shell wait instead: the
    child retains the terminal's foreground process group and explicit stdin.
    The terminal already sends INT to the child; do not send a duplicate signal
    while Frida is entering its shutdown handler.
    Only this child, with its original /proc start time, can be force-stopped.
    There is no timer while the server is running normally.
    """
    command = foreground_process_identity_command() + '\n' + r'''
frida_pid=
frida_start=
frida_ready=0
frida_interrupted=0
frida_stopping=0
frida_forced=0
frida_stop() {
    if test "$frida_stopping" -eq 1; then return; fi
    frida_stopping=1
    trap '' INT
    frida_read_identity
    if test -z "$frida_start" || test "$frida_current_start" != "$frida_start"; then return; fi
    printf '\nStopping Frida; allowing up to __TIMEOUT__ seconds for shutdown...\n'
    frida_remaining=__TIMEOUT__
    while test "$frida_remaining" -gt 0; do
        frida_read_identity
        if test "$frida_current_start" != "$frida_start"; then return; fi
        sleep 1
        frida_remaining=$((frida_remaining - 1))
    done
    frida_read_identity
    if test "$frida_current_start" = "$frida_start"; then
        printf 'Frida did not stop within __TIMEOUT__ seconds; force-stopping this session\047s server (PID %s).\n' "$frida_pid" >&2
        kill -KILL "$frida_pid" 2>/dev/null && frida_forced=1
    fi
}
trap 'frida_interrupted=1; if test "$frida_ready" -eq 1; then frida_stop; fi' INT
(trap - INT QUIT; exec ./frida-server) <&0 &
frida_pid=$!
frida_read_identity
frida_start=$frida_current_start
frida_ready=1
if test "$frida_interrupted" -eq 1; then frida_stop; fi
wait "$frida_pid"
frida_status=$?
if test "$frida_interrupted" -eq 1; then
    wait "$frida_pid"
    frida_reaped_status=$?
    if test "$frida_reaped_status" -ne 127; then frida_status=$frida_reaped_status; fi
    if test "$frida_forced" -eq 1; then frida_status=130; fi
fi
trap - INT
'''.replace('__TIMEOUT__', str(FOREGROUND_STOP_TIMEOUT))
    marker = frida_marker()
    if marker is not None:
        # Full auto owns just this process incarnation. Publish its identity
        # before readiness so cancellation can stop it without scanning/killing
        # unrelated servers. Manual sessions do not create a marker.
        record = (
            'frida_start=$frida_current_start\n'
            f'if ! (umask 077; printf "%s %s\\n" "$frida_pid" "$frida_start" > {shlex.quote(marker)}); then\n'
            '    kill -KILL "$frida_pid" 2>/dev/null; wait "$frida_pid"; exit 1\n'
            'fi'
        )
        command = command.replace('frida_start=$frida_current_start', record)
    return command


def foreground_server_command(interactive: bool, root_mode: str = 'direct') -> str:
    """Build the remote foreground lifecycle after one final process-free scan."""
    preflight = managed_server_absent_command()
    directory = shlex.quote(REMOTE_DIRECTORY)
    # Print from Android, after cd succeeds, so a quiet server still visibly
    # identifies the device, working directory, and command being run.
    launch_line = (
        'frida_device=$(getprop ro.product.device 2>/dev/null); '
        'frida_device=${frida_device:-android}; '
        "printf '\\n%s:%s # ./frida-server\\n' \"$frida_device\" \"$PWD\""
    )
    command = (
        f'{preflight}; cd {directory} || exit $?; {launch_line}; '
        f'{supervised_server_command()}\n'
    )
    if not interactive:
        return command + 'exit "$frida_status"'
    return command + (
        'if test "$frida_interrupted" -eq 1 || test "$frida_status" -eq 0 || test "$frida_status" -eq 130; then '
        f'{root_shell_continuation(root_mode)}; fi; '
        'exit "$frida_status"'
    )


def _reap_windows_adb_child(process) -> None:
    """Terminate and reap a Windows ADB child after host-side interruption."""
    try:
        process.terminate()
    except OSError:
        # The child may have exited between the interruption and cleanup.
        pass
    try:
        process.wait(timeout=WINDOWS_CHILD_CLEANUP_TIMEOUT)
        return
    except (OSError, subprocess.TimeoutExpired):
        pass

    try:
        process.kill()
    except OSError:
        pass
    try:
        process.wait(timeout=WINDOWS_CHILD_CLEANUP_TIMEOUT)
    except (OSError, subprocess.TimeoutExpired):
        print(
            'Warning: could not reap the Windows ADB child after cancellation; '
            'check Task Manager before retrying.',
            file=sys.stderr,
        )


def handoff_to_adb(argv: list[str], purpose: str) -> NoReturn:
    """Give ADB inherited terminal streams after all temporary cleanup finishes."""
    try:
        # exec does not flush Python's buffered output. No Python finally block
        # runs after success either: callers must finish cleanup before here.
        sys.stdout.flush()
        sys.stderr.flush()
        if sys.platform.startswith('win'):
            # Windows has no POSIX-style exec replacement. Own one direct ADB
            # child with inherited terminal streams and wait indefinitely while
            # it owns the session; only host cancellation/error enters bounded
            # termination and reaping.
            try:
                process = subprocess.Popen(argv, shell=False)
            except OSError as error:
                raise SetupError(
                    f'{purpose}: ADB could not start: {error}. '
                    'Check the ADB executable and reconnect the Android device before retrying.'
                ) from error
            try:
                returncode = process.wait()
            except KeyboardInterrupt:
                with ignore_interrupts():
                    _reap_windows_adb_child(process)
                print(
                    'ADB session cancelled. Reconnect the Android device if needed '
                    'before retrying setup.',
                    file=sys.stderr,
                )
                raise SystemExit(130) from None
            except OSError as error:
                with ignore_interrupts():
                    _reap_windows_adb_child(process)
                raise SetupError(
                    f'{purpose}: ADB session wait failed: {error}. '
                    'Reconnect the Android device if needed before retrying.'
                ) from error
            if returncode:
                print(
                    f'ADB session ended with exit status {returncode}. If the Android '
                    'device disconnected, reconnect it before retrying; otherwise '
                    'inspect the ADB/Frida output above.',
                    file=sys.stderr,
                )
            raise SystemExit(returncode)
        os.execv(argv[0], argv)
    except OSError as error:
        raise SetupError(f'{purpose}: {error}') from error


def run_foreground_server(adb: str, serial: str, root_mode: str, *, interactive: bool) -> NoReturn:
    """Give ADB the terminal for the server and any subsequent Android shells."""
    shell_arguments = root_session_command(
        root_mode, foreground_server_command(interactive, root_mode), interactive=interactive,
    )
    terminal_mode = '-t' if interactive or (sys.stdin.isatty() and sys.stdout.isatty()) else '-T'
    argv = [adb, '-s', serial, shell_arguments[0], terminal_mode, shell_arguments[1]]
    if interactive:
        print('\nOpening ADB terminal; starting Frida in the foreground.')
        print(f'Ctrl+C: stop Frida (force-stop after {FOREGROUND_STOP_TIMEOUT}s if needed).')
        if root_mode != 'direct':
            print('Then exit twice: root shell -> Android shell -> host.')
        else:
            print('Then exit: root shell -> host.')
    else:
        print('\nStarting Frida in the ADB terminal; no follow-up shell.')
        print(f'Ctrl+C: stop Frida (force-stop after {FOREGROUND_STOP_TIMEOUT}s if needed).')
    emit_event('frida_launch', device_id=serial, root_mode=root_mode, marker=frida_marker())
    handoff_to_adb(argv, 'Running foreground Frida server failed')


def install_server(adb: str, serial: str, root_mode: str, server: Path,
                   version: str, *, staging_name: str | None = None) -> None:
    """Verify a staged candidate, stop only managed processes, then replace atomically."""
    # Selection happened before download/cache work. Recheck the same transport
    # immediately before uploading; never substitute another connected device.
    state = adb_command(adb, serial, 'get-state', purpose='Checking device before upload', check=False)
    if state.returncode != 0 or (state.stdout or '').strip() != 'device':
        raise SetupError(
            f'Android device {serial} is no longer online. Reconnect and authorize '
            'it, wait for its home screen, and retry. No file was uploaded.'
        )
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
        # Candidate verification precedes stopping the existing daemon, so a
        # corrupt upload leaves the currently working server untouched.
        destination_is_safe = (
            f'if {remote_quote("test", "-L", REMOTE_SERVER)} || '
            f'{remote_quote("test", "-d", REMOTE_SERVER)}; then exit 1; '
            f'elif {remote_quote("test", "-f", REMOTE_SERVER)} || '
            f'{remote_quote("test", "!", "-e", REMOTE_SERVER)}; then :; else exit 1; fi'
        )
        run_root(
            adb, serial, root_mode, destination_is_safe,
            'Checking managed Frida server destination',
        )
        stop_managed_servers(adb, serial, root_mode)
        remaining = managed_server_pids(adb, serial, root_mode)
        if remaining:
            raise SetupError(
                'Managed Frida server appeared while preparing replacement '
                f'(PID(s): {", ".join(remaining)}); destination was not replaced.'
            )
        run_root(
            adb, serial, root_mode,
            f'{destination_is_safe}; {managed_server_absent_command()} && '
            f'{remote_quote("mv", staging, REMOTE_SERVER)}',
            'Installing Frida server',
        )
        cleanup_needed = False  # mv consumed the owned staging file.
    finally:
        if cleanup_needed:
            # Best effort only: do not touch the existing destination, running
            # server, or any path except the UUID-bearing staging file we made.
            with ignore_interrupts():
                try:
                    run_root(
                        adb, serial, root_mode, remote_quote('rm', '-f', staging),
                        'Removing partial Frida upload', timeout=STAGING_CLEANUP_TIMEOUT,
                    )
                except SetupError as error:
                    print(f'Warning: partial upload may remain at {staging}: {error}', file=sys.stderr)


def normalized_distribution_name(name: str) -> str:
    """Normalize a distribution name without loading an optional packaging library."""
    return re.sub(r'[-_.]+', '-', name).lower()


def installed_host_requirements(version: str) -> list[str]:
    """Pin the current environment while leaving Frida and frida-tools resolvable.

    A complete requirement set lets pip check reverse dependencies before any
    mutation. Distribution metadata is validated before it is written to the
    temporary requirements file, so malformed local metadata cannot add pip
    options or another requirement source.
    """
    requirements: dict[str, str] = {}
    for distribution in metadata.distributions():
        name = distribution.metadata.get('Name')
        installed_version = distribution.version
        if not isinstance(name, str) or not PACKAGE_NAME_PATTERN.fullmatch(name):
            raise SetupError(
                'An installed Python distribution has an unsafe or missing name; '
                'refuse to construct a pip requirements file from local metadata.'
            )
        if not isinstance(installed_version, str) or not PACKAGE_VERSION_PATTERN.fullmatch(installed_version):
            raise SetupError(
                f'Installed Python distribution {name!r} has an unsafe version; '
                'refuse to construct a pip requirements file from local metadata.'
            )
        normalized = normalized_distribution_name(name)
        if normalized in {'frida', 'frida-tools'}:
            continue
        requirement = f'{name}=={installed_version}'
        existing = requirements.get(normalized)
        if existing is not None and existing != requirement:
            raise SetupError(
                f'Installed Python metadata has conflicting entries for {name!r}; '
                'refuse to change the environment automatically.'
            )
        requirements[normalized] = requirement
    return [requirements[name] for name in sorted(requirements)] + [
        f'frida=={version}',
        'frida-tools',
    ]


def host_pip_install_command(requirements_file: Path, *, dry_run: bool) -> list[str]:
    """Build the resolver command without selecting a different interpreter."""
    command = [
        sys.executable, '-I', '-m', 'pip', 'install', '--upgrade',
        '--disable-pip-version-check', '--no-input', '--progress-bar', 'off',
        '--only-binary=frida', '--require-virtualenv',
        '--timeout', '30', '--retries', '2',
    ]
    if dry_run:
        command.append('--dry-run')
    return [*command, '--requirement', str(requirements_file)]


def fresh_host_frida_version() -> tuple[str, str | None]:
    """Read distribution and imported binding versions in a new interpreter."""
    script = (
        'import json\n'
        'from importlib import metadata\n'
        'import frida\n'
        'print(json.dumps({"distribution": metadata.version("frida"), '
        '"module": getattr(frida, "__version__", None)}))\n'
    )
    result = host_package_output(
        [sys.executable, '-I', '-c', script],
        'Verifying the installed host Python Frida bindings', timeout=PIP_CHECK_TIMEOUT,
    )
    try:
        report = json.loads((result.stdout or '').strip().splitlines()[-1])
    except (IndexError, json.JSONDecodeError) as error:
        raise SetupError(
            'Host Python Frida verification returned an unreadable version report.'
        ) from error
    distribution = report.get('distribution') if isinstance(report, dict) else None
    imported = report.get('module') if isinstance(report, dict) else None
    if not isinstance(distribution, str) or not (isinstance(imported, str) or imported is None):
        raise SetupError('Host Python Frida verification returned invalid version fields.')
    return distribution, imported


def frida_update_verb(installed: str | None, version: str) -> str:
    """Describe a numeric Frida transition without lexicographic comparison."""
    if installed is None:
        return 'installing'
    match = VERSION_PATTERN.fullmatch(installed)
    if match is None:
        return 'updating'
    installed_parts = tuple(int(part) for part in match.group(1).split('.'))
    target_parts = tuple(int(part) for part in version.split('.'))
    if installed_parts < target_parts:
        return 'upgrading'
    if installed_parts > target_parts:
        return 'downgrading'
    return 'updating'


def host_environment_guidance() -> str:
    """Keep package-operation failures actionable without changing interpreters."""
    return (
        f'This helper only updates its running interpreter ({sys.executable}). '
        'Create or activate a virtual environment and rerun this helper there. '
        'If a matching Frida wheel is unavailable for this Python/platform, choose a supported interpreter; '
        'native source builds are intentionally disabled.'
    )


def pip_routing_configuration() -> list[str]:
    """Reject pip settings that redirect or weaken the complete resolver run."""
    configured_environment = [name for name in PIP_ROUTING_ENVIRONMENT if name in os.environ]
    if configured_environment:
        raise SetupError(
            'Automatic host Frida sync refuses pip routing environment variables: '
            f'{", ".join(configured_environment)}.'
        )
    resolver_environment = [name for name in PIP_RESOLVER_ENVIRONMENT if name in os.environ]
    if resolver_environment:
        raise SetupError(
            'Automatic host Frida sync refuses pip dependency-resolution environment variables: '
            f'{", ".join(resolver_environment)}.'
        )
    result = host_package_output(
        [sys.executable, '-I', '-m', 'pip', 'config', 'list'],
        'Checking pip installation routing configuration', timeout=PIP_CHECK_TIMEOUT,
    )
    routing_overrides = []
    resolver_overrides = []
    for line in (result.stdout or '').splitlines():
        key, separator, _value = line.partition('=')
        if not separator:
            continue
        option = key.strip().strip("'\"").lower().rsplit('.', 1)[-1]
        if option in PIP_ROUTING_OPTIONS:
            routing_overrides.append(key.strip())
        if option in PIP_RESOLVER_OPTIONS:
            resolver_overrides.append(key.strip())
    if routing_overrides:
        raise SetupError(
            'Automatic host Frida sync refuses pip routing configuration: '
            f'{", ".join(routing_overrides)}.'
        )
    if resolver_overrides:
        raise SetupError(
            'Automatic host Frida sync refuses pip dependency-resolution configuration: '
            f'{", ".join(resolver_overrides)}.'
        )
    return []


def ensure_host_frida_version(version: str) -> None:
    """Synchronize host bindings to the selected deployable Android server version.

    An exact initial match is a metadata-only no-op. Otherwise, preflight the
    full current environment before pip mutates it, preserving all existing
    package versions except Frida and frida-tools. New dependencies may be
    resolved when required by a compatible frida-tools release.
    """
    version = normalize_version(version)
    try:
        installed = metadata.version('frida')
    except metadata.PackageNotFoundError:
        installed = None
    if installed == version:
        print(f'Host Python frida {version} matches the selected Android server.', flush=True)
        return

    current = installed if installed is not None else 'not installed'
    print(
        f'Warning: host Python frida is {current}, but the selected Android server is {version}. '
        'Synchronizing exact versions before deployment.',
        file=sys.stderr, flush=True,
    )
    if not running_in_virtual_environment():
        raise SetupError(
            'Automatic host Frida sync only changes a virtual environment. '
            f'{host_environment_guidance()}'
        )
    try:
        pip_routing_configuration()
    except SetupError as error:
        raise SetupError(
            f'Automatic host Frida sync will not run with redirected pip installation routing. '
            f'{error} {host_environment_guidance()}'
        ) from error
    print(
        f'Automatically {frida_update_verb(installed, version)} host Python Frida: '
        f'{current} -> frida=={version} using {sys.executable} (environment {sys.prefix}).',
        flush=True,
    )
    print(
        'Resolving a compatible frida-tools version while keeping other installed package versions fixed.',
        flush=True,
    )
    try:
        host_package_output(
            [sys.executable, '-I', '-m', 'pip', 'check'],
            'Checking current host Python package dependencies', timeout=PIP_CHECK_TIMEOUT,
        )
    except SetupError as error:
        raise SetupError(
            f'Host Python dependencies are already inconsistent; automatic Frida sync will not modify them. '
            f'{error} {host_environment_guidance()}'
        ) from error

    try:
        requirements = installed_host_requirements(version)
    except SetupError as error:
        raise SetupError(f'Could not preflight host Python package requirements. {error} {host_environment_guidance()}') from error

    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    with scratch_directory('frida-pip-', TMP_ROOT) as staging:
        requirements_file = staging / 'host-frida-requirements.txt'
        requirements_file.write_text('\n'.join(requirements) + '\n', encoding='utf-8')
        try:
            print('Preflighting the complete host Python dependency set...', flush=True)
            host_package_output(
                host_pip_install_command(requirements_file, dry_run=True),
                'Preflighting the host Python Frida update', timeout=PIP_TIMEOUT,
            )
        except SetupError as error:
            raise SetupError(
                f'Host Python Frida update was not started because its dependency preflight failed. '
                f'{error} {host_environment_guidance()}'
            ) from error
        try:
            print('Installing the preflighted host Python Frida update...', flush=True)
            host_package_output(
                host_pip_install_command(requirements_file, dry_run=False),
                'Updating host Python Frida packages', timeout=PIP_TIMEOUT,
            )
        except KeyboardInterrupt:
            with ignore_interrupts():
                print(
                    'Host Frida update was cancelled while pip was changing this virtual environment. '
                    'The virtual environment may be partially changed; Android was not changed. '
                    'Inspect or repair the virtual environment before retrying.',
                    file=sys.stderr,
                )
            raise
        except SetupError as error:
            raise SetupError(
                f'Host Python Frida update did not complete. No Android server was changed; '
                f'the interrupted or failed pip operation may have changed this host environment. '
                f'{error} {host_environment_guidance()}'
            ) from error

    try:
        distribution, imported = fresh_host_frida_version()
    except SetupError as error:
        raise SetupError(
            f'Host Python Frida update completed, but fresh-process verification failed. '
            f'No Android server was changed. {error} {host_environment_guidance()}'
        ) from error
    if distribution != version or imported != version:
        raise SetupError(
            f'Host Python Frida verification expected {version}, but the distribution reports '
            f'{distribution!r} and the imported module reports {imported!r}. No Android server was changed. '
            f'{host_environment_guidance()}'
        )
    try:
        host_package_output(
            [sys.executable, '-I', '-m', 'pip', 'check'],
            'Checking host Python package dependencies after the Frida update', timeout=PIP_CHECK_TIMEOUT,
        )
    except SetupError as error:
        raise SetupError(
            f'Host Python Frida installed {version}, but its dependency check failed. '
            f'No Android server was changed. {error} {host_environment_guidance()}'
        ) from error
    print(f'Host Python Frida synchronized: {version} (fresh import and dependency check passed).', flush=True)


def open_device_shell(adb: str, serial: str, root_mode: str) -> NoReturn:
    """Hand the user a root shell in the install directory after server setup."""
    command = (
        f'cd {shlex.quote(REMOTE_DIRECTORY)} || exit $?; '
        f"trap ':' INT; {root_shell_continuation(root_mode)}"
    )
    shell_arguments = root_session_command(root_mode, command, interactive=True)
    argv = [adb, '-s', serial, shell_arguments[0], '-t', shell_arguments[1]]
    print('Handing terminal to ADB for the Android root shell.')
    handoff_to_adb(argv, 'Opening interactive Android shell failed')


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
    shell_mode.add_argument(
        '--no-shell', '--non-interactive', action='store_true',
        help='Install and run Frida server without a follow-up shell. '
             'Use --no-shell for manual runs; --non-interactive is reserved for full_auto.py.',
    )
    shell_mode.add_argument('--shell', action='store_true', help='Run the installed Frida server in the foreground, then open a root shell.')
    return parser


def _main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.shell and (args.ver or args.arch != 'auto'):
        parser.error('--shell cannot be combined with --ver or an explicit --arch; it does not replace the Android server.')
    if args.ver:
        try:
            args.ver = normalize_version(args.ver)
        except SetupError as error:
            parser.error(str(error))
    if not args.no_shell and (not sys.stdin.isatty() or not sys.stdout.isatty()):
        parser.error('the default interactive shell requires a TTY; use --no-shell for unattended installation.')

    try:
        print('\nFrida setup (Ctrl+C to cancel)', flush=True)
        adb = resolve_adb(args.adb)
        print(f'ADB: {adb}', flush=True)
        # Require an online ADB transport before root checks, scratch/cache
        # access, release lookup, downloads, or any device changes.
        device = select_device(list_adb_devices(adb), args.device_id)
        if args.shell:
            # Shell-only may start a server, so it requires root. It skips the
            # normal install target checks because it does not download/update.
            root_mode = probe_root(adb, device.serial)
            action = prepare_existing_server(adb, device.serial, root_mode)
            if action == 'ready':
                installed_version = validate_existing_server(adb, device.serial, root_mode)
                print(
                    f'Using installed Frida {installed_version} on {device.serial}.',
                    flush=True,
                )
                return run_foreground_server(adb, device.serial, root_mode, interactive=True)
            if action == 'orphan':
                print(
                    f'A managed Frida server is still running on {device.serial}, but {REMOTE_SERVER} is missing; '
                    'opening a root shell without stopping or relaunching it.',
                    flush=True,
                )
            else:
                print(f'No managed Frida server is installed on {device.serial}; opening a root shell only.', flush=True)
            return open_device_shell(adb, device.serial, root_mode)
        # Refuse a mismatched architecture before probe_root can call adb root
        # and restart adbd. Normal setup only mutates after this preflight.
        sdk, abi, architecture = validate_target(adb, device.serial, args.arch)
        root_mode = probe_root(adb, device.serial)
        print(f'Device: {device.serial} | API {sdk} | ABI {abi} | root {root_mode}', flush=True)

        TMP_ROOT.mkdir(exist_ok=True)
        with scratch_directory('frida-', TMP_ROOT) as staging:
            server = staging / 'frida-server'
            artifact = select_server_artifact(args.ver, architecture, server)
            ensure_host_frida_version(artifact.version)
            print(f'Installing Frida {artifact.version} on {device.serial}...', flush=True)
            install_server(adb, device.serial, root_mode, server, artifact.version)

        print(f'Installed: {REMOTE_SERVER}', flush=True)
        return run_foreground_server(adb, device.serial, root_mode, interactive=not args.no_shell)
    except (SetupError, AutoSessionError) as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    except OSError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    """Make Ctrl+C work from terminal preparation through the ADB handoff."""
    try:
        prepare_terminal()
        if __name__ == '__main__':
            bootstrap(Path(__file__))
        return _main(argv)
    except BootstrapError as error:
        print(f'error: {error}', file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        with ignore_interrupts():
            print('\nCancelled.', file=sys.stderr)
        return 130


if __name__ == '__main__':
    raise SystemExit(main())
