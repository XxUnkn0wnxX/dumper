"""Open a configured DRM test page in Chrome on the selected Android target.

This helper deliberately owns only the small amount of browser setup needed by
the dumper.  It does not start Frida, gain root, download anything, or claim
that a page has started playback.  The caller supplies the Frida device ID;
the same serial must be online in ADB before any Chrome command is attempted.
"""

from dataclasses import dataclass
import logging
from pathlib import Path
import re
import shlex
import subprocess
from typing import Iterable
from urllib.parse import urlsplit

from tools.setup_frida import SetupError, resolve_adb
from Helpers.AutoLogging import log_captured_output, run_logged_subprocess


# ------------------------------------------------------------------------------
# TEST PAGE AND REMOTE CHROME SETTINGS
# Keep one active URL beside the repository root so it can be edited without
# changing Python.  The flags file is intentionally in the same writable,
# non-root location used by the manual Chrome setup workflow.
# ------------------------------------------------------------------------------
DEFAULT_SITE_FILE = Path(__file__).resolve().parents[1] / 'drm_test_site.txt'
CHROME_PACKAGE = 'com.android.chrome'
CHROME_FLAGS_PATH = '/data/local/tmp/chrome-command-line'
COMMAND_TIMEOUT = 5
_MISSING_MARKER = '__DUMPER_CHROME_FLAGS_MISSING__'
_EXISTS_MARKER = '__DUMPER_CHROME_FLAGS_EXISTS__'
_SYMLINK_MARKER = '__DUMPER_CHROME_FLAGS_SYMLINK__'
_ERROR_MARKERS = ('Error:', 'SecurityException', 'Exception occurred')
_CURRENT_FOCUS_LINE = re.compile(r'^\s*mCurrentFocus\s*=\s*(?P<window>.+?)\s*$')
_FOCUSED_WINDOW = re.compile(
    r'^Window\{[^}\n]*\bu\d+\s+'
    r'(?P<package>[A-Za-z0-9_]+(?:\.[A-Za-z0-9_]+)*)/(?P<activity>[^\s}]+)\}$'
)

# Keep the browser policy in data so a verified compatibility addition is a
# small, reviewable change.  Scalar switches are compared by their name before
# ``=``; their values below are the exact tokens written to Chrome.
_MANAGED_SCALAR_FLAGS = (
    '--disable-fre',
    '--no-first-run',
    '--autoplay-policy=no-user-gesture-required',
    '--disable-startup-promos-for-testing',
    '--propagate-iph-for-testing',
    '--disable-default-browser-promo',
)

# FeatureList consumes each switch as one comma-separated value.  Keep the
# feature entry, including its parameter syntax, in the policy data.  The
# NotificationPermissionVariant parameter limits permission-request prompts;
# it does not grant or revoke an Android permission.
_MANAGED_ENABLED_FEATURES = (
    'NotificationPermissionVariant:permission_request_max_count/0',
    'DisablePrivacySandboxPrompts',
)
_MANAGED_DISABLED_FEATURES: tuple[str, ...] = ()
_FEATURE_SWITCHES = ('--enable-features', '--disable-features')


class BrowserSetupError(RuntimeError):
    """A browser preflight, flags, or launch operation could not complete."""


@dataclass(frozen=True)
class _AdbDevice:
    serial: str
    state: str


@dataclass(frozen=True)
class _ChromeFlag:
    """One Chrome flags-file token, retaining both raw and parsed forms."""

    raw: str
    value: str


# ------------------------------------------------------------------------------
# ACTIVE SITE CONFIGURATION
# Only complete-line comments are removed.  In particular, URL fragments and
# any other content after a URL's '#' remain part of the URL being opened.
# ------------------------------------------------------------------------------
def _valid_https_url(value: str) -> bool:
    """Return whether *value* is a safe, host-bearing HTTPS URL."""
    if not value or any(character.isspace() or ord(character) < 32 or ord(character) == 127
                         for character in value):
        return False
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        # Accessing ``port`` validates malformed/non-numeric ports.
        port = parsed.port
    except ValueError:
        return False
    if parsed.scheme.lower() != 'https' or not hostname:
        return False
    if parsed.username is not None or parsed.password is not None:
        return False
    if parsed.netloc.endswith(':'):
        return False
    return port is None or 1 <= port <= 65535


def read_test_site(site_file=DEFAULT_SITE_FILE, logger=None) -> str | None:
    """Read exactly one valid HTTPS URL from the active site file.

    Blank lines and whole-line comments are ignored.  More than one active
    line is an explicit configuration error: this helper never silently picks
    a fallback URL.  The separate reference list is documentation only and is
    never read here.
    """
    logger = logger or logging.getLogger(__name__)
    path = Path(site_file)
    try:
        # utf-8-sig accepts ordinary UTF-8 and removes an optional BOM only at
        # the beginning of the file.
        lines = path.read_text(encoding='utf-8-sig').splitlines()
    except (OSError, UnicodeError) as error:
        logger.warning('Cannot read active DRM test site file %s: %s', path, error)
        return None

    active_lines: list[tuple[int, str]] = []
    for line_number, line in enumerate(lines, 1):
        value = line.strip()
        if not value or value.startswith('#'):
            continue
        active_lines.append((line_number, value))

    if len(active_lines) != 1:
        logger.warning(
            'Active DRM test site file %s must contain exactly one non-comment URL; found %d',
            path,
            len(active_lines),
        )
        return None

    line_number, value = active_lines[0]
    if not _valid_https_url(value):
        logger.warning('Ignoring invalid DRM test URL on line %d: %s', line_number, value)
        return None
    return value


# ------------------------------------------------------------------------------
# BOUNDED ADB COMMANDS
# Every remote operation is one argument after ``adb shell``.  ``shlex.join``
# quotes dynamic values, including URLs containing fragments or shell syntax;
# host-side subprocess execution never invokes a shell.
# ------------------------------------------------------------------------------
def _run_host(command: list[str], purpose: str, *, input_text: str | None = None):
    try:
        result = run_logged_subprocess(
            command,
            input=input_text,
            text=True,
            capture_output=True,
            timeout=COMMAND_TIMEOUT,
            check=False,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        log_captured_output(error)
        raise BrowserSetupError(f'{purpose}: {error}') from error
    log_captured_output(result)
    return result


def _adb_shell(adb: str, serial: str, remote_command: str, purpose: str,
               *, input_text: str | None = None):
    return _run_host(
        [adb, '-s', serial, 'shell', remote_command],
        purpose,
        input_text=input_text,
    )


def _combined_output(result) -> str:
    return '\n'.join(
        value for value in (getattr(result, 'stdout', '') or '', getattr(result, 'stderr', '') or '')
        if value
    )


def _require_success(result, purpose: str):
    output = _combined_output(result)
    if getattr(result, 'returncode', 1) or any(marker in output for marker in _ERROR_MARKERS):
        detail = output.strip()
        suffix = f': {detail}' if detail else ''
        raise BrowserSetupError(f'{purpose} failed{suffix}')
    return output


def _parse_adb_devices(output: str) -> list[_AdbDevice]:
    """Parse ``adb devices -l`` without treating offline rows as usable."""
    devices: list[_AdbDevice] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or line.startswith('List of devices attached') or line.startswith('*'):
            continue
        fields = line.split()
        if len(fields) >= 2:
            devices.append(_AdbDevice(fields[0], fields[1]))
    return devices


def _require_matching_device(adb: str, device_id: str, logger):
    result = _run_host(
        [adb, 'devices', '-l'],
        'Listing Android devices',
    )
    output = _require_success(result, 'Listing Android devices')
    match = next((device for device in _parse_adb_devices(output)
                  if device.serial == device_id), None)
    if match is None or match.state != 'device':
        state = match.state if match is not None else 'not found'
        raise BrowserSetupError(
            f'Frida device {device_id!r} is not an online ADB device ({state}). '
            'Connect and authorize the same device before opening a DRM test page.'
        )
    logger.info('Using matching online ADB device %s', device_id)


# ------------------------------------------------------------------------------
# CHROME FLAGS
# Read and rewrite only the flags needed for deterministic DRM testing.  Chrome
# parses this file with its own quoted-argument tokenizer rather than a POSIX
# shell, so unrelated raw tokens (including user-agent flags) retain their
# exact spelling, order, backslashes, and quoting.
# ------------------------------------------------------------------------------
def _flags_read_command() -> str:
    path = shlex.quote(CHROME_FLAGS_PATH)
    missing = shlex.quote(_MISSING_MARKER)
    exists = shlex.quote(_EXISTS_MARKER)
    symlink = shlex.quote(_SYMLINK_MARKER)
    return (
        f'if test -L {path}; then printf "%s\\n" {symlink}; '
        f'elif test -e {path}; then printf "%s\\n" {exists}; cat -- {path}; '
        f'else printf "%s\\n" {missing}; fi'
    )


def _read_chrome_flags(adb: str, serial: str):
    result = _adb_shell(adb, serial, _flags_read_command(), 'Reading Chrome flags')
    output = _require_success(result, 'Reading Chrome flags').replace('\r\n', '\n')
    first_line, separator, remainder = output.partition('\n')
    if first_line == _MISSING_MARKER:
        return []
    if first_line == _SYMLINK_MARKER:
        raise BrowserSetupError(f'Refusing symlinked Chrome flags path {CHROME_FLAGS_PATH}')
    if first_line != _EXISTS_MARKER or not separator:
        raise BrowserSetupError(f'Chrome flags path {CHROME_FLAGS_PATH} could not be read')
    return _parse_chrome_flags(remainder)


def _parse_chrome_flags(content: str) -> list[_ChromeFlag]:
    """Tokenize Chrome flags while retaining each token's original spelling.

    Follow Chromium's CommandLine.java ``tokenizeQuotedArguments``: either
    quote style can enclose a token, and a backslash escapes a quote only when
    that quote could open or close the current quoted section. Other
    backslashes and shell-looking characters remain literal. Reject unmatched
    quotes so a rewrite cannot accidentally absorb the appended flags.
    """
    tokens: list[_ChromeFlag] = []
    raw_start: int | None = None
    value_parts: list[str] = []
    current_quote: str | None = None
    for index, character in enumerate(content):
        if character.isspace() and current_quote is None:
            if raw_start is not None:
                tokens.append(_ChromeFlag(content[raw_start:index], ''.join(value_parts)))
                raw_start = None
                value_parts = []
            continue

        if raw_start is None:
            raw_start = index
        if ((current_quote is None and character in ('"', "'"))
                or character == current_quote):
            if value_parts and value_parts[-1] == '\\':
                value_parts[-1] = character
            else:
                current_quote = character if current_quote is None else None
        else:
            value_parts.append(character)

    if current_quote is not None:
        raise BrowserSetupError('Chrome flags contain an unterminated quote')
    if raw_start is not None:
        tokens.append(_ChromeFlag(content[raw_start:], ''.join(value_parts)))
    return tokens


def _feature_base(entry: str) -> str:
    """Return a feature name without override, trial, or parameter syntax."""
    value = entry.strip()
    if value.startswith('*'):
        value = value[1:]
    # Chromium parses feature parameters first, then an optional dot group,
    # then a study override after ``<``.  All of those forms still belong to
    # the same managed feature identity.
    value = value.split(':', 1)[0]
    value = value.split('.', 1)[0]
    return value.split('<', 1)[0]


def _feature_entries(value: str | None) -> list[str]:
    """Split one effective Chrome feature-switch value into unique entries."""
    if not value:
        return []
    entries: list[str] = []
    seen: set[str] = set()
    for entry in value.split(','):
        if not entry.strip() or entry in seen:
            continue
        entries.append(entry)
        seen.add(entry)
    return entries


def _chrome_quote_feature_value(value: str) -> str:
    """Quote a reconstructed feature value for Chromium's tokenizer.

    ``shlex.quote`` uses POSIX shell rules, which are not Chrome's rules.  A
    double-quoted Chrome fragment preserves spaces and literal quotes; trailing
    backslashes stay outside the closing quote so they cannot escape it.
    """
    if not any(character.isspace() or character in ('"', "'") for character in value):
        return value

    trailing = len(value) - len(value.rstrip('\\'))
    core = value[:-trailing] if trailing else value
    encoded = ['"']
    for character in core:
        if character == '"':
            # Inside a double-quoted Chrome fragment, a backslash before a
            # quote makes that quote literal and keeps the quoted section open.
            encoded.extend(('\\', '"'))
        else:
            encoded.append(character)
    encoded.append('"')
    if trailing:
        encoded.append('\\' * trailing)
    return ''.join(encoded)


def _feature_flag(switch: str, entries: Iterable[str]) -> _ChromeFlag:
    """Build one switch and retain the parsed value alongside its raw token."""
    value = f'{switch}={",".join(entries)}'
    raw_value = _chrome_quote_feature_value(value.partition('=')[2])
    raw = f'{switch}={raw_value}'
    return _ChromeFlag(raw, value)


def _merge_chrome_flags(existing: Iterable[_ChromeFlag]) -> list[_ChromeFlag]:
    """Preserve unrelated options while applying the verified browser policy.

    Chromium's command-line switch map uses the last occurrence of a repeated
    switch.  We therefore retain only the last pre-``--`` feature switch value
    before filtering entries; this preserves the effective unrelated features
    without accidentally re-enabling an earlier, shadowed value.
    """
    managed_scalars = {
        policy.partition('=')[0] for policy in _MANAGED_SCALAR_FLAGS
    }
    managed_features = {
        _feature_base(entry)
        for entry in (*_MANAGED_ENABLED_FEATURES, *_MANAGED_DISABLED_FEATURES)
    }
    original = list(existing)
    # Chrome consumes argv[0] as the executable name. Keep that placeholder,
    # and put managed switches before any end-of-options marker.
    flags = original[:1] or [_ChromeFlag('_', '_')]
    tail: list[_ChromeFlag] = []
    effective_features: dict[str, str | None] = {switch: None for switch in _FEATURE_SWITCHES}
    for index, flag in enumerate(original[1:], 1):
        if flag.value == '--':
            tail = original[index:]
            break
        switch, separator, switch_value = flag.value.partition('=')
        if switch in effective_features:
            # Repeated feature switches have last-value-wins semantics in
            # Chromium's command-line switch map.
            effective_features[switch] = switch_value if separator else ''
            continue
        if switch in managed_scalars:
            continue
        flags.append(flag)

    flags.extend(_ChromeFlag(value, value) for value in _MANAGED_SCALAR_FLAGS)

    for switch, managed_entries in (
        ('--enable-features', _MANAGED_ENABLED_FEATURES),
        ('--disable-features', _MANAGED_DISABLED_FEATURES),
    ):
        entries = [
            entry for entry in _feature_entries(effective_features[switch])
            if _feature_base(entry) not in managed_features
        ]
        entries.extend(entry for entry in managed_entries if entry not in entries)
        if entries:
            flags.append(_feature_flag(switch, entries))
    return flags + tail


def _serialize_chrome_flags(flags: Iterable[_ChromeFlag]) -> str:
    return ' '.join(flag.raw for flag in flags) + '\n'


def _write_flags_command() -> str:
    path = shlex.quote(CHROME_FLAGS_PATH)
    symlink = shlex.quote(_SYMLINK_MARKER)
    return (
        f'if test -L {path}; then printf "%s\\n" {symlink}; exit 1; fi; '
        f'cat > {path} && chmod 0644 {path}'
    )


def _configure_chrome(adb: str, serial: str, logger) -> None:
    # Parse and merge before selecting Chrome as the persistent debug app.  A
    # malformed flags file must not leave a device with a changed debug target.
    flags = _read_chrome_flags(adb, serial)
    merged = _merge_chrome_flags(flags)
    serialized = _serialize_chrome_flags(merged)

    set_debug = shlex.join(('am', 'set-debug-app', '--persistent', CHROME_PACKAGE))
    result = _adb_shell(adb, serial, set_debug, 'Selecting Chrome as the debug app')
    _require_success(result, 'Selecting Chrome as the debug app')

    result = _adb_shell(
        adb,
        serial,
        _write_flags_command(),
        'Writing Chrome flags',
        input_text=serialized,
    )
    _require_success(result, 'Writing Chrome flags')
    logger.info('Configured Chrome flags for DRM test playback')


# ------------------------------------------------------------------------------
# PUBLIC LAUNCHER
# Preflight all local configuration and Chrome readiness before force-stopping
# or starting Chrome.  The public boundary turns expected setup failures into
# an actionable warning and lets the dumper continue; Ctrl+C remains an
# operator interruption and is deliberately re-raised.
# ------------------------------------------------------------------------------
def launch_test_page(device_id: str, logger, *, site_file=DEFAULT_SITE_FILE) -> bool:
    """Open the one configured DRM test URL in Chrome on *device_id*."""
    try:
        url = read_test_site(site_file, logger)
        if url is None:
            return False
        logger.info('Selected DRM test URL: %s', url)

        adb = resolve_adb(None)
        _require_matching_device(adb, device_id, logger)

        path_result = _adb_shell(
            adb,
            device_id,
            shlex.join(('pm', 'path', CHROME_PACKAGE)),
            'Checking Chrome installation',
        )
        path_output = _require_success(path_result, 'Checking Chrome installation')
        if not any(line.strip().startswith('package:') for line in path_output.splitlines()):
            raise BrowserSetupError(
                'Chrome is not installed on the selected Android device; install or enable '
                'com.android.chrome and retry.'
            )

        enabled_result = _adb_shell(
            adb,
            device_id,
            shlex.join(('pm', 'list', 'packages', '-e', CHROME_PACKAGE)),
            'Checking whether Chrome is enabled',
        )
        enabled_output = _require_success(enabled_result, 'Checking whether Chrome is enabled')
        if not any(line.strip() == f'package:{CHROME_PACKAGE}'
                   for line in enabled_output.splitlines()):
            raise BrowserSetupError(
                'Chrome is installed but disabled on the selected Android device; '
                'enable com.android.chrome and retry.'
            )

        _configure_chrome(adb, device_id, logger)

        stop_result = _adb_shell(
            adb,
            device_id,
            shlex.join(('am', 'force-stop', CHROME_PACKAGE)),
            'Stopping Chrome before launch',
        )
        _require_success(stop_result, 'Stopping Chrome before launch')

        # FLAG_ACTIVITY_NEW_TASK brings Chrome's task forward. Android's `am`
        # accepts this through -f; it has no --activity-new-task option.
        launch_args = ('am', 'start', '-a', 'android.intent.action.VIEW',
                       '-p', CHROME_PACKAGE)
        start_result = _adb_shell(
            adb,
            device_id,
            shlex.join((*launch_args, '-f', '0x10000000', '-d', url)),
            'Opening the DRM test URL',
        )
        try:
            _require_success(start_result, 'Opening the DRM test URL')
        except BrowserSetupError as error:
            # An explicit argument rejection happens before Android launches
            # the activity. Retry once without the optional focus flags. Do
            # not retry timeouts or transport failures: launch may have begun.
            rejection = str(error).lower()
            if not any(marker in rejection for marker in (
                'unknown option', 'unrecognized option', 'unsupported option',
                'unknown flag', 'unsupported flag', 'invalid flag',
            )):
                raise
            logger.warning(
                'Android rejected the Chrome focus option; trying one normal browser launch.'
            )
            start_result = _adb_shell(
                adb,
                device_id,
                shlex.join((*launch_args, '-d', url)),
                'Opening the DRM test URL without focus flags',
            )
            _require_success(start_result, 'Opening the DRM test URL without focus flags')
        logger.info(
            'Opened %s in Chrome on %s; autoplay is configured, but the page controls playback.',
            url,
            device_id,
        )
        return True
    except KeyboardInterrupt:
        raise
    except (BrowserSetupError, SetupError, OSError, subprocess.TimeoutExpired,
            UnicodeError, ValueError, TypeError) as error:
        logger.warning('Could not open DRM test page on %s: %s', device_id, error)
        return False


def _focused_window_package(output: str) -> tuple[str | None, str]:
    """Return the exact package of one well-formed ``mCurrentFocus`` window."""
    windows = [
        match.group('window').strip()
        for line in output.splitlines()
        if (match := _CURRENT_FOCUS_LINE.match(line)) is not None
    ]
    if not windows:
        return None, 'the current focus is absent'
    if len(windows) != 1:
        return None, 'the current focus is ambiguous'

    window = windows[0]
    if window.lower() in {'null', 'none'}:
        return None, 'the current focus is null'
    match = _FOCUSED_WINDOW.fullmatch(window)
    if match is None:
        return None, 'the current focus window is malformed'
    package = match.group('package')
    if 'permission' in package.lower():
        return package, 'an Android permission window is focused'
    if package != CHROME_PACKAGE:
        return package, f'the current focus belongs to {package}'
    return package, 'Chrome is focused'


def refresh_test_page(device_id: str, logger) -> bool:
    """Request one refresh from Chrome only when its window is focused.

    The focus snapshot is a short race window: Android may change focus after
    the dump and before the key event.  We deliberately do not retry, steal
    focus, relaunch Chrome, or claim that playback succeeded.
    """
    try:
        if not isinstance(device_id, str) or not device_id:
            raise ValueError('device ID must be a non-empty string')
        adb = resolve_adb(None)
        focus_result = _adb_shell(
            adb,
            device_id,
            shlex.join(('dumpsys', 'window')),
            'Checking the focused Android window',
        )
        focus_output = _require_success(focus_result, 'Checking the focused Android window')
        package, reason = _focused_window_package(focus_output)
        if package != CHROME_PACKAGE:
            logger.warning(f'Skipping Chrome page refresh on {device_id}: {reason}.')
            return False

        refresh_result = _adb_shell(
            adb,
            device_id,
            shlex.join(('input', 'keyevent', 'KEYCODE_F5')),
            'Requesting one Chrome page refresh',
        )
        _require_success(refresh_result, 'Requesting one Chrome page refresh')
        logger.info(
            'Sent one Chrome page-refresh request to %s; this does not guarantee playback.',
            device_id,
        )
        return True
    except KeyboardInterrupt:
        raise
    except (BrowserSetupError, SetupError, OSError, subprocess.TimeoutExpired,
            UnicodeError, ValueError, TypeError) as error:
        logger.warning('Could not refresh the Chrome page on %s: %s', device_id, error)
        return False


def close_test_browser(device_id: str, logger) -> bool:
    """Stop Chrome on the already-selected Android device during CLI exit.

    This is deliberately independent of browser setup and Frida state.  The
    caller already knows the selected serial, so no device discovery or retry
    can accidentally target another phone while capture files are unwinding.
    """
    try:
        if not isinstance(device_id, str) or not device_id:
            raise ValueError('device ID must be a non-empty string')
        adb = resolve_adb(None)
        result = _adb_shell(
            adb,
            device_id,
            shlex.join(('am', 'force-stop', CHROME_PACKAGE)),
            'Stopping Chrome after capture',
        )
        _require_success(result, 'Stopping Chrome after capture')
        logger.info('Closed Chrome on %s after capture.', device_id)
        return True
    except KeyboardInterrupt:
        raise
    except (BrowserSetupError, SetupError, OSError, subprocess.TimeoutExpired,
            UnicodeError, ValueError, TypeError) as error:
        logger.warning(
            'Could not close Chrome on %s: %s. Capture files are retained; exiting continues.',
            device_id,
            error,
        )
        return False
