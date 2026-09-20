"""Best-effort host and connected Frida version diagnostics."""

import logging
import re
import subprocess
import threading
from typing import Callable

import frida

from tools.setup_frida import resolve_adb
from Helpers.AutoLogging import log_captured_output, run_logged_subprocess


DIAGNOSTIC_TIMEOUT = 2.0
VERSION_PATTERN = re.compile(r'^\d+(?:\.\d+){2}(?:[-+][0-9A-Za-z.-]+)?$')
SERVER_VERSION_SCRIPT = "rpc.exports = { getVersion() { return Frida.version; } };"
LOGGER = logging.getLogger(__name__)


def _normalise_version(value):
    """Return a normal Frida version string, or raise for unusable RPC data."""
    if not isinstance(value, str):
        raise ValueError('Frida version was not a string')
    version = value.strip()
    if not VERSION_PATTERN.fullmatch(version):
        raise ValueError(f'Frida version was malformed: {value!r}')
    return version


def _run_cancellable(operation: Callable[[], object], timeout=DIAGNOSTIC_TIMEOUT):
    """Run one synchronous Frida operation with a bounded cancellation timer."""
    cancellable = frida.Cancellable()
    timer = threading.Timer(timeout, cancellable.cancel)
    timer.daemon = True
    try:
        with cancellable:
            timer.start()
            return operation()
    finally:
        timer.cancel()


# ------------------------------------------------------------------------------
# HOST ADB CLIENT
# This is optional diagnostics only. It never runs an Android command or changes
# the resolver's PATH/venv fallback behavior.
# ------------------------------------------------------------------------------
def report_adb_version(logger: logging.Logger):
    """Log the host ADB client build when the executable is available."""
    try:
        adb = resolve_adb(None)
    except Exception as error:
        logger.info(
            'Optional ADB client diagnostics unavailable; continuing without ADB version: %s',
            error,
        )
        return None

    try:
        result = run_logged_subprocess(
            [adb, 'version'],
            text=True,
            capture_output=True,
            timeout=DIAGNOSTIC_TIMEOUT,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        log_captured_output(error)
        logger.info(
            'Optional ADB client diagnostics unavailable; continuing without ADB version (%s): %s',
            adb,
            error,
        )
        return None

    log_captured_output(result)
    output = '\n'.join(part for part in (result.stdout or '', result.stderr or '') if part)
    protocol_match = re.search(r'^Android Debug Bridge version\s+(\S+)', output, re.MULTILINE)
    build_match = re.search(r'^Version\s+(\S+)', output, re.MULTILINE)
    if result.returncode != 0 or protocol_match is None:
        detail = output.strip() or f'exit status {result.returncode}'
        logger.info(
            'Optional ADB client diagnostics unavailable; continuing without ADB version (%s): %s',
            adb,
            detail,
        )
        return None

    protocol_version = protocol_match.group(1)
    client_version = build_match.group(1) if build_match is not None else protocol_version
    if build_match is not None:
        logger.info(
            'ADB client %s (%s; protocol %s)',
            client_version,
            adb,
            protocol_version,
        )
    else:
        logger.info('ADB client %s (%s)', client_version, adb)
    return client_version


# ------------------------------------------------------------------------------
# CONNECTED FRIDA SERVER
# Frida.version is evaluated in the remote system session. It is distinct from
# the host Python binding version and from any installed disk binary.
# ------------------------------------------------------------------------------
def _probe_server_version(usb_device):
    """Read Frida.version from the connected server's system session."""
    session = None
    try:
        def probe():
            nonlocal session
            session = usb_device.attach(0)
            script = session.create_script(SERVER_VERSION_SCRIPT)
            script.load()
            return _normalise_version(script.exports_sync.getVersion())

        return _run_cancellable(probe)
    finally:
        if session is not None:
            try:
                _run_cancellable(session.detach)
            except KeyboardInterrupt:
                raise
            except Exception as error:
                # Version reporting is diagnostic only. Preserve the probe result
                # or failure while still making a bounded cleanup attempt.
                LOGGER.debug(
                    'Frida diagnostic system session cleanup failed: %s',
                    error,
                )


def report_frida_versions(usb_device, logger: logging.Logger):
    """Log host bindings and the live connected server's distinct versions."""
    host_version = getattr(frida, '__version__', None)
    try:
        host_version = _normalise_version(host_version)
    except ValueError as error:
        host_version = None
        logger.info('Host Python frida version unavailable: %s', error)

    if host_version is not None:
        logger.info('Host Python frida %s', host_version)

    try:
        server_version = _probe_server_version(usb_device)
    except KeyboardInterrupt:
        raise
    except Exception as error:
        logger.info('Connected Frida server version unavailable; continuing: %s', error)
        return host_version, None

    logger.info('Connected Frida server %s', server_version)
    if host_version is not None and host_version != server_version:
        logger.warning(
            'Frida host/server version mismatch: host %s, server %s',
            host_version,
            server_version,
        )
    return host_version, server_version
