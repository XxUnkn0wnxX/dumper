#!/usr/bin/env python3

# ------------------------------------------------------------------------------
# CLI ENTRY POINT
# Parse settings, select a verified Android device, and install the Frida hooks.
# Helpers/Device.py handles agent messages and output; Helpers/script.js runs the
# hooks and automatic signature detection inside the Android process.
# ------------------------------------------------------------------------------

import argparse
import time
import logging
import sys

from Helpers.CLI import ignore_interrupts, prepare_terminal
from Helpers.AutoSession import AutoSessionError, emit_event
from Helpers.Bootstrap import BootstrapError, bootstrap

# Repair a terminal left in raw mode before importing any Frida/ADB helpers.
# Direct imports used by tests remain side-effect free.
if __name__ == '__main__':
    try:
        prepare_terminal()
        bootstrap(__file__)
    except BootstrapError as error:
        print(f'error: {error}', file=sys.stderr)
        raise SystemExit(1)
    except KeyboardInterrupt:
        with ignore_interrupts():
            print('\nStopped by user.', file=sys.stderr)
        raise SystemExit(0)

from Helpers.Browser import DEFAULT_SITE_FILE, close_test_browser, launch_test_page, refresh_test_page

# Keep --help usable even when the venv is missing required packages. Only
# dependency import failures are deferred; broken project imports still surface.
DEPENDENCY_IMPORT_ERROR = None
DEPENDENCY_IMPORT_INTERRUPTED = False
FRIDA_CONNECTION_ERRORS = ()
CAPTURE_DISCONNECT_ERRORS = ()
try:
    import frida
    from Helpers.Connection import (
        CaptureConnection, CaptureDisconnected, FRIDA_CONNECTION_ERRORS,
    )
    CAPTURE_DISCONNECT_ERRORS = (CaptureDisconnected,)
    from Helpers.Device import Device, HookError
    from Helpers.Diagnostics import report_adb_version, report_frida_versions
    from Helpers.DeviceSelection import DeviceSelectionError, FRIDA_CONNECTION_GUIDANCE
except ImportError as error:
    if (error.name or '').split('.')[0] not in {'frida', 'Crypto', 'google', '_cffi_backend'}:
        raise
    DEPENDENCY_IMPORT_ERROR = str(error)
except KeyboardInterrupt:
    # The normal run() wrapper is not defined until this import block finishes.
    # Defer the cancellation marker so direct CLI execution still exits cleanly.
    if __name__ != '__main__':
        raise
    DEPENDENCY_IMPORT_INTERRUPTED = True


# ------------------------------------------------------------------------------
# REQUEST LAYOUT OPTIONS
# These labels select PrepareKeyRequest argument layouts, not Android or Frida
# versions. Keep manual labels aligned with manualLayouts in Helpers/script.js;
# automatic signature entries are maintained in that script's layout table.
# ------------------------------------------------------------------------------
CDM_VERSION_CHOICES = [
    'auto',
    '14.0.0',
    '15.0.0',
    '16.0.0',
    '16.1.0',
    '17.0.0',
]

# Shared log formatting also applies to the device and selection helpers.
logging.basicConfig(
    format='%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %I:%M:%S %p',
    level=logging.DEBUG,
)

# ------------------------------------------------------------------------------
# EXIT CLEANUP
# Release capture hooks, then stop Chrome through ADB on the same Android serial.
# Browser cleanup does not depend on Frida still being alive or a pair being saved.
# Callers suppress repeated interrupts while this bounded cleanup completes.
# ------------------------------------------------------------------------------
def _close_device_and_browser(device):
    device_id = device.usb_device.id
    try:
        device.close()
    finally:
        close_test_browser(device_id, logging.getLogger('main'))


# ------------------------------------------------------------------------------
# CAPTURE PROGRESS AND ONE-SHOT BROWSER RECOVERY
# The dumper owns the warning and refresh in both manual and full-auto runs.
# Publishing a status event lets the controller mirror it without another timer.
# ------------------------------------------------------------------------------
def _check_capture_progress(device):
    if device.warn_if_no_pair() is not True:
        return
    should_refresh = (
        getattr(device, 'browser_launched', False) is True
        and getattr(device, '_browser_refresh_attempted', False) is not True
        and getattr(device, '_matching_pair_save_attempted', False) is not True
        and device._has_verified_saved_pair() is not True
    )
    if should_refresh:
        # Consume the attempt before any status/ADB operation. A failed or
        # skipped refresh must never create an automatic refresh loop.
        device._browser_refresh_attempted = True
    emit_event(
        'no_pair_yet',
        device_id=device.usb_device.id,
        android_api=str(device.android_api_level),
        browser_refresh_requested=should_refresh,
    )
    # A capture callback may finish while the status event is being flushed.
    # Keep the attempt consumed but avoid refreshing after that completion.
    if (should_refresh
            and getattr(device, '_matching_pair_save_attempted', False) is not True
            and device._has_verified_saved_pair() is not True):
        refresh_test_page(device.usb_device.id, logging.getLogger('main'))


# ------------------------------------------------------------------------------
# STARTUP - argument parsing completes before any device interaction.
# main() returns the device after hook setup; run() monitors capture progress.
# ------------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description='Android Widevine L3 dumper.')
    parser.add_argument(
        '--cdm-version',
        choices=CDM_VERSION_CHOICES,
        help='PrepareKeyRequest layout override; auto detects the known layout from its signature (default: auto).',
        default='auto',
    )
    parser.add_argument('--device-id', help='The Frida USB device ID (see frida-ls-devices)')
    parser.add_argument('--function-name', help='The name of the function to hook to retrieve the private key.', default='')
    parser.add_argument('--module-name', 
        nargs='+',
        type=str,
        help='The names of the widevine `.so` modules',
        default=["libwvaidl.so", "libwvhidl.so"]
    )
    parser.add_argument(
        '--no-browser', action='store_true',
        help='Skip Chrome setup/navigation; Chrome still closes on capture exit.',
    )
    parser.add_argument(
        '--site-file', default=DEFAULT_SITE_FILE, metavar='PATH',
        help='Read the single test-page URL from this file (default: repo drm_test_site.txt).',
    )
    parser.add_argument(
        '--non-interactive', action='store_true',
        help='Internal option reserved for full_auto.py; omit this flag for manual runs.',
    )
    if DEPENDENCY_IMPORT_INTERRUPTED:
        raise KeyboardInterrupt
    args = parser.parse_args()
    if DEPENDENCY_IMPORT_ERROR is not None:
        parser.error(
            f'Cannot load a required Python dependency: {DEPENDENCY_IMPORT_ERROR}. '
            'Activate the dumper virtual environment and run '
            'python -m pip install -r requirements.txt, then retry.'
        )
        return

    dynamic_function_name = args.function_name
    cdm_version = args.cdm_version
    module_names = args.module_name
    if args.non_interactive and (cdm_version != 'auto' or dynamic_function_name):
        parser.error('--non-interactive requires --cdm-version auto and no --function-name')
        return

    # Device construction verifies the target OS and prepares the JavaScript agent.
    # Expected setup failures become argparse errors with a nonzero exit status.
    logger = logging.getLogger("main")
    report_adb_version(logger)
    try:
        device = Device(dynamic_function_name, cdm_version, module_names, args.device_id)
    except (DeviceSelectionError, HookError) as error:
        parser.error(str(error))
        return
    ready = False
    try:
        logger.info('Connected to %s (%s)', device.name, device.usb_device.id)
        report_frida_versions(device.usb_device, logger)
        logger.info('Scanning all processes')

        # Scan processes whose names contain 'drm', then try each requested library
        # found in them. A library's hook failure does not prevent trying another one.
        hooked_libraries = 0
        hook_errors = []
        for process in device.usb_device.enumerate_processes():
            if 'drm' in process.name:
                for library in device.find_widevine_process(process.name):
                    try:
                        device.hook_to_process(process.name, library)
                        hooked_libraries += 1
                    except HookError as error:
                        hook_errors.append(str(error))
                        logger.error('%s', error)
        # Require at least one initialized library before showing playback guidance.
        # Hook setup alone does not establish that a matching key pair was captured.
        if not hooked_libraries:
            if hook_errors:
                parser.error(
                    'No Widevine libraries were hooked. Hook failures: '
                    + '; '.join(hook_errors) + '. ' + FRIDA_CONNECTION_GUIDANCE
                )
            else:
                parser.error(
                    'No Widevine libraries were hooked. Check the target process '
                    'and --module-name values, then retry.'
                )
            return
        logger.info('Functions hooked; waiting for Widevine playback.')
        device.start_capture_wait()
        emit_event(
            'hooks_ready',
            device_id=device.usb_device.id,
            android_api=str(device.android_api_level),
            hooked_libraries=hooked_libraries,
        )
        # Launch only after a library is ready to capture. Browser setup is optional:
        # its helper reports expected ADB/Chrome errors while capture stays active.
        device.browser_launched = False
        if args.no_browser:
            logger.info(
                'Automatic browser launch disabled. Open a Widevine test page on '
                'the selected Android device; the configured URL is in %s.', args.site_file,
            )
        else:
            device.browser_launched = launch_test_page(
                device.usb_device.id, logger, site_file=args.site_file,
            ) is True
            if not device.browser_launched:
                logger.warning(
                    'Capture remains active. Open a Widevine test page manually on '
                    'the selected Android device; check %s for the configured URL.', args.site_file,
                )
        ready = True
        return device
    finally:
        if not ready:
            # A second Ctrl+C must not interrupt detachment while unwinding a
            # cancelled discovery, hook, or browser setup. Real cleanup errors
            # still propagate through this context.
            with ignore_interrupts():
                _close_device_and_browser(device)


# ------------------------------------------------------------------------------
# PROCESS LIFETIME
# Keep Python running after successful setup so Frida can deliver capture callbacks.
# Monitor transport/session health as well as capture progress while waiting.
# Tests call main() directly and therefore do not enter this wait loop.
# ------------------------------------------------------------------------------
def run():
    device = None
    connection = None
    try:
        # Imported callers do not pass through the __main__ bootstrap. Keep
        # terminal repair inside the same cancellation path for those callers.
        if __name__ != '__main__':
            prepare_terminal()
        device = main()
        if device is None:
            return 1
        connection = CaptureConnection(
            device.usb_device, device.capture_sessions, logging.getLogger('main'),
        )
        while True:
            time.sleep(1)
            connection.check()
            _check_capture_progress(device)
    except KeyboardInterrupt:
        with ignore_interrupts():
            logging.getLogger('main').info('Stopped by user.')
        return 0
    except AutoSessionError as error:
        logging.getLogger('main').error('%s. Capture stopped; saved files are retained.', error)
        return 1
    except CAPTURE_DISCONNECT_ERRORS as error:
        logging.getLogger('main').warning(
            'Capture stopped for %s (%s): %s. Exiting cleanly; saved files are retained. '
            'Reconnect the device, wait for its home screen, restart Frida if needed, '
            'then rerun the dumper.', device.name, device.usb_device.id, error,
        )
        return 1
    except FRIDA_CONNECTION_ERRORS as error:
        # Discovery can succeed just before the device/server disappears. Keep
        # expected Frida failures from scanning/attachment out of tracebacks,
        # while allowing unrelated programming errors to remain diagnosable.
        if isinstance(error, frida.ServerNotRunningError):
            reason = 'Frida server is not running or cannot be reached'
        elif isinstance(error, frida.TransportError):
            reason = 'Connection to the Android device or Frida server was lost'
        elif isinstance(error, frida.TimedOutError):
            reason = 'The Android device or Frida server did not respond in time'
        elif isinstance(error, frida.PermissionDeniedError):
            reason = 'Frida access to the Android device or process was denied'
        else:
            reason = 'Frida could not access the Android device or its processes'
        logging.getLogger('main').error(
            '%s: %s. %s', reason, error, FRIDA_CONNECTION_GUIDANCE,
        )
        return 1
    finally:
        # The first Ctrl+C is handled above; keep a repeated terminal interrupt
        # from abandoning listener/session cleanup or producing a traceback.
        with ignore_interrupts():
            try:
                if connection is not None:
                    connection.close()
            finally:
                if device is not None:
                    _close_device_and_browser(device)


if __name__ == '__main__':
    raise SystemExit(run())
