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

from Helpers.Browser import DEFAULT_SITE_FILE, launch_test_page

# Keep --help usable even when the venv is missing required packages. Only
# dependency import failures are deferred; broken project imports still surface.
DEPENDENCY_IMPORT_ERROR = None
FRIDA_CONNECTION_ERRORS = ()
try:
    import frida
    FRIDA_CONNECTION_ERRORS = (
        frida.ServerNotRunningError,
        frida.TransportError,
        frida.TimedOutError,
        frida.PermissionDeniedError,
        frida.ProtocolError,
        frida.ProcessNotFoundError,
        frida.ProcessNotRespondingError,
        frida.InvalidOperationError,
        frida.NotSupportedError,
        frida.OperationCancelledError,
    )
    from Helpers.Device import Device, HookError
    from Helpers.Diagnostics import report_adb_version, report_frida_versions
    from Helpers.DeviceSelection import DeviceSelectionError, FRIDA_CONNECTION_GUIDANCE
except ImportError as error:
    if (error.name or '').split('.')[0] not in {'frida', 'Crypto', 'google', '_cffi_backend'}:
        raise
    DEPENDENCY_IMPORT_ERROR = str(error)


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
        help='Keep capturing without configuring or opening Chrome through ADB.',
    )
    parser.add_argument(
        '--site-file', default=DEFAULT_SITE_FILE, metavar='PATH',
        help='Read the single test-page URL from this file (default: repo drm_test_site.txt).',
    )
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

    # Device construction verifies the target OS and prepares the JavaScript agent.
    # Expected setup failures become argparse errors with a nonzero exit status.
    logger = logging.getLogger("main")
    report_adb_version(logger)
    try:
        device = Device(dynamic_function_name, cdm_version, module_names, args.device_id)
    except (DeviceSelectionError, HookError) as error:
        parser.error(str(error))
        return
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
    # Launch only after a library is ready to capture. Browser setup is optional:
    # its helper reports expected ADB/Chrome errors while capture stays active.
    if args.no_browser:
        logger.info(
            'Automatic browser launch disabled. Open a Widevine test page on '
            'the selected Android device; the configured URL is in %s.', args.site_file,
        )
    elif not launch_test_page(device.usb_device.id, logger, site_file=args.site_file):
        logger.warning(
            'Capture remains active. Open a Widevine test page manually on '
            'the selected Android device; check %s for the configured URL.', args.site_file,
        )
    return device


# ------------------------------------------------------------------------------
# PROCESS LIFETIME
# Keep Python running after successful setup so Frida can deliver capture callbacks.
# Check capture progress without changing the agent or its streamed output.
# Tests call main() directly and therefore do not enter this wait loop.
# ------------------------------------------------------------------------------
def run():
    try:
        device = main()
        while True:
            time.sleep(1)
            device.warn_if_no_pair()
    except KeyboardInterrupt:
        logging.getLogger('main').info('Stopped by user.')
        return 0
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


if __name__ == '__main__':
    raise SystemExit(run())
