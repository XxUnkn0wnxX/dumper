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
from Helpers.Device import Device, HookError
from Helpers.DeviceSelection import DeviceSelectionError


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
# main() returns after hook setup; the script entry point below keeps it alive.
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
    args = parser.parse_args()

    dynamic_function_name = args.function_name
    cdm_version = args.cdm_version
    module_names = args.module_name

    # Device construction verifies the target OS and prepares the JavaScript agent.
    # Expected setup failures become argparse errors with a nonzero exit status.
    logger = logging.getLogger("main")
    try:
        device = Device(dynamic_function_name, cdm_version, module_names, args.device_id)
    except (DeviceSelectionError, HookError) as error:
        parser.error(str(error))
        return
    logger.info('Connected to %s (%s)', device.name, device.usb_device.id)
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
                + '; '.join(hook_errors)
            )
        else:
            parser.error(
                'No Widevine libraries were hooked. Check the target process '
                'and --module-name values, then retry.'
            )
        return
    logger.info(
        'Functions hooked, now open either test site from your Android device!:\n'
        'https://bitmovin.com/demos/drm\n'
        'https://reference.dashif.org/dash.js/v4_latest/samples/drm/widevine.html'
    )


# ------------------------------------------------------------------------------
# PROCESS LIFETIME
# Keep Python running after successful setup so Frida can deliver capture callbacks.
# Tests call main() directly and therefore do not enter this wait loop.
# ------------------------------------------------------------------------------
if __name__ == '__main__':
    main()
    while True:
        time.sleep(1000)
