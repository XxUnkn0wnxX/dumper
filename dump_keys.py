#!/usr/bin/env python3

import argparse
import time
import logging
from Helpers.Device import Device, HookError
from Helpers.DeviceSelection import DeviceSelectionError


CDM_VERSION_CHOICES = [
    'auto',
    '14.0.0',
    '15.0.0',
    '16.0.0',
    '16.1.0',
    '17.0.0',
]

logging.basicConfig(
    format='%(asctime)s - %(name)s - %(lineno)d - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %I:%M:%S %p',
    level=logging.DEBUG,
)

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

    logger = logging.getLogger("main")
    try:
        device = Device(dynamic_function_name, cdm_version, module_names, args.device_id)
    except (DeviceSelectionError, HookError) as error:
        parser.error(str(error))
        return
    logger.info('Connected to %s (%s)', device.name, device.usb_device.id)
    logger.info('Scanning all processes')

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


if __name__ == '__main__':
    main()
    while True:
        time.sleep(1000)
