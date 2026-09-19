"""Select a verified Android USB device exposed by Frida."""

import logging
import threading
import time

import frida


LOGGER = logging.getLogger(__name__)
OS_QUERY_TIMEOUT = 2.0
_UNCLASSIFIED = object()


class DeviceSelectionError(RuntimeError):
    """Raised when a verified Android Frida device cannot be selected."""


def _device_id(device):
    return getattr(device, 'id', None)


def _device_name(device):
    return getattr(device, 'name', '<unnamed>')


def _device_label(device):
    device_id = _device_id(device)
    name = _device_name(device)
    return f'{device_id or "<missing-id>"} ({name or "<unnamed>"})'


def _query_system_parameters(device, timeout=OS_QUERY_TIMEOUT):
    """Query one device while allowing Frida to cancel a stalled request."""
    cancellable = frida.Cancellable()
    timer = threading.Timer(timeout, cancellable.cancel)
    timer.daemon = True
    try:
        with cancellable:
            timer.start()
            return device.query_system_parameters()
    finally:
        timer.cancel()


def _classify_android(device):
    """Return True for Android, False for another known OS, or None on error."""
    try:
        parameters = _query_system_parameters(device)
    except Exception as error:
        LOGGER.warning(
            'Skipping Frida device %s: OS metadata query failed (%s)',
            _device_label(device),
            error,
        )
        return None

    try:
        operating_system = parameters['os']
        operating_system_id = operating_system['id']
    except (KeyError, TypeError):
        LOGGER.warning(
            'Skipping Frida device %s: OS metadata is missing or malformed',
            _device_label(device),
        )
        return None

    if operating_system_id != 'android':
        LOGGER.warning(
            'Skipping Frida device %s: verified OS id is %r',
            _device_label(device),
            operating_system_id,
        )
        return False
    return True


def _select_explicit_device(device_id):
    if not device_id:
        raise DeviceSelectionError(
            'The --device-id value is empty. Run frida-ls-devices to find a USB device ID.'
        )

    try:
        device = frida.get_device(device_id, timeout=1)
    except Exception as error:
        raise DeviceSelectionError(
            f'Could not find Frida USB device {device_id!r}. '
            'Run frida-ls-devices and pass one of its IDs with --device-id.'
        ) from error

    if getattr(device, 'type', None) != 'usb':
        raise DeviceSelectionError(
            f'Frida device {device_id!r} is not a USB device. '
            'Run frida-ls-devices and choose an Android USB device.'
        )

    if _classify_android(device) is not True:
        raise DeviceSelectionError(
            f'Frida device {device_id!r} is not a verified Android device. '
            'The OS metadata must report os.id="android".'
        )
    return device


def select_android_device(device_id=None, timeout=1.0):
    """Return one verified Android USB Frida device.

    Without an explicit ID, startup discovery polls briefly and classifies all
    USB devices in each snapshot. Device IDs are classified at most once per
    invocation, including devices whose metadata cannot be verified.
    """
    if device_id is not None:
        return _select_explicit_device(device_id)

    try:
        discovery_timeout = max(0.0, float(timeout))
    except (TypeError, ValueError) as error:
        raise ValueError('timeout must be a non-negative number') from error

    deadline = time.monotonic() + discovery_timeout
    classifications = {}
    final_snapshot_attempted = False

    while True:
        try:
            devices = frida.enumerate_devices()
        except Exception as error:
            LOGGER.warning('Frida device discovery failed: %s', error)
            devices = []

        android_devices = []
        classified_new_device = False
        for device in devices:
            if getattr(device, 'type', None) != 'usb':
                continue

            current_id = _device_id(device)
            if not current_id:
                LOGGER.warning(
                    'Skipping Frida USB device %s: device ID is missing',
                    _device_label(device),
                )
                continue

            classification = classifications.get(current_id, _UNCLASSIFIED)
            if classification is _UNCLASSIFIED:
                classification = _classify_android(device)
                classifications[current_id] = classification
                classified_new_device = True

            if classification is True:
                android_devices.append(device)

        if len(android_devices) > 1:
            devices_description = ', '.join(
                _device_label(device) for device in android_devices
            )
            raise DeviceSelectionError(
                'Multiple verified Android USB devices found: '
                f'{devices_description}. Use --device-id to select one; '
                'run frida-ls-devices to list IDs.'
            )
        if android_devices:
            return android_devices[0]

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if classified_new_device and not final_snapshot_attempted:
                # A slow OS probe can finish after the discovery window while
                # another device becomes available. Give that new device one
                # bounded chance, without re-probing cached IDs.
                final_snapshot_attempted = True
                continue
            break
        time.sleep(min(0.05, remaining))

    raise DeviceSelectionError(
        'No verified Android USB device found. Start frida-server on an Android '
        'device, or run frida-ls-devices and select an ID with --device-id. '
        'Only devices whose OS metadata reports os.id="android" are accepted.'
    )
