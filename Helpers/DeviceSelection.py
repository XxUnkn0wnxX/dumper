"""Select a verified Android USB device exposed by Frida."""

import logging
import threading
import time

import frida


# ------------------------------------------------------------------------------
# DISCOVERY STATE
# OS_QUERY_TIMEOUT applies to each metadata probe, separately from the discovery
# polling window. The sentinel distinguishes an unprobed ID from a cached failure.
# ------------------------------------------------------------------------------
LOGGER = logging.getLogger(__name__)
OS_QUERY_TIMEOUT = 2.0
_UNCLASSIFIED = object()


# ------------------------------------------------------------------------------
# SELECTION ERRORS - surfaced by the CLI before any process scan or attachment.
# ------------------------------------------------------------------------------
class DeviceSelectionError(RuntimeError):
    """Raised when a verified Android Frida device cannot be selected."""


FRIDA_CONNECTION_GUIDANCE = (
    'Connect and authorize an Android device, ensure root frida-server is running, '
    'and keep the host Python frida version matched to the server. '
    'For an installed server, run "python tools/setup_frida.py --shell"; '
    'for a fresh setup, run "python tools/setup_frida.py". '
    'Run frida-ls-devices to list reachable IDs and pass one with --device-id.'
)


# ------------------------------------------------------------------------------
# DEVICE LABELS - tolerate incomplete metadata while building diagnostic messages.
# IDs identify devices for selection/caching; display names never establish the OS.
# ------------------------------------------------------------------------------
def _device_id(device):
    return getattr(device, 'id', None)


def _device_name(device):
    return getattr(device, 'name', '<unnamed>')


def _device_label(device):
    device_id = _device_id(device)
    name = _device_name(device)
    return f'{device_id or "<missing-id>"} ({name or "<unnamed>"})'


# ------------------------------------------------------------------------------
# CANCELLABLE OS PROBE
# A daemon timer requests Frida cancellation if a metadata query stalls. Cancel
# the timer on success and failure to avoid leaving a pending cancellation behind.
# ------------------------------------------------------------------------------
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


# ------------------------------------------------------------------------------
# ANDROID API METADATA
# Frida exposes Android's SDK level as a top-level `api-level` field. Keep this
# probe separate from OS classification so the selected device is queried once
# for the output label without adding an ADB dependency.
# ------------------------------------------------------------------------------
def _normalise_android_api_level(value):
    """Return a canonical positive API level, or None for malformed metadata."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return str(value) if value > 0 else None
    if isinstance(value, str):
        if not value or not value.isascii() or any(char < '0' or char > '9' for char in value):
            return None
        try:
            numeric_value = int(value)
        except ValueError:
            return None
        return str(numeric_value) if numeric_value > 0 else None
    return None


def get_android_api_level(device):
    """Return a selected device's SDK API label, or ``unknown`` on bad metadata.

    KeyboardInterrupt is intentionally allowed to propagate so Ctrl-C remains a
    cancellation rather than being converted into a recoverable output label.
    """
    try:
        parameters = _query_system_parameters(device)
    except Exception as error:
        LOGGER.warning(
            'Android API metadata query failed for Frida device %s: %s',
            _device_label(device),
            error,
        )
        return 'unknown'

    try:
        value = parameters['api-level']
    except (KeyError, TypeError):
        LOGGER.warning(
            'Android API metadata is missing or malformed for Frida device %s',
            _device_label(device),
        )
        return 'unknown'

    api_level = _normalise_android_api_level(value)
    if api_level is None:
        LOGGER.warning(
            'Android API metadata is missing or malformed for Frida device %s',
            _device_label(device),
        )
        return 'unknown'
    return api_level


# ------------------------------------------------------------------------------
# ANDROID CLASSIFICATION
# Accept only os.id == 'android'. A device name, USB transport, or Linux label is
# insufficient. Query/metadata failures are logged and excluded from selection.
# ------------------------------------------------------------------------------
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


# ------------------------------------------------------------------------------
# EXPLICIT DEVICE SELECTION - used when --device-id is supplied.
# Look up only the requested ID, then require USB transport and verified Android
# metadata. An explicit choice does not bypass either check.
# ------------------------------------------------------------------------------
def _select_explicit_device(device_id):
    if not device_id:
        raise DeviceSelectionError(
            'The --device-id value is empty. Run frida-ls-devices to find a USB device ID.'
        )

    try:
        device = frida.get_device(device_id, timeout=1)
    except Exception as error:
        raise DeviceSelectionError(
            f'Could not reach Frida device {device_id!r}. {FRIDA_CONNECTION_GUIDANCE}'
        ) from error

    if getattr(device, 'type', None) != 'usb':
        raise DeviceSelectionError(
            f'Frida device {device_id!r} is not a USB device. '
            'Run frida-ls-devices and choose an Android USB device.'
        )

    classification = _classify_android(device)
    if classification is None:
        raise DeviceSelectionError(
            f'Could not verify reachable Android Frida device {device_id!r}. '
            f'{FRIDA_CONNECTION_GUIDANCE}'
        )
    if classification is False:
        raise DeviceSelectionError(
            f'Frida device {device_id!r} is not a verified Android device. '
            'The OS metadata must report os.id="android".'
        )
    return device


# ------------------------------------------------------------------------------
# PUBLIC SELECTOR AND AUTOMATIC DISCOVERY
# Explicit IDs use the path above. Otherwise inspect USB devices in successive
# snapshots and return one verified Android target; multiple targets need an ID.
# ------------------------------------------------------------------------------
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

    # The discovery deadline controls polling, not the duration of an active OS
    # query. Per-device probes can extend elapsed time beyond this polling window.
    deadline = time.monotonic() + discovery_timeout
    classifications = {}
    final_snapshot_attempted = False

    while True:
        try:
            devices = frida.enumerate_devices()
        except Exception as error:
            LOGGER.warning('Frida device discovery failed: %s', error)
            devices = []

        # Rebuild candidates from the current snapshot so vanished devices are not
        # selected merely because an earlier snapshot classified them as Android.
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

            # Cache every result, including False and None. A slow or failed ID
            # is probed at most once during this selector invocation.
            classification = classifications.get(current_id, _UNCLASSIFIED)
            if classification is _UNCLASSIFIED:
                classification = _classify_android(device)
                classifications[current_id] = classification
                classified_new_device = True

            if classification is True:
                android_devices.append(device)

        # Inspect the whole snapshot before choosing; enumeration order must not
        # silently select between multiple verified Android devices.
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

    # The polling window and any final snapshot produced no verified target.
    raise DeviceSelectionError(
        'No reachable, verified Android Frida device or server was found. '
        f'{FRIDA_CONNECTION_GUIDANCE} '
        'Only devices whose OS metadata reports os.id="android" are accepted.'
    )
