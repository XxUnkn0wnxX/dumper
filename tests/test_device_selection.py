import sys
import unittest
from types import SimpleNamespace
from unittest import mock

from Helpers import DeviceSelection
from Helpers.DeviceSelection import (
    FRIDA_CONNECTION_GUIDANCE,
    DeviceSelectionError,
    select_android_device,
)


# ---------------------------------------------------------------------------
# FAKE FRIDA DEVICES
# FakeDevice exposes the fields and probe behavior used by the selector, so
# discovery regressions run without a connected Android or iOS device.
# ---------------------------------------------------------------------------
_UNSET = object()


class FakeDevice:
    def __init__(self, device_id, name, os_id=None, device_type='usb', parameters=_UNSET):
        self.id = device_id
        self.name = name
        self.type = device_type
        self.parameters = {'os': {'id': os_id}} if parameters is _UNSET else parameters

    def query_system_parameters(self):
        if isinstance(self.parameters, Exception):
            raise self.parameters
        return self.parameters


class DeviceSelectionTests(unittest.TestCase):
    # Keep enumeration and metadata probes deterministic while exercising the
    # same selector entry point used by the command-line application.
    def select_from(self, devices, **kwargs):
        with mock.patch.object(DeviceSelection.frida, 'enumerate_devices', return_value=devices), \
                mock.patch.object(DeviceSelection, '_query_system_parameters',
                                  side_effect=lambda device, timeout=2.0: device.query_system_parameters()):
            return select_android_device(timeout=0, **kwargs)

    # OS metadata and candidate filtering must win over display names and
    # desktop or non-USB device entries.
    def test_iphone_before_android_selects_android(self):
        iphone = FakeDevice('iphone-1', 'Android-looking iPhone', 'ios')
        android = FakeDevice('android-1', 'Pixel', 'android')

        self.assertIs(self.select_from([iphone, android]), android)

    def test_android_looking_iphone_name_is_rejected(self):
        iphone = FakeDevice('phone-1', 'Android Phone', 'ios')

        with self.assertRaises(DeviceSelectionError):
            self.select_from([iphone])

    def test_ios_only_raises_actionable_error(self):
        with self.assertRaisesRegex(DeviceSelectionError, 'frida-ls-devices'):
            self.select_from([FakeDevice('ios-1', 'iPhone', 'ios')])

    def test_empty_discovery_explains_android_server_setup(self):
        with self.assertRaises(DeviceSelectionError) as error:
            self.select_from([])

        self.assertIn('No reachable, verified Android Frida device or server', str(error.exception))
        self.assertIn(FRIDA_CONNECTION_GUIDANCE, str(error.exception))

    def test_server_not_running_query_uses_connection_guidance(self):
        device = FakeDevice(
            'android-1',
            'Unavailable Pixel',
            parameters=RuntimeError('server not running'),
        )
        with self.assertRaises(DeviceSelectionError) as error:
            self.select_from([device])

        message = str(error.exception)
        self.assertIn(FRIDA_CONNECTION_GUIDANCE, message)
        self.assertNotIn('OS metadata must report os.id="android".', message)

    def test_enumeration_failure_uses_connection_guidance(self):
        with mock.patch.object(
                DeviceSelection.frida,
                'enumerate_devices',
                side_effect=RuntimeError('transport unavailable'),
        ):
            with self.assertRaises(DeviceSelectionError) as error:
                select_android_device(timeout=0)

        self.assertIn(FRIDA_CONNECTION_GUIDANCE, str(error.exception))

    def test_explicit_unreachable_metadata_uses_connection_guidance(self):
        device = FakeDevice(
            'android-1',
            'Unavailable Pixel',
            parameters=RuntimeError('server not running'),
        )
        with mock.patch.object(DeviceSelection.frida, 'get_device', return_value=device), \
                mock.patch.object(
                    DeviceSelection,
                    '_query_system_parameters',
                    side_effect=RuntimeError('server not running'),
                ):
            with self.assertRaises(DeviceSelectionError) as error:
                select_android_device('android-1')

        message = str(error.exception)
        self.assertIn('Could not verify reachable Android Frida device', message)
        self.assertIn(FRIDA_CONNECTION_GUIDANCE, message)
        self.assertNotIn('OS metadata must report os.id="android".', message)

    def test_missing_or_malformed_os_metadata_is_rejected(self):
        metadata = [{}, {'os': {}}, {'os': None}, None, {'os': []}]
        for parameters in metadata:
            with self.subTest(parameters=parameters):
                device = FakeDevice('device-1', 'Unknown', parameters=parameters)
                with self.assertRaises(DeviceSelectionError):
                    self.select_from([device])

    def test_desktop_linux_metadata_is_rejected(self):
        device = FakeDevice('desktop-1', 'Linux desktop', 'linux')

        with self.assertRaises(DeviceSelectionError):
            self.select_from([device])

    def test_query_failure_does_not_hide_valid_android(self):
        failed = FakeDevice('phone-1', 'Unavailable phone', parameters=RuntimeError('offline'))
        android = FakeDevice('android-1', 'Pixel', 'android')

        with mock.patch.object(DeviceSelection.frida, 'enumerate_devices', return_value=[failed, android]), \
                mock.patch.object(DeviceSelection, '_query_system_parameters',
                                  side_effect=[RuntimeError('offline'), android.parameters]):
            self.assertIs(select_android_device(timeout=0), android)

    def test_multiple_android_devices_require_explicit_id(self):
        first = FakeDevice('android-1', 'Pixel A', 'android')
        second = FakeDevice('android-2', 'Pixel B', 'android')

        with self.assertRaisesRegex(DeviceSelectionError, 'android-1.*Pixel A.*android-2.*Pixel B'):
            self.select_from([first, second])

    # Explicit IDs use direct Frida lookup and still verify the selected OS
    # before any process scan or attachment can begin.
    def test_explicit_android_only_probes_selected_device(self):
        selected = FakeDevice('android-1', 'Pixel', 'android')

        with mock.patch.object(DeviceSelection.frida, 'get_device', return_value=selected) as get_device, \
                mock.patch.object(DeviceSelection.frida, 'enumerate_devices') as enumerate_devices, \
                mock.patch.object(DeviceSelection, '_query_system_parameters',
                                  return_value=selected.parameters) as query:
            self.assertIs(select_android_device('android-1'), selected)

        get_device.assert_called_once_with('android-1', timeout=1)
        enumerate_devices.assert_not_called()
        query.assert_called_once_with(selected)

    def test_explicit_ios_device_is_rejected(self):
        iphone = FakeDevice('ios-1', 'iPhone', 'ios')

        with mock.patch.object(DeviceSelection.frida, 'get_device', return_value=iphone), \
                mock.patch.object(DeviceSelection, '_query_system_parameters',
                                  return_value=iphone.parameters):
            with self.assertRaisesRegex(DeviceSelectionError, 'not a verified Android'):
                select_android_device('ios-1')

    def test_missing_explicit_id_is_informative(self):
        with mock.patch.object(DeviceSelection.frida, 'get_device',
                               side_effect=RuntimeError('not found')):
            with self.assertRaisesRegex(DeviceSelectionError, 'missing-id.*frida-ls-devices'):
                select_android_device('missing-id')

    def test_non_usb_devices_are_excluded(self):
        local = FakeDevice('local-1', 'Local', 'android', device_type='local')
        remote = FakeDevice('remote-1', 'Remote', 'android', device_type='remote')

        with mock.patch.object(DeviceSelection.frida, 'enumerate_devices', return_value=[local, remote]), \
                mock.patch.object(DeviceSelection, '_query_system_parameters') as query:
            with self.assertRaises(DeviceSelectionError):
                select_android_device(timeout=0)
        query.assert_not_called()

    # Discovery retries after an empty snapshot so a just-connected emulator
    # can be selected within the configured window.
    def test_discovery_retries_after_initially_empty_snapshot(self):
        android = FakeDevice('android-1', 'Emulator', 'android')
        with mock.patch.object(DeviceSelection.frida, 'enumerate_devices',
                               side_effect=[[], [android]]), \
                mock.patch.object(DeviceSelection, '_query_system_parameters',
                                  return_value=android.parameters), \
                mock.patch.object(DeviceSelection.time, 'monotonic',
                                  side_effect=[0.0, 0.1]), \
                mock.patch.object(DeviceSelection.time, 'sleep') as sleep:
            self.assertIs(select_android_device(timeout=1), android)
        sleep.assert_called_once()

    # A final bounded snapshot catches a device that appears while an earlier
    # candidate is being probed.
    def test_final_snapshot_catches_android_appearing_during_probe(self):
        iphone = FakeDevice('iphone-1', 'iPhone', 'ios')
        android = FakeDevice('android-1', 'Emulator', 'android')
        with mock.patch.object(DeviceSelection.frida, 'enumerate_devices',
                               side_effect=[[iphone], [iphone, android]]) as enumerate_devices, \
                mock.patch.object(DeviceSelection, '_query_system_parameters',
                                  side_effect=[iphone.parameters, android.parameters]) as query, \
                mock.patch.object(DeviceSelection.time, 'monotonic',
                                  side_effect=[0.0, 2.0]):
            self.assertIs(select_android_device(timeout=1), android)

        self.assertEqual(enumerate_devices.call_count, 2)
        self.assertEqual(query.call_count, 2)

    # Timed metadata probes must cancel their timer on both success and error.
    def test_os_probe_timer_is_cancelled(self):
        class FakeCancellable:
            def __init__(self):
                self.cancel_calls = 0

            def __enter__(self):
                return self

            def __exit__(self, *args):
                return False

            def cancel(self):
                self.cancel_calls += 1

        class FakeTimer:
            instances = []

            def __init__(self, interval, callback):
                self.interval = interval
                self.callback = callback
                self.daemon = False
                self.started = False
                self.cancelled = False
                self.__class__.instances.append(self)

            def start(self):
                self.started = True

            def cancel(self):
                self.cancelled = True

        cancellable = FakeCancellable()
        device = FakeDevice('android-1', 'Pixel', 'android')
        with mock.patch.object(DeviceSelection.frida, 'Cancellable', return_value=cancellable), \
                mock.patch.object(DeviceSelection.threading, 'Timer', FakeTimer):
            self.assertEqual(DeviceSelection._query_system_parameters(device, timeout=2), device.parameters)

        timer = FakeTimer.instances[-1]
        self.assertTrue(timer.started)
        self.assertTrue(timer.daemon)
        self.assertTrue(timer.cancelled)
        timer.callback()
        self.assertEqual(cancellable.cancel_calls, 1)

        failing_device = FakeDevice(
            'android-2', 'Unavailable Pixel', parameters=RuntimeError('probe failed')
        )
        with mock.patch.object(DeviceSelection.frida, 'Cancellable', return_value=cancellable), \
                mock.patch.object(DeviceSelection.threading, 'Timer', FakeTimer):
            with self.assertRaisesRegex(RuntimeError, 'probe failed'):
                DeviceSelection._query_system_parameters(failing_device, timeout=2)
        self.assertTrue(FakeTimer.instances[-1].cancelled)


# ---------------------------------------------------------------------------
# COMMAND-LINE INTEGRATION
# These checks prove selection failures stop before process enumeration or
# attachment, while an explicit device ID reaches the Device constructor.
# ---------------------------------------------------------------------------
class CommandLineIntegrationTests(unittest.TestCase):
    def setUp(self):
        # Keep optional version diagnostics isolated from the selector tests.
        for name in ('report_adb_version', 'report_frida_versions', 'launch_test_page'):
            patcher = mock.patch(f'dump_keys.{name}')
            self.addCleanup(patcher.stop)
            patcher.start()

    def test_device_id_is_forwarded_before_process_scan(self):
        fake_device = mock.Mock(name='device')
        fake_device.name = 'Pixel'
        fake_device.usb_device.id = 'android-1'
        fake_device.usb_device.enumerate_processes.return_value = [
            SimpleNamespace(name='drm_process')
        ]
        fake_device.find_widevine_process.return_value = ['libwvhidl.so']
        fake_device.hook_to_process.return_value = mock.Mock()

        with mock.patch.object(sys, 'argv', ['dump_keys.py', '--device-id', 'android-1']), \
                mock.patch('dump_keys.Device', return_value=fake_device) as device_class:
            import dump_keys
            dump_keys.main()

        device_class.assert_called_once_with('', 'auto', ['libwvaidl.so', 'libwvhidl.so'], 'android-1')
        fake_device.usb_device.enumerate_processes.assert_called_once_with()
        fake_device.hook_to_process.assert_called_once_with('drm_process', 'libwvhidl.so')

    def test_selection_failure_exits_before_process_scan(self):
        with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                mock.patch('dump_keys.Device', side_effect=DeviceSelectionError('selection failed')) as device_class, \
                mock.patch('argparse.ArgumentParser.error', side_effect=SystemExit(2)) as parser_error:
            import dump_keys
            with self.assertRaises(SystemExit):
                dump_keys.main()

        device_class.assert_called_once()
        parser_error.assert_called_once_with('selection failed')

    def test_real_device_constructor_rejects_explicit_iphone_before_process_scan(self):
        iphone = FakeDevice('ios-1', 'iPhone', 'ios')
        iphone.enumerate_processes = mock.Mock()
        iphone.attach = mock.Mock()
        with mock.patch.object(sys, 'argv', ['dump_keys.py', '--device-id', 'ios-1']), \
                mock.patch.object(DeviceSelection.frida, 'get_device', return_value=iphone) as get_device, \
                mock.patch.object(DeviceSelection, '_query_system_parameters',
                                  return_value=iphone.parameters):
            import dump_keys
            with self.assertRaises(SystemExit) as exit_error:
                dump_keys.main()

        self.assertEqual(exit_error.exception.code, 2)
        get_device.assert_called_once_with('ios-1', timeout=1)
        iphone.enumerate_processes.assert_not_called()
        iphone.attach.assert_not_called()


# Running this file directly keeps the focused selector regressions easy to
# invoke during maintainer debugging.
if __name__ == '__main__':
    unittest.main()
