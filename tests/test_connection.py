"""Focused tests for Frida transport monitoring and capture cleanup."""

from pathlib import Path
import threading
import tempfile
import unittest
from unittest import mock

import frida

import dump_keys
from Helpers import Connection as connection_module
from Helpers.Connection import CaptureConnection, CaptureDisconnected
from Helpers.Device import Device


class SignalSource:
    """Minimal Frida-like source with inspectable signal registration."""

    def __init__(self, *, is_lost=False, is_detached=False):
        self.is_lost = is_lost
        self.is_detached = is_detached
        self.listeners = {}
        self.on_calls = []
        self.off_calls = []

    def on(self, signal, callback):
        self.on_calls.append((signal, callback))
        self.listeners[signal] = callback

    def off(self, signal, callback):
        self.off_calls.append((signal, callback))
        if self.listeners.get(signal) is callback:
            del self.listeners[signal]

    def emit(self, signal, *args):
        callback = self.listeners.get(signal)
        if callback is not None:
            callback(*args)


class CaptureConnectionTests(unittest.TestCase):
    def setUp(self):
        self.device = SignalSource()
        self.session = SignalSource()
        self.script = mock.Mock()
        self.logger = mock.Mock()

    def make_connection(self):
        return CaptureConnection(
            self.device,
            ((self.session, self.script),),
            self.logger,
        )

    def test_selected_device_lost_signal_latches_disconnect_reason(self):
        connection = self.make_connection()
        self.device.emit('lost')

        with self.assertRaisesRegex(CaptureDisconnected, 'Android device/ADB connection disconnected'):
            connection.check(now=0)
        connection.close()

    def test_connection_terminated_and_detached_signals_report_capture_loss(self):
        for reason, expected in (
            ('connection-terminated', 'Frida/device connection disconnected'),
            ('device-lost', 'Frida/device connection disconnected'),
            ('application-requested', 'Capture session ended'),
        ):
            with self.subTest(reason=reason):
                connection = self.make_connection()
                self.session.emit('detached', reason, None)
                with self.assertRaisesRegex(CaptureDisconnected, expected):
                    connection.check(now=0)
                connection.close()

    def test_preexisting_device_or_session_loss_is_cleaned_during_construction(self):
        for source, attribute in (
            (self.device, 'is_lost'),
            (self.session, 'is_detached'),
        ):
            with self.subTest(attribute=attribute):
                setattr(source, attribute, True)
                with self.assertRaises(CaptureDisconnected):
                    self.make_connection()
                self.assertEqual(len(self.device.off_calls), 1)
                self.assertEqual(len(self.session.off_calls), 1)
                self.device.off_calls.clear()
                self.session.off_calls.clear()
                setattr(source, attribute, False)

    def test_no_capture_sessions_fail_cleanly_without_external_connection_work(self):
        with self.assertRaisesRegex(CaptureDisconnected, 'Capture session disconnected'):
            CaptureConnection(self.device, (), self.logger)
        self.assertEqual([signal for signal, _ in self.device.on_calls], ['lost'])
        self.assertEqual([signal for signal, _ in self.device.off_calls], ['lost'])

    def test_first_disconnect_reason_is_latched(self):
        connection = self.make_connection()
        connection._device_lost()
        connection._session_detached('connection-terminated')

        self.assertEqual(connection._reason, 'Android device/ADB connection disconnected')
        with self.assertRaisesRegex(CaptureDisconnected, 'Android device/ADB connection disconnected'):
            connection.check(now=0)
        connection.close()

    def test_close_unregisters_exact_callbacks_once_and_suppresses_late_signals(self):
        connection = self.make_connection()
        registered_device_callback = self.device.on_calls[0][1]
        registered_session_callback = self.session.on_calls[0][1]

        connection.close()
        connection.close()

        self.assertEqual(self.device.off_calls, [('lost', registered_device_callback)])
        self.assertEqual(self.session.off_calls, [('detached', registered_session_callback)])
        self.device.is_lost = True
        self.session.is_detached = True
        with mock.patch.object(connection_module, '_probe_agent') as heartbeat:
            connection.check(now=float('inf'))
        heartbeat.assert_not_called()
        self.assertIsNone(connection._reason)

    def test_heartbeat_uses_retained_script_exports_with_bounded_timeout(self):
        connection = self.make_connection()
        connection._next_heartbeat = 0
        with mock.patch.object(connection_module, '_probe_agent') as heartbeat:
            connection.check(now=10)

        heartbeat.assert_called_once_with(self.script, timeout=2.0)
        connection.close()

    def test_heartbeat_is_periodic_and_stops_after_timeout(self):
        connection = self.make_connection()
        connection._next_heartbeat = 5.0
        with mock.patch.object(connection_module, '_probe_agent') as heartbeat:
            connection.check(now=4.99)
            heartbeat.assert_not_called()
            connection.check(now=5.0)
            connection.check(now=9.99)
            heartbeat.assert_called_once()
            heartbeat.side_effect = frida.TimedOutError('agent timed out')
            with self.assertRaises(CaptureDisconnected):
                connection.check(now=10.0)
            with self.assertRaises(CaptureDisconnected):
                connection.check(now=20.0)
            self.assertEqual(heartbeat.call_count, 2)
        connection.close()

    def test_heartbeat_connection_and_rpc_failures_become_capture_disconnects(self):
        for error in (frida.TransportError('transport lost'), frida.core.RPCException('rpc lost')):
            with self.subTest(error=type(error).__name__):
                connection = self.make_connection()
                connection._next_heartbeat = 0
                with mock.patch.object(
                        connection_module, '_probe_agent', side_effect=error):
                    with self.assertRaises(CaptureDisconnected):
                        connection.check(now=10)
                connection.close()

    def test_heartbeat_unexpected_errors_and_interrupts_propagate(self):
        for error in (RuntimeError('unexpected'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                connection = self.make_connection()
                connection._next_heartbeat = 0
                with mock.patch.object(
                        connection_module, '_probe_agent', side_effect=error):
                    with self.assertRaises(type(error)):
                        connection.check(now=10)
                connection.close()

    def test_stalled_probe_times_out_without_leaving_a_worker(self):
        started = threading.Event()
        released = threading.Event()
        finished = threading.Event()
        workers = []

        def stalled_probe():
            workers.append(threading.current_thread())
            started.set()
            try:
                released.wait()
            finally:
                finished.set()

        self.script.list_exports_sync.side_effect = stalled_probe
        try:
            with self.assertRaises(frida.TimedOutError):
                connection_module._probe_agent(self.script, timeout=0.02)
        finally:
            released.set()
        self.assertTrue(started.is_set())
        self.assertTrue(finished.wait(1.0))
        for worker in workers:
            worker.join(1.0)
            self.assertFalse(worker.is_alive())

    def test_probe_completes_and_preserves_worker_errors(self):
        connection_module._probe_agent(self.script, timeout=1.0)
        self.script.list_exports_sync.assert_called_once_with()
        for error in (frida.TransportError('closed'), RuntimeError('bug'), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__):
                self.script.list_exports_sync.side_effect = error
                with self.assertRaises(type(error)):
                    connection_module._probe_agent(self.script, timeout=1.0)


class DeviceCleanupTests(unittest.TestCase):
    def test_close_is_idempotent_and_cleanup_failures_do_not_touch_saved_output(self):
        tmp_root = Path(__file__).resolve().parents[1] / '.tmp'
        tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='dumper-connection-',
                                          dir=tmp_root) as temporary:
            saved_file = Path(temporary) / 'private_key.pem'
            saved_file.write_bytes(b'key material')
            session = mock.Mock()
            device = Device.__new__(Device)
            device.logger = mock.Mock()
            device._capture_sessions = [(session, mock.Mock())]

            with mock.patch('Helpers.Device._run_cancellable', side_effect=RuntimeError('lost')) as cleanup:
                device.close()
                device.close()

            cleanup.assert_called_once_with(session.detach)
            self.assertEqual(saved_file.read_bytes(), b'key material')
            device.logger.debug.assert_called_once()


class DumperRunIntegrationTests(unittest.TestCase):
    def setUp(self):
        browser_patch = mock.patch.object(dump_keys, 'close_test_browser', return_value=True)
        self.addCleanup(browser_patch.stop)
        self.browser_close = browser_patch.start()

    @staticmethod
    def run_device():
        device_source = SignalSource()
        session = SignalSource()
        script = mock.Mock()
        device = mock.Mock()
        device.name = 'Android Emulator 5554'
        device.usb_device = device_source
        device.usb_device.id = 'emulator-5554'
        device.capture_sessions = ((session, script),)
        device_source.is_lost = False
        session.is_detached = False
        return device, device_source, session

    def test_run_exits_cleanly_on_selected_device_loss_and_retains_saved_file(self):
        device, device_source, session = self.run_device()
        tmp_root = Path(__file__).resolve().parents[1] / '.tmp'
        tmp_root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='dumper-run-',
                                          dir=tmp_root) as temporary:
            saved_file = Path(temporary) / 'client_id.bin'
            saved_file.write_bytes(b'client id')

            def lose_device(_seconds):
                device_source.is_lost = True

            with mock.patch.object(dump_keys, 'main', return_value=device), \
                    mock.patch.object(dump_keys.time, 'sleep', side_effect=lose_device), \
                    self.assertLogs('main', level='WARNING') as logs:
                result = dump_keys.run()

            self.assertEqual(result, 1)
            self.assertTrue(any(
                'Android Emulator 5554' in line
                and 'emulator-5554' in line
                and 'Exiting cleanly; saved files are retained' in line
                for line in logs.output
            ))
            device.close.assert_called_once_with()
            self.browser_close.assert_called_once()
            self.assertEqual(self.browser_close.call_args.args[0], 'emulator-5554')
            self.assertEqual(saved_file.read_bytes(), b'client id')
            self.assertEqual(device_source.listeners, {})
            self.assertEqual(session.listeners, {})

    def test_run_interruption_returns_zero_and_closes_connection_and_device(self):
        device, device_source, session = self.run_device()
        with mock.patch.object(dump_keys, 'main', return_value=device), \
                mock.patch.object(dump_keys.time, 'sleep', side_effect=KeyboardInterrupt):
            self.assertEqual(dump_keys.run(), 0)
        device.close.assert_called_once_with()
        self.assertEqual(device_source.listeners, {})
        self.assertEqual(session.listeners, {})

    def test_frida_session_disconnect_closes_chrome_while_device_remains_connected(self):
        device, device_source, session = self.run_device()
        with mock.patch.object(dump_keys, 'main', return_value=device), \
                mock.patch.object(dump_keys.time, 'sleep',
                                  side_effect=lambda _: session.emit('detached', 'connection-terminated', None)), \
                self.assertLogs('main', level='WARNING'):
            self.assertEqual(dump_keys.run(), 1)
        self.assertFalse(device_source.is_lost)
        device.close.assert_called_once_with()
        self.browser_close.assert_called_once()
        self.assertEqual(self.browser_close.call_args.args[0], 'emulator-5554')
        self.assertEqual(device_source.listeners, {})
        self.assertEqual(session.listeners, {})

    def test_already_disconnected_device_exits_before_waiting(self):
        device, device_source, session = self.run_device()
        device_source.is_lost = True
        with mock.patch.object(dump_keys, 'main', return_value=device), \
                mock.patch.object(dump_keys.time, 'sleep') as wait, \
                self.assertLogs('main', level='WARNING') as logs:
            self.assertEqual(dump_keys.run(), 1)
        self.assertIn('disconnected', '\n'.join(logs.output))
        wait.assert_not_called()
        device.close.assert_called_once_with()
        self.assertEqual(device_source.listeners, {})
        self.assertEqual(session.listeners, {})


if __name__ == '__main__':
    unittest.main()
