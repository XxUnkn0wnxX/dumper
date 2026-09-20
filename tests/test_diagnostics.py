import unittest
from unittest import mock

from Helpers import Diagnostics


class FakeScript:
    def __init__(self, version='17.17.0', load_error=None):
        self.version = version
        self.load_error = load_error
        self.loaded = False
        self.source = None
        self.exports_sync = mock.Mock()
        self.exports_sync.getVersion.return_value = version

    def load(self):
        if self.load_error is not None:
            raise self.load_error
        self.loaded = True


class FakeSession:
    def __init__(self, script=None, create_error=None, detach_error=None):
        self.script = script or FakeScript()
        self.create_error = create_error
        self.detach_error = detach_error
        self.detached = False

    def create_script(self, source):
        if self.create_error is not None:
            raise self.create_error
        self.script.source = source
        return self.script

    def detach(self):
        if self.detach_error is not None:
            raise self.detach_error
        self.detached = True


class FakeDevice:
    def __init__(self, session):
        self.session = session
        self.targets = []

    def attach(self, target):
        self.targets.append(target)
        return self.session


class DiagnosticsTests(unittest.TestCase):
    def test_adb_version_logs_native_client_and_selected_path(self):
        logger = mock.Mock()
        result = mock.Mock(
            returncode=0,
            stdout='Android Debug Bridge version 1.0.41\nVersion 37.0.1-15733141\n',
            stderr='',
        )
        with mock.patch.object(Diagnostics, 'resolve_adb', return_value='/venv/bin/adb') as resolve, \
                mock.patch.object(Diagnostics.subprocess, 'run', return_value=result) as run:
            self.assertEqual(Diagnostics.report_adb_version(logger), '37.0.1-15733141')

        resolve.assert_called_once_with(None)
        run.assert_called_once_with(
            ['/venv/bin/adb', 'version'],
            text=True,
            capture_output=True,
            timeout=2.0,
            check=False,
        )
        logger.info.assert_called_once_with(
            'ADB client %s (%s; protocol %s)',
            '37.0.1-15733141',
            '/venv/bin/adb',
            '1.0.41',
        )

    def test_adb_old_format_falls_back_to_protocol_version(self):
        logger = mock.Mock()
        result = mock.Mock(returncode=0, stdout='Android Debug Bridge version 1.0.41\n', stderr='')
        with mock.patch.object(Diagnostics, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(Diagnostics.subprocess, 'run', return_value=result):
            self.assertEqual(Diagnostics.report_adb_version(logger), '1.0.41')

        logger.info.assert_called_once_with('ADB client %s (%s)', '1.0.41', '/adb')

    def test_adb_unavailable_is_informational_and_does_not_probe_devices(self):
        logger = mock.Mock()
        with mock.patch.object(Diagnostics, 'resolve_adb', side_effect=OSError('adb missing')) as resolve, \
                mock.patch.object(Diagnostics.subprocess, 'run') as run:
            self.assertIsNone(Diagnostics.report_adb_version(logger))

        resolve.assert_called_once_with(None)
        run.assert_not_called()
        logger.info.assert_called_once()
        self.assertIn('Optional ADB client diagnostics unavailable', logger.info.call_args.args[0])

    def test_adb_command_failure_is_informational(self):
        logger = mock.Mock()
        result = mock.Mock(returncode=7, stdout='', stderr='adb failed')
        with mock.patch.object(Diagnostics, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(Diagnostics.subprocess, 'run', return_value=result):
            self.assertIsNone(Diagnostics.report_adb_version(logger))

        self.assertIn('Optional ADB client diagnostics unavailable', logger.info.call_args.args[0])

    def test_adb_timeout_is_informational(self):
        logger = mock.Mock()
        with mock.patch.object(Diagnostics, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(
                    Diagnostics.subprocess, 'run',
                    side_effect=Diagnostics.subprocess.TimeoutExpired(['/adb', 'version'], 2),
                ):
            self.assertIsNone(Diagnostics.report_adb_version(logger))
        self.assertIn('continuing without ADB version', logger.info.call_args.args[0])

    def test_frida_server_version_comes_from_system_session_and_detaches(self):
        logger = mock.Mock()
        script = FakeScript(version='17.17.0')
        session = FakeSession(script=script)
        device = FakeDevice(session)
        with mock.patch.object(Diagnostics.frida, '__version__', '17.18.0'), \
                mock.patch.object(Diagnostics, '_run_cancellable', side_effect=lambda operation: operation()), \
                mock.patch.object(Diagnostics.subprocess, 'run') as subprocess_run:
            self.assertEqual(
                Diagnostics.report_frida_versions(device, logger),
                ('17.18.0', '17.17.0'),
            )

        self.assertEqual(device.targets, [0])
        self.assertTrue(script.loaded)
        self.assertTrue(session.detached)
        self.assertIn('Frida.version', script.source)
        subprocess_run.assert_not_called()
        logger.warning.assert_called_once_with(
            'Frida host/server version mismatch: host %s, server %s',
            '17.18.0',
            '17.17.0',
        )

    def test_server_probe_failure_reports_unavailable_and_detaches(self):
        logger = mock.Mock()
        session = FakeSession(create_error=RuntimeError('server unavailable'))
        device = FakeDevice(session)
        with mock.patch.object(Diagnostics.frida, '__version__', '17.18.0'), \
                mock.patch.object(Diagnostics, '_run_cancellable', side_effect=lambda operation: operation()):
            self.assertEqual(Diagnostics.report_frida_versions(device, logger), ('17.18.0', None))

        self.assertTrue(session.detached)
        self.assertIn('Connected Frida server version unavailable', logger.info.call_args_list[-1].args[0])

    def test_malformed_server_version_is_unavailable_but_cleanup_runs(self):
        logger = mock.Mock()
        session = FakeSession(script=FakeScript(version='unknown'))
        device = FakeDevice(session)
        with mock.patch.object(Diagnostics.frida, '__version__', '17.18.0'), \
                mock.patch.object(Diagnostics, '_run_cancellable', side_effect=lambda operation: operation()):
            self.assertEqual(Diagnostics.report_frida_versions(device, logger), ('17.18.0', None))

        self.assertTrue(session.detached)
        self.assertIn('Connected Frida server version unavailable', logger.info.call_args_list[-1].args[0])

    def test_keyboard_interrupt_propagates_after_bounded_detach(self):
        logger = mock.Mock()
        session = FakeSession(script=FakeScript(load_error=KeyboardInterrupt()))
        device = FakeDevice(session)
        calls = []

        def invoke(operation):
            calls.append(operation)
            return operation()

        with mock.patch.object(Diagnostics.frida, '__version__', '17.18.0'), \
                mock.patch.object(Diagnostics, '_run_cancellable', side_effect=invoke):
            with self.assertRaises(KeyboardInterrupt):
                Diagnostics.report_frida_versions(device, logger)

        self.assertTrue(session.detached)
        self.assertEqual(len(calls), 2)

    def test_cleanup_failure_is_debugged_without_traceback(self):
        logger = mock.Mock()
        cleanup_error = RuntimeError('detach failed')
        session = FakeSession(detach_error=cleanup_error)
        device = FakeDevice(session)
        with mock.patch.object(Diagnostics.frida, '__version__', '17.18.0'), \
                mock.patch.object(Diagnostics, '_run_cancellable', side_effect=lambda operation: operation()), \
                mock.patch.object(Diagnostics.LOGGER, 'debug') as debug:
            self.assertEqual(Diagnostics.report_frida_versions(device, logger), ('17.18.0', '17.17.0'))

        debug.assert_called_once_with(
            'Frida diagnostic system session cleanup failed: %s',
            cleanup_error,
        )

    def test_cancellable_probe_starts_and_cancels_timer(self):
        events = []

        class Cancellable:
            def __enter__(self):
                events.append('enter')
                return self

            def __exit__(self, *unused):
                events.append('exit')
                return False

            def cancel(self):
                events.append('cancel')

        class Timer:
            def __init__(self, timeout, callback):
                self.timeout = timeout
                self.callback = callback
                self.daemon = False

            def start(self):
                events.append(('start', self.timeout))

            def cancel(self):
                events.append('timer-cancel')

        with mock.patch.object(Diagnostics.frida, 'Cancellable', return_value=Cancellable()), \
                mock.patch.object(Diagnostics.threading, 'Timer', Timer):
            self.assertEqual(Diagnostics._run_cancellable(lambda: 'ok'), 'ok')

        self.assertEqual(events, ['enter', ('start', 2.0), 'exit', 'timer-cancel'])

    def test_timeout_cancels_frida_and_cleans_up_timer_on_failure(self):
        # Trigger the deadline immediately, without waiting or contacting any
        # device. The operation sees a real cancelled Frida context.
        timer = mock.Mock()
        def make_timer(timeout, cancel):
            timer.start.side_effect = cancel
            return timer

        with mock.patch.object(Diagnostics.threading, 'Timer', side_effect=make_timer):
            with self.assertRaises(Diagnostics.frida.OperationCancelledError):
                Diagnostics._run_cancellable(
                    lambda: Diagnostics.frida.Cancellable.get_current().raise_if_cancelled(),
                )
        timer.cancel.assert_called_once_with()
        self.assertTrue(timer.daemon)


if __name__ == '__main__':
    unittest.main()
