import logging
import builtins
import io
from pathlib import Path
import runpy
import signal
import subprocess
import sys
import unittest
from types import SimpleNamespace
from unittest import mock

import dump_keys
from Helpers.Device import Device, HookError


# ---------------------------------------------------------------------------
# HOOK SESSION LIFECYCLE
# The fixtures create only the Device state needed for a controlled Frida
# session, allowing cleanup and retained-session behavior to be tested locally.
# ---------------------------------------------------------------------------
class HookLifecycleTests(unittest.TestCase):
    def make_device(self, session):
        # Bypass hardware initialization and make attach return the supplied
        # session so each lifecycle stage can fail deterministically.
        device = Device.__new__(Device)
        device.logger = logging.getLogger('test.device')
        device.usb_device = mock.Mock()
        device.usb_device.attach.return_value = session
        device.frida_script = 'script'
        device.on_message = mock.Mock()
        return device

    # Every failed stage must detach the partially-created session and preserve
    # the library/process context in the reported HookError.
    def test_failed_session_is_detached_and_context_is_reported(self):
        for stage in ('create_script', 'load', 'rpc'):
            with self.subTest(stage=stage):
                session = mock.Mock()
                script = mock.Mock()
                session.create_script.return_value = script
                if stage == 'create_script':
                    session.create_script.side_effect = RuntimeError('create failed')
                elif stage == 'load':
                    script.load.side_effect = RuntimeError('load failed')
                else:
                    script.exports.hooklibfunctions.side_effect = RuntimeError('rpc failed')

                device = self.make_device(session)
                with self.assertRaisesRegex(HookError, 'libwvhidl.so.*drm_process'):
                    device.hook_to_process('drm_process', 'libwvhidl.so')
                session.detach.assert_called_once_with()

    def test_successful_session_is_returned_and_retained(self):
        session = mock.Mock()
        script = mock.Mock()
        session.create_script.return_value = script
        device = self.make_device(session)

        self.assertIs(device.hook_to_process('drm_process', 'libwvhidl.so'), session)

        session.detach.assert_not_called()
        self.assertEqual(device.capture_sessions, ((session, script),))
        script.on.assert_called_once_with('message', device.on_message)
        script.load.assert_called_once_with()
        script.exports.hooklibfunctions.assert_called_once_with('libwvhidl.so')

    def test_hook_interruption_releases_partial_session_without_wrapping(self):
        session = mock.Mock()
        session.create_script.return_value.load.side_effect = KeyboardInterrupt
        device = self.make_device(session)

        with self.assertRaises(KeyboardInterrupt):
            device.hook_to_process('drm_process', 'libwvhidl.so')

        session.detach.assert_called_once_with()
        self.assertEqual(device.capture_sessions, ())

    def test_failed_hook_detach_defers_interrupt_before_wrapping_error(self):
        session = mock.Mock()
        session.create_script.return_value.load.side_effect = RuntimeError('load failed')
        completed = []

        def detach():
            signal.raise_signal(signal.SIGINT)
            completed.append(True)

        session.detach.side_effect = detach
        device = self.make_device(session)

        with self.assertRaises(KeyboardInterrupt):
            device.hook_to_process('drm_process', 'libwvhidl.so')

        self.assertEqual(completed, [True])
        session.detach.assert_called_once_with()


# ---------------------------------------------------------------------------
# DISCOVERY SESSION LIFECYCLE
# Discovery must release its temporary attachment while allowing cancellation
# to reach the CLI unchanged.
# ---------------------------------------------------------------------------
class DiscoveryLifecycleTests(unittest.TestCase):
    def make_device(self):
        device = Device.__new__(Device)
        device.logger = logging.getLogger('test.discovery')
        device.usb_device = mock.Mock()
        device.frida_script = 'script'
        device.widevine_libraries = ['libwvhidl.so']
        process = mock.Mock()
        script = mock.Mock()
        device.usb_device.attach.return_value = process
        process.create_script.return_value = script
        return device, process, script

    def test_discovery_interrupt_detaches_and_propagates(self):
        for stage in ('create_script', 'load', 'lookup'):
            with self.subTest(stage=stage):
                device, process, script = self.make_device()
                if stage == 'create_script':
                    process.create_script.side_effect = KeyboardInterrupt
                elif stage == 'load':
                    script.load.side_effect = KeyboardInterrupt
                else:
                    script.exports.getmodulebyname.side_effect = KeyboardInterrupt

                with self.assertRaises(KeyboardInterrupt):
                    device.find_widevine_process('drm_process')

                process.detach.assert_called_once_with()

    def test_detach_failure_does_not_hide_discovery_interrupt(self):
        device, process, script = self.make_device()
        script.exports.getmodulebyname.side_effect = KeyboardInterrupt
        process.detach.side_effect = RuntimeError('detach failed')

        with self.assertLogs('test.discovery', level='WARNING') as logs:
            with self.assertRaises(KeyboardInterrupt):
                device.find_widevine_process('drm_process')

        process.detach.assert_called_once_with()
        self.assertTrue(any('detach failed' in line for line in logs.output))

    def test_successful_discovery_returns_modules_and_detaches(self):
        device, process, script = self.make_device()
        module = object()
        script.exports.getmodulebyname.return_value = module

        self.assertEqual(
            device.find_widevine_process('drm_process'),
            [module],
        )

        process.detach.assert_called_once_with()
        process.create_script.assert_called_once_with('script')
        script.load.assert_called_once_with()

    def test_discovery_detach_defers_an_interrupt_before_return(self):
        device, process, script = self.make_device()
        module = object()
        script.exports.getmodulebyname.return_value = module
        completed = []

        def detach():
            signal.raise_signal(signal.SIGINT)
            completed.append(True)

        process.detach.side_effect = detach

        with self.assertRaises(KeyboardInterrupt):
            device.find_widevine_process('drm_process')

        self.assertEqual(completed, [True])
        process.detach.assert_called_once_with()


# ---------------------------------------------------------------------------
# COMMAND-LINE REGRESSIONS
# The fake device mirrors the CLI's process and library calls; run_cli patches
# argv and construction so argument forwarding can be checked without Frida.
# ---------------------------------------------------------------------------
class CdmCommandLineTests(unittest.TestCase):
    def setUp(self):
        # Version probes have their own mocked tests. CLI fixtures must never
        # invoke a real ADB client or attach to the server's system session.
        adb_patch = mock.patch.object(dump_keys, 'report_adb_version')
        frida_patch = mock.patch.object(dump_keys, 'report_frida_versions')
        browser_patch = mock.patch.object(dump_keys, 'launch_test_page', return_value=True)
        connection_patch = mock.patch.object(dump_keys, 'CaptureConnection')
        event_patch = mock.patch.object(dump_keys, 'emit_event')
        self.addCleanup(adb_patch.stop)
        self.addCleanup(frida_patch.stop)
        self.addCleanup(browser_patch.stop)
        self.addCleanup(connection_patch.stop)
        self.addCleanup(event_patch.stop)
        self.adb_report = adb_patch.start()
        self.frida_report = frida_patch.start()
        self.browser_launch = browser_patch.start()
        self.connection_class = connection_patch.start()
        self.emit_event = event_patch.start()

    def make_cli_device(self, processes=(), libraries=()):
        # Materialize supplied iterables as predictable process and library
        # lists for the mock.
        device = mock.Mock(name='device')
        device.name = 'Pixel'
        device.usb_device.id = 'android-1'
        device.usb_device.enumerate_processes.return_value = list(processes)
        device.find_widevine_process.return_value = list(libraries)
        device.hook_to_process.return_value = mock.Mock()
        return device

    def run_cli(self, argv, device):
        # Keep command-line tests on the real dump_keys.main() entry point while
        # replacing only its Device constructor and process arguments.
        with mock.patch.object(sys, 'argv', ['dump_keys.py', *argv]), \
                mock.patch.object(dump_keys, 'Device', return_value=device) as device_class:
            self.assertIs(dump_keys.main(), device)
        return device_class

    # Defaults and explicit choices must reach Device, while invalid choices
    # must fail before any device is constructed.
    def test_default_cdm_version_is_auto(self):
        process = SimpleNamespace(name='drm_process')
        device_class = self.run_cli(
            [], self.make_cli_device([process], ['libwvhidl.so'])
        )

        device_class.assert_called_once_with(
            '', 'auto', ['libwvaidl.so', 'libwvhidl.so'], None
        )
        self.adb_report.assert_called_once()
        self.frida_report.assert_called_once_with(
            device_class.return_value.usb_device, logging.getLogger('main'),
        )
        self.browser_launch.assert_called_once_with(
            'android-1', logging.getLogger('main'), site_file=dump_keys.DEFAULT_SITE_FILE,
        )

    def test_browser_launch_happens_after_successful_hooks(self):
        device = self.make_cli_device([SimpleNamespace(name='drm_process')], ['libwvhidl.so'])
        calls = []
        device.hook_to_process.side_effect = lambda *_: calls.append('hook')
        self.browser_launch.side_effect = lambda *_args, **_kwargs: calls.append('browser')

        self.run_cli([], device)

        self.assertEqual(calls, ['hook', 'browser'])

    def test_no_browser_keeps_capture_running_without_launch(self):
        device = self.make_cli_device([SimpleNamespace(name='drm_process')], ['libwvhidl.so'])

        self.run_cli(['--no-browser'], device)

        self.browser_launch.assert_not_called()
        device.hook_to_process.assert_called_once()

    def test_custom_site_file_is_forwarded_and_browser_failure_is_nonfatal(self):
        device = self.make_cli_device([SimpleNamespace(name='drm_process')], ['libwvhidl.so'])
        self.browser_launch.return_value = False

        self.run_cli(['--site-file', 'custom-sites.txt'], device)

        self.browser_launch.assert_called_once_with(
            'android-1', logging.getLogger('main'), site_file='custom-sites.txt',
        )

    def test_explicit_cdm_version_is_forwarded(self):
        process = SimpleNamespace(name='drm_process')
        device_class = self.run_cli(
            ['--cdm-version', '17.0.0'],
            self.make_cli_device([process], ['libwvhidl.so']),
        )

        device_class.assert_called_once_with(
            '', '17.0.0', ['libwvaidl.so', 'libwvhidl.so'], None
        )

    def test_invalid_cdm_version_exits_before_device_creation(self):
        with mock.patch.object(sys, 'argv', ['dump_keys.py', '--cdm-version', '13.0.0']), \
                mock.patch.object(dump_keys, 'Device') as device_class:
            with self.assertRaises(SystemExit) as exit_error:
                dump_keys.main()

        self.assertEqual(exit_error.exception.code, 2)
        device_class.assert_not_called()

    def test_noninteractive_requires_auto_layout_and_no_function_name(self):
        for extra_args in (
            ['--non-interactive', '--cdm-version', '17.0.0'],
            ['--non-interactive', '--function-name', 'PrepareKeyRequest'],
        ):
            with self.subTest(extra_args=extra_args), \
                    mock.patch.object(sys, 'argv', ['dump_keys.py', *extra_args]), \
                    mock.patch.object(dump_keys, 'Device') as device_class, \
                    mock.patch('argparse.ArgumentParser.error', side_effect=SystemExit(2)) as parser_error:
                with self.assertRaises(SystemExit) as exit_error:
                    dump_keys.main()

            self.assertEqual(exit_error.exception.code, 2)
            self.assertIn('--non-interactive requires', parser_error.call_args.args[0])
            device_class.assert_not_called()

    def test_noninteractive_emits_hooks_ready_before_browser(self):
        process = SimpleNamespace(name='drm_process')
        device = self.make_cli_device([process], ['libwvhidl.so'])
        device.android_api_level = 29
        calls = []
        self.emit_event.side_effect = lambda *args, **kwargs: calls.append(('event', args, kwargs))
        self.browser_launch.side_effect = lambda *args, **kwargs: calls.append(('browser', args, kwargs))

        self.run_cli(['--non-interactive'], device)

        self.assertEqual(calls[0], (
            'event', ('hooks_ready',), {
                'device_id': 'android-1', 'android_api': '29', 'hooked_libraries': 1,
            },
        ))
        self.assertEqual(calls[1][0], 'browser')

    def test_failed_hook_does_not_emit_hooks_ready(self):
        process = SimpleNamespace(name='drm_process')
        device = self.make_cli_device([process], ['libwvhidl.so'])
        device.hook_to_process.side_effect = HookError('unknown signature')

        with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                mock.patch.object(dump_keys, 'Device', return_value=device), \
                mock.patch('argparse.ArgumentParser.error', side_effect=SystemExit(2)):
            with self.assertRaises(SystemExit):
                dump_keys.main()

        self.emit_event.assert_not_called()

    # CLI failures use argparse's clean error path and suppress a success
    # banner whenever no library completed successfully.
    def test_zero_hooked_libraries_suppresses_success_banner(self):
        device = self.make_cli_device()

        with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                mock.patch.object(dump_keys, 'Device', return_value=device), \
                mock.patch('argparse.ArgumentParser.error', side_effect=SystemExit(2)) as parser_error:
            with self.assertLogs('main', level='INFO') as logs:
                with self.assertRaises(SystemExit) as exit_error:
                    dump_keys.main()

        self.assertEqual(exit_error.exception.code, 2)
        parser_error.assert_called_once()
        self.assertTrue(any('Scanning all processes' in line for line in logs.output))
        self.assertFalse(any('Functions hooked' in line for line in logs.output))
        self.browser_launch.assert_not_called()

    def test_hook_error_uses_clean_cli_failure(self):
        process = SimpleNamespace(name='drm_process')
        device = self.make_cli_device([process])
        device.find_widevine_process.return_value = ['libwvhidl.so']
        device.hook_to_process.side_effect = HookError(
            "Failed to hook library 'libwvhidl.so' in process 'drm_process': rpc failed"
        )

        with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                mock.patch.object(dump_keys, 'Device', return_value=device), \
                mock.patch('argparse.ArgumentParser.error', side_effect=SystemExit(2)) as parser_error:
            with self.assertLogs('main', level='INFO') as logs:
                with self.assertRaises(SystemExit) as exit_error:
                    dump_keys.main()

        self.assertEqual(exit_error.exception.code, 2)
        parser_error.assert_called_once()
        self.assertFalse(any('Functions hooked' in line for line in logs.output))
        self.browser_launch.assert_not_called()

    # Direct-library failures remain isolated so one successful hook can still
    # produce the normal success result.
    def test_one_library_failure_does_not_block_another(self):
        for outcomes in (
            [HookError('args[5] signature was not recognized'), mock.Mock()],
            [mock.Mock(), HookError('args[5] signature was not recognized')],
        ):
            with self.subTest(outcomes=outcomes):
                process = SimpleNamespace(name='drm_process')
                device = self.make_cli_device(
                    [process], ['libwvaidl.so', 'libwvhidl.so']
                )
                device.hook_to_process.side_effect = outcomes

                with self.assertLogs('main', level='INFO') as logs:
                    self.run_cli([], device)

                self.assertTrue(
                    any('signature was not recognized' in line for line in logs.output)
                )
                self.assertTrue(any('Functions hooked' in line for line in logs.output))
                self.assertEqual(device.hook_to_process.call_count, 2)

    # When every library fails, the CLI must report an error without claiming
    # that any functions were hooked.
    def test_all_library_failures_exit_without_success_banner(self):
        process = SimpleNamespace(name='drm_process')
        device = self.make_cli_device(
            [process], ['libwvaidl.so', 'libwvhidl.so']
        )
        device.hook_to_process.side_effect = [
            HookError('first failure'),
            HookError('second failure'),
        ]

        with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                mock.patch.object(dump_keys, 'Device', return_value=device), \
                mock.patch('argparse.ArgumentParser.error', side_effect=SystemExit(2)) as parser_error:
            with self.assertLogs('main', level='INFO') as logs:
                with self.assertRaises(SystemExit) as exit_error:
                    dump_keys.main()

        self.assertEqual(exit_error.exception.code, 2)
        parser_error.assert_called_once()
        self.assertFalse(any('Functions hooked' in line for line in logs.output))

    def test_run_handles_interrupt_during_startup(self):
        with mock.patch.object(dump_keys, 'main', side_effect=KeyboardInterrupt), \
                self.assertLogs('main', level='INFO') as logs:
            self.assertEqual(dump_keys.run(), 0)

        self.assertTrue(any('Stopped by user.' in line for line in logs.output))

    def test_imported_run_entry_repairs_terminal_before_startup(self):
        with mock.patch.object(dump_keys, 'prepare_terminal') as prepare, \
                mock.patch.object(dump_keys, 'main', side_effect=KeyboardInterrupt), \
                self.assertLogs('main', level='INFO'):
            self.assertEqual(dump_keys.run(), 0)

        prepare.assert_called_once_with()

    def test_run_handles_interrupt_during_argument_parsing(self):
        with mock.patch('argparse.ArgumentParser.parse_args', side_effect=KeyboardInterrupt), \
                self.assertLogs('main', level='INFO') as logs:
            self.assertEqual(dump_keys.run(), 0)

        self.assertTrue(any('Stopped by user.' in line for line in logs.output))

    def test_run_handles_interrupt_during_optional_adb_diagnostics(self):
        self.adb_report.side_effect = KeyboardInterrupt
        with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                self.assertLogs('main', level='INFO') as logs:
            self.assertEqual(dump_keys.run(), 0)

        self.assertTrue(any('Stopped by user.' in line for line in logs.output))

    def test_run_handles_interrupt_during_dependency_import(self):
        with mock.patch.object(dump_keys, 'DEPENDENCY_IMPORT_INTERRUPTED', True), \
                mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                self.assertLogs('main', level='INFO') as logs:
            self.assertEqual(dump_keys.run(), 0)

        self.assertTrue(any('Stopped by user.' in line for line in logs.output))

    def test_run_handles_interrupt_during_device_selection(self):
        with mock.patch.object(dump_keys, 'Device', side_effect=KeyboardInterrupt), \
                mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                self.assertLogs('main', level='INFO') as logs:
            self.assertEqual(dump_keys.run(), 0)

        self.assertTrue(any('Stopped by user.' in line for line in logs.output))

    def test_run_handles_interrupt_during_process_enumeration(self):
        device = self.make_cli_device()
        device.usb_device.enumerate_processes.side_effect = KeyboardInterrupt
        with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                mock.patch.object(dump_keys, 'Device', return_value=device), \
                self.assertLogs('main', level='INFO') as logs:
            self.assertEqual(dump_keys.run(), 0)

        device.close.assert_called_once_with()
        self.assertTrue(any('Stopped by user.' in line for line in logs.output))

    def test_run_handles_interrupt_during_hook_setup(self):
        device = self.make_cli_device(
            [SimpleNamespace(name='drm_process')], ['libwvhidl.so'],
        )
        device.hook_to_process.side_effect = KeyboardInterrupt
        with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                mock.patch.object(dump_keys, 'Device', return_value=device), \
                self.assertLogs('main', level='INFO') as logs:
            self.assertEqual(dump_keys.run(), 0)

        device.close.assert_called_once_with()
        self.assertTrue(any('Stopped by user.' in line for line in logs.output))

    def test_connection_failures_during_startup_exit_without_waiting(self):
        for error_type in dump_keys.FRIDA_CONNECTION_ERRORS:
            for stage in ('construct', 'enumerate', 'discover'):
                with self.subTest(error=error_type.__name__, stage=stage):
                    device = self.make_cli_device([SimpleNamespace(name='drm_process')])
                    failure = error_type('simulated connection failure')
                    if stage == 'enumerate':
                        device.usb_device.enumerate_processes.side_effect = failure
                    elif stage == 'discover':
                        device.find_widevine_process.side_effect = failure
                    with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                            mock.patch.object(dump_keys, 'Device', return_value=device) as constructor, \
                            mock.patch.object(dump_keys.time, 'sleep') as wait, \
                            self.assertLogs('main', level='INFO') as logs:
                        if stage == 'construct':
                            constructor.side_effect = failure
                        self.assertEqual(dump_keys.run(), 1)
                    wait.assert_not_called()
                    device.hook_to_process.assert_not_called()
                    messages = '\n'.join(logs.output)
                    self.assertIn('simulated connection failure', messages)
                    self.assertIn('setup_frida.py --shell', messages)
                    self.assertNotIn('Functions hooked', messages)

    def test_wrapped_hook_connection_failure_has_recovery_guidance(self):
        device = self.make_cli_device(
            [SimpleNamespace(name='drm_process')], ['libwvhidl.so'],
        )
        device.hook_to_process.side_effect = HookError('unable to communicate with remote frida-server')
        with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                mock.patch.object(dump_keys, 'Device', return_value=device), \
                mock.patch('argparse.ArgumentParser.error', side_effect=SystemExit(2)) as parser_error, \
                mock.patch.object(dump_keys.time, 'sleep') as wait:
            with self.assertRaises(SystemExit) as exit_error:
                dump_keys.run()
        self.assertEqual(exit_error.exception.code, 2)
        self.assertIn('setup_frida.py --shell', parser_error.call_args.args[0])
        wait.assert_not_called()

    def test_run_handles_interrupt_during_wait(self):
        with mock.patch.object(dump_keys, 'main') as main_mock, \
                mock.patch.object(dump_keys.time, 'sleep', side_effect=KeyboardInterrupt), \
                self.assertLogs('main', level='INFO') as logs:
            self.assertEqual(dump_keys.run(), 0)

        main_mock.assert_called_once_with()
        self.assertTrue(any('Stopped by user.' in line for line in logs.output))

    def test_run_ignores_a_second_interrupt_during_session_cleanup(self):
        device = self.make_cli_device()

        def interrupt_again():
            signal.raise_signal(signal.SIGINT)

        self.connection_class.return_value.close.side_effect = interrupt_again
        with mock.patch.object(dump_keys, 'main', return_value=device), \
                mock.patch.object(dump_keys.time, 'sleep', side_effect=KeyboardInterrupt), \
                self.assertLogs('main', level='INFO'):
            self.assertEqual(dump_keys.run(), 0)

        self.connection_class.return_value.close.assert_called_once_with()
        device.close.assert_called_once_with()

    def test_run_checks_capture_progress_while_waiting(self):
        device = mock.Mock()
        with mock.patch.object(dump_keys, 'main', return_value=device), \
                mock.patch.object(dump_keys.time, 'sleep', side_effect=[None, KeyboardInterrupt]) as wait, \
                self.assertLogs('main', level='INFO'):
            self.assertEqual(dump_keys.run(), 0)
        device.warn_if_no_pair.assert_called_once_with()
        self.connection_class.return_value.check.assert_called_once_with()
        self.connection_class.return_value.close.assert_called_once_with()
        device.close.assert_called_once_with()
        self.assertEqual(wait.call_args_list, [mock.call(1), mock.call(1)])

    def test_startup_failure_releases_previously_installed_hooks(self):
        device = self.make_cli_device(
            [SimpleNamespace(name='drm_process')], ['libwvhidl.so'],
        )
        self.browser_launch.side_effect = KeyboardInterrupt
        with mock.patch.object(sys, 'argv', ['dump_keys.py']), \
                mock.patch.object(dump_keys, 'Device', return_value=device), \
                self.assertLogs('main', level='INFO'):
            self.assertEqual(dump_keys.run(), 0)
        device.hook_to_process.assert_called_once()
        device.close.assert_called_once_with()
        self.connection_class.assert_not_called()

    def test_failed_automatic_status_stops_cleanly_and_closes_capture(self):
        device = mock.Mock()
        device.warn_if_no_pair.side_effect = dump_keys.AutoSessionError('status unavailable')
        with mock.patch.object(dump_keys, 'main', return_value=device), \
                mock.patch.object(dump_keys.time, 'sleep'), \
                self.assertLogs('main', level='ERROR') as logs:
            self.assertEqual(dump_keys.run(), 1)
        self.assertIn('saved files are retained', ' '.join(logs.output))
        self.connection_class.return_value.close.assert_called_once_with()
        device.close.assert_called_once_with()

    def test_run_propagates_real_errors(self):
        with mock.patch.object(dump_keys, 'main', side_effect=RuntimeError('startup failed')):
            with self.assertRaisesRegex(RuntimeError, 'startup failed'):
                dump_keys.run()

    def test_run_preserves_argparse_exit_code(self):
        with mock.patch.object(sys, 'argv', ['dump_keys.py', '--cdm-version', '13.0.0']):
            with self.assertRaises(SystemExit) as exit_error:
                dump_keys.run()

        self.assertEqual(exit_error.exception.code, 2)


# ---------------------------------------------------------------------------
# MISSING DEPENDENCIES
# -S disables site packages only in a child interpreter. Bootstrap is mocked
# because these tests specifically simulate an already selected but incomplete
# environment; they must never install packages or reconnect to a real device.
# ---------------------------------------------------------------------------
class MissingDependencyTests(unittest.TestCase):
    def run_without_site_packages(self, *arguments):
        script = (
            'import runpy, sys\n'
            'from unittest import mock\n'
            'sys.argv[0] = "dump_keys.py"\n'
            'with mock.patch("Helpers.Bootstrap.bootstrap"):\n'
            '    runpy.run_path("dump_keys.py", run_name="__main__")\n'
        )
        return subprocess.run(
            [sys.executable, '-S', '-c', script, *arguments],
            cwd=Path(__file__).resolve().parents[1],
            capture_output=True, text=True, timeout=10, check=False,
        )

    def test_missing_frida_dependency_prints_install_guidance_without_traceback(self):
        result = self.run_without_site_packages()
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn('required Python dependency', result.stderr)
        self.assertIn('frida', result.stderr)
        self.assertIn('python -m pip install -r requirements.txt', result.stderr)
        self.assertNotIn('Traceback', result.stderr)
        self.assertNotIn('Functions hooked', result.stdout + result.stderr)

    def test_help_works_without_frida_installed(self):
        result = self.run_without_site_packages('--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('--device-id', result.stdout)
        self.assertNotIn('Traceback', result.stderr)

    def test_direct_entry_prepares_terminal_before_running(self):
        script = Path(__file__).resolve().parents[1] / 'dump_keys.py'
        with mock.patch('Helpers.CLI.prepare_terminal') as prepare, \
                mock.patch('argparse.ArgumentParser.parse_args', side_effect=KeyboardInterrupt):
            with self.assertRaises(SystemExit) as exit_error:
                runpy.run_path(str(script), run_name='__main__')

        self.assertEqual(exit_error.exception.code, 0)
        prepare.assert_called_once_with()

    def test_direct_entry_terminal_repair_interrupt_is_clean(self):
        script = Path(__file__).resolve().parents[1] / 'dump_keys.py'
        stderr = io.StringIO()
        with mock.patch('Helpers.CLI.prepare_terminal', side_effect=KeyboardInterrupt), \
                mock.patch.object(sys, 'stderr', stderr):
            with self.assertRaises(SystemExit) as exit_error:
                runpy.run_path(str(script), run_name='__main__')

        self.assertEqual(exit_error.exception.code, 0)
        self.assertIn('Stopped by user.', stderr.getvalue())

    def test_dependency_import_interrupt_is_clean_at_direct_entry(self):
        script = Path(__file__).resolve().parents[1] / 'dump_keys.py'
        original_import = builtins.__import__

        def interrupt_frida(name, *args, **kwargs):
            if name == 'frida':
                raise KeyboardInterrupt
            return original_import(name, *args, **kwargs)

        for argv in (['dump_keys.py'], ['dump_keys.py', '--help'],
                     ['dump_keys.py', '--invalid-option']):
            with self.subTest(argv=argv):
                stdout = io.StringIO()
                stderr = io.StringIO()
                with mock.patch('Helpers.CLI.prepare_terminal'), \
                        mock.patch('builtins.__import__', side_effect=interrupt_frida), \
                        mock.patch.object(sys, 'argv', argv), \
                        mock.patch.object(sys, 'stdout', stdout), \
                        mock.patch.object(sys, 'stderr', stderr), \
                        self.assertRaises(SystemExit) as exit_error:
                    runpy.run_path(str(script), run_name='__main__')

                self.assertEqual(exit_error.exception.code, 0)
                self.assertNotIn('usage:', stdout.getvalue().lower())
                self.assertNotIn('unrecognized arguments', stderr.getvalue().lower())

    def test_dependency_import_interrupt_propagates_for_named_module(self):
        script = Path(__file__).resolve().parents[1] / 'dump_keys.py'
        original_import = builtins.__import__

        def interrupt_frida(name, *args, **kwargs):
            if name == 'frida':
                raise KeyboardInterrupt
            return original_import(name, *args, **kwargs)

        with mock.patch('builtins.__import__', side_effect=interrupt_frida):
            with self.assertRaises(KeyboardInterrupt):
                runpy.run_path(str(script), run_name='dumper_named_import')


# Direct execution runs the tests defined in this module for quick focused
# checks during CLI maintenance.
if __name__ == '__main__':
    unittest.main()
