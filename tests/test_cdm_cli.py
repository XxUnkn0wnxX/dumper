import logging
from pathlib import Path
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
        script.on.assert_called_once_with('message', device.on_message)
        script.load.assert_called_once_with()
        script.exports.hooklibfunctions.assert_called_once_with('libwvhidl.so')


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
        self.addCleanup(adb_patch.stop)
        self.addCleanup(frida_patch.stop)
        self.adb_report = adb_patch.start()
        self.frida_report = frida_patch.start()

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

    def test_run_checks_capture_progress_while_waiting(self):
        device = mock.Mock()
        with mock.patch.object(dump_keys, 'main', return_value=device), \
                mock.patch.object(dump_keys.time, 'sleep', side_effect=[None, KeyboardInterrupt]) as wait, \
                self.assertLogs('main', level='INFO'):
            self.assertEqual(dump_keys.run(), 0)
        device.warn_if_no_pair.assert_called_once_with()
        self.assertEqual(wait.call_args_list, [mock.call(1), mock.call(1)])

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
# -S disables site packages only in a child interpreter. This tests the real
# entry point without uninstalling anything or contacting an Android device.
# ---------------------------------------------------------------------------
class MissingDependencyTests(unittest.TestCase):
    def run_without_site_packages(self, *arguments):
        return subprocess.run(
            [sys.executable, '-S', 'dump_keys.py', *arguments],
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


# Direct execution runs the tests defined in this module for quick focused
# checks during CLI maintenance.
if __name__ == '__main__':
    unittest.main()
