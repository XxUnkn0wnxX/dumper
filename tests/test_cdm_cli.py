import logging
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
# COMMAND-LINE REGRESSIONS
# The fake device mirrors the CLI's process and library calls; run_cli patches
# argv and construction so argument forwarding can be checked without Frida.
# ---------------------------------------------------------------------------
class CdmCommandLineTests(unittest.TestCase):
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
            dump_keys.main()
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


# Direct execution runs the tests defined in this module for quick focused
# checks during CLI maintenance.
if __name__ == '__main__':
    unittest.main()
