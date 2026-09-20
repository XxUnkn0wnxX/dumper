"""Offline contracts for full-auto's Frida handoff and process ownership."""

from contextlib import redirect_stdout
import io
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

import full_auto
from Helpers.AutoSession import AutoSessionError
from tools import setup_frida as setup


class AutoFridaTests(unittest.TestCase):
    def test_noninteractive_alias_preserves_no_shell_and_excludes_shell(self):
        self.assertTrue(setup.build_parser().parse_args(['--non-interactive']).no_shell)
        with redirect_stdout(io.StringIO()), mock.patch('sys.stderr', io.StringIO()):
            with self.assertRaises(SystemExit):
                setup.build_parser().parse_args(['--non-interactive', '--shell'])

    def test_marker_is_published_after_start_identity_before_ready(self):
        marker = '/data/local/tmp/.dumper-auto-' + 'a' * 32 + '.pid'
        with mock.patch.object(setup, 'frida_marker', return_value=marker):
            command = setup.supervised_server_command()
        position = command.index('> ' + marker)
        self.assertLess(command.index('frida_start=$frida_current_start'), position)
        self.assertLess(position, command.index('frida_ready=1'))
        self.assertIn('umask 077', command)

    def test_manual_server_has_no_automation_marker(self):
        with mock.patch.object(setup, 'frida_marker', return_value=None):
            self.assertNotIn('.dumper-auto-', setup.supervised_server_command())

    def test_launch_event_precedes_adb_handoff(self):
        calls = []
        with mock.patch.object(setup, 'frida_marker', return_value='/marker'), \
                mock.patch.object(setup, 'foreground_server_command', return_value='server'), \
                mock.patch.object(setup, 'emit_event', side_effect=lambda *a, **k: calls.append(('event', a, k))), \
                mock.patch.object(setup, 'handoff_to_adb', side_effect=lambda *a: calls.append(('handoff', a))), \
                redirect_stdout(io.StringIO()):
            setup.run_foreground_server('adb', 'device-1', 'su-0', interactive=False)
        self.assertEqual([row[0] for row in calls], ['event', 'handoff'])
        self.assertEqual(calls[0][2]['root_mode'], 'su-0')
        self.assertEqual(calls[0][2]['device_id'], 'device-1')

    def test_auto_adb_override_used_by_dumper_helpers(self):
        with tempfile.TemporaryDirectory() as tmp:
            binary = Path(tmp) / 'custom-adb'
            binary.write_text('placeholder')
            binary.chmod(0o700)
            with mock.patch.object(setup, 'auto_context', return_value=(Path(tmp), 'a' * 32, 'dumper')), \
                    mock.patch.dict(os.environ, {'DUMPER_AUTO_ADB': str(binary)}), \
                    mock.patch.object(setup.shutil, 'which') as which:
                self.assertEqual(setup.resolve_adb(None), str(binary.resolve()))
            which.assert_not_called()

    def test_failed_launch_event_prevents_server_handoff(self):
        with mock.patch.object(setup, 'frida_marker', return_value='/marker'), \
                mock.patch.object(setup, 'foreground_server_command', return_value='server'), \
                mock.patch.object(setup, 'emit_event', side_effect=AutoSessionError('status unavailable')), \
                mock.patch.object(setup, 'handoff_to_adb') as handoff, redirect_stdout(io.StringIO()):
            with self.assertRaises(AutoSessionError):
                setup.run_foreground_server('adb', 'device-1', 'su-0', interactive=False)
        handoff.assert_not_called()

    @unittest.skipUnless(os.name == 'posix', 'requires a local POSIX shell')
    def test_generated_cleanup_checks_incarnation_and_executable_before_signals(self):
        # Execute the actual generated shell program with fake process helpers.
        # No real kill, ADB, /proc access, or sleep runs in these scenarios.
        for identity, executable, expected_signals, expected_code in (
            ('456', '/data/local/tmp/frida-server', '-INT 123\n', 0),
            ('999', '/data/local/tmp/frida-server', '', 0),
            ('456', '/system/bin/sh', '', 3),
            ('', '/data/local/tmp/frida-server', '', 0),
        ):
            with self.subTest(identity=identity, executable=executable):
                with tempfile.TemporaryDirectory() as tmp:
                    marker = Path(tmp) / 'owned.pid'
                    log = Path(tmp) / 'signals'
                    marker.write_text('123 456\n')
                    functions = f'''
frida_identity={shlex.quote(identity)}
frida_read_identity() {{ frida_current_start=$frida_identity; }}
readlink() {{ printf '%s\\n' {shlex.quote(executable)}; }}
kill() {{ printf '%s\\n' "$*" >> {shlex.quote(str(log))}; frida_identity=; }}
sleep() {{ :; }}
'''
                    with mock.patch.object(setup, 'foreground_process_identity_command', return_value=functions):
                        command = full_auto.remote_cleanup_command(str(marker))
                    result = subprocess.run(['sh', '-c', command], capture_output=True, text=True, timeout=3)
                    self.assertEqual(result.returncode, expected_code, result.stderr)
                    self.assertEqual(log.read_text() if log.exists() else '', expected_signals)
                    self.assertEqual(marker.exists(), expected_code != 0)


if __name__ == '__main__':
    unittest.main()
