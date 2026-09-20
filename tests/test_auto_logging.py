"""Offline tests for full-auto controller and captured-output logging."""

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import full_auto
from Helpers import AutoLogging as logging_helper


class AutoLoggingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.repo_tmp = Path(__file__).resolve().parents[1] / '.tmp'
        cls.repo_tmp.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='auto-logging-', dir=self.repo_tmp,
        )
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)

    def test_controller_logging_resets_four_fixed_raw_logs_with_private_mode(self):
        logs = self.root / 'logs'
        logs.mkdir()
        for name in logging_helper.LOG_NAMES:
            path = logs / name
            path.write_text('stale output', encoding='utf-8')
            path.chmod(0o644)

        with logging_helper.controller_logging(self.root):
            for name in logging_helper.LOG_NAMES:
                path = logs / name
                self.assertEqual(path.read_bytes(), b'')
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)

        self.assertTrue((self.root / '.tmp' / 'full-auto.lock').is_file())

    def test_second_controller_lock_fails_without_clobbering_first_run_logs(self):
        with logging_helper.controller_logging(self.root):
            first_log = self.root / 'logs' / 'full_auto.log'
            print('first run')
            first_content = first_log.read_text(encoding='utf-8')
            with self.assertRaisesRegex(OSError, 'Another full_auto.py run'):
                with logging_helper.controller_logging(self.root):
                    pass
            self.assertEqual(first_log.read_text(encoding='utf-8'), first_content)

    def test_controller_logging_mirrors_stdout_and_stderr_to_full_auto_log(self):
        console_out = io.StringIO()
        console_err = io.StringIO()
        with redirect_stdout(console_out), redirect_stderr(console_err):
            with logging_helper.controller_logging(self.root):
                print('console output')
                print('console error', file=os.sys.stderr)

        self.assertEqual(console_out.getvalue(), 'console output\n')
        self.assertEqual(console_err.getvalue(), 'console error\n')
        self.assertEqual(
            (self.root / 'logs' / 'full_auto.log').read_text(encoding='utf-8'),
            'console output\nconsole error\n',
        )

    def test_captured_output_logs_full_text_and_timeout_bytes_only_when_enabled(self):
        stdout = 'O' * 13001
        stderr = 'E' * 13002
        timeout_stdout = b'T' * 13003
        timeout_stderr = b'R' * 13004
        result = SimpleNamespace(stdout=stdout, stderr=stderr)
        timeout = subprocess.TimeoutExpired(
            ['fixture'], 1, output=timeout_stdout, stderr=timeout_stderr,
        )
        console_out = io.StringIO()
        console_err = io.StringIO()
        with redirect_stdout(console_out), redirect_stderr(console_err):
            with logging_helper.controller_logging(self.root):
                logging_helper.log_captured_output(result)
                logging_helper.log_captured_output(timeout)

        logged = (self.root / 'logs' / 'full_auto.log').read_text(encoding='utf-8')
        self.assertEqual(logged, stdout + stderr + timeout_stdout.decode() + timeout_stderr.decode())
        self.assertEqual(console_out.getvalue(), '')
        self.assertEqual(console_err.getvalue(), '')

    def test_normal_progress_is_mirrored_but_raw_captured_adb_output_stays_off_console(self):
        captured_stdout = b'ADB\x00stdout\xff\n'
        captured_stderr = b'ADB stderr\x01\n'
        console_out = io.StringIO()
        console_err = io.StringIO()
        with redirect_stdout(console_out), redirect_stderr(console_err):
            with logging_helper.controller_logging(self.root):
                print('normal progress')
                logging_helper.log_captured_output(
                    SimpleNamespace(stdout=captured_stdout, stderr=captured_stderr),
                )
                print('normal warning', file=os.sys.stderr)

        self.assertEqual(console_out.getvalue(), 'normal progress\n')
        self.assertEqual(console_err.getvalue(), 'normal warning\n')
        self.assertEqual(
            (self.root / 'logs' / 'full_auto.log').read_bytes(),
            b'normal progress\n' + captured_stdout + captured_stderr + b'normal warning\n',
        )

    def test_raw_captured_output_is_preserved_in_plain_redirected_streams(self):
        raw_stdout = b'child stdout\x00\xff\n'
        raw_stderr = b'child stderr\x01\n'
        stdout_bytes = io.BytesIO()
        stderr_bytes = io.BytesIO()
        stdout = io.TextIOWrapper(stdout_bytes, encoding='utf-8')
        stderr = io.TextIOWrapper(stderr_bytes, encoding='utf-8')
        try:
            with mock.patch.dict(os.environ, {'DUMPER_AUTO_LOGGING': '1'}, clear=True), \
                    mock.patch.object(logging_helper.sys, 'stdout', stdout), \
                    mock.patch.object(logging_helper.sys, 'stderr', stderr):
                logging_helper.log_captured_output(
                    SimpleNamespace(stdout=raw_stdout, stderr=raw_stderr),
                )
            self.assertEqual(stdout_bytes.getvalue(), raw_stdout)
            self.assertEqual(stderr_bytes.getvalue(), raw_stderr)
        finally:
            stdout.detach()
            stderr.detach()

    def test_captured_output_is_unchanged_for_manual_runs_without_logging_flag(self):
        result = SimpleNamespace(stdout='manual stdout', stderr='manual stderr')
        with mock.patch.dict(os.environ, {}, clear=True), \
                redirect_stdout(io.StringIO()) as stdout, redirect_stderr(io.StringIO()) as stderr:
            logging_helper.log_captured_output(result)
        self.assertEqual(stdout.getvalue(), '')
        self.assertEqual(stderr.getvalue(), '')
        self.assertFalse((self.root / 'logs').exists())

    def test_logged_subprocess_success_returns_decoded_output_and_logs_once(self):
        def run(command, *, stdout, stderr, **_options):
            stdout.write(b'child stdout')
            stderr.write(b'child stderr')
            return subprocess.CompletedProcess(command, 0)

        with mock.patch.object(logging_helper.subprocess, 'run', side_effect=run):
            with logging_helper.controller_logging(self.root):
                result = logging_helper.run_logged_subprocess(
                    ['fixture'], capture_output=True, text=True,
                )
                logging_helper.log_captured_output(result)

        self.assertEqual(result.stdout, 'child stdout')
        self.assertEqual(result.stderr, 'child stderr')
        self.assertTrue(getattr(result, '_auto_logged'))
        self.assertEqual(
            (self.root / 'logs' / 'full_auto.log').read_text(encoding='utf-8'),
            'child stdoutchild stderr',
        )

    def test_logged_subprocess_preserves_partial_output_when_cancelled(self):
        def cancel(command, *, stdout, stderr, **_options):
            stdout.write(b'partial stdout')
            stderr.write(b'partial stderr')
            raise KeyboardInterrupt

        with mock.patch.object(logging_helper.subprocess, 'run', side_effect=cancel), \
                logging_helper.controller_logging(self.root):
            with self.assertRaises(KeyboardInterrupt):
                logging_helper.run_logged_subprocess(['fixture'], capture_output=True)

        self.assertEqual(
            (self.root / 'logs' / 'full_auto.log').read_text(encoding='utf-8'),
            'partial stdoutpartial stderr',
        )

    def test_logged_subprocess_preserves_partial_output_on_timeout(self):
        def timeout(command, *, stdout, stderr, **_options):
            stdout.write(b'timeout stdout')
            stderr.write(b'timeout stderr')
            raise subprocess.TimeoutExpired(command, 1)

        with mock.patch.object(logging_helper.subprocess, 'run', side_effect=timeout), \
                logging_helper.controller_logging(self.root):
            with self.assertRaises(subprocess.TimeoutExpired):
                logging_helper.run_logged_subprocess(['fixture'], capture_output=True)

        self.assertEqual(
            (self.root / 'logs' / 'full_auto.log').read_text(encoding='utf-8'),
            'timeout stdouttimeout stderr',
        )

    def test_manual_logged_subprocess_delegates_to_subprocess_run_unchanged(self):
        expected = subprocess.CompletedProcess(['fixture'], 0, 'out', 'err')
        with mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(logging_helper.subprocess, 'run', return_value=expected) as run:
            result = logging_helper.run_logged_subprocess(
                ['fixture'], capture_output=True, text=True,
            )

        self.assertIs(result, expected)
        run.assert_called_once_with(['fixture'], capture_output=True, text=True)

    def test_help_exits_before_controller_logging_or_job_and_log_creation(self):
        with mock.patch.object(full_auto, 'ROOT', self.root), \
                mock.patch.object(full_auto, 'prepare_terminal'), \
                mock.patch.object(full_auto, 'controller_logging') as logging_context, \
                redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit) as exit_result:
                full_auto.main(['--help'])

        self.assertEqual(exit_result.exception.code, 0)
        logging_context.assert_not_called()
        self.assertIn('Experimental guided capture', output.getvalue())
        self.assertFalse((self.root / 'logs').exists())
        self.assertFalse((self.root / '.tmp').exists())


if __name__ == '__main__':
    unittest.main()
