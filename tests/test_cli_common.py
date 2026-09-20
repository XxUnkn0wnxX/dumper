"""Focused terminal and short-cleanup tests for the shared CLI helpers."""

import errno
import io
import os
from pathlib import Path
import select
import signal
import sys
import subprocess
import tempfile
import textwrap
import time
import unittest
from unittest import mock

from Helpers import CLI as cli_common

if os.name == 'posix':
    import pty


class CliCommonTests(unittest.TestCase):
    """Exercise behavior that does not require a native terminal."""

    def test_prepare_terminal_leaves_redirected_stringio_untouched(self):
        stdin = io.StringIO('input')
        stdout = io.StringIO('captured')
        stderr = io.StringIO('errors')
        streams = (stdin, stdout, stderr)

        with mock.patch.object(cli_common.sys, 'stdin', stdin), \
                mock.patch.object(cli_common.sys, 'stdout', stdout), \
                mock.patch.object(cli_common.sys, 'stderr', stderr):
            cli_common.prepare_terminal()

        self.assertEqual(tuple(stream.getvalue() for stream in streams),
                         ('input', 'captured', 'errors'))
        self.assertEqual(tuple(stream.tell() for stream in streams), (0, 0, 0))

    def test_windows_break_uses_the_keyboard_interrupt_cleanup_handler(self):
        with mock.patch.object(cli_common.signal, 'SIGBREAK', 9876, create=True), \
                mock.patch.object(cli_common.signal, 'signal') as install, \
                mock.patch.object(cli_common.sys, 'stdin', io.StringIO()), \
                mock.patch.object(cli_common.sys, 'stdout', io.StringIO()), \
                mock.patch.object(cli_common.sys, 'stderr', io.StringIO()):
            cli_common.prepare_terminal()
        install.assert_any_call(9876, signal.default_int_handler)

    def test_ignore_interrupts_restores_handler_when_cleanup_raises(self):
        previous = signal.getsignal(signal.SIGINT)
        replacement = lambda signum, frame: None
        signal.signal(signal.SIGINT, replacement)
        try:
            with self.assertRaisesRegex(RuntimeError, 'cleanup failed'):
                with cli_common.ignore_interrupts():
                    self.assertIs(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
                    raise RuntimeError('cleanup failed')
            self.assertIs(signal.getsignal(signal.SIGINT), replacement)
        finally:
            signal.signal(signal.SIGINT, previous)

    def test_defer_interrupts_records_sigint_finishes_cleanup_then_raises(self):
        previous = signal.getsignal(signal.SIGINT)
        replacement = lambda signum, frame: None
        signal.signal(signal.SIGINT, replacement)
        cleanup = []
        try:
            with self.assertRaises(KeyboardInterrupt):
                with cli_common.defer_interrupts():
                    signal.raise_signal(signal.SIGINT)
                    cleanup.append('completed')
            self.assertEqual(cleanup, ['completed'])
            self.assertIs(signal.getsignal(signal.SIGINT), replacement)
        finally:
            signal.signal(signal.SIGINT, previous)

    def test_defer_interrupts_inside_ignore_preserves_outer_ignore_and_body_oserror(self):
        previous = signal.getsignal(signal.SIGINT)
        replacement = lambda signum, frame: None
        signal.signal(signal.SIGINT, replacement)
        try:
            with self.assertRaisesRegex(OSError, 'cleanup failed'):
                with cli_common.ignore_interrupts():
                    self.assertIs(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
                    with cli_common.defer_interrupts():
                        self.assertIs(signal.getsignal(signal.SIGINT), signal.SIG_IGN)
                        signal.raise_signal(signal.SIGINT)
                        raise OSError('cleanup failed')
                    self.fail('defer_interrupts body unexpectedly completed')
            self.assertIs(signal.getsignal(signal.SIGINT), replacement)
        finally:
            signal.signal(signal.SIGINT, previous)

    def test_deferred_interrupt_does_not_replace_body_exception(self):
        previous = signal.getsignal(signal.SIGINT)
        replacement = lambda signum, frame: None
        signal.signal(signal.SIGINT, replacement)
        try:
            with self.assertRaisesRegex(RuntimeError, 'body failed'):
                with cli_common.defer_interrupts():
                    signal.raise_signal(signal.SIGINT)
                    raise RuntimeError('body failed')
            self.assertIs(signal.getsignal(signal.SIGINT), replacement)
        finally:
            signal.signal(signal.SIGINT, previous)

    def test_deferred_interrupt_stops_recovery_from_an_earlier_error(self):
        completed = []
        with self.assertRaises(KeyboardInterrupt):
            try:
                raise RuntimeError('recoverable operation failed')
            except RuntimeError:
                with cli_common.defer_interrupts():
                    signal.raise_signal(signal.SIGINT)
                    completed.append('cleanup')
                completed.append('retry')
        self.assertEqual(completed, ['cleanup'])


@unittest.skipUnless(os.name == 'posix', 'Native PTY coverage requires POSIX')
class PosixPtyTests(unittest.TestCase):
    """Use a real PTY and isolated child process, never ADB or a device."""

    @classmethod
    def setUpClass(cls):
        cls.repo_root = Path(__file__).resolve().parents[1]
        cls.tmp_root = cls.repo_root / '.tmp'
        cls.tmp_root.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='cli-common-pty-', dir=self.tmp_root,
        )
        self.addCleanup(self.temporary.cleanup)
        self.helper = Path(self.temporary.name) / 'pty_child.py'
        self.helper.write_text(textwrap.dedent('''
            import fcntl
            import os
            import termios
            import tty

            from Helpers import CLI as cli_common

            # Popen starts a fresh session without a controlling terminal.
            # Acquire this PTY before changing its line discipline so the
            # terminal driver can deliver VINTR to this child process group.
            try:
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
                if hasattr(os, 'tcsetpgrp'):
                    os.tcsetpgrp(0, os.getpgrp())
            except (AttributeError, OSError):
                pass

            # Begin with the same broken/raw state left by an interrupted
            # interactive shell. The production helper must restore output
            # translation, canonical input, echo, signals, and VINTR.
            tty.setraw(0)
            cli_common.prepare_terminal()
            os.write(1, b'PTY_READY\\n')
            try:
                os.read(0, 1)
            except KeyboardInterrupt:
                os.write(1, b'CTRL_C_KEYBOARD_INTERRUPT\\n')
                raise SystemExit(0)
            os.write(1, b'NO_INTERRUPT\\n')
            raise SystemExit(2)
        '''), encoding='utf-8')

    def read_until(self, descriptor, output, marker, timeout=5.0):
        deadline = time.monotonic() + timeout
        while marker not in output:
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, f'Missing {marker!r}: {bytes(output)!r}')
            readable, _, _ = select.select([descriptor], [], [], remaining)
            self.assertTrue(readable, f'Missing {marker!r}: {bytes(output)!r}')
            try:
                data = os.read(descriptor, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b''
            self.assertTrue(data, f'PTY closed before {marker!r}: {bytes(output)!r}')
            output.extend(data)

    def wait_for_child(self, process, timeout=5.0):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if process.poll() is not None:
                return process.returncode
            time.sleep(0.01)
        self.fail(f'PTY child {process.pid} did not exit')

    def test_raw_pty_is_normalized_and_ctrl_c_becomes_keyboard_interrupt(self):
        output = bytearray()
        master, slave = pty.openpty()
        environment = os.environ.copy()
        current_path = environment.get('PYTHONPATH', '')
        environment['PYTHONPATH'] = os.pathsep.join(
            part for part in (str(self.repo_root), current_path) if part
        )
        try:
            process = subprocess.Popen(
                [sys.executable, str(self.helper)],
                cwd=self.repo_root,
                env=environment,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                start_new_session=True,
            )
        except BaseException:
            os.close(master)
            raise
        finally:
            os.close(slave)

        child_reaped = False
        try:
            # ONLCR is observable on the PTY master: the child wrote only LF,
            # while a normalized terminal emits CRLF for aligned output.
            self.read_until(master, output, b'PTY_READY\r\n')
            self.assertNotIn(b'PTY_READY\n', output.replace(b'PTY_READY\r\n', b''))

            # In canonical mode with ISIG/VINTR restored, the terminal driver
            # turns this byte into SIGINT for the foreground child process.
            os.write(master, b'\x03')
            self.read_until(master, output, b'CTRL_C_KEYBOARD_INTERRUPT\r\n')
            returncode = self.wait_for_child(process)
            child_reaped = True
            self.assertEqual(returncode, 0)
            self.assertNotIn(b'NO_INTERRUPT', output)
        finally:
            os.close(master)
            if not child_reaped:
                try:
                    process.kill()
                except ProcessLookupError:
                    pass
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass


if __name__ == '__main__':
    unittest.main()
