"""Exercise the real foreground commands with local terminals, never Android.

A fake ADB relays a raw host terminal into a separate device-like PTY. Verify
that it replaces the helper process and that Ctrl+C reaches the remote server,
with root and ordinary shell exits behaving like an interactive ADB session.
"""

import errno
import os
from pathlib import Path
import select
import shlex
import signal
import sys
import subprocess
import tempfile
import time
import unittest

from tools import setup_frida as setup

if os.name == 'posix':
    import pty


# These programs run only under temporary local paths. The fake su exercises
# both command syntaxes without gaining privileges or invoking the system's su.
FAKE_SU = '''import os, sys
os.environ['FRIDA_TEST_SHELL_LAYER'] = 'root'
if sys.argv[1] == '-c':
    os.execv('/bin/sh', ['sh', '-c', sys.argv[2]])
assert sys.argv[1:4] == ['0', 'sh', '-c'], sys.argv
os.execv('/bin/sh', ['sh', '-c', sys.argv[4]])
'''

FAKE_SERVER = '''import os, signal, sys, time
def stop(signum, frame):
    print('SERVER_STOPPED', flush=True)
    sys.exit(int(os.environ['FRIDA_TEST_STOP_STATUS']))
if os.environ['FRIDA_TEST_IGNORE_INT'] == '1':
    def request_stop(signum, frame):
        # The supervisor must bound cleanup even when a server ignores the
        # first terminal interrupt. It deliberately stays alive until the
        # supervisor's same-process identity guard force-stops it.
        print('SERVER_STOP_REQUESTED', flush=True)
    signal.signal(signal.SIGINT, request_stop)
else:
    signal.signal(signal.SIGINT, stop)
print('SERVER_STARTED', flush=True)
if os.environ['FRIDA_TEST_FAIL_START'] == '1':
    sys.exit(7)
while True:
    time.sleep(0.1)
'''

FAKE_ADB = '''import errno, os, pty, select, sys, termios, time, tty
assert sys.argv[1:5] == ['-s', 'test-device', 'shell', '-t'], sys.argv
print('ADB_PID=' + str(os.getpid()), flush=True)
command = sys.argv[-1].replace('/system/bin/sh', '/bin/sh')
saved = termios.tcgetattr(0)
tty.setraw(0)
child, terminal = pty.fork()
if child == 0:
    os.execv('/bin/sh', ['sh', '-c', command])
try:
    while True:
        ready, _, _ = select.select([0, terminal], [], [])
        for source in ready:
            try:
                data = os.read(source, 4096)
            except OSError as error:
                if error.errno != errno.EIO:
                    raise
                data = b''
            if not data:
                os.close(terminal)
                terminal = None
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    ended, result = os.waitpid(child, os.WNOHANG)
                    if ended:
                        sys.exit(os.waitstatus_to_exitcode(result))
                    time.sleep(0.02)
                raise RuntimeError('Fake device terminal did not exit')
            os.write(terminal if source == 0 else 1, data)
finally:
    termios.tcsetattr(0, termios.TCSADRAIN, saved)
    if terminal is not None:
        os.close(terminal)
'''


@unittest.skipUnless(os.name == 'posix', 'Local PTY integration requires POSIX terminals')
class FridaTerminalTests(unittest.TestCase):
    """Verify terminal ownership, shell continuation, and actual exit statuses."""

    def setUp(self):
        setup.TMP_ROOT.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(
            prefix="frida 'terminal-", dir=setup.TMP_ROOT,
        )
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.server = self.make_program('frida-server', FAKE_SERVER)
        self.adb = self.make_program('fake-adb', FAKE_ADB)
        self.make_program('su', FAKE_SU)
        self.make_program('getprop', "print('generic_test_device')\n")
        # Model Android's readable /proc links instead of inspecting the host's
        # process table (macOS has no /proc, and ls exit statuses differ).
        self.make_program('ls', "print('lrwxrwxrwx 1 root root 0 2026-01-01 00:00 /proc/123/exe -> /system/bin/sh')\n")

    def make_program(self, name, source):
        script = self.directory / f'{name}.py'
        script.write_text(source, encoding='utf-8')
        executable = self.directory / name
        # A shell wrapper also supports Python installations whose paths contain
        # spaces, which cannot be represented reliably in a direct shebang.
        executable.write_text(
            '#!/bin/sh\nexec ' + shlex.join([sys.executable, str(script)]) + ' "$@"\n',
            encoding='utf-8',
        )
        executable.chmod(0o755)
        return executable

    def exercise_session(self, root_mode, *, interactive=True, stop_status=0,
                         fail_start=False, hold_seconds=0.1, shell_only=False,
                         ignore_int=False):
        # The host helper needs terminal streams but no controlling terminal of
        # its own. Use Popen instead of forking the unittest runner; only fake
        # ADB's device-side PTY needs a session leader for Ctrl+C delivery.
        terminal, slave = pty.openpty()
        runner = (
            'import sys; from tools import setup_frida as setup; '
            'setup.REMOTE_DIRECTORY = sys.argv[2]; '
            'setup.REMOTE_SERVER = sys.argv[2] + "/frida-server"; '
            # macOS has no Android /proc tree. The production command still
            # gets exercised, while this local identity primitive uses a live
            # host PID query with the same re-check semantics.
            'setup.foreground_process_identity_command = lambda: '
            '\'frida_read_identity() { frida_current_start=$(ps -p "$frida_pid" '
            '-o lstart= 2>/dev/null); test -n "$frida_current_start"; }\'; '
        )
        if shell_only:
            runner += 'setup.open_device_shell(sys.argv[1], "test-device", sys.argv[3])'
        else:
            runner += (
                'setup.run_foreground_server('
                'sys.argv[1], "test-device", sys.argv[3], interactive=sys.argv[4] == "1")'
            )
        environment = os.environ.copy()
        environment['FRIDA_TEST_STOP_STATUS'] = str(stop_status)
        environment['FRIDA_TEST_FAIL_START'] = str(int(fail_start))
        environment['FRIDA_TEST_IGNORE_INT'] = str(int(ignore_int))
        environment['FRIDA_TEST_SHELL_LAYER'] = 'adb'
        environment['PATH'] = str(self.directory) + os.pathsep + environment.get('PATH', '')
        try:
            process = subprocess.Popen(
                [sys.executable, '-c', runner, str(self.adb), str(self.directory),
                 root_mode, str(int(interactive))],
                cwd=setup.ROOT, env=environment, stdin=slave, stdout=slave,
                stderr=slave, start_new_session=True,
            )
        except BaseException:
            os.close(terminal)
            raise
        finally:
            os.close(slave)
        output = bytearray()

        def read_until(marker, timeout=8):
            deadline = time.monotonic() + timeout
            while marker not in output:
                self.assertLess(time.monotonic(), deadline, f'Missing {marker!r}: {output!r}')
                readable, _, _ = select.select([terminal], [], [], 0.1)
                if not readable:
                    continue
                try:
                    data = os.read(terminal, 4096)
                except OSError as error:
                    if error.errno != errno.EIO:
                        raise
                    data = b''
                self.assertTrue(data, f'Terminal closed before {marker!r}: {output!r}')
                output.extend(data)

        try:
            # A spawned child would have a different PID. This proves the real
            # exec handoff, beyond simply mocking os.execv in unit tests.
            read_until(f'ADB_PID={process.pid}\r\n'.encode())
            if not shell_only:
                read_until(b'SERVER_STARTED')
                launch_line = f'generic_test_device:{self.directory} # ./frida-server'.encode()
                self.assertIn(launch_line, output)
                self.assertLess(output.index(launch_line), output.index(b'SERVER_STARTED'))
            if fail_start:
                expected = 7
            else:
                time.sleep(hold_seconds)
                self.assertIsNone(process.poll(), f'Session ended early: {output!r}')
                if not shell_only:
                    os.write(terminal, b'\x03')
                    if ignore_int:
                        read_until(b'SERVER_STOP_REQUESTED', timeout=8)
                    else:
                        read_until(b'SERVER_STOPPED')
                if interactive:
                    # Verify the resulting shell by executing a command instead
                    # of assuming a Bash/mksh-specific prompt string.
                    os.write(terminal, b'printf "CWD=%s\\n" "$PWD"\n')
                    read_until(b'CWD=' + str(self.directory).encode())
                    if ignore_int:
                        # The fallback warning must be emitted before the
                        # returned prompt accepts this first command. The
                        # startup banner contains "force-stops"; assert the
                        # actual supervisor warning's exact wording instead.
                        lower_output = bytes(output).lower()
                        warning = b"force-stopping this session"
                        cwd_marker = b'cwd=' + str(self.directory).encode().lower()
                        self.assertIn(warning, lower_output)
                        self.assertLess(lower_output.index(warning), lower_output.index(cwd_marker))
                    if root_mode != 'direct':
                        os.write(terminal, b'printf "ROOT_LAYER=%s\\n" "$FRIDA_TEST_SHELL_LAYER"\n')
                        read_until(b'ROOT_LAYER=root')
                        # Even a nonzero last command at the root prompt must
                        # return to the original ADB user when leaving su.
                        os.write(terminal, b'false; exit\n')
                        os.write(terminal, b'printf "ADB_LAYER=%s CWD=%s\\n" "$FRIDA_TEST_SHELL_LAYER" "$PWD"\n')
                        read_until(b'ADB_LAYER=adb CWD=' + str(self.directory).encode())
                        self.assertIsNone(process.poll(), 'Leaving su also closed ADB')
                    os.write(terminal, b'exit\n')
                    expected = 0
                else:
                    expected = stop_status
            # Keep acting as the terminal emulator until the helper exits.
            # Waiting without reading can deadlock terminal drain/restore on
            # macOS when the shell prints its final prompt or exit message.
            deadline = time.monotonic() + 8
            while process.poll() is None:
                self.assertLess(time.monotonic(), deadline, f'Session did not exit: {output!r}')
                readable, _, _ = select.select([terminal], [], [], 0.05)
                if readable:
                    try:
                        output.extend(os.read(terminal, 4096))
                    except OSError as error:
                        if error.errno != errno.EIO:
                            raise
            self.assertEqual(process.returncode, expected, output)
        finally:
            os.close(terminal)
            if process.poll() is None:
                # Limit cleanup to the isolated test session, including fake
                # ADB; never signal a real adb or frida-server process.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    pass
                process.wait(timeout=5)

    def test_ctrl_c_returns_to_shell_for_each_root_command(self):
        for root_mode in ('direct', 'su-c', 'su-0'):
            with self.subTest(root_mode=root_mode):
                self.exercise_session(root_mode)

    def test_remote_interrupt_status_also_returns_to_shell(self):
        self.exercise_session('su-c', stop_status=130)

    def test_unresponsive_server_is_force_stopped_before_root_shell(self):
        # The fake server acknowledges Ctrl+C but deliberately remains alive.
        # The remote supervisor must bound the wait, report its fallback, and
        # still return to the same root/ADB shell sequence.
        self.exercise_session('su-c', ignore_int=True)

    def test_shell_only_handoff_and_exit_for_each_root_command(self):
        for root_mode in ('direct', 'su-c', 'su-0'):
            with self.subTest(root_mode=root_mode):
                self.exercise_session(root_mode, shell_only=True)

    def test_no_shell_returns_server_interrupt_status(self):
        for root_mode in ('direct', 'su-c', 'su-0'):
            with self.subTest(root_mode=root_mode):
                self.exercise_session(root_mode, interactive=False, stop_status=130)

    def test_startup_failure_propagates_without_opening_shell(self):
        for interactive in (True, False):
            with self.subTest(interactive=interactive):
                self.exercise_session('su-0', interactive=interactive, fail_start=True)

    @unittest.skipUnless(os.environ.get('FRIDA_TEST_LONG_SESSION') == '1',
                         'Set FRIDA_TEST_LONG_SESSION=1 for the 31-second lifetime check')
    def test_foreground_session_outlives_command_timeout(self):
        self.exercise_session('su-0', hold_seconds=31)


if __name__ == '__main__':
    unittest.main()
