"""Tests for the bounded foreground-server process identity primitive.

These tests execute the generated POSIX shell function against fixture files
under ``.tmp``. They do not inspect or signal a real process.
"""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from tools import setup_frida as setup


@unittest.skipUnless(os.name == 'posix', 'Generated identity shell requires POSIX /bin/sh')
class ForegroundProcessIdentityTests(unittest.TestCase):
    """Validate PID start-time extraction from Linux-style stat rows."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_root = setup.ROOT / '.tmp'
        cls.tmp_root.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='frida-identity-', dir=self.tmp_root,
        )
        self.proc_root = Path(self.temporary.name) / 'proc'
        self.proc_root.mkdir()

    def tearDown(self):
        self.temporary.cleanup()

    @staticmethod
    def stat_row(pid, comm, *, state='S', start='123456'):
        """Build a minimal /proc/PID/stat row with a controllable field 22."""
        # After ``(comm)`` Linux field 3 is state. The 19 values following it
        # put ``start`` at field 22, while the trailing values make the row
        # look like a normal complete stat record.
        fields = [state, *[str(value) for value in range(4, 22)], str(start), '0', '0']
        return f'{pid} ({comm}) ' + ' '.join(fields) + '\n'

    def identity_source(self):
        source = setup.foreground_process_identity_command()
        # The production helper uses /proc literally on Android. Replace only
        # that root with this fixture directory; the shell parser remains real.
        return source.replace('"/proc/', f'"{self.proc_root}/')

    def read_identity(self, pid=42):
        script = (
            self.identity_source()
            + f'\nfrida_pid={pid}; frida_read_identity; '
            + 'printf "%s\\n" "$frida_current_start"\n'
        )
        return subprocess.run(
            ['/bin/sh', '-c', script],
            text=True,
            capture_output=True,
            check=False,
        )

    def write_stat(self, pid, content):
        path = self.proc_root / str(pid)
        path.mkdir(exist_ok=True)
        (path / 'stat').write_text(content, encoding='utf-8')

    def test_start_time_field_survives_spaces_and_closing_parenthesis_in_comm(self):
        self.write_stat(
            42,
            self.stat_row(42, 'com.example service) worker', start='987654321'),
        )

        result = self.read_identity()

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, '987654321\n')

    def test_zombie_missing_and_malformed_rows_are_unusable(self):
        cases = {
            'zombie': self.stat_row(42, 'dead worker', state='Z', start='987654'),
            'dead': self.stat_row(42, 'dead worker', state='X', start='987654'),
            'malformed-start': self.stat_row(42, 'bad worker', start='not-a-number'),
            'short-row': '42 (short) S 4 5\n',
        }
        for name, content in cases.items():
            with self.subTest(case=name):
                self.write_stat(42, content)
                result = self.read_identity()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, '\n')
                (self.proc_root / '42' / 'stat').unlink()

        missing = self.read_identity(43)
        self.assertEqual(missing.returncode, 0, missing.stderr)
        self.assertEqual(missing.stdout, '\n')


if __name__ == '__main__':
    unittest.main()
