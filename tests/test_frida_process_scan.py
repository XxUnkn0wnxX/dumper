"""Focused tests for the one-pass managed Frida process scan.

The scan is intentionally exercised as the generated remote shell script.  A
local ``ls`` shell function supplies synthetic ``/proc`` link listings, so the
tests cover shell quoting and exit behavior without an ADB connection, a real
process lookup, or signals.
"""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

from tools import setup_frida as setup


@unittest.skipUnless(os.name == 'posix', 'Generated Android shell tests require a local POSIX shell')
class ManagedProcessScanTests(unittest.TestCase):
    """Run generated scan scripts against deterministic fake ``ls`` output."""

    @classmethod
    def setUpClass(cls):
        # Keep generated fixtures in the repository's ignored scratch area.
        cls.tmp_root = setup.ROOT / '.tmp'
        cls.tmp_root.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.fixture_dir = tempfile.TemporaryDirectory(
            prefix='frida-process-scan-', dir=self.tmp_root,
        )
        self.fixture_path = Path(self.fixture_dir.name) / 'ls-output.txt'
        self.count_path = Path(self.fixture_dir.name) / 'ls-count.txt'

    def tearDown(self):
        self.fixture_dir.cleanup()

    @staticmethod
    def link_line(pid, target, metadata='root root 0 2026-09-20 12:00'):
        """Build an ``ls -ld /proc/PID/exe``-style line.

        The parser must ignore the variable metadata and use only the path and
        link target suffix.
        """
        return f'lrwxrwxrwx {metadata} /proc/{pid}/exe -> {target}'

    def run_scan(self, listing='', *, status=0, include_deleted=True,
                 fail_if_found=False, remote='/data/local/tmp/frida-server',
                 count=False, trailing=''):
        """Execute one generated script in ``/bin/sh`` with a fake ``ls``."""
        self.fixture_path.write_text(listing, encoding='utf-8')
        with mock.patch.object(setup, 'REMOTE_SERVER', remote):
            command = setup._managed_server_scan_command(
                include_deleted=include_deleted,
                fail_if_found=fail_if_found,
            )

        # A function named ls is found by ``LC_ALL=C ls`` in POSIX shells.  It
        # reads fixture data as bytes/text, so shell metacharacters in a link
        # target remain data and can never become commands.
        prefix = '''
ls() {
    cat "$SYNTHETIC_LS_FILE"
    if test -n "$SYNTHETIC_LS_COUNT"; then
        printf 'x' >> "$SYNTHETIC_LS_COUNT"
    fi
    return "$SYNTHETIC_LS_STATUS"
}
'''
        script = prefix + command
        if trailing:
            script += f'\nprintf %s {shlex.quote(trailing)}\n'
        environment = os.environ.copy()
        environment.update({
            'SYNTHETIC_LS_FILE': str(self.fixture_path),
            'SYNTHETIC_LS_STATUS': str(status),
            'SYNTHETIC_LS_COUNT': str(self.count_path) if count else '',
        })
        return subprocess.run(
            ['/bin/sh', '-c', script],
            env=environment,
            text=True,
            capture_output=True,
            check=False,
            timeout=5,
        )

    def test_exact_current_and_deleted_targets_are_selected(self):
        remote = '/data/local/tmp/frida-server'
        listing = '\n'.join([
            self.link_line(42, remote),
            self.link_line(43, f'{remote} (deleted)'),
            self.link_line(44, f'{remote}-other'),
            self.link_line(45, f'{remote}/child'),
        ]) + '\n'

        result = self.run_scan(listing)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['42', '43'])

    def test_deleted_target_can_be_excluded(self):
        remote = '/data/local/tmp/frida-server'
        listing = '\n'.join([
            self.link_line(42, remote),
            self.link_line(43, f'{remote} (deleted)'),
        ]) + '\n'

        result = self.run_scan(listing, include_deleted=False)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['42'])

    def test_metadata_variations_do_not_change_path_matching(self):
        remote = '/data/local/tmp/frida-server'
        listing = '\n'.join([
            self.link_line(10, remote, 'u0_a1 u0_a1 0 Jan 1 00:00'),
            self.link_line(11, remote, 'root root 0 2024-01-01 01:02:03'),
            self.link_line(12, remote, 'system shell 0 Dec 31 23:59'),
        ]) + '\n'

        result = self.run_scan(listing)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['10', '11', '12'])

    def test_remote_path_with_spaces_quotes_and_shell_characters_is_literal(self):
        remote = '/data/local/tmp/odd dir/frida-\'server"$x;echo PWNED'
        listing = '\n'.join([
            self.link_line(77, remote),
            self.link_line(78, remote + ' (deleted)'),
            self.link_line(79, remote + '-other'),
        ]) + '\n'

        result = self.run_scan(listing, remote=remote)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['77', '78'])
        self.assertNotIn('PWNED', result.stdout + result.stderr)

    def test_ls_status_one_is_tolerated_but_larger_failure_is_closed(self):
        remote = '/data/local/tmp/frida-server'
        listing = self.link_line(42, remote) + '\n'

        tolerated = self.run_scan(listing, status=1)
        self.assertEqual(tolerated.returncode, 0, tolerated.stderr)
        self.assertEqual(tolerated.stdout.splitlines(), ['42'])

        fatal = self.run_scan(listing, status=2)
        self.assertEqual(fatal.returncode, 2)
        self.assertIn('Could not inspect Android process executable links', fatal.stderr)
        self.assertEqual(fatal.stdout, '')

    def test_malformed_matching_pid_and_pid_one_fail_closed(self):
        remote = '/data/local/tmp/frida-server'

        malformed = self.run_scan(self.link_line('12x', remote) + '\n')
        self.assertEqual(malformed.returncode, 2)
        self.assertEqual(malformed.stdout, '')

        pid_one = self.run_scan(self.link_line(1, remote) + '\n')
        self.assertEqual(pid_one.returncode, 2)
        self.assertEqual(pid_one.stdout, '')

    def test_absence_guard_exits_before_same_shell_trailing_work(self):
        remote = '/data/local/tmp/frida-server'
        found = self.run_scan(
            self.link_line(42, remote) + '\n',
            fail_if_found=True,
            trailing='TRAILING',
        )
        self.assertEqual(found.returncode, 1)
        self.assertNotIn('TRAILING', found.stdout)

        # A readable inventory with no managed target is the successful
        # absence case; a genuinely empty inventory is covered by the
        # fail-closed test below.
        absent = self.run_scan(
            self.link_line(55, '/system/bin/app_process'),
            fail_if_found=True,
            trailing='TRAILING',
        )
        self.assertEqual(absent.returncode, 0, absent.stderr)
        self.assertIn('TRAILING', absent.stdout)

    def test_empty_listing_fails_closed(self):
        for listing in ('', 'unrecognized listing format\n'):
            for status in (0, 1):
                with self.subTest(listing=listing, status=status):
                    result = self.run_scan(listing, status=status)
                    self.assertEqual(result.returncode, 2)
                    self.assertEqual(result.stdout, '')

    def test_large_listing_uses_one_ls_invocation(self):
        remote = '/data/local/tmp/frida-server'
        rows = [self.link_line(500, remote)]
        rows.extend(self.link_line(pid, f'/system/bin/other-{pid}') for pid in range(1000, 1300))

        result = self.run_scan('\n'.join(rows) + '\n', count=True)

        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ['500'])
        self.assertEqual(self.count_path.read_text(encoding='utf-8'), 'x')

    def test_managed_server_pid_parser_sorts_and_deduplicates_scan_output(self):
        scan_output = '43\n42\n43\n'
        completed = type('Completed', (), {'stdout': scan_output})()
        with mock.patch.object(setup, 'run_root', return_value=completed):
            self.assertEqual(
                setup.managed_server_pids('/adb', 'serial', 'direct'),
                ['42', '43'],
            )

    def test_managed_server_pid_parser_rejects_invalid_or_privileged_pid(self):
        for scan_output in ('not-a-pid\n', '1\n', '0\n'):
            with self.subTest(scan_output=scan_output):
                completed = type('Completed', (), {'stdout': scan_output})()
                with mock.patch.object(setup, 'run_root', return_value=completed):
                    with self.assertRaisesRegex(setup.SetupError, 'invalid managed Frida process ID'):
                        setup.managed_server_pids('/adb', 'serial', 'direct')


class CommandTimeoutTests(unittest.TestCase):
    def test_timeout_explains_stage_without_dumping_remote_script(self):
        command = ['/adb', 'shell', 'LONG_REMOTE_SCRIPT_MARKER']
        with mock.patch.object(
            setup.subprocess, 'run', side_effect=subprocess.TimeoutExpired(command, 30),
        ):
            with self.assertRaises(setup.SetupError) as raised:
                setup.command_output(command, 'Finding managed Frida server processes')
        message = str(raised.exception)
        self.assertIn('Finding managed Frida server processes timed out after 30 seconds', message)
        self.assertIn('device/ADB connection', message)
        self.assertNotIn('LONG_REMOTE_SCRIPT_MARKER', message)


if __name__ == '__main__':
    unittest.main()
