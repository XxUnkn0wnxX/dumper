"""Mocked ADB tests for the maintainer-facing DRM browser helper."""

from pathlib import Path
import shlex
import subprocess
import tempfile
import unittest
from unittest import mock

from Helpers import Browser as browser


class BrowserHelperTests(unittest.TestCase):
    def setUp(self):
        self.tmp_root = Path(__file__).resolve().parents[1] / '.tmp'
        self.tmp_root.mkdir(parents=True, exist_ok=True)
        self.tempdir = tempfile.TemporaryDirectory(prefix='dumper-browser-', dir=self.tmp_root)
        self.site_file = Path(self.tempdir.name) / 'drm_test_site.txt'
        self.site_file.write_text(
            '# active test page\nhttps://example.test/drm#fragment\n',
            encoding='utf-8',
        )
        self.logger = mock.Mock()
        self.calls = []
        self.flags_mode = 'existing'
        self.chrome_enabled = True
        self.flags_content = (
            'chrome --keep="two words" --user-agent="Keep Me" '
            '--literal=C:\\temp --dollar=$HOME --backtick=`tick` '
            "--single-user-agent='Single UA with spaces' "
            "--single-literal='C:\\single\\$HOME`tick`' "
            "--single-nested='nested \"double\"' "
            '--double-nested="nested \'single\'" '
            '--autoplay-policy=none\n'
        )

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def result(stdout='', stderr='', returncode=0):
        return subprocess.CompletedProcess([], returncode, stdout, stderr)

    def run_command(self, command, **kwargs):
        self.calls.append((command, kwargs))
        if command[1:] == ['devices', '-l']:
            return self.result('List of devices attached\nemulator-5554\tdevice product:sdk\n')

        self.assertEqual(command[:4], ['/adb', '-s', 'emulator-5554', 'shell'])
        remote = command[4]
        if remote == "pm path com.android.chrome":
            return self.result('package:/data/app/com.android.chrome/base.apk\n')
        if remote == "pm list packages -e com.android.chrome":
            return self.result('package:com.android.chrome\n' if self.chrome_enabled else '')
        if remote.startswith('am set-debug-app'):
            return self.result('')
        # Check the write command first: it also contains the flags path and
        # must not be mistaken for the read command.
        if 'cat >' in remote:
            return self.result('')
        if remote.startswith('if test -L') and 'chrome-command-line' in remote:
            if self.flags_mode == 'missing':
                return self.result('__DUMPER_CHROME_FLAGS_MISSING__\n')
            if self.flags_mode == 'symlink':
                return self.result('__DUMPER_CHROME_FLAGS_SYMLINK__\n')
            if self.flags_mode == 'malformed-double':
                return self.result('__DUMPER_CHROME_FLAGS_EXISTS__\nchrome --bad="unterminated\n')
            if self.flags_mode == 'malformed-single':
                return self.result("__DUMPER_CHROME_FLAGS_EXISTS__\nchrome --bad='unterminated\n")
            return self.result(
                '__DUMPER_CHROME_FLAGS_EXISTS__\n' + self.flags_content
            )
        if remote == 'am force-stop com.android.chrome':
            return self.result('')
        if remote.startswith('am start'):
            return self.result('Starting: Intent { act=android.intent.action.VIEW }\n')
        self.fail(f'unexpected ADB command: {remote!r}')

    def launch(self, *, site_file=None):
        return browser.launch_test_page(
            'emulator-5554',
            self.logger,
            site_file=site_file or self.site_file,
        )

    def close(self, device_id='emulator-5554'):
        return browser.close_test_browser(device_id, self.logger)

    def test_site_parser_requires_one_valid_active_url_and_preserves_fragment(self):
        self.site_file.write_text(
            '\ufeff# comment\n\nhttps://example.test/path#keep-this-fragment\n',
            encoding='utf-8',
        )
        self.assertEqual(
            browser.read_test_site(self.site_file, self.logger),
            'https://example.test/path#keep-this-fragment',
        )

        for contents in ('', '# comment\n', 'https://one.test\nhttps://two.test\n'):
            with self.subTest(contents=contents):
                self.site_file.write_text(contents, encoding='utf-8')
                self.assertIsNone(browser.read_test_site(self.site_file, self.logger))

    def test_site_parser_rejects_injection_userinfo_and_bad_ports(self):
        invalid = (
            'http://example.test',
            'https://user:pass@example.test/path',
            'https://example.test:bad/path',
            'https://example.test:/path',
            'https://example.test/path with-space',
            'https://example.test/path\x00',
            'https://',
        )
        for line_number, value in enumerate(invalid, 1):
            with self.subTest(value=value):
                self.site_file.write_text(f'{value}\n', encoding='utf-8')
                self.assertIsNone(browser.read_test_site(self.site_file, self.logger))
        self.assertTrue(any('line' in call.args[0] for call in self.logger.warning.call_args_list))

    def test_site_gate_never_resolves_adb_for_missing_invalid_or_multiple_urls(self):
        cases = {
            'missing': None,
            'empty': '',
            'comment-only': '# reference only\n\n',
            'invalid': 'http://example.test\n',
            'multiple': 'https://one.test\nhttps://two.test\n',
        }
        with mock.patch.object(browser, 'resolve_adb') as resolve, \
                mock.patch.object(browser.subprocess, 'run') as run:
            for label, contents in cases.items():
                with self.subTest(label=label):
                    path = self.site_file if label != 'missing' else Path(self.tempdir.name) / 'does-not-exist.txt'
                    if contents is not None:
                        path.write_text(contents, encoding='utf-8')
                    self.assertFalse(self.launch(site_file=path))
            resolve.assert_not_called()
            run.assert_not_called()

    def test_matching_online_device_and_chrome_launch_successfully(self):
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=self.run_command):
            self.assertTrue(self.launch())

        remotes = [command[4] for command, _kwargs in self.calls if len(command) > 4]
        self.assertEqual(remotes[-2], 'am force-stop com.android.chrome')
        self.assertTrue(remotes[-1].startswith('am start -a android.intent.action.VIEW'))
        start_args = shlex.split(remotes[-1])
        self.assertEqual(start_args[-1], 'https://example.test/drm#fragment')
        self.assertLess(remotes.index(remotes[-3]), remotes.index(remotes[-2]))
        write_call = next(
            (kwargs for command, kwargs in self.calls
             if len(command) > 4 and 'cat >' in command[4]),
            None,
        )
        self.assertIsNotNone(write_call)
        self.assertIn('--keep="two words"', write_call['input'])
        self.assertIn('--user-agent="Keep Me"', write_call['input'])
        self.assertIn("--single-user-agent='Single UA with spaces'", write_call['input'])
        self.assertIn(r"--single-literal='C:\single\$HOME`tick`'", write_call['input'])
        self.assertIn("--single-nested='nested \"double\"'", write_call['input'])
        self.assertIn('--double-nested="nested \'single\'"', write_call['input'])
        self.assertIn(r'--literal=C:\temp', write_call['input'])
        self.assertIn('--dollar=$HOME', write_call['input'])
        self.assertIn('--backtick=`tick`', write_call['input'])
        self.assertIn('--disable-fre', write_call['input'])
        self.assertIn('--no-first-run', write_call['input'])
        self.assertIn('--autoplay-policy=no-user-gesture-required', write_call['input'])
        self.assertIn('--disable-startup-promos-for-testing', write_call['input'])
        self.assertIn('--propagate-iph-for-testing', write_call['input'])
        self.assertIn('--disable-default-browser-promo', write_call['input'])
        self.assertIn(
            '--enable-features=NotificationPermissionVariant:permission_request_max_count/0,'
            'DisablePrivacySandboxPrompts',
            write_call['input'],
        )
        self.assertNotRegex(write_call['input'], r'\b(?:grant|revoke|pm clear)\b')
        self.assertNotIn('--autoplay-policy=none', write_call['input'])
        for _command, kwargs in self.calls:
            self.assertIs(kwargs['shell'], False)
            self.assertEqual(kwargs['timeout'], 5)

    def test_managed_flags_are_inserted_before_existing_end_of_options_marker(self):
        self.flags_content = 'chrome --keep --enable-features=Existing<Trial -- --passthrough\n'
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=self.run_command):
            self.assertTrue(self.launch())

        write_call = next(kwargs for command, kwargs in self.calls if len(command) > 4 and 'cat >' in command[4])
        written = write_call['input'].strip()
        self.assertLess(written.index('--disable-fre'), written.index(' -- '))
        self.assertLess(written.index('--no-first-run'), written.index(' -- '))
        self.assertLess(written.index('--autoplay-policy=no-user-gesture-required'), written.index(' -- '))
        self.assertLess(written.index('--enable-features='), written.index(' -- '))
        self.assertTrue(written.endswith('-- --passthrough'))

    def test_missing_flags_file_starts_with_chrome_argv0(self):
        self.flags_mode = 'missing'
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=self.run_command):
            self.assertTrue(self.launch())

        write_call = next(kwargs for command, kwargs in self.calls if len(command) > 4 and 'cat >' in command[4])
        self.assertTrue(write_call['input'].startswith('_ '))

    def test_unterminated_single_or_double_flags_stop_before_debug_selection(self):
        for mode in ('malformed-single', 'malformed-double'):
            with self.subTest(mode=mode):
                self.flags_mode = mode
                self.calls.clear()
                with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                        mock.patch.object(browser.subprocess, 'run', side_effect=self.run_command):
                    self.assertFalse(self.launch())
                remotes = [command[4] for command, _ in self.calls if len(command) > 4]
                self.assertFalse(any('set-debug-app' in remote for remote in remotes))
                self.assertFalse(any('force-stop' in remote for remote in remotes))

    def test_disabled_chrome_stops_before_debug_selection(self):
        self.chrome_enabled = False
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=self.run_command):
            self.assertFalse(self.launch())
        remotes = [command[4] for command, _ in self.calls if len(command) > 4]
        self.assertFalse(any('set-debug-app' in remote for remote in remotes))
        self.assertFalse(any('force-stop' in remote for remote in remotes))

    def test_url_with_shell_metacharacters_remains_one_start_argument(self):
        url = "https://example.test/drm?x=';$()#fragment"
        self.site_file.write_text(url + '\n', encoding='utf-8')
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=self.run_command):
            self.assertTrue(self.launch())

        start_remote = next(
            command[4] for command, _ in self.calls
            if len(command) > 4 and command[4].startswith('am start')
        )
        self.assertEqual(shlex.split(start_remote)[-1], url)
        self.assertIn(";$()#fragment", start_remote)

    def test_flag_serialization_round_trips_spaces_quotes_and_backslashes(self):
        raw = r'chrome --label="two words" --quote="a\"b" --path=C:\temp --dollar=$HOME --tick=`tick`'
        tokens = browser._parse_chrome_flags(raw)
        self.assertEqual(browser._serialize_chrome_flags(tokens), raw + '\n')

    def test_feature_policy_removes_owned_conflicts_and_retains_unknown_entries(self):
        raw = (
            'chrome --keep="two words" '
            '--enable-features="Unknown<Trial:Group,NotificationPermissionVariant<Old,'
            '*DisablePrivacySandboxPrompts<OldTrial,Keep:Param/1" '
            '--disable-features="NotificationPermissionVariant:blocked/1,'
            '*DisablePrivacySandboxPrompts<Blocked,Other<Trial" -- --tail\n'
        )
        merged = browser._merge_chrome_flags(browser._parse_chrome_flags(raw))
        values = [flag.value for flag in merged]
        enable = [value for value in values if value.startswith('--enable-features=')]
        disable = [value for value in values if value.startswith('--disable-features=')]

        self.assertEqual(len(enable), 1)
        self.assertEqual(len(disable), 1)
        self.assertIn('Unknown<Trial:Group', enable[0])
        self.assertIn('Keep:Param/1', enable[0])
        self.assertIn('Other<Trial', disable[0])
        self.assertIn('NotificationPermissionVariant:permission_request_max_count/0', enable[0])
        self.assertIn('DisablePrivacySandboxPrompts', enable[0])
        self.assertNotIn('NotificationPermissionVariant<Old', enable[0])
        self.assertNotIn('DisablePrivacySandboxPrompts<OldTrial', enable[0])
        self.assertNotIn('NotificationPermissionVariant:blocked/1', disable[0])
        self.assertNotIn('DisablePrivacySandboxPrompts<Blocked', disable[0])
        self.assertTrue(values[-2:] == ['--', '--tail'])

    def test_feature_policy_removes_starred_grouped_managed_entries(self):
        raw = (
            'chrome '
            '--enable-features="NotificationPermissionVariant.Group:permission_request_max_count/5,'
            '*DisablePrivacySandboxPrompts.Group<OldStudy,Unrelated.Group:Param/1" '
            '--disable-features="*NotificationPermissionVariant.Other:blocked/1,'
            'DisablePrivacySandboxPrompts.Other<Blocked,Other.Group<Study"\n'
        )
        merged = browser._merge_chrome_flags(browser._parse_chrome_flags(raw))
        values = [flag.value for flag in merged]
        enable = next(value for value in values if value.startswith('--enable-features='))
        disable = next(value for value in values if value.startswith('--disable-features='))

        self.assertIn('Unrelated.Group:Param/1', enable)
        self.assertIn('Other.Group<Study', disable)
        self.assertNotIn('NotificationPermissionVariant.Group', enable)
        self.assertNotIn('DisablePrivacySandboxPrompts.Group', enable)
        self.assertNotIn('NotificationPermissionVariant.Other', disable)
        self.assertNotIn('DisablePrivacySandboxPrompts.Other', disable)
        self.assertIn('NotificationPermissionVariant:permission_request_max_count/0', enable)
        self.assertIn('DisablePrivacySandboxPrompts', enable)

    def test_reconstructed_feature_values_round_trip_chrome_quotes_and_backslashes(self):
        raw = r'chrome --enable-features="Quoted Feature,With\backslash,Has\"quote" --keep="two words"'
        merged = browser._merge_chrome_flags(browser._parse_chrome_flags(raw))
        serialized = browser._serialize_chrome_flags(merged)
        reparsed = browser._parse_chrome_flags(serialized)
        values = [flag.value for flag in reparsed]
        enable = next(value for value in values if value.startswith('--enable-features='))

        self.assertIn('Quoted Feature', enable)
        self.assertIn(r'With\backslash', enable)
        self.assertIn('Has"quote', enable)
        self.assertIn('--keep=two words', values)

    def test_duplicate_feature_switches_use_effective_last_value_and_merge_is_idempotent(self):
        raw = (
            'chrome --enable-features=Shadowed --enable-features=Effective,Effective '
            '--disable-features=ShadowedDisabled --disable-features=EffectiveDisabled,EffectiveDisabled\n'
        )
        first = browser._merge_chrome_flags(browser._parse_chrome_flags(raw))
        first_serialized = browser._serialize_chrome_flags(first)
        second_serialized = browser._serialize_chrome_flags(
            browser._merge_chrome_flags(browser._parse_chrome_flags(first_serialized))
        )
        values = [flag.value for flag in first]

        self.assertEqual(first_serialized, second_serialized)
        self.assertEqual(sum(value.startswith('--enable-features=') for value in values), 1)
        self.assertEqual(sum(value.startswith('--disable-features=') for value in values), 1)
        self.assertIn('Effective,', next(value for value in values if value.startswith('--enable-features=')))
        self.assertNotIn('Shadowed', first_serialized)
        self.assertIn('EffectiveDisabled', first_serialized)

    def test_offline_or_different_device_stops_before_chrome_commands(self):
        def offline(command, **kwargs):
            self.calls.append((command, kwargs))
            return self.result('List of devices attached\nemulator-5554\toffline\n')

        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=offline):
            self.assertFalse(self.launch())
        self.assertEqual(len(self.calls), 1)

        self.calls.clear()
        def other_device(command, **kwargs):
            self.calls.append((command, kwargs))
            return self.result('List of devices attached\nother\tdevice\n')
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=other_device):
            self.assertFalse(self.launch())
        self.assertEqual(len(self.calls), 1)

    def test_missing_adb_and_chrome_are_actionable_and_nonfatal(self):
        with mock.patch.object(browser, 'resolve_adb', side_effect=browser.SetupError('adb missing')):
            self.assertFalse(self.launch())

        calls = []
        def missing_chrome(command, **kwargs):
            calls.append((command, kwargs))
            if command[1:] == ['devices', '-l']:
                return self.result('List of devices attached\nemulator-5554\tdevice\n')
            return self.result('Error: package com.android.chrome not found\n', returncode=1)
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=missing_chrome):
            self.assertFalse(self.launch())
        self.assertEqual(len(calls), 2)

    def test_symlink_flags_timeout_and_text_failures_stop_before_force_stop(self):
        def symlink(command, **kwargs):
            self.calls.append((command, kwargs))
            if command[1:] == ['devices', '-l']:
                return self.result('List of devices attached\nemulator-5554\tdevice\n')
            remote = command[4]
            if remote == 'pm path com.android.chrome':
                return self.result('package:/data/app/chrome.apk\n')
            if remote == 'pm list packages -e com.android.chrome':
                return self.result('package:com.android.chrome\n')
            if remote.startswith('am set-debug-app'):
                return self.result('')
            if 'chrome-command-line' in remote:
                return self.result('__DUMPER_CHROME_FLAGS_SYMLINK__\n')
            self.fail(remote)

        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=symlink):
            self.assertFalse(self.launch())
        self.assertFalse(any('force-stop' in command[4] for command, _ in self.calls if len(command) > 4))

        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=subprocess.TimeoutExpired('/adb', 5)):
            self.assertFalse(self.launch())

        self.calls.clear()
        def start_failure(command, **kwargs):
            result = self.run_command(command, **kwargs)
            if len(command) > 4 and command[4].startswith('am start'):
                return self.result('SecurityException: blocked\n')
            return result
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=start_failure):
            self.assertFalse(self.launch())
        remotes = [command[4] for command, _ in self.calls if len(command) > 4]
        self.assertIn('am force-stop com.android.chrome', remotes)
        self.assertFalse(any('Opened ' in call.args[0] for call in self.logger.info.call_args_list))

    def test_keyboard_interrupt_is_not_swallowed(self):
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.launch()

    def test_failed_prelaunch_chrome_stop_prevents_relaunch(self):
        def cannot_stop(command, **kwargs):
            result = self.run_command(command, **kwargs)
            if command[1:] == ['-s', 'emulator-5554', 'shell', 'am force-stop com.android.chrome']:
                return self.result('SecurityException: stop denied\n', returncode=1)
            return result

        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=cannot_stop):
            self.assertFalse(self.launch())
        remotes = [command[4] for command, _kwargs in self.calls if len(command) > 4]
        self.assertEqual(remotes[-1], 'am force-stop com.android.chrome')
        self.assertFalse(any(command.startswith('am start ') for command in remotes))
        self.logger.warning.assert_called_once()

    def test_close_uses_exact_selected_serial_and_one_remote_command(self):
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=self.run_command):
            self.assertTrue(self.close())

        self.assertEqual(len(self.calls), 1)
        command, kwargs = self.calls[0]
        self.assertEqual(
            command,
            ['/adb', '-s', 'emulator-5554', 'shell', 'am force-stop com.android.chrome'],
        )
        self.assertFalse(kwargs['shell'])
        self.assertEqual(kwargs['timeout'], 5)

    def test_close_does_not_read_flags_or_change_chrome_data(self):
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=self.run_command):
            self.assertTrue(self.close())

        remote = self.calls[0][0][4]
        self.assertEqual(remote, 'am force-stop com.android.chrome')
        self.assertNotIn(browser.CHROME_FLAGS_PATH, remote)
        self.assertNotIn('pm clear', remote)
        self.assertNotIn('set-debug-app', remote)

    def test_close_missing_adb_is_nonfatal(self):
        with mock.patch.object(browser, 'resolve_adb', side_effect=browser.SetupError('adb missing')), \
                mock.patch.object(browser.subprocess, 'run') as run:
            self.assertFalse(self.close())

        run.assert_not_called()
        self.logger.warning.assert_called_once()
        self.assertIn('Capture files are retained', self.logger.warning.call_args.args[0])

    def test_close_offline_nonzero_and_error_marker_are_nonfatal(self):
        results = (
            self.result('error: device offline\n', returncode=1),
            self.result('Error: failed to stop package\n'),
        )
        for result in results:
            with self.subTest(result=result):
                with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                        mock.patch.object(browser.subprocess, 'run', return_value=result):
                    self.assertFalse(self.close())

    def test_close_timeout_is_nonfatal(self):
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=subprocess.TimeoutExpired('/adb', 5)):
            self.assertFalse(self.close())

    def test_close_rejects_invalid_id_before_resolving_adb(self):
        for device_id in ('', None, 123):
            with self.subTest(device_id=device_id), \
                    mock.patch.object(browser, 'resolve_adb') as resolve, \
                    mock.patch.object(browser.subprocess, 'run') as run:
                self.assertFalse(self.close(device_id))
            resolve.assert_not_called()
            run.assert_not_called()

    def test_close_keyboard_interrupt_is_not_swallowed(self):
        with mock.patch.object(browser, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(browser.subprocess, 'run', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                self.close()


if __name__ == '__main__':
    unittest.main()
