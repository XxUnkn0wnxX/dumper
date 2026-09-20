"""Offline controller tests for the experimental full-auto workflow."""

from contextlib import nullcontext, redirect_stderr, redirect_stdout
import hashlib
import io
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest import mock

import full_auto
from tools import setup_frida


class FakeProcess:
    """Owned-process substitute with observable lifecycle operations."""

    def __init__(self, *, status=None, error=None, close_result=True):
        self.status = status
        self.error = error
        self.close_result = close_result
        self.close_calls = 0

    def poll(self):
        return self.status

    def close(self):
        self.close_calls += 1
        return self.close_result


class FullAutoTests(unittest.TestCase):
    """Use a patched controller root and never contact ADB, GUI, or pip."""

    @classmethod
    def setUpClass(cls):
        cls.repo_tmp = Path(__file__).resolve().parents[1] / '.tmp'
        cls.repo_tmp.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='full-auto-test-', dir=self.repo_tmp,
        )
        self.root = Path(self.temporary.name)
        (self.root / '.tmp').mkdir()
        (self.root / 'key_dumps').mkdir()
        self.root_patch = mock.patch.object(full_auto, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.temporary.cleanup)

    def pair_event(self, name='fresh-pair', *, serial='pixel', api='30', client=b'client-id', key=b'private-key'):
        directory = self.root / 'key_dumps' / name
        directory.mkdir(parents=True)
        (directory / 'client_id.bin').write_bytes(client)
        (directory / 'private_key.pem').write_bytes(key)
        return {
            'event': 'pair_saved',
            'device_id': serial,
            'android_api': api,
            'path': f'key_dumps/{name}',
            'client_sha256': hashlib.sha256(client).hexdigest(),
            'key_sha256': hashlib.sha256(key).hexdigest(),
        }

    def make_controller(self, *, timeout=10, initialize=False):
        return full_auto.AutoRun(
            Path('/current/venv/bin/python'), 'adb-fixture', 'pixel', 30,
            startup_timeout=timeout, initialize=initialize,
        )

    def prepare_init_fixture(self, controller, *, event=None, process=None):
        controller.directory = self.root / '.tmp' / 'session'
        controller.directory.mkdir()
        controller.log_directory = self.root / 'logs'
        controller.log_directory.mkdir()
        process = process or FakeProcess(status=0)
        event = event or {
            'event': 'environment_ready',
            'python': str(Path(os.sys.executable).resolve()),
            'adb': str(Path(os.sys.executable).resolve()),
        }
        controller.events = mock.Mock(return_value=[event])
        controller.start_process = mock.Mock(
            side_effect=lambda role, _args: controller.processes.__setitem__(role, process)
        )
        return process

    def test_supported_target_accepts_every_supported_api(self):
        device = SimpleNamespace(serial='pixel')
        for api in range(full_auto.MIN_ANDROID_API, full_auto.MAX_ANDROID_API + 1):
            with self.subTest(api=api), \
                    mock.patch.object(full_auto.setup_frida, 'list_adb_devices', return_value=['fixture']), \
                    mock.patch.object(full_auto.setup_frida, 'select_device', return_value=device), \
                    mock.patch.object(full_auto.setup_frida, 'validate_target',
                                      return_value=(api, 'arm64-v8a', 'arm64')), \
                    mock.patch.object(full_auto.setup_frida, 'shell_property', return_value='1'):
                self.assertEqual(
                    full_auto.supported_target('adb-fixture', None),
                    ('pixel', api, 'arm64-v8a'),
                )

    def test_prepare_environment_runs_init_child_before_device_preflight(self):
        controller = self.make_controller(initialize=True)
        init_process = self.prepare_init_fixture(controller)
        with mock.patch.object(full_auto, 'supported_target', return_value=('pixel', 30, 'arm64-v8a')) as target:
            controller.prepare_environment()

        controller.start_process.assert_called_once_with('init', ['-m', 'Helpers.AutoInit'])
        target.assert_called_once_with(str(Path(os.sys.executable).resolve()), 'pixel')
        self.assertEqual(controller.python, Path(os.sys.executable).resolve())
        self.assertEqual(controller.adb, str(Path(os.sys.executable).resolve()))
        self.assertNotIn('init', controller.processes)
        self.assertEqual(init_process.close_calls, 1)

    def test_boot_incomplete_during_init_stage_stops_before_frida_or_dumper(self):
        controller = self.make_controller(initialize=True)
        self.prepare_init_fixture(controller)
        device = SimpleNamespace(serial='pixel')
        with mock.patch.object(full_auto.setup_frida, 'list_adb_devices', return_value=['fixture']), \
                mock.patch.object(full_auto.setup_frida, 'select_device', return_value=device), \
                mock.patch.object(full_auto.setup_frida, 'validate_target', return_value=(30, 'arm64-v8a', 'arm64')), \
                mock.patch.object(full_auto.setup_frida, 'shell_property', return_value='0'), \
                self.assertRaisesRegex(full_auto.AutoError, 'not finished booting'):
            controller.prepare_environment()

        roles = [call.args[0] for call in controller.start_process.call_args_list]
        self.assertEqual(roles, ['init'])
        self.assertNotIn('frida', controller.processes)
        self.assertNotIn('dumper', controller.processes)

    def test_offline_adb_during_init_stage_stops_before_frida_or_dumper(self):
        controller = self.make_controller(initialize=True)
        self.prepare_init_fixture(controller)
        with mock.patch.object(
                full_auto.setup_frida, 'list_adb_devices',
                side_effect=setup_frida.SetupError('adb offline')), \
                self.assertRaisesRegex(setup_frida.SetupError, 'adb offline'):
            controller.prepare_environment()

        roles = [call.args[0] for call in controller.start_process.call_args_list]
        self.assertEqual(roles, ['init'])
        self.assertNotIn('frida', controller.processes)
        self.assertNotIn('dumper', controller.processes)

    def test_verify_pair_accepts_fresh_pair_with_both_hashes_and_regular_files(self):
        event = self.pair_event()

        self.assertEqual(full_auto.verify_pair(event, 'pixel', 30), 'key_dumps/fresh-pair')

    def test_verify_pair_rejects_changed_empty_and_symlinked_outputs(self):
        changed = self.pair_event('changed')
        (self.root / 'key_dumps/changed/client_id.bin').write_bytes(b'changed-after-event')
        with self.assertRaisesRegex(full_auto.AutoError, 'incomplete or changed'):
            full_auto.verify_pair(changed, 'pixel', 30)

        empty = self.pair_event('empty', client=b'', key=b'private-key')
        with self.assertRaisesRegex(full_auto.AutoError, 'empty, oversized, or not regular'):
            full_auto.verify_pair(empty, 'pixel', 30)

        symlinked = self.pair_event('symlinked')
        target = self.root / 'outside-client.bin'
        target.write_bytes(b'client-id')
        client = self.root / 'key_dumps/symlinked/client_id.bin'
        client.unlink()
        client.symlink_to(target)
        with self.assertRaisesRegex(full_auto.AutoError, 'symbolic link'):
            full_auto.verify_pair(symlinked, 'pixel', 30)

    def test_verify_pair_enforces_fixture_size_ceiling(self):
        with mock.patch.object(full_auto, 'MAX_OUTPUT_FILE_BYTES', 5):
            exact = self.pair_event('exact', client=b'12345', key=b'abcde')
            self.assertEqual(full_auto.verify_pair(exact, 'pixel', 30), 'key_dumps/exact')

            oversized = self.pair_event('oversized', client=b'123456', key=b'abcde')
            with self.assertRaisesRegex(full_auto.AutoError, 'empty, oversized, or not regular'):
                full_auto.verify_pair(oversized, 'pixel', 30)

    def test_verify_pair_rejects_wrong_device_api_and_path(self):
        event = self.pair_event()
        for bad_event, expected in (
            ({**event, 'device_id': 'other'}, 'device/API'),
            ({**event, 'android_api': '31'}, 'device/API'),
            ({**event, 'path': '../key_dumps/fresh-pair'}, 'outside key_dumps'),
        ):
            with self.subTest(expected=expected), self.assertRaisesRegex(full_auto.AutoError, expected):
                full_auto.verify_pair(bad_event, 'pixel', 30)

    def test_wait_for_pair_warns_at_twenty_seconds_and_continues_to_pair(self):
        controller = self.make_controller(timeout=100)
        pair = self.pair_event()
        events = [
            [{'event': 'hooks_ready', 'device_id': 'pixel', 'android_api': '30', 'hooked_libraries': 1}],
            [{'event': 'hooks_ready', 'device_id': 'pixel', 'android_api': '30', 'hooked_libraries': 1}],
            [{'event': 'hooks_ready', 'device_id': 'pixel', 'android_api': '30', 'hooked_libraries': 1}, pair],
        ]
        clock = [0.0]
        sleeps = []

        def advance(seconds):
            sleeps.append(seconds)
            clock[0] += 20.0 if len(sleeps) == 1 else seconds

        with mock.patch.object(controller, 'events', side_effect=events), \
                mock.patch.object(controller, 'check_processes'), \
                mock.patch.object(full_auto, 'verify_pair', return_value='key_dumps/fresh-pair') as verify, \
                mock.patch.object(full_auto.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(full_auto.time, 'sleep', side_effect=advance), \
                mock.patch.object(full_auto, 'print') as output:
            self.assertEqual(controller.wait_for_pair(), 'key_dumps/fresh-pair')

        verify.assert_called_once_with(pair, 'pixel', 30)
        self.assertEqual(len(sleeps), 2)
        self.assertTrue(any('No pair saved yet.' in call.args[0] for call in output.call_args_list))

    def test_start_process_records_owned_background_process_and_log_path(self):
        controller = self.make_controller()
        controller.directory = self.root / '.tmp' / 'session'
        controller.directory.mkdir()
        controller.log_directory = self.root / 'logs'
        controller.log_directory.mkdir()
        processes = [FakeProcess(), FakeProcess(), FakeProcess()]
        with mock.patch.object(full_auto, 'launch_process', side_effect=processes) as launch:
            for role in ('init', 'frida', 'dumper'):
                controller.start_process(role, ['setup.py'])

        self.assertEqual(set(controller.processes), {'init', 'frida', 'dumper'})
        for role, call in zip(('init', 'frida', 'dumper'), launch.call_args_list):
            self.assertEqual(call.args[:4], (
                role, [str(controller.python), 'setup.py'], full_auto.ROOT, controller.directory,
            ))
            self.assertEqual(call.kwargs['log_path'], controller.log_directory / f'{role}.log')
            self.assertEqual(call.args[4], {
                'DUMPER_AUTO_DIRECTORY': str(controller.directory),
                'DUMPER_AUTO_TOKEN': controller.token,
                'DUMPER_AUTO_ROLE': role,
                'DUMPER_AUTO_ADB': 'adb-fixture',
                'PYTHONUNBUFFERED': '1',
            })

    def test_run_success_returns_pair_waits_three_seconds_and_retains_logs(self):
        controller = self.make_controller()
        opened = {}
        milestones = []

        def start_process(role, _arguments):
            process = FakeProcess()
            opened[role] = process
            controller.processes[role] = process

        def pair_ready():
            milestones.append('pair_verified')
            return 'key_dumps/fresh-pair'

        with mock.patch.object(controller, 'start_process', side_effect=start_process), \
                mock.patch.object(controller, 'wait_for_frida'), \
                mock.patch.object(controller, 'wait_for_pair', side_effect=pair_ready), \
                mock.patch.object(full_auto.time, 'sleep', side_effect=lambda _: milestones.append('grace')) as sleep, \
                mock.patch.object(full_auto.setup_frida, 'adb_command',
                                  side_effect=lambda *args, **kwargs: milestones.append('chrome_closed')) as adb:
            result = controller.run()

        self.assertEqual(result, 'key_dumps/fresh-pair')
        sleep.assert_called_once_with(full_auto.FINISH_DELAY)
        self.assertEqual(milestones, ['pair_verified', 'grace', 'chrome_closed'])
        adb.assert_called_once_with(
            'adb-fixture', 'pixel', 'shell', 'am', 'force-stop', 'com.android.chrome',
            purpose='Closing Chrome after capture', timeout=10,
        )
        self.assertEqual(set(controller.processes), {'frida', 'dumper'})
        self.assertTrue(all(process.close_calls == 1 for process in opened.values()))
        self.assertFalse(controller.directory.exists())
        self.assertTrue(controller.log_directory.is_dir())

    def test_chrome_stop_failure_warns_without_losing_pair_or_skipping_cleanup(self):
        for error in (setup_frida.SetupError('ADB timed out'), OSError('ADB unavailable')):
            with self.subTest(error=str(error)):
                controller = self.make_controller()
                opened = {}

                def start_process(role, _arguments):
                    opened[role] = FakeProcess()
                    controller.processes[role] = opened[role]

                stderr = io.StringIO()
                with mock.patch.object(controller, 'start_process', side_effect=start_process), \
                        mock.patch.object(controller, 'wait_for_frida'), \
                        mock.patch.object(controller, 'wait_for_pair', return_value='key_dumps/fresh-pair'), \
                        mock.patch.object(full_auto.time, 'sleep'), \
                        mock.patch.object(full_auto.setup_frida, 'adb_command', side_effect=error), \
                        redirect_stderr(stderr):
                    self.assertEqual(controller.run(), 'key_dumps/fresh-pair')

                self.assertIn('could not close Chrome on pixel', stderr.getvalue())
                self.assertIn('saved pair is retained', stderr.getvalue())
                self.assertTrue(all(process.close_calls == 1 for process in opened.values()))
                self.assertFalse(controller.directory.exists())

    def test_run_failure_retains_session_and_logs_when_owned_process_close_fails(self):
        controller = self.make_controller()
        opened = {}

        def start_process(role, _arguments):
            process = FakeProcess(close_result=(role != 'dumper'))
            opened[role] = process
            controller.processes[role] = process

        stderr = io.StringIO()
        with mock.patch.object(controller, 'start_process', side_effect=start_process), \
                mock.patch.object(controller, 'wait_for_frida'), \
                mock.patch.object(controller, 'wait_for_pair',
                                  side_effect=full_auto.AutoError('pair fixture failed')), \
                mock.patch.object(controller, 'close_chrome') as chrome, \
                redirect_stderr(stderr):
            with self.assertRaisesRegex(full_auto.AutoError, 'pair fixture failed'):
                controller.run()

        chrome.assert_not_called()
        self.assertTrue(controller.directory.is_dir())
        self.assertTrue(controller.log_directory.is_dir())
        self.assertEqual(opened['dumper'].close_calls, 1)
        self.assertEqual(opened['frida'].close_calls, 1)
        self.assertIn('Session status retained', stderr.getvalue())

    def test_run_child_exit_cleans_owned_setup_process(self):
        controller = self.make_controller()
        frida = FakeProcess(status=7, error='child exited')

        def start_process(role, _arguments):
            controller.processes[role] = frida

        with mock.patch.object(controller, 'start_process', side_effect=start_process), \
                mock.patch.object(controller, 'wait_for_pair'):
            with self.assertRaisesRegex(full_auto.AutoError, 'child exited'):
                controller.run()

        self.assertEqual(frida.close_calls, 1)
        self.assertFalse(controller.directory.exists())
        self.assertTrue(controller.log_directory.is_dir())

    def test_run_signature_failure_cleans_owned_setup_process(self):
        controller = self.make_controller(timeout=1)
        frida = FakeProcess()
        controller.launch = {
            'device_id': 'pixel',
            'root_mode': 'direct',
            'marker': full_auto.marker_path(controller.token),
        }
        clock = [0.0]

        def start_process(role, _args):
            controller.processes[role] = frida

        def advance(_seconds):
            clock[0] += 2.0

        with mock.patch.object(controller, 'start_process', side_effect=start_process), \
                mock.patch.object(controller, 'remember_launch'), \
                mock.patch.object(full_auto.setup_frida, 'run_root',
                                  return_value=subprocess.CompletedProcess([], 0)), \
                mock.patch.object(full_auto, 'frida_responds', return_value=False), \
                mock.patch.object(full_auto.time, 'monotonic', side_effect=lambda: clock[0]), \
                mock.patch.object(full_auto.time, 'sleep', side_effect=advance):
            with self.assertRaisesRegex(full_auto.AutoError, 'Frida did not become ready'):
                controller.run()

        self.assertEqual(frida.close_calls, 1)
        self.assertFalse(controller.directory.exists())

    def test_deferred_sigint_during_launch_keeps_process_ownership_metadata(self):
        controller = self.make_controller()
        controller.directory = self.root / '.tmp' / 'launch-session'
        controller.directory.mkdir()
        controller.log_directory = self.root / 'logs'
        controller.log_directory.mkdir()
        process = FakeProcess()
        previous = signal.getsignal(signal.SIGINT)

        def launch(*_args, **_kwargs):
            signal.raise_signal(signal.SIGINT)
            return process

        try:
            with mock.patch.object(full_auto, 'launch_process', side_effect=launch), \
                    self.assertRaises(KeyboardInterrupt):
                controller.start_process('frida', ['setup'])
            self.assertIs(controller.processes['frida'], process)
        finally:
            signal.signal(signal.SIGINT, previous)
            controller.cleanup()

    def test_run_cancellation_at_setup_dumper_wait_and_success_grace_cleans_process_metadata(self):
        scenarios = ('setup', 'dumper', 'wait', 'grace', 'chrome')
        for scenario in scenarios:
            with self.subTest(scenario=scenario):
                controller = self.make_controller()
                opened = {}

                def start_process(role, _args):
                    if scenario == 'setup' and role == 'frida':
                        raise KeyboardInterrupt
                    process = FakeProcess()
                    opened[role] = process
                    controller.processes[role] = process
                    if scenario == 'dumper' and role == 'dumper':
                        raise KeyboardInterrupt

                def wait_for_pair():
                    if scenario == 'wait':
                        raise KeyboardInterrupt
                    return 'key_dumps/fresh-pair'

                patches = [
                    mock.patch.object(controller, 'start_process', side_effect=start_process),
                    mock.patch.object(controller, 'wait_for_frida'),
                    mock.patch.object(controller, 'wait_for_pair', side_effect=wait_for_pair),
                ]
                chrome = mock.Mock(side_effect=KeyboardInterrupt if scenario == 'chrome' else None)
                patches.append(mock.patch.object(controller, 'close_chrome', chrome))
                if scenario == 'grace':
                    patches.append(mock.patch.object(full_auto.time, 'sleep', side_effect=KeyboardInterrupt))
                elif scenario == 'chrome':
                    patches.append(mock.patch.object(full_auto.time, 'sleep'))
                for patcher in patches:
                    patcher.start()
                try:
                    with self.assertRaises(KeyboardInterrupt):
                        controller.run()
                finally:
                    for patcher in reversed(patches):
                        patcher.stop()

                expected = {
                    'setup': set(),
                    'dumper': {'frida', 'dumper'},
                    'wait': {'frida', 'dumper'},
                    'grace': {'frida', 'dumper'},
                    'chrome': {'frida', 'dumper'},
                }[scenario]
                self.assertEqual(chrome.call_count, 1 if scenario == 'chrome' else 0)
                self.assertEqual(set(controller.processes), expected)
                self.assertTrue(all(process.close_calls == 1 for process in opened.values()))
                self.assertFalse(controller.directory.exists())
                self.assertTrue(controller.log_directory.is_dir())

    def test_main_wraps_controller_run_in_logging_context(self):
        with mock.patch.object(full_auto, 'prepare_terminal'), \
                mock.patch.object(full_auto, 'controller_logging', return_value=nullcontext()) as logging_context, \
                mock.patch.object(full_auto, 'run_controller', return_value=0) as run:
            self.assertEqual(full_auto.main([]), 0)

        logging_context.assert_called_once_with(full_auto.ROOT)
        run.assert_called_once()

    def test_frida_probe_keeps_raw_stdout_and_stderr_in_controller_log(self):
        def probe(_command, **options):
            options['stdout'].write(b'probe stdout\x00\xff\n')
            options['stderr'].write(b'probe stderr\n')
            return subprocess.CompletedProcess(_command, 1)

        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                full_auto.controller_logging(self.root), \
                mock.patch.object(subprocess, 'run', side_effect=probe):
            self.assertFalse(full_auto.frida_responds(os.sys.executable, 'pixel'))

        output = (self.root / 'logs' / 'full_auto.log').read_bytes()
        self.assertIn(b'probe stdout\x00\xff\n', output)
        self.assertIn(b'probe stderr\n', output)

    def test_unexpected_controller_failure_keeps_full_traceback_in_log(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                mock.patch.object(full_auto, 'prepare_terminal'), \
                mock.patch.object(full_auto.AutoRun, 'run', side_effect=RuntimeError('debug fixture')):
            self.assertEqual(full_auto.main([]), 1)

        output = (self.root / 'logs' / 'full_auto.log').read_text()
        self.assertIn('Traceback (most recent call last):', output)
        self.assertIn('RuntimeError: debug fixture', output)


if __name__ == '__main__':
    unittest.main()
