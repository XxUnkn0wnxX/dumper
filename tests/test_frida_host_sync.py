"""Host Frida synchronization contracts; every package command is mocked."""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tools import setup_frida as setup


class Completed:
    def __init__(self, stdout='', stderr='', returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


def distribution(name, version):
    item = mock.Mock()
    item.metadata = {'Name': name}
    item.version = version
    return item


class HostFridaSyncTests(unittest.TestCase):
    """Keep resolver, pip, ADB, and Android operations entirely simulated."""

    def clean_pip_environment(self):
        environment = dict(setup.os.environ)
        for name in (*setup.PIP_ROUTING_ENVIRONMENT, *setup.PIP_RESOLVER_ENVIRONMENT):
            environment.pop(name, None)
        return mock.patch.dict(setup.os.environ, environment, clear=True)

    def run_update(self, installed, target, *, distributions=None, replies=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        tmp_root = Path(temporary.name) / '.tmp'
        captured_requirements = []
        commands = []
        replies = list(replies or [
            Completed(),
            Completed(),
            Completed(),
            Completed(),
            Completed(stdout=json.dumps({'distribution': target, 'module': target}) + '\n'),
            Completed(),
        ])

        def runner(command, purpose, *, timeout):
            commands.append((command, purpose, timeout))
            if '--requirement' in command:
                requirements_file = Path(command[command.index('--requirement') + 1])
                captured_requirements.append(requirements_file.read_text(encoding='utf-8').splitlines())
            response = replies.pop(0)
            if isinstance(response, BaseException):
                raise response
            return response

        stdout = io.StringIO()
        stderr = io.StringIO()
        version_patch = (
            mock.patch.object(setup.metadata, 'version', side_effect=setup.metadata.PackageNotFoundError('frida'))
            if installed is None else mock.patch.object(setup.metadata, 'version', return_value=installed)
        )
        with mock.patch.object(setup, 'TMP_ROOT', tmp_root), \
                mock.patch.object(setup, 'running_in_virtual_environment', return_value=True), \
                self.clean_pip_environment(), \
                version_patch, \
                mock.patch.object(setup.metadata, 'distributions', return_value=distributions or [distribution('Other', '1.2.3')]), \
                mock.patch.object(setup, 'host_package_output', side_effect=runner), \
                redirect_stdout(stdout), redirect_stderr(stderr):
            setup.ensure_host_frida_version(target)
        return commands, captured_requirements, stdout.getvalue(), stderr.getvalue(), tmp_root

    def test_matching_version_is_a_metadata_only_no_op(self):
        with mock.patch.object(setup.metadata, 'version', return_value='17.18.0'), \
                mock.patch.object(setup.metadata, 'distributions') as distributions, \
                mock.patch.object(setup, 'host_package_output') as runner, \
                redirect_stdout(io.StringIO()) as stdout:
            setup.ensure_host_frida_version('17.18.0')
        self.assertIn('matches the selected Android server', stdout.getvalue())
        distributions.assert_not_called()
        runner.assert_not_called()

    def test_outside_venv_blocks_update_even_when_virtual_env_is_spoofed(self):
        with mock.patch.object(setup.sys, 'prefix', '/system/python'), \
                mock.patch.object(setup.sys, 'base_prefix', '/system/python'), \
                mock.patch.object(setup.sys, 'real_prefix', None, create=True), \
                mock.patch.dict(setup.os.environ, {'VIRTUAL_ENV': '/pretend/venv'}, clear=False), \
                mock.patch.object(setup.metadata, 'version', return_value='17.9.0'), \
                mock.patch.object(setup, 'host_package_output') as runner:
            with self.assertRaisesRegex(setup.SetupError, 'only changes a virtual environment'):
                setup.ensure_host_frida_version('17.18.0')
        runner.assert_not_called()

    def test_pip_routing_environment_or_configuration_blocks_sync(self):
        with mock.patch.object(setup, 'running_in_virtual_environment', return_value=True), \
                self.clean_pip_environment(), \
                mock.patch.object(setup.metadata, 'version', return_value='17.9.0'), \
                mock.patch.dict(setup.os.environ, {'PIP_TARGET': '/elsewhere'}, clear=False), \
                mock.patch.object(setup, 'host_package_output') as runner:
            with self.assertRaisesRegex(setup.SetupError, 'PIP_TARGET'):
                setup.ensure_host_frida_version('17.18.0')
        runner.assert_not_called()

        with mock.patch.object(setup, 'running_in_virtual_environment', return_value=True), \
                self.clean_pip_environment(), \
                mock.patch.object(setup.metadata, 'version', return_value='17.9.0'), \
                mock.patch.object(
                    setup, 'host_package_output', return_value=Completed(stdout="global.target='/elsewhere'\n"),
                ) as runner:
            with self.assertRaisesRegex(setup.SetupError, 'global.target'):
                setup.ensure_host_frida_version('17.18.0')
        runner.assert_called_once_with(
            [setup.sys.executable, '-I', '-m', 'pip', 'config', 'list'],
            'Checking pip installation routing configuration', timeout=setup.PIP_CHECK_TIMEOUT,
        )

    def test_pip_resolver_bypass_environment_or_global_configuration_blocks_sync(self):
        for name in setup.PIP_RESOLVER_ENVIRONMENT:
            with self.subTest(environment=name), \
                    mock.patch.object(setup, 'running_in_virtual_environment', return_value=True), \
                    self.clean_pip_environment(), \
                    mock.patch.object(setup.metadata, 'version', return_value='17.9.0'), \
                    mock.patch.dict(setup.os.environ, {name: '1'}, clear=False), \
                    mock.patch.object(setup, 'host_package_output') as runner:
                with self.assertRaisesRegex(setup.SetupError, name):
                    setup.ensure_host_frida_version('17.18.0')
            runner.assert_not_called()

        for option, value in (
            ('no-deps', 'true'),
            ('use-deprecated', 'legacy-resolver'),
            ('requirement', '/elsewhere/requirements.txt'),
        ):
            with self.subTest(configuration=option), \
                    mock.patch.object(setup, 'running_in_virtual_environment', return_value=True), \
                    self.clean_pip_environment(), \
                    mock.patch.object(setup.metadata, 'version', return_value='17.9.0'), \
                    mock.patch.object(
                        setup, 'host_package_output',
                        return_value=Completed(stdout=f'global.{option}={value!r}\n'),
                    ) as runner:
                with self.assertRaisesRegex(setup.SetupError, f'global.{option}'):
                    setup.ensure_host_frida_version('17.18.0')
            runner.assert_called_once_with(
                [setup.sys.executable, '-I', '-m', 'pip', 'config', 'list'],
                'Checking pip installation routing configuration', timeout=setup.PIP_CHECK_TIMEOUT,
            )

    def test_missing_upgrade_and_downgrade_use_numeric_direction_and_full_preflight(self):
        cases = (
            (None, '17.18.0', 'installing'),
            ('17.9.0', '17.18.0', 'upgrading'),
            ('17.18.0', '16.3.3', 'downgrading'),
        )
        for installed, target, action in cases:
            with self.subTest(installed=installed, target=target):
                commands, requirements, stdout, stderr, tmp_root = self.run_update(
                    installed, target,
                    distributions=[
                        distribution('Frida', '99.0.0'),
                        distribution('frida-tools', '1.0.0'),
                        distribution('Other', '1.2.3'),
                    ],
                )
                self.assertIn(f'Automatically {action}', stdout)
                self.assertIn(f'frida=={target}', stdout)
                self.assertIn('Warning: host Python frida', stderr)
                self.assertEqual(len(commands), 6)
                self.assertEqual(commands[0][0], [setup.sys.executable, '-I', '-m', 'pip', 'config', 'list'])
                self.assertEqual(commands[1][0], [setup.sys.executable, '-I', '-m', 'pip', 'check'])
                self.assertIn('--dry-run', commands[2][0])
                self.assertNotIn('--dry-run', commands[3][0])
                self.assertEqual(commands[2][0][-1], commands[3][0][-1])
                for command, _purpose, _timeout in commands[2:4]:
                    self.assertIn('--only-binary=frida', command)
                    self.assertIn('--require-virtualenv', command)
                    self.assertNotIn('--no-deps', command)
                    self.assertNotIn('--user', command)
                    self.assertNotIn('--break-system-packages', command)
                self.assertEqual(requirements, [
                    ['Other==1.2.3', f'frida=={target}', 'frida-tools'],
                    ['Other==1.2.3', f'frida=={target}', 'frida-tools'],
                ])
                self.assertEqual(commands[4][0][0], setup.sys.executable)
                self.assertEqual(commands[4][0][1:3], ['-I', '-c'])
                self.assertEqual(commands[5][0], [setup.sys.executable, '-I', '-m', 'pip', 'check'])
                self.assertFalse(list(tmp_root.glob('frida-pip-*')))

    def test_preflight_failure_stops_before_package_mutation(self):
        with self.assertRaisesRegex(setup.SetupError, 'preflight failed'):
            self.run_update(
                '17.9.0', '17.18.0',
                replies=[Completed(), Completed(), setup.SetupError('preflight failed')],
            )

    def test_broken_baseline_pip_check_stops_before_requirements_or_install(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        tmp_root = Path(temporary.name) / '.tmp'
        with mock.patch.object(setup, 'TMP_ROOT', tmp_root), \
                mock.patch.object(setup, 'running_in_virtual_environment', return_value=True), \
                self.clean_pip_environment(), \
                mock.patch.object(setup.metadata, 'version', return_value='17.9.0'), \
                mock.patch.object(setup.metadata, 'distributions') as distributions, \
                mock.patch.object(
                    setup, 'host_package_output',
                    side_effect=[Completed(), setup.SetupError('baseline is broken')],
                ) as runner:
            with self.assertRaisesRegex(setup.SetupError, 'already inconsistent'):
                setup.ensure_host_frida_version('17.18.0')
        self.assertEqual(runner.call_count, 2)
        distributions.assert_not_called()
        self.assertFalse(tmp_root.exists())

    def test_update_failure_does_not_verify_or_check_afterwards(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        tmp_root = Path(temporary.name) / '.tmp'
        with mock.patch.object(setup, 'TMP_ROOT', tmp_root), \
                mock.patch.object(setup, 'running_in_virtual_environment', return_value=True), \
                self.clean_pip_environment(), \
                mock.patch.object(setup.metadata, 'version', return_value='17.9.0'), \
                mock.patch.object(setup.metadata, 'distributions', return_value=[distribution('Other', '1.2.3')]), \
                mock.patch.object(
                    setup, 'host_package_output',
                    side_effect=[Completed(), Completed(), Completed(), setup.SetupError('wheel unavailable')],
                ) as runner:
            with self.assertRaisesRegex(setup.SetupError, 'wheel unavailable'):
                setup.ensure_host_frida_version('17.18.0')
        self.assertEqual(runner.call_count, 4)
        self.assertFalse(list(tmp_root.glob('frida-pip-*')))

    def test_fresh_process_version_mismatch_stops_before_final_pip_check(self):
        with self.assertRaisesRegex(setup.SetupError, 'imported module reports'):
            self.run_update(
                '17.9.0', '17.18.0',
                replies=[
                    Completed(), Completed(), Completed(), Completed(),
                    Completed(stdout=json.dumps({'distribution': '17.18.0', 'module': '17.9.0'})),
                ],
            )

    def test_final_pip_check_failure_stops_deployment_gate(self):
        with self.assertRaisesRegex(setup.SetupError, 'dependency check failed'):
            self.run_update(
                '17.9.0', '17.18.0',
                replies=[
                    Completed(), Completed(), Completed(), Completed(),
                    Completed(stdout=json.dumps({'distribution': '17.18.0', 'module': '17.18.0'})),
                    setup.SetupError('broken dependency'),
                ],
            )


class HostSyncFlowTests(unittest.TestCase):
    def test_selected_cached_fallback_version_is_the_sync_target(self):
        device = setup.AndroidDevice('serial', 'device', '')
        fallback = setup.CachedArtifact(
            '17.0.0', 'x86_64', 'frida-server-17.0.0-android-x86_64.xz', Path('cache.xz'),
        )
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(setup, 'TMP_ROOT', Path(temporary) / '.tmp'), \
                    mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                    mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                    mock.patch.object(setup, 'validate_target', return_value=(34, 'x86_64', 'x86_64')), \
                    mock.patch.object(setup, 'probe_root', return_value='direct'), \
                    mock.patch.object(setup, 'select_server_artifact', return_value=fallback), \
                    mock.patch.object(setup, 'ensure_host_frida_version') as sync, \
                    mock.patch.object(setup, 'install_server', side_effect=setup.SetupError('stop after sync')):
                self.assertEqual(setup.main(['--no-shell']), 1)
        sync.assert_called_once_with('17.0.0')

    def test_explicit_version_downgrade_reaches_sync_before_deployment(self):
        device = setup.AndroidDevice('serial', 'device', '')
        artifact = setup.CachedArtifact('16.3.3', 'x86_64', 'server.xz', Path('cache.xz'))
        with tempfile.TemporaryDirectory() as temporary:
            with mock.patch.object(setup, 'TMP_ROOT', Path(temporary) / '.tmp'), \
                    mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                    mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                    mock.patch.object(setup, 'validate_target', return_value=(34, 'x86_64', 'x86_64')), \
                    mock.patch.object(setup, 'probe_root', return_value='direct'), \
                    mock.patch.object(setup, 'select_server_artifact', return_value=artifact) as select, \
                    mock.patch.object(setup, 'ensure_host_frida_version') as sync, \
                    mock.patch.object(setup, 'install_server', side_effect=setup.SetupError('stop after sync')):
                self.assertEqual(setup.main(['--no-shell', '--ver', '16.3.3']), 1)
        self.assertEqual(select.call_args.args[:2], ('16.3.3', 'x86_64'))
        sync.assert_called_once_with('16.3.3')

    def test_shell_syncs_validated_version_before_stopping_server(self):
        events = []

        def validate(*_args):
            events.append('validate')
            return '17.18.0'

        with mock.patch.object(setup, 'managed_server_pids', side_effect=[['71'], []]), \
                mock.patch.object(setup, 'existing_server_state', return_value='executable'), \
                mock.patch.object(setup, 'validate_existing_server', side_effect=validate), \
                mock.patch.object(setup, 'ensure_host_frida_version', side_effect=lambda _version: events.append('sync')), \
                mock.patch.object(setup, 'stop_managed_servers', side_effect=lambda *_args: events.append('stop')):
            self.assertEqual(setup.prepare_existing_server('/adb', 'serial', 'direct'), 'ready')
        self.assertEqual(events, ['validate', 'sync', 'stop'])

    def test_shell_missing_and_orphan_servers_do_not_sync(self):
        for pids, expected in (([], 'missing'), (['71'], 'orphan')):
            with self.subTest(expected=expected), \
                    mock.patch.object(setup, 'managed_server_pids', return_value=pids), \
                    mock.patch.object(setup, 'existing_server_state', return_value='missing'), \
                    mock.patch.object(setup, 'ensure_host_frida_version') as sync:
                self.assertEqual(setup.prepare_existing_server('/adb', 'serial', 'direct'), expected)
            sync.assert_not_called()


if __name__ == '__main__':
    unittest.main()
