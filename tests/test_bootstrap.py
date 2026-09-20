"""Offline unit tests for the shared virtual-environment bootstrap.

All subprocess and venv creation calls are mocked.  The temporary repository
trees contain only requirements text and placeholder interpreter files; no
package operation, network access, or real .venv mutation is permitted here.
"""

from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from Helpers import Bootstrap as bootstrap_helper


class Completed:
    def __init__(self, stdout='', stderr='', returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class BootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'repository with spaces'
        self.root.mkdir()
        (self.root / 'requirements.txt').write_text(
            '--only-binary=adbutils\n'
            'adbutils==2.12.0; platform_machine == "x86_64" or '
            'platform_machine == "AMD64" or platform_machine == "x86"\n'
            'frida\nfrida-tools\nprotobuf==7.36.2\npycryptodome\n',
            encoding='utf-8',
        )
        self.root_patch = mock.patch.object(bootstrap_helper, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    @property
    def venv(self):
        return self.root / '.venv'

    @property
    def python(self):
        return bootstrap_helper._venv_python(self.venv)

    def make_existing_venv(self):
        self.python.parent.mkdir(parents=True)
        self.python.write_text('', encoding='utf-8')
        (self.venv / 'pyvenv.cfg').write_text(
            'include-system-site-packages = false\n', encoding='utf-8',
        )

    def prefix_result(self, *, prefix=None):
        return Completed(stdout=json.dumps({
            'prefix': str(prefix or self.venv),
            'base_prefix': '/outside-python',
            'real_prefix': None,
        }) + '\n')

    @staticmethod
    def packages_result(packages):
        return Completed(stdout=json.dumps(packages) + '\n')

    @staticmethod
    def requirement_result(packages, machine):
        return Completed(stdout=json.dumps({
            'machine': machine,
            'installed': packages,
        }) + '\n')

    def call_is_pip(self, command, operation):
        return '-m' in command and 'pip' in command and operation in command

    def standard_runner(self, *, initially_missing=False, create_file=False, target_machine='x86_64',
                        adb_installed=True, frida_version='17.18.0', frida_tools_version='14.4.6'):
        packages = {
            'adbutils': '2.12.0' if adb_installed else None,
            'frida': None if initially_missing else frida_version,
            'frida-tools': frida_tools_version,
            'protobuf': '7.36.2',
            'pycryptodome': '3.23.0',
        }
        calls = []

        def run(command, **kwargs):
            command = list(command)
            if self.call_is_pip(command, 'install'):
                requirements_file = Path(command[-1])
                if not requirements_file.is_absolute():
                    requirements_file = Path(kwargs['cwd']) / requirements_file
                kwargs = {
                    **kwargs,
                    'resolved_requirements_path': requirements_file,
                    'requirements_text': requirements_file.read_text(encoding='utf-8'),
                }
            calls.append((command, kwargs))
            if command[1:4] == ['-I', '-m', 'venv']:
                if create_file:
                    self.python.parent.mkdir(parents=True, exist_ok=True)
                    self.python.write_text('', encoding='utf-8')
                return Completed()
            if '-c' in command:
                script = command[command.index('-c') + 1]
                if 'base_prefix' in script:
                    return self.prefix_result()
                if 'metadata.distributions' in script:
                    return self.packages_result([
                        [name, version] for name, version in {
                            **{name: version for name, version in packages.items() if version is not None},
                            'other-package': '1.0',
                        }.items()
                    ])
                if 'metadata.version' in script:
                    reported = packages.copy()
                    if target_machine not in {'x86_64', 'AMD64', 'x86'}:
                        reported['adbutils'] = False
                    return self.requirement_result(reported, target_machine)
            if self.call_is_pip(command, 'install'):
                if '--dry-run' not in command:
                    packages['frida'] = '17.18.0'
                    if target_machine in {'x86_64', 'AMD64', 'x86'}:
                        packages['adbutils'] = '2.12.0'
                return Completed()
            if self.call_is_pip(command, 'check'):
                return Completed()
            self.fail(f'Unexpected command: {command!r}')

        return run, calls

    def test_no_venv_creates_then_installs_in_order(self):
        runner, calls = self.standard_runner(initially_missing=True, create_file=True)
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner), \
                redirect_stdout(io.StringIO()) as output:
            selected = bootstrap_helper.initialize_environment()

        self.assertEqual(selected, self.python)
        self.assertEqual(calls[0][0][0], sys.executable)
        self.assertEqual(calls[0][0][1:4], ['-I', '-m', 'venv'])
        self.assertTrue(all(Path(kwargs['cwd']) == self.root for _command, kwargs in calls))
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertIn('Creating repository virtual environment at .venv...', output.getvalue())
        self.assertIn('repository virtual environment .venv', output.getvalue())
        self.assertIn('Virtual environment ready: .venv/bin/python.', output.getvalue())
        install_calls = [
            (command, kwargs) for command, kwargs in calls if self.call_is_pip(command, 'install')
        ]
        self.assertEqual(len(install_calls), 2)
        preflight, install = install_calls
        self.assertIn('--dry-run', preflight[0])
        self.assertNotIn('--dry-run', install[0])
        self.assertIn('--require-virtualenv', install[0])
        self.assertNotIn('--upgrade', install[0])
        self.assertEqual(install[1]['env']['PIP_CONFIG_FILE'], os.devnull)
        for command, kwargs in install_calls:
            self.assertFalse(Path(command[-1]).is_absolute())
            self.assertEqual(
                Path(kwargs['resolved_requirements_path']), Path(kwargs['cwd']) / command[-1],
            )

    def test_existing_complete_venv_reuses_without_install(self):
        self.make_existing_venv()
        runner, calls = self.standard_runner()
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            self.assertEqual(bootstrap_helper.initialize_environment(), self.python)

        self.assertFalse(any(command[1:4] == ['-I', '-m', 'venv'] for command, _ in calls))
        self.assertFalse(any(self.call_is_pip(command, 'install') for command, _ in calls))
        self.assertTrue(any(self.call_is_pip(command, 'check') for command, _ in calls))
        check_kwargs = next(
            kwargs for command, kwargs in calls if self.call_is_pip(command, 'check')
        )
        self.assertEqual(check_kwargs['env']['PIP_CONFIG_FILE'], os.devnull)

    def test_rebuild_check_keeps_healthy_unpinned_frida_versions_without_installing(self):
        self.make_existing_venv()
        for frida_version, frida_tools_version in (
            ('16.7.19', '13.7.19'),
            ('17.18.1', '14.4.7'),
        ):
            with self.subTest(frida=frida_version, frida_tools=frida_tools_version):
                runner, calls = self.standard_runner(
                    frida_version=frida_version, frida_tools_version=frida_tools_version,
                )
                with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                        mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
                    self.assertEqual(
                        bootstrap_helper.initialize_environment(rebuild_corrupt=True), self.python,
                    )

                self.assertFalse(any(
                    command[1:4] == ['-I', '-m', 'venv'] for command, _kwargs in calls
                ))
                self.assertFalse(any(
                    self.call_is_pip(command, 'install') for command, _kwargs in calls
                ))

    def test_rebuild_never_deletes_a_custom_active_environment(self):
        custom_venv = self.root / 'custom-environment'
        custom_python = bootstrap_helper._venv_python(custom_venv)
        runner, calls = self.standard_runner()
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=True), \
                mock.patch.multiple(
                    bootstrap_helper.sys,
                    prefix=str(custom_venv), base_prefix='/outside-python', executable=str(custom_python),
                ), mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner), \
                mock.patch.object(bootstrap_helper.shutil, 'rmtree') as rmtree:
            self.assertEqual(
                bootstrap_helper.initialize_environment(rebuild_corrupt=True), custom_python,
            )

        rmtree.assert_not_called()
        self.assertFalse(any(command[1:4] == ['-I', '-m', 'venv'] for command, _kwargs in calls))

    def test_missing_requirement_installs_root_requirements(self):
        self.make_existing_venv()
        runner, calls = self.standard_runner(initially_missing=True)
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            bootstrap_helper.initialize_environment()

        install_calls = [command for command, _ in calls if self.call_is_pip(command, 'install')]
        self.assertEqual(len(install_calls), 2)
        self.assertNotIn('--dry-run', install_calls[1])
        self.assertIn('--dry-run', install_calls[0])

    def test_only_binary_metadata_is_validated_and_preserved_in_full_request(self):
        self.make_existing_venv()
        runner, calls = self.standard_runner(initially_missing=True)
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            bootstrap_helper.initialize_environment()

        parsed = bootstrap_helper._read_requirements()
        self.assertEqual(parsed.pip_options, ('--only-binary=adbutils',))
        self.assertEqual([item.name for item in parsed.requirements][0], 'adbutils')
        requests = [
            kwargs['requirements_text']
            for command, kwargs in calls if self.call_is_pip(command, 'install')
        ]
        self.assertEqual(len(requests), 2)
        self.assertEqual(requests[0], requests[1])
        self.assertIn('--only-binary=adbutils\n', requests[0])
        self.assertIn('other-package==1.0\n', requests[0])
        self.assertIn(
            'adbutils==2.12.0; platform_machine == "x86_64" or '
            'platform_machine == "AMD64" or platform_machine == "x86"\n',
            requests[0],
        )
        self.assertNotIn('adbutils==2.12.0\n', requests[0])

    def test_arm_target_keeps_existing_marked_package_pinned_and_marker_preserved(self):
        self.make_existing_venv()
        runner, calls = self.standard_runner(initially_missing=True, target_machine='arm64')
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            bootstrap_helper.initialize_environment()

        request = next(
            kwargs['requirements_text']
            for command, kwargs in calls
            if self.call_is_pip(command, 'install') and '--dry-run' in command
        )
        self.assertIn('adbutils==2.12.0\n', request)
        self.assertIn(
            'adbutils==2.12.0; platform_machine == "x86_64" or '
            'platform_machine == "AMD64" or platform_machine == "x86"\n',
            request,
        )

    def test_missing_frida_repairs_through_dry_run_without_baseline_pip_check(self):
        self.make_existing_venv()
        runner, calls = self.standard_runner(initially_missing=True)
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            bootstrap_helper.initialize_environment()

        pip_operations = [
            command for command, _ in calls if '-m' in command and 'pip' in command
        ]
        self.assertIn('--dry-run', pip_operations[0])
        self.assertEqual(pip_operations[-1][-1], 'check')

    def test_arm_initialization_skips_only_bundled_adb_and_finishes_other_setup(self):
        runner, calls = self.standard_runner(
            initially_missing=True, create_file=True, target_machine='aarch64', adb_installed=False,
        )
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner), \
                mock.patch.object(bootstrap_helper.shutil, 'which', return_value=None), \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(bootstrap_helper.initialize_environment(), self.python)

        installs = [
            (command, kwargs) for command, kwargs in calls if self.call_is_pip(command, 'install')
        ]
        self.assertEqual(len(installs), 2)
        self.assertNotIn('adbutils==2.12.0\n', installs[-1][1]['requirements_text'])
        for requirement in ('frida', 'frida-tools', 'protobuf==7.36.2', 'pycryptodome'):
            self.assertIn(requirement + '\n', installs[-1][1]['requirements_text'])
        self.assertTrue(any(self.call_is_pip(command, 'check') for command, _ in calls))
        self.assertIn('all other Python setup continues', output.getvalue())
        self.assertIn('docs/android-setup.md#arm-hosts', output.getvalue())

    def test_arm_with_path_adb_does_not_print_manual_install_message(self):
        self.make_existing_venv()
        runner, calls = self.standard_runner(target_machine='arm64', adb_installed=False)
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner), \
                mock.patch.object(bootstrap_helper.shutil, 'which', return_value='/system/bin/adb') as which, \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(bootstrap_helper.initialize_environment(), self.python)
        which.assert_called_once_with('adb')
        self.assertNotIn('Bundled ADB is skipped', output.getvalue())
        self.assertNotIn('Install or build ADB manually', output.getvalue())
        self.assertFalse(any(self.call_is_pip(command, 'install') for command, _ in calls))

    def test_intel_installs_bundled_adb_even_when_path_adb_exists(self):
        self.make_existing_venv()
        runner, calls = self.standard_runner(adb_installed=False)
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner), \
                mock.patch.object(bootstrap_helper.shutil, 'which', return_value='/system/bin/adb') as which:
            self.assertEqual(bootstrap_helper.initialize_environment(), self.python)
        installs = [
            (command, kwargs) for command, kwargs in calls if self.call_is_pip(command, 'install')
        ]
        self.assertEqual(len(installs), 2)
        self.assertNotIn('--dry-run', installs[-1][0])
        self.assertIn('adbutils==2.12.0;', installs[-1][1]['requirements_text'])
        which.assert_not_called()

    def test_preflight_failure_does_not_install_or_leave_temporary_requirements(self):
        self.make_existing_venv()
        runner, calls = self.standard_runner(initially_missing=True)

        def incompatible(command, **kwargs):
            if self.call_is_pip(command, 'install') and '--dry-run' in command:
                calls.append((list(command), kwargs))
                return Completed(stderr='reverse dependency rejects protobuf', returncode=1)
            return runner(command, **kwargs)

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=incompatible):
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'not changed'):
                bootstrap_helper.initialize_environment()

        self.assertFalse(any(
            self.call_is_pip(command, 'install') and '--dry-run' not in command
            for command, _ in calls
        ))
        self.assertEqual(list((self.root / '.tmp').glob('bootstrap-pip-*')), [])

    def test_missing_transitive_dependency_gets_one_preflighted_repair(self):
        self.make_existing_venv()
        runner, calls = self.standard_runner()
        checks = []

        def interrupted_environment(command, **kwargs):
            reply = runner(command, **kwargs)
            if self.call_is_pip(command, 'check'):
                checks.append(command)
                if len(checks) == 1:
                    return Completed(stderr='frida-tools requires colorama, which is not installed', returncode=1)
            return reply

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=interrupted_environment):
            self.assertEqual(bootstrap_helper.initialize_environment(), self.python)
        pip_commands = [command for command, _ in calls if 'pip' in command]
        self.assertEqual(len(pip_commands), 4)
        self.assertEqual(pip_commands[0][-1], 'check')
        self.assertIn('--dry-run', pip_commands[1])
        self.assertNotIn('--dry-run', pip_commands[2])
        self.assertEqual(pip_commands[3][-1], 'check')

    def test_failed_dependency_repair_stops_without_retry_loop(self):
        self.make_existing_venv()
        runner, calls = self.standard_runner()

        def broken_environment(command, **kwargs):
            reply = runner(command, **kwargs)
            if self.call_is_pip(command, 'check'):
                return Completed(stderr='dependency is still missing', returncode=1)
            return reply

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=broken_environment):
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'Dependency check'):
                bootstrap_helper.initialize_environment()
        self.assertEqual(sum(self.call_is_pip(command, 'install') for command, _ in calls), 2)
        self.assertEqual(sum(self.call_is_pip(command, 'check') for command, _ in calls), 2)

    def test_preflight_cancellation_cleans_temporary_requirements(self):
        self.make_existing_venv()
        runner, _calls = self.standard_runner(initially_missing=True)

        def cancelled(command, **kwargs):
            if self.call_is_pip(command, 'install') and '--dry-run' in command:
                raise KeyboardInterrupt
            return runner(command, **kwargs)

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=cancelled):
            with self.assertRaises(KeyboardInterrupt):
                bootstrap_helper.initialize_environment()

        self.assertEqual(list((self.root / '.tmp').glob('bootstrap-pip-*')), [])

    def test_malformed_existing_venv_is_preserved(self):
        self.venv.mkdir()
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run') as runner:
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'missing') as raised:
                bootstrap_helper.initialize_environment()

        self.assertTrue(self.venv.is_dir())
        runner.assert_not_called()
        self.assertIn('.venv', str(raised.exception))
        self.assertNotIn(str(self.root), str(raised.exception))

    def test_bootstrap_is_noop_inside_any_real_venv(self):
        entrypoint = self.root / 'command.py'
        entrypoint.write_text('', encoding='utf-8')
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=True), \
                mock.patch.object(bootstrap_helper, 'initialize_environment') as initialize, \
                mock.patch.object(bootstrap_helper.os, 'execv') as execv:
            bootstrap_helper.bootstrap(entrypoint, ['--anything'])

        initialize.assert_not_called()
        execv.assert_not_called()

    def test_help_does_not_create_or_initialize_any_environment(self):
        entrypoint = self.root / 'command.py'
        entrypoint.write_text('', encoding='utf-8')
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper, 'initialize_environment') as initialize:
            bootstrap_helper.bootstrap(entrypoint, ['--help'])
            bootstrap_helper.bootstrap(entrypoint, ['-h'])

        initialize.assert_not_called()
        self.assertFalse(self.venv.exists())

    def test_rejected_pip_routing_never_creates_or_installs(self):
        with mock.patch.dict(os.environ, {'PIP_TARGET': str(self.root / 'outside')}, clear=False), \
                mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run') as runner:
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'PIP_TARGET'):
                bootstrap_helper.initialize_environment()

        self.assertFalse(self.venv.exists())
        runner.assert_not_called()

    def test_cancelled_venv_creation_removes_only_our_owned_directory(self):
        def interrupted(command, **_kwargs):
            self.assertEqual(command[1:4], ['-I', '-m', 'venv'])
            raise KeyboardInterrupt

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=interrupted):
            with self.assertRaises(KeyboardInterrupt):
                bootstrap_helper.initialize_environment()

        self.assertFalse(self.venv.exists())

    def test_posix_handoff_keeps_absolute_script_and_all_arguments(self):
        entrypoint = self.root / 'command.py'
        entrypoint.write_text('', encoding='utf-8')
        selected = self.root / '.venv' / 'bin' / 'python'

        class ReplacedProcess(Exception):
            pass

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper, 'initialize_environment', return_value=selected), \
                mock.patch.object(bootstrap_helper.os, 'execv', side_effect=ReplacedProcess) as execv:
            with self.assertRaises(ReplacedProcess):
                bootstrap_helper.bootstrap(entrypoint, ['--device-id', 'serial one'])

        execv.assert_called_once_with(
            str(selected), [str(selected), str(entrypoint.resolve()), '--device-id', 'serial one'],
        )

    def test_windows_handoff_exits_with_child_status(self):
        entrypoint = self.root / 'command.py'
        entrypoint.write_text('', encoding='utf-8')
        selected = self.root / '.venv' / 'Scripts' / 'python.exe'
        child = mock.Mock()
        child.wait.return_value = 7
        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper, 'initialize_environment', return_value=selected), \
                mock.patch.object(bootstrap_helper, '_is_windows', return_value=True), \
                mock.patch.object(bootstrap_helper.subprocess, 'Popen', return_value=child) as popen:
            with self.assertRaises(SystemExit) as exited:
                bootstrap_helper.bootstrap(entrypoint, ['--flag'])

        self.assertEqual(exited.exception.code, 7)
        popen.assert_called_once_with([str(selected), str(entrypoint.resolve()), '--flag'])

    def test_legacy_real_prefix_is_accepted_as_a_real_virtual_environment(self):
        report = Completed(stdout=json.dumps({
            'prefix': '/legacy-venv',
            'base_prefix': '/legacy-venv',
            'real_prefix': '/base-python',
        }) + '\n')
        with mock.patch.object(bootstrap_helper.subprocess, 'run', return_value=report):
            bootstrap_helper._fresh_venv_report(Path('/fake-python'), expected_prefix=None)

    def test_windows_interrupt_reap_is_bounded_and_ignores_cleanup_oserrors(self):
        child = mock.Mock()
        child.wait.side_effect = [
            subprocess.TimeoutExpired(['python'], 15),
            subprocess.TimeoutExpired(['python'], 5),
            subprocess.TimeoutExpired(['python'], 5),
        ]
        child.terminate.side_effect = OSError('already exited')
        child.kill.side_effect = OSError('already exited')
        stderr = io.StringIO()
        with redirect_stderr(stderr):
            bootstrap_helper._reap_windows_child_after_interrupt(child)

        self.assertEqual(
            child.wait.call_args_list,
            [mock.call(timeout=15), mock.call(timeout=5), mock.call(timeout=5)],
        )
        self.assertIn('could not reap', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
