"""Offline tests for the dedicated WVD virtual-environment bootstrap."""

from __future__ import annotations

from contextlib import redirect_stdout
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
from Helpers import WvdBootstrap as wvd_bootstrap


class Completed:
    def __init__(self, stdout='', stderr='', returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class WvdBootstrapTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / 'repository with spaces'
        self.root.mkdir()
        (self.root / 'requirements-wvd.txt').write_text('pywidevine==1.9.0\n', encoding='utf-8')
        self.root_patch = mock.patch.object(bootstrap_helper, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    @property
    def venv(self):
        return self.root / '.venv-wvd'

    @property
    def python(self):
        return bootstrap_helper._venv_python(self.venv)

    def make_wvd_venv(self, *, system_site_packages=False):
        self.python.parent.mkdir(parents=True)
        self.python.write_text('', encoding='utf-8')
        (self.venv / 'pyvenv.cfg').write_text(
            f'include-system-site-packages = {str(system_site_packages).lower()}\n',
            encoding='utf-8',
        )

    @staticmethod
    def call_is_pip(command, operation):
        return '-m' in command and 'pip' in command and operation in command

    def prefix_result(self, *, prefix=None):
        return Completed(stdout=json.dumps({
            'prefix': str(prefix or self.venv),
            'base_prefix': '/outside-python',
            'real_prefix': None,
        }) + '\n')

    @staticmethod
    def requirements_result(packages):
        return Completed(stdout=json.dumps({
            'machine': 'x86_64',
            'installed': packages,
        }) + '\n')

    def runner(self, *, initially_missing=False, create_file=False, prefix=None):
        packages = {'pywidevine': None if initially_missing else '1.9.0'}
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
                    (self.venv / 'pyvenv.cfg').write_text(
                        'include-system-site-packages = false\n', encoding='utf-8',
                    )
                return Completed()
            if '-c' in command:
                script = command[command.index('-c') + 1]
                if script == 'import venv':
                    return Completed()
                if 'base_prefix' in script:
                    return self.prefix_result(prefix=prefix)
                if 'metadata.distributions' in script:
                    return Completed(stdout=json.dumps([
                        ['pywidevine', version]
                        for version in packages.values() if version is not None
                    ] + [['other-package', '1.0']]) + '\n')
                if 'metadata.version' in script:
                    return self.requirements_result(packages.copy())
            if self.call_is_pip(command, 'install'):
                if '--dry-run' not in command:
                    packages['pywidevine'] = '1.9.0'
                return Completed()
            if self.call_is_pip(command, 'check'):
                return Completed()
            self.fail(f'Unexpected command: {command!r}')

        return run, calls

    def active_environment(self, prefix):
        return mock.patch.multiple(
            bootstrap_helper.sys,
            prefix=str(prefix),
            base_prefix='/outside-python',
            executable=str(self.python),
        )

    def outside_environment(self):
        return mock.patch.multiple(
            bootstrap_helper.sys,
            prefix='/outside-python',
            base_prefix='/outside-python',
            executable='/outside-python/bin/python',
        )

    def initialize(self, **kwargs):
        return bootstrap_helper.initialize_dedicated_environment(
            venv_name='.venv-wvd', requirements_file=self.root / 'requirements-wvd.txt',
            **kwargs,
        )

    def test_project_initializer_uses_active_custom_main_then_repository_wvd(self):
        main_python = Path('/custom main/bin/python')
        wvd_python = self.python
        sequence = []

        def initialize_main(**kwargs):
            sequence.append(('main', kwargs))
            return main_python

        def initialize_wvd(**kwargs):
            sequence.append(('wvd', kwargs))
            return wvd_python

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=True), \
                mock.patch.object(wvd_bootstrap.sys, 'prefix', '/custom main'), \
                mock.patch.object(bootstrap_helper, 'initialize_environment', side_effect=initialize_main), \
                mock.patch.object(
                    bootstrap_helper, 'initialize_dedicated_environment', side_effect=initialize_wvd,
                ):
            self.assertEqual(
                wvd_bootstrap.initialize_project_environments(), (main_python, wvd_python),
            )

        self.assertEqual(sequence, [
            ('main', {'use_active_environment': True, 'rebuild_corrupt': True}),
            ('wvd', {
                'venv_name': '.venv-wvd',
                'requirements_file': self.root / 'requirements-wvd.txt',
                'use_active_environment': False,
                'rebuild_corrupt': True,
            }),
        ])

    def test_project_initializer_uses_repository_main_when_started_in_wvd(self):
        main_python = self.root / '.venv' / 'bin' / 'python'
        wvd_python = self.python
        sequence = []

        def initialize_main(**kwargs):
            sequence.append(('main', kwargs))
            return main_python

        def initialize_wvd(**kwargs):
            sequence.append(('wvd', kwargs))
            return wvd_python

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=True), \
                mock.patch.object(wvd_bootstrap.sys, 'prefix', str(self.venv)), \
                mock.patch.object(bootstrap_helper, 'initialize_environment', side_effect=initialize_main), \
                mock.patch.object(
                    bootstrap_helper, 'initialize_dedicated_environment', side_effect=initialize_wvd,
                ):
            self.assertEqual(
                wvd_bootstrap.initialize_project_environments(), (main_python, wvd_python),
            )

        self.assertEqual(sequence, [
            ('main', {'use_active_environment': False, 'rebuild_corrupt': True}),
            ('wvd', {
                'venv_name': '.venv-wvd',
                'requirements_file': self.root / 'requirements-wvd.txt',
                'use_active_environment': False,
                'rebuild_corrupt': True,
            }),
        ])

    def test_project_initializer_does_not_start_wvd_after_main_failure(self):
        with mock.patch.object(
            bootstrap_helper, 'initialize_environment',
            side_effect=bootstrap_helper.BootstrapError('main setup failed'),
        ), mock.patch.object(bootstrap_helper, 'initialize_dedicated_environment') as initialize_wvd:
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'main setup failed'):
                wvd_bootstrap.initialize_project_environments()

        initialize_wvd.assert_not_called()

    def test_project_initializer_runs_wvd_after_main_and_propagates_wvd_failure(self):
        main_python = self.root / '.venv' / 'bin' / 'python'
        sequence = []

        def initialize_main(**kwargs):
            sequence.append(('main', kwargs))
            return main_python

        def initialize_wvd(**kwargs):
            sequence.append(('wvd', kwargs))
            raise bootstrap_helper.BootstrapError('WVD setup failed')

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper, 'initialize_environment', side_effect=initialize_main), \
                mock.patch.object(
                    bootstrap_helper, 'initialize_dedicated_environment', side_effect=initialize_wvd,
                ):
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'WVD setup failed'):
                wvd_bootstrap.initialize_project_environments()

        self.assertEqual([name for name, _kwargs in sequence], ['main', 'wvd'])

    def test_help_never_initializes_or_relaunches(self):
        entrypoint = self.root / 'generate_wvd.py'
        entrypoint.write_text('', encoding='utf-8')
        with mock.patch.object(bootstrap_helper, 'initialize_dedicated_environment') as initialize, \
                mock.patch.object(bootstrap_helper, '_relaunch') as relaunch:
            wvd_bootstrap.bootstrap_wvd(entrypoint, ['--help'])
            wvd_bootstrap.bootstrap_wvd(entrypoint, ['-h'])

        initialize.assert_not_called()
        relaunch.assert_not_called()
        self.assertFalse(self.venv.exists())

    def test_other_real_venv_refuses_before_any_subprocess_or_wvd_mutation(self):
        entrypoint = self.root / 'generate_wvd.py'
        entrypoint.write_text('', encoding='utf-8')
        main_venv = self.root / '.venv'
        with self.active_environment(main_venv), \
                mock.patch.object(bootstrap_helper.subprocess, 'run') as runner:
            with self.assertRaisesRegex(
                bootstrap_helper.BootstrapError, 'Deactivate the current environment',
            ) as raised:
                wvd_bootstrap.bootstrap_wvd(entrypoint, [])

        runner.assert_not_called()
        self.assertFalse(self.venv.exists())
        self.assertIn('.venv-wvd', str(raised.exception))
        self.assertNotIn(str(self.root), str(raised.exception))

    def test_stale_virtual_env_does_not_reject_the_explicit_wvd_interpreter(self):
        self.make_wvd_venv()
        runner, calls = self.runner()
        with self.active_environment(self.venv), \
                mock.patch.dict(os.environ, {'VIRTUAL_ENV': str(self.root / '.venv')}, clear=False), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            self.assertEqual(self.initialize(), self.python)

        self.assertFalse(any(self.call_is_pip(command, 'install') for command, _ in calls))

    def test_dedicated_symlink_is_rejected_before_interpreter_or_pip(self):
        target = self.root / '.venv'
        target.mkdir()
        self.venv.symlink_to(target, target_is_directory=True)
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run') as runner, \
                mock.patch.object(bootstrap_helper.shutil, 'rmtree') as rmtree:
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'not a normal directory'):
                self.initialize(use_active_environment=False, rebuild_corrupt=True)

        runner.assert_not_called()
        self.assertFalse(any(
            call.args and Path(call.args[0]) == self.venv for call in rmtree.call_args_list
        ))

    def test_system_site_packages_is_rejected_before_interpreter_or_pip(self):
        self.make_wvd_venv(system_site_packages=True)
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run') as runner:
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'include-system-site-packages=true'):
                self.initialize()

        runner.assert_not_called()

    def test_wrong_dedicated_interpreter_prefix_is_rejected_before_requirement_check(self):
        self.make_wvd_venv()
        runner, calls = self.runner(prefix=self.root / '.venv')
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'sys.prefix'):
                self.initialize()

        self.assertEqual(len(calls), 1)
        self.assertFalse(any(self.call_is_pip(command, 'install') for command, _ in calls))

    def test_active_healthy_wvd_environment_checks_wvd_requirements_without_installing(self):
        self.make_wvd_venv()
        runner, calls = self.runner()
        with self.active_environment(self.venv), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            self.assertEqual(self.initialize(), self.python)

        self.assertFalse(any(command[1:4] == ['-I', '-m', 'venv'] for command, _ in calls))
        self.assertFalse(any(self.call_is_pip(command, 'install') for command, _ in calls))
        self.assertTrue(any(self.call_is_pip(command, 'check') for command, _ in calls))

    def test_rebuild_check_reuses_healthy_project_wvd_environment_without_installing(self):
        self.make_wvd_venv()
        runner, calls = self.runner()
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            self.assertEqual(
                self.initialize(use_active_environment=False, rebuild_corrupt=True), self.python,
            )

        self.assertFalse(any(command[1:4] == ['-I', '-m', 'venv'] for command, _ in calls))
        self.assertFalse(any(self.call_is_pip(command, 'install') for command, _ in calls))
        self.assertTrue(any(self.call_is_pip(command, 'check') for command, _ in calls))

    def test_rebuild_repairs_missing_wvd_requirement_without_deleting_environment(self):
        self.make_wvd_venv()
        runner, calls = self.runner(initially_missing=True)
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner), \
                mock.patch.object(bootstrap_helper.shutil, 'rmtree') as rmtree:
            self.assertEqual(
                self.initialize(use_active_environment=False, rebuild_corrupt=True), self.python,
            )

        self.assertFalse(any(
            call.args and Path(call.args[0]) == self.venv for call in rmtree.call_args_list
        ))
        self.assertFalse(any(command[1:4] == ['-I', '-m', 'venv'] for command, _ in calls))
        installs = [
            kwargs['requirements_text']
            for command, kwargs in calls if self.call_is_pip(command, 'install')
        ]
        self.assertEqual(len(installs), 2)
        self.assertTrue(all('pywidevine==1.9.0\n' in requirements for requirements in installs))
        self.assertTrue(all('frida' not in requirements and 'protobuf' not in requirements for requirements in installs))

    def test_rebuild_timeout_or_permission_failure_never_deletes_wvd_environment(self):
        self.make_wvd_venv()
        failures = (
            subprocess.TimeoutExpired(['python'], 15),
            PermissionError('permission denied'),
        )
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                with self.outside_environment(), \
                        mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=failure), \
                        mock.patch.object(bootstrap_helper.shutil, 'rmtree') as rmtree:
                    with self.assertRaises(bootstrap_helper.BootstrapError):
                        self.initialize(use_active_environment=False, rebuild_corrupt=True)

                rmtree.assert_not_called()
                self.assertTrue(self.venv.is_dir())

    def test_rebuild_broken_dependency_graph_recreates_then_installs_only_wvd_requirements(self):
        self.make_wvd_venv()
        runner, calls = self.runner(initially_missing=True, create_file=True)
        checks = 0

        def broken_graph(command, **kwargs):
            nonlocal checks
            result = runner(command, **kwargs)
            if self.call_is_pip(command, 'check'):
                checks += 1
                if checks == 1:
                    return Completed(stderr='pywidevine dependency is broken', returncode=1)
            return result

        original_rmtree = bootstrap_helper.shutil.rmtree
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=broken_graph), \
                mock.patch.object(bootstrap_helper, '_verify_venv_creator') as verify_creator, \
                mock.patch.object(bootstrap_helper.shutil, 'rmtree', wraps=original_rmtree) as rmtree:
            self.assertEqual(
                self.initialize(use_active_environment=False, rebuild_corrupt=True), self.python,
            )

        target_removals = [
            call for call in rmtree.call_args_list if call.args and Path(call.args[0]) == self.venv
        ]
        self.assertEqual(len(target_removals), 1)
        self.assertTrue(self.python.is_file())
        verify_creator.assert_called_once()
        self.assertIn('base_prefix', calls[0][0][-1])
        self.assertEqual(calls[1][0][-1], 'check')
        self.assertEqual(calls[2][0][-1], 'import venv')
        self.assertEqual(calls[3][0][1:4], ['-I', '-m', 'venv'])
        installs = [
            kwargs['requirements_text']
            for command, kwargs in calls if self.call_is_pip(command, 'install')
        ]
        self.assertEqual(len(installs), 2)
        self.assertTrue(all('pywidevine==1.9.0\n' in requirements for requirements in installs))
        self.assertTrue(all('frida' not in requirements and 'protobuf' not in requirements for requirements in installs))

    def test_rebuild_base_probe_cancellation_leaves_damaged_wvd_environment_untouched(self):
        self.venv.mkdir()
        damaged_file = self.venv / 'damaged-state'
        damaged_file.write_text('incomplete environment', encoding='utf-8')

        def cancelled_base_probe(command, **_kwargs):
            self.assertEqual(command[-1], 'import venv')
            raise KeyboardInterrupt

        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=cancelled_base_probe), \
                mock.patch.object(bootstrap_helper.shutil, 'rmtree') as rmtree:
            with self.assertRaises(KeyboardInterrupt):
                self.initialize(use_active_environment=False, rebuild_corrupt=True)

        rmtree.assert_not_called()
        self.assertTrue(damaged_file.is_file())

    def test_rebuild_creator_probe_failure_leaves_damaged_wvd_environment_untouched(self):
        self.venv.mkdir()
        damaged_file = self.venv / 'damaged-state'
        damaged_file.write_text('incomplete environment', encoding='utf-8')
        runner, calls = self.runner()
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner), \
                mock.patch.object(
                    bootstrap_helper, '_verify_venv_creator',
                    side_effect=bootstrap_helper.BootstrapError('creator probe failed'),
                ) as verify_creator, \
                mock.patch.object(bootstrap_helper.shutil, 'rmtree') as rmtree:
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'creator probe failed'):
                self.initialize(use_active_environment=False, rebuild_corrupt=True)

        verify_creator.assert_called_once()
        rmtree.assert_not_called()
        self.assertTrue(damaged_file.is_file())
        self.assertFalse(any(command[1:4] == ['-I', '-m', 'venv'] for command, _ in calls))

    def test_rebuild_removal_error_leaves_damaged_wvd_environment_without_recreating(self):
        self.venv.mkdir()
        damaged_file = self.venv / 'damaged-state'
        damaged_file.write_text('incomplete environment', encoding='utf-8')
        runner, calls = self.runner()
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner), \
                mock.patch.object(bootstrap_helper, '_verify_venv_creator') as verify_creator, \
                mock.patch.object(
                    bootstrap_helper.shutil, 'rmtree', side_effect=PermissionError('permission denied'),
                ) as rmtree:
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'Could not remove damaged environment'):
                self.initialize(use_active_environment=False, rebuild_corrupt=True)

        verify_creator.assert_called_once()
        rmtree.assert_called_once_with(self.venv)
        self.assertTrue(damaged_file.is_file())
        self.assertFalse(any(command[1:4] == ['-I', '-m', 'venv'] for command, _ in calls))

    def test_windows_running_corrupt_wvd_target_refuses_before_probe_or_deletion(self):
        self.venv.mkdir()
        damaged_file = self.venv / 'damaged-state'
        damaged_file.write_text('incomplete environment', encoding='utf-8')
        with self.active_environment(self.venv), \
                mock.patch.object(bootstrap_helper, '_is_windows', return_value=True), \
                mock.patch.object(bootstrap_helper.subprocess, 'run') as runner, \
                mock.patch.object(bootstrap_helper, '_verify_venv_creator') as verify_creator, \
                mock.patch.object(bootstrap_helper.shutil, 'rmtree') as rmtree:
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'running on Windows'):
                self.initialize(use_active_environment=False, rebuild_corrupt=True)

        runner.assert_not_called()
        verify_creator.assert_not_called()
        rmtree.assert_not_called()
        self.assertTrue(damaged_file.is_file())

    def test_active_wvd_environment_repairs_only_wvd_requirements(self):
        self.make_wvd_venv()
        runner, calls = self.runner(initially_missing=True)
        with self.active_environment(self.venv), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            self.assertEqual(self.initialize(), self.python)

        installs = [
            kwargs['requirements_text']
            for command, kwargs in calls if self.call_is_pip(command, 'install')
        ]
        self.assertEqual(len(installs), 2)
        self.assertEqual(installs[0], installs[1])
        self.assertIn('pywidevine==1.9.0\n', installs[0])
        self.assertNotIn('frida', installs[0])
        self.assertNotIn('protobuf==7.36.2', installs[0])

    def test_rebuild_creates_missing_wvd_environment_and_relaunches_with_all_arguments(self):
        runner, calls = self.runner(initially_missing=True, create_file=True)
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner), \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                self.initialize(use_active_environment=False, rebuild_corrupt=True), self.python,
            )

        self.assertEqual(calls[0][0][0], '/outside-python/bin/python')
        self.assertEqual(calls[0][0][1:4], ['-I', '-m', 'venv'])
        self.assertTrue(all(Path(kwargs['cwd']) == self.root for _command, kwargs in calls))
        installs = [
            (command, kwargs) for command, kwargs in calls if self.call_is_pip(command, 'install')
        ]
        self.assertEqual(len(installs), 2)
        for command, kwargs in installs:
            self.assertEqual(command[0], str(self.python))
            self.assertFalse(Path(command[-1]).is_absolute())
            self.assertEqual(
                Path(kwargs['resolved_requirements_path']), Path(kwargs['cwd']) / command[-1],
            )
            self.assertIn('pywidevine==1.9.0\n', kwargs['requirements_text'])

        status = output.getvalue()
        self.assertNotIn(str(self.root), status)
        self.assertIn('Creating dedicated WVD virtual environment at .venv-wvd...', status)
        self.assertIn(
            'Preflighting the complete requested dependency set for dedicated WVD virtual environment .venv-wvd...',
            status,
        )
        self.assertIn(
            'Installing preflighted WVD requirements into dedicated WVD virtual environment .venv-wvd...',
            status,
        )
        self.assertIn('Virtual environment ready: .venv-wvd/bin/python.', status)

        entrypoint = self.root / 'generate_wvd.py'
        entrypoint.write_text('', encoding='utf-8')

        class ReplacedProcess(Exception):
            pass

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper, 'initialize_dedicated_environment', return_value=self.python) as initialize, \
                mock.patch.object(bootstrap_helper.os, 'execv', side_effect=ReplacedProcess) as execv, \
                redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(ReplacedProcess):
                wvd_bootstrap.bootstrap_wvd(entrypoint, ['--client-id', 'device one'])

        initialize.assert_called_once_with(
            venv_name='.venv-wvd', requirements_file=self.root / 'requirements-wvd.txt',
        )
        execv.assert_called_once_with(
            str(self.python), [str(self.python), str(entrypoint.resolve()), '--client-id', 'device one'],
        )
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertIn('Relaunching with .venv-wvd/bin/python: generate_wvd.py', output.getvalue())

    def test_rebuild_replaces_corrupt_wvd_environment_without_backup(self):
        self.venv.mkdir()
        damaged_file = self.venv / 'damaged-state'
        damaged_file.write_text('incomplete environment', encoding='utf-8')
        runner, calls = self.runner(initially_missing=True, create_file=True)
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner), \
                mock.patch.object(bootstrap_helper, '_verify_venv_creator') as verify_creator, \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(
                self.initialize(use_active_environment=False, rebuild_corrupt=True), self.python,
            )

        self.assertFalse(damaged_file.exists())
        self.assertTrue(self.python.is_file())
        verify_creator.assert_called_once()
        self.assertEqual(calls[0][0][-1], 'import venv')
        self.assertEqual(calls[1][0][1:4], ['-I', '-m', 'venv'])
        self.assertFalse(any('backup' in path.name for path in self.root.iterdir()))
        self.assertNotIn(str(self.root), output.getvalue())
        self.assertIn('Rebuilding dedicated wvd virtual environment at .venv-wvd:', output.getvalue())


if __name__ == '__main__':
    unittest.main()
