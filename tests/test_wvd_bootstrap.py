"""Offline tests for the dedicated WVD virtual-environment bootstrap."""

from __future__ import annotations

import json
import os
from pathlib import Path
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
        self.root = Path(self.temporary.name)
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
                kwargs = {
                    **kwargs,
                    'requirements_text': Path(command[-1]).read_text(encoding='utf-8'),
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

    def initialize(self):
        return bootstrap_helper.initialize_dedicated_environment(
            venv_name='.venv-wvd', requirements_file=self.root / 'requirements-wvd.txt',
        )

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
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'Deactivate the current environment'):
                wvd_bootstrap.bootstrap_wvd(entrypoint, [])

        runner.assert_not_called()
        self.assertFalse(self.venv.exists())

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
                mock.patch.object(bootstrap_helper.subprocess, 'run') as runner:
            with self.assertRaisesRegex(bootstrap_helper.BootstrapError, 'not a normal directory'):
                self.initialize()

        runner.assert_not_called()

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

    def test_outside_creates_wvd_environment_and_relaunches_with_all_arguments(self):
        runner, calls = self.runner(create_file=True)
        with self.outside_environment(), \
                mock.patch.object(bootstrap_helper.subprocess, 'run', side_effect=runner):
            self.assertEqual(self.initialize(), self.python)

        self.assertEqual(calls[0][0][1:4], ['-I', '-m', 'venv'])
        self.assertFalse(any(self.call_is_pip(command, 'install') for command, _ in calls))

        entrypoint = self.root / 'generate_wvd.py'
        entrypoint.write_text('', encoding='utf-8')

        class ReplacedProcess(Exception):
            pass

        with mock.patch.object(bootstrap_helper, 'running_in_virtual_environment', return_value=False), \
                mock.patch.object(bootstrap_helper, 'initialize_dedicated_environment', return_value=self.python) as initialize, \
                mock.patch.object(bootstrap_helper.os, 'execv', side_effect=ReplacedProcess) as execv:
            with self.assertRaises(ReplacedProcess):
                wvd_bootstrap.bootstrap_wvd(entrypoint, ['--client-id', 'device one'])

        initialize.assert_called_once_with(
            venv_name='.venv-wvd', requirements_file=self.root / 'requirements-wvd.txt',
        )
        execv.assert_called_once_with(
            str(self.python), [str(self.python), str(entrypoint.resolve()), '--client-id', 'device one'],
        )


if __name__ == '__main__':
    unittest.main()
