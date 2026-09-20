"""Exercise pip's real source-path output without installs or network access."""

from importlib import metadata
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest import mock

from Helpers import Bootstrap


class PipOutputTests(unittest.TestCase):
    def test_base_python_probe_creates_a_real_venv_and_cleans_it(self):
        scratch = Bootstrap.ROOT / '.tmp'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='venv-probe-test-', dir=scratch) as staging:
            creator = Path(getattr(sys, '_base_executable', None) or sys.executable).resolve()
            with mock.patch.object(Bootstrap, 'ROOT', Path(staging)):
                Bootstrap._verify_venv_creator(creator)
            self.assertEqual(list((Path(staging) / '.tmp').iterdir()), [])

    def test_real_pip_uses_relative_requirement_path_from_another_working_directory(self):
        # Use only this interpreter's already-installed pip. The dry run has
        # no index and no cache writes; this never installs project packages.
        try:
            version = metadata.version('pip')
        except metadata.PackageNotFoundError:
            self.skipTest('This interpreter has no pip.')
        if not Bootstrap.running_in_virtual_environment():
            self.skipTest('The pip probe requires a real virtual environment.')
        scratch = Bootstrap.ROOT / '.tmp'
        scratch.mkdir(exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='pip-output-', dir=scratch) as staging, \
                tempfile.TemporaryDirectory() as outside:
            requirements = Path(staging) / 'requirements.txt'
            requirements.write_text(f'pip=={version}\n', encoding='utf-8')
            command = Bootstrap._pip_install_command(Path(sys.executable), requirements, dry_run=True)
            command.extend(['--no-index', '--no-cache-dir'])
            previous = Path.cwd()
            try:
                os.chdir(outside)
                with mock.patch.dict(os.environ, {'DUMPER_AUTO_LOGGING': '0'}):
                    result = Bootstrap._run_command(
                        command, 'Checking pip source-path output', timeout=30,
                        environment=Bootstrap._pip_environment(),
                    )
            finally:
                os.chdir(previous)
            output = result.stdout + result.stderr
            self.assertIn(f'-r {requirements.relative_to(Bootstrap.ROOT)}', output)
            self.assertNotIn(str(Bootstrap.ROOT), output)
            self.assertIn('Requirement already satisfied', output)


if __name__ == '__main__':
    unittest.main()
