"""The initialization entry point never starts the dumper or device tools."""

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import unittest
from unittest import mock

import init as initializer


class InitializationEntryTests(unittest.TestCase):
    def test_success_reports_both_environment_results(self):
        with mock.patch.object(initializer, 'prepare_terminal') as terminal, \
                mock.patch.object(
                    initializer,
                    'initialize_project_environments',
                    return_value=(Path('/repo/.venv/bin/python'), Path('/repo/.venv-wvd/bin/python')),
                ) as initialize, \
                mock.patch.object(
                    initializer,
                    'display_path',
                    side_effect=['.venv/bin/python', '.venv-wvd/bin/python'],
                ) as display, \
                redirect_stdout(io.StringIO()) as output:
            self.assertEqual(initializer.main([]), 0)
        terminal.assert_called_once_with()
        initialize.assert_called_once_with()
        self.assertEqual(display.call_args_list, [
            mock.call(Path('/repo/.venv/bin/python')),
            mock.call(Path('/repo/.venv-wvd/bin/python')),
        ])
        self.assertIn('Main Python setup is ready: .venv/bin/python', output.getvalue())
        self.assertIn('WVD Python setup is ready: .venv-wvd/bin/python', output.getvalue())
        self.assertIn('requirements and pip checks passed', output.getvalue())

    def test_help_and_invalid_arguments_do_not_initialize(self):
        for arguments, expected in ((['--help'], 0), (['--unknown'], 2)):
            with self.subTest(arguments=arguments), \
                    mock.patch.object(initializer, 'prepare_terminal'), \
                    mock.patch.object(initializer, 'initialize_project_environments') as initialize, \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()), \
                    self.assertRaises(SystemExit) as result:
                initializer.main(arguments)
            self.assertEqual(result.exception.code, expected)
            initialize.assert_not_called()

    def test_setup_error_is_clean(self):
        with mock.patch.object(initializer, 'prepare_terminal'), \
                mock.patch.object(initializer, 'initialize_project_environments', side_effect=initializer.BootstrapError('dependency conflict')), \
                redirect_stderr(io.StringIO()) as output:
            self.assertEqual(initializer.main([]), 1)
        self.assertIn('error: dependency conflict', output.getvalue())
        self.assertNotIn('Traceback', output.getvalue())

    def test_cancellation_is_clean_before_or_during_setup(self):
        for stage in ('prepare_terminal', 'initialize_project_environments'):
            with self.subTest(stage=stage), \
                    mock.patch.object(initializer, 'prepare_terminal'), \
                    mock.patch.object(initializer, 'initialize_project_environments'), \
                    mock.patch.object(initializer, stage, side_effect=KeyboardInterrupt), \
                    redirect_stderr(io.StringIO()) as output:
                self.assertEqual(initializer.main([]), 130)
            self.assertIn('Initialization cancelled.', output.getvalue())
            self.assertNotIn('Traceback', output.getvalue())


if __name__ == '__main__':
    unittest.main()
