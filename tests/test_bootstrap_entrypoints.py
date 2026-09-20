"""Direct CLI startup enters the shared bootstrap before doing normal work."""

from contextlib import redirect_stderr, redirect_stdout
import io
from pathlib import Path
import runpy
import sys
import unittest
from unittest import mock

from Helpers.Bootstrap import BootstrapError


ROOT = Path(__file__).resolve().parents[1]
ENTRYPOINTS = ('dump_keys.py', 'tools/setup_frida.py', 'tools/regenerate_protobuf.py')


class BootstrapEntryTests(unittest.TestCase):
    def test_bootstrap_error_stops_each_entrypoint_before_work(self):
        for relative in ENTRYPOINTS:
            events = []

            def stop(script):
                events.append(Path(script).resolve())
                raise BootstrapError('environment unavailable')

            with self.subTest(script=relative), \
                    mock.patch('Helpers.CLI.prepare_terminal', side_effect=lambda: events.append('terminal')), \
                    mock.patch('Helpers.Bootstrap.bootstrap', side_effect=stop), \
                    mock.patch.object(sys, 'argv', [str(ROOT / relative)]), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as output, \
                    self.assertRaises(SystemExit) as result:
                runpy.run_path(str(ROOT / relative), run_name='__main__')
            self.assertEqual(result.exception.code, 1)
            self.assertEqual(events, ['terminal', ROOT / relative])
            self.assertIn('environment unavailable', output.getvalue())
            self.assertNotIn('Traceback', output.getvalue())

    def test_bootstrap_cancellation_preserves_each_cli_exit_convention(self):
        for relative in ENTRYPOINTS:
            with self.subTest(script=relative), \
                    mock.patch('Helpers.CLI.prepare_terminal'), \
                    mock.patch('Helpers.Bootstrap.bootstrap', side_effect=KeyboardInterrupt), \
                    mock.patch.object(sys, 'argv', [str(ROOT / relative)]), \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()) as output, \
                    self.assertRaises(SystemExit) as result:
                runpy.run_path(str(ROOT / relative), run_name='__main__')
            self.assertEqual(result.exception.code, 0 if relative == 'dump_keys.py' else 130)
            self.assertNotIn('Traceback', output.getvalue())


if __name__ == '__main__':
    unittest.main()
