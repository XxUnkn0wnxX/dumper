"""Offline tests for full-auto's background environment initializer."""

from contextlib import nullcontext, redirect_stderr
import io
from pathlib import Path
import sys
import unittest
from unittest import mock

import init as public_init
from Helpers import AutoInit as initializer
from tools import setup_frida


class AutoInitTests(unittest.TestCase):
    """Exercise init sequencing without installing packages or probing devices."""

    def test_bootstrap_then_public_init_then_adb_resolution_emits_ready(self):
        with mock.patch.object(initializer, 'prepare_terminal'), \
                mock.patch.object(initializer, 'bootstrap') as bootstrap, \
                mock.patch.object(public_init, 'main', return_value=0) as init_main, \
                mock.patch.object(setup_frida, 'resolve_adb', return_value='/fixture/adb') as resolve_adb, \
                mock.patch.object(initializer, 'emit_event') as emit:
            self.assertEqual(initializer.main(), 0)

        bootstrap.assert_called_once_with(Path(initializer.__file__))
        init_main.assert_called_once_with([])
        resolve_adb.assert_called_once_with(None)
        emit.assert_called_once_with(
            'environment_ready', python=sys.executable, adb='/fixture/adb',
        )

    def test_public_init_nonzero_status_stops_before_adb_or_event(self):
        with mock.patch.object(initializer, 'prepare_terminal'), \
                mock.patch.object(initializer, 'bootstrap'), \
                mock.patch.object(public_init, 'main', return_value=3) as init_main, \
                mock.patch.object(setup_frida, 'resolve_adb') as resolve_adb, \
                mock.patch.object(initializer, 'emit_event') as emit:
            self.assertEqual(initializer.main(), 3)

        init_main.assert_called_once_with([])
        resolve_adb.assert_not_called()
        emit.assert_not_called()

    def test_adb_resolution_failure_returns_clean_status_without_ready_event(self):
        with mock.patch.object(initializer, 'prepare_terminal'), \
                mock.patch.object(initializer, 'bootstrap'), \
                mock.patch.object(public_init, 'main', return_value=0), \
                mock.patch.object(
                    setup_frida, 'resolve_adb',
                    side_effect=setup_frida.SetupError('adb unavailable'),
                ), \
                mock.patch.object(initializer, 'emit_event') as emit, \
                redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(initializer.main(), 1)

        self.assertIn('error: adb unavailable', stderr.getvalue())
        emit.assert_not_called()

    def test_bootstrap_failure_returns_clean_status_without_public_init(self):
        with mock.patch.object(initializer, 'prepare_terminal'), \
                mock.patch.object(
                    initializer, 'bootstrap',
                    side_effect=initializer.BootstrapError('bootstrap failed'),
                ), \
                mock.patch.object(public_init, 'main') as init_main, \
                redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(initializer.main(), 1)

        init_main.assert_not_called()
        self.assertIn('error: bootstrap failed', stderr.getvalue())

    def test_ctrl_c_returns_130_after_running_cancellation_cleanup(self):
        with mock.patch.object(initializer, 'prepare_terminal'), \
                mock.patch.object(initializer, 'bootstrap'), \
                mock.patch.object(public_init, 'main', side_effect=KeyboardInterrupt), \
                mock.patch.object(initializer, 'ignore_interrupts', return_value=nullcontext()) as cleanup, \
                redirect_stderr(io.StringIO()) as stderr:
            self.assertEqual(initializer.main(), 130)

        cleanup.assert_called_once_with()
        self.assertIn('Initialization cancelled.', stderr.getvalue())


if __name__ == '__main__':
    unittest.main()
