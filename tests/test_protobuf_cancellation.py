"""Cancellation and rollback tests for the protobuf regeneration helper."""

from contextlib import contextmanager, redirect_stderr
import io
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest import mock

from tools import regenerate_protobuf as regen


class ProtobufCancellationTests(unittest.TestCase):
    """Use an isolated fake repository and never invoke real protoc or pip."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_root = regen.ROOT / '.tmp'
        cls.tmp_root.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='protobuf-cancel-', dir=self.tmp_root,
        )
        self.root = Path(self.temporary.name)
        (self.root / 'Helpers').mkdir()
        (self.root / 'Helpers/wv_proto2.proto').write_text('syntax = "proto2";\n', encoding='utf-8')
        (self.root / 'Helpers/wv_proto2_pb2.py').write_bytes(b'old binding\n')
        (self.root / 'requirements.txt').write_text('protobuf==3.19.3\nother==1\n', encoding='utf-8')
        (self.root / '.tmp').mkdir()
        self.patches = mock.patch.multiple(
            regen,
            ROOT=self.root,
            SCHEMA=Path('Helpers/wv_proto2.proto'),
            BINDING=Path('Helpers/wv_proto2_pb2.py'),
            REQUIREMENTS=Path('requirements.txt'),
        )
        self.patches.start()
        self.addCleanup(self.patches.stop)

    def tearDown(self):
        self.temporary.cleanup()

    @contextmanager
    def command_line(self, *arguments):
        with mock.patch.object(sys, 'argv', ['regenerate_protobuf.py', *arguments]):
            yield

    def run_cancelled(self, *arguments):
        stderr = io.StringIO()
        with self.command_line(*arguments), \
                mock.patch.object(regen, 'prepare_terminal'), \
                redirect_stderr(stderr):
            result = regen.main()
        self.assertEqual(result, 130)
        self.assertIn('Cancelled.', stderr.getvalue())
        return stderr.getvalue()

    def generated_command(self, command, purpose):
        """Satisfy version/generation phases without a compiler process."""
        if purpose == 'Locating protoc':
            return 'libprotoc 3.21.12'
        if purpose == 'Generating Python bindings':
            output_root = Path(next(value.split('=', 1)[1] for value in command
                                    if value.startswith('--python_out=')))
            generated = output_root / regen.BINDING
            generated.parent.mkdir(parents=True, exist_ok=True)
            generated.write_bytes(b'# Protobuf Python Version: 3.21.12\n')
            return ''
        raise AssertionError(f'unexpected command phase: {purpose}')

    def test_cancel_during_argument_parsing_returns_130(self):
        with self.command_line(), \
                mock.patch.object(regen, 'prepare_terminal') as prepare, \
                mock.patch('argparse.ArgumentParser.parse_args', side_effect=KeyboardInterrupt), \
                redirect_stderr(io.StringIO()) as stderr:
            result = regen.main()

        self.assertEqual(result, 130)
        prepare.assert_called_once_with()
        self.assertIn('Cancelled.', stderr.getvalue())

    def test_cancel_during_protoc_version_check_cleans_staging(self):
        with mock.patch.object(regen, 'run_command', side_effect=KeyboardInterrupt):
            self.run_cancelled()
        self.assertEqual(list((self.root / '.tmp').iterdir()), [])

    def test_cancel_during_compile_cleans_partial_staging(self):
        with mock.patch.object(regen, 'run_command', side_effect=[
            'libprotoc 3.21.12', KeyboardInterrupt(),
        ]):
            self.run_cancelled()
        self.assertEqual(list((self.root / '.tmp').iterdir()), [])

    def test_cancel_during_validation_leaves_existing_outputs_unchanged(self):
        def command(command, purpose):
            if purpose == 'Validating generated import (use --update-runtime if the runtime is incompatible)':
                raise KeyboardInterrupt
            return self.generated_command(command, purpose)

        with mock.patch.object(regen, 'run_command', side_effect=command):
            self.run_cancelled()
        self.assertEqual((self.root / regen.BINDING).read_bytes(), b'old binding\n')
        self.assertEqual(
            (self.root / regen.REQUIREMENTS).read_text(encoding='utf-8'),
            'protobuf==3.19.3\nother==1\n',
        )
        self.assertEqual(list((self.root / '.tmp').iterdir()), [])

    def test_cancel_during_optional_runtime_update_does_not_replace_outputs(self):
        def command(command, purpose):
            if purpose == 'Updating protobuf runtime':
                raise KeyboardInterrupt
            return self.generated_command(command, purpose)

        with mock.patch.object(regen, 'run_command', side_effect=command), \
                mock.patch.object(regen.sys, 'prefix', '/tmp/test-venv'), \
                mock.patch.object(regen.sys, 'base_prefix', '/usr'):
            self.run_cancelled('--update-runtime')
        self.assertEqual((self.root / regen.BINDING).read_bytes(), b'old binding\n')
        self.assertEqual(list((self.root / '.tmp').iterdir()), [])

    def test_cancel_during_second_atomic_rename_restores_both_existing_outputs(self):
        binding = self.root / regen.BINDING
        requirements = self.root / regen.REQUIREMENTS
        staging = self.root / '.tmp' / 'replacement'
        staging.mkdir()
        outputs = {
            regen.BINDING: b'new binding\n',
            regen.REQUIREMENTS: b'protobuf==3.21.12\nother==1\n',
        }
        original_replace = Path.replace

        def replace(path, target):
            if path.name == 'replacement-1':
                raise KeyboardInterrupt
            if path.name.startswith('restore-'):
                # A second terminal interrupt during rollback must be ignored.
                signal.raise_signal(signal.SIGINT)
            return original_replace(path, target)

        with mock.patch.object(Path, 'replace', autospec=True, side_effect=replace):
            with self.assertRaises(KeyboardInterrupt):
                regen.replace_outputs(outputs, staging)

        self.assertEqual(binding.read_bytes(), b'old binding\n')
        self.assertEqual(requirements.read_bytes(), b'protobuf==3.19.3\nother==1\n')

    def test_cancel_reports_when_rollback_cannot_restore_a_replaced_output(self):
        binding = self.root / regen.BINDING
        requirements = self.root / regen.REQUIREMENTS
        staging = self.root / '.tmp' / 'replacement-failure'
        staging.mkdir()
        outputs = {
            regen.BINDING: b'new binding\n',
            regen.REQUIREMENTS: b'protobuf==3.21.12\nother==1\n',
        }
        original_replace = Path.replace

        def replace(path, target):
            if path.name == 'replacement-1':
                raise KeyboardInterrupt
            if path.name.startswith('restore-'):
                raise OSError('restore fixture failure')
            return original_replace(path, target)

        stderr = io.StringIO()
        with mock.patch.object(Path, 'replace', autospec=True, side_effect=replace), \
                redirect_stderr(stderr):
            with self.assertRaises(KeyboardInterrupt):
                regen.replace_outputs(outputs, staging)

        self.assertIn('rollback did not fully restore', stderr.getvalue())
        self.assertNotEqual(binding.read_bytes(), b'old binding\n')

    def test_cleanup_failure_during_cancellation_preserves_status_130(self):
        staging = self.root / '.tmp' / 'cleanup-failure'

        class Temporary:
            name = str(staging)

            def __init__(self, *args, **kwargs):
                staging.mkdir()

            def cleanup(self):
                raise OSError('cleanup fixture failure')

        with mock.patch.object(regen.tempfile, 'TemporaryDirectory', Temporary), \
                mock.patch.object(regen, 'run_command', side_effect=[
                    'libprotoc 3.21.12', KeyboardInterrupt(),
                ]):
            stderr = self.run_cancelled()

        self.assertIn('could not clean temporary protobuf staging', stderr)


if __name__ == '__main__':
    unittest.main()
