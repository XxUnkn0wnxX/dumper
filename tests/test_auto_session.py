"""Offline tests for the per-run full-auto status channel."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from Helpers import AutoSession as session


class AutoSessionTests(unittest.TestCase):
    """Keep status validation and event parsing isolated from real sessions."""

    @classmethod
    def setUpClass(cls):
        cls.repo_tmp = Path(__file__).resolve().parents[1] / '.tmp'
        cls.repo_tmp.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='auto-session-', dir=self.repo_tmp,
        )
        self.root = Path(self.temporary.name)
        self.addCleanup(self.temporary.cleanup)
        (self.root / '.tmp').mkdir()
        self.root_patch = mock.patch.object(session, 'ROOT', self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)
        self.environment = mock.patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    def owned_context(self, role='dumper'):
        directory = self.root / '.tmp' / 'session'
        directory.mkdir()
        token = 'a' * 32
        os.environ.update({
            'DUMPER_AUTO_DIRECTORY': str(directory),
            'DUMPER_AUTO_TOKEN': token,
            'DUMPER_AUTO_ROLE': role,
        })
        return directory, token

    def test_manual_process_has_no_context_and_emits_no_status_file(self):
        self.assertIsNone(session.context())
        self.assertFalse(session.emit_event('manual_probe', value='ignored'))
        self.assertEqual(list(self.root.rglob('*')), [self.root / '.tmp'])

    def test_context_accepts_owned_directory_and_marker_for_frida_role(self):
        directory, token = self.owned_context('frida')

        self.assertEqual(session.context(), (directory, token, 'frida'))
        self.assertEqual(
            session.frida_marker(),
            f'/data/local/tmp/.dumper-auto-{token}.pid',
        )
        self.assertEqual(session.marker_path(token), session.frida_marker())

    def test_context_rejects_missing_fields_bad_role_and_unowned_paths(self):
        cases = (
            {'DUMPER_AUTO_DIRECTORY': str(self.root / '.tmp' / 'missing'),
             'DUMPER_AUTO_TOKEN': 'a' * 32, 'DUMPER_AUTO_ROLE': 'dumper'},
            {'DUMPER_AUTO_DIRECTORY': str(self.root / '.tmp'),
             'DUMPER_AUTO_TOKEN': 'g' * 32, 'DUMPER_AUTO_ROLE': 'dumper'},
            {'DUMPER_AUTO_DIRECTORY': str(self.root / '.tmp'),
             'DUMPER_AUTO_TOKEN': 'a' * 32, 'DUMPER_AUTO_ROLE': 'other'},
        )
        for values in cases:
            with self.subTest(values=values):
                os.environ.update(values)
                with self.assertRaisesRegex(ValueError, '(Invalid full-auto session context|owned directory)'):
                    session.context()
                os.environ.clear()

        outside = self.root / 'outside'
        outside.mkdir()
        os.environ.update({
            'DUMPER_AUTO_DIRECTORY': str(outside),
            'DUMPER_AUTO_TOKEN': 'a' * 32,
            'DUMPER_AUTO_ROLE': 'dumper',
        })
        with self.assertRaisesRegex(ValueError, 'owned directory'):
            session.context()

    def test_context_rejects_symlinked_session_directory(self):
        target = self.root / 'real-session'
        target.mkdir()
        link = self.root / '.tmp' / 'session-link'
        link.symlink_to(target, target_is_directory=True)
        os.environ.update({
            'DUMPER_AUTO_DIRECTORY': str(link),
            'DUMPER_AUTO_TOKEN': 'a' * 32,
            'DUMPER_AUTO_ROLE': 'dumper',
        })

        with self.assertRaisesRegex(ValueError, 'owned directory'):
            session.context()

    def test_marker_path_rejects_non_hex_or_wrong_length_tokens(self):
        for token in ('', 'a' * 31, 'a' * 33, 'A' * 32, 'g' * 32):
            with self.subTest(token=token):
                with self.assertRaisesRegex(ValueError, 'session token'):
                    session.marker_path(token)

    def test_dumper_role_has_no_frida_marker(self):
        self.owned_context('dumper')
        self.assertIsNone(session.frida_marker())

    def test_emit_event_writes_complete_metadata_that_read_events_accepts(self):
        directory, token = self.owned_context('dumper')
        with mock.patch.object(session.time, 'time', return_value=123.5), \
                mock.patch.object(session.os, 'getpid', return_value=4321):
            self.assertTrue(session.emit_event(
                'hooks_ready', device_id='pixel', android_api='30', hooked_libraries=2,
            ))

        events_path = directory / 'dumper.events.jsonl'
        self.assertEqual(events_path.stat().st_mode & 0o777, 0o600)
        events = session.read_events(directory, token, 'dumper')
        self.assertEqual(events, [{
            'android_api': '30',
            'device_id': 'pixel',
            'event': 'hooks_ready',
            'hooked_libraries': 2,
            'pid': 4321,
            'role': 'dumper',
            'time': 123.5,
            'token': token,
        }])

    def test_emit_event_raises_session_error_when_owned_status_write_fails(self):
        self.owned_context('dumper')
        with mock.patch.object(session.os, 'open', side_effect=OSError('disk full')):
            with self.assertRaisesRegex(session.AutoSessionError, 'Could not notify full_auto.py'):
                session.emit_event('hooks_ready')

    def test_read_events_ignores_partial_final_line_for_retry(self):
        directory, token = self.owned_context('frida')
        complete = {
            'event': 'frida_launch', 'token': token, 'role': 'frida',
            'device_id': 'pixel', 'root_mode': 'direct',
        }
        path = directory / 'frida.events.jsonl'
        path.write_bytes(
            (json.dumps(complete) + '\n').encode('utf-8') + b'{"event":"partial"',
        )

        self.assertEqual(session.read_events(directory, token, 'frida'), [complete])

    def test_read_events_rejects_wrong_token_and_invalid_reader_context(self):
        directory, token = self.owned_context('dumper')
        path = directory / 'dumper.events.jsonl'
        path.write_text(json.dumps({
            'event': 'hooks_ready', 'token': 'b' * 32, 'role': 'dumper',
        }) + '\n', encoding='utf-8')
        with self.assertRaisesRegex(ValueError, 'different session'):
            session.read_events(directory, token, 'dumper')

        for bad_token, bad_role in (('x' * 32, 'dumper'), (token, 'other')):
            with self.subTest(bad_token=bad_token, bad_role=bad_role):
                with self.assertRaisesRegex(ValueError, 'Invalid full-auto event reader context'):
                    session.read_events(directory, bad_token, bad_role)


if __name__ == '__main__':
    unittest.main()
