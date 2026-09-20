"""Regression tests for RSA capture progress and delayed pair guidance."""

import json
import logging
from pathlib import Path
import unittest
from unittest import mock

from Crypto.PublicKey import RSA

from Helpers import Device as device_module
from Helpers.Device import Device
from Helpers.wv_proto2_pb2 import SignedLicenseRequest


class CaptureProgressTests(unittest.TestCase):
    """Keep delayed capture guidance deterministic and tied to real state."""

    @classmethod
    def setUpClass(cls):
        cls.private_key = RSA.generate(1024)
        fixture_path = Path(__file__).parent / 'fixtures' / 'protobuf_legacy.json'
        cls.request_bytes = bytes.fromhex(
            json.loads(fixture_path.read_text(encoding='utf-8'))['request_hex']
        )

    @staticmethod
    def device():
        device = Device.__new__(Device)
        device.logger = logging.getLogger('test.capture_progress')
        device.saved_keys = {}
        device._saved_pair_paths = {}
        return device

    @classmethod
    def request_with_versions(cls, *versions):
        request = SignedLicenseRequest.FromString(cls.request_bytes)
        del request.Msg.ClientId.ClientInfo[:]
        for version in versions:
            request.Msg.ClientId.ClientInfo.add(
                Name='widevine_cdm_version', Value=version
            )
        return request.SerializeToString()

    def test_client_version_is_logged_before_matching_or_saving(self):
        device = self.device()
        data = self.request_with_versions('15.0.0')
        device.export_key = mock.Mock()

        with self.assertLogs('test.capture_progress', level='INFO') as logs:
            device.license_request_message(data)

        self.assertTrue(any(
            'Client ID reports widevine_cdm_version: 15.0.0' in line
            for line in logs.output
        ))
        device.export_key.assert_not_called()

    def test_client_version_is_logged_even_when_matching_save_fails(self):
        device = self.device()
        data = self.request_with_versions('16.0.0')
        request = SignedLicenseRequest.FromString(data)
        public_key = RSA.import_key(
            request.Msg.ClientId.Token._DeviceCertificate.PublicKey
        )
        device.saved_keys = {public_key.n: mock.sentinel.private_key}
        device.export_key = mock.Mock(return_value=None)

        with self.assertLogs('test.capture_progress', level='INFO') as logs:
            device.license_request_message(data)

        self.assertTrue(any(
            'Client ID reports widevine_cdm_version: 16.0.0' in line
            for line in logs.output
        ))
        device.export_key.assert_called_once()

    def test_each_distinct_client_version_is_reported_once(self):
        device = self.device()
        first = self.request_with_versions('14.0.0')
        second = self.request_with_versions('14.0.0')
        third = self.request_with_versions('17.0.0')

        with self.assertLogs('test.capture_progress', level='INFO') as logs:
            device.license_request_message(first)
            device.license_request_message(second)
            device.license_request_message(third)

        version_lines = [
            line for line in logs.output
            if 'Client ID reports widevine_cdm_version:' in line
        ]
        self.assertEqual(len(version_lines), 2)
        self.assertIn('14.0.0', version_lines[0])
        self.assertIn('17.0.0', version_lines[1])

    def test_missing_or_ambiguous_client_version_is_not_reported_as_success(self):
        device = self.device()
        missing = self.request_with_versions()
        ambiguous = self.request_with_versions('14.0.0', '15.0.0')

        with self.assertLogs('test.capture_progress', level='INFO') as logs:
            device.license_request_message(missing)
            device.license_request_message(ambiguous)

        self.assertFalse(any(
            'Client ID reports widevine_cdm_version:' in line
            for line in logs.output
        ))
        self.assertTrue(any('missing or blank' in line for line in logs.output))
        self.assertTrue(any('conflicting' in line for line in logs.output))

    def test_no_ready_hooks_or_key_capture_never_warns(self):
        device = self.device()

        with mock.patch.object(device.logger, 'warning') as warning:
            self.assertFalse(device.warn_if_no_pair(now=35.0))

        warning.assert_not_called()

    def test_warning_waits_for_grace_period_and_is_emitted_once(self):
        device = self.device()
        with mock.patch.object(device_module.time, 'monotonic', return_value=100.0):
            device.on_message({'payload': 'private_key'}, self.private_key.export_key())

        with mock.patch.object(device.logger, 'warning') as warning:
            self.assertFalse(device.warn_if_no_pair(now=134.99))
            self.assertTrue(device.warn_if_no_pair(now=135.0))
            self.assertFalse(device.warn_if_no_pair(now=170.0))

        warning.assert_called_once()
        message = warning.call_args.args[0]
        self.assertIn('RSA keys received', message)
        self.assertIn('--cdm-version <layout>', message)
        self.assertIn('Missing output alone does not prove a mismatch', message)

    def test_ready_hooks_warn_once_after_35_seconds_even_without_rsa(self):
        device = self.device()
        device.start_capture_wait(now=100.0)
        # Repeated readiness cannot postpone the user's warning indefinitely.
        device.start_capture_wait(now=130.0)
        with mock.patch.object(device.logger, 'warning') as warning:
            self.assertFalse(device.warn_if_no_pair(now=134.99))
            self.assertTrue(device.warn_if_no_pair(now=135.0))
            self.assertFalse(device.warn_if_no_pair(now=170.0))
        warning.assert_called_once()
        self.assertIn('No matching client ID/key pair', warning.call_args.args[0])
        self.assertEqual(warning.call_args.args[1], 35.0)
        self.assertNotIn('--cdm-version', warning.call_args.args[0])

    def test_rsa_arrival_does_not_restart_the_ready_hooks_deadline(self):
        device = self.device()
        device.start_capture_wait(now=100.0)
        device._first_private_key_at = 132.0
        with mock.patch.object(device.logger, 'warning') as warning:
            self.assertFalse(device.warn_if_no_pair(now=134.99))
            self.assertTrue(device.warn_if_no_pair(now=135.0))
        self.assertIn('RSA keys received', warning.call_args.args[0])

    def test_successfully_saved_pair_suppresses_guidance(self):
        device = self.device()
        device._first_private_key_at = 100.0
        device._saved_pair_paths = {(b'client', b'private'): '/output'}

        with mock.patch.object(device_module, '_pair_matches', return_value=True), \
                mock.patch.object(device.logger, 'warning') as warning:
            self.assertFalse(device.warn_if_no_pair(now=135.0))

        warning.assert_not_called()

    def test_matching_save_failure_keeps_specific_warning_without_layout_hint(self):
        device = self.device()
        request = SignedLicenseRequest.FromString(self.request_bytes)
        public_key = RSA.import_key(
            request.Msg.ClientId.Token._DeviceCertificate.PublicKey
        )
        device.saved_keys = {public_key.n: mock.sentinel.private_key}
        device._first_private_key_at = 100.0

        def failed_export(*_args):
            device.logger.warning('Could not save key pair under key_dumps: write failed')
            return None

        device.export_key = mock.Mock(side_effect=failed_export)
        with self.assertLogs('test.capture_progress', level='WARNING') as logs:
            device.license_request_message(self.request_bytes)
            self.assertFalse(device.warn_if_no_pair(now=135.0))

        device.export_key.assert_called_once()
        self.assertTrue(any('Could not save key pair' in line for line in logs.output))
        self.assertFalse(any('--cdm-version <layout>' in line for line in logs.output))

    def test_rsa_debug_log_is_preserved_when_capture_starts(self):
        device = self.device()

        with mock.patch.object(device_module.time, 'monotonic', return_value=100.0), \
                self.assertLogs('test.capture_progress', level='DEBUG') as logs:
            device.on_message({'payload': 'private_key'}, self.private_key.export_key())

        self.assertTrue(any('Retrieved key:' in line for line in logs.output))
        self.assertTrue(any('BEGIN RSA PRIVATE KEY' in line for line in logs.output))
        self.assertEqual(device._first_private_key_at, 100.0)


if __name__ == '__main__':
    unittest.main()
