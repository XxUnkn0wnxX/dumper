"""Preserve the dumper's protobuf contract when regenerating Python bindings."""

import hashlib
import json
import logging
from pathlib import Path
import unittest
from unittest import mock

from Crypto.PublicKey import RSA
from google.protobuf import descriptor_pb2

from Helpers.Device import Device
from Helpers import wv_proto2_pb2


# ------------------------------------------------------------------------------
# LEGACY WIRE FIXTURE
# Serialized with the original binding and protobuf 3.19.3 before the upgrade.
# All data is synthetic; the RSA public key has no associated device or service.
# Keep these bytes independent of the generated module being tested.
# ------------------------------------------------------------------------------
FIXTURE_PATH = Path(__file__).parent / 'fixtures' / 'protobuf_legacy.json'


class ProtobufCompatibilityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = json.loads(FIXTURE_PATH.read_text(encoding='utf-8'))
        cls.request_bytes = bytes.fromhex(cls.fixture['request_hex'])

    # Regenerating for a newer runtime must preserve every message, enum, field
    # number, type, and default. Only the schema's repository filename moved.
    def test_schema_matches_legacy_descriptor(self):
        schema = descriptor_pb2.FileDescriptorProto()
        wv_proto2_pb2.DESCRIPTOR.CopyToProto(schema)
        schema.ClearField('name')
        digest = hashlib.sha256(schema.SerializeToString(deterministic=True)).hexdigest()
        self.assertEqual(digest, self.fixture['schema_sha256_without_filename'])

    def test_legacy_request_round_trip_and_client_id(self):
        request = wv_proto2_pb2.SignedLicenseRequest.FromString(self.request_bytes)
        client = request.Msg.ClientId
        certificate = client.Token._DeviceCertificate

        self.assertTrue(request.IsInitialized(), request.FindInitializationErrors())
        self.assertEqual(request.Type, wv_proto2_pb2.SignedLicenseRequest.LICENSE_REQUEST)
        self.assertEqual(certificate.SystemId, self.fixture['system_id'])
        self.assertEqual(certificate.SerialNumber.decode(), self.fixture['serial_number'])
        self.assertEqual(client.ClientInfo[0].Value, self.fixture['model_name'])
        self.assertEqual(client.SerializeToString(deterministic=True).hex(), self.fixture['client_id_hex'])
        self.assertEqual(request.SerializeToString(deterministic=True), self.request_bytes)

    # Proto2 distinguishes an explicitly stored default from an absent field.
    # A newer runtime must also retain fields that this schema does not recognize.
    def test_presence_and_unknown_fields_survive_round_trip(self):
        wire = bytes.fromhex(self.fixture['request_with_unknown_field_hex'])
        request = wv_proto2_pb2.SignedLicenseRequest.FromString(wire)

        self.assertTrue(request.Msg.ClientId.HasField('LicenseCounter'))
        self.assertEqual(request.Msg.ClientId.LicenseCounter, 0)
        self.assertFalse(request.Msg.ClientId.HasField('ProviderClientToken'))
        self.assertEqual(request.SerializeToString(deterministic=True), wire)
        request.DiscardUnknownFields()
        self.assertEqual(request.SerializeToString(deterministic=True), self.request_bytes)

    # Exercise the real request handler using its cached-key lookup. Replace the
    # output method so this regression neither connects to Frida nor writes keys.
    def test_device_handler_matches_certificate_to_cached_key(self):
        request = wv_proto2_pb2.SignedLicenseRequest.FromString(self.request_bytes)
        public_key = RSA.import_key(request.Msg.ClientId.Token._DeviceCertificate.PublicKey)
        cached_private_key = mock.sentinel.cached_private_key
        device = Device.__new__(Device)
        device.logger = logging.getLogger('test.protobuf')
        device.saved_keys = {public_key.n: cached_private_key}
        device.export_key = mock.Mock()

        device.license_request_message(self.request_bytes)

        device.export_key.assert_called_once()
        key, client = device.export_key.call_args.args
        self.assertIs(key, cached_private_key)
        self.assertEqual(client.SerializeToString(deterministic=True).hex(), self.fixture['client_id_hex'])

        device.export_key.reset_mock()
        device.saved_keys.clear()
        device.license_request_message(self.request_bytes)
        device.export_key.assert_not_called()


if __name__ == '__main__':
    unittest.main()
