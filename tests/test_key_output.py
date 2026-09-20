"""Focused tests for metadata-labelled, collision-safe key output."""

import importlib
import logging
import os
from datetime import datetime as real_datetime
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from Crypto.PublicKey import RSA

from Helpers import DeviceSelection
from Helpers.DeviceSelection import get_android_api_level
from Helpers.wv_proto2_pb2 import ClientIdentification


device_module = importlib.import_module('Helpers.Device')
Device = device_module.Device


class KeyOutputTests(unittest.TestCase):
    """Use synthetic protobufs and keys in a managed temporary output root."""

    @classmethod
    def setUpClass(cls):
        cls.key = RSA.generate(1024)
        cls.other_key = RSA.generate(1024)

    def setUp(self):
        self.tempdir = tempfile.TemporaryDirectory(prefix='dumper-key-output-')
        self.root = Path(self.tempdir.name) / 'key_dumps'
        self.output_patch = mock.patch.object(device_module, 'KEY_DUMPS_ROOT', str(self.root))
        self.output_patch.start()
        self.addCleanup(self.output_patch.stop)

    def tearDown(self):
        self.tempdir.cleanup()

    @staticmethod
    def client(version=None, versions=None):
        client_id = ClientIdentification()
        client_id.Type = ClientIdentification.KEYBOX
        if versions is None and version is not None:
            versions = [version]
        for value in versions or []:
            client_id.ClientInfo.add(Name='widevine_cdm_version', Value=value)
        return client_id

    @staticmethod
    def device(name='Pixel 8', api_level='28'):
        device = Device.__new__(Device)
        device.logger = logging.getLogger('test.key_output')
        device.name = name
        device.android_api_level = api_level
        device._saved_pair_paths = {}
        return device

    def test_layout_uses_client_metadata_and_api_instead_of_manual_layout(self):
        device = self.device(api_level=28)
        path = Path(device.export_key(self.key, self.client('14.0.0')))

        self.assertEqual(
            path.relative_to(self.root).parts,
            ('Pixel 8', 'private_keys', 'CDM 14.0.0 - API 28'),
        )
        self.assertEqual(path.joinpath('client_id.bin').read_bytes(), self.client('14.0.0').SerializeToString())
        self.assertEqual(path.joinpath('private_key.pem').read_bytes(), self.key.export_key())

        # A layout argument such as --cdm-version is not present on this output
        # object and cannot override the version embedded in ClientInfo.
        device.cdm_version = '14.0.0'
        second = Path(device.export_key(self.key, self.client('16.0.0')))
        self.assertIn('CDM 16.0.0 - API 28', second.name)

    def test_success_log_uses_repository_relative_timestamped_path(self):
        client_id = self.client('14.0.0')
        # Keep the fixture outside the checkout while making its temporary
        # parent act as the module's repository root for the display contract.
        with mock.patch.object(device_module, 'REPOSITORY_ROOT', self.tempdir.name):
            first = self.device().export_key(self.key, client_id)
            with self.assertLogs('test.key_output', level='INFO') as logs:
                second = self.device().export_key(self.key, client_id)

        relative = Path(second).relative_to(Path(self.tempdir.name)).as_posix()
        self.assertEqual(relative, f'key_dumps/Pixel 8/private_keys/{Path(second).name}')
        self.assertTrue(Path(second).name.startswith('CDM 14.0.0 - API 28 ('))
        self.assertNotEqual(first, second)
        self.assertIn(f'Key pairs saved at {relative}', logs.output[-1])

    def test_exact_pair_reuses_path_only_within_one_device_run(self):
        client_id = self.client('14.0.0')
        device = self.device()

        first = device.export_key(self.key, client_id)
        second = device.export_key(self.key, client_id)

        self.assertEqual(first, second)
        self.assertEqual(len(list(self.root.joinpath('Pixel 8', 'private_keys').iterdir())), 1)

    def test_new_run_same_pair_gets_timestamped_sibling(self):
        client_id = self.client('14.0.0')
        first = self.device().export_key(self.key, client_id)
        second = self.device().export_key(self.key, client_id)

        self.assertNotEqual(first, second)
        self.assertRegex(Path(second).name, r'^CDM 14\.0\.0 - API 28 \(\d{4}-\d{2}-\d{2} \d{2}-\d{2}-\d{2}')
        self.assertEqual(Path(first, 'client_id.bin').read_bytes(), client_id.SerializeToString())

    def test_different_pair_preserves_previous_pair(self):
        device = self.device()
        first_client = self.client('14.0.0')
        first = Path(device.export_key(self.key, first_client))
        second = Path(device.export_key(self.other_key, first_client))

        self.assertNotEqual(first, second)
        self.assertIn('CDM 14.0.0 - API 28', second.name)
        self.assertEqual(first.joinpath('private_key.pem').read_bytes(), self.key.export_key())
        self.assertEqual(second.joinpath('private_key.pem').read_bytes(), self.other_key.export_key())

    def test_modified_cached_pair_is_preserved_and_saved_again(self):
        client_id = self.client('14.0.0')
        device = self.device()
        first = Path(device.export_key(self.key, client_id))
        (first / 'private_key.pem').write_bytes(b'changed')

        second = Path(device.export_key(self.key, client_id))

        self.assertNotEqual(first, second)
        self.assertEqual((first / 'private_key.pem').read_bytes(), b'changed')
        self.assertEqual((second / 'private_key.pem').read_bytes(), self.key.export_key())

    def test_write_failure_does_not_cache_incomplete_pair(self):
        client_id = self.client('14.0.0')
        device = self.device()
        with self.assertLogs('test.key_output', level='INFO') as logs:
            with mock.patch.object(
                device_module, '_write_exclusive', side_effect=[None, OSError('write failed')]
            ):
                self.assertIsNone(device.export_key(self.key, client_id))

        self.assertFalse(any('Key pairs saved at' in line for line in logs.output))

        output = Path(device.export_key(self.key, client_id))
        self.assertEqual((output / 'client_id.bin').read_bytes(), client_id.SerializeToString())
        self.assertEqual((output / 'private_key.pem').read_bytes(), self.key.export_key())

    def test_incomplete_existing_base_is_preserved(self):
        base = self.root / 'Pixel 8' / 'private_keys' / 'CDM 14.0.0 - API 28'
        base.mkdir(parents=True)
        (base / 'client_id.bin').write_bytes(b'old client')

        output = Path(self.device().export_key(self.key, self.client('14.0.0')))

        self.assertNotEqual(output, base)
        self.assertEqual((base / 'client_id.bin').read_bytes(), b'old client')
        self.assertTrue((output / 'private_key.pem').exists())

    def test_existing_pair_from_previous_run_is_not_deduplicated(self):
        client_id = self.client('14.0.0')
        base = self.root / 'Pixel 8' / 'private_keys' / 'CDM 14.0.0 - API 28'
        base.mkdir(parents=True)
        (base / 'client_id.bin').write_bytes(client_id.SerializeToString())
        (base / 'private_key.pem').write_bytes(self.key.export_key())

        output = Path(self.device().export_key(self.key, client_id))

        self.assertNotEqual(output, base)
        self.assertEqual((base / 'private_key.pem').read_bytes(), self.key.export_key())

    def test_missing_blank_and_conflicting_versions_use_unknown(self):
        for client_id in (
            self.client(),
            self.client(versions=['']),
            self.client(versions=['14.0.0', '15.0.0']),
        ):
            with self.subTest(client_id=client_id):
                output = Path(self.device().export_key(self.key, client_id))
                self.assertIn('CDM unknown - API 28', output.name)

    def test_unsafe_and_reserved_names_stay_contained(self):
        device = self.device('../CON<>:"/\\|?*\x01 trailing. ')
        output = Path(device.export_key(self.key, self.client('CON.txt')))

        self.assertEqual(output.parent.parent.parent, self.root)
        self.assertTrue(output.joinpath('client_id.bin').is_file())
        for component in output.relative_to(self.root).parts:
            self.assertNotIn('/', component)
            self.assertNotIn('\\', component)
            self.assertNotIn('\x01', component)
            self.assertNotIn(component.upper().split('.', 1)[0], {'CON', 'PRN', 'AUX', 'NUL'})

    def test_same_second_timestamp_uses_progressing_suffix(self):
        client_id = self.client('14.0.0')
        base = self.root / 'Pixel 8' / 'private_keys' / 'CDM 14.0.0 - API 28'
        timestamped = base.with_name('CDM 14.0.0 - API 28 (2026-09-20 15-45-30)')
        base.mkdir(parents=True)
        timestamped.mkdir(parents=True)

        class FrozenDatetime:
            @classmethod
            def now(cls):
                return real_datetime(2026, 9, 20, 15, 45, 30)

        with mock.patch.object(device_module, 'datetime', FrozenDatetime):
            output = Path(self.device().export_key(self.key, client_id))

        self.assertIn('(2026-09-20 15-45-30.000001)', output.name)
        self.assertEqual(list(timestamped.iterdir()), [])

    def test_long_multibyte_metadata_preserves_api_label_and_byte_limit(self):
        output = Path(self.device(name='装置' * 100).export_key(self.key, self.client('版本' * 100)))

        self.assertTrue(output.name.startswith('CDM '))
        self.assertTrue(output.name.endswith(' - API 28'))
        for component in output.relative_to(self.root).parts:
            self.assertLessEqual(len(component.encode('utf-8')), 120)

    def test_malformed_unicode_metadata_is_sanitized_before_saving(self):
        client = mock.Mock()
        client.ClientInfo = [mock.Mock(Name='widevine_cdm_version', Value='14.\ud800')]
        client.SerializeToString.return_value = b'synthetic client ID'
        output = Path(self.device(name='Pixel\ud800').export_key(self.key, client))

        self.assertEqual(output.parent.parent.name, 'Pixel_')
        self.assertEqual(output.name, 'CDM 14._ - API 28')

    def test_preexisting_symlink_candidate_is_skipped(self):
        base = self.root / 'Pixel 8' / 'private_keys' / 'CDM 14.0.0 - API 28'
        base.parent.mkdir(parents=True)
        try:
            base.symlink_to(self.root)
        except (OSError, NotImplementedError) as error:
            self.skipTest(f'This host does not permit symlink creation: {error}')

        output = Path(self.device().export_key(self.key, self.client('14.0.0')))

        self.assertNotEqual(output, base)
        self.assertTrue(output.joinpath('private_key.pem').is_file())

    def test_binary_io_preserves_newlines_and_control_z_on_windows(self):
        # Simulate Windows CRT text mode on any test host. A missing binary flag
        # would alter protobuf bytes or treat an embedded Ctrl-Z as end-of-file.
        payload = b'\x00\n\r\n\x1a\xff'
        output = Path(self.tempdir.name) / 'binary-payload.bin'
        real_open, real_write, real_read = os.open, os.write, os.read
        native_binary = getattr(os, 'O_BINARY', 0)
        binary_flag = native_binary or (1 << 29)
        binary_descriptors = {}

        def crt_open(path, flags, *args):
            descriptor = real_open(path, (flags & ~binary_flag) | native_binary, *args)
            binary_descriptors[descriptor] = bool(flags & binary_flag)
            return descriptor

        def crt_write(descriptor, data):
            value = bytes(data)
            if not binary_descriptors[descriptor]:
                value = value.replace(b'\n', b'\r\n')
            real_write(descriptor, value)
            return len(data)

        def crt_read(descriptor, count):
            value = real_read(descriptor, count)
            if not binary_descriptors[descriptor]:
                value = value.split(b'\x1a', 1)[0].replace(b'\r\n', b'\n')
            return value

        with mock.patch.object(os, 'O_BINARY', binary_flag, create=True), \
                mock.patch.object(os, 'open', side_effect=crt_open), \
                mock.patch.object(os, 'write', side_effect=crt_write), \
                mock.patch.object(os, 'read', side_effect=crt_read):
            device_module._write_exclusive(output, payload)
            reread = device_module._read_regular_file(output, len(payload))

        self.assertEqual(output.read_bytes(), payload)
        self.assertEqual(reread, payload)


class AndroidApiMetadataTests(unittest.TestCase):
    def test_positive_integer_and_ascii_decimal_string_are_normalised(self):
        device = mock.Mock(id='android-1', name='Pixel')
        for value, expected in ((28, '28'), ('28', '28'), ('028', '28')):
            with self.subTest(value=value), mock.patch.object(
                DeviceSelection, '_query_system_parameters', return_value={'api-level': value}
            ) as query:
                self.assertEqual(get_android_api_level(device), expected)
                query.assert_called_once_with(device)

    def test_missing_and_malformed_api_metadata_use_unknown(self):
        device = mock.Mock(id='android-1', name='Pixel')
        for parameters in ({}, {'api-level': 0}, {'api-level': -1}, {'api-level': True},
                            {'api-level': False}, {'api-level': 28.0}, {'api-level': ''},
                            {'api-level': ' 28'}, {'api-level': '28 '}, {'api-level': '２８'},
                            None):
            with self.subTest(parameters=parameters), mock.patch.object(
                DeviceSelection, '_query_system_parameters', return_value=parameters
            ):
                self.assertEqual(get_android_api_level(device), 'unknown')

    def test_query_error_uses_unknown_but_keyboard_interrupt_propagates(self):
        device = mock.Mock(id='android-1', name='Pixel')
        with mock.patch.object(DeviceSelection, '_query_system_parameters', side_effect=RuntimeError('offline')):
            self.assertEqual(get_android_api_level(device), 'unknown')
        with mock.patch.object(DeviceSelection, '_query_system_parameters', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                get_android_api_level(device)

    def test_device_constructor_fetches_api_once_after_selection(self):
        selected = mock.Mock(name='selected-device')
        selected.name = 'Pixel'
        with mock.patch.object(device_module, 'select_android_device', return_value=selected) as select, \
                mock.patch.object(device_module, 'get_android_api_level', return_value='33') as api_level, \
                mock.patch('builtins.open', mock.mock_open(read_data='agent')):
            device = Device('', '14.0.0', ['libwvaidl.so'], 'android-1')

        select.assert_called_once_with('android-1')
        api_level.assert_called_once_with(selected)
        self.assertEqual(device.android_api_level, '33')


if __name__ == '__main__':
    unittest.main()
