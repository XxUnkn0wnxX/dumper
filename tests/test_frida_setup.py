import hashlib
from contextlib import ExitStack
from http.client import IncompleteRead
import io
import json
import lzma
from pathlib import Path
import shlex
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from tools import setup_frida as setup


# ---------------------------------------------------------------------------
# TEST FIXTURES
# These fixtures emulate process results and HTTP bodies only.  The suite never
# contacts GitHub, an ADB daemon, or an Android device.
# ---------------------------------------------------------------------------
class Completed:
    def __init__(self, stdout='', stderr='', returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class HttpBody:
    def __init__(self, payload, headers=None):
        self.payload = io.BytesIO(payload)
        self.headers = headers or {}

    def read(self, size=-1):
        return self.payload.read(size)

    def __enter__(self):
        return self

    def __exit__(self, *unused):
        return False


class TtyBuffer(io.StringIO):
    """A controllable stream that passes the command's interactive TTY guard."""

    def isatty(self):
        return True


def elf(architecture='x86_64'):
    """Return a minimal ELF header with the selected class and machine number."""
    details = setup.ARCHITECTURES[architecture]
    header = bytearray(20)
    header[:4] = b'\x7fELF'
    header[4] = details['elf_class']
    header[5] = 1  # EI_DATA: little-endian, required by Android ELF binaries.
    header[18:20] = details['machine'].to_bytes(2, 'little')
    return bytes(header) + b'frida-test-payload'


def release_document(version='17.18.0', architecture='x86_64', *, digest=None):
    tag = version
    asset = f'frida-server-{version}-android-{architecture}.xz'
    return {
        'tag_name': tag,
        'draft': False,
        'prerelease': False,
        'assets': [{
            'name': asset,
            'size': 123,
            'digest': digest,
            'browser_download_url': f'https://github.com/frida/frida/releases/download/{tag}/{asset}',
        }],
    }


def store_cached_archive(cache_root, version, architecture):
    """Create a fully validated cache fixture without involving the network."""
    payload = lzma.compress(elf(architecture))
    asset_name = f'frida-server-{version}-android-{architecture}.xz'
    archive = cache_root / asset_name
    archive.write_bytes(payload)
    archive_hash = hashlib.sha256(payload).hexdigest()
    manifest = {
        'version': version,
        'architecture': architecture,
        'asset_name': asset_name,
        'archive_size': len(payload),
        'archive_sha256': archive_hash,
        'upstream_sha256': archive_hash,
    }
    (cache_root / f'{asset_name}.json').write_text(json.dumps(manifest), encoding='utf-8')
    return setup.Release(version, version, asset_name, 'https://example.invalid/server.xz', len(payload), archive_hash), payload


# ---------------------------------------------------------------------------
# ADB TARGET SELECTION
# Offline and unauthorized rows are deliberately not candidates.  Explicit
# selection must also reject a row that is present but not online.
# ---------------------------------------------------------------------------
class DeviceSelectionTests(unittest.TestCase):
    def test_single_online_device_is_selected_and_offline_is_ignored(self):
        devices = [
            setup.AndroidDevice('offline-serial', 'offline', ''),
            setup.AndroidDevice('emulator-5554', 'device', 'product:sdk'),
        ]
        self.assertEqual(setup.select_device(devices, None).serial, 'emulator-5554')

    def test_unauthorized_or_offline_devices_are_rejected(self):
        for state in ('offline', 'unauthorized'):
            with self.subTest(state=state):
                devices = [setup.AndroidDevice('phone', state, '')]
                with self.assertRaisesRegex(setup.SetupError, 'No online Android device'):
                    setup.select_device(devices, None)
                with self.assertRaisesRegex(setup.SetupError, state):
                    setup.select_device(devices, 'phone')

    def test_multiple_and_missing_explicit_selection_are_actionable(self):
        devices = [
            setup.AndroidDevice('one', 'device', ''),
            setup.AndroidDevice('two', 'device', ''),
        ]
        with self.assertRaisesRegex(setup.SetupError, '--device-id SERIAL'):
            setup.select_device(devices, None)
        with self.assertRaisesRegex(setup.SetupError, 'was not reported'):
            setup.select_device(devices, 'missing')

    def test_adb_parser_retains_all_reported_states(self):
        output = '''List of devices attached
emulator-5554\tdevice product:sdk model:sdk_gphone
phone\toffline transport_id:4
unknown\tunauthorized usb:1-1
'''
        with mock.patch.object(setup, 'command_output', return_value=Completed(stdout=output)):
            rows = setup.list_adb_devices('/adb')
        self.assertEqual([(row.serial, row.state) for row in rows], [
            ('emulator-5554', 'device'), ('phone', 'offline'), ('unknown', 'unauthorized'),
        ])


# ---------------------------------------------------------------------------
# TARGET AND ROOT PREFLIGHT
# These tests prove that an ABI mismatch ends before any release or upload work,
# and that every supported root mechanism remains explicit and verifiable.
# ---------------------------------------------------------------------------
class TargetAndRootTests(unittest.TestCase):
    def test_abi_mismatch_refuses_before_mutation(self):
        calls = []

        def properties(*args, **kwargs):
            calls.append(args)
            return Completed(stdout='34\n' if args[-1] == 'ro.build.version.sdk' else 'arm64-v8a\n')

        with mock.patch.object(setup, 'adb_command', side_effect=properties):
            with self.assertRaisesRegex(setup.SetupError, '--arch arm64'):
                setup.validate_target('/adb', 'device', 'x86_64')
        self.assertEqual(len(calls), 2)
        self.assertTrue(all('push' not in call for call in calls))

    def test_auto_architecture_maps_primary_abi_and_explicit_arch_stays_exact(self):
        replies = [Completed(stdout='35\n'), Completed(stdout='arm64-v8a\n')]
        with mock.patch.object(setup, 'adb_command', side_effect=replies):
            self.assertEqual(
                setup.validate_target('/adb', 'serial', 'auto'),
                (35, 'arm64-v8a', 'arm64'),
            )
        replies = [Completed(stdout='35\n'), Completed(stdout='arm64-v8a\n')]
        with mock.patch.object(setup, 'adb_command', side_effect=replies):
            self.assertEqual(
                setup.validate_target('/adb', 'serial', 'arm64'),
                (35, 'arm64-v8a', 'arm64'),
            )

    def test_root_probes_support_direct_su_and_su_zero_forms(self):
        cases = (
            ('direct', [Completed(stdout='0\n')]),
            ('su-c', [Completed(stdout='2000\n'), Completed(stdout='0\n')]),
            ('su-0', [Completed(stdout='2000\n'), Completed(stdout='2000\n'), Completed(stdout='0\n')]),
        )
        for expected, replies in cases:
            with self.subTest(expected=expected), \
                mock.patch.object(setup, 'adb_command', side_effect=replies) as adb:
                self.assertEqual(setup.probe_root('/adb', 'serial'), expected)
                self.assertEqual(adb.call_args_list[0].args[2], 'shell')
                self.assertIn('id -u', adb.call_args_list[0].args[3])

    def test_root_command_keeps_each_c_argument_as_one_remote_shell_word(self):
        command = 'cd /data/local/tmp && exec /system/bin/sh -i'
        self.assertEqual(shlex.split(setup.root_command('direct', command)[1]), ['sh', '-c', command])
        self.assertEqual(shlex.split(setup.root_command('su-c', command)[1]), ['su', '-c', command])
        self.assertEqual(shlex.split(setup.root_command('su-0', command)[1]), ['su', '0', 'sh', '-c', command])

    def test_adb_root_is_checked_after_waiting_for_reconnect(self):
        replies = [
            Completed(stdout='2000\n'), Completed(stdout='2000\n'), Completed(stdout='2000\n'),
            Completed(stdout='restarting adbd as root\n'), Completed(), Completed(stdout='0\n'),
        ]
        with mock.patch.object(setup, 'adb_command', side_effect=replies) as adb:
            self.assertEqual(setup.probe_root('/adb', 'serial'), 'direct')
        commands = [call.args[2:] for call in adb.call_args_list]
        self.assertIn(('root',), commands)
        self.assertIn(('wait-for-device',), commands)

    def test_root_denial_stops_before_upload(self):
        replies = [Completed(stdout='2000\n')] * 3 + [Completed(returncode=1)]
        with mock.patch.object(setup, 'adb_command', side_effect=replies):
            with self.assertRaisesRegex(setup.SetupError, 'Root access is required'):
                setup.probe_root('/adb', 'serial')

    def test_existing_root_probe_returns_none_when_probes_fail(self):
        with mock.patch.object(
            setup, 'adb_command', side_effect=setup.SetupError('adb transport closed'),
        ) as adb:
            self.assertIsNone(setup.probe_existing_root('/adb', 'serial'))
        self.assertEqual(adb.call_count, 3)


# ---------------------------------------------------------------------------
# RELEASE AND LOCAL ARCHIVE VALIDATION
# The fixture release metadata follows the official GitHub URL shape.  Download
# checks exercise content size/digest/XZ/ELF handling without a real network.
# ---------------------------------------------------------------------------
class ReleaseAndArchiveTests(unittest.TestCase):
    def test_latest_and_pinned_versions_choose_the_exact_asset(self):
        document = release_document()
        with mock.patch.object(setup, 'fetch_json', return_value=document) as fetch:
            latest = setup.release_for(None, 'x86_64')
        self.assertEqual(latest.version, '17.18.0')
        self.assertTrue(fetch.call_args.args[0].endswith('/latest'))
        with mock.patch.object(setup, 'fetch_json', return_value=release_document('16.3.3')) as fetch:
            pinned = setup.release_for('v16.3.3', 'x86_64')
        self.assertEqual(pinned.asset_name, 'frida-server-16.3.3-android-x86_64.xz')
        self.assertTrue(fetch.call_args.args[0].endswith('/tags/16.3.3'))

    def test_bad_version_missing_asset_and_unofficial_url_are_rejected(self):
        with self.assertRaisesRegex(setup.SetupError, 'exact X.Y.Z'):
            setup.release_for('latest', 'x86_64')
        with mock.patch.object(setup, 'fetch_json', return_value={'tag_name': '17.18.0', 'assets': []}):
            with self.assertRaisesRegex(setup.SetupError, 'has no Android'):
                setup.release_for(None, 'x86_64')
        document = release_document()
        document['assets'][0]['browser_download_url'] = 'https://example.invalid/server.xz'
        with mock.patch.object(setup, 'fetch_json', return_value=document):
            with self.assertRaisesRegex(setup.SetupError, 'official Frida'):
                setup.release_for(None, 'x86_64')

    def test_truncated_release_api_response_is_reported_cleanly(self):
        with mock.patch.object(setup, 'urlopen', side_effect=IncompleteRead(b'{', 10)):
            with self.assertRaisesRegex(setup.SetupError, 'GitHub release lookup failed'):
                setup.fetch_json('https://api.github.com/repos/frida/frida/releases/latest')

    def test_connection_reset_release_api_response_is_reported_cleanly(self):
        with mock.patch.object(setup, 'urlopen', side_effect=ConnectionResetError('connection reset')):
            with self.assertRaisesRegex(setup.SetupError, 'GitHub release lookup failed'):
                setup.fetch_json('https://api.github.com/repos/frida/frida/releases/latest')

    def test_download_digest_xz_and_elf_validation(self):
        payload = lzma.compress(elf())
        digest = hashlib.sha256(payload).hexdigest()
        release = setup.Release('17.18.0', '17.18.0', 'server.xz', 'https://example.invalid', len(payload), digest)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            archive = folder / 'server.xz'
            server = folder / 'frida-server'
            with mock.patch.object(setup, 'urlopen', return_value=HttpBody(payload, {'Content-Length': str(len(payload))})):
                setup.download_asset(release, archive)
            setup.unpack_xz(archive, server)
            setup.validate_elf(server, 'x86_64')

    def test_bad_digest_invalid_xz_and_wrong_elf_are_rejected_before_push(self):
        payload = b'not an xz archive'
        release = setup.Release('17.18.0', '17.18.0', 'server.xz', 'https://example.invalid', len(payload), '0' * 64)
        with tempfile.TemporaryDirectory() as temporary:
            folder = Path(temporary)
            archive = folder / 'server.xz'
            with mock.patch.object(setup, 'urlopen', return_value=HttpBody(payload)):
                with self.assertRaisesRegex(setup.SetupError, 'SHA-256'):
                    setup.download_asset(release, archive)
            archive.write_bytes(payload)
            with self.assertRaisesRegex(setup.SetupError, 'Extracting'):
                setup.unpack_xz(archive, folder / 'frida-server')
            wrong = folder / 'wrong-server'
            wrong.write_bytes(elf('arm64'))
            with self.assertRaisesRegex(setup.SetupError, 'does not match'):
                setup.validate_elf(wrong, 'x86_64')


# ---------------------------------------------------------------------------
# ARCHIVE CACHE
# Cache fixtures contain only compressed synthetic ELF files and manifests. They
# prove selection behavior without network access or any Android interaction.
# ---------------------------------------------------------------------------
class ArchiveCacheTests(unittest.TestCase):
    def test_pinned_cache_hit_uses_zero_network_and_materializes_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            cache_root.mkdir()
            store_cached_archive(cache_root, '16.3.3', 'x86_64')
            destination = Path(temporary) / 'frida-server'
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'release_for') as release:
                artifact = setup.select_server_artifact('16.3.3', 'x86_64', destination)
            self.assertEqual(artifact.version, '16.3.3')
            self.assertTrue(destination.exists())
        release.assert_not_called()

    def test_latest_checks_metadata_then_uses_matching_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            cache_root.mkdir()
            release, _payload = store_cached_archive(cache_root, '17.18.0', 'x86_64')
            destination = Path(temporary) / 'frida-server'
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'release_for', return_value=release) as lookup, \
                    mock.patch.object(setup, 'cache_release') as download:
                artifact = setup.select_server_artifact(None, 'x86_64', destination)
        self.assertEqual(artifact.version, '17.18.0')
        lookup.assert_called_once_with(None, 'x86_64')
        download.assert_not_called()

    def test_latest_metadata_or_download_failure_uses_highest_valid_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            cache_root.mkdir()
            store_cached_archive(cache_root, '16.3.3', 'x86_64')
            latest, _payload = store_cached_archive(cache_root, '17.0.0', 'x86_64')
            destination = Path(temporary) / 'metadata-fallback-server'
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'release_for', side_effect=setup.SetupError('offline')):
                artifact = setup.select_server_artifact(None, 'x86_64', destination)
            self.assertEqual(artifact.version, '17.0.0')

            destination = Path(temporary) / 'download-fallback-server'
            newer = setup.Release('18.0.0', '18.0.0', 'frida-server-18.0.0-android-x86_64.xz', 'https://example.invalid/new.xz', 1, None)
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'release_for', return_value=newer), \
                    mock.patch.object(setup, 'cache_release', side_effect=setup.SetupError('timeout')):
                artifact = setup.select_server_artifact(None, 'x86_64', destination)
            self.assertEqual(artifact.version, latest.version)

    def test_empty_offline_cache_stops_without_materializing_binary(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            destination = Path(temporary) / 'frida-server'
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'release_for', side_effect=setup.SetupError('offline')):
                with self.assertRaisesRegex(setup.SetupError, 'No valid cached'):
                    setup.select_server_artifact(None, 'x86_64', destination)
            self.assertFalse(destination.exists())

    def test_corrupt_pinned_cache_refreshes_exactly_once_and_publishes_atomically(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            cache_root.mkdir()
            release, payload = store_cached_archive(cache_root, '16.3.3', 'x86_64')
            (cache_root / release.asset_name).write_bytes(b'corrupt')
            destination = Path(temporary) / 'frida-server'

            def download(_release, target):
                target.write_bytes(payload)

            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'release_for', return_value=release) as lookup, \
                    mock.patch.object(setup, 'download_asset', side_effect=download) as download_mock:
                artifact = setup.select_server_artifact('16.3.3', 'x86_64', destination)
            self.assertEqual(artifact.version, '16.3.3')
            self.assertTrue(destination.exists())
            self.assertEqual(list(cache_root.glob('download-*')), [])
        lookup.assert_called_once_with('16.3.3', 'x86_64')
        download_mock.assert_called_once()

    def test_cache_architectures_are_separate_and_partial_download_is_not_published(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            cache_root.mkdir()
            store_cached_archive(cache_root, '17.18.0', 'x86_64')
            store_cached_archive(cache_root, '17.18.0', 'arm64')
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root):
                self.assertEqual([entry.architecture for entry in setup.cached_artifacts('arm64')], ['arm64'])
                failed_release = setup.Release('18.0.0', '18.0.0', 'frida-server-18.0.0-android-arm64.xz', 'https://example.invalid/new.xz', 1, None)
                with mock.patch.object(setup, 'download_asset', side_effect=setup.SetupError('network interrupted')):
                    with self.assertRaisesRegex(setup.SetupError, 'network interrupted'):
                        setup.cache_release(failed_release, 'arm64')
            self.assertFalse((cache_root / failed_release.asset_name).exists())
            self.assertFalse((cache_root / f'{failed_release.asset_name}.json').exists())

    def test_latest_metadata_mismatch_refreshes_and_newer_latest_wins_over_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            cache_root.mkdir()
            old_release, _old_payload = store_cached_archive(cache_root, '17.18.0', 'x86_64')
            fresh_payload = lzma.compress(elf('x86_64') + b'new-build')
            latest = setup.Release(
                '18.0.0', '18.0.0', 'frida-server-18.0.0-android-x86_64.xz',
                'https://example.invalid/latest.xz', len(fresh_payload), hashlib.sha256(fresh_payload).hexdigest(),
            )

            def download(_release, target):
                target.write_bytes(fresh_payload)

            destination = Path(temporary) / 'frida-server'
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'release_for', return_value=latest), \
                    mock.patch.object(setup, 'download_asset', side_effect=download) as refresh:
                artifact = setup.select_server_artifact(None, 'x86_64', destination)
            self.assertEqual(artifact.version, '18.0.0')
            self.assertTrue((cache_root / latest.asset_name).exists())
            self.assertNotEqual(old_release.asset_name, latest.asset_name)
        refresh.assert_called_once()

    def test_same_asset_metadata_mismatch_is_excluded_after_failed_refresh(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            cache_root.mkdir()
            store_cached_archive(cache_root, '16.3.3', 'x86_64')
            current, _payload = store_cached_archive(cache_root, '17.18.0', 'x86_64')
            # This is the same asset name but fresh GitHub metadata says the
            # cached bytes are stale. A failed replacement must not reuse it.
            fresh_metadata = setup.Release(
                current.version, current.tag, current.asset_name, current.url,
                current.size + 1, 'f' * 64,
            )
            destination = Path(temporary) / 'frida-server'
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'release_for', return_value=fresh_metadata), \
                    mock.patch.object(setup, 'cache_release', side_effect=setup.SetupError('refresh failed')):
                artifact = setup.select_server_artifact(None, 'x86_64', destination)
            self.assertEqual(artifact.version, '16.3.3')
            self.assertTrue(destination.exists())

    def test_manifest_upstream_hash_must_match_local_archive_hash(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            cache_root.mkdir()
            release, _payload = store_cached_archive(cache_root, '17.18.0', 'x86_64')
            manifest_path = cache_root / f'{release.asset_name}.json'
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            manifest['upstream_sha256'] = 'f' * 64
            manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root):
                with self.assertRaisesRegex(setup.CacheError, 'does not match'):
                    setup.load_cached_artifact(release.asset_name, 'x86_64')

    def test_corrupt_xz_or_elf_cache_is_skipped_by_offline_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            cache_root.mkdir()
            store_cached_archive(cache_root, '17.0.0', 'x86_64')
            broken_release, _payload = store_cached_archive(cache_root, '18.0.0', 'x86_64')
            broken_payload = lzma.compress(b'not-an-elf')
            broken_archive = cache_root / broken_release.asset_name
            broken_archive.write_bytes(broken_payload)
            manifest_path = cache_root / f'{broken_release.asset_name}.json'
            manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
            manifest['archive_size'] = len(broken_payload)
            manifest['archive_sha256'] = hashlib.sha256(broken_payload).hexdigest()
            manifest['upstream_sha256'] = manifest['archive_sha256']
            manifest_path.write_text(json.dumps(manifest), encoding='utf-8')
            destination = Path(temporary) / 'frida-server'
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'release_for', side_effect=setup.SetupError('offline')):
                artifact = setup.select_server_artifact(None, 'x86_64', destination)
            self.assertEqual(artifact.version, '17.0.0')
            self.assertTrue(destination.exists())

    def test_pinned_missing_or_corrupt_version_never_falls_back_to_another_cache(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            cache_root.mkdir()
            store_cached_archive(cache_root, '17.18.0', 'x86_64')
            destination = Path(temporary) / 'frida-server'
            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'release_for', side_effect=setup.SetupError('pinned lookup failed')):
                with self.assertRaisesRegex(setup.SetupError, 'pinned lookup failed'):
                    setup.select_server_artifact('16.3.3', 'x86_64', destination)
            self.assertFalse(destination.exists())

    def test_validated_cache_is_retained_when_deployment_fails(self):
        with tempfile.TemporaryDirectory() as temporary:
            cache_root = Path(temporary) / 'cache'
            tmp_root = Path(temporary) / '.tmp'
            payload = lzma.compress(elf('x86_64'))
            release = setup.Release(
                '17.18.0', '17.18.0', 'frida-server-17.18.0-android-x86_64.xz',
                'https://example.invalid/server.xz', len(payload), hashlib.sha256(payload).hexdigest(),
            )
            device = setup.AndroidDevice('emulator-5554', 'device', '')

            def download(_release, target):
                target.write_bytes(payload)

            with mock.patch.object(setup, 'CACHE_ROOT', cache_root), \
                    mock.patch.object(setup, 'TMP_ROOT', tmp_root), \
                    mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                    mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                    mock.patch.object(setup, 'validate_target', return_value=(34, 'x86_64', 'x86_64')), \
                    mock.patch.object(setup, 'probe_root', return_value='direct'), \
                    mock.patch.object(setup, 'release_for', return_value=release), \
                    mock.patch.object(setup, 'download_asset', side_effect=download), \
                    mock.patch.object(setup, 'warn_frida_version'), \
                    mock.patch.object(setup, 'install_server', side_effect=setup.SetupError('remote install failed')):
                self.assertEqual(setup.main(['--no-shell']), 1)
            self.assertTrue((cache_root / release.asset_name).exists())
            self.assertTrue((cache_root / f'{release.asset_name}.json').exists())


# ---------------------------------------------------------------------------
# INSTALL, MANAGED PROCESS, AND OPERATOR SHELL
# The mocked ADB calls make ordering and process identity inspectable.  Existing
# servers are stopped only after candidate validation, and only when /proc/PID/
# exe identifies the exact managed path.
# ---------------------------------------------------------------------------
class InstallAndShellTests(unittest.TestCase):
    def test_install_validates_candidate_before_stopping_and_atomically_replaces(self):
        with tempfile.TemporaryDirectory() as temporary:
            server = Path(temporary) / 'frida-server'
            server.write_bytes(elf())
            with mock.patch.object(setup, 'adb_command', return_value=Completed()) as adb, \
                    mock.patch.object(setup, 'run_root', side_effect=[Completed(stdout='17.18.0\n'), Completed(), Completed()]) as root, \
                    mock.patch.object(setup, 'stop_managed_servers') as stop, \
                    mock.patch.object(setup, 'managed_server_pids', return_value=[]):
                setup.install_server('/adb', 'serial', 'su-c', server, '17.18.0', staging_name='/data/local/tmp/.frida-server-test')
        upload = adb.call_args_list[0]
        self.assertEqual(upload.args[2:4], ('push', str(server)))
        self.assertEqual(upload.args[4], '/data/local/tmp/.frida-server-test')
        scripts = [call.args[3] for call in root.call_args_list]
        self.assertTrue(any('--version' in script for script in scripts))
        self.assertIn("/data/local/tmp/.frida-server-test --version", scripts[0])
        stop.assert_called_once_with('/adb', 'serial', 'su-c')
        self.assertIn('test -f /data/local/tmp/frida-server', scripts[-1])
        self.assertIn("test '!' -e /data/local/tmp/frida-server", scripts[-1])
        self.assertIn('/proc/[0-9]*', scripts[-1])
        self.assertIn('(deleted)', scripts[-1])
        self.assertIn("mv /data/local/tmp/.frida-server-test /data/local/tmp/frida-server", scripts[-1])

    def test_special_destination_rejects_before_stopping_or_moving(self):
        with tempfile.TemporaryDirectory() as temporary:
            server = Path(temporary) / 'frida-server'
            server.write_bytes(elf())
            with mock.patch.object(setup, 'adb_command', return_value=Completed()), \
                    mock.patch.object(
                        setup, 'run_root',
                        side_effect=[Completed(stdout='17.18.0\n'), setup.SetupError('destination is special'), Completed()],
                    ) as root, \
                    mock.patch.object(setup, 'stop_managed_servers') as stop:
                with self.assertRaisesRegex(setup.SetupError, 'destination is special'):
                    setup.install_server('/adb', 'serial', 'direct', server, '17.18.0', staging_name='/data/local/tmp/.frida-server-special')
        stop.assert_not_called()
        commands = [call.args[3] for call in root.call_args_list]
        self.assertFalse(any(' mv ' in command for command in commands))

    def test_failed_preinstall_removes_only_its_staging_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            server = Path(temporary) / 'frida-server'
            server.write_bytes(elf())
            with mock.patch.object(setup, 'adb_command', return_value=Completed()), \
                    mock.patch.object(setup, 'run_root', side_effect=[setup.SetupError('version failed'), Completed()]) as root:
                with self.assertRaisesRegex(setup.SetupError, 'version failed'):
                    setup.install_server('/adb', 'serial', 'direct', server, '17.18.0', staging_name='/data/local/tmp/.frida-server-owned')
        cleanup = root.call_args_list[-1]
        self.assertIn('rm /data/local/tmp/.frida-server-owned', cleanup.args[3])
        self.assertNotIn(setup.REMOTE_SERVER, cleanup.args[3])

    def test_managed_process_discovery_and_stop_are_narrow_and_graceful(self):
        with mock.patch.object(setup, 'run_root', return_value=Completed(stdout='42\n77\n')) as root:
            self.assertEqual(setup.managed_server_pids('/adb', 'serial', 'direct'), ['42', '77'])
        listing = root.call_args.args[3]
        self.assertIn('/proc/[0-9]*', listing)
        self.assertIn(setup.REMOTE_SERVER, listing)
        self.assertIn('(deleted)', listing)
        self.assertNotIn('pkill', listing)
        self.assertNotIn('killall', listing)

        with mock.patch.object(setup, 'run_root', return_value=Completed()) as root:
            setup.terminate_managed_pid('/adb', 'serial', 'su-c', '42')
        command = root.call_args.args[3]
        self.assertIn('/proc/42/exe', command)
        self.assertIn('kill -TERM 42', command)
        self.assertNotIn('kill -KILL', command)

        with mock.patch.object(setup, 'managed_server_pids', side_effect=[['42'], []]), \
                mock.patch.object(setup, 'terminate_managed_pid') as terminate:
            setup.stop_managed_servers('/adb', 'serial', 'direct')
        terminate.assert_called_once_with('/adb', 'serial', 'direct', '42')

    def test_stop_timeout_does_not_force_kill_or_replace(self):
        with mock.patch.object(setup, 'managed_server_pids', return_value=['42']), \
                mock.patch.object(setup, 'terminate_managed_pid') as terminate, \
                mock.patch.object(setup.time, 'monotonic', side_effect=[0, 10]), \
                mock.patch.object(setup.time, 'sleep') as sleep:
            with self.assertRaisesRegex(setup.SetupError, 'did not stop after SIGTERM'):
                setup.stop_managed_servers('/adb', 'serial', 'direct', timeout=10)
        terminate.assert_called_once()
        sleep.assert_not_called()

    def test_existing_server_prepare_handles_missing_orphan_and_foreground_restart(self):
        with mock.patch.object(setup, 'managed_server_pids', return_value=[]), \
                mock.patch.object(setup, 'existing_server_state', return_value='missing'):
            self.assertEqual(setup.prepare_existing_server('/adb', 'serial', 'direct'), 'missing')

        with mock.patch.object(setup, 'managed_server_pids', return_value=['71']), \
                mock.patch.object(setup, 'existing_server_state', return_value='missing'), \
                mock.patch.object(setup, 'stop_managed_servers') as stop:
            self.assertEqual(setup.prepare_existing_server('/adb', 'serial', 'direct'), 'orphan')
        stop.assert_not_called()

        with mock.patch.object(setup, 'managed_server_pids', side_effect=[['71'], []]), \
                mock.patch.object(setup, 'existing_server_state', return_value='executable'), \
                mock.patch.object(setup, 'validate_existing_server', return_value='17.18.0') as validate, \
                mock.patch.object(setup, 'stop_managed_servers') as stop:
            self.assertEqual(setup.prepare_existing_server('/adb', 'serial', 'direct'), 'ready')
        validate.assert_called_once_with('/adb', 'serial', 'direct')
        stop.assert_called_once_with('/adb', 'serial', 'direct')

        for state_name, message in (
            ('symlink', 'symlink'), ('directory', 'directory'), ('non-executable', 'not executable'),
            ('special', 'not a regular'),
        ):
            with self.subTest(state=state_name), \
                    mock.patch.object(setup, 'managed_server_pids', return_value=[]), \
                    mock.patch.object(setup, 'existing_server_state', return_value=state_name):
                with self.assertRaisesRegex(setup.SetupError, message):
                    setup.prepare_existing_server('/adb', 'serial', 'direct')

    def test_foreground_command_and_terminal_routing_do_not_daemonize_or_time_out(self):
        interactive = setup.foreground_server_command(True)
        self.assertIn('/proc/[0-9]*', interactive)
        self.assertIn("trap ':' INT", interactive)
        self.assertIn('exec /system/bin/sh -i', interactive)
        self.assertIn('./frida-server', interactive)
        self.assertNotIn('--daemonize', interactive)
        noninteractive = setup.foreground_server_command(False)
        self.assertIn('exec ./frida-server', noninteractive)
        self.assertNotIn('exec /system/bin/sh -i', noninteractive)

        with mock.patch.object(setup, 'handoff_to_adb') as handoff, \
                mock.patch.object(setup.sys, 'stdin', TtyBuffer()), \
                mock.patch.object(setup.sys, 'stdout', TtyBuffer()):
            self.assertIsNone(setup.run_foreground_server('/adb', 'serial', 'su-0', interactive=True))
        argv = handoff.call_args.args[0]
        self.assertEqual(argv[:5], ['/adb', '-s', 'serial', 'shell', '-t'])
        self.assertIn("su 0 sh -c", argv[-1])
        self.assertEqual(handoff.call_args.args[1], 'Running foreground Frida server failed')

        non_tty = mock.Mock(isatty=mock.Mock(return_value=False))
        with mock.patch.object(setup, 'handoff_to_adb') as handoff, \
                mock.patch.object(setup.sys, 'stdin', non_tty), \
                mock.patch.object(setup.sys, 'stdout', non_tty):
            self.assertIsNone(setup.run_foreground_server('/adb', 'serial', 'direct', interactive=False))
        self.assertEqual(handoff.call_args.args[0][4], '-T')

        with mock.patch.object(setup, 'handoff_to_adb') as handoff, \
                mock.patch.object(setup.sys, 'stdin', TtyBuffer()), \
                mock.patch.object(setup.sys, 'stdout', TtyBuffer()):
            self.assertIsNone(setup.run_foreground_server('/adb', 'serial', 'direct', interactive=False))
        self.assertEqual(handoff.call_args.args[0][4], '-t')

    def test_handoff_flushes_streams_and_reports_exec_failure(self):
        events = []

        class FlushRecorder:
            def flush(self):
                events.append(self.name)

        stdout = FlushRecorder()
        stdout.name = 'stdout'
        stderr = FlushRecorder()
        stderr.name = 'stderr'

        def fail_exec(path, argv):
            events.append('execv')
            raise OSError('exec denied')

        with mock.patch.object(setup.sys, 'platform', 'darwin'), \
                mock.patch.object(setup.sys, 'stdout', stdout), \
                mock.patch.object(setup.sys, 'stderr', stderr), \
                mock.patch.object(setup.os, 'execv', side_effect=fail_exec) as execv:
            with self.assertRaisesRegex(setup.SetupError, 'foreground ADB handoff'):
                setup.handoff_to_adb(['/adb', '-s', 'serial'], 'foreground ADB handoff')
        self.assertEqual(events, ['stdout', 'stderr', 'execv'])
        execv.assert_called_once_with('/adb', ['/adb', '-s', 'serial'])

    def test_windows_handoff_waits_and_exits_with_adb_status_without_execv(self):
        argv = ['/adb.exe', '-s', 'serial', 'shell', '-t', 'sh -c true']
        for returncode in (0, 7, 130):
            with self.subTest(returncode=returncode), \
                    mock.patch.object(setup.sys, 'platform', 'win32'), \
                    mock.patch.object(setup.sys, 'stdout', mock.Mock()), \
                    mock.patch.object(setup.sys, 'stderr', mock.Mock()), \
                    mock.patch.object(
                        setup.subprocess,
                        'run',
                        return_value=Completed(returncode=returncode),
                    ) as run, \
                    mock.patch.object(setup.os, 'execv') as execv:
                with self.assertRaises(SystemExit) as exit_error:
                    setup.handoff_to_adb(argv, 'Windows ADB handoff')
            self.assertEqual(exit_error.exception.code, returncode)
            run.assert_called_once_with(argv, check=False)
            execv.assert_not_called()

    def test_windows_handoff_reports_adb_startup_failure(self):
        argv = ['/adb.exe', '-s', 'serial', 'shell', '-t', 'sh -c true']
        with mock.patch.object(setup.sys, 'platform', 'win32'), \
                mock.patch.object(setup.sys, 'stdout', mock.Mock()), \
                mock.patch.object(setup.sys, 'stderr', mock.Mock()), \
                mock.patch.object(
                    setup.subprocess,
                    'run',
                    side_effect=OSError('adb startup failed'),
                ) as run, \
                mock.patch.object(setup.os, 'execv') as execv:
            with self.assertRaisesRegex(setup.SetupError, 'Windows ADB handoff: adb startup failed'):
                setup.handoff_to_adb(argv, 'Windows ADB handoff')
        run.assert_called_once_with(argv, check=False)
        execv.assert_not_called()

    def test_windows_handoff_maps_ctrl_c_to_status_130_without_execv(self):
        argv = ['/adb.exe', '-s', 'serial', 'shell', '-t', 'sh -c true']
        with mock.patch.object(setup.sys, 'platform', 'win32'), \
                mock.patch.object(setup.sys, 'stdout', mock.Mock()), \
                mock.patch.object(setup.sys, 'stderr', mock.Mock()), \
                mock.patch.object(setup.subprocess, 'run', side_effect=KeyboardInterrupt) as run, \
                mock.patch.object(setup.os, 'execv') as execv:
            with self.assertRaises(SystemExit) as exit_error:
                setup.handoff_to_adb(argv, 'Windows ADB handoff')
        self.assertEqual(exit_error.exception.code, 130)
        run.assert_called_once_with(argv, check=False)
        execv.assert_not_called()

    def test_existing_server_requires_a_real_version(self):
        with mock.patch.object(setup, 'run_root', return_value=Completed(stdout='17.18.0\n')):
            self.assertEqual(setup.validate_existing_server('/adb', 'serial', 'direct'), '17.18.0')
        with mock.patch.object(setup, 'run_root', return_value=Completed(stdout='not-frida\n')):
            with self.assertRaisesRegex(setup.SetupError, 'invalid version'):
                setup.validate_existing_server('/adb', 'serial', 'direct')

    def test_device_shell_elevates_before_chdir_and_does_not_start_server(self):
        for root_mode, elevation in (('su-c', 'su -c'), ('su-0', 'su 0 sh -c')):
            with self.subTest(root_mode=root_mode), \
                    mock.patch.object(setup, 'handoff_to_adb') as handoff:
                self.assertIsNone(setup.open_device_shell('/adb', 'serial', root_mode))
            argv = handoff.call_args.args[0]
            self.assertEqual(argv[:5], ['/adb', '-s', 'serial', 'shell', '-t'])
            self.assertIn(elevation, argv[-1])
            self.assertIn('cd /data/local/tmp', argv[-1])
            self.assertIn('exec /system/bin/sh -i', argv[-1])
            self.assertNotIn('./frida-server', argv[-1])
            self.assertEqual(handoff.call_args.args[1], 'Opening interactive Android shell failed')


# ---------------------------------------------------------------------------
# HOST FALLBACKS AND NONINTERACTIVE GUARD
# An optional adbutils binary is only located, never imported.  Default mode is
# prevented from deploying and then hanging when it has no controlling terminal.
# ---------------------------------------------------------------------------
class HostSafetyTests(unittest.TestCase):
    def test_adbutils_binary_is_a_last_resort(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'adb'
            binary.write_bytes(b'test')
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            distribution = mock.Mock()
            distribution.locate_file.return_value = binary
            with mock.patch.object(setup.shutil, 'which', return_value=None), \
                    mock.patch.object(setup.metadata, 'distribution', return_value=distribution):
                self.assertEqual(setup.resolve_adb(None), str(binary.resolve()))

    def test_path_adb_wins_without_inspecting_adbutils(self):
        with mock.patch.object(setup.shutil, 'which', return_value='/path/adb') as which, \
                mock.patch.object(setup.metadata, 'distribution', side_effect=AssertionError('fallback inspected')):
            self.assertEqual(setup.resolve_adb(None), '/path/adb')
        which.assert_called_once_with('adb')

    def test_adbutils_fallback_uses_the_host_appropriate_bundled_binary(self):
        for platform_name, name in (
            ('darwin', 'adb'), ('linux', 'adb'), ('win32', 'adb.exe'),
        ):
            with self.subTest(platform=platform_name):
                with tempfile.TemporaryDirectory() as temporary:
                    binary = Path(temporary) / name
                    binary.write_bytes(b'test')
                    if platform_name != 'win32':
                        binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
                    distribution = mock.Mock()
                    distribution.locate_file.return_value = binary
                    with mock.patch.object(setup.sys, 'platform', platform_name), \
                            mock.patch.object(setup.shutil, 'which', return_value=None), \
                            mock.patch.object(setup.metadata, 'distribution', return_value=distribution):
                        self.assertEqual(setup.resolve_adb(None), str(binary.resolve()))
                    distribution.locate_file.assert_called_once_with(f'adbutils/binaries/{name}')

    def test_missing_adb_reports_the_optional_fallback_install_path(self):
        with mock.patch.object(setup.shutil, 'which', return_value=None), \
                mock.patch.object(
                    setup.metadata,
                    'distribution',
                    side_effect=setup.metadata.PackageNotFoundError('adbutils'),
                ):
            with self.assertRaisesRegex(setup.SetupError, r'Android Debug Bridge.*requirements-adb\.txt'):
                setup.resolve_adb(None)

    def test_present_adbutils_without_a_matching_binary_reports_the_install_path(self):
        distribution = mock.Mock()
        distribution.locate_file.return_value = Path('/missing/adb')
        with mock.patch.object(setup.shutil, 'which', return_value=None), \
                mock.patch.object(setup.metadata, 'distribution', return_value=distribution):
            with self.assertRaisesRegex(setup.SetupError, r'Android Debug Bridge.*requirements-adb\.txt'):
                setup.resolve_adb(None)
        name = 'adb.exe' if setup.sys.platform.startswith('win') else 'adb'
        distribution.locate_file.assert_called_once_with(f'adbutils/binaries/{name}')

    def test_explicit_adb_path_wins_or_fails_without_fallback(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / 'custom-adb'
            binary.write_bytes(b'test')
            binary.chmod(binary.stat().st_mode | stat.S_IXUSR)
            with mock.patch.object(setup.shutil, 'which') as which, \
                    mock.patch.object(setup.metadata, 'distribution', side_effect=AssertionError('fallback inspected')):
                self.assertEqual(setup.resolve_adb(str(binary)), str(binary.resolve()))
            which.assert_not_called()

            missing = Path(temporary) / 'missing-adb'
            with mock.patch.object(setup.shutil, 'which', side_effect=AssertionError('fallback inspected')), \
                    mock.patch.object(setup.metadata, 'distribution', side_effect=AssertionError('fallback inspected')):
                with self.assertRaisesRegex(setup.SetupError, '--adb path is not an executable file'):
                    setup.resolve_adb(str(missing))

    def test_default_mode_requires_tty_before_any_adb_lookup(self):
        fake_stdin = mock.Mock(isatty=mock.Mock(return_value=False))
        fake_stdout = mock.Mock(isatty=mock.Mock(return_value=False))
        with mock.patch.object(setup.sys, 'stdin', fake_stdin), \
                mock.patch.object(setup.sys, 'stdout', fake_stdout), \
                mock.patch.object(setup, 'resolve_adb') as resolve:
            with self.assertRaises(SystemExit) as exit_error:
                setup.main([])
        self.assertEqual(exit_error.exception.code, 2)
        resolve.assert_not_called()

    def test_main_requires_an_online_device_before_any_runtime_or_release_work(self):
        modes = ((), ('--no-shell',), ('--ver', '16.3.3'), ('--shell',))
        cases = (
            ('no devices', [], None, 'No online Android device'),
            (
                'offline',
                [setup.AndroidDevice('offline', 'offline', '')],
                None,
                'No online Android device',
            ),
            (
                'unauthorized',
                [setup.AndroidDevice('phone', 'unauthorized', '')],
                None,
                'No online Android device',
            ),
            (
                'mixed non-online',
                [
                    setup.AndroidDevice('offline', 'offline', ''),
                    setup.AndroidDevice('phone', 'unauthorized', ''),
                ],
                None,
                'No online Android device',
            ),
            (
                'explicit missing',
                [setup.AndroidDevice('other', 'device', '')],
                'missing',
                'was not reported',
            ),
            (
                'explicit offline',
                [setup.AndroidDevice('offline', 'offline', '')],
                'offline',
                "is 'offline'",
            ),
            (
                'ambiguous multiple',
                [
                    setup.AndroidDevice('one', 'device', ''),
                    setup.AndroidDevice('two', 'device', ''),
                ],
                None,
                'Multiple online Android devices',
            ),
        )
        for case_name, devices, requested, expected_error in cases:
            for mode in modes:
                arguments = list(mode)
                if requested is not None:
                    arguments.extend(('--device-id', requested))
                with self.subTest(case=case_name, mode=mode):
                    with tempfile.TemporaryDirectory() as temporary:
                        runtime_root = Path(temporary) / 'runtime'
                        with ExitStack() as stack:
                            stack.enter_context(mock.patch.object(setup, 'TMP_ROOT', runtime_root))
                            resolve = stack.enter_context(mock.patch.object(setup, 'resolve_adb', return_value='/adb'))
                            listing = stack.enter_context(mock.patch.object(setup, 'list_adb_devices', return_value=devices))
                            target = stack.enter_context(mock.patch.object(setup, 'validate_target'))
                            root = stack.enter_context(mock.patch.object(setup, 'probe_root'))
                            artifact = stack.enter_context(mock.patch.object(setup, 'select_server_artifact'))
                            release = stack.enter_context(mock.patch.object(setup, 'release_for'))
                            download = stack.enter_context(mock.patch.object(setup, 'download_asset'))
                            install = stack.enter_context(mock.patch.object(setup, 'install_server'))
                            prepare = stack.enter_context(mock.patch.object(setup, 'prepare_existing_server'))
                            validate = stack.enter_context(mock.patch.object(setup, 'validate_existing_server'))
                            foreground = stack.enter_context(mock.patch.object(setup, 'run_foreground_server'))
                            shell = stack.enter_context(mock.patch.object(setup, 'open_device_shell'))
                            warning = stack.enter_context(mock.patch.object(setup, 'warn_frida_version'))
                            temporary_directory = stack.enter_context(
                                mock.patch.object(setup.tempfile, 'TemporaryDirectory'),
                            )
                            stack.enter_context(mock.patch.object(setup.sys, 'stdin', TtyBuffer()))
                            stack.enter_context(mock.patch.object(setup.sys, 'stdout', TtyBuffer()))
                            stderr = stack.enter_context(mock.patch.object(setup.sys, 'stderr', io.StringIO()))
                            self.assertEqual(setup.main(arguments), 1)
                        self.assertFalse(runtime_root.exists())
                    self.assertIn(expected_error, stderr.getvalue())
                    resolve.assert_called_once_with(None)
                    listing.assert_called_once_with('/adb')
                    for operation in (
                        target, root, artifact, release, download, install,
                        prepare, validate, foreground, shell, warning,
                    ):
                        operation.assert_not_called()
                    temporary_directory.assert_not_called()

    def test_main_stops_on_abi_mismatch_before_release_or_upload(self):
        device = setup.AndroidDevice('serial', 'device', '')
        with mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                mock.patch.object(setup, 'validate_target', side_effect=setup.SetupError('ABI mismatch')), \
                mock.patch.object(setup, 'probe_root') as root, \
                mock.patch.object(setup, 'select_server_artifact') as select:
            self.assertEqual(setup.main(['--no-shell']), 1)
        root.assert_not_called()
        select.assert_not_called()

    def test_root_denial_after_read_only_preflight_does_not_download_or_install(self):
        device = setup.AndroidDevice('serial', 'device', '')
        with mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                mock.patch.object(setup, 'validate_target', return_value=(34, 'x86_64', 'x86_64')), \
                mock.patch.object(setup, 'probe_root', side_effect=setup.SetupError('root required')), \
                mock.patch.object(setup, 'select_server_artifact') as select, \
                mock.patch.object(setup, 'install_server') as install:
            self.assertEqual(setup.main(['--no-shell']), 1)
        select.assert_not_called()
        install.assert_not_called()

    def test_bad_version_fails_before_any_adb_operation(self):
        with mock.patch.object(setup, 'resolve_adb') as resolve:
            with self.assertRaises(SystemExit) as exit_error:
                setup.main(['--no-shell', '--ver', 'not-a-version'])
        self.assertEqual(exit_error.exception.code, 2)
        resolve.assert_not_called()

    def test_main_combines_device_arch_version_and_cleans_before_shell(self):
        artifact = setup.CachedArtifact(
            '16.3.3', 'arm64', 'frida-server-16.3.3-android-arm64.xz', Path('cached.xz'),
        )
        device = setup.AndroidDevice('phone', 'device', '')
        with tempfile.TemporaryDirectory() as temporary:
            tmp_root = Path(temporary) / '.tmp'

            def shell_after_cleanup(*_args, **_kwargs):
                self.assertEqual(list(tmp_root.glob('frida-*')), [])
                return 0

            with mock.patch.object(setup, 'TMP_ROOT', tmp_root), \
                    mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                    mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                    mock.patch.object(setup, 'validate_target', return_value=(35, 'arm64-v8a', 'arm64')) as target, \
                    mock.patch.object(setup, 'probe_root', return_value='su-c') as root, \
                    mock.patch.object(setup, 'select_server_artifact', return_value=artifact) as select, \
                    mock.patch.object(setup, 'warn_frida_version'), \
                    mock.patch.object(setup, 'install_server') as install, \
                    mock.patch.object(setup, 'run_foreground_server', side_effect=shell_after_cleanup) as foreground, \
                    mock.patch.object(setup.sys, 'stdin', TtyBuffer()), \
                    mock.patch.object(setup.sys, 'stdout', TtyBuffer()):
                self.assertEqual(setup.main(['--ver', '16.3.3', '--arch', 'arm64', '--device-id', 'phone']), 0)
        target.assert_called_once_with('/adb', 'phone', 'arm64')
        root.assert_called_once_with('/adb', 'phone')
        select.assert_called_once()
        self.assertEqual(select.call_args.args[:2], ('16.3.3', 'arm64'))
        install.assert_called_once()
        self.assertEqual(install.call_args.args[1:3], ('phone', 'su-c'))
        foreground.assert_called_once_with('/adb', 'phone', 'su-c', interactive=True)

    def test_main_default_arch_uses_detected_architecture_for_release(self):
        device = setup.AndroidDevice('emulator-5554', 'device', '')
        with mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                mock.patch.object(setup, 'validate_target', return_value=(34, 'x86', 'x86')) as target, \
                mock.patch.object(setup, 'probe_root', return_value='direct'), \
                mock.patch.object(setup, 'select_server_artifact', side_effect=setup.SetupError('stop after architecture')) as select:
            self.assertEqual(setup.main(['--no-shell']), 1)
        target.assert_called_once_with('/adb', 'emulator-5554', 'auto')
        select.assert_called_once()
        self.assertEqual(select.call_args.args[:2], (None, 'x86'))

    def test_no_shell_installs_and_starts_without_opening_a_shell(self):
        artifact = setup.CachedArtifact('17.18.0', 'x86_64', 'server.xz', Path('cached.xz'))
        device = setup.AndroidDevice('emulator-5554', 'device', '')
        with tempfile.TemporaryDirectory() as temporary:
            tmp_root = Path(temporary) / '.tmp'

            with mock.patch.object(setup, 'TMP_ROOT', tmp_root), \
                    mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                    mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                    mock.patch.object(setup, 'validate_target', return_value=(34, 'x86_64', 'x86_64')), \
                    mock.patch.object(setup, 'probe_root', return_value='direct'), \
                    mock.patch.object(setup, 'select_server_artifact', return_value=artifact), \
                    mock.patch.object(setup, 'warn_frida_version'), \
                    mock.patch.object(setup, 'install_server') as install, \
                    mock.patch.object(setup, 'run_foreground_server', return_value=7) as foreground, \
                    mock.patch.object(setup, 'open_device_shell') as shell:
                self.assertEqual(setup.main(['--no-shell']), 7)
        install.assert_called_once()
        foreground.assert_called_once_with('/adb', 'emulator-5554', 'direct', interactive=False)
        shell.assert_not_called()


# ---------------------------------------------------------------------------
# SHELL MODE
# Shell mode requires verified root because it can launch an existing server.
# It never downloads or replaces a binary, but it can reuse/start only this
# tool's exact managed path before handing the operator a root shell.
# ---------------------------------------------------------------------------
class ShellOnlyTests(unittest.TestCase):
    def test_shell_mode_stops_existing_server_and_restarts_it_foreground(self):
        devices = [
            setup.AndroidDevice('emulator-5554', 'device', ''),
            setup.AndroidDevice('phone', 'device', ''),
        ]
        with mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(setup, 'list_adb_devices', return_value=devices), \
                mock.patch.object(setup, 'probe_root', return_value='su-c') as root, \
                mock.patch.object(setup, 'prepare_existing_server', return_value='ready') as prepare, \
                mock.patch.object(setup, 'validate_existing_server', return_value='17.18.0'), \
                mock.patch.object(setup, 'run_foreground_server', return_value=9) as foreground, \
                mock.patch.object(setup, 'validate_target') as target, \
                mock.patch.object(setup, 'release_for') as release, \
                mock.patch.object(setup, 'download_asset') as download, \
                mock.patch.object(setup, 'install_server') as install, \
                mock.patch.object(setup.tempfile, 'TemporaryDirectory') as temporary, \
                mock.patch.object(setup.sys, 'stdin', TtyBuffer()), \
                mock.patch.object(setup.sys, 'stdout', TtyBuffer()):
            self.assertEqual(setup.main(['--shell', '--device-id', 'phone']), 9)
        root.assert_called_once_with('/adb', 'phone')
        prepare.assert_called_once_with('/adb', 'phone', 'su-c')
        foreground.assert_called_once_with('/adb', 'phone', 'su-c', interactive=True)
        target.assert_not_called()
        release.assert_not_called()
        download.assert_not_called()
        install.assert_not_called()
        temporary.assert_not_called()

    def test_shell_mode_missing_server_opens_root_shell_without_starting_one(self):
        device = setup.AndroidDevice('phone', 'device', '')
        with mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                mock.patch.object(setup, 'probe_root', return_value='direct'), \
                mock.patch.object(setup, 'prepare_existing_server', return_value='missing') as prepare, \
                mock.patch.object(setup, 'open_device_shell', return_value=0) as shell, \
                mock.patch.object(setup.sys, 'stdin', TtyBuffer()), \
                mock.patch.object(setup.sys, 'stdout', TtyBuffer()):
            self.assertEqual(setup.main(['--shell']), 0)
        prepare.assert_called_once_with('/adb', 'phone', 'direct')
        shell.assert_called_once_with('/adb', 'phone', 'direct')

    def test_shell_mode_orphan_server_opens_root_shell_without_stopping_it(self):
        device = setup.AndroidDevice('emulator-5554', 'device', '')
        with mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                mock.patch.object(setup, 'probe_root', return_value='direct'), \
                mock.patch.object(setup, 'prepare_existing_server', return_value='orphan') as prepare, \
                mock.patch.object(setup, 'open_device_shell', return_value=0) as shell, \
                mock.patch.object(setup.sys, 'stdin', TtyBuffer()), \
                mock.patch.object(setup.sys, 'stdout', TtyBuffer()):
            self.assertEqual(setup.main(['--shell']), 0)
        prepare.assert_called_once_with('/adb', 'emulator-5554', 'direct')
        shell.assert_called_once_with('/adb', 'emulator-5554', 'direct')

    def test_shell_mode_root_denial_has_no_server_or_install_side_effects(self):
        device = setup.AndroidDevice('phone', 'device', '')
        with mock.patch.object(setup, 'resolve_adb', return_value='/adb'), \
                mock.patch.object(setup, 'list_adb_devices', return_value=[device]), \
                mock.patch.object(setup, 'probe_root', side_effect=setup.SetupError('root guidance')) as root, \
                mock.patch.object(setup, 'prepare_existing_server') as prepare, \
                mock.patch.object(setup, 'open_device_shell') as shell, \
                mock.patch.object(setup, 'validate_target') as target, \
                mock.patch.object(setup, 'release_for') as release, \
                mock.patch.object(setup, 'install_server') as install, \
                mock.patch.object(setup.sys, 'stdin', TtyBuffer()), \
                mock.patch.object(setup.sys, 'stdout', TtyBuffer()):
            self.assertEqual(setup.main(['--shell']), 1)
        root.assert_called_once_with('/adb', 'phone')
        prepare.assert_not_called()
        shell.assert_not_called()
        target.assert_not_called()
        release.assert_not_called()
        install.assert_not_called()

    def test_shell_mode_rejects_install_options_before_adb_lookup(self):
        invalid = (
            ['--shell', '--ver', '16.3.3'],
            ['--shell', '--arch', 'arm64'],
            ['--shell', '--no-shell'],
        )
        for arguments in invalid:
            with self.subTest(arguments=arguments), \
                    mock.patch.object(setup, 'resolve_adb') as resolve:
                with self.assertRaises(SystemExit) as exit_error:
                    setup.main(arguments)
            self.assertEqual(exit_error.exception.code, 2)
            resolve.assert_not_called()

    def test_root_shell_starts_in_the_shared_directory_without_frida_command(self):
        with mock.patch.object(setup, 'handoff_to_adb') as handoff:
            self.assertIsNone(setup.open_device_shell('/adb', 'phone', 'direct'))
        argv = handoff.call_args.args[0]
        self.assertEqual(argv[:5], ['/adb', '-s', 'phone', 'shell', '-t'])
        self.assertIn('cd /data/local/tmp', argv[-1])
        self.assertIn('exec /system/bin/sh -i', argv[-1])
        self.assertNotIn('frida-server', argv[-1])
        self.assertEqual(handoff.call_args.args[1], 'Opening interactive Android shell failed')


if __name__ == '__main__':
    unittest.main()
