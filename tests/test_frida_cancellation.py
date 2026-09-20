"""Cancellation regressions for the Frida setup/download pipeline."""

from contextlib import ExitStack, redirect_stderr
import io
import json
import os
from pathlib import Path
import signal
import shlex
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from tools import setup_frida as setup


class Completed:
    def __init__(self, stdout='', stderr='', returncode=0):
        self.stdout = stdout
        self.stderr = stderr
        self.returncode = returncode


class FridaCancellationTests(unittest.TestCase):
    """Use only isolated .tmp fixtures; no ADB, network, or real downloads."""

    @classmethod
    def setUpClass(cls):
        cls.tmp_root = setup.ROOT / '.tmp'
        cls.tmp_root.mkdir(parents=True, exist_ok=True)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix='frida-cancel-', dir=self.tmp_root,
        )
        self.root = Path(self.temporary.name)
        self.cache = self.root / 'cache'
        self.scratch = self.root / 'scratch'
        self.cache.mkdir()
        self.scratch.mkdir()
        self.patches = mock.patch.multiple(
            setup,
            CACHE_ROOT=self.cache,
            TMP_ROOT=self.scratch,
        )
        self.patches.start()
        self.addCleanup(self.patches.stop)

    def tearDown(self):
        self.temporary.cleanup()

    def run_main_cancelled(self, *, patches=(), arguments=('--no-shell',)):
        stderr = io.StringIO()
        with ExitStack() as stack, redirect_stderr(stderr):
            stack.enter_context(mock.patch.object(setup, 'prepare_terminal'))
            for patcher in patches:
                stack.enter_context(patcher)
            result = setup.main(list(arguments))
        self.assertEqual(result, 130)
        self.assertIn('Cancelled.', stderr.getvalue())
        return stderr.getvalue()

    def base_main_patches(self):
        return [
            mock.patch.object(setup, 'resolve_adb', return_value='/adb'),
            mock.patch.object(
                setup, 'list_adb_devices',
                return_value=[setup.AndroidDevice('serial', 'device', '')],
            ),
            mock.patch.object(
                setup, 'validate_target', return_value=(34, 'x86_64', 'x86_64'),
            ),
            mock.patch.object(setup, 'probe_root', return_value='direct'),
        ]

    def test_cancel_at_main_preflight_stages_returns_130_without_later_work(self):
        stages = (
            ('resolve', [mock.patch.object(setup, 'resolve_adb', side_effect=KeyboardInterrupt)]),
            ('adb devices', [
                mock.patch.object(setup, 'resolve_adb', return_value='/adb'),
                mock.patch.object(setup, 'list_adb_devices', side_effect=KeyboardInterrupt),
            ]),
            ('target', [
                mock.patch.object(setup, 'resolve_adb', return_value='/adb'),
                mock.patch.object(setup, 'list_adb_devices', return_value=[setup.AndroidDevice('serial', 'device', '')]),
                mock.patch.object(setup, 'validate_target', side_effect=KeyboardInterrupt),
            ]),
            ('root', [
                *self.base_main_patches()[:3],
                mock.patch.object(setup, 'probe_root', side_effect=KeyboardInterrupt),
            ]),
            ('release/download', [
                *self.base_main_patches(),
                mock.patch.object(setup, 'select_server_artifact', side_effect=KeyboardInterrupt),
            ]),
        )
        for name, patches in stages:
            with self.subTest(stage=name):
                self.run_main_cancelled(patches=patches)

    def test_cancel_during_install_does_not_launch_or_retry(self):
        artifact = setup.CachedArtifact(
            '17.18.0', 'x86_64', 'frida-server-17.18.0-android-x86_64.xz',
            self.root / 'server.xz',
        )
        with mock.patch.object(setup, 'select_server_artifact', return_value=artifact), \
                mock.patch.object(setup, 'ensure_host_frida_version'), \
                mock.patch.object(setup, 'install_server', side_effect=KeyboardInterrupt), \
                mock.patch.object(setup, 'run_foreground_server') as launch:
            self.run_main_cancelled(patches=self.base_main_patches())
        launch.assert_not_called()

    def release(self):
        return setup.Release(
            '17.18.0', '17.18.0',
            'frida-server-17.18.0-android-x86_64.xz',
            'https://example.invalid/frida-server.xz', 4, None,
        )

    def write_existing_cache(self, release):
        archive = self.cache / release.asset_name
        manifest = self.cache / f'{release.asset_name}.json'
        archive.write_bytes(b'valid cached archive')
        manifest.write_text(json.dumps({'version': release.version}), encoding='utf-8')
        return archive.read_bytes(), manifest.read_bytes()

    def test_cancel_download_removes_fragment_and_preserves_existing_cache(self):
        release = self.release()
        archive_before, manifest_before = self.write_existing_cache(release)
        def partial_download(_release, destination):
            destination.write_bytes(b'partial archive before Ctrl+C')
            raise KeyboardInterrupt

        with mock.patch.object(setup, 'download_asset', side_effect=partial_download):
            with self.assertRaises(KeyboardInterrupt):
                setup.cache_release(release, 'x86_64')
        self.assertEqual((self.cache / release.asset_name).read_bytes(), archive_before)
        self.assertEqual((self.cache / f'{release.asset_name}.json').read_bytes(), manifest_before)
        self.assertEqual(list(self.cache.glob('download-*')), [])

    def test_cancel_after_local_artifact_before_upload_cleans_scratch_and_preserves_cache(self):
        release = self.release()
        archive_before, manifest_before = self.write_existing_cache(release)

        def materialize(_version, _architecture, destination):
            destination.write_bytes(b'validated extracted Frida server')
            return setup.CachedArtifact(
                release.version, 'x86_64', release.asset_name, self.cache / release.asset_name,
            )

        with mock.patch.object(setup, 'select_server_artifact', side_effect=materialize), \
                mock.patch.object(setup, 'ensure_host_frida_version', side_effect=KeyboardInterrupt), \
                mock.patch.object(setup, 'install_server') as install, \
                mock.patch.object(setup, 'run_foreground_server') as launch:
            stderr = self.run_main_cancelled(patches=self.base_main_patches())

        self.assertIn('Cancelled.', stderr)
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertEqual((self.cache / release.asset_name).read_bytes(), archive_before)
        self.assertEqual((self.cache / f'{release.asset_name}.json').read_bytes(), manifest_before)
        install.assert_not_called()
        launch.assert_not_called()

    def test_cancel_during_host_sync_reaps_pip_scratch_and_never_deploys(self):
        artifact = setup.CachedArtifact(
            '17.18.0', 'x86_64', 'server.xz', self.cache / 'server.xz',
        )
        distribution = mock.Mock()
        distribution.metadata = {'Name': 'Other'}
        distribution.version = '1.2.3'
        environment = os.environ.copy()
        for name in (*setup.PIP_ROUTING_ENVIRONMENT, *setup.PIP_RESOLVER_ENVIRONMENT):
            environment.pop(name, None)
        with mock.patch.object(setup, 'select_server_artifact', return_value=artifact), \
                mock.patch.object(setup, 'running_in_virtual_environment', return_value=True), \
                mock.patch.dict(setup.os.environ, environment, clear=True), \
                mock.patch.object(setup.metadata, 'version', return_value='17.9.0'), \
                mock.patch.object(setup.metadata, 'distributions', return_value=[distribution]), \
                mock.patch.object(
                    setup, 'host_package_output',
                    side_effect=[Completed(), Completed(), Completed(), KeyboardInterrupt],
                ), \
                mock.patch.object(setup, 'install_server') as install, \
                mock.patch.object(setup, 'run_foreground_server') as launch:
            stderr = self.run_main_cancelled(patches=self.base_main_patches())
        self.assertEqual(list(self.scratch.iterdir()), [])
        self.assertIn('virtual environment may be partially changed', stderr)
        install.assert_not_called()
        launch.assert_not_called()

    def test_cancel_extract_removes_fragment_without_publishing_cache(self):
        release = self.release()

        def download(_release, destination):
            destination.write_bytes(b'partial archive')

        with mock.patch.object(setup, 'download_asset', side_effect=download), \
                mock.patch.object(setup, 'unpack_xz', side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                setup.cache_release(release, 'x86_64')
        self.assertFalse((self.cache / release.asset_name).exists())
        self.assertEqual(list(self.cache.glob('download-*')), [])

    def test_cancel_latest_cache_refresh_does_not_retry_or_fallback(self):
        release = self.release()
        with mock.patch.object(setup, 'release_for', return_value=release) as fetch, \
                mock.patch.object(setup, 'cache_release', side_effect=KeyboardInterrupt) as download, \
                mock.patch.object(setup, 'materialize_highest_cached') as fallback:
            with self.assertRaises(KeyboardInterrupt):
                setup.select_server_artifact(None, 'x86_64', self.root / 'server')
        fetch.assert_called_once_with(None, 'x86_64')
        download.assert_called_once_with(release, 'x86_64')
        fallback.assert_not_called()

    def test_cancel_latest_release_fetch_does_not_retry_or_use_cache(self):
        with mock.patch.object(setup, 'release_for', side_effect=KeyboardInterrupt) as fetch, \
                mock.patch.object(setup, 'cache_release') as download, \
                mock.patch.object(setup, 'materialize_highest_cached') as fallback:
            with self.assertRaises(KeyboardInterrupt):
                setup.select_server_artifact(None, 'x86_64', self.root / 'server')
        fetch.assert_called_once_with(None, 'x86_64')
        download.assert_not_called()
        fallback.assert_not_called()

    def server_path(self):
        server = self.root / 'frida-server'
        server.write_bytes(b'candidate')
        return server

    def test_cancel_get_state_happens_before_upload(self):
        with mock.patch.object(setup, 'adb_command', side_effect=KeyboardInterrupt) as adb, \
                mock.patch.object(setup, 'run_root') as root:
            with self.assertRaises(KeyboardInterrupt):
                setup.install_server('/adb', 'serial', 'direct', self.server_path(), '17.18.0')
        self.assertEqual(adb.call_count, 1)
        root.assert_not_called()

    def test_cancel_upload_cleans_only_owned_remote_staging_with_bounded_timeout(self):
        staging = '/data/local/tmp/.frida-server-owned-cancel'
        calls = []

        def adb_command(_adb, _serial, operation, *args, **kwargs):
            calls.append((operation, args, kwargs))
            if operation == 'get-state':
                return Completed(stdout='device')
            raise KeyboardInterrupt

        cleanup_calls = []

        def run_root(_adb, _serial, _mode, command, purpose, **kwargs):
            cleanup_calls.append((command, purpose, kwargs))
            signal.raise_signal(signal.SIGINT)
            raise setup.SetupError('cleanup timed out')

        with mock.patch.object(setup, 'adb_command', side_effect=adb_command), \
                mock.patch.object(setup, 'run_root', side_effect=run_root):
            with self.assertRaises(KeyboardInterrupt):
                setup.install_server(
                    '/adb', 'serial', 'direct', self.server_path(), '17.18.0',
                    staging_name=staging,
                )
        self.assertEqual([operation for operation, _, _ in calls], ['get-state', 'push'])
        self.assertEqual(len(cleanup_calls), 1)
        cleanup_command, purpose, options = cleanup_calls[0]
        self.assertIn('rm', cleanup_command)
        self.assertIn(staging, cleanup_command)
        self.assertEqual(purpose, 'Removing partial Frida upload')
        self.assertEqual(options['timeout'], setup.STAGING_CLEANUP_TIMEOUT)
        self.assertEqual(setup.STAGING_CLEANUP_TIMEOUT, 3)

    def test_cancel_post_upload_validation_cleans_staging_and_never_stops_server(self):
        staging = '/data/local/tmp/.frida-server-validate-cancel'
        adb_calls = []
        root_calls = []

        def adb_command(_adb, _serial, operation, *args, **kwargs):
            adb_calls.append(operation)
            if operation == 'get-state':
                return Completed(stdout='device')
            return Completed()

        def run_root(_adb, _serial, _mode, command, purpose, **kwargs):
            root_calls.append((command, purpose, kwargs))
            if purpose == 'Preparing and validating staged Frida server':
                raise KeyboardInterrupt
            return Completed()

        with mock.patch.object(setup, 'adb_command', side_effect=adb_command), \
                mock.patch.object(setup, 'run_root', side_effect=run_root), \
                mock.patch.object(setup, 'stop_managed_servers') as stop:
            with self.assertRaises(KeyboardInterrupt):
                setup.install_server(
                    '/adb', 'serial', 'direct', self.server_path(), '17.18.0',
                    staging_name=staging,
                )
        self.assertEqual(adb_calls, ['get-state', 'push'])
        self.assertEqual([purpose for _, purpose, _ in root_calls], [
            'Preparing and validating staged Frida server',
            'Removing partial Frida upload',
        ])
        stop.assert_not_called()

    def test_main_upload_cancellation_returns_130_without_launch(self):
        with mock.patch.object(setup, 'ensure_host_frida_version'), \
                mock.patch.object(setup, 'install_server', side_effect=KeyboardInterrupt), \
                mock.patch.object(setup, 'run_foreground_server') as launch:
            artifact = setup.CachedArtifact(
                '17.18.0', 'x86_64', 'server.xz', self.root / 'server',
            )
            with mock.patch.object(setup, 'select_server_artifact', return_value=artifact):
                self.run_main_cancelled(patches=self.base_main_patches())
        launch.assert_not_called()

    def test_main_upload_cleanup_warning_preserves_130_and_owned_path(self):
        staging = '/data/local/tmp/.frida-server-main-cancel'
        adb_calls = []
        cleanup_calls = []

        def adb_command(_adb, _serial, operation, *args, **kwargs):
            adb_calls.append(operation)
            if operation == 'get-state':
                return Completed(stdout='device')
            raise KeyboardInterrupt

        def run_root(_adb, _serial, _mode, command, purpose, **kwargs):
            cleanup_calls.append((command, purpose, kwargs))
            signal.raise_signal(signal.SIGINT)
            raise setup.SetupError('cleanup timed out')

        artifact = setup.CachedArtifact(
            '17.18.0', 'x86_64', 'server.xz', self.root / 'server',
        )
        patches = [
            *self.base_main_patches(),
            mock.patch.object(setup, 'select_server_artifact', return_value=artifact),
            mock.patch.object(setup, 'ensure_host_frida_version'),
            mock.patch.object(setup, 'adb_command', side_effect=adb_command),
            mock.patch.object(setup, 'run_root', side_effect=run_root),
        ]
        stderr = self.run_main_cancelled(patches=patches)
        self.assertIn('partial upload may remain', stderr)
        self.assertEqual(adb_calls, ['get-state', 'push'])
        self.assertEqual(len(cleanup_calls), 1)
        command, purpose, options = cleanup_calls[0]
        self.assertEqual(purpose, 'Removing partial Frida upload')
        self.assertIn('/data/local/tmp/.frida-server-', command)
        self.assertNotIn(setup.REMOTE_SERVER, command)
        self.assertEqual(options['timeout'], setup.STAGING_CLEANUP_TIMEOUT)

    @unittest.skipUnless(os.name == 'posix', 'Subprocess SIGINT regression requires POSIX')
    def test_sigint_during_adb_device_listing_kills_and_reaps_fake_adb(self):
        marker = self.root / 'fake-adb.pid'
        fake_script = self.root / 'fake-adb.py'
        fake_script.write_text(
            '''#!/usr/bin/env python3
import os
from pathlib import Path
import signal
import sys
import time

if sys.argv[1:] != ['devices', '-l']:
    raise SystemExit(3)
signal.signal(signal.SIGINT, signal.SIG_IGN)
Path(os.environ['FRIDA_CANCEL_PID']).write_text(str(os.getpid()), encoding='ascii')
while True:
    time.sleep(0.05)
''',
            encoding='utf-8',
        )
        fake_adb = self.root / 'fake-adb'
        fake_adb.write_text(
            '#!/bin/sh\nexec ' + shlex.join([sys.executable, str(fake_script)]) + ' "$@"\n',
            encoding='utf-8',
        )
        fake_adb.chmod(0o755)
        environment = os.environ.copy()
        environment['FRIDA_CANCEL_PID'] = str(marker)
        command = [
            sys.executable,
            str(setup.ROOT / 'tools' / 'setup_frida.py'),
            '--no-shell', '--adb', str(fake_adb),
        ]
        process = subprocess.Popen(
            command,
            cwd=setup.ROOT,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            start_new_session=True,
        )
        try:
            deadline = time.monotonic() + 5
            marker_text = ''
            while not marker_text and process.poll() is None:
                self.assertLess(time.monotonic(), deadline, 'fake ADB never reached devices listing')
                if marker.exists():
                    marker_text = marker.read_text(encoding='ascii').strip()
                time.sleep(0.02)
            self.assertTrue(marker_text, process.stderr.read() if process.poll() else 'no PID marker')
            fake_pid = int(marker_text)
            os.kill(process.pid, signal.SIGINT)
            stdout, stderr = process.communicate(timeout=8)
            self.assertEqual(process.returncode, 130, (stdout, stderr))
            self.assertNotIn('Traceback', stderr)
            deadline = time.monotonic() + 3
            while True:
                try:
                    os.kill(fake_pid, 0)
                except ProcessLookupError:
                    break
                self.assertLess(time.monotonic(), deadline, 'fake ADB child was not reaped')
                time.sleep(0.02)
        finally:
            if process.poll() is None:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)


if __name__ == '__main__':
    unittest.main()
