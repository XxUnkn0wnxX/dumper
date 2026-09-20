"""Offline tests for the optional pywidevine WVD batch generator."""

from contextlib import redirect_stderr, redirect_stdout
import io
import os
from pathlib import Path
import stat
import tempfile
import unittest
from unittest import mock
from zlib import crc32

from tools import generate_wvd


ROOT = Path(__file__).resolve().parents[1]
TMP_ROOT = ROOT / ".tmp"


class GenerateWvdCliTests(unittest.TestCase):
    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        temporary = tempfile.TemporaryDirectory(prefix="generate-wvd-cli-", dir=TMP_ROOT)
        self.addCleanup(temporary.cleanup)
        self.missing_root = Path(temporary.name) / "missing-root"
        root_patch = mock.patch.object(generate_wvd, "KEY_DUMPS_ROOT", self.missing_root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        # None of these CLI-only cases should reach key parsing or real data.
        dependency_patch = mock.patch.object(
            generate_wvd, "_load_dependencies",
            side_effect=AssertionError("CLI fixture unexpectedly reached key parsing"),
        )
        dependency_patch.start()
        self.addCleanup(dependency_patch.stop)

    def test_help_does_not_bootstrap(self):
        with mock.patch.object(generate_wvd, "prepare_terminal") as terminal, \
                mock.patch.object(generate_wvd, "bootstrap_wvd") as bootstrap:
            with self.assertRaises(SystemExit) as result, \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                generate_wvd.main(["--help"])
        self.assertEqual(result.exception.code, 0)
        terminal.assert_not_called()
        bootstrap.assert_not_called()

    def test_wrong_arguments_do_not_bootstrap(self):
        with mock.patch.object(generate_wvd, "prepare_terminal") as terminal, \
                mock.patch.object(generate_wvd, "bootstrap_wvd") as bootstrap:
            with self.assertRaises(SystemExit) as result, \
                    redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                generate_wvd.main(["--root", "somewhere"])
        self.assertEqual(result.exception.code, 2)
        terminal.assert_not_called()
        bootstrap.assert_not_called()

    def test_cancellation_before_bootstrap_returns_130(self):
        with mock.patch.object(generate_wvd, "prepare_terminal", side_effect=KeyboardInterrupt), \
                mock.patch.object(generate_wvd, "bootstrap_wvd") as bootstrap:
            with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
                self.assertEqual(generate_wvd.main([]), 130)
        bootstrap.assert_not_called()

    def test_missing_root_reports_actionable_pair_guidance(self):
        with mock.patch.object(generate_wvd, "prepare_terminal"), \
                mock.patch.object(generate_wvd, "bootstrap_wvd"):
            stdout = io.StringIO()
            stderr = io.StringIO()
            with redirect_stdout(stdout), redirect_stderr(stderr):
                result = generate_wvd.main([])
        self.assertEqual(result, 1)
        self.assertIn("No key pairs found in key_dumps/", stderr.getvalue())
        self.assertIn("client_id.bin", stderr.getvalue())

    def test_default_root_uses_current_setting_before_any_filesystem_read(self):
        with mock.patch.object(generate_wvd.os, "lstat", side_effect=FileNotFoundError) as inspect:
            summary = generate_wvd.generate()
        inspect.assert_called_once_with(self.missing_root)
        self.assertFalse(summary.success)


class GenerateWvdOptionalTests(unittest.TestCase):
    """These tests run only in the separately maintained WVD environment."""

    @classmethod
    def setUpClass(cls):
        try:
            from Crypto.PublicKey import RSA
            from pywidevine.device import Device
            from pywidevine.license_protocol_pb2 import (
                ClientIdentification,
                DrmCertificate,
                SignedDrmCertificate,
            )
            from unidecode import unidecode
        except ImportError as error:
            raise unittest.SkipTest(f"optional WVD dependencies unavailable: {error}")
        cls.RSA = RSA
        cls.Device = Device
        cls.ClientIdentification = ClientIdentification
        cls.DrmCertificate = DrmCertificate
        cls.SignedDrmCertificate = SignedDrmCertificate
        cls.unidecode = unidecode

    def setUp(self):
        TMP_ROOT.mkdir(parents=True, exist_ok=True)
        self.temporary = tempfile.TemporaryDirectory(prefix="generate-wvd-", dir=TMP_ROOT)
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "key_dumps"
        self.root.mkdir()
        root_patch = mock.patch.object(generate_wvd, "ROOT", self.root.parent)
        root_patch.start()
        self.addCleanup(root_patch.stop)

    def _pair_bytes(self, *, key=None, company="Google", model="sdk_gphone_x86_64",
                    version="17.0.0", system_id=22596):
        key = key or self.RSA.generate(2048)
        certificate = self.DrmCertificate()
        certificate.type = 2  # DEVICE
        certificate.algorithm = 1  # RSA
        certificate.public_key = key.publickey().export_key(format="DER")
        certificate.system_id = system_id

        signed = self.SignedDrmCertificate()
        signed.drm_certificate = certificate.SerializeToString()

        client = self.ClientIdentification()
        client.type = 1  # DRM_DEVICE_CERTIFICATE
        client.token = signed.SerializeToString()
        for name, value in (
            ("company_name", company),
            ("model_name", model),
            ("widevine_cdm_version", version),
        ):
            entry = client.client_info.add()
            entry.name = name
            entry.value = value
        return client.SerializeToString(), key.export_key(format="PEM")

    def _make_pair(self, relative="nested/pair", **kwargs):
        directory = self.root / relative
        directory.mkdir(parents=True)
        client, private_key = self._pair_bytes(**kwargs)
        (directory / "client_id.bin").write_bytes(client)
        (directory / "private_key.pem").write_bytes(private_key)
        return directory, client, private_key

    def _expected_name(self, payload):
        return (
            "google_sdk_gphone_x86_64_17.0.0_"
            f"{crc32(payload).to_bytes(4, 'big').hex()}_22596_l3.wvd"
        )

    def test_valid_generation_uses_upstream_name_and_roundtrips(self):
        directory, client_before, key_before = self._make_pair()
        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            summary = generate_wvd.generate(self.root)
        self.assertEqual((summary.generated, summary.overwritten, summary.failed), (1, 0, 0))
        output_directory = directory / "WVD"
        files = list(output_directory.glob("*.wvd"))
        expected_name = self._expected_name(files[0].read_bytes())
        self.assertEqual([path.name for path in files], [expected_name])
        self.assertIn(f"Created: {summary.output_paths[0]}", stdout.getvalue())
        self.assertIn("Created: key_dumps/nested/pair/WVD/", stdout.getvalue())
        self.assertNotIn(str(self.root), stdout.getvalue())
        self.assertEqual(stderr.getvalue(), "")
        device = self.Device.loads(files[0].read_bytes())
        self.assertEqual(device.security_level, 3)
        self.assertEqual(device.dumps(), files[0].read_bytes())
        self.assertEqual((directory / "client_id.bin").read_bytes(), client_before)
        self.assertEqual((directory / "private_key.pem").read_bytes(), key_before)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(files[0].stat().st_mode), 0o600)

    def test_overwrites_every_existing_wvd_and_preserves_other_entries(self):
        directory, _, _ = self._make_pair("pair")
        output_directory = directory / "WVD"
        output_directory.mkdir()
        (output_directory / "first.WVD").write_bytes(b"old-one")
        (output_directory / "second.wvd").write_bytes(b"old-two")
        (output_directory / "keep.txt").write_bytes(b"keep")
        (output_directory / "subdir").mkdir()

        stdout = io.StringIO()
        stderr = io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            summary = generate_wvd.generate(self.root)
        self.assertEqual(summary.overwritten, 2)
        self.assertEqual(summary.generated, 0)
        self.assertIn("Replaced: key_dumps/pair/WVD/first.WVD", stdout.getvalue())
        self.assertIn("Replaced: key_dumps/pair/WVD/second.wvd", stdout.getvalue())
        self.assertNotIn(str(self.root), stdout.getvalue())
        self.assertEqual((output_directory / "keep.txt").read_bytes(), b"keep")
        self.assertTrue((output_directory / "subdir").is_dir())
        self.assertEqual(
            (output_directory / "first.WVD").read_bytes(),
            (output_directory / "second.wvd").read_bytes(),
        )
        self.assertEqual(list(output_directory.glob("*.tmp")), [])

    def test_invalid_pairs_are_skipped_and_recursive_wvd_directories_are_excluded(self):
        self._make_pair("valid/deep")
        missing_client = self.root / "missing-client"
        missing_client.mkdir()
        (missing_client / "private_key.pem").write_bytes(b"missing")
        missing_key = self.root / "missing-key"
        missing_key.mkdir()
        (missing_key / "client_id.bin").write_bytes(b"missing")
        malformed = self.root / "malformed"
        malformed.mkdir()
        (malformed / "client_id.bin").write_bytes(b"bad")
        (malformed / "private_key.pem").write_bytes(b"bad")
        public_only = self.root / "public-only"
        public_only.mkdir()
        client, private_key = self._pair_bytes()
        public_only_key = self.RSA.import_key(private_key).publickey().export_key(format="PEM")
        (public_only / "client_id.bin").write_bytes(client)
        (public_only / "private_key.pem").write_bytes(public_only_key)
        mismatch_key = self.RSA.generate(2048)
        mismatch_client, _ = self._pair_bytes()
        mismatch = self.root / "mismatch"
        mismatch.mkdir()
        (mismatch / "client_id.bin").write_bytes(mismatch_client)
        (mismatch / "private_key.pem").write_bytes(mismatch_key.export_key(format="PEM"))
        ignored = self.root / "nested" / "WVD"
        ignored.mkdir(parents=True)
        ignored_pair, _, _ = self._make_pair("nested/WVD/ignored")

        stderr = io.StringIO()
        with redirect_stderr(stderr):
            summary = generate_wvd.generate(self.root)
        self.assertEqual(summary.valid_pairs, 1)
        self.assertGreaterEqual(summary.skipped, 5)
        self.assertIn("Skipped: ", stderr.getvalue())
        self.assertIn("Skipped: key_dumps/missing-client: missing client_id.bin", stderr.getvalue())
        self.assertIn("Skipped: key_dumps/missing-key: missing private_key.pem", stderr.getvalue())
        self.assertNotIn(str(self.root), stderr.getvalue())
        self.assertFalse(summary.success)
        self.assertIn("missing client_id.bin", stderr.getvalue())
        self.assertTrue((self.root / "valid/deep/WVD").is_dir())
        self.assertFalse((ignored_pair / "WVD").exists())

    @unittest.skipUnless(os.name == "posix", "filesystem safety fixtures need POSIX symlinks")
    def test_symlinked_root_input_and_output_are_rejected(self):
        outside = Path(self.temporary.name) / "outside"
        outside.mkdir()
        source_key = self.RSA.generate(2048)
        client, private_key = self._pair_bytes(key=source_key)
        outside_pair = outside / "source"
        outside_pair.mkdir()
        (outside_pair / "client_id.bin").write_bytes(client)
        (outside_pair / "private_key.pem").write_bytes(private_key)

        root_link = Path(self.temporary.name) / "root-link"
        root_link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaisesRegex(generate_wvd.GenerationError, "symlinked"):
            generate_wvd.generate(root_link)

        linked_input = self.root / "linked-input"
        linked_input.mkdir()
        (linked_input / "client_id.bin").symlink_to(outside_pair / "client_id.bin")
        (linked_input / "private_key.pem").write_bytes(private_key)
        summary = generate_wvd.generate(self.root)
        self.assertGreaterEqual(summary.skipped, 1)
        self.assertFalse((linked_input / "WVD").exists())

        pair, _, _ = self._make_pair("output-link")
        output_link = self.root / "output-link"
        (pair / "WVD").symlink_to(outside, target_is_directory=True)
        summary = generate_wvd.generate(self.root)
        self.assertGreaterEqual(summary.failed, 1)
        self.assertFalse(list(outside.glob("*.wvd")))

    def test_failed_write_and_interrupt_remove_only_temporary_file(self):
        directory, _, _ = self._make_pair("pair")
        first = generate_wvd.generate(self.root)
        output = next((directory / "WVD").glob("*.wvd"))
        old = b"existing-output"
        output.write_bytes(old)
        with mock.patch.object(generate_wvd.os, "replace", side_effect=OSError("replace failed")):
            summary = generate_wvd.generate(self.root)
        self.assertEqual(summary.failed, 1)
        self.assertEqual(output.read_bytes(), old)
        self.assertEqual(list((directory / "WVD").glob(".generate-wvd-*.tmp")), [])

        with mock.patch.object(generate_wvd.os, "fsync", side_effect=KeyboardInterrupt):
            with self.assertRaises(KeyboardInterrupt):
                generate_wvd.generate(self.root)
        self.assertEqual(output.read_bytes(), old)
        self.assertEqual(list((directory / "WVD").glob(".generate-wvd-*.tmp")), [])


if __name__ == "__main__":
    unittest.main()
