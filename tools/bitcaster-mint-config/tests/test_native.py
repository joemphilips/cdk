"""Opt-in checks against a current, already built CDK native validator."""

import os
from pathlib import Path
import subprocess
import tempfile
import unittest

from test_render import fixture, render

BINARY = os.environ.get("MINT_CONFIG_TEST_BINARY")
TEST_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"


@unittest.skipUnless(BINARY, "set MINT_CONFIG_TEST_BINARY to a built cdk-mintd 0.18.2")
class NativeValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="mint-render-native-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.binary = str(Path(BINARY).resolve())
        self.env = {
            "PATH": os.defpath,
            "TEST_MINT_MNEMONIC": TEST_MNEMONIC,
            "TEST_MINT_POSTGRES_URL": "postgresql://mint:synthetic-password@127.0.0.1:5432/mintdb",
        }
        result = subprocess.run([self.binary, "--version"], env=self.env, cwd=self.root,
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), "cdk-mintd 0.18.2")

    def validate(self, value):
        document = self.root / "mint.toml"
        document.write_text(render.render_document(value))
        # This command does not open a mint database or start a payment backend.
        return subprocess.run([self.binary, "config", "validate", "--file", str(document)],
                              env=self.env, cwd=self.root, capture_output=True, text=True, timeout=20)

    def with_pin(self, value):
        certificates = self.root / "certificates"
        certificates.mkdir(exist_ok=True)
        pin = certificates / "client.spki.sha256"
        pin.write_text("11" * 32 + "\n")
        management = value["settings"]["mint_management_rpc"]
        management["tls_dir"] = str(certificates)
        management["expected_client_spki_pin_path"] = str(pin)
        return pin

    def test_all_profiles_pass_native_validation(self):
        for environment, database, management in [
            ("local", "postgres", True), ("local", "sqlite", False),
            ("staging", "postgres", True), ("staging", "postgres", False),
        ]:
            with self.subTest(environment=environment, database=database, management=management):
                value = fixture(environment, database, management)
                if management:
                    self.with_pin(value)
                result = self.validate(value)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout.strip(), "Configuration is valid.")
        self.assertFalse(list(self.root.rglob("*.sqlite")))

    def test_native_validator_remains_domain_semantics_authority(self):
        value = fixture(management=False)
        value["settings"]["mint_info"]["ctf_settlement"]["max_participants"] = 1
        result = self.validate(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("max_participants", result.stderr)

    def test_strict_rpc_pin_must_exist_and_parse_before_validation(self):
        value = fixture()
        pin = self.with_pin(value)
        pin.unlink()
        result = self.validate(value)
        self.assertNotEqual(result.returncode, 0)
        pin.write_text("invalid\n")
        result = self.validate(value)
        self.assertNotEqual(result.returncode, 0)
        pin.write_text("11" * 32 + "\n")
        self.assertEqual(self.validate(value).returncode, 0)

    def test_reference_resolution_is_native_and_missing_secret_refuses(self):
        value = fixture(management=False)
        del self.env["TEST_MINT_MNEMONIC"]
        result = self.validate(value)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("TEST_MINT_MNEMONIC", result.stderr)


if __name__ == "__main__":
    unittest.main()
