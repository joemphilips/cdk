"""Tests for the standalone nonsecret mint configuration renderer."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import tomllib
import unittest
from unittest.mock import patch

TOOL = Path(__file__).resolve().parents[1] / "render.py"
spec = importlib.util.spec_from_file_location("mint_config_render", TOOL)
render = importlib.util.module_from_spec(spec)
spec.loader.exec_module(render)


def fixture(environment="local", database="postgres", management=True):
    """Use explicit synthetic limits, not a hosted deployment policy."""
    settings = {
        "info": {
            "url": "http://localhost:8086" if environment == "local" else "https://mint.example.test",
            "listen_host": "127.0.0.1" if environment == "local" else "0.0.0.0",
            "listen_port": 8086,
            "mnemonic": "env:TEST_MINT_MNEMONIC",
            "input_fee_ppk": 1000,
            "use_keyset_v2": True,
            "http_cache": {"backend": "memory"},
            "logging": {"output": "stderr", "format": "json", "console_level": "info"},
            "quote_ttl": {"mint_ttl": 91, "melt_ttl": 17},
        },
        "database": {"engine": database},
        "payment_backend": [{"backend": "fakewallet", "unit": "msat", "min_mint": 1000,
                             "max_mint": 2000000, "min_melt": 1000, "max_melt": 3000000}],
        "fake_wallet": {},
        "limits": {"max_inputs": 128, "max_outputs": 256},
        "mint_info": {
            "name": "A test mint", "ctf_default_keyset_creation": "one-vs-rest",
            "ctf_registration_fees": [{"unit": "msat", "registration_fee_base": 13,
                                       "registration_fee_per_keyset": 17}],
            "ctf_settlement": {"max_participants": 4, "max_inputs": 128, "max_outputs": 256,
                               "max_request_bytes": 65536, "max_expiry_seconds": 3600,
                               "max_pool_entries": 8},
        },
        "mint_management_rpc": {"enabled": False},
    }
    if database == "postgres":
        settings["database"]["postgres"] = {
            "url": "env:TEST_MINT_POSTGRES_URL",
            "tls_mode": "disable" if environment == "local" else "verify-full",
            "max_connections": 20, "connection_timeout_seconds": 10,
        }
    if management:
        settings["mint_management_rpc"] = {
            "enabled": True, "address": "127.0.0.1", "port": 8087,
            "tls_dir": "/not-read/certs", "strict_tls": True, "allow_insecure": False,
            "allow_mint_quote_payment_override": False, "expected_client_dns_name": "orchard",
            "expected_client_spki_pin_path": "/not-read/certs/client.spki.sha256",
        }
    return {"environment": environment, "settings": settings}


class DocumentTests(unittest.TestCase):
    def test_all_supported_profiles_round_trip_without_defaults(self):
        for environment, database, management in [
            ("local", "postgres", True), ("local", "sqlite", False),
            ("staging", "postgres", True), ("staging", "postgres", False),
        ]:
            with self.subTest(environment=environment, database=database, management=management):
                value = fixture(environment, database, management)
                self.assertEqual(tomllib.loads(render.render_document(value)), value["settings"])

    def test_output_is_deterministic_under_input_key_reordering(self):
        def reverse(value):
            if isinstance(value, dict):
                return {key: reverse(child) for key, child in reversed(list(value.items()))}
            if isinstance(value, list):
                return [reverse(child) for child in value]
            return value
        value = fixture()
        self.assertEqual(render.render_document(value), render.render_document(reverse(value)))
        self.assertTrue(render.render_document(value).endswith("\n"))

    def test_strings_cannot_inject_toml(self):
        value = fixture()
        text = '日本語 "quoted" \\ path\n[ln]\nbackend = "lnbits"\r\t\b\f\x01\x7f 😀'
        value["settings"]["mint_info"]["description"] = text
        parsed = tomllib.loads(render.render_document(value))
        self.assertEqual(parsed["mint_info"]["description"], text)
        self.assertNotIn("ln", parsed)

    def test_renderer_never_resolves_secret_references_or_environment(self):
        value = fixture()
        value["settings"]["info"]["mnemonic"] = "file:/nonexistent/mint-secret"
        with patch.dict(os.environ, {"CDK_MINTD_LN_BACKEND": "lnbits"}), \
                patch.object(Path, "read_text", side_effect=AssertionError("file read")), \
                patch.object(os, "getenv", side_effect=AssertionError("environment read")):
            self.assertEqual(tomllib.loads(render.render_document(value)), value["settings"])

    def test_optional_public_metadata_and_seed_reference_are_preserved(self):
        value = fixture()
        info = value["settings"]["info"]
        del info["mnemonic"]
        info["seed"] = "file:/run/mint/seed"
        value["settings"]["mint_info"].update({
            "pubkey": "02" + "11" * 32, "description_long": "long description",
            "icon_url": "https://example.test/icon.png", "motd": "hello",
            "contact_nostr_public_key": "11" * 32, "contact_email": "mint@example.test",
            "tos_url": "https://example.test/terms",
        })
        value["settings"]["limits"]["max_outcomes_per_condition"] = 7
        self.assertEqual(tomllib.loads(render.render_document(value)), value["settings"])

    def test_unknown_keys_at_each_boundary_are_refused(self):
        for path in [(), ("settings",), ("settings", "info"), ("settings", "info", "logging"),
                     ("settings", "info", "http_cache"), ("settings", "info", "quote_ttl"),
                     ("settings", "database"), ("settings", "database", "postgres"),
                     ("settings", "payment_backend", 0), ("settings", "fake_wallet"),
                     ("settings", "limits"), ("settings", "mint_info"),
                     ("settings", "mint_info", "ctf_registration_fees", 0),
                     ("settings", "mint_info", "ctf_settlement"), ("settings", "mint_management_rpc")]:
            value = fixture()
            node = value
            for key in path:
                node = node[key]
            node["unrecognized"] = "must-not-be-printed"
            with self.subTest(path=path), self.assertRaises(render.InputRefused):
                render.render_document(value)

    def test_numeric_and_boolean_types_are_exact(self):
        for field, invalid in [("listen_port", True), ("listen_port", "8086"), ("listen_port", 8.5),
                               ("listen_port", 0), ("listen_port", 65536), ("input_fee_ppk", -1),
                               ("input_fee_ppk", 2**63), ("use_keyset_v2", 1), ("use_keyset_v2", False),
                               ("input_fee_ppk", float("nan")), ("input_fee_ppk", float("inf"))]:
            value = fixture()
            value["settings"]["info"][field] = invalid
            with self.subTest(field=field, invalid=invalid), self.assertRaises(render.InputRefused):
                render.render_document(value)

    def test_bad_json_is_refused_without_input_echo(self):
        for raw in [b'{"environment":"local","environment":"staging"}',
                    b'{"settings":{"info":{"url":"x","url":"y"}}}',
                    b'{"secret":NaN}', b'{"secret":Infinity}', b'{"secret":-Infinity}',
                    b'{"secret":1e9999}', b'[]', b'null', b'\xff', b'{bad',
                    b'[' * 2000 + b']' * 2000, b' ' * (render.MAX_INPUT_BYTES + 1)]:
            with self.subTest(raw=raw[:40]), self.assertRaises(render.InputRefused):
                render.parse_input(raw)

    def test_secret_literals_and_ambiguous_references_are_refused(self):
        for invalid in ["literal-sensitive-value", "env:", "env:BAD NAME", "file:relative",
                        "file:/path/../seed", "file:/path\nseed", "file:/", "env:NAME\x00"]:
            for path in [("info", "mnemonic"), ("database", "postgres", "url")]:
                value = fixture()
                node = value["settings"]
                for key in path[:-1]:
                    node = node[key]
                node[path[-1]] = invalid
                with self.subTest(path=path, invalid=invalid), self.assertRaises(render.InputRefused):
                    render.render_document(value)

    def test_missing_or_dual_signer_references_are_refused(self):
        for dual in [False, True]:
            value = fixture()
            if dual:
                value["settings"]["info"]["seed"] = "env:SEED"
            else:
                del value["settings"]["info"]["mnemonic"]
            with self.assertRaises(render.InputRefused):
                render.render_document(value)

    def test_production_and_other_backends_are_refused(self):
        for backend in ["lnbits", "lnd", "cln", "grpcprocessor", "none"]:
            value = fixture()
            value["settings"]["payment_backend"][0]["backend"] = backend
            with self.subTest(backend=backend), self.assertRaises(render.InputRefused):
                render.render_document(value)
        value = fixture()
        value["environment"] = "production"
        with self.assertRaises(render.InputRefused):
            render.render_document(value)

    def test_single_msat_rail_and_fee_entry_only(self):
        for path in ["payment_backend", "ctf_registration_fees"]:
            for change in ["empty", "duplicate", "sat"]:
                value = fixture()
                node = value["settings"] if path == "payment_backend" else value["settings"]["mint_info"]
                if change == "empty":
                    node[path] = []
                elif change == "duplicate":
                    node[path].append(copy.deepcopy(node[path][0]))
                else:
                    node[path][0]["unit"] = "sat"
                with self.subTest(path=path, change=change), self.assertRaises(render.InputRefused):
                    render.render_document(value)

    def test_staging_requires_tls_and_postgres(self):
        for field, invalid in [("tls_mode", "require"), ("tls_mode", "disable")]:
            value = fixture("staging")
            value["settings"]["database"]["postgres"][field] = invalid
            with self.assertRaises(render.InputRefused):
                render.render_document(value)
        with self.assertRaises(render.InputRefused):
            render.render_document(fixture("staging", "sqlite"))

    def test_urls_and_host_paths_cannot_carry_credentials_or_control_characters(self):
        for invalid in ["http://user:secret@localhost:8086", "https://example.test/#fragment",
                        "http://example.test/\n", "file:///tmp/mint", "https://example.test/?token=x",
                        "https://invalid host.test"]:
            value = fixture()
            value["settings"]["info"]["url"] = invalid
            with self.subTest(invalid=invalid), self.assertRaises(render.InputRefused):
                render.render_document(value)
        value = fixture("staging")
        value["settings"]["info"]["url"] = "http://mint.example.test"
        with self.assertRaises(render.InputRefused):
            render.render_document(value)

    def test_enabled_management_requires_strict_peer_fields(self):
        for field, invalid in [("strict_tls", False), ("allow_insecure", True),
                               ("allow_mint_quote_payment_override", True), ("tls_dir", "relative"),
                               ("expected_client_spki_pin_path", "/tmp/../pin"),
                               ("expected_client_dns_name", "")]:
            value = fixture()
            value["settings"]["mint_management_rpc"][field] = invalid
            with self.subTest(field=field), self.assertRaises(render.InputRefused):
                render.render_document(value)
        value = fixture()
        del value["settings"]["mint_management_rpc"]["expected_client_spki_pin_path"]
        with self.assertRaises(render.InputRefused):
            render.render_document(value)
        value = fixture(management=False)
        value["settings"]["mint_management_rpc"]["allow_insecure"] = True
        with self.assertRaises(render.InputRefused):
            render.render_document(value)

    def test_missing_required_sections_and_invalid_unicode_are_refused(self):
        for key in fixture()["settings"]:
            value = fixture()
            del value["settings"][key]
            with self.subTest(key=key), self.assertRaises(render.InputRefused):
                render.render_document(value)
        value = fixture()
        value["settings"]["mint_info"]["description"] = "\ud800"
        with self.assertRaises(render.InputRefused):
            render.render_document(value)


class OutputTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)

    def test_create_then_explicit_overwrite_with_private_mode(self):
        target = self.root / "mint.toml"
        render.write_document(target, "old\n")
        self.assertEqual(stat.S_IMODE(target.stat().st_mode), 0o600)
        with self.assertRaises(FileExistsError):
            render.write_document(target, "new\n")
        self.assertEqual(target.read_text(), "old\n")
        render.write_document(target, "new\n", overwrite=True)
        self.assertEqual(target.read_text(), "new\n")
        self.assertEqual(list(self.root.iterdir()), [target])

    def test_atomic_no_clobber_when_destination_appears_during_publish(self):
        target = self.root / "mint.toml"
        original_link = os.link
        def race(source, destination, **kwargs):
            target.write_text("other owner\n")
            return original_link(source, destination, **kwargs)
        with patch.object(os, "link", side_effect=race), self.assertRaises(FileExistsError):
            render.write_document(target, "our bytes\n")
        self.assertEqual(target.read_text(), "other owner\n")
        self.assertEqual(list(self.root.iterdir()), [target])

    def test_replace_failure_preserves_old_content_and_removes_temporary_file(self):
        target = self.root / "mint.toml"
        target.write_text("old\n")
        with patch.object(os, "replace", side_effect=OSError("synthetic")), self.assertRaises(OSError):
            render.write_document(target, "new\n", overwrite=True)
        self.assertEqual(target.read_text(), "old\n")
        self.assertEqual(list(self.root.iterdir()), [target])

    def test_symlink_refusal_and_nonregular_output(self):
        other = self.root / "other"
        other.write_text("keep\n")
        target = self.root / "mint.toml"
        target.symlink_to(other)
        for overwrite in [False, True]:
            with self.assertRaises(OSError):
                render.write_document(target, "new\n", overwrite=overwrite)
        self.assertEqual(other.read_text(), "keep\n")
        with self.assertRaises(OSError):
            render.write_document(self.root, "new\n", overwrite=True)

    def test_fsync_failure_before_publish_preserves_destination(self):
        target = self.root / "mint.toml"
        target.write_text("old\n")
        with patch.object(os, "fsync", side_effect=OSError("synthetic")), self.assertRaises(OSError):
            render.write_document(target, "new\n", overwrite=True)
        self.assertEqual(target.read_text(), "old\n")
        self.assertEqual(list(self.root.iterdir()), [target])

    def test_cli_success_and_safe_refusal(self):
        source, target = self.root / "input.json", self.root / "mint.toml"
        source.write_text(json.dumps(fixture()))
        command = [sys.executable, str(TOOL), "--input", str(source), "--output", str(target)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(tomllib.loads(target.read_text()), fixture()["settings"])
        previous = target.read_bytes()
        source.write_text('{"sensitive-marker":"do-not-print"}')
        result = subprocess.run(command + ["--overwrite"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 64)
        self.assertNotIn("sensitive-marker", result.stdout + result.stderr)
        self.assertNotIn("do-not-print", result.stdout + result.stderr)
        self.assertEqual(target.read_bytes(), previous)
        result = subprocess.run([sys.executable, str(TOOL), "--sensitive-marker"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 64)
        self.assertNotIn("sensitive-marker", result.stderr)

    def test_cli_refuses_input_output_alias_even_with_overwrite(self):
        source = self.root / "input.json"
        original = json.dumps(fixture())
        source.write_text(original)
        result = subprocess.run([sys.executable, str(TOOL), "--input", str(source),
                                 "--output", str(source), "--overwrite"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(source.read_text(), original)

    def test_cli_refuses_hard_link_to_input(self):
        source, target = self.root / "input.json", self.root / "mint.toml"
        original = json.dumps(fixture())
        source.write_text(original)
        os.link(source, target)
        result = subprocess.run([sys.executable, str(TOOL), "--input", str(source),
                                 "--output", str(target), "--overwrite"],
                                capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 64)
        self.assertEqual(source.read_text(), original)
        self.assertEqual(target.read_text(), original)


if __name__ == "__main__":
    unittest.main()
