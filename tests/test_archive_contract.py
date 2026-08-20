import importlib.util
import json
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VALIDATOR_PATH = ROOT / "scripts" / "validate_outbox.py"


def load_validator():
    spec = importlib.util.spec_from_file_location("validate_outbox", VALIDATOR_PATH)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


class ValidatorRulesTests(unittest.TestCase):
    def setUp(self):
        self.validator = load_validator()

    def test_published_json_policy_loads_and_enforces_non_default_rules(self):
        policy_path = ROOT / "config" / "validation-rules.json"
        self.assertTrue(policy_path.exists(), "published JSON policy is missing")
        rules = self.validator.load_rules(
            str(policy_path)
        )

        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "result.txt"
            output.write_text("password = 'secret123'")
            is_valid, reason = self.validator.validate_file(output, rules)

        self.assertFalse(is_valid)
        self.assertIn("Blocked pattern", reason)
        self.assertEqual(["type", "timestamp"], rules["required_json_fields"])

    def test_required_json_fields_reject_non_object_documents(self):
        rules = {
            "reject_symlinks": False,
            "max_file_size": 1024,
            "required_json_fields": ["type", "timestamp"],
        }
        cases = {
            "array.json": '["type", "timestamp"]',
            "scalar.json": "1",
            "null.json": "null",
            "string.json": '"type timestamp"',
        }
        with tempfile.TemporaryDirectory() as directory:
            for name, content in cases.items():
                with self.subTest(name=name):
                    output = Path(directory) / name
                    output.write_text(content)
                    is_valid, reason = self.validator.validate_file(output, rules)
                    self.assertFalse(is_valid)
                    self.assertIn("object", reason)

    def test_required_json_fields_accept_complete_object(self):
        rules = {
            "reject_symlinks": False,
            "max_file_size": 1024,
            "required_json_fields": ["type", "timestamp"],
        }
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "ok.json"
            output.write_text('{"type": "result", "timestamp": "2026-08-18T00:00:00Z"}')
            is_valid, reason = self.validator.validate_file(output, rules)
            self.assertTrue(is_valid, reason)

    def test_invalid_policy_is_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            policy = Path(directory) / "rules.json"
            policy.write_text("{not valid json")
            with self.assertRaises(json.JSONDecodeError):
                self.validator.load_rules(str(policy))

    def test_missing_policy_is_fatal(self):
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory) / "missing.json"
            with self.assertRaises(FileNotFoundError):
                self.validator.load_rules(str(missing))


class PolicySchemaTests(unittest.TestCase):
    """The README promises a malformed policy exits instead of selecting weaker
    behavior. These prove it for field schemas, not just missing/unparseable files."""

    def setUp(self):
        self.validator = load_validator()

    def valid_policy(self, **overrides) -> dict:
        policy = {
            "max_file_size": 5242880,
            "reject_symlinks": True,
            "blocked_patterns": ["AKIA[0-9A-Z]{16}"],
            "required_json_fields": ["type"],
            "allowed_extensions": [".json"],
        }
        policy.update(overrides)
        return policy

    def assert_rejected(self, policy: dict, *expected_fragments: str):
        with self.assertRaises(self.validator.PolicySchemaError) as caught:
            self.validator.validate_policy(policy, "rules.json")
        message = str(caught.exception)
        for fragment in expected_fragments:
            self.assertIn(fragment, message)
        return message

    def test_published_policy_satisfies_the_schema(self):
        policy = self.validator.load_rules(str(ROOT / "config" / "validation-rules.json"))
        self.assertEqual(["type", "timestamp"], policy["required_json_fields"])

    def test_wrong_typed_reject_symlinks_is_fatal(self):
        # The reported trigger: a syntactically valid object whose falsy value
        # silently skipped the symlink branch.
        for bad in (None, "true", 1, [], {}):
            with self.subTest(value=bad):
                self.assert_rejected(
                    self.valid_policy(reject_symlinks=bad), "reject_symlinks", "boolean"
                )

    def test_missing_mandatory_key_is_fatal(self):
        for key in self.validator.POLICY_REQUIRED_KEYS:
            with self.subTest(key=key):
                policy = self.valid_policy()
                del policy[key]
                self.assert_rejected(policy, "missing required policy key", key)

    def test_misspelled_key_is_fatal_rather_than_silently_ignored(self):
        policy = self.valid_policy()
        policy["blocked_paterns"] = policy.pop("blocked_patterns")
        self.assert_rejected(policy, "unknown policy key", "blocked_paterns")

    def test_max_file_size_type_and_range_are_enforced(self):
        for bad in (None, True, "5242880", 1.5, [5242880]):
            with self.subTest(value=bad):
                self.assert_rejected(
                    self.valid_policy(max_file_size=bad), "max_file_size", "whole number"
                )
        for bad in (0, -1, self.validator.MAX_FILE_SIZE_CEILING + 1):
            with self.subTest(value=bad):
                self.assert_rejected(
                    self.valid_policy(max_file_size=bad), "max_file_size", "between"
                )

    def test_present_optional_key_cannot_be_an_empty_or_wrong_typed_array(self):
        for key in ("blocked_patterns", "required_json_fields", "allowed_extensions"):
            with self.subTest(key=key, case="empty"):
                self.assert_rejected(self.valid_policy(**{key: []}), key, "must not be empty")
            with self.subTest(key=key, case="wrong type"):
                self.assert_rejected(self.valid_policy(**{key: "x"}), key, "array of strings")
            with self.subTest(key=key, case="non-string member"):
                self.assert_rejected(self.valid_policy(**{key: [7]}), f"{key}[0]", "must be a string")
            with self.subTest(key=key, case="empty member"):
                self.assert_rejected(self.valid_policy(**{key: [""]}), f"{key}[0]", "empty string")

    def test_allowed_extensions_must_be_lowercase_and_dotted(self):
        self.assert_rejected(self.valid_policy(allowed_extensions=["json"]), "must start with '.'")
        self.assert_rejected(self.valid_policy(allowed_extensions=[".JSON"]), "must be lowercase")

    def test_uncompilable_regex_is_fatal_at_load_not_at_first_file(self):
        self.assert_rejected(
            self.valid_policy(blocked_patterns=["(unterminated"]),
            "blocked_patterns[0]",
            "not a valid regular expression",
        )

    def test_blocked_patterns_are_precompiled(self):
        policy = self.validator.validate_policy(self.valid_policy(), "rules.json")
        self.assertTrue(all(isinstance(p, re.Pattern) for p in policy["blocked_patterns"]))

    def test_omitting_an_optional_key_disables_only_that_check(self):
        policy = self.validator.validate_policy(
            {"max_file_size": 1024, "reject_symlinks": True}, "rules.json"
        )
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "anything.bin"
            output.write_text("AKIA0123456789ABCDEF")
            is_valid, reason = self.validator.validate_file(output, policy)
        self.assertTrue(is_valid, reason)


class ValidatorStartupTests(unittest.TestCase):
    """Fail-closed at the process boundary: a malformed policy must stop the
    validator before it reports itself ready to watch."""

    def run_validator(self, policy_text: str, *extra_args: str):
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            policy = workdir / "rules.json"
            policy.write_text(policy_text)
            outbox = workdir / "outbox"
            outbox.mkdir()
            return subprocess.run(
                [sys.executable, str(VALIDATOR_PATH), str(outbox), "--watch",
                 "--rules", str(policy), *extra_args],
                capture_output=True,
                text=True,
                timeout=30,
            )

    def test_malformed_field_schema_refuses_to_start(self):
        # Exactly the reported trigger: documented boolean replaced by null.
        result = self.run_validator(
            json.dumps({"max_file_size": 1024, "reject_symlinks": None})
        )
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertNotIn("Watching", result.stdout)
        self.assertIn("POLICY ERROR", result.stderr)
        self.assertIn("reject_symlinks", result.stderr)
        self.assertIn("boolean", result.stderr)

    def test_binary_policy_file_refuses_to_start_with_the_same_exit_code(self):
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            policy = workdir / "rules.json"
            policy.write_bytes(b"\xff\xfe\x00binary")
            outbox = workdir / "outbox"
            outbox.mkdir()
            result = subprocess.run(
                [sys.executable, str(VALIDATOR_PATH), str(outbox), "--watch",
                 "--rules", str(policy)],
                capture_output=True, text=True, timeout=30,
            )
        self.assertEqual(2, result.returncode, result.stderr)
        self.assertNotIn("Watching", result.stdout)
        self.assertIn("POLICY ERROR", result.stderr)
        self.assertNotIn("Traceback", result.stderr)

    def test_missing_and_unparseable_policies_also_refuse_to_start(self):
        for label, policy_text in (
            ("not json", "{not valid json"),
            ("non-object root", "[]"),
            ("unknown key", json.dumps({"max_file_size": 1, "reject_symlinks": True, "typo": 1})),
        ):
            with self.subTest(case=label):
                result = self.run_validator(policy_text)
                self.assertEqual(2, result.returncode, result.stderr)
                self.assertNotIn("Watching", result.stdout)
                self.assertIn("POLICY ERROR", result.stderr)

    def test_valid_policy_still_runs_the_documented_path(self):
        # Positive control: exit 2 above is the schema check, not a broken CLI.
        with tempfile.TemporaryDirectory() as directory:
            workdir = Path(directory)
            policy = workdir / "rules.json"
            policy.write_text(json.dumps({"max_file_size": 1024, "reject_symlinks": True}))
            output = workdir / "result.txt"
            output.write_text("ok")
            result = subprocess.run(
                [sys.executable, str(VALIDATOR_PATH), str(output), "--rules", str(policy)],
                capture_output=True,
                text=True,
                timeout=30,
            )
        self.assertEqual(0, result.returncode, result.stderr)
        self.assertIn("VALID: result.txt", result.stdout)

class ArchivedDocumentationContractTests(unittest.TestCase):
    def test_compose_requires_real_agent_and_uses_json_policy(self):
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertIn("${AGENT_IMAGE:?", compose)
        self.assertIn("${AGENT_COMMAND:?", compose)
        self.assertIn("./config/validation-rules.json:/app/rules.json:ro", compose)
        self.assertIn("--rules /app/rules.json", compose)
        self.assertNotIn("node /app/agent.js", compose)

    def test_validator_networking_is_disabled_not_empty_list(self):
        compose = (ROOT / "docker-compose.yml").read_text()
        empty_networks_key = re.compile(r"^\s*networks:\s*\[\]\s*$", re.MULTILINE)
        self.assertIsNone(empty_networks_key.search(compose))
        self.assertIn('network_mode: "none"', compose)

    def test_readme_has_scoped_archive_claims_and_no_rate_limit_claim(self):
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("proved sound as a containment primitive", readme)
        self.assertNotIn("The agent never touches your host filesystem", readme)
        self.assertNotIn("Every output file is scanned before you see it", readme)
        self.assertNotIn("rate_limit", readme)
        self.assertIn("writable host bind mounts", readme)
        self.assertIn("DNS", readme)
        self.assertIn("observational", readme)

    def test_readme_discloses_non_reproducible_runtime(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("Execution is not reproducible", readme)
        self.assertIn("mutable image tags", readme)

    def test_example_squid_policy_is_marked_reference_only_with_copy_step(self):
        example = (ROOT / "examples" / "openai-agent" / "agent.yml").read_text()
        self.assertIn("REFERENCE ONLY", example)
        self.assertIn("cp examples/openai-agent/squid.conf config/squid.conf", example)
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("operative Squid-policy examples", readme)
        self.assertIn("cp examples/openai-agent/squid.conf config/squid.conf", readme)

    def test_outbox_is_described_as_read_write_not_write_only(self):
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("outbox write-only", readme)
        self.assertIn("read/write host bind mount", readme)
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertNotIn("agent can only read inbox, write outbox", compose)

    def test_readme_egress_claims_are_scoped_and_placeholder_is_disclosed(self):
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("only through supervised channels", readme)
        self.assertNotIn("can only reach domains you approve", readme)
        self.assertNotIn("By default, everything is blocked", readme)
        self.assertIn("placeholder `.example.com`", readme)
        squid = (ROOT / "config" / "squid.conf").read_text()
        self.assertIn("placeholder", squid.lower())

    def test_validator_and_readme_use_observational_not_gate_language(self):
        validator_source = VALIDATOR_PATH.read_text()
        self.assertNotIn("before allowing it through", validator_source)
        self.assertIn("observational, not a gate", validator_source)
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("Scan every file", readme)
        self.assertNotIn("# Agent → Host (validated)", readme)

    def test_readme_does_not_promise_unwired_secret_mounting(self):
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("mounted as Docker secrets", readme)
        self.assertNotIn("mkdir -p inbox outbox logs agent-state secrets", readme)
        self.assertIn("Credential injection is not implemented", readme)

    def test_agent_metadata_is_not_presented_as_compose_policy(self):
        agent_config = (ROOT / "config" / "agent.yml").read_text()
        self.assertIn("metadata", agent_config.lower())
        self.assertIn("not consumed by Docker Compose", agent_config)
        self.assertNotIn("allowed_domains:", agent_config)
        self.assertNotIn("resources:", agent_config)
        self.assertNotIn("validation:", agent_config)

    def test_readme_documents_the_bind_mount_ownership_prerequisite(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("configured container UID/GID", readme)
        self.assertIn("only needs to be readable", readme)
        self.assertIn("sudo chown -R 1000:1000 outbox logs agent-state", readme)
        self.assertIn("setfacl", readme)
        self.assertIn("EACCES", readme)
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertIn("must be writable by this same", compose)

    def test_readme_documents_the_enforced_policy_schema(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn("schema-checked before the validator starts watching", readme)
        self.assertIn("disabled by omitting its key, never by giving it a falsy", readme)
        self.assertIn("POLICY ERROR", readme)
        validator = load_validator()
        for key in validator.POLICY_REQUIRED_KEYS + validator.POLICY_OPTIONAL_KEYS:
            with self.subTest(key=key):
                self.assertIn(f"`{key}`", readme)

    def test_no_published_configuration_advertises_inactive_rate_limit(self):
        paths = [
            ROOT / "config" / "agent.yml",
            ROOT / "config" / "validation-rules.json",
            ROOT / "examples" / "openai-agent" / "agent.yml",
            ROOT / "examples" / "web-scraper" / "agent.yml",
        ]
        for path in paths:
            with self.subTest(path=path):
                self.assertTrue(path.exists(), f"published configuration is missing: {path}")
                self.assertNotIn("rate_limit", path.read_text())


if __name__ == "__main__":
    unittest.main()
