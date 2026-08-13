import importlib.util
import json
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


class ArchivedDocumentationContractTests(unittest.TestCase):
    def test_compose_requires_real_agent_and_uses_json_policy(self):
        compose = (ROOT / "docker-compose.yml").read_text()
        self.assertIn("${AGENT_IMAGE:?", compose)
        self.assertIn("${AGENT_COMMAND:?", compose)
        self.assertIn("./config/validation-rules.json:/app/rules.json:ro", compose)
        self.assertIn("--rules /app/rules.json", compose)
        self.assertNotIn("node /app/agent.js", compose)

    def test_readme_has_scoped_archive_claims_and_no_rate_limit_claim(self):
        readme = (ROOT / "README.md").read_text()
        self.assertNotIn("proved sound as a containment primitive", readme)
        self.assertNotIn("The agent never touches your host filesystem", readme)
        self.assertNotIn("Every output file is scanned before you see it", readme)
        self.assertNotIn("rate_limit", readme)
        self.assertIn("writable host bind mounts", readme)
        self.assertIn("DNS", readme)
        self.assertIn("observational", readme)

    def test_agent_metadata_is_not_presented_as_compose_policy(self):
        agent_config = (ROOT / "config" / "agent.yml").read_text()
        self.assertIn("metadata", agent_config.lower())
        self.assertIn("not consumed by Docker Compose", agent_config)
        self.assertNotIn("allowed_domains:", agent_config)
        self.assertNotIn("resources:", agent_config)
        self.assertNotIn("validation:", agent_config)

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
