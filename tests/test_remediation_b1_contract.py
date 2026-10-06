"""Regression contracts for the archived template's registry and operator docs."""

import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).absolute().parents[1]
WORKSPACE = ROOT.parents[1]


class RegistryArchiveContractTests(unittest.TestCase):
    def test_f1_registry_matches_archive_without_disabling_authorized_reviews(self):
        registry_path = WORKSPACE / "orchestration/registry/projects/agent-embassy.yaml"
        if not registry_path.exists():
            self.skipTest("workspace registry is not included in this standalone app checkout")
        registry = registry_path.read_text()
        readme = (ROOT / "README.md").read_text().replace("**", "")
        description = (
            "Archived Docker Compose hardening template for running AI agents you broadly trust."
        )

        self.assertRegex(registry, r"(?m)^status:\s*archived\s*$")
        self.assertRegex(registry, r"(?m)^featured:\s*false\s*$")
        description_match = re.search(r'^description:\s*"([^"]*)"\s*$', registry, re.MULTILINE)
        self.assertIsNotNone(description_match, "registry needs a plain quoted description")
        self.assertEqual(description, description_match.group(1))
        self.assertIn(description, readme)
        self.assertNotRegex(description_match.group(1).lower(), r"turnkey|sandbox")

        campaign = json.loads((WORKSPACE / "orchestration/repo-pro-campaign/repos.json").read_text())
        entry = next(repo for repo in campaign["repos"] if repo["name"] == "agent-embassy")
        self.assertIs(entry["archived"], True)
        self.assertIs(entry["review_only"], True)
        self.assertEqual("clear", entry["gate"])
        self.assertIn(
            "No fix, no push, no unarchive without an explicit owner ruling.",
            entry["remediation_path"],
        )


class QuickStartContractTests(unittest.TestCase):
    def setUp(self):
        self.readme = (ROOT / "README.md").read_text()
        self.prose = re.sub(r"\s+", " ", self.readme.lower().replace("**", ""))

    def test_f2_detached_start_requires_the_worker_input_output_contract(self):
        quick_start = self.prose.split("## quick start", 1)[1]
        before_start = quick_start.split("docker compose up -d", 1)[0]
        self.assertRegex(before_start, r"persistent.{0,80}inbox-aware worker")
        self.assertRegex(before_start, r"no task-processing adapter")
        for required in ("/app/inbox", "read-only", "task-001.json", "/app/state", "/app/outbox"):
            with self.subTest(requirement=required):
                self.assertIn(required, before_start)
        self.assertRegex(before_start, r"(?:deduplicat|deduplication)")
        self.assertRegex(before_start, r"(?:durabl|persist).{0,100}(?:complet|task)|(?:complet|task).{0,100}(?:durabl|persist)")
        self.assertRegex(before_start, r"cannot.{0,60}(?:delete|remove|move)")
        self.assertIn("type", before_start)
        self.assertIn("timestamp", before_start)
        self.assertIn("config/validation-rules.json", before_start)

    def test_f2_one_shot_does_not_use_the_service_restart_policy(self):
        self.assertIn("unless-stopped", self.prose)
        self.assertRegex(self.prose, r"restart.{0,100}(?:successful|success|zero|0)")
        self.assertRegex(self.prose, r"repeat.{0,80}(?:api|paid)")
        self.assertIn("one-shot", self.prose)
        self.assertIn("docker compose stop agent", self.readme)
        self.assertIn("docker compose up -d egress-proxy validator", self.readme)
        self.assertRegex(self.readme, r"(?m)^docker compose run --rm --no-deps agent\s*$")
        self.assertRegex(self.prose, r"--rm.{0,100}(?:override|disable|restart)")

    def test_f2_examples_are_metadata_and_do_not_supply_runnable_workers(self):
        self.assertRegex(self.prose, r"examples/.{0,180}metadata")
        self.assertRegex(self.prose, r"(?:not|no).{0,50}runnable.{0,30}(?:agent|worker)")
        example = (ROOT / "examples/openai-agent/agent.yml").read_text().lower()
        self.assertIn("metadata only", example)


class ImageCommandContractTests(unittest.TestCase):
    def test_f4_command_is_documented_as_cmd_override_preserving_entrypoint(self):
        readme = (ROOT / "README.md").read_text()
        compose = (ROOT / "docker-compose.yml").read_text()
        for obsolete in (
            "its real entrypoint",
            "that program's entrypoint inside the image",
            "Entrypoint present inside `AGENT_IMAGE`",
            "must already contain this entrypoint",
            "to an entrypoint present in AGENT_IMAGE",
        ):
            self.assertFalse(obsolete in readme or obsolete in compose, f"obsolete command contract: {obsolete}")
        self.assertTrue(
            re.search(r"CMD.{0,100}override|override.{0,100}CMD", readme),
            "AGENT_COMMAND must be identified as the image CMD override",
        )
        self.assertTrue(
            re.search(r"ENTRYPOINT.{0,100}(?:remains|preserv)|(?:preserv|retain).{0,100}ENTRYPOINT", readme),
            "the existing image ENTRYPOINT must remain in effect",
        )
        self.assertRegex(compose, r"(?m)^    command: \$\{AGENT_COMMAND:\?")
        self.assertIsNone(re.search(r"(?m)^\s*entrypoint:", compose), "do not change Compose startup semantics")

    def test_f4_existing_entrypoint_example_supplies_arguments_without_repeating_executable(self):
        readme = (ROOT / "README.md").read_text()
        self.assertIn('ENTRYPOINT ["/opt/agent/worker"]', readme)
        example = re.search(r"(?m)^AGENT_COMMAND='([^']+)'\s*$", readme)
        self.assertIsNotNone(example, "include a command-arguments example for the image entrypoint")
        self.assertEqual(
            "--inbox /app/inbox --outbox /app/outbox --state /app/state", example.group(1)
        )
        self.assertNotIn("/opt/agent/worker", example.group(1))
        self.assertTrue(
            re.search(r"(?:no|without).{0,20}(?:`)?ENTRYPOINT", readme, re.IGNORECASE),
            "also explain command syntax for an image with no ENTRYPOINT",
        )


if __name__ == "__main__":
    unittest.main()
