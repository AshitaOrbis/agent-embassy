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



class RegexCompilerLimitsTest(unittest.TestCase):
    """A policy the regex compiler REFUSES must still fail the documented way.

    agent-policy_regex_diagnostic_02 (Astra Pro dive 2026-09-05): the compiler
    boundary caught only `re.error`, and main() catches only (OSError, ValueError),
    so the compiler's own limit failures — plain builtins, not re.error — escaped
    BOTH handlers and produced a traceback with exit 1 instead of the documented
    "POLICY ERROR: ... exit 2" contract in README.md. Reproduced on CPython 3.12:
    a{4294967296} raised OverflowError, and 1000 nested groups raised RecursionError.
    """

    def _run(self, pattern):
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            outbox = tmp / "outbox"
            outbox.mkdir()
            rules = tmp / "policy.json"
            rules.write_text(json.dumps({
                "max_file_size": 1024,
                "reject_symlinks": True,
                "blocked_patterns": [pattern],
            }))
            return subprocess.run(
                [sys.executable, str(VALIDATOR_PATH), "--watch", "--rules", str(rules), str(outbox)],
                capture_output=True, text=True, timeout=120,
            )

    def test_repetition_count_overflow_is_a_policy_error(self):
        r = self._run("a{4294967296}")
        self.assertEqual(r.returncode, 2, r.stderr[-400:])
        self.assertIn("POLICY ERROR", r.stderr)
        self.assertIn("blocked_patterns[0]", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_deeply_nested_group_is_a_policy_error(self):
        r = self._run("(" * 1000 + "a" + ")" * 1000)
        self.assertEqual(r.returncode, 2, r.stderr[-400:])
        self.assertIn("POLICY ERROR", r.stderr)
        self.assertNotIn("Traceback", r.stderr)

    def test_an_ordinary_invalid_pattern_still_reports_the_same_way(self):
        """Control: the case that already worked must keep working."""
        r = self._run("a[")
        self.assertEqual(r.returncode, 2, r.stderr[-400:])
        self.assertIn("POLICY ERROR", r.stderr)
        self.assertIn("not a valid regular expression", r.stderr)

    def test_a_compilable_pattern_is_still_accepted(self):
        """Control: a valid policy must not be refused by the new handler."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp = Path(tmp)
            rules = tmp / "policy.json"
            rules.write_text(json.dumps({
                "max_file_size": 1024, "reject_symlinks": True,
                "blocked_patterns": ["secret[0-9]+"],
            }))
            module = load_validator()
            loaded = module.load_rules(str(rules))
            self.assertEqual(len(loaded["blocked_patterns"]), 1)



class OwnershipQuarantineRecipeTests(unittest.TestCase):
    """Execute the documented shell with offline Compose/sleep substitutes.

    The substitutes run the actual shell write command and actual validator scan
    in synthetic directories. They do not exercise Docker, UID maps or a watcher.
    """

    def setUp(self):
        self.prepare_fixture()

    def prepare_fixture(self):
        self.storage = tempfile.TemporaryDirectory(prefix="embassy recipe ")
        self.addCleanup(self.storage.cleanup)
        self.work = Path(self.storage.name)
        for name in ("bin", "home", "tmp", "outbox/rejected", "logs", "agent-state"):
            (self.work / name).mkdir(parents=True)
        section = (ROOT / "README.md").read_text().split(
            "Then **verify with a real write and a real quarantine", 1
        )[1].split("\n## Configuration", 1)[0]
        match = re.search(r"(?ms)^> ```bash\n(.*?)^> ```", section)
        self.assertIsNotNone(match, "ownership recipe must remain an executable Bash fence")
        self.recipe = "\n".join(
            line[2:] if line.startswith("> ") else line[1:]
            for line in match.group(1).splitlines()
        )
        shim = r'''import importlib.util
import json
from pathlib import Path
import shlex
import shutil
import subprocess
import sys

root = Path(__file__).resolve().parents[1]
mode = (root / "mode").read_text()
with (root / "calls.txt").open("a") as log:
    log.write(Path(sys.argv[0]).name + " " + " ".join(sys.argv[1:3]) + "\n")
child_env = {
    "HOME": str(root / "home"), "PATH": "/usr/bin:/bin",
    "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
    "TMPDIR": str(root / "tmp"), "PYTHONDONTWRITEBYTECODE": "1",
}
if Path(sys.argv[0]).name == "docker":
    args = sys.argv[1:]
    if args == ["compose", "up", "-d", "validator"]:
        sys.exit(7 if mode == "startup-failure" else 0)
    if args == ["compose", "logs", "validator"]:
        print("synthetic validator diagnostics")
        sys.exit(0)
    if args[:2] != ["compose", "run"] or args[-3:-1] != ["sh", "-c"]:
        raise SystemExit("unexpected offline Docker invocation")
    if mode == "write-failure":
        sys.exit(9)
    command = args[-1]
    for inside, outside in [
        ("/app/outbox", root / "outbox"),
        ("/w/logs", root / "logs"),
        ("/w/state", root / "agent-state"),
    ]:
        command = command.replace(inside, shlex.quote(str(outside)))
    assert "/app/" not in command and "/w/" not in command
    result = subprocess.run(["/bin/sh", "-c", command], cwd=root,
                            env=child_env, timeout=5)
    sys.exit(result.returncode)

assert Path(sys.argv[0]).name == "sleep" and sys.argv[1:] == ["5"]
source = root / "outbox/ownership-check.bin"
payload = root / "outbox/rejected/ownership-check.bin"
report = root / "outbox/rejected/ownership-check.rejection.json"
if mode == "normal":
    spec = importlib.util.spec_from_file_location("recipe_validator", __VALIDATOR__)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rules = module.load_rules(__POLICY__)
    module.scan_once(root / "outbox", rules, root / "outbox/rejected")
elif mode == "policy-invalid":
    result = subprocess.run(
        [sys.executable, "-I", "-B", __VALIDATOR__, str(root / "outbox"),
         "--watch", "--rules", str(root / "bad-policy.json")],
        cwd=root, env=child_env, capture_output=True, timeout=5,
    )
    assert result.returncode == 2 and b"POLICY ERROR" in result.stderr
elif mode == "payload-only":
    shutil.move(source, payload)
elif mode in ("report-only", "source-remains", "payload-link", "report-link"):
    report.write_text(json.dumps({"file": source.name, "reason": "synthetic"}))
    if mode != "report-only":
        shutil.copyfile(source, payload)
    if mode != "source-remains":
        source.unlink()
    if mode == "payload-link":
        payload.unlink()
        payload.symlink_to(root / "witness")
    if mode == "report-link":
        report.unlink()
        report.symlink_to(root / "witness")
else:
    assert mode == "inactive", mode
'''
        shim = shim.replace("__VALIDATOR__", repr(str(VALIDATOR_PATH)))
        shim = shim.replace("__POLICY__", repr(str(ROOT / "config/validation-rules.json")))
        for name in ("docker", "sleep"):
            command = self.work / "bin" / name
            command.write_text("#!" + sys.executable + " -B\n" + shim)
            command.chmod(0o700)
        (self.work / "witness").write_bytes(b"synthetic witness")
        (self.work / "bad-policy.json").write_text("{}")

    def run_recipe(self, mode):
        (self.work / "mode").write_text(mode)
        return subprocess.run(
            ["/bin/bash", "--noprofile", "--norc", "-c", self.recipe],
            cwd=self.work, env={
                "HOME": str(self.work / "home"),
                "PATH": str(self.work / "bin") + ":/usr/bin:/bin",
                "LANG": "C.UTF-8", "LC_ALL": "C.UTF-8",
                "TMPDIR": str(self.work / "tmp"), "PYTHONDONTWRITEBYTECODE": "1",
            }, capture_output=True, text=True, timeout=10,
        )

    def test_stale_probe_entries_refuse_before_starting_and_preserve_evidence(self):
        for relative in ("outbox/ownership-check.bin",
                         "outbox/rejected/ownership-check.bin",
                         "outbox/rejected/ownership-check.rejection.json"):
            for kind in ("file", "directory", "link", "dangling-link"):
                with self.subTest(path=relative, kind=kind):
                    self.prepare_fixture()
                    path = self.work / relative
                    if kind == "file":
                        path.write_bytes(b"previous synthetic evidence")
                    elif kind == "directory":
                        path.mkdir()
                    else:
                        path.symlink_to(self.work / ("witness" if kind == "link" else "absent"))
                    result = self.run_recipe("inactive")
                    self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                    self.assertFalse((self.work / "calls.txt").exists(), "preflight must precede Docker")
                    if kind == "file":
                        self.assertEqual(b"previous synthetic evidence", path.read_bytes())
                    elif kind == "directory":
                        self.assertTrue(path.is_dir())
                    else:
                        self.assertTrue(path.is_symlink())
                        self.assertEqual(self.work / ("witness" if kind == "link" else "absent"), path.readlink())
                    if kind == "directory":
                        path.rmdir()
                    else:
                        path.unlink()

    def test_fresh_scan_succeeds_with_current_payload_and_associated_report(self):
        sentinel = self.work / "outbox/rejected/ownership-check.keep"
        sentinel.write_bytes(b"keep unrelated evidence")
        result = self.run_recipe("normal")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("Fresh quarantine observed", result.stdout)
        self.assertFalse((self.work / "outbox/ownership-check.bin").exists())
        self.assertEqual(b"x", (self.work / "outbox/rejected/ownership-check.bin").read_bytes())
        report = json.loads((self.work / "outbox/rejected/ownership-check.rejection.json").read_text())
        self.assertEqual("ownership-check.bin", report["file"])
        self.assertIn("Disallowed extension", report["reason"])
        self.assertEqual(b"keep unrelated evidence", sentinel.read_bytes())

    def test_inactive_validator_does_not_turn_successful_writes_into_quarantine_success(self):
        result = self.run_recipe("inactive")
        self.assertIn("writes-ok", result.stdout)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn("Fresh quarantine observed", result.stdout)
        self.assertEqual(b"x", (self.work / "outbox/ownership-check.bin").read_bytes())

    def test_invalid_policy_does_not_turn_successful_writes_into_quarantine_success(self):
        result = self.run_recipe("policy-invalid")
        self.assertIn("writes-ok", result.stdout)
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn("Fresh quarantine observed", result.stdout)
        self.assertTrue((self.work / "outbox/ownership-check.bin").exists())

    def test_partial_quarantine_symlink_artifacts_and_remaining_source_cannot_pass(self):
        for mode in ("payload-only", "report-only", "source-remains", "payload-link", "report-link"):
            with self.subTest(mode=mode):
                self.prepare_fixture()
                result = self.run_recipe(mode)
                self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
                self.assertNotIn("Fresh quarantine observed", result.stdout)
                self.assertEqual(b"synthetic witness", (self.work / "witness").read_bytes())
                for relative in ("outbox/ownership-check.bin", "outbox/rejected/ownership-check.bin",
                                 "outbox/rejected/ownership-check.rejection.json"):
                    path = self.work / relative
                    if path.is_symlink() or path.exists():
                        path.unlink()

    def test_failed_startup_stops_before_the_write_command(self):
        result = self.run_recipe("startup-failure")
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertEqual("docker compose up\n", (self.work / "calls.txt").read_text())
        self.assertFalse((self.work / "outbox/ownership-check.bin").exists())

    def test_failed_write_cannot_be_reported_as_success(self):
        result = self.run_recipe("write-failure")
        self.assertNotEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertNotIn("Fresh quarantine observed", result.stdout)
        self.assertNotIn("sleep", (self.work / "calls.txt").read_text())


if __name__ == "__main__":
    unittest.main()
