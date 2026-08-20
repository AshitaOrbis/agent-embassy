#!/usr/bin/env python3
"""
Agent Embassy - Output Validator

Observes top-level, non-hidden files that appear in the outbox directory and
checks them against configurable rules. This is observational, not a gate:
files are checked after they are already present in the shared outbox, can be
consumed or mutated before or without being checked, and directories and
dotfiles are skipped entirely.

Files that fail a check are moved to outbox/rejected/ with a rejection report.
"""

import argparse
import json
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

# Policy schema. Mandatory keys must always be present; an optional key that is
# present must carry a real value. There is no falsy off-switch: to disable an
# optional check, omit its key.
POLICY_REQUIRED_KEYS = ("max_file_size", "reject_symlinks")
POLICY_OPTIONAL_KEYS = ("allowed_extensions", "blocked_patterns", "required_json_fields")

# A max_file_size outside this range is a typo, not a policy.
MAX_FILE_SIZE_CEILING = 1 << 40  # 1 TiB

_JSON_TYPE_NAMES = {
    type(None): "null",
    bool: "boolean",
    int: "number",
    float: "number",
    str: "string",
    list: "array",
    dict: "object",
}


class PolicySchemaError(ValueError):
    """The validation policy does not match the documented schema."""


def _json_type(value) -> str:
    """Name a value using JSON's type vocabulary, for policy error messages."""
    return _JSON_TYPE_NAMES.get(type(value), type(value).__name__)


def validate_policy(rules: dict, rules_path: str = "<policy>") -> dict:
    """Check the complete policy schema and return a normalized policy.

    Fails closed before the watcher starts: every mandatory key must be present
    with the exact JSON type documented in the README, every optional key that
    IS present must be a non-empty array of strings, every blocked pattern must
    compile, and unknown keys are rejected so a misspelled key cannot silently
    disable a check. Returns the policy with `blocked_patterns` precompiled.
    """

    def fail(detail: str):
        raise PolicySchemaError(f"{rules_path}: {detail}")

    unknown = sorted(set(rules) - set(POLICY_REQUIRED_KEYS) - set(POLICY_OPTIONAL_KEYS))
    if unknown:
        fail(f"unknown policy key(s): {', '.join(unknown)}")

    missing = [key for key in POLICY_REQUIRED_KEYS if key not in rules]
    if missing:
        fail(f"missing required policy key(s): {', '.join(missing)}")

    max_file_size = rules["max_file_size"]
    if isinstance(max_file_size, bool) or not isinstance(max_file_size, int):
        fail(
            "max_file_size must be a whole number of bytes, got "
            f"{_json_type(max_file_size)}"
        )
    if not 1 <= max_file_size <= MAX_FILE_SIZE_CEILING:
        fail(
            f"max_file_size must be between 1 and {MAX_FILE_SIZE_CEILING} bytes, "
            f"got {max_file_size}"
        )

    if not isinstance(rules["reject_symlinks"], bool):
        fail(
            "reject_symlinks must be a boolean, got "
            f"{_json_type(rules['reject_symlinks'])}"
        )

    def string_array(key: str) -> list:
        value = rules[key]
        if not isinstance(value, list):
            fail(f"{key} must be an array of strings, got {_json_type(value)}")
        if not value:
            fail(f"{key} must not be empty — omit the key to disable this check")
        for index, item in enumerate(value):
            if not isinstance(item, str):
                fail(f"{key}[{index}] must be a string, got {_json_type(item)}")
            if not item:
                fail(f"{key}[{index}] must not be an empty string")
        return value

    normalized = dict(rules)

    if "allowed_extensions" in rules:
        for index, extension in enumerate(string_array("allowed_extensions")):
            if not extension.startswith("."):
                fail(f"allowed_extensions[{index}] must start with '.', got {extension!r}")
            if extension != extension.lower():
                fail(
                    f"allowed_extensions[{index}] must be lowercase — it is compared "
                    f"against a lowercased file suffix, got {extension!r}"
                )

    if "blocked_patterns" in rules:
        compiled = []
        for index, pattern in enumerate(string_array("blocked_patterns")):
            try:
                compiled.append(re.compile(pattern))
            except re.error as exc:
                raise PolicySchemaError(
                    f"{rules_path}: blocked_patterns[{index}] is not a valid regular "
                    f"expression ({exc}): {pattern!r}"
                ) from exc
        normalized["blocked_patterns"] = compiled

    if "required_json_fields" in rules:
        string_array("required_json_fields")

    return normalized


def load_rules(rules_path: str) -> dict:
    """Load and schema-check the JSON policy, failing closed on any error.

    Returns the normalized policy: `blocked_patterns` holds compiled regular
    expressions, so `validate_file` must be given a policy from this function.
    """
    with open(rules_path) as policy_file:
        rules = json.load(policy_file)
    if not isinstance(rules, dict):
        raise PolicySchemaError(f"Validation policy must be a JSON object: {rules_path}")
    return validate_policy(rules, rules_path)


def validate_file(filepath: Path, rules: dict) -> tuple[bool, str]:
    """Validate a single file against a policy from load_rules.

    Returns (is_valid, reason).
    """

    # Check symlinks
    if rules["reject_symlinks"] and filepath.is_symlink():
        return False, "Symlink detected (potential path traversal)"

    # Check file size
    size = filepath.stat().st_size
    if size > rules["max_file_size"]:
        return False, f"File too large: {size} bytes (max {rules['max_file_size']})"

    # Check extension
    if "allowed_extensions" in rules:
        if filepath.suffix.lower() not in rules["allowed_extensions"]:
            return False, f"Disallowed extension: {filepath.suffix}"

    # Check content for blocked patterns
    try:
        content = filepath.read_text(errors="replace")
    except Exception as e:
        return False, f"Cannot read file: {e}"

    for pattern in rules.get("blocked_patterns", []):
        if pattern.search(content):
            return False, f"Blocked pattern detected: {pattern.pattern}"

    # Check required JSON fields
    if filepath.suffix == ".json" and "required_json_fields" in rules:
        try:
            data = json.loads(content)
        except json.JSONDecodeError:
            return False, "Invalid JSON"
        # Arrays, strings, numbers, booleans, and null have no fields; a
        # non-object here previously passed (array of matching strings) or
        # crashed the watcher (scalar/null TypeError).
        if not isinstance(data, dict):
            return False, f"JSON output must be an object, got {type(data).__name__}"
        for field in rules["required_json_fields"]:
            if field not in data:
                return False, f"Missing required JSON field: {field}"

    return True, "OK"


def reject_file(filepath: Path, reason: str, reject_dir: Path):
    """Move rejected file and create rejection report."""
    reject_dir.mkdir(parents=True, exist_ok=True)

    # Move the file
    dest = reject_dir / filepath.name
    shutil.move(str(filepath), str(dest))

    # Write rejection report
    report = {
        "file": filepath.name,
        "rejected_at": datetime.now(timezone.utc).isoformat(),
        "reason": reason,
    }
    report_path = reject_dir / f"{filepath.stem}.rejection.json"
    report_path.write_text(json.dumps(report, indent=2))

    print(f"REJECTED: {filepath.name} - {reason}")


def scan_once(outbox: Path, rules: dict, reject_dir: Path) -> int:
    """Scan outbox once, validate all files. Returns count of validated files."""
    count = 0
    for filepath in outbox.iterdir():
        if filepath.is_dir():
            continue
        if filepath.name.startswith("."):
            continue

        is_valid, reason = validate_file(filepath, rules)
        if is_valid:
            print(f"VALID: {filepath.name}")
            count += 1
        else:
            reject_file(filepath, reason, reject_dir)

    return count


def watch_loop(outbox: Path, rules: dict, reject_dir: Path, interval: float = 2.0):
    """Poll the outbox directory for new files."""
    seen = set()
    print(f"Watching {outbox} for new files (Ctrl+C to stop)...")

    while True:
        current_files = set()
        for filepath in outbox.iterdir():
            if filepath.is_dir() or filepath.name.startswith("."):
                continue
            current_files.add(filepath.name)

            if filepath.name not in seen:
                is_valid, reason = validate_file(filepath, rules)
                if is_valid:
                    print(f"VALID: {filepath.name}")
                else:
                    reject_file(filepath, reason, reject_dir)

        seen = current_files
        time.sleep(interval)


def main():
    parser = argparse.ArgumentParser(description="Agent Embassy output validator")
    parser.add_argument("path", nargs="?", help="File or directory to validate")
    parser.add_argument("--watch", action="store_true", help="Watch directory for new files")
    parser.add_argument("--rules", default="/app/rules.json", help="Path to validation rules")
    parser.add_argument("--reject-dir", default=None, help="Directory for rejected files")
    args = parser.parse_args()

    path = Path(args.path) if args.path else Path("/app/outbox")
    # Fail closed before anything is watched or validated: a policy that is
    # missing, unreadable, not JSON, or off-schema stops the validator here.
    # ValueError covers PolicySchemaError, json.JSONDecodeError, and the
    # UnicodeDecodeError a non-text policy file raises; OSError covers missing
    # and unreadable ones.
    try:
        rules = load_rules(args.rules)
    except (OSError, ValueError) as exc:
        print(f"POLICY ERROR: {exc}", file=sys.stderr)
        sys.exit(2)
    reject_dir = Path(args.reject_dir) if args.reject_dir else path / "rejected"

    if args.watch or (path.is_dir() and not args.path):
        watch_loop(path, rules, reject_dir)
    elif path.is_dir():
        count = scan_once(path, rules, reject_dir)
        print(f"Validated {count} files")
    elif path.is_file():
        is_valid, reason = validate_file(path, rules)
        if is_valid:
            print(f"VALID: {path.name}")
        else:
            print(f"INVALID: {path.name} - {reason}")
            sys.exit(1)
    else:
        print(f"Path not found: {path}")
        sys.exit(1)


if __name__ == "__main__":
    main()
