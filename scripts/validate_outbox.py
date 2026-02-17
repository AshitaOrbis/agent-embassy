#!/usr/bin/env python3
"""
Agent Embassy - Output Validator

Watches the outbox directory for new files from the sandboxed agent.
Validates each file against configurable rules before allowing it through.

Rejected files are moved to outbox/rejected/ with a rejection report.
"""

import argparse
import json
import os
import re
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

try:
    import yaml
    HAS_YAML = True
except ImportError:
    HAS_YAML = False


def load_rules(rules_path: str) -> dict:
    """Load validation rules from YAML or use defaults."""
    defaults = {
        "max_file_size": 5 * 1024 * 1024,
        "rate_limit": 10,
        "reject_symlinks": True,
        "blocked_patterns": [
            r"-----BEGIN.*PRIVATE KEY-----",
            r"sk-[a-zA-Z0-9]{48}",
            r"AKIA[0-9A-Z]{16}",
        ],
        "required_json_fields": [],
        "allowed_extensions": [".json", ".md", ".txt", ".csv"],
    }

    if not os.path.exists(rules_path):
        return defaults

    if HAS_YAML:
        with open(rules_path) as f:
            rules = yaml.safe_load(f) or {}
        return {**defaults, **rules}

    # Fallback: try JSON
    try:
        with open(rules_path) as f:
            rules = json.load(f)
        return {**defaults, **rules}
    except (json.JSONDecodeError, ValueError):
        print(f"Warning: Could not parse {rules_path}, using defaults")
        return defaults


def validate_file(filepath: Path, rules: dict) -> tuple[bool, str]:
    """Validate a single file. Returns (is_valid, reason)."""

    # Check symlinks
    if rules["reject_symlinks"] and filepath.is_symlink():
        return False, "Symlink detected (potential path traversal)"

    # Check file size
    size = filepath.stat().st_size
    if size > rules["max_file_size"]:
        return False, f"File too large: {size} bytes (max {rules['max_file_size']})"

    # Check extension
    if rules.get("allowed_extensions"):
        if filepath.suffix.lower() not in rules["allowed_extensions"]:
            return False, f"Disallowed extension: {filepath.suffix}"

    # Check content for blocked patterns
    try:
        content = filepath.read_text(errors="replace")
    except Exception as e:
        return False, f"Cannot read file: {e}"

    for pattern in rules.get("blocked_patterns", []):
        if re.search(pattern, content):
            return False, f"Blocked pattern detected: {pattern}"

    # Check required JSON fields
    if filepath.suffix == ".json" and rules.get("required_json_fields"):
        try:
            data = json.loads(content)
            for field in rules["required_json_fields"]:
                if field not in data:
                    return False, f"Missing required JSON field: {field}"
        except json.JSONDecodeError:
            return False, "Invalid JSON"

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
    parser.add_argument("--rules", default="/app/rules.yml", help="Path to validation rules")
    parser.add_argument("--reject-dir", default=None, help="Directory for rejected files")
    args = parser.parse_args()

    path = Path(args.path) if args.path else Path("/app/outbox")
    rules = load_rules(args.rules)
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
