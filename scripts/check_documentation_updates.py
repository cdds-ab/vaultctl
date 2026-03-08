#!/usr/bin/env python3
"""Pre-commit hook to remind about documentation updates.

Analyzes staged files and commit messages to determine if documentation
updates might be needed. Provides helpful reminders but does not block
commits (exits with 0).

Usage:
    Called automatically by pre-commit hook
    Manual: python scripts/check_documentation_updates.py
"""

from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path


def run_command(cmd: list[str]) -> tuple[int, str]:
    """Run a shell command and return exit code and output."""
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            check=False,
        )
        return result.returncode, result.stdout.strip()
    except Exception as e:
        return 1, str(e)


def get_staged_files() -> list[str]:
    """Get list of staged files."""
    returncode, output = run_command(["git", "diff", "--cached", "--name-only"])
    if returncode == 0 and output:
        return output.splitlines()
    return []


def get_commit_message_type() -> str | None:
    """Extract commit type from commit message if available."""
    commit_msg_file = Path(".git/COMMIT_EDITMSG")
    try:
        if commit_msg_file.exists():
            with commit_msg_file.open() as f:
                first_line = f.readline().strip()
                match = re.match(r"^(\w+)(?:\([^)]+\))?:", first_line)
                if match:
                    return match.group(1)
    except Exception:
        pass
    return None


def main() -> int:
    """Check for documentation update needs and print reminders."""
    staged_files = get_staged_files()

    if not staged_files:
        return 0

    reminders: list[str] = []

    # Check: CLI changed?
    cli_changed = any("vaultctl/cli" in f for f in staged_files)
    if cli_changed:
        reminders.append("CLI commands changed")
        reminders.append("   -> Consider updating README.md")
        reminders.append("")

    # Check: Core modules changed?
    core_changed = any(
        any(mod in f for mod in ["vaultctl/vault", "vaultctl/keys", "vaultctl/password", "vaultctl/config"])
        for f in staged_files
    )
    if core_changed:
        reminders.append("INFO: Core logic changed")
        reminders.append("   -> Consider updating CLAUDE.md if significant")
        reminders.append("")

    # Check: Tests changed?
    tests_changed = any("tests/" in f for f in staged_files)
    if tests_changed:
        reminders.append("INFO: Tests changed")
        reminders.append("   -> Run: uv run pytest --cov to verify coverage")
        reminders.append("")

    # Check commit type
    commit_type = get_commit_message_type()

    if commit_type == "feat":
        reminders.append("New feature detected (feat:)")
        reminders.append("   -> Update README.md if user-facing feature")
        reminders.append("   -> Update CLAUDE.md if architectural change")
        reminders.append("")

    elif commit_type == "fix":
        reminders.append("Bug fix detected (fix:)")
        reminders.append("")

    # Check: README changed?
    readme_changed = any("README.md" in f for f in staged_files)
    if readme_changed:
        reminders.append("README.md updated")
        reminders.append("")

    # Print reminders if any
    if reminders:
        print()
        print("=" * 70)
        print("Documentation Update Reminders")
        print("=" * 70)
        print()
        for reminder in reminders:
            print(reminder)
        print("=" * 70)
        print("INFO: These are reminders only - commit will proceed")
        print("=" * 70)
        print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
