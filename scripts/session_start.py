#!/usr/bin/env python3
"""Session start checker for Claude Code development sessions.

Provides a comprehensive overview at session start:
- Git repository status
- Recent commits
- Open GitHub issues
- Current project version
- Uncommitted changes

Usage:
    uv run python scripts/session_start.py
"""

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


def get_project_version() -> str:
    """Extract version from pyproject.toml."""
    pyproject = Path("pyproject.toml")
    if not pyproject.exists():
        return "unknown"

    try:
        for line in pyproject.read_text().splitlines():
            if line.startswith("version = "):
                return line.split('"')[1]
    except Exception:
        pass

    return "unknown"


def main() -> int:
    """Run session start checks and display summary."""
    print("=" * 70)
    print("vaultctl Development Session Start")
    print("=" * 70)
    print()

    # 1. Project Version
    version = get_project_version()
    print(f"Current Version: v{version}")
    print()

    # 2. Git Status
    print("Git Status:")
    print("-" * 70)
    returncode, status = run_command(["git", "status", "--short"])
    if returncode == 0:
        if status:
            print(status)
            print()
            print("You have uncommitted changes!")
        else:
            print("Working tree clean")
    else:
        print(f"Error checking git status: {status}")
    print()

    # 3. Current Branch
    returncode, branch = run_command(["git", "branch", "--show-current"])
    if returncode == 0:
        print(f"Current Branch: {branch}")
    print()

    # 4. Recent Commits
    print("Recent Commits (last 3):")
    print("-" * 70)
    returncode, commits = run_command(["git", "log", "--oneline", "--max-count=3", "--decorate"])
    if returncode == 0:
        print(commits if commits else "No commits yet")
    else:
        print(f"Error fetching commits: {commits}")
    print()

    # 5. Open GitHub Issues
    print("Open GitHub Issues:")
    print("-" * 70)
    returncode, issues = run_command(["gh", "issue", "list", "--limit", "5", "--state", "open"])
    if returncode == 0:
        if issues:
            print(issues)
        else:
            print("No open issues")
    else:
        print("Unable to fetch issues (gh CLI not available or not authenticated)")
    print()

    # 6. Latest Release
    print("Latest Release:")
    print("-" * 70)
    returncode, release = run_command(["gh", "release", "list", "--limit", "1"])
    if returncode == 0:
        if release:
            print(release)
        else:
            print("No releases yet")
    else:
        print("Unable to fetch releases")
    print()

    # 7. Reminders
    print("Session Reminders:")
    print("-" * 70)
    print("- Pre-commit hooks will run automatically on commit")
    print("- Check CLAUDE.md for Development Workflow Checklists")
    print("- Use conventional commits (feat/fix/docs/test/chore)")
    print()

    print("=" * 70)
    print("Session start checks complete. Ready to code!")
    print("=" * 70)
    print()

    return 0


if __name__ == "__main__":
    sys.exit(main())
