"""Integration tests for vaultctl CLI using Click CliRunner."""

from __future__ import annotations

import shutil

import pytest
from click.testing import CliRunner
from vaultctl.cli import main

pytestmark = pytest.mark.skipif(
    not shutil.which("ansible-vault"),
    reason="ansible-vault not installed",
)

PASS = "test-vault-password-12345"


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def cli_env(config_file, vault_file, monkeypatch):
    """Set up environment for CLI tests."""
    monkeypatch.setenv("VAULTCTL_CONFIG", str(config_file))
    monkeypatch.setenv("VAULTCTL_TEST_PASS", PASS)
    return config_file


def test_list(runner, cli_env):
    result = runner.invoke(main, ["list"])
    assert result.exit_code == 0
    assert "test_key" in result.output
    assert "another_key" in result.output


def test_get(runner, cli_env):
    result = runner.invoke(main, ["get", "test_key"])
    assert result.exit_code == 0
    assert "test_value" in result.output


def test_get_missing_key(runner, cli_env):
    result = runner.invoke(main, ["get", "nonexistent"])
    assert result.exit_code == 1
    assert "not found in vault" in result.output


def test_set_new_key(runner, cli_env):
    result = runner.invoke(main, ["set", "new_key", "new_value", "--force", "--no-backup"])
    assert result.exit_code == 0
    assert "Added" in result.output

    # Verify
    result = runner.invoke(main, ["get", "new_key"])
    assert result.exit_code == 0
    assert "new_value" in result.output


def test_set_existing_key_with_backup(runner, cli_env):
    result = runner.invoke(main, ["set", "test_key", "updated", "--force"])
    assert result.exit_code == 0
    assert "Backup" in result.output

    # Verify backup
    result = runner.invoke(main, ["get", "test_key_previous"])
    assert result.exit_code == 0
    assert "test_value" in result.output


def test_set_idempotent(runner, cli_env):
    result = runner.invoke(main, ["set", "test_key", "test_value", "--force"])
    assert result.exit_code == 0
    assert "Unchanged" in result.output


def test_delete(runner, cli_env):
    result = runner.invoke(main, ["delete", "test_key", "--force"])
    assert result.exit_code == 0
    assert "Deleted" in result.output

    # Verify
    result = runner.invoke(main, ["get", "test_key"])
    assert result.exit_code == 1


def test_delete_missing_key(runner, cli_env):
    result = runner.invoke(main, ["delete", "nonexistent", "--force"])
    assert result.exit_code == 1


def test_describe(runner, cli_env):
    result = runner.invoke(main, ["describe", "test_key"])
    assert result.exit_code == 0
    assert "A test key" in result.output
    assert "365d" in result.output
    assert "host01" in result.output


def test_describe_missing(runner, cli_env):
    result = runner.invoke(main, ["describe", "nonexistent"])
    assert result.exit_code == 1
    assert "No metadata" in result.output


def test_restore(runner, cli_env):
    result = runner.invoke(main, ["restore", "restore_key", "--force"])
    assert result.exit_code == 0
    assert "Restored" in result.output

    # Verify swap
    result = runner.invoke(main, ["get", "restore_key"])
    assert "old_value" in result.output

    result = runner.invoke(main, ["get", "restore_key_previous"])
    assert "current_value" in result.output


def test_restore_no_previous(runner, cli_env):
    result = runner.invoke(main, ["restore", "another_key", "--force"])
    assert result.exit_code == 1
    assert "not found in vault" in result.output


def test_check(runner, cli_env):
    result = runner.invoke(main, ["check"])
    assert result.exit_code == 1  # expired_key should trigger exit 1
    assert "expired_key" in result.output
    assert "expiring_key" in result.output


def test_check_json(runner, cli_env):
    result = runner.invoke(main, ["check", "--json"])
    assert result.exit_code == 1
    import json

    data = json.loads(result.output)
    keys = [d["key"] for d in data]
    assert "expired_key" in keys


def test_check_quiet(runner, cli_env):
    result = runner.invoke(main, ["check", "--quiet"])
    assert result.exit_code == 1
    assert result.output == ""


def test_set_with_expires(runner, cli_env):
    result = runner.invoke(
        main,
        [
            "set",
            "test_key",
            "new_val",
            "--force",
            "--expires",
            "2026-12-31",
        ],
    )
    assert result.exit_code == 0

    # Check metadata was updated
    result = runner.invoke(main, ["describe", "test_key"])
    assert "2026-12-31" in result.output


def test_version(runner):
    result = runner.invoke(main, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output
