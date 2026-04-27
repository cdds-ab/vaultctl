"""Tests for vaultctl.schema module."""

from __future__ import annotations

import shutil

import pytest
import yaml
from vaultctl.schema import (
    bundled_schema,
    cross_check_keys,
    cue_available,
    discover_user_schema,
    validate_config_file,
    validate_keys_file,
    validate_vault_data,
)

requires_cue = pytest.mark.skipif(not shutil.which("cue"), reason="cue binary not installed")


# --- module-level helpers (no cue required) ---


def test_cue_available_returns_bool():
    assert isinstance(cue_available(), bool)


def test_bundled_schema_returns_paths_for_known_names():
    for name in ("config", "keys", "vault"):
        path = bundled_schema(name)
        assert path.is_file()
        assert path.suffix == ".cue"


def test_bundled_schema_unknown_name_raises():
    from vaultctl.schema import SchemaError

    with pytest.raises(SchemaError):
        bundled_schema("nonexistent")


def test_discover_user_schema_returns_none_when_absent(tmp_path):
    assert discover_user_schema(tmp_path, "vault") is None


def test_discover_user_schema_returns_path_when_present(tmp_path):
    cue_dir = tmp_path / ".vaultctl"
    cue_dir.mkdir()
    custom = cue_dir / "vault.cue"
    custom.write_text("package vaultctl\n#VaultFile: { ... }\n")
    assert discover_user_schema(tmp_path, "vault") == custom


# --- cross_check_keys (pure Python, always runs) ---


def test_cross_check_keys_no_issues_when_aligned():
    vault_data = {"a": "1", "b": "2"}
    keys_meta = {"vault_keys": {"a": {}, "b": {}}}
    assert cross_check_keys(vault_data, keys_meta) == []


def test_cross_check_keys_detects_value_without_metadata():
    vault_data = {"a": "1", "orphan": "x"}
    keys_meta = {"vault_keys": {"a": {}}}
    issues = cross_check_keys(vault_data, keys_meta)
    assert len(issues) == 1
    assert "orphan" in issues[0].message
    assert "no metadata" in issues[0].message


def test_cross_check_keys_detects_metadata_without_value():
    vault_data = {"a": "1"}
    keys_meta = {"vault_keys": {"a": {}, "stale": {}}}
    issues = cross_check_keys(vault_data, keys_meta)
    assert len(issues) == 1
    assert "stale" in issues[0].message
    assert "no value" in issues[0].message


def test_cross_check_keys_ignores_previous_backup_keys():
    vault_data = {"a": "1", "a_previous": "old"}
    keys_meta = {"vault_keys": {"a": {}}}
    assert cross_check_keys(vault_data, keys_meta) == []


def test_cross_check_keys_handles_missing_vault_keys_section():
    vault_data = {"a": "1"}
    keys_meta = {}
    issues = cross_check_keys(vault_data, keys_meta)
    assert len(issues) == 1
    assert "a" in issues[0].message


# --- CUE-backed validations (require cue binary) ---


@requires_cue
def test_validate_config_file_accepts_valid_config(tmp_path):
    cfg = tmp_path / "config.yml"
    cfg.write_text(
        yaml.dump(
            {
                "vault_file": "vault.yml",
                "keys_file": "vault-keys.yml",
                "password": {"env": "VAULT_PASS"},
            }
        )
    )
    assert validate_config_file(cfg) == []


@requires_cue
def test_validate_config_file_rejects_typo(tmp_path):
    cfg = tmp_path / "config.yml"
    cfg.write_text("vault_file: vault.yml\npasword:\n  env: X\n")
    issues = validate_config_file(cfg)
    assert any("pasword" in i.message for i in issues)


@requires_cue
def test_validate_config_file_rejects_wrong_type(tmp_path):
    cfg = tmp_path / "config.yml"
    # vault_file must be string, not int
    cfg.write_text("vault_file: 123\n")
    issues = validate_config_file(cfg)
    assert len(issues) > 0


@requires_cue
def test_validate_keys_file_accepts_valid_metadata(tmp_path):
    kf = tmp_path / "vault-keys.yml"
    kf.write_text(
        yaml.dump(
            {
                "vault_keys": {
                    "api_token": {
                        "description": "API token",
                        "type": "secretText",
                        "rotate": "365d",
                        "expires": "2026-12-31",
                    }
                }
            }
        )
    )
    assert validate_keys_file(kf) == []


@requires_cue
def test_validate_keys_file_rejects_invalid_type(tmp_path):
    kf = tmp_path / "vault-keys.yml"
    kf.write_text(yaml.dump({"vault_keys": {"k": {"type": "bogusType"}}}))
    issues = validate_keys_file(kf)
    assert any("bogusType" in i.message or "conflicting values" in i.message for i in issues)


@requires_cue
def test_validate_keys_file_rejects_bad_date(tmp_path):
    kf = tmp_path / "vault-keys.yml"
    kf.write_text(yaml.dump({"vault_keys": {"k": {"expires": "tomorrow"}}}))
    issues = validate_keys_file(kf)
    assert len(issues) > 0


@requires_cue
def test_validate_vault_data_accepts_mixed_content():
    data = {
        "plain_string": "value",
        "structured": {"username": "admin", "password": "secret"},
    }
    assert validate_vault_data(data) == []


@requires_cue
def test_validate_keys_file_with_user_override(tmp_path):
    """User-provided schema overrides the bundled one."""
    schema = tmp_path / "strict.cue"
    schema.write_text("package vaultctl\n#KeysFile: {\n    vault_keys: [string]: { description: string }\n}\n")
    kf = tmp_path / "vault-keys.yml"
    # description missing → strict schema should fail
    kf.write_text(yaml.dump({"vault_keys": {"k": {}}}))
    issues = validate_keys_file(kf, override=schema)
    assert len(issues) > 0


# --- importlib.resources path resolution ---


def test_bundled_schema_resolves_via_importlib_resources():
    """Schemas must be discoverable through the package, not just via filesystem."""
    path = bundled_schema("config")
    # The file exists and is readable
    assert path.read_text().startswith("// Schema")
