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
    infer_vault_schema,
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


# --- schema inference (pure Python, no cue required) ---


def test_infer_renders_primitive_types():
    schema = infer_vault_schema({"a": "x", "b": 42, "c": True, "d": 3.14})
    # bool MUST come out as bool, not int — Python's isinstance hierarchy quirk.
    assert "a: string" in schema
    assert "b: int" in schema
    assert "c: bool" in schema
    assert "d: number" in schema


def test_infer_skips_previous_backup_keys():
    schema = infer_vault_schema({"live": "x", "live_previous": "old", "other_previous": "y"})
    assert "live" in schema
    assert "_previous" not in schema


def test_infer_renders_nested_dict():
    schema = infer_vault_schema({"creds": {"username": "u", "password": "p"}})
    assert "creds: {" in schema
    assert "username: string" in schema
    assert "password: string" in schema


def test_infer_renders_homogeneous_list():
    schema = infer_vault_schema({"hosts": ["h1", "h2"]})
    assert "hosts: [...string]" in schema


def test_infer_renders_heterogeneous_list_as_disjunction():
    schema = infer_vault_schema({"mixed": ["s", 42]})
    # Sorted: int before string
    assert "[...(int | string)]" in schema


def test_infer_renders_empty_collections():
    schema = infer_vault_schema({"empty_list": [], "empty_dict": {}})
    assert "empty_list: [...]" in schema
    assert "empty_dict: {}" in schema


def test_infer_quotes_keys_with_special_characters():
    schema = infer_vault_schema({"normal_key": "x", "key.with.dots": "y", "key-with-dashes": "z"})
    assert "normal_key: string" in schema
    assert '"key.with.dots": string' in schema
    assert '"key-with-dashes": string' in schema


def test_infer_output_is_deterministic():
    data = {"b": "x", "a": "y", "c": {"z": 1, "y": 2}}
    assert infer_vault_schema(data) == infer_vault_schema(data)


def test_infer_includes_header_and_package():
    schema = infer_vault_schema({"a": "x"})
    assert "AUTO-GENERATED" in schema
    assert "vault.constraints.cue" in schema
    assert "package vaultctl" in schema
    assert "#VaultFile" in schema


def test_infer_handles_empty_vault():
    schema = infer_vault_schema({})
    assert "#VaultFile: {" in schema
    assert "package vaultctl" in schema


@requires_cue
def test_infer_round_trips_through_validate(tmp_path):
    """The inferred schema must accept the same data it was inferred from."""
    data = {
        "token": "x",
        "creds": {"username": "u", "password": "p", "type": "usernamePassword"},
        "hosts": ["h1", "h2"],
        "port": 5432,
        "enabled": True,
    }
    schema_path = tmp_path / "vault.cue"
    schema_path.write_text(infer_vault_schema(data))
    assert validate_vault_data(data, override=schema_path) == []


@requires_cue
def test_infer_produces_closed_schema_that_rejects_new_keys(tmp_path):
    """Inferred schemas must reject keys that weren't in the source data."""
    data = {"a": "x"}
    schema_path = tmp_path / "vault.cue"
    schema_path.write_text(infer_vault_schema(data))
    issues = validate_vault_data({**data, "uninvited": "y"}, override=schema_path)
    assert len(issues) > 0


@requires_cue
def test_infer_merges_with_user_constraints_file(tmp_path):
    """Baseline + constraints.cue should unify — CUE's package merging behavior."""
    data = {"password": "shortpw"}
    baseline = tmp_path / "vault.cue"
    baseline.write_text(infer_vault_schema(data))
    constraints = tmp_path / "vault.constraints.cue"
    # Same package, additional constraint: password must be at least 12 chars.
    constraints.write_text('package vaultctl\n#VaultFile: password: =~"^.{12,}$"\n')

    # Use the baseline path as the schema — cue vet will pick up sibling files
    # in the same directory automatically when they share the package.
    issues = validate_vault_data(data, override=baseline)
    assert any("password" in i.message for i in issues), "expected merged constraint to reject the short password"
