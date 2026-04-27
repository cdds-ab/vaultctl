"""Tests for vaultctl.config module."""

from __future__ import annotations

from pathlib import Path

import yaml
from vaultctl.config import find_config, load_config


def _write_config(root: Path, payload: str) -> Path:
    """Write a config under the conventional .vaultctl/config.yml layout."""
    config_dir = root / ".vaultctl"
    config_dir.mkdir(exist_ok=True)
    cfg = config_dir / "config.yml"
    cfg.write_text(payload)
    return cfg


def test_find_config_in_cwd(tmp_path, monkeypatch):
    cfg = _write_config(tmp_path, "vault_file: vault.yml\n")
    monkeypatch.chdir(tmp_path)
    assert find_config() == cfg


def test_find_config_walks_up_to_git_root(tmp_path, monkeypatch):
    cfg = _write_config(tmp_path, "vault_file: vault.yml\n")
    nested = tmp_path / "sub" / "deep"
    nested.mkdir(parents=True)
    monkeypatch.chdir(nested)
    assert find_config() == cfg


def test_find_config_env_variable(tmp_path, monkeypatch):
    cfg = tmp_path / "custom-config.yml"
    cfg.write_text("vault_file: vault.yml\n")
    monkeypatch.setenv("VAULTCTL_CONFIG", str(cfg))
    found = find_config()
    assert found == cfg


def test_find_config_returns_none(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VAULTCTL_CONFIG", raising=False)
    # No config anywhere
    assert find_config(tmp_path) is None


def test_find_config_user_global(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("VAULTCTL_CONFIG", raising=False)
    user_cfg = Path.home() / ".config" / "vaultctl" / "config.yml"
    if user_cfg.exists():
        found = find_config(tmp_path)
        assert found == user_cfg


def test_load_config_resolves_paths_relative_to_project_root(tmp_path):
    cfg_data = {
        "vault_file": "data/vault.yml",
        "keys_file": "data/keys.yml",
        "password": {
            "env": "MY_PASS",
            "file": "~/.vault-pass",
            "cmd": "pass show vault",
        },
    }
    cfg_path = _write_config(tmp_path, yaml.dump(cfg_data))

    config = load_config(cfg_path)
    # Paths resolve from the project root (parent of .vaultctl/), not from
    # inside .vaultctl/ — keeps vault.yml/vault-keys.yml at their natural
    # location next to inventory data.
    assert config.vault_file == tmp_path / "data" / "vault.yml"
    assert config.keys_file == tmp_path / "data" / "keys.yml"
    assert config.password.env == "MY_PASS"
    assert config.password.file == str(Path("~/.vault-pass").expanduser())
    assert config.password.cmd == "pass show vault"


def test_load_config_defaults(tmp_path):
    cfg_path = _write_config(tmp_path, "{}\n")
    config = load_config(cfg_path)
    assert config.vault_file == tmp_path / "vault.yml"
    assert config.keys_file == tmp_path / "vault-keys.yml"


def test_load_config_explicit_path_resolves_from_file_dir(tmp_path):
    """For --config <arbitrary-path>, paths resolve from the file's own dir."""
    cfg_path = tmp_path / "standalone.yml"
    cfg_path.write_text("vault_file: vault.yml\n")
    config = load_config(cfg_path)
    assert config.vault_file == tmp_path / "vault.yml"
