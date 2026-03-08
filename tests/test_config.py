"""Tests for vaultctl.config module."""

from __future__ import annotations

from pathlib import Path

import yaml
from vaultctl.config import find_config, load_config


def test_find_config_in_cwd(tmp_path, monkeypatch):
    cfg = tmp_path / ".vaultctl.yml"
    cfg.write_text("vault_file: vault.yml\n")
    monkeypatch.chdir(tmp_path)
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


def test_load_config_resolves_paths(tmp_path):
    cfg_data = {
        "vault_file": "data/vault.yml",
        "keys_file": "data/keys.yml",
        "password": {
            "env": "MY_PASS",
            "file": "~/.vault-pass",
            "cmd": "pass show vault",
        },
    }
    cfg_path = tmp_path / ".vaultctl.yml"
    cfg_path.write_text(yaml.dump(cfg_data))

    config = load_config(cfg_path)
    assert config.vault_file == tmp_path / "data" / "vault.yml"
    assert config.keys_file == tmp_path / "data" / "keys.yml"
    assert config.password.env == "MY_PASS"
    assert config.password.file == str(Path("~/.vault-pass").expanduser())
    assert config.password.cmd == "pass show vault"


def test_load_config_defaults(tmp_path):
    cfg_path = tmp_path / ".vaultctl.yml"
    cfg_path.write_text("{}\n")
    config = load_config(cfg_path)
    assert config.vault_file == tmp_path / "vault.yml"
    assert config.keys_file == tmp_path / "vault-keys.yml"
