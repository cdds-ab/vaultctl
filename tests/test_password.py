"""Tests for vaultctl.password module."""

from __future__ import annotations

import pytest
from vaultctl.config import PasswordConfig
from vaultctl.password import PasswordError, resolve_password


def test_resolve_from_env(monkeypatch):
    monkeypatch.setenv("TEST_VAULT_PW", "secret123")
    cfg = PasswordConfig(env="TEST_VAULT_PW")
    assert resolve_password(cfg) == "secret123"


def test_resolve_from_file(tmp_path):
    pf = tmp_path / "vault-pass"
    pf.write_text("file-password\n")
    cfg = PasswordConfig(file=str(pf))
    assert resolve_password(cfg) == "file-password"


def test_resolve_from_cmd():
    cfg = PasswordConfig(cmd="echo cmd-password")
    assert resolve_password(cfg) == "cmd-password"


def test_resolve_fallback_order(tmp_path, monkeypatch):
    """Env takes precedence over file and cmd."""
    pf = tmp_path / "vault-pass"
    pf.write_text("file-pw")
    monkeypatch.setenv("PRIO_TEST", "env-pw")
    cfg = PasswordConfig(env="PRIO_TEST", file=str(pf), cmd="echo cmd-pw")
    assert resolve_password(cfg) == "env-pw"


def test_resolve_file_fallback_when_env_unset(tmp_path, monkeypatch):
    monkeypatch.delenv("MISSING_VAR", raising=False)
    pf = tmp_path / "vault-pass"
    pf.write_text("fallback-pw")
    cfg = PasswordConfig(env="MISSING_VAR", file=str(pf))
    assert resolve_password(cfg) == "fallback-pw"


def test_empty_env_var_falls_through(tmp_path, monkeypatch):
    """VAULT_PASS="" should be treated as unset and fall through to file."""
    monkeypatch.setenv("VAULT_PASS", "")
    pf = tmp_path / "vault-pass"
    pf.write_text("file-password")
    cfg = PasswordConfig(env="VAULT_PASS", file=str(pf))
    assert resolve_password(cfg) == "file-password"


def test_resolve_raises_when_nothing_configured():
    cfg = PasswordConfig()
    with pytest.raises(PasswordError, match="no sources configured"):
        resolve_password(cfg)


def test_resolve_raises_with_details(monkeypatch):
    monkeypatch.delenv("NONEXISTENT", raising=False)
    cfg = PasswordConfig(env="NONEXISTENT", file="/nonexistent/path")
    with pytest.raises(PasswordError, match="NONEXISTENT"):
        resolve_password(cfg)
