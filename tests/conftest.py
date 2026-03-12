"""Shared fixtures for vaultctl tests."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

import pytest
import yaml

TEST_PASSWORD = "test-vault-password-12345"


@pytest.fixture
def tmp_dir(tmp_path):
    """Return a temporary directory as Path."""
    return tmp_path


@pytest.fixture
def vault_password():
    """Return the test vault password."""
    return TEST_PASSWORD


@pytest.fixture
def password_file(tmp_path):
    """Create a temporary password file."""
    pf = tmp_path / "vault-pass"
    pf.write_text(TEST_PASSWORD)
    return pf


@pytest.fixture
def vault_file(tmp_path):
    """Create an encrypted vault file with test data."""
    data = {
        "test_key": "test_value",
        "another_key": "another_value",
        "restore_key": "current_value",
        "restore_key_previous": "old_value",
        "db_creds": {
            "type": "usernamePassword",
            "username": "admin",
            "password": "s3cret",
        },
        "untyped_creds": {
            "username": "deploy",
            "password": "d3ploy",
        },
    }
    plain = tmp_path / "vault-plain.yml"
    encrypted = tmp_path / "vault.yml"
    plain.write_text(yaml.dump(data, default_flow_style=False))

    pf_fd, pf_name = tempfile.mkstemp(suffix=".pass")
    os.fchmod(pf_fd, 0o600)
    try:
        with os.fdopen(pf_fd, "w") as pf:
            pf.write(TEST_PASSWORD)
            pf.flush()
            subprocess.run(
                [
                    "ansible-vault",
                    "encrypt",
                    str(plain),
                    "--output",
                    str(encrypted),
                    "--vault-password-file",
                    pf_name,
                ],
                check=True,
                capture_output=True,
            )
    finally:
        Path(pf_name).unlink(missing_ok=True)
    plain.unlink()
    return encrypted


@pytest.fixture
def keys_file(tmp_path):
    """Create a test vault-keys.yml."""
    data = {
        "vault_keys": {
            "test_key": {
                "description": "A test key",
                "rotate": "365d",
                "consumers": ["host01", "host02"],
                "rotate_cmd": "manual rotation",
            },
            "another_key": {
                "description": "Another test key",
                "rotate": "never",
                "consumers": [],
            },
            "expiring_key": {
                "description": "Key that expires soon",
                "rotate": "365d",
                "expires": "2026-04-01",
            },
            "expired_key": {
                "description": "Key already expired",
                "rotate": "365d",
                "expires": "2026-01-01",
            },
            "db_creds": {
                "description": "Database credentials",
                "type": "usernamePassword",
                "rotate": "90d",
                "consumers": ["app01"],
            },
        }
    }
    kf = tmp_path / "vault-keys.yml"
    kf.write_text(yaml.dump(data, default_flow_style=False))
    return kf


@pytest.fixture
def config_file(tmp_path, vault_file, keys_file):
    """Create a complete .vaultctl.yml config."""
    config = {
        "vault_file": str(vault_file),
        "keys_file": str(keys_file),
        "password": {
            "env": "VAULTCTL_TEST_PASS",
        },
    }
    cf = tmp_path / ".vaultctl.yml"
    cf.write_text(yaml.dump(config, default_flow_style=False))
    return cf
