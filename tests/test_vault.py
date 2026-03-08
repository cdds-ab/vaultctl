"""Tests for vaultctl.vault module."""

from __future__ import annotations

import pytest
from vaultctl.vault import VaultError, decrypt_vault, encrypt_vault


@pytest.fixture
def _require_ansible_vault():
    """Skip if ansible-vault is not installed."""
    import shutil

    if not shutil.which("ansible-vault"):
        pytest.skip("ansible-vault not installed")


@pytest.mark.usefixtures("_require_ansible_vault")
class TestVault:
    def test_decrypt(self, vault_file, vault_password):
        data = decrypt_vault(vault_file, vault_password)
        assert data["test_key"] == "test_value"
        assert data["another_key"] == "another_value"

    def test_decrypt_wrong_password(self, vault_file):
        with pytest.raises(VaultError):
            decrypt_vault(vault_file, "wrong-password")

    def test_encrypt_decrypt_roundtrip(self, tmp_path, vault_password):
        original = {"round_trip_key": "round_trip_value", "number": 42}
        encrypted_path = tmp_path / "roundtrip.yml"

        encrypt_vault(original, encrypted_path, vault_password)
        assert encrypted_path.exists()

        result = decrypt_vault(encrypted_path, vault_password)
        assert result["round_trip_key"] == "round_trip_value"
        assert result["number"] == 42

    def test_encrypt_overwrites(self, vault_file, vault_password):
        new_data = {"new_key": "new_value"}
        encrypt_vault(new_data, vault_file, vault_password)

        result = decrypt_vault(vault_file, vault_password)
        assert "new_key" in result
        assert "test_key" not in result
