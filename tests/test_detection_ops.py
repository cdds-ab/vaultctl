"""Tests for detection_ops — apply detected types to vault and keys."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

import pytest
from vaultctl.detect import DetectionResult
from vaultctl.detection_ops import ApplyResult, apply_detected_types


@pytest.fixture
def actionable_results() -> list[DetectionResult]:
    """Sample actionable detection results."""
    return [
        DetectionResult(
            key="db_creds",
            current_type=None,
            suggested_type="usernamePassword",
            confidence="high",
            signals=["fields:password+username"],
        ),
        DetectionResult(
            key="ssh_key",
            current_type=None,
            suggested_type="sshKey",
            confidence="high",
            signals=["value_pattern:sshKey"],
        ),
    ]


class TestApplyDetectedTypes:
    """Test apply_detected_types logic."""

    def test_updates_dict_entries_with_type(self, tmp_path: Path, actionable_results: list[DetectionResult]) -> None:
        vault_data: dict = {
            "db_creds": {"username": "admin", "password": "s3cret"},
            "ssh_key": "-----BEGIN RSA PRIVATE KEY-----\ndata",
        }
        keys_meta: dict = {"db_creds": {}, "ssh_key": {}}

        with (
            patch("vaultctl.detection_ops.encrypt_vault") as mock_encrypt,
            patch("vaultctl.detection_ops.save_keys") as mock_save,
        ):
            result = apply_detected_types(
                actionable_results, vault_data, keys_meta, tmp_path / "vault.yml", tmp_path / "keys.yml", "pass"
            )

        assert result.applied_count == 2
        assert result.vault_modified is True
        # Dict entry should have type added
        assert vault_data["db_creds"]["type"] == "usernamePassword"
        # String entry should not be modified (no dict to add type to)
        assert isinstance(vault_data["ssh_key"], str)
        # Keys metadata should be updated for both
        assert keys_meta["db_creds"]["type"] == "usernamePassword"
        assert keys_meta["ssh_key"]["type"] == "sshKey"
        mock_encrypt.assert_called_once()
        mock_save.assert_called_once()

    def test_skips_secret_text_type(self, tmp_path: Path) -> None:
        results = [
            DetectionResult(
                key="plain",
                current_type=None,
                suggested_type="secretText",
                confidence="low",
                signals=[],
            ),
        ]
        vault_data: dict = {"plain": "value"}
        keys_meta: dict = {}

        with patch("vaultctl.detection_ops.encrypt_vault") as mock_encrypt, patch("vaultctl.detection_ops.save_keys"):
            result = apply_detected_types(
                results, vault_data, keys_meta, tmp_path / "vault.yml", tmp_path / "keys.yml", "pass"
            )

        assert result.applied_count == 1
        assert result.vault_modified is False
        mock_encrypt.assert_not_called()

    def test_does_not_overwrite_existing_type_in_vault(self, tmp_path: Path) -> None:
        results = [
            DetectionResult(
                key="creds",
                current_type=None,
                suggested_type="usernamePassword",
                confidence="high",
                signals=["fields:password+username"],
            ),
        ]
        vault_data: dict = {"creds": {"type": "existingType", "username": "u", "password": "p"}}
        keys_meta: dict = {}

        with patch("vaultctl.detection_ops.encrypt_vault") as mock_encrypt, patch("vaultctl.detection_ops.save_keys"):
            result = apply_detected_types(
                results, vault_data, keys_meta, tmp_path / "vault.yml", tmp_path / "keys.yml", "pass"
            )

        # Should not modify vault since type already exists
        assert vault_data["creds"]["type"] == "existingType"
        assert result.vault_modified is False
        mock_encrypt.assert_not_called()

    def test_empty_actionable_list(self, tmp_path: Path) -> None:
        vault_data: dict = {}
        keys_meta: dict = {}

        with (
            patch("vaultctl.detection_ops.encrypt_vault") as mock_encrypt,
            patch("vaultctl.detection_ops.save_keys") as mock_save,
        ):
            result = apply_detected_types([], vault_data, keys_meta, tmp_path / "v.yml", tmp_path / "k.yml", "pass")

        assert result.applied_count == 0
        assert result.vault_modified is False
        mock_encrypt.assert_not_called()
        mock_save.assert_called_once()

    def test_propagates_vault_error(self, tmp_path: Path, actionable_results: list[DetectionResult]) -> None:
        from vaultctl.vault import VaultError

        vault_data: dict = {"db_creds": {"username": "u", "password": "p"}, "ssh_key": "key"}
        keys_meta: dict = {}

        with (
            patch("vaultctl.detection_ops.encrypt_vault", side_effect=VaultError("fail")),
            patch("vaultctl.detection_ops.save_keys"),
        ):
            with pytest.raises(VaultError, match="fail"):
                apply_detected_types(
                    actionable_results, vault_data, keys_meta, tmp_path / "v.yml", tmp_path / "k.yml", "pass"
                )


class TestApplyResult:
    def test_dataclass_fields(self) -> None:
        r = ApplyResult(applied_count=5, vault_modified=True)
        assert r.applied_count == 5
        assert r.vault_modified is True
