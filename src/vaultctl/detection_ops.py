"""Apply detected types to vault data and key metadata."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .detect import DetectionResult
from .keys import save_keys, update_key_metadata
from .vault import encrypt_vault


@dataclass
class ApplyResult:
    """Result of applying detected types."""

    applied_count: int
    vault_modified: bool


def apply_detected_types(
    actionable: list[DetectionResult],
    vault_data: dict[str, Any],
    keys_meta: dict[str, Any],
    vault_file: Path,
    keys_file: Path,
    password: str,
) -> ApplyResult:
    """Apply detected types to vault entries and keys metadata.

    Updates dict entries in vault_data with a ``type`` field where missing,
    and updates the keys metadata file with the suggested type.

    Returns an ``ApplyResult`` with the count of applied types and whether
    the vault was modified on disk.

    Raises ``VaultError`` if the vault cannot be written.
    """
    modified_vault = False

    for r in actionable:
        if r.suggested_type == "secretText":
            continue
        # Update vault dict entries with type field
        if isinstance(vault_data.get(r.key), dict) and "type" not in vault_data[r.key]:
            vault_data[r.key]["type"] = r.suggested_type
            modified_vault = True
        # Update keys metadata
        update_key_metadata(keys_meta, r.key, type=r.suggested_type)

    if modified_vault:
        encrypt_vault(vault_data, vault_file, password)

    save_keys(keys_meta, keys_file)

    return ApplyResult(applied_count=len(actionable), vault_modified=modified_vault)
