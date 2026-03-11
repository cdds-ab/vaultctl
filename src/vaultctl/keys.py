"""Vault key metadata management (vault-keys.yml CRUD)."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

from .yaml_util import dump_yaml, load_yaml

ExpiryStatus = Literal["expired", "warning", "ok"]


@dataclass
class KeyInfo:
    name: str
    description: str = ""
    rotate: str = ""
    consumers: list[str] = field(default_factory=list)
    rotate_cmd: str = ""
    ui_manageable: bool = False
    expires: str = ""
    entry_type: str = ""


@dataclass
class ExpiryWarning:
    key: str
    expires: datetime.date
    days_remaining: int
    status: ExpiryStatus


def load_keys(keys_file: Path) -> dict[str, Any]:
    """Load vault-keys.yml and return the vault_keys mapping."""
    if not keys_file.is_file():
        return {}
    data = load_yaml(keys_file)
    result: dict[str, Any] = data.get("vault_keys", {})
    return result


def save_keys(keys_data: dict[str, Any], keys_file: Path) -> None:
    """Write the vault_keys mapping back to keys_file."""
    dump_yaml({"vault_keys": keys_data}, keys_file)


def get_key_info(keys: dict[str, Any], key: str) -> KeyInfo | None:
    """Return metadata for a single key, or None if not found."""
    meta = keys.get(key)
    if meta is None:
        return None
    return KeyInfo(
        name=key,
        description=meta.get("description", ""),
        rotate=meta.get("rotate", ""),
        consumers=meta.get("consumers", []),
        rotate_cmd=meta.get("rotate_cmd", ""),
        ui_manageable=meta.get("ui_manageable", False),
        expires=meta.get("expires", ""),
        entry_type=meta.get("type", ""),
    )


def list_keys(keys: dict[str, Any]) -> list[KeyInfo]:
    """Return KeyInfo for all keys, sorted by name."""
    result = []
    for name in sorted(keys):
        info = get_key_info(keys, name)
        if info:
            result.append(info)
    return result


def update_key_metadata(keys: dict[str, Any], key: str, **updates: Any) -> dict[str, Any]:
    """Update metadata fields for a key. Creates the entry if needed."""
    if key not in keys:
        keys[key] = {}
    for field_name, value in updates.items():
        if value is not None:
            keys[key][field_name] = value
    return keys


def check_expiry(
    keys: dict[str, Any],
    today: datetime.date | None = None,
    warn_days: int = 30,
) -> list[ExpiryWarning]:
    """Check all keys for expired or soon-to-expire credentials."""
    today = today or datetime.date.today()
    warnings: list[ExpiryWarning] = []

    for name, meta in sorted(keys.items()):
        expires_str = meta.get("expires", "")
        if not expires_str:
            continue
        try:
            expires = datetime.date.fromisoformat(str(expires_str))
        except ValueError:
            continue

        days_remaining = (expires - today).days
        status: ExpiryStatus
        if days_remaining < 0:
            status = "expired"
        elif days_remaining <= warn_days:
            status = "warning"
        else:
            status = "ok"

        warnings.append(
            ExpiryWarning(
                key=name,
                expires=expires,
                days_remaining=days_remaining,
                status=status,
            )
        )

    return warnings
