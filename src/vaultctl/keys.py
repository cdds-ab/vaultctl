"""Vault key metadata management (vault-keys.yml CRUD)."""

from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from pathlib import Path

from .yaml_util import dump_yaml, load_yaml


@dataclass
class KeyInfo:
    name: str
    description: str = ""
    rotate: str = ""
    consumers: list[str] = field(default_factory=list)
    rotate_cmd: str = ""
    ui_manageable: bool = False
    expires: str = ""


@dataclass
class ExpiryWarning:
    key: str
    expires: datetime.date
    days_remaining: int
    status: str  # "expired", "warning", "ok"


def load_keys(keys_file: Path) -> dict:
    """Load vault-keys.yml and return the vault_keys mapping."""
    if not keys_file.is_file():
        return {}
    data = load_yaml(keys_file)
    return data.get("vault_keys", {})


def save_keys(keys_data: dict, keys_file: Path) -> None:
    """Write the vault_keys mapping back to keys_file."""
    dump_yaml({"vault_keys": keys_data}, keys_file)


def get_key_info(keys: dict, key: str) -> KeyInfo | None:
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
    )


def list_keys(keys: dict) -> list[KeyInfo]:
    """Return KeyInfo for all keys, sorted by name."""
    result = []
    for name in sorted(keys):
        info = get_key_info(keys, name)
        if info:
            result.append(info)
    return result


def update_key_metadata(keys: dict, key: str, **updates) -> dict:
    """Update metadata fields for a key. Creates the entry if needed."""
    if key not in keys:
        keys[key] = {}
    for field_name, value in updates.items():
        if value is not None:
            keys[key][field_name] = value
    return keys


def check_expiry(
    keys: dict,
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
