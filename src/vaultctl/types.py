"""Vault entry type detection and field access utilities."""

from __future__ import annotations

from typing import Any

DEFAULT_TYPE = "secretText"
KNOWN_TYPES = frozenset({"secretText", "usernamePassword", "sshKey", "certificate"})


def detect_entry_type(value: Any) -> str:
    """Detect the type of a vault entry from its value.

    Returns the ``type`` field of a dict entry, or ``"secretText"`` for
    plain string values and dicts without an explicit type.
    """
    if isinstance(value, dict):
        return str(value.get("type", DEFAULT_TYPE))
    return DEFAULT_TYPE


def get_entry_fields(value: Any) -> list[str]:
    """Return sorted field names of a structured entry (excluding 'type')."""
    if isinstance(value, dict):
        return sorted(k for k in value if k != "type")
    return []


def get_field_value(value: Any, field: str) -> Any:
    """Access a specific field within a structured vault entry.

    Raises ``KeyError`` when *value* is not a dict or *field* is missing.
    """
    if not isinstance(value, dict):
        msg = f"Entry is not structured (plain string), cannot access field '{field}'"
        raise KeyError(msg)
    if field not in value:
        msg = f"Field '{field}' not found"
        raise KeyError(msg)
    return value[field]
