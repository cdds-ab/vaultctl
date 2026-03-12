"""Deterministic redaction of vault data for safe external processing."""

from __future__ import annotations

from typing import Any

REDACTED_PLACEHOLDER = "***REDACTED***"

# Fields whose values are preserved (structural metadata, not secrets).
_PRESERVED_FIELDS: frozenset[str] = frozenset({"type"})


def redact_value(value: Any) -> Any:
    """Redact a single value, preserving only structure.

    - Dicts: keys preserved, values recursively redacted (except _PRESERVED_FIELDS)
    - Lists: length preserved, each element redacted
    - Scalars (str, int, float, bool, None): replaced with placeholder
    """
    if isinstance(value, dict):
        return {
            k: v if k in _PRESERVED_FIELDS else redact_value(v)
            for k, v in value.items()
        }
    if isinstance(value, list):
        return [redact_value(item) for item in value]
    return REDACTED_PLACEHOLDER


def redact_vault_data(data: dict[str, Any]) -> dict[str, Any]:
    """Redact all secret values in a vault data dict.

    Preserves: key names, dict field names, ``type`` field values, structure.
    Replaces: all other leaf values with a fixed placeholder.

    The output is safe to display, log, or transmit — it contains no secrets.
    """
    return {key: redact_value(value) for key, value in data.items()}


def contains_unredacted(original: dict[str, Any], redacted: dict[str, Any]) -> list[str]:
    """Check that no original leaf value appears in the redacted output.

    Returns a list of leaked values (should be empty for correct redaction).
    This is a verification helper for testing and auditing.
    """
    original_values = _collect_leaf_values(original)
    redacted_str = _serialize_for_check(redacted)

    leaked: list[str] = []
    for val in original_values:
        s = str(val)
        # Skip trivially short values that could match structurally
        # (e.g. empty string, single chars, booleans, small ints).
        if len(s) <= 2:
            continue
        if s in redacted_str:
            leaked.append(s)
    return leaked


def _collect_leaf_values(data: Any) -> set[str]:
    """Recursively collect all leaf values as strings."""
    values: set[str] = set()
    if isinstance(data, dict):
        for k, v in data.items():
            if k not in _PRESERVED_FIELDS:
                values.update(_collect_leaf_values(v))
    elif isinstance(data, list):
        for item in data:
            values.update(_collect_leaf_values(item))
    else:
        values.add(str(data))
    return values


def _serialize_for_check(data: Any) -> str:
    """Serialize data structure to string for leak detection."""
    if isinstance(data, dict):
        parts = [f"{k}:{_serialize_for_check(v)}" for k, v in data.items()]
        return "{" + ",".join(parts) + "}"
    if isinstance(data, list):
        return "[" + ",".join(_serialize_for_check(item) for item in data) + "]"
    return str(data)
