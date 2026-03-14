"""Heuristic detection of vault entry types based on structure, values, and key names."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Literal

from .types import DEFAULT_TYPE, detect_entry_type

Confidence = Literal["high", "medium", "low"]


@dataclass
class DetectionResult:
    """Result of type detection for a single vault entry."""

    key: str
    current_type: str | None
    suggested_type: str
    confidence: Confidence
    signals: list[str] = field(default_factory=list)
    skipped: bool = False
    sub_types: dict[str, int] = field(default_factory=dict)


# --- Key name patterns ---

_KEY_NAME_PATTERNS: list[tuple[str, str]] = [
    (r"(?:user|login|cred|password|passwd|pass)(?:word)?", "usernamePassword"),
    (r"(?:ssh|privkey|private.?key|id_rsa|id_ed25519)", "sshKey"),
    (r"(?:cert|certificate|pem|crt|ssl.?cert|tls.?cert)", "certificate"),
]

# --- Value patterns (applied to string values) ---

_PEM_SSH_KEY = re.compile(r"-----BEGIN\s+(?:RSA |EC |OPENSSH |ED25519 )?PRIVATE KEY-----")
_PEM_CERTIFICATE = re.compile(r"-----BEGIN CERTIFICATE-----")
_SSH_PUBLIC_KEY = re.compile(r"^ssh-(?:rsa|ed25519|ecdsa)\s+")

# --- Field-set patterns (applied to dict keys) ---

_FIELD_SET_PATTERNS: list[tuple[frozenset[str], str]] = [
    # Order matters: more specific (larger sets) before less specific.
    (frozenset({"username", "password"}), "usernamePassword"),
    (frozenset({"user", "password"}), "usernamePassword"),
    (frozenset({"user", "pass"}), "usernamePassword"),
    (frozenset({"certificate", "chain"}), "certificate"),
    (frozenset({"cert", "key"}), "certificate"),
    (frozenset({"private_key"}), "sshKey"),
    (frozenset({"certificate"}), "certificate"),
    (frozenset({"cert"}), "certificate"),
    (frozenset({"key"}), "sshKey"),
]


_MAX_RECURSION_DEPTH = 50


def _collect_nested_credential_types(value: Any, _depth: int = 0) -> dict[str, int]:
    """Recursively scan a value for credential lists containing typed sub-objects.

    Looks for list values where items are dicts with an explicit ``type`` field.
    Returns a mapping of type names to their occurrence counts.
    Only structural metadata (``type`` field values) is inspected — no secrets.

    Recursion is bounded by ``_MAX_RECURSION_DEPTH`` to prevent stack overflow
    on adversarial or malformed input.
    """
    if _depth > _MAX_RECURSION_DEPTH:
        return {}
    counts: dict[str, int] = {}
    if isinstance(value, dict):
        for v in value.values():
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict) and "type" in item:
                        type_name = str(item["type"])
                        counts[type_name] = counts.get(type_name, 0) + 1
            # Recurse into nested dicts (e.g. global -> credentials)
            if isinstance(v, dict):
                for t, c in _collect_nested_credential_types(v, _depth + 1).items():
                    counts[t] = counts.get(t, 0) + c
            # Recurse into list items that are dicts (e.g. domains[] -> credentials)
            if isinstance(v, list):
                for item in v:
                    if isinstance(item, dict):
                        for t, c in _collect_nested_credential_types(item, _depth + 1).items():
                            counts[t] = counts.get(t, 0) + c
    return counts


def detect_type_heuristic(key: str, value: Any) -> DetectionResult:
    """Detect the type of a vault entry using heuristics.

    Priority order:
    1. Explicit ``type`` field in dict entries (skipped — already typed)
    2. Nested credential store pattern (high confidence)
    3. Dict field structure (high confidence)
    4. Value patterns — PEM headers, ssh prefixes (high confidence)
    5. Key name patterns (medium/low confidence)
    """
    # Already has explicit type
    if isinstance(value, dict) and "type" in value:
        explicit = detect_entry_type(value)
        return DetectionResult(
            key=key,
            current_type=explicit,
            suggested_type=explicit,
            confidence="high",
            signals=["explicit_type"],
            skipped=True,
        )

    # Check for nested credential store pattern
    if isinstance(value, dict):
        nested_types = _collect_nested_credential_types(value)
        if nested_types:
            total = sum(nested_types.values())
            return DetectionResult(
                key=key,
                current_type=None,
                suggested_type="credentialStore",
                confidence="high",
                signals=[f"nested_credentials:{total}_items"],
                sub_types=nested_types,
            )

    signals: list[str] = []
    suggested: str | None = None
    confidence: Confidence = "low"

    # 1. Dict field structure (highest priority)
    if isinstance(value, dict):
        fields = frozenset(k for k in value if k != "type")
        for pattern_fields, entry_type in _FIELD_SET_PATTERNS:
            if pattern_fields.issubset(fields):
                signals.append(f"fields:{'+'.join(sorted(pattern_fields))}")
                suggested = entry_type
                confidence = "high"
                break

    # 2. Value patterns (PEM headers etc.)
    if suggested is None:
        str_value = _get_string_value(value)
        if str_value:
            val_type = _match_value_pattern(str_value)
            if val_type:
                signals.append(f"value_pattern:{val_type}")
                suggested = val_type
                confidence = "high"

    # 3. Key name patterns (lowest priority)
    if suggested is None:
        key_lower = key.lower()
        for pattern, entry_type in _KEY_NAME_PATTERNS:
            if re.search(pattern, key_lower):
                signals.append(f"key_name:{pattern}")
                suggested = entry_type
                confidence = "medium" if len(signals) > 0 else "low"
                break

    return DetectionResult(
        key=key,
        current_type=None,
        suggested_type=suggested or DEFAULT_TYPE,
        confidence=confidence if suggested else "low",
        signals=signals,
    )


_CONFIDENCE_ORDER: dict[str, int] = {"high": 3, "medium": 2, "low": 1}


def filter_by_confidence(results: list[DetectionResult], min_level: Confidence) -> list[DetectionResult]:
    """Filter detection results by minimum confidence level.

    Confidence levels: ``"high"`` > ``"medium"`` > ``"low"``.
    """
    min_value = _CONFIDENCE_ORDER[min_level]
    return [r for r in results if _CONFIDENCE_ORDER[r.confidence] >= min_value]


def detect_all(data: dict[str, Any]) -> list[DetectionResult]:
    """Run heuristic detection on all vault entries.

    Skips ``_previous`` backup keys.
    """
    results: list[DetectionResult] = []
    for key in sorted(data):
        if key.endswith("_previous"):
            results.append(
                DetectionResult(
                    key=key,
                    current_type=None,
                    suggested_type=DEFAULT_TYPE,
                    confidence="low",
                    signals=["backup_key"],
                    skipped=True,
                )
            )
            continue
        results.append(detect_type_heuristic(key, data[key]))
    return results


def _get_string_value(value: Any) -> str | None:
    """Extract a string for pattern matching from a value."""
    if isinstance(value, str):
        return value
    if isinstance(value, dict):
        # Check common field names for string values
        for field_name in ("private_key", "key", "certificate", "cert", "value"):
            if field_name in value and isinstance(value[field_name], str):
                result: str = value[field_name]
                return result
    return None


def _match_value_pattern(value: str) -> str | None:
    """Match a string value against known patterns."""
    if _PEM_SSH_KEY.search(value):
        return "sshKey"
    if _PEM_CERTIFICATE.search(value):
        return "certificate"
    if _SSH_PUBLIC_KEY.match(value):
        return "sshKey"
    return None
