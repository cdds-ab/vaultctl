"""Recursive search through vault data structures.

Security: This module never logs or exposes search patterns or matched values
in its return data.  Callers are responsible for gating value display behind
explicit user consent (--show-match).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

# Maximum recursion depth to prevent runaway traversal.
MAX_DEPTH: int = 20


@dataclass
class SearchMatch:
    """A single match found during vault value search.

    Attributes:
        key: Top-level vault key name.
        path: Dot/bracket-separated path to the matched value within the entry.
              Empty string for top-level string matches.
        value: The matched value (only populated when caller requests it).
    """

    key: str
    path: str = ""
    value: str | None = None


def search_values(
    data: dict[str, Any],
    pattern: str,
    *,
    include_values: bool = False,
    max_depth: int = MAX_DEPTH,
) -> list[SearchMatch]:
    """Search all vault values for *pattern* (regex).

    Recursively traverses dicts and lists.  Only string values are matched.

    Args:
        data: Decrypted vault data (top-level dict).
        pattern: Regular expression to match against string values.
        include_values: If True, populate ``SearchMatch.value`` with the
            matched string.  **Security-sensitive** -- caller must gate this
            behind explicit user consent.
        max_depth: Maximum nesting depth for recursive traversal.

    Returns:
        List of ``SearchMatch`` objects for every value that matches.
    """
    compiled = re.compile(pattern)
    matches: list[SearchMatch] = []

    for key in sorted(data.keys()):
        _search_node(
            node=data[key],
            top_key=key,
            current_path="",
            compiled=compiled,
            matches=matches,
            include_values=include_values,
            depth=0,
            max_depth=max_depth,
        )

    return matches


def _search_node(
    *,
    node: Any,
    top_key: str,
    current_path: str,
    compiled: re.Pattern[str],
    matches: list[SearchMatch],
    include_values: bool,
    depth: int,
    max_depth: int,
) -> None:
    """Recursively search a single node for pattern matches."""
    if depth > max_depth:
        return

    if isinstance(node, str):
        if compiled.search(node):
            matches.append(
                SearchMatch(
                    key=top_key,
                    path=current_path,
                    value=node if include_values else None,
                )
            )
    elif isinstance(node, dict):
        for sub_key in sorted(node.keys()):
            child_path = f"{current_path}.{sub_key}" if current_path else sub_key
            _search_node(
                node=node[sub_key],
                top_key=top_key,
                current_path=child_path,
                compiled=compiled,
                matches=matches,
                include_values=include_values,
                depth=depth + 1,
                max_depth=max_depth,
            )
    elif isinstance(node, list):
        for idx, item in enumerate(node):
            child_path = f"{current_path}[{idx}]" if current_path else f"[{idx}]"
            _search_node(
                node=item,
                top_key=top_key,
                current_path=child_path,
                compiled=compiled,
                matches=matches,
                include_values=include_values,
                depth=depth + 1,
                max_depth=max_depth,
            )


def filter_keys(
    keys: list[str],
    metadata: dict[str, Any],
    pattern: str,
) -> list[str]:
    """Filter vault keys by regex pattern against names and metadata.

    Matches against:
    - Key name
    - Description (from vault-keys.yml)
    - Consumers (from vault-keys.yml)

    Args:
        keys: Sorted list of vault key names.
        metadata: Loaded vault-keys.yml data (the vault_keys mapping).
        pattern: Regular expression to filter by.

    Returns:
        Filtered list of key names that match the pattern.
    """
    compiled = re.compile(pattern, re.IGNORECASE)
    result: list[str] = []

    for key in keys:
        # Match against key name
        if compiled.search(key):
            result.append(key)
            continue

        # Match against metadata fields
        meta = metadata.get(key)
        if meta is None:
            continue

        description = meta.get("description", "")
        if description and compiled.search(description):
            result.append(key)
            continue

        consumers = meta.get("consumers", [])
        for consumer in consumers:
            if compiled.search(str(consumer)):
                result.append(key)
                break

    return result
