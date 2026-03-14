"""Recursive search through vault data structures.

Security: This module never logs or exposes search patterns or matched values
in its return data.  Callers are responsible for gating value display behind
explicit user consent (--show-match).
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

# Maximum recursion depth to prevent runaway traversal.
MAX_DEPTH: int = 20

# Maximum allowed regex pattern length to mitigate ReDoS.
MAX_PATTERN_LENGTH: int = 500

# Shared recursion depth constant (also used by detect module).
MAX_RECURSION_DEPTH: int = 50


@dataclass(frozen=True)
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


def _compile_pattern(pattern: str, *, fixed_string: bool = False, flags: int = 0) -> Callable[[str], bool]:
    """Compile a search pattern into a matcher function.

    Args:
        pattern: Search string or regex.
        fixed_string: If True, use literal substring matching instead of regex.
        flags: Regex flags (only used when fixed_string is False).

    Returns:
        A callable that returns True if the input string matches.

    Raises:
        ValueError: If pattern exceeds MAX_PATTERN_LENGTH.
        re.error: If the regex pattern is invalid.
    """
    if len(pattern) > MAX_PATTERN_LENGTH:
        raise ValueError(f"Pattern too long ({len(pattern)} chars, max {MAX_PATTERN_LENGTH}).")

    if fixed_string:
        lowered = pattern.lower() if (flags & re.IGNORECASE) else None
        if lowered is not None:

            def _match(s: str) -> bool:
                return lowered in s.lower()
        else:

            def _match(s: str) -> bool:
                return pattern in s

        return _match

    compiled = re.compile(pattern, flags)

    def _regex_match(s: str) -> bool:
        return compiled.search(s) is not None

    return _regex_match


def search_values(
    data: dict[str, Any],
    pattern: str,
    *,
    include_values: bool = False,
    max_depth: int = MAX_DEPTH,
    fixed_string: bool = False,
) -> list[SearchMatch]:
    """Search all vault values for *pattern* (regex or fixed string).

    Recursively traverses dicts and lists.  Only string values are matched.

    Args:
        data: Decrypted vault data (top-level dict).
        pattern: Regular expression (or literal string if *fixed_string*) to
            match against string values.
        include_values: If True, populate ``SearchMatch.value`` with the
            matched string.  **Security-sensitive** -- caller must gate this
            behind explicit user consent.
        max_depth: Maximum nesting depth for recursive traversal.
        fixed_string: If True, use literal substring matching instead of regex.

    Returns:
        List of ``SearchMatch`` objects for every value that matches.

    Raises:
        ValueError: If pattern exceeds MAX_PATTERN_LENGTH.
        re.error: If the regex pattern is invalid (only when fixed_string is False).
    """
    matcher = _compile_pattern(pattern, fixed_string=fixed_string)
    matches: list[SearchMatch] = []

    for key in sorted(data.keys()):
        _search_node(
            node=data[key],
            top_key=key,
            current_path="",
            matcher=matcher,
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
    matcher: Callable[[str], bool],
    matches: list[SearchMatch],
    include_values: bool,
    depth: int,
    max_depth: int,
) -> None:
    """Recursively search a single node for pattern matches."""
    if depth > max_depth:
        return

    if isinstance(node, str):
        if matcher(node):
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
                matcher=matcher,
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
                matcher=matcher,
                matches=matches,
                include_values=include_values,
                depth=depth + 1,
                max_depth=max_depth,
            )


def filter_keys(
    keys: list[str],
    metadata: dict[str, Any],
    pattern: str,
    *,
    fixed_string: bool = False,
) -> list[str]:
    """Filter vault keys by regex (or fixed string) against names and metadata.

    Matches against:
    - Key name
    - Description (from vault-keys.yml)
    - Consumers (from vault-keys.yml)

    Args:
        keys: Sorted list of vault key names.
        metadata: Loaded vault-keys.yml data (the vault_keys mapping).
        pattern: Regular expression (or literal string if *fixed_string*) to filter by.
        fixed_string: If True, use literal substring matching instead of regex.

    Returns:
        Filtered list of key names that match the pattern.

    Raises:
        ValueError: If pattern exceeds MAX_PATTERN_LENGTH.
        re.error: If the regex pattern is invalid (only when fixed_string is False).
    """
    matcher = _compile_pattern(pattern, fixed_string=fixed_string, flags=re.IGNORECASE)
    result: list[str] = []

    for key in keys:
        # Match against key name
        if matcher(key):
            result.append(key)
            continue

        # Match against metadata fields
        meta = metadata.get(key)
        if meta is None:
            continue

        description = meta.get("description", "")
        if description and matcher(description):
            result.append(key)
            continue

        consumers = meta.get("consumers", [])
        for consumer in consumers:
            if matcher(str(consumer)):
                result.append(key)
                break

    return result
