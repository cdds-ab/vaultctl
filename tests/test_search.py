"""Unit tests for vaultctl.search module."""

from __future__ import annotations

import re

import pytest
from vaultctl.search import MAX_PATTERN_LENGTH, SearchMatch, filter_keys, search_values


class TestSearchValues:
    """Tests for search_values()."""

    def test_simple_string_match(self) -> None:
        data = {"api_key": "abc123", "db_pass": "xyz789"}
        matches = search_values(data, "abc")
        assert len(matches) == 1
        assert matches[0].key == "api_key"
        assert matches[0].path == ""
        assert matches[0].value is None  # not requested

    def test_no_match(self) -> None:
        data = {"key": "value"}
        matches = search_values(data, "nonexistent")
        assert matches == []

    def test_regex_pattern(self) -> None:
        data = {"key1": "admin_user", "key2": "root_user", "key3": "guest"}
        matches = search_values(data, r".*_user$")
        assert len(matches) == 2
        keys = [m.key for m in matches]
        assert "key1" in keys
        assert "key2" in keys

    def test_nested_dict(self) -> None:
        data = {
            "db_creds": {
                "username": "admin",
                "password": "s3cret",
            }
        }
        matches = search_values(data, "s3cret")
        assert len(matches) == 1
        assert matches[0].key == "db_creds"
        assert matches[0].path == "password"

    def test_nested_list(self) -> None:
        data = {
            "jenkins": {
                "credentials": [
                    {"user": "deploy", "token": "tok123"},
                    {"user": "admin", "token": "tok456"},
                ]
            }
        }
        matches = search_values(data, "tok456")
        assert len(matches) == 1
        assert matches[0].key == "jenkins"
        assert matches[0].path == "credentials[1].token"

    def test_deeply_nested(self) -> None:
        data = {
            "config": {
                "level1": {
                    "level2": {
                        "level3": "deep_value",
                    }
                }
            }
        }
        matches = search_values(data, "deep_value")
        assert len(matches) == 1
        assert matches[0].path == "level1.level2.level3"

    def test_multiple_matches_same_key(self) -> None:
        data = {
            "creds": {
                "username": "admin",
                "password": "admin123",
            }
        }
        matches = search_values(data, "admin")
        assert len(matches) == 2
        paths = [m.path for m in matches]
        assert "password" in paths
        assert "username" in paths

    def test_include_values(self) -> None:
        data = {"key": "secret_value"}
        matches = search_values(data, "secret", include_values=True)
        assert len(matches) == 1
        assert matches[0].value == "secret_value"

    def test_values_excluded_by_default(self) -> None:
        data = {"key": "secret_value"}
        matches = search_values(data, "secret")
        assert len(matches) == 1
        assert matches[0].value is None

    def test_depth_limit(self) -> None:
        # Build a structure deeper than max_depth
        node: dict[str, object] = {"val": "target"}
        for i in range(5):
            node = {f"level{i}": node}
        data = {"deep": node}

        # With sufficient depth, it finds the value
        matches = search_values(data, "target", max_depth=10)
        assert len(matches) == 1

        # With shallow depth limit, it does not
        matches = search_values(data, "target", max_depth=2)
        assert len(matches) == 0

    def test_non_string_values_ignored(self) -> None:
        data = {
            "port": 5432,
            "enabled": True,
            "tags": ["web", "prod"],
            "name": "myservice",
        }
        matches = search_values(data, "myservice")
        assert len(matches) == 1
        assert matches[0].key == "name"

    def test_list_of_strings(self) -> None:
        data = {"hosts": ["web01.example.com", "db01.example.com"]}
        matches = search_values(data, "db01")
        assert len(matches) == 1
        assert matches[0].path == "[1]"

    def test_top_level_list(self) -> None:
        data = {"servers": ["alpha", "beta", "gamma"]}
        matches = search_values(data, "beta")
        assert len(matches) == 1
        assert matches[0].key == "servers"
        assert matches[0].path == "[1]"

    def test_sorted_output(self) -> None:
        data = {"zulu": "match", "alpha": "match", "mike": "match"}
        matches = search_values(data, "match")
        keys = [m.key for m in matches]
        assert keys == ["alpha", "mike", "zulu"]

    def test_empty_vault(self) -> None:
        matches = search_values({}, "anything")
        assert matches == []


class TestFilterKeys:
    """Tests for filter_keys()."""

    def test_filter_by_key_name(self) -> None:
        keys = ["db_password", "api_token", "ssh_key"]
        metadata: dict[str, object] = {}
        result = filter_keys(keys, metadata, "token")
        assert result == ["api_token"]

    def test_filter_by_description(self) -> None:
        keys = ["vault_key"]
        metadata = {"vault_key": {"description": "Jenkins API token"}}
        result = filter_keys(keys, metadata, "jenkins")
        assert result == ["vault_key"]

    def test_filter_by_consumer(self) -> None:
        keys = ["db_pass"]
        metadata = {"db_pass": {"description": "", "consumers": ["web-app", "worker"]}}
        result = filter_keys(keys, metadata, "worker")
        assert result == ["db_pass"]

    def test_filter_case_insensitive(self) -> None:
        keys = ["Jenkins_Token"]
        metadata: dict[str, object] = {}
        result = filter_keys(keys, metadata, "jenkins")
        assert result == ["Jenkins_Token"]

    def test_filter_regex(self) -> None:
        keys = ["gitlab_token", "github_token", "jira_password"]
        metadata: dict[str, object] = {}
        result = filter_keys(keys, metadata, r"git.*_token")
        assert result == ["gitlab_token", "github_token"]

    def test_filter_no_match(self) -> None:
        keys = ["key1", "key2"]
        metadata: dict[str, object] = {}
        result = filter_keys(keys, metadata, "nonexistent")
        assert result == []

    def test_filter_no_duplicate_on_multi_match(self) -> None:
        """Key matching both name and description should appear only once."""
        keys = ["jenkins_token"]
        metadata = {"jenkins_token": {"description": "Jenkins CI token"}}
        result = filter_keys(keys, metadata, "jenkins")
        assert result == ["jenkins_token"]

    def test_filter_empty_keys(self) -> None:
        result = filter_keys([], {}, "anything")
        assert result == []

    def test_filter_fixed_string(self) -> None:
        """Fixed string mode should match literally, not as regex."""
        keys = ["git.*_token", "github_token"]
        metadata: dict[str, object] = {}
        result = filter_keys(keys, metadata, r"git.*_token", fixed_string=True)
        assert result == ["git.*_token"]

    def test_filter_fixed_string_case_insensitive(self) -> None:
        keys = ["Jenkins_Token"]
        metadata: dict[str, object] = {}
        result = filter_keys(keys, metadata, "jenkins", fixed_string=True)
        assert result == ["Jenkins_Token"]


class TestSearchSecurity:
    """Security-related tests for search module."""

    def test_pattern_length_limit_search_values(self) -> None:
        """Patterns exceeding MAX_PATTERN_LENGTH must be rejected."""
        data = {"key": "value"}
        long_pattern = "a" * (MAX_PATTERN_LENGTH + 1)
        with pytest.raises(ValueError, match="Pattern too long"):
            search_values(data, long_pattern)

    def test_pattern_length_limit_filter_keys(self) -> None:
        """Patterns exceeding MAX_PATTERN_LENGTH must be rejected."""
        long_pattern = "a" * (MAX_PATTERN_LENGTH + 1)
        with pytest.raises(ValueError, match="Pattern too long"):
            filter_keys(["key"], {}, long_pattern)

    def test_invalid_regex_raises_error(self) -> None:
        """Invalid regex must raise re.error, not crash."""
        data = {"key": "value"}
        with pytest.raises(re.error):
            search_values(data, "[invalid")

    def test_invalid_regex_filter_keys(self) -> None:
        with pytest.raises(re.error):
            filter_keys(["key"], {}, "[invalid")

    def test_fixed_string_bypasses_regex(self) -> None:
        """Fixed string mode must not interpret regex metacharacters."""
        data = {"key": "abc.*def"}
        matches = search_values(data, ".*", fixed_string=True)
        assert len(matches) == 1

        # Without fixed_string, .* matches everything
        matches_regex = search_values(data, ".*")
        assert len(matches_regex) == 1  # matches the string

    def test_fixed_string_no_regex_error(self) -> None:
        """Fixed string mode must not raise re.error on invalid regex chars."""
        data = {"key": "test[value"}
        matches = search_values(data, "[value", fixed_string=True)
        assert len(matches) == 1

    def test_fixed_string_search_values(self) -> None:
        data = {"key1": "hello world", "key2": "goodbye"}
        matches = search_values(data, "hello", fixed_string=True)
        assert len(matches) == 1
        assert matches[0].key == "key1"

    def test_search_match_is_frozen(self) -> None:
        """SearchMatch should be immutable (frozen dataclass)."""
        match = SearchMatch(key="test", path="a.b", value="val")
        with pytest.raises(AttributeError):
            match.key = "changed"  # type: ignore[misc]
