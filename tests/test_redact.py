"""Tests for vault data redaction."""

from __future__ import annotations

import pytest
from vaultctl.redact import (
    REDACTED_PLACEHOLDER,
    contains_unredacted,
    redact_value,
    redact_vault_data,
)


class TestRedactValue:
    def test_string(self):
        assert redact_value("my-secret") == REDACTED_PLACEHOLDER

    def test_int(self):
        assert redact_value(42) == REDACTED_PLACEHOLDER

    def test_float(self):
        assert redact_value(3.14) == REDACTED_PLACEHOLDER

    def test_bool(self):
        assert redact_value(True) == REDACTED_PLACEHOLDER

    def test_none(self):
        assert redact_value(None) == REDACTED_PLACEHOLDER

    def test_empty_string(self):
        assert redact_value("") == REDACTED_PLACEHOLDER

    def test_dict_keys_preserved(self):
        result = redact_value({"username": "admin", "password": "s3cret"})
        assert "username" in result
        assert "password" in result
        assert result["username"] == REDACTED_PLACEHOLDER
        assert result["password"] == REDACTED_PLACEHOLDER

    def test_dict_type_field_preserved(self):
        result = redact_value({
            "type": "usernamePassword",
            "username": "admin",
            "password": "s3cret",
        })
        assert result["type"] == "usernamePassword"
        assert result["username"] == REDACTED_PLACEHOLDER

    def test_nested_dict(self):
        result = redact_value({
            "outer": {"inner": "secret"},
        })
        assert result["outer"]["inner"] == REDACTED_PLACEHOLDER

    def test_list_length_preserved(self):
        result = redact_value(["a", "b", "c"])
        assert len(result) == 3
        assert all(v == REDACTED_PLACEHOLDER for v in result)

    def test_list_of_dicts(self):
        result = redact_value([{"key": "val"}])
        assert result[0]["key"] == REDACTED_PLACEHOLDER

    def test_deeply_nested(self):
        data = {"a": {"b": {"c": {"d": "deep-secret"}}}}
        result = redact_value(data)
        assert result["a"]["b"]["c"]["d"] == REDACTED_PLACEHOLDER

    def test_mixed_list(self):
        result = redact_value([1, "two", {"three": 3}, [4]])
        assert result[0] == REDACTED_PLACEHOLDER
        assert result[1] == REDACTED_PLACEHOLDER
        assert result[2]["three"] == REDACTED_PLACEHOLDER
        assert result[3][0] == REDACTED_PLACEHOLDER


class TestRedactVaultData:
    def test_simple_vault(self):
        data = {"key1": "secret1", "key2": "secret2"}
        result = redact_vault_data(data)
        assert result["key1"] == REDACTED_PLACEHOLDER
        assert result["key2"] == REDACTED_PLACEHOLDER

    def test_structured_entry(self):
        data = {
            "db_creds": {
                "type": "usernamePassword",
                "username": "admin",
                "password": "s3cret",
            }
        }
        result = redact_vault_data(data)
        assert result["db_creds"]["type"] == "usernamePassword"
        assert result["db_creds"]["username"] == REDACTED_PLACEHOLDER
        assert result["db_creds"]["password"] == REDACTED_PLACEHOLDER

    def test_empty_vault(self):
        assert redact_vault_data({}) == {}

    def test_key_names_preserved(self):
        data = {"api_token": "tok-123", "db_password": "pass"}
        result = redact_vault_data(data)
        assert set(result.keys()) == {"api_token", "db_password"}

    def test_multiline_string(self):
        pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIE...\n-----END RSA PRIVATE KEY-----"
        result = redact_vault_data({"ssh_key": pem})
        assert result["ssh_key"] == REDACTED_PLACEHOLDER

    def test_mixed_types(self):
        data = {
            "plain": "secret",
            "structured": {"type": "sshKey", "private_key": "pem-data"},
            "number": 42,
            "flag": True,
        }
        result = redact_vault_data(data)
        assert result["plain"] == REDACTED_PLACEHOLDER
        assert result["structured"]["type"] == "sshKey"
        assert result["structured"]["private_key"] == REDACTED_PLACEHOLDER
        assert result["number"] == REDACTED_PLACEHOLDER
        assert result["flag"] == REDACTED_PLACEHOLDER


class TestContainsUnredacted:
    def test_clean_redaction(self):
        original = {"key": "my-super-secret-password"}
        redacted = redact_vault_data(original)
        assert contains_unredacted(original, redacted) == []

    def test_leaked_value(self):
        original = {"key": "leaked-secret"}
        # Simulate broken redaction
        bad_redacted = {"key": "leaked-secret"}
        leaked = contains_unredacted(original, bad_redacted)
        assert "leaked-secret" in leaked

    def test_nested_leak(self):
        original = {"a": {"b": "nested-secret-value"}}
        bad_redacted = {"a": {"b": "nested-secret-value"}}
        leaked = contains_unredacted(original, bad_redacted)
        assert "nested-secret-value" in leaked

    def test_short_values_skipped(self):
        """Values <= 2 chars are skipped to avoid false positives."""
        original = {"x": "ab"}
        bad_redacted = {"x": "ab"}
        assert contains_unredacted(original, bad_redacted) == []

    def test_type_field_not_flagged(self):
        """The 'type' field value is preserved and should not be flagged."""
        original = {
            "creds": {
                "type": "usernamePassword",
                "password": "s3cret",
            }
        }
        redacted = redact_vault_data(original)
        assert contains_unredacted(original, redacted) == []

    def test_complex_vault(self):
        original = {
            "api_key": "sk-1234567890abcdef",
            "db": {
                "type": "usernamePassword",
                "username": "prod-admin",
                "password": "P@ssw0rd!Complex123",
            },
            "ssh": "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...",
            "cert": {
                "certificate": "-----BEGIN CERTIFICATE-----\nMIIF...",
                "chain": "-----BEGIN CERTIFICATE-----\nMIIE...",
            },
            "list_val": ["secret-a", "secret-b"],
        }
        redacted = redact_vault_data(original)
        assert contains_unredacted(original, redacted) == []


@pytest.mark.parametrize(
    "vault_data",
    [
        {"key": "simple-secret-value"},
        {"key": {"nested": {"deep": "secret-deep-value"}}},
        {"key": ["list-secret-1", "list-secret-2", "list-secret-3"]},
        {"key": {"type": "sshKey", "private_key": "pem-content-here"}},
        {"a": "sec-a", "b": {"c": "sec-c"}, "d": ["sec-d1", {"e": "sec-e"}]},
        {"multiline": "line1\nline2\nline3\nsecret-line"},
        {"unicode": "geheimes-passwort-\u00fc\u00e4\u00f6"},
        {"numbers": {"port": 5432, "retries": 3, "ratio": 0.95}},
        {"empty_dict": {}, "empty_list": [], "empty_str": ""},
        {"bool_val": True, "none_val": None, "int_val": 999999},
    ],
    ids=[
        "simple_string",
        "nested_dict",
        "list_values",
        "typed_entry",
        "mixed_structure",
        "multiline",
        "unicode",
        "numeric_values",
        "empty_containers",
        "special_types",
    ],
)
def test_redaction_completeness(vault_data):
    """Parametrized test: no original value must survive redaction."""
    redacted = redact_vault_data(vault_data)
    leaked = contains_unredacted(vault_data, redacted)
    assert leaked == [], f"Leaked values: {leaked}"
