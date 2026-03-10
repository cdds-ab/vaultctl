"""Tests for vault entry type detection utilities."""

from __future__ import annotations

import pytest
from vaultctl.types import (
    DEFAULT_TYPE,
    detect_entry_type,
    get_entry_fields,
    get_field_value,
)


class TestDetectEntryType:
    def test_string_value(self):
        assert detect_entry_type("some-password") == "secretText"

    def test_dict_without_type(self):
        assert detect_entry_type({"username": "u", "password": "p"}) == "secretText"

    def test_dict_with_type(self):
        val = {"type": "usernamePassword", "username": "u", "password": "p"}
        assert detect_entry_type(val) == "usernamePassword"

    def test_dict_with_custom_type(self):
        assert detect_entry_type({"type": "custom"}) == "custom"

    def test_none_value(self):
        assert detect_entry_type(None) == DEFAULT_TYPE

    def test_int_value(self):
        assert detect_entry_type(42) == DEFAULT_TYPE


class TestGetEntryFields:
    def test_string_value(self):
        assert get_entry_fields("secret") == []

    def test_dict_excludes_type(self):
        val = {"type": "usernamePassword", "username": "u", "password": "p"}
        assert get_entry_fields(val) == ["password", "username"]

    def test_dict_without_type(self):
        assert get_entry_fields({"a": 1, "b": 2}) == ["a", "b"]

    def test_empty_dict(self):
        assert get_entry_fields({}) == []


class TestGetFieldValue:
    def test_valid_field(self):
        val = {"type": "usernamePassword", "username": "u", "password": "p"}
        assert get_field_value(val, "password") == "p"

    def test_missing_field(self):
        with pytest.raises(KeyError, match="not found"):
            get_field_value({"username": "u"}, "password")

    def test_string_raises(self):
        with pytest.raises(KeyError, match="not structured"):
            get_field_value("plain-secret", "field")
