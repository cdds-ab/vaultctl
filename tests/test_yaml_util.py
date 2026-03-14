"""Tests for vaultctl.yaml_util module."""

from __future__ import annotations

from vaultctl.yaml_util import clean_multiline_value


class TestCleanMultilineValue:
    def test_strips_trailing_spaces(self) -> None:
        result = clean_multiline_value("line1  \nline2\t\nline3\n")
        assert result == "line1\nline2\nline3\n"

    def test_ensures_trailing_newline(self) -> None:
        result = clean_multiline_value("no trailing newline")
        assert result == "no trailing newline\n"

    def test_single_trailing_newline(self) -> None:
        result = clean_multiline_value("line\n\n\n")
        assert result == "line\n"

    def test_ssh_key_format(self) -> None:
        key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEA  \nAAAA  \n-----END OPENSSH PRIVATE KEY-----\n"
        result = clean_multiline_value(key)
        assert "  " not in result
        assert result.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n")
        assert result.endswith("-----END OPENSSH PRIVATE KEY-----\n")

    def test_empty_string(self) -> None:
        result = clean_multiline_value("")
        assert result == "\n"

    def test_preserves_internal_spaces(self) -> None:
        result = clean_multiline_value("hello world\nfoo  bar\n")
        assert result == "hello world\nfoo  bar\n"

    def test_already_clean(self) -> None:
        clean = "line1\nline2\nline3\n"
        result = clean_multiline_value(clean)
        assert result == clean
