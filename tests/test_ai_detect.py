"""Tests for AI-assisted vault entry type detection."""

from __future__ import annotations

import json

import pytest
from vaultctl.ai_detect import (
    AIDetectionError,
    _parse_ai_response,
    _validate_endpoint,
    build_payload,
    merge_results,
    resolve_api_key,
)
from vaultctl.config import AIConfig
from vaultctl.detect import DetectionResult


class TestBuildPayload:
    def test_redacts_all_values(self):
        vault_data = {"secret_key": "my-super-secret"}
        phase1 = [DetectionResult(key="secret_key", current_type=None, suggested_type="secretText", confidence="low")]
        ai_config = AIConfig(endpoint="https://api.example.com", model="gpt-4o-mini")
        payload = build_payload(vault_data, phase1, ai_config)

        # No secret values in payload
        payload_str = json.dumps(payload.redacted_data)
        assert "my-super-secret" not in payload_str
        assert payload.payload_hash  # has a hash
        assert payload.endpoint == "https://api.example.com"

    def test_includes_phase1_hints(self):
        vault_data = {"db_creds": {"username": "admin", "password": "s3cret"}}
        phase1 = [
            DetectionResult(
                key="db_creds",
                current_type=None,
                suggested_type="usernamePassword",
                confidence="high",
                signals=["fields:password+username"],
            )
        ]
        ai_config = AIConfig(endpoint="https://api.example.com", model="test")
        payload = build_payload(vault_data, phase1, ai_config)
        entries = payload.redacted_data["entries"]
        db_entry = next(e for e in entries if e["key"] == "db_creds")
        assert db_entry["phase1_suggestion"] == "usernamePassword"
        assert db_entry["phase1_confidence"] == "high"

    def test_skipped_entries_no_phase1_hint(self):
        vault_data = {"typed": {"type": "sshKey", "key": "data"}}
        phase1 = [
            DetectionResult(
                key="typed", current_type="sshKey", suggested_type="sshKey", confidence="high", skipped=True
            )
        ]
        ai_config = AIConfig(endpoint="https://api.example.com", model="test")
        payload = build_payload(vault_data, phase1, ai_config)
        entries = payload.redacted_data["entries"]
        typed_entry = next(e for e in entries if e["key"] == "typed")
        assert "phase1_suggestion" not in typed_entry

    def test_no_secret_in_structured_entry(self):
        vault_data = {
            "creds": {
                "type": "usernamePassword",
                "username": "admin-user",
                "password": "P@ssw0rd!Complex",
            }
        }
        phase1 = [
            DetectionResult(
                key="creds",
                current_type="usernamePassword",
                suggested_type="usernamePassword",
                confidence="high",
                skipped=True,
            )
        ]
        ai_config = AIConfig(endpoint="https://api.example.com", model="test")
        payload = build_payload(vault_data, phase1, ai_config)
        payload_str = json.dumps(payload.redacted_data)
        assert "admin-user" not in payload_str
        assert "P@ssw0rd" not in payload_str

    def test_deterministic_hash(self):
        vault_data = {"key": "value"}
        phase1 = [DetectionResult(key="key", current_type=None, suggested_type="secretText", confidence="low")]
        ai_config = AIConfig(endpoint="https://api.example.com", model="test")
        h1 = build_payload(vault_data, phase1, ai_config).payload_hash
        h2 = build_payload(vault_data, phase1, ai_config).payload_hash
        assert h1 == h2

    def test_redaction_runtime_guard(self, monkeypatch: pytest.MonkeyPatch):
        """build_payload aborts if redaction verification detects leaked values."""
        from vaultctl import ai_detect

        # Monkey-patch redact_vault_data to return data unchanged (simulating a broken redactor).
        monkeypatch.setattr(ai_detect, "redact_vault_data", lambda data: data)

        vault_data = {"secret_key": "my-super-secret-value"}
        phase1 = [DetectionResult(key="secret_key", current_type=None, suggested_type="secretText", confidence="low")]
        ai_config = AIConfig(endpoint="https://api.example.com", model="test")

        with pytest.raises(AIDetectionError, match="Redaction verification failed"):
            build_payload(vault_data, phase1, ai_config)


class TestValidateEndpoint:
    def test_https_accepted(self):
        _validate_endpoint("https://api.openai.com/v1/chat/completions")

    def test_localhost_http_accepted(self):
        _validate_endpoint("http://localhost:11434/v1/chat/completions")
        _validate_endpoint("http://127.0.0.1:11434/v1/chat/completions")

    def test_remote_http_rejected(self):
        with pytest.raises(AIDetectionError, match="HTTPS"):
            _validate_endpoint("http://api.example.com/v1/chat/completions")

    def test_empty_endpoint_rejected(self):
        with pytest.raises(AIDetectionError, match="No AI endpoint"):
            _validate_endpoint("")


class TestResolveApiKey:
    def test_success(self):
        key = resolve_api_key("echo test-api-key-123")
        assert key == "test-api-key-123"

    def test_failing_command(self):
        with pytest.raises(AIDetectionError, match="Failed to execute"):
            resolve_api_key("false")

    def test_empty_cmd(self):
        with pytest.raises(AIDetectionError, match="No api_key_cmd"):
            resolve_api_key("")


class TestParseAIResponse:
    def test_valid_response(self):
        response = {
            "choices": [
                {
                    "message": {
                        "content": json.dumps(
                            [{"key": "db_creds", "suggested_type": "usernamePassword", "confidence": "high"}]
                        )
                    }
                }
            ]
        }
        results = _parse_ai_response(response)
        assert len(results) == 1
        assert results[0]["key"] == "db_creds"
        assert results[0]["suggested_type"] == "usernamePassword"

    def test_markdown_code_fence(self):
        response = {"choices": [{"message": {"content": '```json\n[{"key": "k", "suggested_type": "sshKey"}]\n```'}}]}
        results = _parse_ai_response(response)
        assert len(results) == 1

    def test_invalid_json(self):
        response = {"choices": [{"message": {"content": "not json"}}]}
        assert _parse_ai_response(response) == []

    def test_missing_fields(self):
        response = {"choices": [{"message": {"content": '[{"key": "k"}]'}}]}
        results = _parse_ai_response(response)
        assert results == []  # missing suggested_type

    def test_empty_response(self):
        assert _parse_ai_response({}) == []

    def test_rejects_non_string_values(self):
        response = {
            "choices": [
                {"message": {"content": json.dumps([{"key": "k", "suggested_type": 123, "confidence": "high"}])}}
            ]
        }
        results = _parse_ai_response(response)
        assert results == []  # suggested_type is int, rejected


class TestMergeResults:
    def test_ai_upgrades_low_confidence(self):
        phase1 = [
            DetectionResult(key="k", current_type=None, suggested_type="secretText", confidence="low", signals=[])
        ]
        ai = [{"key": "k", "suggested_type": "usernamePassword", "confidence": "high"}]
        merged = merge_results(phase1, ai)
        assert merged[0].suggested_type == "usernamePassword"
        assert "ai:usernamePassword" in merged[0].signals

    def test_phase1_high_not_overridden(self):
        phase1 = [
            DetectionResult(
                key="k", current_type=None, suggested_type="sshKey", confidence="high", signals=["fields:key"]
            )
        ]
        ai = [{"key": "k", "suggested_type": "certificate", "confidence": "high"}]
        merged = merge_results(phase1, ai)
        assert merged[0].suggested_type == "sshKey"  # Phase 1 wins

    def test_skipped_not_modified(self):
        phase1 = [
            DetectionResult(key="k", current_type="sshKey", suggested_type="sshKey", confidence="high", skipped=True)
        ]
        ai = [{"key": "k", "suggested_type": "certificate", "confidence": "high"}]
        merged = merge_results(phase1, ai)
        assert merged[0].skipped is True

    def test_no_ai_suggestions(self):
        phase1 = [DetectionResult(key="k", current_type=None, suggested_type="secretText", confidence="low")]
        merged = merge_results(phase1, [])
        assert merged[0].suggested_type == "secretText"

    def test_ai_low_confidence_ignored(self):
        phase1 = [DetectionResult(key="k", current_type=None, suggested_type="secretText", confidence="low")]
        ai = [{"key": "k", "suggested_type": "sshKey", "confidence": "low"}]
        merged = merge_results(phase1, ai)
        assert merged[0].suggested_type == "secretText"  # AI low confidence ignored
