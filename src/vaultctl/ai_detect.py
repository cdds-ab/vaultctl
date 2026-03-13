"""AI-assisted vault entry type detection with mandatory redaction.

All data sent externally passes through ``redact_vault_data()`` — the redaction
function is a security boundary. No original secret values may leave the process.
"""

from __future__ import annotations

import hashlib
import json
import logging
import subprocess
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .config import AIConfig
from .detect import DetectionResult
from .redact import redact_vault_data

logger = logging.getLogger(__name__)

# Only the redacted payload structure is logged, never raw vault data.
# Logging is disabled by default; enable with --debug-ai.


class AIDetectionError(Exception):
    """Raised when AI detection fails. Never contains secret data."""


@dataclass
class AIPayload:
    """The redacted payload prepared for the AI provider."""

    redacted_data: dict[str, Any]
    payload_hash: str
    endpoint: str
    model: str


def resolve_api_key(api_key_cmd: str) -> str:
    """Execute a command to retrieve the API key.

    The API key is never logged or included in error messages.
    """
    if not api_key_cmd:
        msg = "No api_key_cmd configured in .vaultctl.yml ai: section."
        raise AIDetectionError(msg)
    try:
        result = subprocess.run(  # nosec B602
            api_key_cmd,
            shell=True,
            capture_output=True,
            text=True,
            check=True,
        )
        return result.stdout.strip()
    except subprocess.CalledProcessError:
        # Never include stderr — it might contain hints about the key store.
        msg = f"Failed to execute api_key_cmd: '{api_key_cmd}'"
        raise AIDetectionError(msg) from None


def build_payload(
    vault_data: dict[str, Any],
    phase1_results: list[DetectionResult],
    ai_config: AIConfig,
) -> AIPayload:
    """Build the AI request payload from redacted vault data.

    Data minimization: only key names, structure, field names, and Phase 1
    type hints are included. No secret values, no expiry metadata, no
    consumer lists.
    """
    redacted = redact_vault_data(vault_data)

    # Build a minimal structure for the AI
    entries: list[dict[str, Any]] = []
    p1_by_key = {r.key: r for r in phase1_results}
    for key, value in sorted(redacted.items()):
        entry: dict[str, Any] = {"key": key}
        if isinstance(value, dict):
            entry["fields"] = sorted(value.keys())
            if "type" in value:
                entry["explicit_type"] = value["type"]
        else:
            entry["value_type"] = "string"

        p1 = p1_by_key.get(key)
        if p1 and not p1.skipped:
            entry["phase1_suggestion"] = p1.suggested_type
            entry["phase1_confidence"] = p1.confidence

        entries.append(entry)

    payload_json = json.dumps(entries, sort_keys=True)
    payload_hash = hashlib.sha256(payload_json.encode()).hexdigest()

    return AIPayload(
        redacted_data={"entries": entries},
        payload_hash=payload_hash,
        endpoint=ai_config.endpoint,
        model=ai_config.model,
    )


def _validate_endpoint(endpoint: str) -> None:
    """Validate the AI endpoint URL for security.

    HTTPS required for all non-localhost endpoints. HTTP allowed only
    for local services (Ollama, vLLM, etc.).
    """
    if not endpoint:
        msg = "No AI endpoint configured in .vaultctl.yml ai: section."
        raise AIDetectionError(msg)
    if endpoint.startswith("http://"):
        from urllib.parse import urlparse

        host = urlparse(endpoint).hostname or ""
        if host not in ("localhost", "127.0.0.1", "::1"):
            msg = f"HTTP endpoint '{host}' is not localhost. Use HTTPS for remote endpoints."
            raise AIDetectionError(msg)


def call_ai(payload: AIPayload, api_key: str, timeout: int = 30) -> list[dict[str, Any]]:
    """Send the redacted payload to the AI provider and parse the response.

    Uses OpenAI-compatible chat completions API format (works with
    OpenAI, Ollama, vLLM, LiteLLM, etc.).

    The response is treated as untrusted data — parsed as JSON string
    literals only, never evaluated.
    """
    _validate_endpoint(payload.endpoint)

    prompt = (
        "You are a vault secrets classifier. Given the following vault entry metadata "
        "(all values are redacted), suggest the most appropriate type for each entry.\n"
        "Known types: secretText, usernamePassword, sshKey, certificate\n"
        "Respond with a JSON array of objects: "
        '[{"key": "...", "suggested_type": "...", "confidence": "high|medium|low"}]\n'
        "Only respond with the JSON array, no other text.\n\n"
        f"Entries:\n{json.dumps(payload.redacted_data['entries'], indent=2)}"
    )

    request_body = json.dumps(
        {
            "model": payload.model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0,
        }
    ).encode()

    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {api_key}",
    }

    req = urllib.request.Request(
        payload.endpoint,
        data=request_body,
        headers=headers,
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # nosec B310
            response_data = json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        # Exception firewall: never include response body in error
        msg = f"AI request failed: {type(exc).__name__}"
        raise AIDetectionError(msg) from None
    except (json.JSONDecodeError, TimeoutError) as exc:
        msg = f"AI response parsing failed: {type(exc).__name__}"
        raise AIDetectionError(msg) from None

    return _parse_ai_response(response_data)


def _parse_ai_response(response_data: dict[str, Any]) -> list[dict[str, Any]]:
    """Parse the AI response, treating it as untrusted data.

    Extracts only string literal values — never evaluates code.
    """
    try:
        content = response_data["choices"][0]["message"]["content"]
        # Strip markdown code fences if present
        content = content.strip()
        if content.startswith("```"):
            content = content.split("\n", 1)[1] if "\n" in content else content[3:]
        if content.endswith("```"):
            content = content[: content.rfind("```")]
        content = content.strip()

        suggestions: list[dict[str, Any]] = json.loads(content)
    except (KeyError, IndexError, json.JSONDecodeError):
        return []

    # Validate structure — only accept known fields with string values
    validated: list[dict[str, Any]] = []
    for item in suggestions:
        if not isinstance(item, dict):
            continue
        entry: dict[str, str] = {}
        for field in ("key", "suggested_type", "confidence"):
            val = item.get(field)
            if isinstance(val, str):
                entry[field] = val
        if "key" in entry and "suggested_type" in entry:
            validated.append(entry)

    return validated


def merge_results(
    phase1: list[DetectionResult],
    ai_suggestions: list[dict[str, Any]],
) -> list[DetectionResult]:
    """Merge AI suggestions with Phase 1 results.

    Phase 1 (local heuristics) takes priority on conflicts.
    AI suggestions only upgrade low-confidence Phase 1 results.
    """
    ai_by_key = {s["key"]: s for s in ai_suggestions}

    merged: list[DetectionResult] = []
    for r in phase1:
        ai = ai_by_key.get(r.key)
        if ai and not r.skipped and r.confidence == "low":
            ai_type = ai.get("suggested_type", r.suggested_type)
            ai_conf = ai.get("confidence", "low")
            if ai_conf in ("high", "medium") and ai_type != r.suggested_type:
                merged.append(
                    DetectionResult(
                        key=r.key,
                        current_type=r.current_type,
                        suggested_type=str(ai_type),
                        confidence="medium",
                        signals=[*r.signals, f"ai:{ai_type}"],
                    )
                )
                continue
        merged.append(r)

    return merged
