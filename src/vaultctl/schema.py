"""CUE-based schema validation for vaultctl files.

Calls the external `cue` binary via subprocess (same pattern as ansible-vault).
Schema files are bundled with the package under `vaultctl/schemas/` and can be
overridden by user-provided schemas under `.vaultctl/<name>.cue`.

If the `cue` binary is not on PATH, schema validation is skipped gracefully —
callers should treat `cue_available()` as a feature flag.
"""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Any

import yaml


class SchemaError(Exception):
    """Raised when schema validation fails or cannot be performed."""


@dataclass(frozen=True)
class ValidationIssue:
    """A single schema-violation finding."""

    file: str
    message: str


def cue_available() -> bool:
    """Return True if the `cue` binary is on PATH."""
    return shutil.which("cue") is not None


def bundled_schema(name: str) -> Path:
    """Return the filesystem path of a bundled CUE schema.

    Names are without extension: "config", "keys", "vault".
    Falls back through importlib.resources to support installed wheels.
    """
    filename = f"{name}.cue"
    schema_resource = resources.files("vaultctl.schemas").joinpath(filename)
    # importlib.resources returns Traversable; for our use case (subprocess
    # call to cue), we need a real filesystem path. Materialise if needed.
    with resources.as_file(schema_resource) as p:
        if p.is_file():
            return Path(p)
    msg = f"Bundled schema '{name}' not found."
    raise SchemaError(msg)


def discover_user_schema(config_dir: Path, name: str) -> Path | None:
    """Look for a user-provided override schema in `.vaultctl/<name>.cue`.

    `config_dir` is the project root (parent of `.vaultctl/`). Returns None
    if no override exists.
    """
    candidate = config_dir / ".vaultctl" / f"{name}.cue"
    return candidate if candidate.is_file() else None


def _run_cue_vet(schema_path: Path, definition: str, data_path: Path) -> list[str]:
    """Invoke `cue vet -d <definition> <schema> <data>` and return stderr lines."""
    try:
        result = subprocess.run(  # nosec B603
            ["cue", "vet", "-d", definition, str(schema_path), str(data_path)],
            capture_output=True,
            text=True,
            check=False,
        )
    except FileNotFoundError as exc:
        msg = "cue binary not found on PATH."
        raise SchemaError(msg) from exc

    if result.returncode == 0:
        return []
    # cue prints diagnostics to stderr. Each line is a finding.
    return [line for line in result.stderr.splitlines() if line.strip()]


def validate_yaml_against_schema(
    data: dict[str, Any], schema_path: Path, definition: str, label: str
) -> list[ValidationIssue]:
    """Validate an in-memory YAML structure against a CUE schema definition.

    Writes the data to a temp YAML file and calls `cue vet`. The temp file is
    removed on exit. Returns a (possibly empty) list of issues.
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as tf:
        yaml.safe_dump(data, tf, default_flow_style=False, allow_unicode=True)
        tmp_path = Path(tf.name)
    try:
        diagnostics = _run_cue_vet(schema_path, definition, tmp_path)
    finally:
        tmp_path.unlink(missing_ok=True)
    return [ValidationIssue(file=label, message=line) for line in diagnostics]


def validate_config_file(config_path: Path) -> list[ValidationIssue]:
    """Validate a .vaultctl/config.yml file against the bundled #Config schema."""
    schema = bundled_schema("config")
    diagnostics = _run_cue_vet(schema, "#Config", config_path)
    return [ValidationIssue(file=str(config_path), message=line) for line in diagnostics]


def validate_keys_file(keys_path: Path, override: Path | None = None) -> list[ValidationIssue]:
    """Validate vault-keys.yml against the bundled or user-provided #KeysFile schema."""
    schema = override or bundled_schema("keys")
    diagnostics = _run_cue_vet(schema, "#KeysFile", keys_path)
    return [ValidationIssue(file=str(keys_path), message=line) for line in diagnostics]


def validate_vault_data(
    vault_data: dict[str, Any], override: Path | None = None, label: str = "vault.yml"
) -> list[ValidationIssue]:
    """Validate decrypted vault content against the bundled or user-provided #VaultFile schema.

    The data is written to a temp file because cue operates on filesystem inputs.
    """
    schema = override or bundled_schema("vault")
    return validate_yaml_against_schema(vault_data, schema, "#VaultFile", label)


def cross_check_keys(vault_data: dict[str, Any], keys_meta: dict[str, Any]) -> list[ValidationIssue]:
    """Check that every key in vault.yml has metadata in vault-keys.yml and vice versa.

    `_previous` backup keys are exempt from the metadata-required check.
    Pure Python — does not require the cue binary.
    """
    vault_keys = {k for k in vault_data if not k.endswith("_previous")}
    metadata_keys = set((keys_meta.get("vault_keys") or {}).keys())

    issues: list[ValidationIssue] = []
    for k in sorted(vault_keys - metadata_keys):
        issues.append(
            ValidationIssue(
                file="cross-check",
                message=f"key '{k}' has a value in vault.yml but no metadata in vault-keys.yml",
            )
        )
    for k in sorted(metadata_keys - vault_keys):
        issues.append(
            ValidationIssue(
                file="cross-check",
                message=f"key '{k}' has metadata in vault-keys.yml but no value in vault.yml",
            )
        )
    return issues
