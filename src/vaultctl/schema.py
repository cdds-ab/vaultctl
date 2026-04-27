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


def _siblings_of(schema_path: Path) -> list[Path]:
    """Sibling .cue files in the same directory (excluding the schema itself).

    Supports the baseline + constraints pattern: a user-maintained
    vault.cue alongside hand-edited vault.constraints.cue both contribute
    to the effective schema via CUE's package merging.
    """
    return sorted(p for p in schema_path.parent.glob("*.cue") if p != schema_path)


def _run_cue_vet(schema_path: Path, definition: str, data_path: Path, include_siblings: bool = False) -> list[str]:
    """Invoke `cue vet -d <definition> <schema> [siblings...] <data>` and return stderr lines."""
    schema_files: list[Path] = [schema_path]
    if include_siblings:
        schema_files.extend(_siblings_of(schema_path))
    try:
        result = subprocess.run(  # nosec B603
            ["cue", "vet", "-d", definition, *(str(p) for p in schema_files), str(data_path)],
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
    data: dict[str, Any],
    schema_path: Path,
    definition: str,
    label: str,
    include_siblings: bool = False,
) -> list[ValidationIssue]:
    """Validate an in-memory YAML structure against a CUE schema definition.

    Writes the data to a temp YAML file and calls `cue vet`. The temp file is
    removed on exit. When `include_siblings` is True, sibling .cue files in
    the schema's directory are merged in (baseline + constraints pattern).
    """
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as tf:
        yaml.safe_dump(data, tf, default_flow_style=False, allow_unicode=True)
        tmp_path = Path(tf.name)
    try:
        diagnostics = _run_cue_vet(schema_path, definition, tmp_path, include_siblings=include_siblings)
    finally:
        tmp_path.unlink(missing_ok=True)
    return [ValidationIssue(file=label, message=line) for line in diagnostics]


def validate_config_file(config_path: Path) -> list[ValidationIssue]:
    """Validate a .vaultctl/config.yml file against the bundled #Config schema."""
    schema = bundled_schema("config")
    diagnostics = _run_cue_vet(schema, "#Config", config_path)
    return [ValidationIssue(file=str(config_path), message=line) for line in diagnostics]


def validate_keys_file(keys_path: Path, override: Path | None = None) -> list[ValidationIssue]:
    """Validate vault-keys.yml against the bundled or user-provided #KeysFile schema.

    Sibling .cue files are merged in only for user overrides — supports the
    baseline + constraints pattern.
    """
    schema = override or bundled_schema("keys")
    diagnostics = _run_cue_vet(schema, "#KeysFile", keys_path, include_siblings=override is not None)
    return [ValidationIssue(file=str(keys_path), message=line) for line in diagnostics]


def validate_vault_data(
    vault_data: dict[str, Any], override: Path | None = None, label: str = "vault.yml"
) -> list[ValidationIssue]:
    """Validate decrypted vault content against the bundled or user-provided #VaultFile schema.

    The data is written to a temp file because cue operates on filesystem inputs.
    Sibling .cue files are merged in only for user overrides.
    """
    schema = override or bundled_schema("vault")
    return validate_yaml_against_schema(vault_data, schema, "#VaultFile", label, include_siblings=override is not None)


# --- schema inference (data → CUE) ---

INFER_HEADER = (
    "// AUTO-GENERATED by `vaultctl schema infer` — do not hand-edit.\n"
    "// Project-specific constraints (regex, ranges, required fields) belong in\n"
    "// vault.constraints.cue alongside this file. CUE merges both at validation time.\n"
)


def _is_safe_identifier(name: str) -> bool:
    """CUE-safe unquoted field name: ASCII letters/digits/underscore, no leading digit."""
    if not name:
        return False
    if name[0].isdigit():
        return False
    return all(c.isalnum() or c == "_" for c in name)


def _quote_field(name: str) -> str:
    return name if _is_safe_identifier(name) else f'"{name}"'


def _render_type(value: Any, indent: int) -> str:
    """Map a Python value to a CUE type expression. Recursive for dicts/lists."""
    # bool MUST be checked before int — bool is a subclass of int in Python.
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, str):
        return "string"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "number"
    if value is None:
        return "null"
    if isinstance(value, list):
        if not value:
            return "[...]"
        elem_types = sorted({_render_type(v, indent) for v in value})
        if len(elem_types) == 1:
            return f"[...{elem_types[0]}]"
        return f"[...({' | '.join(elem_types)})]"
    if isinstance(value, dict):
        if not value:
            return "{}"
        prefix = "\t" * indent
        inner_lines = [f"{prefix}\t{_quote_field(k)}: {_render_type(v, indent + 1)}" for k, v in sorted(value.items())]
        return "{\n" + "\n".join(inner_lines) + f"\n{prefix}}}"
    # Unknown type — fall back to top type. Keeps inference total without
    # hiding the surprise in silently-stricter rules.
    return "_"


def infer_vault_schema(vault_data: dict[str, Any]) -> str:
    """Render a closed CUE #VaultFile definition that exactly covers the given data.

    `_previous` backup keys are excluded — they are an implementation detail of
    `vaultctl set --backup` and shouldn't appear in the schema surface.

    The output is deterministic (sorted keys), suitable for git-tracking.
    """
    real_keys = {k: v for k, v in vault_data.items() if not k.endswith("_previous")}

    body_lines: list[str]
    if not real_keys:
        body_lines = []
    else:
        body_lines = [f"\t{_quote_field(k)}: {_render_type(v, 1)}" for k, v in sorted(real_keys.items())]

    header = INFER_HEADER
    package = "package vaultctl\n"
    body = "#VaultFile: {\n" + ("\n".join(body_lines) + "\n" if body_lines else "") + "}\n"
    return f"{header}\n{package}\n{body}"


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
