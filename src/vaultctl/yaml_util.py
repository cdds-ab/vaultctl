"""YAML safe_load/dump helpers with consistent formatting."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_yaml(path: Path) -> dict[str, Any]:
    """Load a YAML file, returning an empty dict if the file is empty."""
    text = path.read_text(encoding="utf-8")
    return yaml.safe_load(text) or {}


def dump_yaml(data: dict[str, Any], path: Path) -> None:
    """Write *data* as YAML to *path* with stable formatting."""
    path.write_text(
        yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=True),
        encoding="utf-8",
    )


def load_yaml_text(text: str) -> dict[str, Any]:
    """Parse a YAML string, returning an empty dict if blank."""
    return yaml.safe_load(text) or {}


def dump_yaml_text(data: dict[str, Any]) -> str:
    """Serialize *data* to a YAML string with stable formatting."""
    return yaml.dump(data, default_flow_style=False, allow_unicode=True, sort_keys=True)
