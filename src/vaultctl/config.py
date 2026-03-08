"""Configuration discovery and loading for vaultctl."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .yaml_util import load_yaml

CONFIG_FILENAME = ".vaultctl.yml"


@dataclass
class PasswordConfig:
    env: str | None = None
    file: str | None = None
    cmd: str | None = None


@dataclass
class VaultConfig:
    vault_file: Path = Path("vault.yml")
    keys_file: Path = Path("vault-keys.yml")
    password: PasswordConfig = field(default_factory=PasswordConfig)
    config_dir: Path = field(default_factory=lambda: Path.cwd())


def _git_root(start: Path) -> Path | None:
    """Find the git repository root from *start* upwards."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--show-toplevel"],
            cwd=start,
            capture_output=True,
            text=True,
            check=True,
        )
        return Path(result.stdout.strip())
    except (subprocess.CalledProcessError, FileNotFoundError):
        return None


def find_config(start: Path | None = None) -> Path | None:
    """Locate .vaultctl.yml using the standard search order.

    1. $VAULTCTL_CONFIG environment variable
    2. .vaultctl.yml in *start* (default: cwd), then upwards to git root
    3. ~/.config/vaultctl/config.yml
    """
    env_path = os.environ.get("VAULTCTL_CONFIG")
    if env_path:
        p = Path(env_path)
        if p.is_file():
            return p
        return None

    start = start or Path.cwd()
    git_root = _git_root(start)
    stop_at = git_root or Path(start.anchor)

    current = start.resolve()
    while True:
        candidate = current / CONFIG_FILENAME
        if candidate.is_file():
            return candidate
        if current == stop_at or current.parent == current:
            break
        current = current.parent

    user_config = Path.home() / ".config" / "vaultctl" / "config.yml"
    if user_config.is_file():
        return user_config

    return None


def load_config(path: Path) -> VaultConfig:
    """Load and validate a vaultctl config file."""
    raw = load_yaml(path)
    config_dir = path.parent.resolve()

    pw_raw = raw.get("password", {}) or {}
    pw = PasswordConfig(
        env=pw_raw.get("env"),
        file=pw_raw.get("file"),
        cmd=pw_raw.get("cmd"),
    )

    vault_file = config_dir / raw.get("vault_file", "vault.yml")
    keys_file = config_dir / raw.get("keys_file", "vault-keys.yml")

    # Expand ~ in password file path
    if pw.file:
        pw.file = str(Path(pw.file).expanduser())

    return VaultConfig(
        vault_file=vault_file,
        keys_file=keys_file,
        password=pw,
        config_dir=config_dir,
    )
