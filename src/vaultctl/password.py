"""Vault password resolution with configurable fallback chain."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .config import PasswordConfig


class PasswordError(Exception):
    """Raised when no vault password source yields a result."""


def resolve_password(cfg: PasswordConfig) -> str:
    """Resolve the vault password using the configured fallback chain.

    Order:
      1. Environment variable (cfg.env)
      2. File (cfg.file)
      3. Command execution (cfg.cmd)
    """
    tried: list[str] = []

    # 1. Environment variable
    if cfg.env:
        value = os.environ.get(cfg.env)
        if value:
            return value
        tried.append(f"env ${cfg.env} (not set)")

    # 2. File
    if cfg.file:
        p = Path(cfg.file).expanduser()
        if p.is_file():
            return p.read_text(encoding="utf-8").strip()
        tried.append(f"file {cfg.file} (not found)")

    # 3. Command
    if cfg.cmd:
        try:
            result = subprocess.run(  # nosec B602 — shell=True is intentional; cmd comes from user-controlled config file
                cfg.cmd,
                shell=True,
                capture_output=True,
                text=True,
                check=True,
            )
            return result.stdout.strip()
        except subprocess.CalledProcessError:
            tried.append(f"cmd '{cfg.cmd}' (failed)")

    sources = "\n  ".join(tried) if tried else "(no sources configured)"
    raise PasswordError(
        f"Vault password not found. Tried:\n  {sources}\n\n"
        "Configure a password source in .vaultctl.yml under 'password:'."
    )
