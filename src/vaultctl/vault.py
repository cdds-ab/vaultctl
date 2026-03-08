"""Ansible Vault decrypt/encrypt wrapper using subprocess."""

from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from .yaml_util import dump_yaml_text, load_yaml_text


class VaultError(Exception):
    """Raised on ansible-vault operation failures."""


def _run_vault(args: list[str], password: str) -> subprocess.CompletedProcess:
    """Run ansible-vault with a temporary password file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pass", delete=True) as pf:
        pf.write(password)
        pf.flush()
        try:
            return subprocess.run(
                ["ansible-vault", *args, "--vault-password-file", pf.name],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            raise VaultError(f"ansible-vault {args[0]} failed: {exc.stderr.strip()}") from exc


def decrypt_vault(vault_file: Path, password: str) -> dict:
    """Decrypt an ansible-vault file and return the parsed YAML data."""
    result = _run_vault(["view", str(vault_file)], password)
    return load_yaml_text(result.stdout)


def encrypt_vault(data: dict, vault_file: Path, password: str) -> None:
    """Serialize *data* as YAML and encrypt it to *vault_file*."""
    yaml_text = dump_yaml_text(data)
    with tempfile.NamedTemporaryFile(mode="w", suffix=".yml", delete=False) as tmp:
        tmp.write(yaml_text)
        tmp_path = Path(tmp.name)
    try:
        _run_vault(["encrypt", str(tmp_path), "--output", str(vault_file)], password)
    finally:
        tmp_path.unlink(missing_ok=True)


def edit_vault(vault_file: Path, password: str) -> None:
    """Open the vault file in $EDITOR via ansible-vault edit."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".pass", delete=True) as pf:
        pf.write(password)
        pf.flush()
        try:
            subprocess.run(
                [
                    "ansible-vault",
                    "edit",
                    str(vault_file),
                    "--vault-password-file",
                    pf.name,
                ],
                check=True,
            )
        except subprocess.CalledProcessError as exc:
            raise VaultError("ansible-vault edit failed") from exc
