"""Ansible Vault decrypt/encrypt wrapper using subprocess."""

from __future__ import annotations

import os
import subprocess
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

from .yaml_util import dump_yaml_text, load_yaml_text


@contextmanager
def _secure_tempfile(
    suffix: str = "", delete: bool = True
) -> Iterator[tuple[Path, int]]:
    """Create a temporary file with restrictive permissions (0600).

    Yields a (path, fd) tuple.  The caller must write via os.fdopen or
    os.write and close the fd when done.  If *delete* is True the file
    is removed on context-manager exit.
    """
    fd, name = tempfile.mkstemp(suffix=suffix)
    path = Path(name)
    # Ensure 0600 regardless of umask (mkstemp already does this on most
    # platforms, but we enforce it explicitly for safety).
    os.fchmod(fd, 0o600)
    try:
        yield path, fd
    finally:
        # Ensure fd is closed (ignore if already closed by caller).
        try:
            os.close(fd)
        except OSError:
            pass
        if delete:
            path.unlink(missing_ok=True)


class VaultError(Exception):
    """Raised on ansible-vault operation failures."""


def _run_vault(args: list[str], password: str) -> subprocess.CompletedProcess[str]:
    """Run ansible-vault with a temporary password file."""
    with _secure_tempfile(suffix=".pass", delete=True) as (pf_path, pf_fd):
        with os.fdopen(pf_fd, "w") as pf:
            pf.write(password)
            pf.flush()
            try:
                return subprocess.run(
                    ["ansible-vault", *args, "--vault-password-file", str(pf_path)],
                    capture_output=True,
                    text=True,
                    check=True,
                )
            except subprocess.CalledProcessError as exc:
                raise VaultError(f"ansible-vault {args[0]} failed: {exc.stderr.strip()}") from exc


def decrypt_vault(vault_file: Path, password: str) -> dict[str, Any]:
    """Decrypt an ansible-vault file and return the parsed YAML data."""
    result = _run_vault(["view", str(vault_file)], password)
    return load_yaml_text(result.stdout)


def encrypt_vault(data: dict[str, Any], vault_file: Path, password: str) -> None:
    """Serialize *data* as YAML and encrypt it to *vault_file*."""
    yaml_text = dump_yaml_text(data)
    with _secure_tempfile(suffix=".yml", delete=False) as (tmp_path, tmp_fd):
        with os.fdopen(tmp_fd, "w") as tmp:
            tmp.write(yaml_text)
    try:
        _run_vault(["encrypt", str(tmp_path), "--output", str(vault_file)], password)
    finally:
        tmp_path.unlink(missing_ok=True)


def edit_vault(vault_file: Path, password: str) -> None:
    """Open the vault file in $EDITOR via ansible-vault edit."""
    with _secure_tempfile(suffix=".pass", delete=True) as (pf_path, pf_fd):
        with os.fdopen(pf_fd, "w") as pf:
            pf.write(password)
            pf.flush()
            try:
                subprocess.run(
                    [
                        "ansible-vault",
                        "edit",
                        str(vault_file),
                        "--vault-password-file",
                        str(pf_path),
                    ],
                    check=True,
                )
            except subprocess.CalledProcessError as exc:
                raise VaultError("ansible-vault edit failed") from exc
