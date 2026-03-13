"""Self-update mechanism for standalone vaultctl binaries."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from packaging.version import InvalidVersion, Version

GITHUB_REPO = "cdds-ab/vaultctl"
RELEASES_API = f"https://api.github.com/repos/{GITHUB_REPO}/releases/latest"


class UpdateError(Exception):
    """Raised when self-update fails."""


@dataclass
class ReleaseInfo:
    """Information about a GitHub release."""

    tag: str
    version: str
    asset_url: str
    asset_name: str
    checksums_url: str


def is_frozen() -> bool:
    """Check if running as a PyInstaller standalone binary."""
    return bool(getattr(sys, "frozen", False))


def get_platform_asset_name() -> str:
    """Determine the expected binary asset name for this platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        msg = f"Unsupported architecture: {machine}"
        raise UpdateError(msg)

    if system == "linux":
        return f"vaultctl-linux-{arch}"
    if system == "darwin":
        return f"vaultctl-macos-{arch}"
    msg = f"Unsupported platform: {system}"
    raise UpdateError(msg)


def fetch_latest_release() -> ReleaseInfo:
    """Fetch the latest release information from GitHub."""
    req = urllib.request.Request(RELEASES_API, headers={"Accept": "application/vnd.github.v3+json"})

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            data = json.loads(resp.read().decode())
    except urllib.error.URLError as exc:
        msg = f"Failed to check for updates: {exc.reason}"
        raise UpdateError(msg) from None

    tag = data.get("tag_name", "")
    version = tag.lstrip("v")
    asset_name = get_platform_asset_name()

    binary_url = ""
    checksums_url = ""
    for asset in data.get("assets", []):
        if asset["name"] == asset_name:
            binary_url = asset["browser_download_url"]
        elif asset["name"] == "checksums.sha256":
            checksums_url = asset["browser_download_url"]

    if not binary_url:
        msg = f"No binary found for this platform ({asset_name}) in release {tag}"
        raise UpdateError(msg)

    return ReleaseInfo(
        tag=tag,
        version=version,
        asset_url=binary_url,
        asset_name=asset_name,
        checksums_url=checksums_url,
    )


def download_binary(url: str, dest: str) -> None:
    """Download a binary from a URL to a local path."""
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=120) as resp:  # nosec B310
            with Path(dest).open("wb") as f:
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    f.write(chunk)
    except urllib.error.URLError as exc:
        msg = f"Download failed: {exc.reason}"
        raise UpdateError(msg) from None


def fetch_checksums(url: str) -> dict[str, str]:
    """Download and parse the checksums.sha256 file.

    Returns a dict mapping filename -> sha256 hex digest.
    Format: ``<hash>  <filename>`` (sha256sum output format).
    """
    req = urllib.request.Request(url)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # nosec B310
            content = resp.read().decode()
    except urllib.error.URLError as exc:
        msg = f"Failed to download checksums: {exc.reason}"
        raise UpdateError(msg) from None

    checksums: dict[str, str] = {}
    for line in content.strip().splitlines():
        parts = line.split(maxsplit=1)
        if len(parts) == 2:
            checksums[parts[1].strip()] = parts[0].strip()
    return checksums


def verify_checksum(file_path: str, expected_hash: str) -> None:
    """Verify the SHA256 checksum of a downloaded file."""
    sha256 = hashlib.sha256()
    with Path(file_path).open("rb") as f:
        while True:
            chunk = f.read(65536)
            if not chunk:
                break
            sha256.update(chunk)

    actual = sha256.hexdigest()
    if actual != expected_hash:
        msg = f"Checksum mismatch: expected {expected_hash[:16]}…, got {actual[:16]}…"
        raise UpdateError(msg)


def _is_newer(current: str, candidate: str) -> bool:
    """Check if candidate version is newer than current (semantic comparison)."""
    try:
        return Version(candidate) > Version(current)
    except InvalidVersion:
        # Fall back to string comparison for non-PEP440 versions
        return candidate != current


def self_update(current_version: str) -> str | None:
    """Check for updates and replace the current binary if newer.

    Only works for standalone (PyInstaller) binaries.
    Returns the new version string, or None if already up to date.
    """
    if not is_frozen():
        msg = "Self-update is only available for standalone binaries. Use 'uv pip install --upgrade vaultctl' instead."
        raise UpdateError(msg)

    release = fetch_latest_release()

    if not _is_newer(current_version, release.version):
        return None

    # Mandatory checksum verification
    if not release.checksums_url:
        msg = "Release has no checksums — refusing to install unverified binary."
        raise UpdateError(msg)

    current_exe = Path(sys.executable)
    if not current_exe.is_file():
        msg = "Cannot determine current executable path."
        raise UpdateError(msg)

    # Download to a temp file in the same directory (for atomic rename)
    exe_dir = str(current_exe.parent)
    fd, tmp_path = tempfile.mkstemp(dir=exe_dir, prefix=".vaultctl-update-")
    os.close(fd)

    tmp = Path(tmp_path)
    try:
        download_binary(release.asset_url, tmp_path)

        # Verify checksum (mandatory)
        checksums = fetch_checksums(release.checksums_url)
        expected = checksums.get(release.asset_name)
        if not expected:
            msg = f"No checksum found for {release.asset_name} — refusing to install."
            raise UpdateError(msg)
        verify_checksum(tmp_path, expected)

        # Preserve permissions from original binary
        original_mode = current_exe.stat().st_mode
        tmp.chmod(original_mode)

        # Atomic replace
        tmp.replace(current_exe)
    except Exception:
        # Clean up temp file on failure
        if tmp.exists():
            tmp.unlink()
        raise

    return release.version
