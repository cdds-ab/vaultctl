"""Self-update mechanism for standalone vaultctl binaries."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import stat
import sys
import tempfile
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

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


def self_update(current_version: str) -> str | None:
    """Check for updates and replace the current binary if newer.

    Returns the new version string, or None if already up to date.
    """
    release = fetch_latest_release()

    if release.version == current_version:
        return None

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

        # Verify checksum if available
        if release.checksums_url:
            checksums = fetch_checksums(release.checksums_url)
            expected = checksums.get(release.asset_name)
            if expected:
                verify_checksum(tmp_path, expected)

        tmp.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)

        # Atomic replace
        tmp.replace(current_exe)
    except Exception:
        # Clean up temp file on failure
        if tmp.exists():
            tmp.unlink()
        raise

    return release.version
