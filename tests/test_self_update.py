"""Tests for the self-update mechanism."""

from __future__ import annotations

import hashlib
import json
import textwrap
from unittest.mock import MagicMock, patch

import pytest
from vaultctl.self_update import (
    ReleaseInfo,
    UpdateError,
    _is_newer,
    fetch_checksums,
    fetch_latest_release,
    get_platform_asset_name,
    is_frozen,
    self_update,
    verify_checksum,
)


class TestIsFrozen:
    def test_not_frozen(self):
        assert is_frozen() is False

    @patch("vaultctl.self_update.sys")
    def test_frozen(self, mock_sys):
        mock_sys.frozen = True
        assert is_frozen() is True


class TestGetPlatformAssetName:
    @patch("vaultctl.self_update.platform")
    def test_linux_amd64(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_platform.machine.return_value = "x86_64"
        assert get_platform_asset_name() == "vaultctl-linux-amd64"

    @patch("vaultctl.self_update.platform")
    def test_linux_arm64(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_platform.machine.return_value = "aarch64"
        assert get_platform_asset_name() == "vaultctl-linux-arm64"

    @patch("vaultctl.self_update.platform")
    def test_darwin_amd64(self, mock_platform):
        mock_platform.system.return_value = "Darwin"
        mock_platform.machine.return_value = "x86_64"
        assert get_platform_asset_name() == "vaultctl-macos-amd64"

    @patch("vaultctl.self_update.platform")
    def test_darwin_arm64(self, mock_platform):
        mock_platform.system.return_value = "Darwin"
        mock_platform.machine.return_value = "arm64"
        assert get_platform_asset_name() == "vaultctl-macos-arm64"

    @patch("vaultctl.self_update.platform")
    def test_unsupported_arch(self, mock_platform):
        mock_platform.system.return_value = "Linux"
        mock_platform.machine.return_value = "s390x"
        with pytest.raises(UpdateError, match="Unsupported architecture"):
            get_platform_asset_name()

    @patch("vaultctl.self_update.platform")
    def test_unsupported_os(self, mock_platform):
        mock_platform.system.return_value = "Windows"
        mock_platform.machine.return_value = "x86_64"
        with pytest.raises(UpdateError, match="Unsupported platform"):
            get_platform_asset_name()


class TestIsNewer:
    def test_newer_version(self):
        assert _is_newer("1.0.0", "2.0.0") is True

    def test_same_version(self):
        assert _is_newer("1.0.0", "1.0.0") is False

    def test_older_version(self):
        assert _is_newer("2.0.0", "1.0.0") is False

    def test_patch_bump(self):
        assert _is_newer("1.0.0", "1.0.1") is True

    def test_minor_bump(self):
        assert _is_newer("1.0.0", "1.1.0") is True

    def test_downgrade_prevented(self):
        assert _is_newer("1.5.0", "1.4.9") is False


class TestFetchLatestRelease:
    def _make_release_response(self, tag="v1.0.0", assets=None):
        if assets is None:
            assets = [
                {"name": "vaultctl-linux-amd64", "browser_download_url": "https://example.com/vaultctl-linux-amd64"},
                {"name": "checksums.sha256", "browser_download_url": "https://example.com/checksums.sha256"},
            ]
        return json.dumps({"tag_name": tag, "assets": assets}).encode()

    @patch("vaultctl.self_update.get_platform_asset_name", return_value="vaultctl-linux-amd64")
    @patch("vaultctl.self_update.urllib.request.urlopen")
    def test_success(self, mock_urlopen, _mock_platform):
        mock_resp = MagicMock()
        mock_resp.read.return_value = self._make_release_response()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        info = fetch_latest_release()
        assert info.version == "1.0.0"
        assert info.tag == "v1.0.0"
        assert info.asset_name == "vaultctl-linux-amd64"
        assert info.checksums_url == "https://example.com/checksums.sha256"

    @patch("vaultctl.self_update.get_platform_asset_name", return_value="vaultctl-linux-amd64")
    @patch("vaultctl.self_update.urllib.request.urlopen")
    def test_no_checksums(self, mock_urlopen, _mock_platform):
        assets = [{"name": "vaultctl-linux-amd64", "browser_download_url": "https://example.com/binary"}]
        mock_resp = MagicMock()
        mock_resp.read.return_value = self._make_release_response(assets=assets)
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        info = fetch_latest_release()
        assert info.checksums_url == ""

    @patch("vaultctl.self_update.get_platform_asset_name", return_value="vaultctl-linux-amd64")
    @patch("vaultctl.self_update.urllib.request.urlopen")
    def test_no_matching_binary(self, mock_urlopen, _mock_platform):
        assets = [{"name": "vaultctl-darwin-arm64", "browser_download_url": "https://example.com/darwin"}]
        mock_resp = MagicMock()
        mock_resp.read.return_value = self._make_release_response(assets=assets)
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        with pytest.raises(UpdateError, match="No binary found"):
            fetch_latest_release()


class TestVerifyChecksum:
    def test_valid_checksum(self, tmp_path):
        file = tmp_path / "binary"
        file.write_bytes(b"test binary content")
        expected = hashlib.sha256(b"test binary content").hexdigest()
        verify_checksum(str(file), expected)

    def test_invalid_checksum(self, tmp_path):
        file = tmp_path / "binary"
        file.write_bytes(b"test binary content")
        with pytest.raises(UpdateError, match="Checksum mismatch"):
            verify_checksum(str(file), "0" * 64)


class TestFetchChecksums:
    @patch("vaultctl.self_update.urllib.request.urlopen")
    def test_parse_checksums(self, mock_urlopen):
        content = textwrap.dedent("""\
            abc123  vaultctl-linux-amd64
            def456  vaultctl-linux-arm64
            789abc  vaultctl-macos-amd64
        """)
        mock_resp = MagicMock()
        mock_resp.read.return_value = content.encode()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_urlopen.return_value = mock_resp

        result = fetch_checksums("https://example.com/checksums.sha256")
        assert result["vaultctl-linux-amd64"] == "abc123"
        assert result["vaultctl-linux-arm64"] == "def456"
        assert result["vaultctl-macos-amd64"] == "789abc"


class TestSelfUpdate:
    @patch("vaultctl.self_update.is_frozen", return_value=False)
    def test_not_frozen_raises(self, _mock_frozen):
        with pytest.raises(UpdateError, match="standalone binaries"):
            self_update("1.0.0")

    @patch("vaultctl.self_update.is_frozen", return_value=True)
    @patch("vaultctl.self_update.fetch_latest_release")
    def test_already_up_to_date(self, mock_fetch, _mock_frozen):
        mock_fetch.return_value = ReleaseInfo(
            tag="v1.0.0", version="1.0.0", asset_url="", asset_name="", checksums_url=""
        )
        result = self_update("1.0.0")
        assert result is None

    @patch("vaultctl.self_update.is_frozen", return_value=True)
    @patch("vaultctl.self_update.fetch_latest_release")
    def test_downgrade_prevented(self, mock_fetch, _mock_frozen):
        mock_fetch.return_value = ReleaseInfo(
            tag="v1.0.0", version="1.0.0", asset_url="", asset_name="", checksums_url=""
        )
        result = self_update("2.0.0")
        assert result is None

    @patch("vaultctl.self_update.is_frozen", return_value=True)
    @patch("vaultctl.self_update.fetch_latest_release")
    def test_no_checksums_refuses(self, mock_fetch, _mock_frozen):
        mock_fetch.return_value = ReleaseInfo(
            tag="v2.0.0",
            version="2.0.0",
            asset_url="https://example.com/binary",
            asset_name="vaultctl-linux-amd64",
            checksums_url="",
        )
        with pytest.raises(UpdateError, match="no checksums"):
            self_update("1.0.0")

    @patch("vaultctl.self_update.is_frozen", return_value=True)
    @patch("vaultctl.self_update.verify_checksum")
    @patch("vaultctl.self_update.fetch_checksums")
    @patch("vaultctl.self_update.download_binary")
    @patch("vaultctl.self_update.fetch_latest_release")
    def test_update_with_checksum(self, mock_fetch, mock_download, mock_checksums, mock_verify, _mock_frozen, tmp_path):
        exe = tmp_path / "vaultctl"
        exe.write_bytes(b"old binary")
        exe.chmod(0o755)

        mock_fetch.return_value = ReleaseInfo(
            tag="v2.0.0",
            version="2.0.0",
            asset_url="https://example.com/binary",
            asset_name="vaultctl-linux-amd64",
            checksums_url="https://example.com/checksums.sha256",
        )
        mock_checksums.return_value = {"vaultctl-linux-amd64": "abc123"}

        with patch("vaultctl.self_update.sys") as mock_sys:
            mock_sys.executable = str(exe)
            result = self_update("1.0.0")

        assert result == "2.0.0"
        mock_verify.assert_called_once()
        mock_checksums.assert_called_once_with("https://example.com/checksums.sha256")

    @patch("vaultctl.self_update.is_frozen", return_value=True)
    @patch("vaultctl.self_update.verify_checksum", side_effect=UpdateError("Checksum mismatch"))
    @patch("vaultctl.self_update.fetch_checksums", return_value={"vaultctl-linux-amd64": "bad"})
    @patch("vaultctl.self_update.download_binary")
    @patch("vaultctl.self_update.fetch_latest_release")
    def test_checksum_mismatch_cleans_up(
        self, mock_fetch, mock_download, _mock_checksums, _mock_verify, _mock_frozen, tmp_path
    ):
        exe = tmp_path / "vaultctl"
        exe.write_bytes(b"old binary")
        exe.chmod(0o755)

        mock_fetch.return_value = ReleaseInfo(
            tag="v2.0.0",
            version="2.0.0",
            asset_url="https://example.com/binary",
            asset_name="vaultctl-linux-amd64",
            checksums_url="https://example.com/checksums.sha256",
        )

        with patch("vaultctl.self_update.sys") as mock_sys:
            mock_sys.executable = str(exe)
            with pytest.raises(UpdateError, match="Checksum mismatch"):
                self_update("1.0.0")

        # Original binary should still exist
        assert exe.read_bytes() == b"old binary"
        # Temp file should be cleaned up
        temp_files = [f for f in tmp_path.iterdir() if f.name.startswith(".vaultctl-update-")]
        assert temp_files == []

    @patch("vaultctl.self_update.is_frozen", return_value=True)
    @patch("vaultctl.self_update.fetch_checksums", return_value={})
    @patch("vaultctl.self_update.download_binary")
    @patch("vaultctl.self_update.fetch_latest_release")
    def test_missing_checksum_entry_refuses(self, mock_fetch, mock_download, mock_checksums, _mock_frozen, tmp_path):
        exe = tmp_path / "vaultctl"
        exe.write_bytes(b"old binary")
        exe.chmod(0o755)

        mock_fetch.return_value = ReleaseInfo(
            tag="v2.0.0",
            version="2.0.0",
            asset_url="https://example.com/binary",
            asset_name="vaultctl-linux-amd64",
            checksums_url="https://example.com/checksums.sha256",
        )

        with patch("vaultctl.self_update.sys") as mock_sys:
            mock_sys.executable = str(exe)
            with pytest.raises(UpdateError, match="No checksum found"):
                self_update("1.0.0")
