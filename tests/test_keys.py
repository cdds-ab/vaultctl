"""Tests for vaultctl.keys module."""

from __future__ import annotations

import datetime

from vaultctl.keys import (
    check_expiry,
    get_key_info,
    list_keys,
    load_keys,
    save_keys,
    update_key_metadata,
)


def test_load_keys(keys_file):
    keys = load_keys(keys_file)
    assert "test_key" in keys
    assert "another_key" in keys


def test_load_keys_missing_file(tmp_path):
    keys = load_keys(tmp_path / "nonexistent.yml")
    assert keys == {}


def test_get_key_info(keys_file):
    keys = load_keys(keys_file)
    info = get_key_info(keys, "test_key")
    assert info is not None
    assert info.name == "test_key"
    assert info.description == "A test key"
    assert info.rotate == "365d"
    assert info.consumers == ["host01", "host02"]
    assert info.rotate_cmd == "manual rotation"


def test_get_key_info_missing():
    assert get_key_info({}, "nonexistent") is None


def test_list_keys(keys_file):
    keys = load_keys(keys_file)
    infos = list_keys(keys)
    names = [i.name for i in infos]
    assert "another_key" in names
    assert "test_key" in names
    # Should be sorted
    assert names == sorted(names)


def test_save_and_reload(tmp_path):
    keys = {"my_key": {"description": "saved key", "rotate": "30d"}}
    kf = tmp_path / "keys.yml"
    save_keys(keys, kf)
    reloaded = load_keys(kf)
    assert reloaded["my_key"]["description"] == "saved key"


def test_update_key_metadata():
    keys = {"existing": {"description": "old"}}
    update_key_metadata(keys, "existing", description="new", expires="2026-12-01")
    assert keys["existing"]["description"] == "new"
    assert keys["existing"]["expires"] == "2026-12-01"


def test_update_key_metadata_creates_entry():
    keys = {}
    update_key_metadata(keys, "new_key", description="brand new")
    assert keys["new_key"]["description"] == "brand new"


def test_check_expiry_expired(keys_file):
    keys = load_keys(keys_file)
    today = datetime.date(2026, 3, 7)
    warnings = check_expiry(keys, today=today, warn_days=30)
    expired = [w for w in warnings if w.status == "expired"]
    assert len(expired) == 1
    assert expired[0].key == "expired_key"
    assert expired[0].days_remaining < 0


def test_check_expiry_warning(keys_file):
    keys = load_keys(keys_file)
    today = datetime.date(2026, 3, 7)
    warnings = check_expiry(keys, today=today, warn_days=30)
    warning_keys = [w for w in warnings if w.status == "warning"]
    assert len(warning_keys) == 1
    assert warning_keys[0].key == "expiring_key"


def test_check_expiry_ok(keys_file):
    keys = load_keys(keys_file)
    today = datetime.date(2026, 1, 1)
    warnings = check_expiry(keys, today=today, warn_days=30)
    ok_keys = [w for w in warnings if w.status == "ok"]
    assert len(ok_keys) == 1  # expiring_key should be ok with this date


def test_check_expiry_no_expires():
    keys = {"plain_key": {"description": "no expiry"}}
    warnings = check_expiry(keys)
    assert warnings == []
