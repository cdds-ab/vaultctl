"""Tests for vaultctl.keys module."""

from __future__ import annotations

import datetime

from vaultctl.keys import (
    check_expiry,
    get_key_info,
    import_keys_from_vault,
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


def test_get_key_info_entry_type():
    keys = {"db_creds": {"description": "DB credentials", "type": "usernamePassword"}}
    info = get_key_info(keys, "db_creds")
    assert info is not None
    assert info.entry_type == "usernamePassword"


def test_get_key_info_entry_type_default():
    keys = {"plain": {"description": "A plain secret"}}
    info = get_key_info(keys, "plain")
    assert info is not None
    assert info.entry_type == ""


def test_get_key_info_entry_type_empty():
    info = get_key_info({}, "missing")
    assert info is None


class TestImportKeysFromVault:
    """Tests for import_keys_from_vault."""

    def test_imports_new_keys(self) -> None:
        vault_data = {"key_a": "val_a", "key_b": "val_b"}
        existing: dict = {}
        updated, count = import_keys_from_vault(vault_data, existing)
        assert count == 2
        assert "key_a" in updated
        assert "key_b" in updated
        assert updated["key_a"] == {"description": ""}

    def test_skips_existing_keys(self) -> None:
        vault_data = {"key_a": "val_a", "key_b": "val_b"}
        existing = {"key_a": {"description": "already tracked"}}
        updated, count = import_keys_from_vault(vault_data, existing)
        assert count == 1
        assert updated["key_a"]["description"] == "already tracked"
        assert "key_b" in updated

    def test_skips_previous_keys(self) -> None:
        vault_data = {"key_a": "val_a", "key_a_previous": "old_val"}
        existing: dict = {}
        updated, count = import_keys_from_vault(vault_data, existing)
        assert count == 1
        assert "key_a" in updated
        assert "key_a_previous" not in updated

    def test_empty_vault(self) -> None:
        updated, count = import_keys_from_vault({}, {})
        assert count == 0
        assert updated == {}

    def test_all_keys_already_exist(self) -> None:
        vault_data = {"k1": "v1", "k2": "v2"}
        existing = {"k1": {"description": "d1"}, "k2": {"description": "d2"}}
        _updated, count = import_keys_from_vault(vault_data, existing)
        assert count == 0
