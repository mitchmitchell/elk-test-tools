"""HA device-registry filtering: HA 2026.10 area devices use config_entry_id + parent_device_id."""

from __future__ import annotations

from elk_test_tools.verify.ha_registry import entry_devices, entry_macs

ENTRY = "01M52YH2FAFSMV3V0DNZ11Q3N9"
PANEL = {
    "id": "panel",
    "config_entries": [ENTRY],
    "connections": [["mac", "cc:03:1e:b0:3b:20"]],
    "name": "My Alarm Engine(3B20)",
}


def test_ha_2026_10_area_devices_counted() -> None:
    """HA 2026.10: area devices carry config_entry_id/parent_device_id, not config_entries."""
    devices = [
        PANEL,
        {"id": "a1", "config_entry_id": ENTRY, "parent_device_id": "panel", "name": "Area 1"},
        {"id": "a2", "config_entry_id": ENTRY, "parent_device_id": "panel", "name": "Area 2"},
        {"id": "other", "config_entries": ["someone-else"], "name": "Other"},
    ]
    assert [d["id"] for d in entry_devices(devices, ENTRY)] == ["panel", "a1", "a2"]
    # The old config_entries-only filter finds just the panel: the false abort.
    assert [d["id"] for d in devices if ENTRY in (d.get("config_entries") or [])] == ["panel"]


def test_parent_only_and_via_device_id_children_are_included() -> None:
    devices = [
        {"id": "a1", "parent_device_id": "panel"},
        {"id": "a2", "via_device_id": "panel"},
        {"id": "grandchild", "parent_device_id": "a1"},
        PANEL,
    ]
    assert {d["id"] for d in entry_devices(devices, ENTRY)} == {"panel", "a1", "a2", "grandchild"}


def test_config_entry_id_only_panel_is_found() -> None:
    panel = {k: v for k, v in PANEL.items() if k != "config_entries"} | {"config_entry_id": ENTRY}
    assert entry_macs([panel], ENTRY) == {"cc031eb03b20"}


def test_pre_2026_10_config_entries_still_work() -> None:
    devices = [PANEL, {"id": "a1", "config_entries": [ENTRY], "via_device_id": "panel"}]
    assert {d["id"] for d in entry_devices(devices, ENTRY)} == {"panel", "a1"}
    assert entry_macs(devices, ENTRY) == {"cc031eb03b20"}


def test_other_entries_devices_are_excluded() -> None:
    devices = [
        PANEL,
        {"id": "x", "config_entry_id": "other", "connections": [["mac", "aa:bb:cc:dd:ee:ff"]]},
        {"id": "y", "parent_device_id": "x"},
    ]
    assert {d["id"] for d in entry_devices(devices, ENTRY)} == {"panel"}
    assert entry_macs(devices, ENTRY) == {"cc031eb03b20"}
