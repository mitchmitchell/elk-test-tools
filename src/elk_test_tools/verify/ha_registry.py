"""Device-registry helpers for the TEST HA identity checks (offline, pure).

HA up to 2026.9 lists every device of an entry in ``config_entries``. On HA
2026.10 the area devices carry ``config_entry_id`` plus ``parent_device_id``
(older registries: ``via_device_id``) pointing at the panel device, with no
``config_entries``. Filtering on ``config_entries`` alone finds 1 device of 3,
so an identity or device-count check would falsely abort. Accept every form.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any


def _parent(device: Mapping[str, Any]) -> Any:
    return device.get("parent_device_id") or device.get("via_device_id")


def directly_in_entry(device: Mapping[str, Any], entry_id: str) -> bool:
    entries = device.get("config_entries") or []
    return entry_id in entries or device.get("config_entry_id") == entry_id


def entry_devices(devices: Iterable[Mapping[str, Any]], entry_id: str) -> list[Mapping[str, Any]]:
    """Devices of ``entry_id``: listed on the entry, or a descendant of one that is."""
    devs = list(devices)
    mine: dict[Any, Mapping[str, Any]] = {
        d.get("id"): d for d in devs if directly_in_entry(d, entry_id)
    }
    grew = True
    while grew:
        grew = False
        for d in devs:
            if d.get("id") not in mine and _parent(d) in mine:
                mine[d.get("id")] = d
                grew = True
    return [d for d in devs if d.get("id") in mine]


def entry_macs(devices: Iterable[Mapping[str, Any]], entry_id: str) -> set[str]:
    """Normalised MACs (12 lower-case hex digits) on the entry's devices."""
    macs: set[str] = set()
    for d in entry_devices(devices, entry_id):
        for conn in d.get("connections") or []:
            if len(conn) == 2 and conn[0] == "mac":
                macs.add("".join(ch for ch in str(conn[1]).lower() if ch in "0123456789abcdef"))
    return macs
