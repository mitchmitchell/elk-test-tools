"""In-memory fake E27 panel implementing the Transport protocol."""

from __future__ import annotations

import copy
from typing import Any

OWN_SN = "AABBCCDDEEFF"
HA_SN = "5A0C11D2E3F4"  # some other HA link (made-up serial)
BASELINE_SN = "119112725266"
TOUCH_SN = "0CC03EB00001"
SECRET = "987654"


class FakePanel:
    def __init__(self, mac: str = "cc:03:1e:b0:3b:20", pin: str = SECRET) -> None:
        self.mac = mac
        self.pin = int(pin)
        self.installer_ok = True
        self.devices: dict[int, dict[str, str]] = {
            1: {"sn": "0100" + HA_SN, "name": "HA TEST", "mn": "222"},
            2: {"sn": "0100" + OWN_SN, "name": "elk-test-tools", "mn": "222"},
            3: {"sn": "0100246915998877", "name": "Old Link A", "mn": "222"},
            4: {"sn": "0100727007405425", "name": "Old Link B", "mn": "222"},
            5: {"sn": "0100" + BASELINE_SN, "name": "HA TEST 0.2.0", "mn": "222"},
            6: {"sn": "0100" + TOUCH_SN, "name": "Frnt Door Tblt", "mn": " 100"},
        }
        self.slots = 8
        self.areas = {1: "DISARMED", 2: "DISARMED"}
        self.frames: list[dict[str, Any]] = []
        self.authed = False
        self.connected = False
        self.on_get_attribs = None  # optional hook(net_dev_id)

    # Transport
    def connect(self) -> None:
        self.connected = True

    def close(self) -> None:
        self.connected = False

    def panel_mac(self) -> str:
        return self.mac

    def own_link_sn(self) -> str:
        return OWN_SN

    def area_arm_states(self):
        return dict(self.areas)

    def observe_session(self, sn: str) -> str:
        return "dropped (fake panel)"

    def authenticate(self, code: str) -> bool:
        # Recorded without the code, like elke27's control_authenticate path.
        self.frames.append({"authenticate": {}})
        ok = code.isdigit() and int(code) == self.pin and self.installer_ok
        self.authed = ok
        return ok

    def request(self, payload):
        self.frames.append(copy.deepcopy(dict(payload)))
        if "authenticate" in payload:
            ok = payload["authenticate"]["pin"] == self.pin and self.installer_ok
            self.authed = ok
            return {"authenticate": {"error_code": 0 if ok else 11, "installer": ok}}
        nd = payload["net_dev"]
        if "get_list" in nd:
            return {
                "net_dev": {
                    # Documented Dealer API shape: parallel name/mn arrays, slot = index + 1.
                    "get_list": {
                        "error_code": 0,
                        "name": [
                            self.devices.get(i, {}).get("name", "")
                            for i in range(1, self.slots + 1)
                        ],
                        "mn": [
                            self.devices.get(i, {}).get("mn", "") for i in range(1, self.slots + 1)
                        ],
                    }
                }
            }
        if "get_attribs" in nd:
            i = nd["get_attribs"]["net_dev_id"]
            if self.on_get_attribs:
                self.on_get_attribs(i)
            d = self.devices.get(i)
            if d is None:
                return {"net_dev": {"get_attribs": {"error_code": 5}}}
            attrs = {k: v for k, v in d.items() if k != "mn"}  # mn only via get_list
            return {"net_dev": {"get_attribs": {"error_code": 0, "net_dev_id": i, **attrs}}}
        if "del_attribs" in nd:
            if not self.authed:
                return {"net_dev": {"del_attribs": {"error_code": 7}}}
            i = nd["del_attribs"]["net_dev_id"]
            self.devices.pop(i, None)
            return {"net_dev": {"del_attribs": {"net_dev_id": i, "error_code": 0}}}
        if "logout" in nd:
            self.authed = False
            return {"net_dev": {"logout": {"error_code": 0}}}
        if "default" in nd:
            raise AssertionError("net_dev.default must never be sent")
        raise AssertionError(f"unexpected frame {payload}")
