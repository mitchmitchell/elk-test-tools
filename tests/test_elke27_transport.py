"""Elke27Transport adapter, against a fake Elke27Client (no panel)."""

from __future__ import annotations

import json
from types import SimpleNamespace
from typing import Any

import pytest

from elk_test_tools import elke27_transport as et
from elk_test_tools import link_removal as lr

KEYS = {"tempkey_hex": "11" * 16, "linkkey_hex": "22" * 16, "linkhmac_hex": "33" * 32}


class FakeClient:
    def __init__(self, error: Any = None, data: Any = None) -> None:
        self.calls: list[tuple[str, Any, dict[str, Any]]] = []
        self.error, self.data = error, data

    async def async_raw_request(self, message: Any, **kw: Any) -> Any:
        self.calls.append(("raw", message, kw))
        return SimpleNamespace(ok=self.error is None, data=self.data, error=self.error)

    async def async_execute(self, key: str, **kw: Any) -> Any:
        self.calls.append((key, None, {"pin_type": type(kw.get("pin")).__name__}))
        return SimpleNamespace(ok=True, data={}, error=None)


def _t(client: FakeClient) -> et.Elke27Transport:
    t = et.Elke27Transport("10.0.0.5", 2101, "AABBCCDDEEFF", KEYS)
    t._client = client
    return t


def test_refuses_ha_link_and_bad_sn():
    with pytest.raises(lr.AbortError, match="HA entry"):
        et.Elke27Transport("h", 1, lr.HA_PROTECTED_SN, KEYS)
    with pytest.raises(lr.AbortError, match="12 hex"):
        et.Elke27Transport("h", 1, "nope", KEYS)


def test_link_keys_are_redaction_secrets():
    lr.REDACTOR.clear()
    et.Elke27Transport("h", 1, "AABBCCDDEEFF", KEYS)
    try:
        assert lr.REDACTOR._scrub(KEYS["linkkey_hex"]) == "***"
    finally:
        lr.REDACTOR.clear()


def test_unreadable_link_file_message_has_no_contents(tmp_path):
    f = tmp_path / "link.json"
    f.write_text(json.dumps({"host": "h", "link_keys": KEYS}))
    with pytest.raises(lr.AbortError) as ei:
        et.Elke27Transport.from_env({et.ENV_LINK_FILE: str(f)})
    assert KEYS["linkkey_hex"] not in str(ei.value)


def test_request_uses_passthrough_with_installer_opt_in():
    reply = {"net_dev": {"get_list": {"error_code": 0, "list": []}}}
    c = FakeClient(data=reply)
    assert _t(c).request({"net_dev": {"get_list": 1}}) == reply
    assert c.calls == [("raw", {"net_dev": {"get_list": 1}}, {"allow_installer": True})]


def test_authenticate_goes_through_control_authenticate():
    c = FakeClient()
    assert _t(c).authenticate("0123") is True
    assert c.calls == [("control_authenticate", None, {"pin_type": "str"})]


def test_outcome_unknown_aborts():
    class Elke27CommandOutcomeUnknownError(Exception):
        pass

    c = FakeClient(error=Elke27CommandOutcomeUnknownError())
    with pytest.raises(lr.AbortError, match="outcome unknown"):
        _t(c).request({"net_dev": {"del_attribs": {"net_dev_id": 3}}})


def test_panel_error_maps_to_error_code_reply():
    c = FakeClient(error=SimpleNamespace(panel_error_code=11008))
    reply = _t(c).request({"net_dev": {"del_attribs": {"net_dev_id": 3}}})
    assert reply == {"net_dev": {"del_attribs": {"error_code": 11008}}}
