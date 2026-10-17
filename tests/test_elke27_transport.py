"""Elke27Transport adapter, against a fake Elke27Client (no panel)."""

from __future__ import annotations

import dataclasses
import inspect
import json
from types import SimpleNamespace
from typing import Any
from unittest.mock import create_autospec

import pytest
from elke27_lib import AreaState, ArmMode, Elke27Client, PanelSnapshot
from elke27_lib.types import DiscoveredPanel

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
        et.Elke27Transport("h", 1, "AABBCCDDEEFF", KEYS, frozenset({"AABBCCDDEEFF"}))
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
    f.chmod(0o600)
    with pytest.raises(lr.AbortError) as ei:
        et.Elke27Transport.from_env({et.ENV_LINK_FILE: str(f)}, ["119112725266"])
    assert KEYS["linkkey_hex"] not in str(ei.value)


def test_request_uses_passthrough_with_installer_opt_in():
    reply = {"net_dev": {"get_list": {"error_code": 0, "list": []}}}
    c = FakeClient(data=reply)
    assert _t(c).request({"net_dev": {"get_list": 1}}) == reply
    assert c.calls == [("raw", {"net_dev": {"get_list": 1}}, {"allow_installer": True})]


def test_authenticate_goes_through_control_authenticate():
    c = FakeClient()
    assert _t(c).authenticate("4123") is True
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


# --- link file hygiene (Architect ruling 6) --------------------------------------
def _link_file(d, mode=0o600):
    f = d / "link.json"
    f.write_text(
        json.dumps({"host": "h", "port": 1, "own_link_sn": "AABBCCDDEEFF", "link_keys": KEYS})
    )
    f.chmod(mode)
    return f


def test_link_file_ok_when_private(tmp_path):
    f = _link_file(tmp_path)
    assert et.check_link_file(f, vault_root=tmp_path / "vault") == f.resolve()
    t = et.Elke27Transport.from_env({et.ENV_LINK_FILE: str(f)}, ["119112725266"])
    assert t.own_link_sn() == "AABBCCDDEEFF"
    lr.REDACTOR.clear()


@pytest.mark.parametrize("mode", [0o640, 0o604, 0o644, 0o660])
def test_link_file_group_or_other_access_refused(tmp_path, mode):
    f = _link_file(tmp_path, mode)
    with pytest.raises(lr.AbortError, match="0600") as ei:
        et.check_link_file(f, vault_root=tmp_path / "vault")
    assert str(tmp_path) not in str(ei.value)


def test_link_file_in_git_repo_refused(tmp_path):
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "sub").mkdir()
    f = _link_file(repo / "sub")
    with pytest.raises(lr.AbortError, match="git") as ei:
        et.check_link_file(f, vault_root=tmp_path / "vault")
    assert str(tmp_path) not in str(ei.value)


def test_link_file_in_vault_refused(tmp_path):
    vault = tmp_path / "obsidian"
    (vault / "notes").mkdir(parents=True)
    f = _link_file(vault / "notes")
    with pytest.raises(lr.AbortError, match="vault") as ei:
        et.check_link_file(f, vault_root=vault)
    assert str(tmp_path) not in str(ei.value)


def test_link_file_symlink_into_vault_refused(tmp_path):
    vault = tmp_path / "obsidian"
    vault.mkdir()
    real = _link_file(vault)
    link = tmp_path / "outside.json"
    link.symlink_to(real)
    with pytest.raises(lr.AbortError, match="vault"):
        et.check_link_file(link, vault_root=vault)


def test_missing_link_file_message_has_no_path(tmp_path):
    p = tmp_path / "nope.json"
    with pytest.raises(lr.AbortError) as ei:
        et.Elke27Transport.from_env({et.ENV_LINK_FILE: str(p)}, ["119112725266"])
    assert str(p) not in str(ei.value)


def test_authenticate_refuses_leading_zero_without_sending():
    c = FakeClient()
    assert _t(c).authenticate("0123") is False
    assert c.calls == []


def test_from_env_uses_shared_extra_protected_list(tmp_path):
    f = _link_file(tmp_path)
    env = {et.ENV_LINK_FILE: str(f)}
    with pytest.raises(lr.AbortError, match="HA entry"):
        et.Elke27Transport.from_env(env, ["119112725266", "AABBCCDDEEFF"])
    with pytest.raises(lr.AbortError, match="--protect"):
        et.Elke27Transport.from_env(env, [])


# --- Contract tests against the REAL elke27 API (pinned commit) -------------------
# The fake panel models the tool logic; these pin the adapter to elke27's actual
# public surface, so a renamed method or field fails here instead of on a panel.


def _real_client() -> Any:
    """An autospec of the real Elke27Client: wrong names or arguments raise."""
    return create_autospec(Elke27Client, instance=True)


def test_real_client_has_every_method_the_adapter_uses():
    for name in (
        "async_discover",
        "async_connect",
        "async_disconnect",
        "wait_ready",
        "async_raw_request",
        "async_execute",
        "set_client_identity",
    ):
        assert callable(getattr(Elke27Client, name)), name
    assert isinstance(inspect.getattr_static(Elke27Client, "snapshot"), property)
    params = inspect.signature(Elke27Client.async_discover).parameters
    assert {"address", "timeout_s"} <= set(params)
    assert {"host", "panel_mac"} <= {f.name for f in dataclasses.fields(DiscoveredPanel)}
    assert "arm_mode" in {f.name for f in dataclasses.fields(AreaState)}


def test_panel_mac_uses_real_discover_api():
    c = _real_client()
    c.async_discover.return_value = [
        DiscoveredPanel(host="10.0.0.9", port=2101, panel_mac="00:11:22:33:44:55"),
        DiscoveredPanel(host="10.0.0.5", port=2101, panel_mac="cc:03:1e:b0:3b:20"),
    ]
    t = _t(c)
    assert t.panel_mac() == "cc:03:1e:b0:3b:20"
    c.async_discover.assert_awaited_once_with(address="10.0.0.5", timeout_s=5)


def test_panel_mac_fails_closed_when_discovery_fails():
    c = _real_client()
    c.async_discover.side_effect = OSError("no route")
    assert _t(c).panel_mac() == ""


def _with_areas(**areas: AreaState) -> PanelSnapshot:
    return dataclasses.replace(
        PanelSnapshot.empty(), areas={int(k[1:]): v for k, v in areas.items()}
    )


def test_area_arm_states_read_real_arm_mode():
    c = _real_client()
    c.snapshot = _with_areas(
        a1=AreaState(area_id=1, arm_mode=ArmMode.DISARMED),
        a2=AreaState(area_id=2, arm_mode=ArmMode.ARMED_AWAY),
        a3=AreaState(area_id=3, arm_mode=None),
    )
    assert _t(c).area_arm_states() == {1: "DISARMED", 2: "ARMED_AWAY", 3: "UNKNOWN"}


def test_all_disarmed_real_areas_pass_the_disarm_gate():
    c = _real_client()
    c.snapshot = _with_areas(
        a1=AreaState(area_id=1, arm_mode=ArmMode.DISARMED),
        a2=AreaState(area_id=2, arm_mode=ArmMode.DISARMED),
    )
    states = _t(c).area_arm_states()
    assert all(s == "DISARMED" for s in states.values())


def test_connect_presents_own_link_identity(monkeypatch):
    c = _real_client()
    c.wait_ready.return_value = True
    monkeypatch.setattr("elke27_lib.Elke27Client", lambda **_kw: c)
    t = et.Elke27Transport("10.0.0.5", 2101, "AABBCCDDEEFF", KEYS)
    try:
        t.connect()
    finally:
        lr.REDACTOR.clear()
    c.set_client_identity.assert_called_once_with({"mn": "222", "sn": "AABBCCDDEEFF"})
    assert c.method_calls.index(
        next(m for m in c.method_calls if m[0] == "set_client_identity")
    ) < c.method_calls.index(next(m for m in c.method_calls if m[0] == "async_connect"))
