"""Live Transport over the elke27 raw API pass-through (decision 34).

Uses the tool's OWN dedicated link, read from the JSON file named by
ELK_TEST_LINK_FILE: {"host", "port", "own_link_sn", "link_keys": {"tempkey_hex",
"linkkey_hex", "linkhmac_hex"}}. Link keys are registered as redaction secrets
and never logged. The installer code is passed only to elke27's
control_authenticate. Every other message goes through
``Elke27Client.async_raw_request(..., allow_installer=True)``.

Not exercised against any panel yet; the fake-panel tests cover the tool logic.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any

from elk_test_tools.link_removal import HA_PROTECTED_SN, REDACTOR, SN_RE, AbortError

ENV_LINK_FILE = "ELK_TEST_LINK_FILE"
CONNECT_READY_TIMEOUT_S = 30.0


class Elke27Transport:
    """Synchronous Transport adapter around an async Elke27Client."""

    def __init__(self, host: str, port: int, own_link_sn: str, link_keys: Mapping[str, str]):
        sn = own_link_sn.strip().upper()
        if not SN_RE.match(sn):
            raise AbortError("own_link_sn in the link file must be 12 hex chars")
        if sn == HA_PROTECTED_SN:
            raise AbortError("link file is the HA entry's link; the tool needs its own link")
        for value in link_keys.values():
            REDACTOR.add_secret(str(value))
        self._host, self._port, self._own_sn = host, int(port), sn
        self._keys = dict(link_keys)
        self._loop = asyncio.new_event_loop()
        self._client: Any = None

    @classmethod
    def from_env(cls, env: MutableMapping[str, str]) -> Elke27Transport:
        path = env.get(ENV_LINK_FILE)
        if not path:
            raise AbortError(f"{ENV_LINK_FILE} is not set (the tool's own link file)")
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            return cls(data["host"], data["port"], data["own_link_sn"], data["link_keys"])
        except (OSError, ValueError, KeyError, TypeError):
            raise AbortError(f"cannot read the link file named by {ENV_LINK_FILE}") from None

    def _run(self, coro: Any) -> Any:
        return self._loop.run_until_complete(coro)

    # Transport ------------------------------------------------------------
    def connect(self) -> None:
        from elke27_lib import Elke27Client, LinkKeys

        self._client = Elke27Client(enable_raw_passthrough=True)
        keys = LinkKeys(
            tempkey_hex=self._keys["tempkey_hex"],
            linkkey_hex=self._keys["linkkey_hex"],
            linkhmac_hex=self._keys["linkhmac_hex"],
        )
        try:
            self._run(self._client.async_connect(self._host, self._port, keys))
        except Exception as exc:  # noqa: BLE001 - never echo details
            raise AbortError(f"connect failed ({type(exc).__name__})") from None
        if not self._run(self._client.wait_ready(CONNECT_READY_TIMEOUT_S)):
            raise AbortError("panel did not become ready")

    def close(self) -> None:
        try:
            if self._client is not None:
                self._run(self._client.async_disconnect())
        finally:
            self._loop.close()

    def panel_mac(self) -> str:
        try:
            panels = self._run(self._client.async_discover(address=self._host, timeout_s=5))
        except Exception:  # noqa: BLE001
            return ""
        for p in panels:
            if p.host == self._host and p.panel_mac:
                return str(p.panel_mac)
        return ""

    def own_link_sn(self) -> str:
        return self._own_sn

    def area_arm_states(self) -> Mapping[int, str]:
        return {
            int(i): str(getattr(a, "arm_state", None) or getattr(a, "armed_state", None))
            for i, a in self._client.areas.items()
        }

    def observe_session(self, sn: str) -> str:
        return "not observed (live transport)"

    def authenticate(self, code: str) -> bool:
        result = self._run(self._client.async_execute("control_authenticate", pin=code))
        return bool(result.ok)

    def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]:
        result = self._run(self._client.async_raw_request(payload, allow_installer=True))
        if result.ok and result.data is not None:
            return result.data
        err = result.error
        name = type(err).__name__
        if name == "Elke27CommandOutcomeUnknownError":
            raise AbortError("no reply after send; outcome unknown, re-read before retrying")
        code = getattr(err, "panel_error_code", None)
        if code is not None:
            domain = next(iter(payload))
            verb = next(iter(payload[domain]))
            return {domain: {verb: {"error_code": code}}}
        raise AbortError(f"pass-through request failed ({name})")
