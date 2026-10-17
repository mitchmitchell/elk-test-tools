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
import stat
from collections.abc import Mapping, MutableMapping
from pathlib import Path
from typing import Any

from elk_test_tools.link_removal import (
    DEFAULT_PROTECTED_SNS,
    REDACTOR,
    SN_RE,
    AbortError,
    protected_serials,
)

ENV_LINK_FILE = "ELK_TEST_LINK_FILE"
VAULT_ROOT = Path("/workspace/obsidian")


def check_link_file(path: Path, vault_root: Path = VAULT_ROOT) -> Path:
    """Refuse a link file that is group/other accessible, inside a git repo, or
    under the vault. Errors never include the path or contents."""
    try:
        real = path.resolve(strict=True)
        st = real.stat()
    except OSError:
        raise AbortError(f"cannot read the link file named by {ENV_LINK_FILE}") from None
    if not stat.S_ISREG(st.st_mode):
        raise AbortError("link file is not a regular file")
    if st.st_mode & 0o077:
        raise AbortError("link file must be mode 0600 (no group/other access)")
    vault = vault_root.resolve()
    if real == vault or vault in real.parents:
        raise AbortError("link file must not be inside the vault")
    for parent in real.parents:
        if (parent / ".git").exists():
            raise AbortError("link file must not be inside a git repository")
    return real


CONNECT_READY_TIMEOUT_S = 30.0
TOOL_MN = "222"  # same manufacturer number HA uses; the serial is the tool's own


class Elke27Transport:
    """Synchronous Transport adapter around an async Elke27Client."""

    def __init__(
        self,
        host: str,
        port: int,
        own_link_sn: str,
        link_keys: Mapping[str, str],
        protected: frozenset[str] = DEFAULT_PROTECTED_SNS,
    ):
        sn = own_link_sn.strip().upper()
        if not SN_RE.match(sn):
            raise AbortError("own_link_sn in the link file must be 12 hex chars")
        # Shared list (built-ins + ELK_TEST_EXTRA_PROTECTED): a protected link is an
        # HA entry's or baseline link, never the tool's own.
        if sn in protected | DEFAULT_PROTECTED_SNS:
            raise AbortError(
                "link file is a protected (HA entry) link; the tool needs its own link"
            )
        for value in link_keys.values():
            REDACTOR.add_secret(str(value))
        self._host, self._port, self._own_sn = host, int(port), sn
        self._keys = dict(link_keys)
        self._loop = asyncio.new_event_loop()
        self._client: Any = None

    @classmethod
    def from_env(cls, env: MutableMapping[str, str], protects: list[str]) -> Elke27Transport:
        path = env.get(ENV_LINK_FILE)
        if not path:
            raise AbortError(f"{ENV_LINK_FILE} is not set (the tool's own link file)")
        # Same shared list as the removal check (--protect serials).
        protected = protected_serials(protects)
        real = check_link_file(Path(path))
        try:
            data = json.loads(real.read_text(encoding="utf-8"))
            return cls(
                data["host"], data["port"], data["own_link_sn"], data["link_keys"], protected
            )
        except (OSError, ValueError, KeyError, TypeError):
            raise AbortError(f"cannot read the link file named by {ENV_LINK_FILE}") from None

    def _run(self, coro: Any) -> Any:
        return self._loop.run_until_complete(coro)

    # Transport ------------------------------------------------------------
    def connect(self) -> None:
        from elke27_lib import Elke27Client, LinkKeys

        self._client = Elke27Client(enable_raw_passthrough=True)
        # HELLO must present the identity this link was provisioned with. The
        # panel looks the link up by this sn and encrypts the session key with that
        # link's key, so HELLO only succeeds when own_link_sn and link_keys belong
        # to the same link (a mistyped sn is refused or fails to decrypt).
        self._client.set_client_identity({"mn": TOOL_MN, "sn": self._own_sn})
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
        """Arm state per area from the public snapshot (``AreaState.arm_mode``).

        ``ArmMode.DISARMED`` reads as "DISARMED"; any other mode is its name; a
        missing mode reads as "UNKNOWN", which the caller treats as not disarmed.
        """
        return {
            int(i): _arm_mode_name(getattr(a, "arm_mode", None))
            for i, a in self._client.snapshot.areas.items()
        }

    def observe_session(self, sn: str) -> str:
        return "not observed (live transport)"

    def authenticate(self, code: str) -> bool:
        if not code.isdigit() or (len(code) > 1 and code.startswith("0")):
            return False  # link_removal rejects these first; elke27 would too
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


def _arm_mode_name(mode: Any) -> str:
    if mode is None:
        return "UNKNOWN"
    value = getattr(mode, "value", mode)
    return str(value).upper() if isinstance(value, str) and value else "UNKNOWN"
