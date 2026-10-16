"""TEST-panel link removal tool (decision 32).

Safety properties (all enforced in code, none overridable):
- Runs only when the connected panel MAC is TEST_PANEL_MAC.
- Every target needs an exact 12-hex serial (--remove) AND the matching
  Network Devices name (--expect-name); any mismatch aborts the whole run.
- 2CCF67CA1AE0 and the tool's own link are always protected.
- There is no remove-all path; ``net_dev.default`` is never sent.
- Dry-run by default; ``--apply`` plus typing the TEST MAC is required to delete.
- The installer code comes only from ELK_TEST_INSTALLER_CODE, is read only on
  --apply, is removed from the process environment, is sent in exactly one
  authenticate frame, and is never logged, printed or stored.
- The tool connects over its own dedicated link, never the HA entry's link.
"""

from __future__ import annotations

import argparse
import datetime as dt
import logging
import os
import re
import sys
import time
from collections.abc import Callable, Mapping, MutableMapping
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

TEST_PANEL_MAC = "cc031eb03b20"
HA_PROTECTED_SN = "2CCF67CA1AE0"
ENV_INSTALLER_CODE = "ELK_TEST_INSTALLER_CODE"
MAX_TARGETS = 6
REAUTH_AFTER_S = 50.0  # panel drops PIN auth after 60 s idle
SN_RE = re.compile(r"^[0-9A-F]{12}$")
REDACT_KEYS = ("pin", "enc", "hmac", "access", "passph", "code")

LOG = logging.getLogger("elk_test_tools.link_removal")


class AbortError(Exception):
    """Run aborted; message never contains secrets. ``result`` holds partial progress."""

    result: RunResult | None = None


class Transport(Protocol):
    """Connection to a panel over the tool's OWN dedicated link."""

    def connect(self) -> None: ...
    def close(self) -> None: ...
    def panel_mac(self) -> str: ...
    def own_link_sn(self) -> str: ...
    def request(self, payload: Mapping[str, Any]) -> Mapping[str, Any]: ...
    def area_arm_states(self) -> Mapping[int, str]: ...
    def observe_session(self, sn: str) -> str: ...


# --------------------------------------------------------------------------- redaction
def _redact(obj: Any) -> Any:
    if isinstance(obj, Mapping):
        return {
            k: ("***" if any(r in str(k).lower() for r in REDACT_KEYS) else _redact(v))
            for k, v in obj.items()
        }
    if isinstance(obj, (list, tuple)):
        return type(obj)(_redact(v) for v in obj)
    return obj


class RedactingFilter(logging.Filter):
    """Redacts secret-looking keys in log args and any known secret values."""

    def __init__(self) -> None:
        super().__init__()
        self._secrets: set[str] = set()

    def add_secret(self, value: str) -> None:
        if value:
            self._secrets.add(value)

    def clear(self) -> None:
        self._secrets.clear()

    def _scrub(self, text: str) -> str:
        for s in self._secrets:
            text = text.replace(s, "***")
        return text

    def filter(self, record: logging.LogRecord) -> bool:
        if record.args:
            args = record.args if isinstance(record.args, tuple) else (record.args,)
            record.args = tuple(_redact(a) for a in args)
        msg = record.getMessage()
        record.msg, record.args = self._scrub(msg), None
        return True


REDACTOR = RedactingFilter()


def install_redaction() -> None:
    """Attach the filter to every existing logger and handler, including children
    such as ``elke27_lib.transport`` with their own handlers (ancestor logger
    filters do not run for those). Called again right before authenticating."""
    loggers = [logging.getLogger()] + [
        lg for lg in logging.Logger.manager.loggerDict.values() if isinstance(lg, logging.Logger)
    ]
    loggers += [logging.getLogger(n) for n in ("elk_test_tools", "elke27_lib")]
    for lg in loggers:
        if REDACTOR not in lg.filters:
            lg.addFilter(REDACTOR)
        for h in lg.handlers:
            if REDACTOR not in h.filters:
                h.addFilter(REDACTOR)


# --------------------------------------------------------------------------- model
@dataclass
class Slot:
    net_dev_id: int
    sn: str
    name: str


@dataclass
class RunResult:
    applied: bool = False
    before: list[Slot] = field(default_factory=list)
    after: list[Slot] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    sessions: dict[str, str] = field(default_factory=dict)
    actions: list[str] = field(default_factory=list)


def normalize_mac(mac: str) -> str:
    return re.sub(r"[^0-9a-f]", "", (mac or "").lower())


def _ok(reply: Mapping[str, Any], *path: str) -> Mapping[str, Any]:
    node: Any = reply
    for p in path:
        node = node.get(p, {}) if isinstance(node, Mapping) else {}
    if not isinstance(node, Mapping) or node.get("error_code", 0) != 0:
        code = node.get("error_code") if isinstance(node, Mapping) else None
        raise AbortError(f"panel error on {'.'.join(path)}: error_code={code}")
    return node


def inventory(t: Transport) -> list[Slot]:
    reply = _ok(t.request({"net_dev": {"get_list": 1}}), "net_dev", "get_list")
    slots: list[Slot] = []
    for entry in reply.get("list", []):
        i = entry.get("net_dev_id")
        if not isinstance(i, int) or not entry.get("name"):
            continue
        a = _ok(
            t.request({"net_dev": {"get_attribs": {"net_dev_id": i}}}),
            "net_dev",
            "get_attribs",
        )
        sn = str(a.get("sn", "")).upper()[-12:]
        slots.append(Slot(i, sn, str(a.get("name", entry.get("name")))))
    return slots


def validate_targets(removes: list[str], names: list[str]) -> list[tuple[str, str]]:
    if not removes:
        raise AbortError("no --remove targets given")
    if len(removes) > MAX_TARGETS:
        raise AbortError(f"at most {MAX_TARGETS} targets per run")
    if len(names) != len(removes):
        raise AbortError("each --remove needs a matching --expect-name, in order")
    out = []
    for sn, name in zip(removes, names, strict=True):
        sn_u = sn.strip().upper()
        if not SN_RE.match(sn_u):
            raise AbortError(f"invalid serial {sn!r}: need exactly 12 hex chars")
        if sn_u == HA_PROTECTED_SN:
            raise AbortError(f"{sn_u} is protected")
        if not name.strip():
            raise AbortError("--expect-name must be non-empty")
        out.append((sn_u, name.strip()))
    if len({s for s, _ in out}) != len(out):
        raise AbortError("duplicate --remove target")
    return out


def _fmt(slots: list[Slot], targets: set[str], protected: set[str]) -> str:
    rows = ["slot  sn            action   name"]
    for s in slots:
        act = "DELETE" if s.sn in targets else ("PROTECT" if s.sn in protected else "keep")
        rows.append(f"{s.net_dev_id:<5} {s.sn}  {act:<8} {s.name}")
    return "\n".join(rows)


# --------------------------------------------------------------------------- run
def run(
    *,
    transport: Transport,
    removes: list[str],
    expect_names: list[str],
    apply: bool,
    env: MutableMapping[str, str],
    confirm: Callable[[str], str],
    out: Callable[[str], None] = print,
    clock: Callable[[], float] = time.monotonic,
) -> RunResult:
    install_redaction()
    targets = validate_targets(removes, expect_names)
    target_sns = {s for s, _ in targets}
    result = RunResult()

    code: str | None = None
    if apply:
        code = env.pop(ENV_INSTALLER_CODE, None)  # never inherited by children
        if not code:
            raise AbortError(f"{ENV_INSTALLER_CODE} is not set; aborting before connect")
        REDACTOR.add_secret(code)

    try:
        transport.connect()
        try:
            return _run_connected(
                transport, targets, target_sns, apply, code, confirm, out, clock, result
            )
        finally:
            transport.close()
    except AbortError as exc:
        exc.result = result
        raise
    finally:
        code = None
        REDACTOR.clear()


def _run_connected(t, targets, target_sns, apply, code, confirm, out, clock, result):
    mac = normalize_mac(t.panel_mac())
    if mac != TEST_PANEL_MAC:
        raise AbortError(f"panel MAC {mac or '?'} is not the TEST panel; refusing")
    own = str(t.own_link_sn()).upper()
    if not SN_RE.match(own):
        raise AbortError("cannot determine the tool's own link serial; refusing")
    protected = {HA_PROTECTED_SN, own}
    if target_sns & protected:
        raise AbortError("a target is protected (2CCF67CA1AE0 or the tool's own link)")

    result.before = inventory(t)
    by_sn = {s.sn: s for s in result.before}
    for sn, name in targets:
        slot = by_sn.get(sn)
        if slot is None:
            raise AbortError(f"{sn} not linked on this panel")
        if slot.name != name:
            raise AbortError(f"{sn} name {slot.name!r} != --expect-name {name!r}")

    out(_fmt(result.before, target_sns, protected))
    if not apply:
        out("DRY RUN: nothing removed. Re-run with --apply to delete.")
        result.actions.append("dry-run")
        return result

    typed = confirm(f"Type the TEST panel MAC ({TEST_PANEL_MAC}) to delete: ")
    if normalize_mac(typed) != TEST_PANEL_MAC:
        raise AbortError("confirmation did not match; nothing removed")

    states = t.area_arm_states()
    armed = {a: s for a, s in states.items() if str(s).upper() != "DISARMED"}
    if not states or armed:
        raise AbortError(f"all areas must be DISARMED; not disarmed: {sorted(armed)}")

    last_auth = [0.0]

    def authenticate() -> None:
        install_redaction()
        try:
            pin = int(code)
        except (TypeError, ValueError):
            raise AbortError(f"{ENV_INSTALLER_CODE} is not numeric") from None
        reply = t.request({"authenticate": {"seq": 0, "pin": pin}})
        node = reply.get("authenticate", {}) if isinstance(reply, Mapping) else {}
        if node.get("error_code", -1) != 0 or node.get("installer") is not True:
            raise AbortError("installer authentication failed; not retrying")
        last_auth[0] = clock()
        result.actions.append("authenticate ok")

    authenticate()
    try:
        for sn, _ in targets:
            if clock() - last_auth[0] > REAUTH_AFTER_S:
                authenticate()
            slot = by_sn[sn]
            a = _ok(
                t.request({"net_dev": {"get_attribs": {"net_dev_id": slot.net_dev_id}}}),
                "net_dev",
                "get_attribs",
            )
            if str(a.get("sn", "")).upper()[-12:] != sn:
                raise AbortError(f"slot {slot.net_dev_id} no longer holds {sn}; stopping")
            if sn in protected:  # belt and braces
                raise AbortError("protected target reached delete step")
            _ok(
                t.request({"net_dev": {"del_attribs": {"net_dev_id": slot.net_dev_id}}}),
                "net_dev",
                "del_attribs",
            )
            last_auth[0] = clock()
            result.removed.append(sn)
            result.actions.append(f"del_attribs net_dev_id={slot.net_dev_id} sn={sn} ok")
    finally:
        try:
            result.after = inventory(t)
            for sn in result.removed:
                try:
                    result.sessions[sn] = t.observe_session(sn)
                except Exception as exc:  # noqa: BLE001 - report, keep going
                    result.sessions[sn] = f"unknown ({type(exc).__name__})"
        finally:
            _ok(t.request({"net_dev": {"logout": True}}), "net_dev", "logout")
            result.actions.append("logout ok")

    after = {s.sn for s in result.after}
    left = target_sns & after
    missing = protected - after
    result.applied = True
    out(_fmt(result.after, set(), protected))
    for sn, state in result.sessions.items():
        out(f"revoked link {sn}: session after delete = {state}")
    if left or missing:
        raise AbortError(
            f"verify failed: still present={sorted(left)} protected missing={sorted(missing)}"
        )
    out("OK: targets removed, protected links present.")
    return result


def append_log(path: Path, mac: str, res: RunResult) -> None:
    ts = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    lines = [
        f"\n## {ts} panel {mac} ({'apply' if res.applied else 'dry-run'})",
        f"- before: {', '.join(s.sn for s in res.before) or '-'}",
        f"- after: {', '.join(s.sn for s in res.after) or '-'}",
        *(f"- {a}" for a in res.actions),
        *(f"- session {sn}: {st}" for sn, st in res.sessions.items()),
    ]
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="elk-remove-test-link",
        description="Remove specific links from the Elk E27 TEST panel (dry-run by default).",
    )
    p.add_argument(
        "--remove",
        action="append",
        default=[],
        metavar="SN",
        help="exact 12-hex link serial to remove (repeatable, max 6)",
    )
    p.add_argument(
        "--expect-name",
        action="append",
        default=[],
        metavar="NAME",
        help="Network Devices name each --remove must have (same order)",
    )
    p.add_argument(
        "--apply",
        action="store_true",
        help=f"actually delete (otherwise dry-run); installer code from {ENV_INSTALLER_CODE}",
    )
    p.add_argument(
        "--log-file",
        type=Path,
        default=None,
        help="append a run record here (never contains secrets)",
    )
    return p


def make_live_transport() -> Transport:
    raise AbortError(
        "live transport not available yet: waits for the elke27 raw API pass-through "
        "(decision 34). Only the fake-panel tests run today."
    )


def main(argv: list[str] | None = None, transport: Transport | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    install_redaction()
    try:
        t = transport or make_live_transport()
        res = run(
            transport=t,
            removes=args.remove,
            expect_names=args.expect_name,
            apply=args.apply,
            env=os.environ,
            confirm=input,
        )
        if args.log_file:
            append_log(args.log_file, TEST_PANEL_MAC, res)
    except AbortError as exc:
        print(f"ABORT: {exc}", file=sys.stderr)
        if args.log_file and exc.result is not None and exc.result.before:
            exc.result.actions.append(f"ABORT: {exc}")
            append_log(args.log_file, TEST_PANEL_MAC, exc.result)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
