"""TEST-panel link removal tool (decision 32).

Safety properties (all enforced in code, none overridable):
- Runs only when the connected panel MAC is TEST_PANEL_MAC.
- Every target needs its serial (--remove; compared in canonical form: no
  whitespace, no leading zeros, upper-case hex) AND the matching
  Network Devices name (--expect-name); any mismatch aborts the whole run.
- Protections (decision 41): the tool's own link (own_link_sn) always, plus the
  link file's optional "protect" array, plus optional --protect serials for one
  run. No serials are built in. Nothing can remove a protection.
- Touch screens are never removed: blocked by device type (get_list "mn"), not
  serial. Unknown or missing type counts as a touch screen (fail closed).
- There is no remove-all path; ``net_dev.default`` is never sent.
- Dry-run by default; ``--apply`` plus typing the TEST MAC is required to delete.
- The installer code comes only from ELK_TEST_INSTALLER_CODE, is read only on
  --apply, is removed from the process environment, is handed only to
  ``Transport.authenticate`` (elke27's audited control_authenticate path), and
  is never logged, printed or stored.
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
from contextlib import AbstractContextManager, nullcontext
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol, cast

TEST_PANEL_MAC = "cc031eb03b20"
# No built-in serials (Mitch, Oct 16 2026 4:53 PM CT: --protect only). Protection
# = required --protect serials + the tool's own link + touch screens by type.
DEFAULT_PROTECTED_SNS: frozenset[str] = frozenset()

# Device type comes from net_dev.get_list "mn" (model number; Dealer API
# net_dev_get_list: "list of network device names and mn numbers"). Only mn
# values known to be integration links are removable; elke27/HA links use "222".
# mn "100" is the touch screen/tablet model in the API examples. Anything else,
# including a missing mn, is treated as a touch screen (fail closed).
REMOVABLE_MN: frozenset[str] = frozenset({"222"})
TOUCH_SCREEN_MN = "100"
ENV_INSTALLER_CODE = "ELK_TEST_INSTALLER_CODE"
MAX_TARGETS = 6
REAUTH_AFTER_S = 50.0  # panel drops PIN auth after 60 s idle
SN_RE = re.compile(r"^[0-9A-F]{12}$")
_SN_CHARS_RE = re.compile(r"^[0-9A-F]{1,12}$")
USER_SN_MIN_LEN = 11
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
    def authenticate(self, code: str) -> bool: ...
    def area_arm_states(self) -> Mapping[int, str]: ...
    def observe_session(self, sn: str) -> str: ...
    def file_protected(self) -> frozenset[str]: ...


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
            # A numeric code may be logged in its integer form ("0123" -> "123").
            stripped = value.lstrip("0")
            if value.isdigit() and stripped and stripped != value:
                self._secrets.add(stripped)

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


_FACTORY_INSTALLED = False


def _install_record_factory() -> None:
    """Redact every LogRecord at creation, so loggers created after the last
    install_redaction() call (e.g. lazy elke27_lib children) cannot bypass it."""
    global _FACTORY_INSTALLED
    if _FACTORY_INSTALLED:
        return
    base = logging.getLogRecordFactory()

    def factory(*args: Any, **kwargs: Any) -> logging.LogRecord:
        record = base(*args, **kwargs)
        REDACTOR.filter(record)
        return record

    logging.setLogRecordFactory(factory)
    _FACTORY_INSTALLED = True


def install_redaction() -> None:
    """Attach the filter to every existing logger and handler, including children
    such as ``elke27_lib.transport`` with their own handlers (ancestor logger
    filters do not run for those). Called again right before authenticating."""
    loggers = [logging.getLogger()] + [
        lg for lg in logging.Logger.manager.loggerDict.values() if isinstance(lg, logging.Logger)
    ]
    loggers += [logging.getLogger(n) for n in ("elk_test_tools", "elke27_lib")]
    _install_record_factory()
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
    mn: str | None = None

    @property
    def touch_screen_reason(self) -> str | None:
        """Why this slot is a protected touch screen, or None if removable by type."""
        mn = (self.mn or "").strip()
        if mn in REMOVABLE_MN:
            return None
        if mn == TOUCH_SCREEN_MN:
            return "touch screen"
        return "touch screen (type unknown)"


@dataclass
class RunResult:
    applied: bool = False
    before: list[Slot] = field(default_factory=list)
    after: list[Slot] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    sessions: dict[str, str] = field(default_factory=dict)
    actions: list[str] = field(default_factory=list)
    # The tool's own link serial; printed and logged only as "(own link)".
    own_sn: str = ""


def canonical_sn(raw: object, *, min_len: int = 1) -> str | None:
    """One comparable form for a link serial, applied to BOTH sides of every match
    (panel inventory, the tool's own link, --protect, the link file's protect list
    and --remove targets).

    Whitespace is removed anywhere, letters are upper-cased and leading zeros are
    dropped: the panel lists a 12-digit serial that starts with 0 as 11 digits
    with a leading space, so "012345678901" and " 12345678901" are the same link.
    Only hex digits are accepted (decimal serials are digits only), at most 12,
    and at least ``min_len`` before zeros are dropped. Operator input uses
    USER_SN_MIN_LEN (the 12-char serial, or the panel's 11-char form of one that
    starts with 0). Returns None for anything else, so malformed input never
    matches.
    """
    if not isinstance(raw, str):
        return None
    sn = re.sub(r"\s+", "", raw).upper()
    if not _SN_CHARS_RE.match(sn) or len(sn) < min_len:
        return None
    return sn.lstrip("0") or "0"


def panel_sn(raw: object) -> str:
    """Canonical serial from a panel get_attribs "sn" value, which may carry a
    device prefix before the 12-char serial: whitespace removed, last 12 kept,
    then canonical_sn. "" (never matches) when unusable."""
    compact = re.sub(r"\s+", "", raw if isinstance(raw, str) else "")
    return canonical_sn(compact[-12:]) or ""


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


def _list_entries(reply: Mapping[str, Any]) -> list[tuple[int, str, str | None]]:
    """(net_dev_id, name, mn) from get_list. Accepts the documented parallel
    arrays ``{"name": [...], "mn": [...]}`` (slot = index + 1) and the
    ``{"list": [{"net_dev_id", "name", "mn"}]}`` shape."""
    out: list[tuple[int, str, str | None]] = []
    if isinstance(reply.get("list"), list):
        for entry in reply["list"]:
            i = entry.get("net_dev_id")
            if isinstance(i, int) and entry.get("name"):
                mn = entry.get("mn")
                out.append((i, str(entry["name"]), None if mn is None else str(mn)))
        return out
    names = reply.get("name")
    mns = reply.get("mn")
    if isinstance(names, list):
        for idx, name in enumerate(names):
            if not name:
                continue
            mn = mns[idx] if isinstance(mns, list) and idx < len(mns) else None
            out.append((idx + 1, str(name), None if mn in (None, "") else str(mn)))
    return out


def inventory(t: Transport) -> list[Slot]:
    reply = _ok(t.request({"net_dev": {"get_list": 1}}), "net_dev", "get_list")
    slots: list[Slot] = []
    for i, name, mn in _list_entries(reply):
        a = _ok(
            t.request({"net_dev": {"get_attribs": {"net_dev_id": i}}}),
            "net_dev",
            "get_attribs",
        )
        sn = panel_sn(str(a.get("sn", "")))
        slots.append(Slot(i, sn, str(a.get("name", name)), mn))
    return slots


def parse_serials(values: Any, source: str) -> frozenset[str]:
    """Validate a list of serials (from --protect or the link file's "protect"
    array) and return their canonical forms (see canonical_sn). Up to 12 hex
    digits; whitespace and leading zeros are ignored. Malformed input aborts
    before connecting."""
    if not isinstance(values, (list, tuple)):
        raise AbortError(f"{source} must be a list of serials")
    given: set[str] = set()
    for raw in values:
        sn = canonical_sn(raw, min_len=USER_SN_MIN_LEN)
        if sn is None:
            raise AbortError(f"invalid serial in {source}: need 11 or 12 hex digits")
        given.add(sn)
    return frozenset(given)


def protected_serials(
    protects: list[str], file_protected: frozenset[str] = frozenset()
) -> frozenset[str]:
    """Run protections = link file "protect" array + optional --protect serials
    (decision 41). The tool's own link is added once connected."""
    # Re-canonicalize the file list too, so every protection uses the same form.
    file_canon = parse_serials(sorted(file_protected), 'link file "protect"')
    return DEFAULT_PROTECTED_SNS | file_canon | parse_serials(protects, "--protect")


def validate_targets(
    removes: list[str], names: list[str], protected: frozenset[str] = DEFAULT_PROTECTED_SNS
) -> list[tuple[str, str]]:
    if not removes:
        raise AbortError("no --remove targets given")
    if len(removes) > MAX_TARGETS:
        raise AbortError(f"at most {MAX_TARGETS} targets per run")
    if len(names) != len(removes):
        raise AbortError("each --remove needs a matching --expect-name, in order")
    out = []
    for sn, name in zip(removes, names, strict=True):
        canon = canonical_sn(sn, min_len=USER_SN_MIN_LEN)
        if canon is None:
            raise AbortError(f"invalid serial {sn!r}: need 11 or 12 hex digits")
        sn_u = canon
        if sn_u in protected | DEFAULT_PROTECTED_SNS:
            raise AbortError(f"{sn_u} is protected")
        if not name.strip():
            raise AbortError("--expect-name must be non-empty")
        out.append((sn_u, name.strip()))
    if len({s for s, _ in out}) != len(out):
        raise AbortError("duplicate --remove target")
    return out


OWN_LINK_LABEL = "(own link)"


def _show_sn(sn: str, own: str) -> str:
    """The tool's own link serial is never printed or logged (as in link_command)."""
    return OWN_LINK_LABEL if own and sn == own else sn


def _fmt(slots: list[Slot], targets: set[str], protected: set[str], own: str = "") -> str:
    rows = ["slot  sn            action   name  [reason]"]
    for s in slots:
        reason = s.touch_screen_reason
        if reason:
            act, why = "PROTECT", f"  [{reason}]"
        elif s.sn in protected:
            act, why = "PROTECT", ""
        else:
            act, why = ("DELETE" if s.sn in targets else "keep"), ""
        rows.append(f"{s.net_dev_id:<5} {_show_sn(s.sn, own):<12}  {act:<8} {s.name}{why}")
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
    protects: list[str] | None = None,
    out: Callable[[str], None] = print,
    clock: Callable[[], float] = time.monotonic,
) -> RunResult:
    install_redaction()
    base_protected = protected_serials(protects or [], transport.file_protected())
    targets = validate_targets(removes, expect_names, base_protected)
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
                transport,
                targets,
                target_sns,
                apply,
                code,
                confirm,
                out,
                clock,
                result,
                base_protected,
            )
        finally:
            transport.close()
    except AbortError as exc:
        exc.result = result
        raise
    finally:
        code = None
        REDACTOR.clear()


def _run_connected(
    t: Any,
    targets: list[tuple[str, str]],
    target_sns: set[str],
    apply: bool,
    code: str | None,
    confirm: Callable[[str], str],
    out: Callable[[str], None],
    clock: Callable[[], float],
    result: RunResult,
    base_protected: frozenset[str] = DEFAULT_PROTECTED_SNS,
) -> RunResult:
    mac = normalize_mac(t.panel_mac())
    if mac != TEST_PANEL_MAC:
        raise AbortError("panel is not the TEST panel")
    own = canonical_sn(str(t.own_link_sn())) or ""
    if not own or own == "0":
        raise AbortError("cannot determine the tool's own link serial; refusing")
    result.own_sn = own
    protected = set(base_protected | DEFAULT_PROTECTED_SNS) | {own}
    if target_sns & protected:
        raise AbortError("a target is protected (--protect or the tool's own link)")

    result.before = inventory(t)
    # The session authenticated with the link file's keys under own_link_sn (HELLO
    # binds them); also require that serial to be a link on this panel.
    if own not in {s.sn for s in result.before}:
        raise AbortError("the tool's own link is not on this panel; refusing")
    # Touch screens join the protected set (verify checks they survive too).
    protected |= {s.sn for s in result.before if s.touch_screen_reason}
    by_sn = {s.sn: s for s in result.before}
    for sn, name in targets:
        slot = by_sn.get(sn)
        if slot is None:
            raise AbortError(f"{sn} not linked on this panel")
        if slot.name != name:
            raise AbortError(f"{sn} name {slot.name!r} != --expect-name {name!r}")
        if slot.touch_screen_reason:
            raise AbortError(f"{sn} is protected: {slot.touch_screen_reason}")

    out(_fmt(result.before, target_sns, protected, own))
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
            # Digits only; the panel's authenticate pin is a JSON number, so a leading
            # zero cannot be sent. Refuse it, matching elke27's control_authenticate.
            if code is None or not code.isdigit():
                raise ValueError
            if len(code) > 1 and code.startswith("0"):
                raise AbortError(f"{ENV_INSTALLER_CODE} has a leading zero; not supported")
            pin = int(code)
        except (TypeError, ValueError):
            raise AbortError(f"{ENV_INSTALLER_CODE} is not numeric") from None
        del pin  # validated only; the transport sends the literal digits
        if not t.authenticate(cast(str, code)):
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
            if panel_sn(str(a.get("sn", ""))) != sn:
                raise AbortError(f"slot {slot.net_dev_id} no longer holds {sn}; stopping")
            if sn in protected or slot.touch_screen_reason:  # belt and braces
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
    # Protected links must survive; ones already absent before the run are not
    # required to appear.
    missing = (protected & {s.sn for s in result.before}) - after
    result.applied = True
    out(_fmt(result.after, set(), protected, own))
    for sn, state in result.sessions.items():
        out(f"revoked link {sn}: session after delete = {state}")
    if left or missing:
        raise AbortError(
            f"verify failed: still present={sorted(left)} "
            f"protected missing={sorted(_show_sn(sn, own) for sn in missing)}"
        )
    out("OK: targets removed, protected links present.")
    return result


def append_log(path: Path, mac: str, res: RunResult) -> None:
    ts = dt.datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    lines = [
        f"\n## {ts} panel {mac} ({'apply' if res.applied else 'dry-run'})",
        f"- before: {', '.join(_show_sn(s.sn, res.own_sn) for s in res.before) or '-'}",
        f"- after: {', '.join(_show_sn(s.sn, res.own_sn) for s in res.after) or '-'}",
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
        help="link serial to remove (11-12 hex digits; spaces and leading zeros "
        "ignored; repeatable, max 6)",
    )
    p.add_argument(
        "--expect-name",
        action="append",
        default=[],
        metavar="NAME",
        help="Network Devices name each --remove must have (same order)",
    )
    p.add_argument(
        "--protect",
        action="append",
        default=[],
        metavar="SN",
        help="extra serial (11-12 hex digits) to protect for this run (optional, "
        "repeatable); adds to the link file's protect list and the tool's own link",
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


def make_live_transport(protects: list[str]) -> Transport:
    from elk_test_tools.elke27_transport import Elke27Transport

    return Elke27Transport.from_env(os.environ, protects)


def main(argv: list[str] | None = None, transport: Transport | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    install_redaction()
    try:
        with _run_lock():
            return _main_locked(args, transport)
    except AbortError as exc:
        print(f"ABORT: {exc}", file=sys.stderr)
        return 2


def _run_lock() -> AbstractContextManager[None]:
    """The link/remove lock next to ELK_TEST_LINK_FILE (shared with the link command)."""
    from elk_test_tools import elke27_transport
    from elk_test_tools.link_lock import exclusive_link_lock

    link_file = os.environ.get("ELK_TEST_LINK_FILE")
    if not link_file:
        return nullcontext()
    # Validate and resolve before locking: a bad path must not create a stray
    # .lock file (in the vault or a repo), and a symlinked path must take the same
    # lock as elk-link-test-tool (which locks next to the real file).
    real = elke27_transport.check_link_file(Path(link_file), elke27_transport.VAULT_ROOT)
    return exclusive_link_lock(real)


def _main_locked(args: argparse.Namespace, transport: Transport | None) -> int:
    try:
        t = transport or make_live_transport(args.protect)
        res = run(
            transport=t,
            removes=args.remove,
            expect_names=args.expect_name,
            apply=args.apply,
            env=os.environ,
            confirm=input,
            protects=args.protect,
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
