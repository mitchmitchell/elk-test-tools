"""Output envelope, exit codes and error codes (design §4.1, §5, §6)."""

from __future__ import annotations

import datetime as dt
import json
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

SCHEMA_VERSION = "1"
TOOL_NAME = "elk-verify"


class CheckStatus(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    SKIP = "skip"
    ERROR = "error"


class Result(StrEnum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    ABORT = "abort"


class Severity(StrEnum):
    ABORT = "abort"
    FAIL = "fail"
    ERROR = "error"


class ErrorCode(StrEnum):
    """Stable error codes (§6). Renaming or removing one is a breaking change."""

    E_USAGE = "E_USAGE"
    E_SECRET_ARG = "E_SECRET_ARG"
    E_HA_NOT_ALLOWED = "E_HA_NOT_ALLOWED"
    E_PANEL_NOT_TEST = "E_PANEL_NOT_TEST"
    E_PANEL_NAME = "E_PANEL_NAME"
    E_LINK_IS_HA_ENTRY = "E_LINK_IS_HA_ENTRY"
    E_LINK_FILE = "E_LINK_FILE"
    E_TOKEN_MISSING = "E_TOKEN_MISSING"
    E_TOKEN_REJECTED = "E_TOKEN_REJECTED"
    E_CODE_MISSING = "E_CODE_MISSING"
    E_CODE_INVALID = "E_CODE_INVALID"
    E_UNREACHABLE = "E_UNREACHABLE"
    E_TIMEOUT = "E_TIMEOUT"
    E_SESSION_CONTENDED = "E_SESSION_CONTENDED"
    E_NOT_DRY_RUN_SAFE = "E_NOT_DRY_RUN_SAFE"
    E_INTERNAL = "E_INTERNAL"


EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_ABORT = 2


@dataclass(frozen=True)
class Check:
    id: str
    status: CheckStatus
    detail: str = ""
    evidence: dict[str, Any] = field(default_factory=dict)
    duration_s: float = 0.0

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "status": self.status.value,
            "detail": self.detail,
            "evidence": self.evidence,
            "duration_s": round(self.duration_s, 3),
        }


@dataclass(frozen=True)
class ErrorItem:
    code: ErrorCode
    severity: Severity
    message: str
    hint: str
    check_id: str | None = None

    def to_json(self) -> dict[str, Any]:
        return {
            "code": self.code.value,
            "severity": self.severity.value,
            "message": self.message,
            "hint": self.hint,
            "check_id": self.check_id,
        }

    def human(self) -> str:
        """``ABORT|FAIL|ERROR: <what> — <why> — <what to do>`` (message holds what — why)."""
        return f"{self.severity.value.upper()}: {self.message} — {self.hint}"


def exit_code(checks: list[Check], errors: list[ErrorItem]) -> int:
    """Map a run to 0/1/2 (§5).

    An abort error is 2. Otherwise any failed check is 1 (fail wins over error).
    Then any errored check, any remaining error item, or a run with no passing
    check (empty or all skipped) is 2. Only "at least one pass, rest pass or
    skip" is 0.
    """
    if any(e.severity is Severity.ABORT for e in errors):
        return EXIT_ABORT
    statuses = [c.status for c in checks]
    if CheckStatus.FAIL in statuses or any(e.severity is Severity.FAIL for e in errors):
        return EXIT_FAIL
    if CheckStatus.ERROR in statuses or errors:
        return EXIT_ABORT
    if CheckStatus.PASS not in statuses:
        return EXIT_ABORT
    return EXIT_PASS


def result_for(code: int, errors: list[ErrorItem]) -> Result:
    if code == EXIT_PASS:
        return Result.PASS
    if code == EXIT_FAIL:
        return Result.FAIL
    if any(e.severity is Severity.ABORT for e in errors):
        return Result.ABORT
    return Result.ERROR


def utc_iso(when: dt.datetime) -> str:
    return when.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


@dataclass
class Run:
    """One command run; ``finish()`` builds the envelope dict."""

    command: str | None
    argv_redacted: list[str]
    tool_version: str
    elke27_version: str | None
    started: dt.datetime
    dry_run: bool = True
    target: dict[str, Any] | None = None
    checks: list[Check] = field(default_factory=list)
    errors: list[ErrorItem] = field(default_factory=list)
    data: dict[str, Any] = field(default_factory=dict)
    planned: list[dict[str, Any]] = field(default_factory=list)
    cleanup: str | None = None

    def finish(self, finished: dt.datetime) -> tuple[dict[str, Any], int]:
        code = exit_code(self.checks, self.errors)
        env: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "tool": {
                "name": TOOL_NAME,
                "version": self.tool_version,
                "elke27_version": self.elke27_version,
            },
            "command": self.command,
            "argv_redacted": self.argv_redacted,
            "target": self.target,
            "dry_run": self.dry_run,
            "result": result_for(code, self.errors).value,
            "started_at": utc_iso(self.started),
            "finished_at": utc_iso(finished),
            "duration_s": round(max(0.0, (finished - self.started).total_seconds()), 3),
            "checks": [c.to_json() for c in self.checks],
            "data": self.data,
            "planned": self.planned,
            "errors": [e.to_json() for e in self.errors],
            "cleanup": self.cleanup,
        }
        return env, code


def dumps(envelope: dict[str, Any]) -> str:
    """One JSON object, sorted keys, UTF-8 (no ASCII escaping), trailing newline."""
    return json.dumps(envelope, sort_keys=True, ensure_ascii=False) + "\n"
