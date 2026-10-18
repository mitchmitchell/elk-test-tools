"""elk-verify offline prototype: envelope, schema, exit and error codes."""

from __future__ import annotations

import datetime as dt
import io
import json
import socket
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from elk_test_tools.verify import cli
from elk_test_tools.verify.envelope import (
    Check,
    CheckStatus,
    ErrorCode,
    ErrorItem,
    Severity,
    exit_code,
)
from elk_test_tools.verify.schema import data_schemas, envelope_schema, get_schema

T0 = dt.datetime(2026, 10, 18, 13, 0, 0, tzinfo=dt.UTC)
SENTINEL = "SENTINEL-7f3a9c"


class _Tty(io.StringIO):
    def isatty(self) -> bool:
        return True


@pytest.fixture(autouse=True)
def no_network(monkeypatch: pytest.MonkeyPatch) -> None:
    """The prototype is offline: any socket use fails the test."""

    def _refuse(*_a: object, **_k: object) -> None:
        raise AssertionError("elk-verify opened a socket")

    monkeypatch.setattr(socket, "socket", _refuse)
    monkeypatch.setattr(socket, "create_connection", _refuse)


def run(*argv: str, env: dict[str, str] | None = None, tty: bool = False) -> tuple[int, str, str]:
    out: io.StringIO = _Tty() if tty else io.StringIO()
    err = io.StringIO()
    ticks = iter([T0, T0 + dt.timedelta(seconds=1.5)])
    code = cli.main(list(argv), env=env or {}, stdout=out, stderr=err, now=lambda: next(ticks))
    return code, out.getvalue(), err.getvalue()


def envelope(*argv: str, env: dict[str, str] | None = None) -> tuple[int, dict[str, Any]]:
    code, out, _ = run("--json", *argv, env=env)
    assert out.endswith("\n") and out.count("\n") == 1
    env_obj = json.loads(out)
    jsonschema.Draft202012Validator(envelope_schema()).validate(env_obj)
    return code, env_obj


# --- envelope and schema ---------------------------------------------------------


def test_schemas_are_valid_json_schema() -> None:
    jsonschema.Draft202012Validator.check_schema(envelope_schema())
    for schema in data_schemas().values():
        jsonschema.Draft202012Validator.check_schema(schema)


def test_checked_in_schema_matches_code() -> None:
    path = Path(__file__).resolve().parents[1] / "schemas" / "envelope.schema.json"
    assert json.loads(path.read_text()) == envelope_schema()


def test_version_envelope_shape() -> None:
    code, env = envelope("version")
    assert code == 0
    assert env["schema_version"] == "1"
    assert env["command"] == "version"
    assert env["result"] == "pass"
    assert env["tool"]["name"] == "elk-verify"
    assert env["target"] is None
    assert env["dry_run"] is True
    assert env["started_at"] == "2026-10-18T13:00:00Z"
    assert env["finished_at"] == "2026-10-18T13:00:01Z"
    assert env["duration_s"] == 1.5
    assert [c["id"] for c in env["checks"]] == ["tool.version.read", "tool.elke27.version"]
    jsonschema.validate(env["data"], data_schemas()["version"])


def test_json_output_is_sorted_and_utf8() -> None:
    _, out, _ = run("--json", "version")
    obj = json.loads(out)
    assert out == json.dumps(obj, sort_keys=True, ensure_ascii=False) + "\n"


def test_data_has_no_timestamps_so_runs_diff_identically() -> None:
    _, a = envelope("version")
    _, b = envelope("version")
    assert a["data"] == b["data"]


@pytest.mark.parametrize("name", ["envelope", "version", "schema"])
def test_schema_command_prints_each_schema(name: str) -> None:
    code, env = envelope("schema", name)
    assert code == 0
    assert env["data"] == {"name": name, "schema": get_schema(name)}
    jsonschema.validate(env["data"], data_schemas()["schema"])


def test_schema_default_is_envelope() -> None:
    _, env = envelope("schema")
    assert env["data"]["name"] == "envelope"


def test_missing_elke27_is_check_error_exit_2(monkeypatch: pytest.MonkeyPatch) -> None:
    real = cli._package_version
    monkeypatch.setattr(cli, "_package_version", lambda n: None if n == "elke27" else real(n))
    code, env = envelope("version")
    assert code == 2
    assert env["result"] == "error"
    assert env["tool"]["elke27_version"] is None


# --- exit codes (§5) ---------------------------------------------------------------


def _c(status: CheckStatus) -> Check:
    return Check("a.b.c", status)


@pytest.mark.parametrize(
    ("statuses", "expected"),
    [
        ([CheckStatus.PASS], 0),
        ([CheckStatus.PASS, CheckStatus.SKIP], 0),
        ([CheckStatus.FAIL], 1),
        ([CheckStatus.FAIL, CheckStatus.ERROR], 1),  # fail wins over error
        ([CheckStatus.PASS, CheckStatus.ERROR], 2),  # errored, nothing failed
        ([CheckStatus.SKIP, CheckStatus.SKIP], 2),  # all skipped
        ([], 2),  # nothing checked
    ],
)
def test_exit_code_rules(statuses: list[CheckStatus], expected: int) -> None:
    assert exit_code([_c(s) for s in statuses], []) == expected


def test_abort_error_is_exit_2_even_with_failures() -> None:
    abort = ErrorItem(ErrorCode.E_PANEL_NOT_TEST, Severity.ABORT, "x — y", "z")
    assert exit_code([_c(CheckStatus.FAIL)], [abort]) == 2


def test_error_codes_are_the_design_list() -> None:
    assert {c.value for c in ErrorCode} == {
        "E_USAGE", "E_SECRET_ARG", "E_HA_NOT_ALLOWED", "E_PANEL_NOT_TEST", "E_PANEL_NAME",
        "E_LINK_IS_HA_ENTRY", "E_LINK_FILE", "E_TOKEN_MISSING", "E_TOKEN_REJECTED",
        "E_CODE_MISSING", "E_CODE_INVALID", "E_UNREACHABLE", "E_TIMEOUT",
        "E_SESSION_CONTENDED", "E_NOT_DRY_RUN_SAFE", "E_INTERNAL",
    }  # fmt: skip


# --- usage and secrets (§3, §6, §7) --------------------------------------------------


@pytest.mark.parametrize(
    "argv",
    [
        ("--dry-run", "--apply", "version"),
        ("no-such-command",),
        ("schema", "nope"),
        (),
    ],
)
def test_usage_errors_exit_2(argv: tuple[str, ...]) -> None:
    code, env = envelope(*argv)
    assert code == 2
    assert env["result"] == "abort"
    assert [e["code"] for e in env["errors"]] == ["E_USAGE"]
    assert env["checks"] == []


@pytest.mark.parametrize(
    "argv",
    [
        ("--token", SENTINEL, "version"),
        (f"--pin={SENTINEL}", "version"),
        ("--installer-code", SENTINEL, "version"),
        ("version", "--passphrase", SENTINEL),
    ],
)
def test_secret_flag_on_argv_aborts_and_is_redacted(argv: tuple[str, ...]) -> None:
    code, out, err = run("--json", *argv)
    assert code == 2
    env = json.loads(out)
    assert [e["code"] for e in env["errors"]] == ["E_SECRET_ARG"]
    assert env["command"] is None  # refused before parsing
    assert SENTINEL not in out + err


def test_secret_value_from_env_on_argv_aborts() -> None:
    code, out, err = run("--json", "schema", SENTINEL, env={"TEST_HA_TOKEN": SENTINEL})
    assert code == 2
    assert json.loads(out)["errors"][0]["code"] == "E_SECRET_ARG"
    assert SENTINEL not in out + err


@pytest.mark.parametrize("tty", [False, True])
def test_env_secrets_never_printed(tty: bool) -> None:
    env = {name: f"{SENTINEL}-{i}" for i, name in enumerate(cli.SECRET_ENV_NAMES)}
    for argv in (("version",), ("schema",), ("bad",)):
        _, out, err = run(*argv, env=env, tty=tty)
        assert SENTINEL not in out + err


def test_internal_error_has_no_traceback(monkeypatch: pytest.MonkeyPatch) -> None:
    def boom(*_a: object) -> None:
        raise RuntimeError(SENTINEL)

    monkeypatch.setitem(cli._COMMANDS, "version", boom)
    code, out, err = run("--json", "version")
    env = json.loads(out)
    assert code == 2
    assert env["errors"][0]["code"] == "E_INTERNAL"
    assert SENTINEL not in out + err and "Traceback" not in out + err


def test_help_lists_env_names_only(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as ei:
        cli.main(["--help"], env={"TEST_HA_TOKEN": SENTINEL})
    assert ei.value.code == 0
    text = capsys.readouterr().out
    assert all(name in text for name in cli.SECRET_ENV_NAMES)
    assert SENTINEL not in text


# --- output mode (§3, §4.2) -----------------------------------------------------------


def test_non_tty_defaults_to_json() -> None:
    _, out, _ = run("version")
    assert json.loads(out)["command"] == "version"


def test_tty_defaults_to_human() -> None:
    code, out, err = run("version", tty=True)
    lines = out.splitlines()
    assert code == 0
    assert lines[0] == "elk-verify version · OFFLINE · DRY RUN"
    assert lines[1].startswith("PASS  tool.version.read")
    assert lines[-1] == "2 pass, 0 fail, 0 skip, 0 error — PASS (exit 0)"
    assert err == ""


def test_human_error_line_format() -> None:
    code, out, err = run("--human", "--dry-run", "--apply", "version")
    assert code == 2
    assert out.splitlines()[-1].endswith("— ABORT (exit 2)")
    assert err.startswith("ABORT: bad usage — ")
    assert err.rstrip().endswith("see elk-verify --help")
