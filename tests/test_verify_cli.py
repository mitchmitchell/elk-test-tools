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
from elk_test_tools.verify.codes import CodeError, load_code
from elk_test_tools.verify.envelope import (
    HINTS,
    Check,
    CheckStatus,
    ErrorCode,
    ErrorItem,
    Severity,
    exit_code,
)
from elk_test_tools.verify.schema import (
    CHECK_IDS,
    bundle_schema,
    command_schema,
    data_schemas,
    envelope_schema,
    get_schema,
)

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
    jsonschema.Draft202012Validator(bundle_schema()).validate(env_obj)
    if env_obj["result"] != "abort":
        jsonschema.Draft202012Validator(command_schema(env_obj["command"])).validate(env_obj)
    return code, env_obj


# --- envelope and schema ---------------------------------------------------------


def test_schemas_are_valid_json_schema() -> None:
    jsonschema.Draft202012Validator.check_schema(envelope_schema())
    jsonschema.Draft202012Validator.check_schema(bundle_schema())
    for name, schema in data_schemas().items():
        jsonschema.Draft202012Validator.check_schema(schema)
        jsonschema.Draft202012Validator.check_schema(command_schema(name))


def test_checked_in_schema_matches_schema_command() -> None:
    """E5: schemas/elk-verify.v1.json is exactly what `elk-verify schema` prints."""
    path = Path(__file__).resolve().parents[1] / "schemas" / "elk-verify.v1.json"
    _, env = envelope("schema")
    assert json.loads(path.read_text()) == env["data"]["schema"]


def test_check_ids_snapshot() -> None:
    """E4: ids are an API. Changing this list needs a schema_version bump."""
    assert CHECK_IDS == {
        "version": ("tool.elke27.version", "tool.version.read"),
        "schema": ("schema.document.built",),
    }
    _, env = envelope("version")
    assert {c["id"] for c in env["checks"]} == set(CHECK_IDS["version"])


def test_command_schema_rejects_an_unlisted_check_id() -> None:
    _, env = envelope("version")
    env["checks"][0]["id"] = "tool.version.renamed"
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(env, command_schema("version"))


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


@pytest.mark.parametrize("name", ["version", "schema"])
def test_schema_command_prints_each_command_schema(name: str) -> None:
    code, env = envelope("schema", name)
    assert code == 0
    assert env["data"] == {"name": name, "schema": get_schema(name)}
    jsonschema.validate(env["data"], data_schemas()["schema"])


def test_schema_default_is_the_bundle() -> None:
    _, env = envelope("schema")
    assert env["data"] == {"name": "elk-verify.v1", "schema": bundle_schema()}


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
        ("--dry-run", "--apply", "--yes", "version"),
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
    assert lines[0] == "elk-verify version · OFFLINE · DRY RUN · 2026-10-18 08:00:00 CT"
    assert lines[1].startswith("PASS  tool.version.read")
    assert lines[-1] == "2 pass, 0 fail, 0 skip, 0 error — PASS (exit 0)"
    assert err == ""


def test_human_error_line_format() -> None:
    code, out, err = run("--human", "--dry-run", "--apply", "version")
    assert code == 2
    assert out.splitlines()[-1].endswith("— ABORT (exit 2)")
    assert err.startswith("ABORT: bad usage — ")
    assert err.rstrip().endswith("see elk-verify --help")


# --- write gating (acceptance A6/A7, E3) ------------------------------------------------


@pytest.mark.parametrize("flag", ["--apply", "--yes"])
def test_only_one_of_apply_yes_is_not_dry_run_safe(flag: str) -> None:
    code, env = envelope(flag, "version")
    assert code == 2
    assert [e["code"] for e in env["errors"]] == ["E_NOT_DRY_RUN_SAFE"]
    assert env["dry_run"] is True
    assert env["checks"] == []  # the command did not run


def test_dry_run_is_the_default_and_accepted() -> None:
    assert envelope("version")[1]["dry_run"] is True
    assert envelope("--dry-run", "version")[1]["dry_run"] is True


def test_only_apply_and_yes_end_dry_run() -> None:
    code, env = envelope("--apply", "--yes", "version")
    assert code == 0
    assert env["dry_run"] is False


def test_env_and_stdin_cannot_stand_in_for_apply(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr("sys.stdin", io.StringIO("y\ny\n"))
    yes_env = {"ELK_VERIFY_YES": "1", "ELK_VERIFY_APPLY": "1", "YES": "y"}
    _, env = envelope("--apply", "version", env=yes_env)
    assert [e["code"] for e in env["errors"]] == ["E_NOT_DRY_RUN_SAFE"]
    assert envelope("version", env=yes_env)[1]["dry_run"] is True


# --- error codes and hints (E9) --------------------------------------------------------


def test_every_error_code_has_a_hint() -> None:
    assert set(HINTS) == set(ErrorCode)
    assert all(HINTS[c].strip() for c in ErrorCode)


@pytest.mark.parametrize(
    ("argv", "code"),
    [
        (("bad",), "E_USAGE"),
        (("--token", "x", "version"), "E_SECRET_ARG"),
        (("--apply", "version"), "E_NOT_DRY_RUN_SAFE"),
    ],
)
def test_offline_codes_carry_their_hint(argv: tuple[str, ...], code: str) -> None:
    _, env = envelope(*argv)
    (err,) = env["errors"]
    assert err["code"] == code
    assert err["hint"].startswith(HINTS[ErrorCode(code)])


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (None, ErrorCode.E_CODE_MISSING),
        ("", ErrorCode.E_CODE_MISSING),
        ("0000", ErrorCode.E_CODE_INVALID),
        ("0", ErrorCode.E_CODE_INVALID),
        ("0123", ErrorCode.E_CODE_INVALID),
        ("12a4", ErrorCode.E_CODE_INVALID),
        ("１２３４", ErrorCode.E_CODE_INVALID),  # non-ASCII digits
    ],
)
def test_code_loader_refuses_missing_and_invalid(value: str | None, code: ErrorCode) -> None:
    env = {} if value is None else {"ELK_TEST_ACCESS_CODE": value}
    with pytest.raises(CodeError) as ei:
        load_code(env, "ELK_TEST_ACCESS_CODE")
    assert ei.value.item.code is code
    assert ei.value.item.hint == HINTS[code]
    if value:
        assert value not in ei.value.item.message


def test_code_loader_accepts_a_valid_code() -> None:
    assert load_code({"ELK_TEST_ACCESS_CODE": "1234"}, "ELK_TEST_ACCESS_CODE") == "1234"


# --- secrets in logs (A12) and human time (E8) ---------------------------------------------


def test_verbose_logs_never_carry_secrets(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level("DEBUG")
    env = {name: f"{SENTINEL}-{i}" for i, name in enumerate(cli.SECRET_ENV_NAMES)}
    _, out, err = run("--verbose", "version", env=env)
    run("--verbose", "schema", f"{SENTINEL}-0", env=env)
    text = caplog.text + out + err
    assert "elk-verify version" in caplog.text
    assert SENTINEL not in text


def test_human_header_shows_ct_time() -> None:
    _, out, _ = run("--human", "version")
    assert out.splitlines()[0].endswith("· 2026-10-18 08:00:00 CT")


def test_help_points_to_schema_for_check_ids(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit):
        cli.main(["--help"], env={})
    assert "elk-verify schema <command>" in " ".join(capsys.readouterr().out.split())
