"""``elk-verify`` entry point. Offline prototype: ``version`` and ``schema`` only.

Every run prints one envelope (§4.1) in JSON mode, or the §4.2 human lines,
and exits 0/1/2 (§5). Guards that apply before any work, even offline: a
secret on argv (E_SECRET_ARG) and bad usage, including ``--dry-run`` with
``--apply`` (E_USAGE). No command here opens a socket.
"""

from __future__ import annotations

import argparse
import datetime as dt
import os
import re
import sys
from collections.abc import Callable, Mapping, Sequence
from importlib import metadata
from typing import IO, Any, NoReturn

from .envelope import (
    Check,
    CheckStatus,
    ErrorCode,
    ErrorItem,
    Run,
    Severity,
    dumps,
)
from .schema import get_schema, schema_names

SECRET_ENV_NAMES = (
    "TEST_HA_TOKEN",
    "ELK_TEST_ACCESS_CODE",
    "ELK_TEST_INSTALLER_CODE",
    "ELK_TEST_PASSPHRASE",
    "ELK_TEST_LINK_FILE",
)
_SECRET_FLAG = re.compile(r"^--(token|code|pin|passphrase|installer[\w-]*)(=.*)?$")
OFFLINE_COMMANDS = ("version", "schema")


class UsageError(Exception):
    pass


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise UsageError(message)


def _package_version(name: str) -> str | None:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return None


def redact_argv(argv: Sequence[str], env: Mapping[str, str]) -> tuple[list[str], bool]:
    """Return argv with secrets masked, and whether any secret was on argv.

    A secret is a ``--token/--code/--pin/--passphrase/--installer*`` flag (and
    the value after it), or any token equal to a secret env var's value.
    """
    secrets = {env[n] for n in SECRET_ENV_NAMES if env.get(n)}
    out: list[str] = []
    found = False
    mask_next = False
    for tok in argv:
        if mask_next:
            out.append("***")
            mask_next = False
            continue
        m = _SECRET_FLAG.match(tok)
        if m:
            found = True
            out.append(f"--{m.group(1)}" + ("=***" if m.group(2) else ""))
            mask_next = m.group(2) is None
            continue
        value = tok.split("=", 1)[1] if tok.startswith("--") and "=" in tok else tok
        if value in secrets:
            found = True
            out.append("***")
            continue
        out.append(tok)
    return out, found


def build_parser() -> _Parser:
    env_names = ", ".join(SECRET_ENV_NAMES)
    p = _Parser(
        prog="elk-verify",
        description="Verify TEST HA and the TEST E27 panel (offline prototype).",
        epilog=f"Secrets are read from the environment only: {env_names}.",
    )
    out = p.add_mutually_exclusive_group()
    out.add_argument("--json", dest="mode", action="store_const", const="json")
    out.add_argument("--human", dest="mode", action="store_const", const="human")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--apply", action="store_true")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--timeout", type=float, default=30.0)
    p.add_argument("--connect-timeout", type=float, default=10.0)
    p.add_argument("--settle", type=float, default=5.0)
    p.add_argument("--verbose", action="store_true")
    p.add_argument("--check", action="append", default=[], metavar="ID")
    sub = p.add_subparsers(dest="command", parser_class=_Parser)
    sub.add_parser("version", help="tool, elke27 and schema versions (offline)")
    s = sub.add_parser("schema", help="print a JSON Schema (offline)")
    s.add_argument("name", nargs="?", default="envelope", help=" | ".join(schema_names()))
    return p


def _cmd_version(run: Run, _args: argparse.Namespace) -> None:
    run.data = {
        "tool_version": run.tool_version,
        "elke27_version": run.elke27_version,
        "schema_version": "1",
    }
    run.checks.append(Check("tool.version.read", CheckStatus.PASS, run.tool_version))
    if run.elke27_version is None:
        run.checks.append(
            Check("tool.elke27.version", CheckStatus.ERROR, "elke27 is not installed")
        )
    else:
        run.checks.append(Check("tool.elke27.version", CheckStatus.PASS, run.elke27_version))


def _cmd_schema(run: Run, args: argparse.Namespace) -> None:
    name = str(args.name)
    schema = get_schema(name)
    if schema is None:
        raise UsageError(f"unknown schema {name!r}; one of: {', '.join(schema_names())}")
    run.data = {"name": name, "schema": schema}
    run.checks.append(Check(f"schema.{name}.available", CheckStatus.PASS, name))


_COMMANDS: dict[str, Callable[[Run, argparse.Namespace], None]] = {
    "version": _cmd_version,
    "schema": _cmd_schema,
}


def _human(env: dict[str, Any], code: int) -> tuple[str, str]:
    header = f"elk-verify {env['command'] or '-'} · OFFLINE"
    if env["dry_run"]:
        header += " · DRY RUN"
    lines = [header]
    labels = {"pass": "PASS", "fail": "FAIL", "skip": "SKIP", "error": "ERR "}
    for c in env["checks"]:
        lines.append(f"{labels[c['status']]}  {c['id']}  {c['detail']}".rstrip())
    n = {k: sum(1 for c in env["checks"] if c["status"] == k) for k in labels}
    lines.append(
        f"{n['pass']} pass, {n['fail']} fail, {n['skip']} skip, {n['error']} error"
        f" — {env['result'].upper()} (exit {code})"
    )
    err = [
        f"{e['severity'].upper()}: {e['message']} — {e['hint']}".rstrip(" —") for e in env["errors"]
    ]
    return "\n".join(lines) + "\n", ("\n".join(err) + "\n") if err else ""


def main(
    argv: Sequence[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    stdout: IO[str] | None = None,
    stderr: IO[str] | None = None,
    now: Callable[[], dt.datetime] | None = None,
) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    env = os.environ if env is None else env
    stdout = stdout or sys.stdout
    stderr = stderr or sys.stderr
    clock = now or (lambda: dt.datetime.now(dt.UTC))

    redacted, secret_on_argv = redact_argv(argv, env)
    run = Run(
        command=None,
        argv_redacted=redacted,
        tool_version=_package_version("elk-test-tools") or "0+unknown",
        elke27_version=_package_version("elke27"),
        started=clock(),
    )
    mode = "json" if "--json" in argv else "human" if "--human" in argv else None
    try:
        if secret_on_argv:
            run.errors.append(
                ErrorItem(
                    ErrorCode.E_SECRET_ARG,
                    Severity.ABORT,
                    "secret on the command line — secrets are never accepted as arguments",
                    f"set it in the environment instead ({', '.join(SECRET_ENV_NAMES)})",
                )
            )
        else:
            args = build_parser().parse_args(argv)
            mode = args.mode or mode
            run.command = args.command
            run.dry_run = not args.apply
            if args.dry_run and args.apply:
                raise UsageError("--dry-run and --apply are mutually exclusive")
            if args.command is None:
                raise UsageError(f"a command is required: {', '.join(OFFLINE_COMMANDS)}")
            _COMMANDS[args.command](run, args)
    except UsageError as err:
        run.checks.clear()
        run.errors.append(
            ErrorItem(
                ErrorCode.E_USAGE,
                Severity.ABORT,
                f"bad usage — {err}",
                "see elk-verify --help",
            )
        )
    except Exception as err:  # noqa: BLE001 - never a traceback (it could carry env)
        run.checks.clear()
        run.errors.append(
            ErrorItem(
                ErrorCode.E_INTERNAL,
                Severity.ABORT,
                f"internal error — {type(err).__name__}",
                "rerun with --verbose and report it",
            )
        )
    envelope, code = run.finish(clock())
    if mode is None:
        mode = "human" if stdout.isatty() else "json"
    if mode == "json":
        stdout.write(dumps(envelope))
    else:
        out, err_text = _human(envelope, code)
        stdout.write(out)
        if err_text:
            stderr.write(err_text)
    return code


def console() -> None:  # pragma: no cover - console_script shim
    raise SystemExit(main())
