"""One-time ``link`` command: provision the tool's OWN link on the TEST panel.

Uses elke27's public ``Elke27Client.async_link`` (the entry point HA's config
flow uses); no protocol code here. Codes come only from env vars
(ELK_TEST_ACCESS_CODE, ELK_TEST_PASSPHRASE). The link file named by
ELK_TEST_LINK_FILE is created atomically (O_CREAT|O_EXCL, mode 0600), never
overwritten, and never under the vault or inside a git repo. Keys, codes and the
file path are never logged or printed; only success or failure is reported.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import secrets
import sys
from collections.abc import Callable, MutableMapping
from pathlib import Path
from typing import Any

from elk_test_tools.elke27_transport import (
    ENV_LINK_FILE,
    TOOL_MN,
    VAULT_ROOT,
    check_link_location,
)
from elk_test_tools.link_lock import exclusive_link_lock
from elk_test_tools.link_removal import (
    REDACTOR,
    TEST_PANEL_MAC,
    AbortError,
    install_redaction,
    normalize_mac,
)

ENV_ACCESS_CODE = "ELK_TEST_ACCESS_CODE"
ENV_PASSPHRASE = "ELK_TEST_PASSPHRASE"


def generate_serial() -> str:
    """Random 12-digit decimal, no leading zero (same scheme as HA's integration ID)."""
    return str(secrets.randbelow(9 * 10**11) + 10**11)


def _prepare_path(raw: str | None, vault_root: Path) -> Path:
    if not raw:
        raise AbortError(f"{ENV_LINK_FILE} is not set")
    path = Path(raw)
    try:
        parent = path.parent.resolve(strict=True)
    except OSError:
        raise AbortError("link file directory does not exist") from None
    target = parent / path.name
    if target.exists() or target.is_symlink():
        raise AbortError("link file already exists; refusing to overwrite")
    check_link_location(target, vault_root)
    return target


def _write_exclusive(path: Path, data: dict[str, Any]) -> None:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        raise AbortError("link file already exists; refusing to overwrite") from None
    except OSError:
        raise AbortError("cannot create the link file") from None
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        os.fchmod(fh.fileno(), 0o600)
        json.dump(data, fh)


async def _discover_mac(client: Any, host: str) -> str:
    try:
        panels = await client.async_discover(address=host, timeout_s=5)
    except Exception:  # noqa: BLE001
        return ""
    for p in panels:
        if getattr(p, "host", None) == host and getattr(p, "panel_mac", None):
            return str(p.panel_mac)
    return ""


async def _link(
    client: Any, host: str, port: int, access: str, passph: str, serial: str
) -> dict[str, str]:
    try:
        keys = await client.async_link(
            host,
            port,
            access_code=access,
            passphrase=passph,
            client_identity={"mn": TOOL_MN, "sn": serial},
        )
    except Exception as exc:  # noqa: BLE001 - never echo details
        raise AbortError(f"link failed ({type(exc).__name__})") from None
    return {
        "tempkey_hex": keys.tempkey_hex,
        "linkkey_hex": keys.linkkey_hex,
        "linkhmac_hex": keys.linkhmac_hex,
    }


def run_link(
    *,
    host: str,
    port: int,
    env: MutableMapping[str, str],
    client_factory: Callable[[], Any],
    out: Callable[[str], None] = print,
    vault_root: Path | None = None,
    serial_factory: Callable[[], str] | None = None,
) -> str:
    install_redaction()
    vault_root = vault_root or VAULT_ROOT
    serial_factory = serial_factory or generate_serial
    raw = env.get(ENV_LINK_FILE)
    _prepare_path(raw, vault_root)  # validate before creating the lock file
    assert raw is not None
    # One run at a time (shared with elk-remove-test-link): the existence check,
    # provisioning and the exclusive write all happen under the lock, so a second
    # run can't also provision a link and then fail to save its keys.
    with exclusive_link_lock(raw):
        return _run_link_locked(
            target=_prepare_path(raw, vault_root),
            host=host,
            port=port,
            env=env,
            client_factory=client_factory,
            out=out,
            serial_factory=serial_factory,
        )


def _run_link_locked(
    *,
    target: Path,
    host: str,
    port: int,
    env: MutableMapping[str, str],
    client_factory: Callable[[], Any],
    out: Callable[[str], None],
    serial_factory: Callable[[], str],
) -> str:
    access = env.pop(ENV_ACCESS_CODE, None)
    passph = env.pop(ENV_PASSPHRASE, None)
    if not access or not passph:
        raise AbortError(f"{ENV_ACCESS_CODE} and {ENV_PASSPHRASE} must both be set")
    REDACTOR.add_secret(access)
    REDACTOR.add_secret(passph)
    loop = asyncio.new_event_loop()
    try:
        client = client_factory()
        mac = normalize_mac(loop.run_until_complete(_discover_mac(client, host)))
        if mac != TEST_PANEL_MAC:
            raise AbortError("panel is not the TEST panel")
        serial = serial_factory()
        # The new keys are not known until async_link returns, so no redaction
        # can catch them during linking: silence all logging for that call.
        logging.disable(logging.CRITICAL)
        try:
            keys = loop.run_until_complete(_link(client, host, port, access, passph, serial))
        finally:
            logging.disable(logging.NOTSET)
        for value in keys.values():
            REDACTOR.add_secret(value)
        _write_exclusive(
            target,
            {"host": host, "port": port, "own_link_sn": serial, "link_keys": keys, "protect": []},
        )
    finally:
        access = passph = None
        loop.close()
        REDACTOR.clear()
    out("OK: link created")  # never the serial, keys, codes or path
    return serial


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="elk-link-test-tool",
        description="One-time: link elk-test-tools to the TEST panel with its own serial.",
    )
    p.add_argument("--host", required=True, help="TEST panel host")
    p.add_argument("--port", type=int, default=2101)
    return p


def main(argv: list[str] | None = None, client_factory: Callable[[], Any] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    install_redaction()

    def default_factory() -> Any:
        from elke27_lib import Elke27Client

        return Elke27Client()

    try:
        run_link(
            host=args.host,
            port=args.port,
            env=os.environ,
            client_factory=client_factory or default_factory,
        )
    except AbortError as exc:
        print(f"ABORT: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
