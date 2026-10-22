"""One-time link command, against a fake elke27 client (no panel)."""

from __future__ import annotations

import json
import logging
import stat
from types import SimpleNamespace
from typing import Any

import pytest

from elk_test_tools import link_command as lc
from elk_test_tools import link_removal as lr
from elk_test_tools.elke27_transport import ENV_LINK_FILE

ACCESS = "acc3ss-31415"
PASSPH = "pass phrase 2718"
KEYS = SimpleNamespace(tempkey_hex="ab" * 16, linkkey_hex="cd" * 16, linkhmac_hex="ef" * 32)
SERIAL = "482910375516"


class FakeClient:
    def __init__(self, mac: str = "cc:03:1e:b0:3b:20") -> None:
        self.mac = mac
        self.link_calls: list[dict[str, Any]] = []

    async def async_discover(self, *, address: str, timeout_s: float) -> list[Any]:
        logging.getLogger("elke27_lib.discovery").debug("discovered %s", address)
        return [SimpleNamespace(host=address, panel_mac=self.mac)]

    async def async_link(self, host: str, port: int, **kw: Any) -> Any:
        self.link_calls.append({"host": host, "port": port, **kw})
        # A leaky library log: must be redacted.
        logging.getLogger("elke27_lib.linking").debug(
            "link access=%s passph=%s key=%s", kw["access_code"], kw["passphrase"], KEYS.linkkey_hex
        )
        return KEYS


def _env(path: Any) -> dict[str, str]:
    return {ENV_LINK_FILE: str(path), lc.ENV_ACCESS_CODE: ACCESS, lc.ENV_PASSPHRASE: PASSPH}


def _run(tmp_path: Any, client: FakeClient, env: dict[str, str], out: list[str]) -> str:
    return lc.run_link(
        host="10.0.0.9",
        port=2101,
        env=env,
        client_factory=lambda: client,
        out=out.append,
        vault_root=tmp_path / "obsidian",
        serial_factory=lambda: SERIAL,
    )


def test_links_with_own_serial_writes_0600_and_reports_only_success(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    f = tmp_path / "tool-link.json"
    client = FakeClient()
    out: list[str] = []
    assert _run(tmp_path, client, _env(f), out) == SERIAL
    assert out == ["OK: link created"]
    assert all(x not in "".join(out) for x in (SERIAL, ACCESS, PASSPH, KEYS.linkkey_hex, str(f)))
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    data = json.loads(f.read_text())
    assert data == {
        "host": "10.0.0.9",
        "port": 2101,
        "own_link_sn": SERIAL,
        "link_keys": {
            "tempkey_hex": KEYS.tempkey_hex,
            "linkkey_hex": KEYS.linkkey_hex,
            "linkhmac_hex": KEYS.linkhmac_hex,
        },
        "protect": [],
    }
    assert client.link_calls[0]["client_identity"] == {"mn": "222", "sn": SERIAL}
    for secret in (ACCESS, PASSPH, KEYS.linkkey_hex, str(f), SERIAL):
        assert secret not in caplog.text


def test_mac_mismatch_aborts_before_link(tmp_path):
    f = tmp_path / "tool-link.json"
    client = FakeClient(mac="00:11:22:33:44:55")
    with pytest.raises(lr.AbortError, match="not the TEST panel"):
        _run(tmp_path, client, _env(f), [])
    assert client.link_calls == [] and not f.exists()


def test_refuses_to_overwrite(tmp_path):
    f = tmp_path / "tool-link.json"
    f.write_text("existing")
    client = FakeClient()
    with pytest.raises(lr.AbortError, match="already exists") as ei:
        _run(tmp_path, client, _env(f), [])
    assert f.read_text() == "existing" and client.link_calls == []
    assert str(f) not in str(ei.value)


def test_refuses_dangling_symlink(tmp_path):
    f = tmp_path / "tool-link.json"
    f.symlink_to(tmp_path / "elsewhere.json")
    with pytest.raises(lr.AbortError, match="already exists"):
        _run(tmp_path, FakeClient(), _env(f), [])


def test_refuses_git_repo_path(tmp_path):
    (tmp_path / "repo" / ".git").mkdir(parents=True)
    f = tmp_path / "repo" / "tool-link.json"
    client = FakeClient()
    with pytest.raises(lr.AbortError, match="git") as ei:
        _run(tmp_path, client, _env(f), [])
    assert client.link_calls == [] and not f.exists()
    assert str(tmp_path) not in str(ei.value)


def test_refuses_vault_path(tmp_path):
    (tmp_path / "obsidian" / "notes").mkdir(parents=True)
    f = tmp_path / "obsidian" / "notes" / "tool-link.json"
    client = FakeClient()
    with pytest.raises(lr.AbortError, match="vault"):
        _run(tmp_path, client, _env(f), [])
    assert client.link_calls == [] and not f.exists()


def test_codes_only_from_env_and_removed(tmp_path):
    f = tmp_path / "tool-link.json"
    env = {ENV_LINK_FILE: str(f)}
    with pytest.raises(lr.AbortError, match=lc.ENV_ACCESS_CODE):
        _run(tmp_path, FakeClient(), env, [])
    env = _env(f)
    _run(tmp_path, FakeClient(), env, [])
    assert lc.ENV_ACCESS_CODE not in env and lc.ENV_PASSPHRASE not in env


def test_cli_reports_only_success_and_has_no_code_options(tmp_path, monkeypatch, capsys):
    f = tmp_path / "tool-link.json"
    for k, v in _env(f).items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(lc, "VAULT_ROOT", tmp_path / "obsidian")
    monkeypatch.setattr(lc, "generate_serial", lambda: SERIAL)
    rc = lc.main(["--host", "10.0.0.9"], client_factory=FakeClient)
    captured = capsys.readouterr()
    assert rc == 0 and captured.out == "OK: link created\n"
    for secret in (SERIAL, ACCESS, PASSPH, KEYS.linkkey_hex, KEYS.tempkey_hex, str(f)):
        assert secret not in captured.out + captured.err
    opts = {o for a in lc.build_parser()._actions for o in a.option_strings}
    assert not any(x in o for o in opts for x in ("code", "pass", "key", "file"))


def test_generated_serial_is_12_digit_decimal_no_leading_zero():
    for _ in range(200):
        s = lc.generate_serial()
        assert len(s) == 12 and s.isdigit() and s[0] != "0"


def test_failure_output_has_no_serial_keys_code_or_path(tmp_path, monkeypatch, capsys):
    f = tmp_path / "tool-link.json"
    for k, v in _env(f).items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(lc, "VAULT_ROOT", tmp_path / "obsidian")
    monkeypatch.setattr(lc, "generate_serial", lambda: SERIAL)
    rc = lc.main(["--host", "10.0.0.9"], client_factory=lambda: FakeClient(mac="001122334455"))
    captured = capsys.readouterr()
    assert rc == 2 and captured.out == "" and captured.err.startswith("ABORT:")
    for secret in (SERIAL, ACCESS, PASSPH, KEYS.linkkey_hex, str(f)):
        assert secret not in captured.out + captured.err


def test_mac_mismatch_never_prints_or_logs_other_mac(tmp_path, monkeypatch, capsys, caplog):
    f = tmp_path / "tool-link.json"
    for k, v in _env(f).items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(lc, "VAULT_ROOT", tmp_path / "obsidian")
    caplog.set_level(logging.DEBUG)
    rc = lc.main(["--host", "10.0.0.9"], client_factory=lambda: FakeClient(mac="00:11:22:33:44:55"))
    captured = capsys.readouterr()
    assert rc == 2 and captured.err.strip() == "ABORT: panel is not the TEST panel"
    text = (captured.out + captured.err + caplog.text).lower()
    for form in ("001122334455", "00:11:22:33:44:55"):
        assert form not in text


# --- --protect at creation (Architect review 5558118767 blocker 1) ---------------
HA_LINK = "119112725266"


def _run_p(tmp_path: Any, client: Any, env: dict[str, str], out: list[str], protects, serial=None):
    return lc.run_link(
        host="10.0.0.9",
        port=2101,
        env=env,
        client_factory=lambda: client,
        out=out.append,
        vault_root=tmp_path / "obsidian",
        serial_factory=serial or (lambda: SERIAL),
        protects=protects,
    )


def test_protect_serials_written_at_creation_and_never_logged(tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    f = tmp_path / "tool-link.json"
    out: list[str] = []
    _run_p(tmp_path, FakeClient(), _env(f), out, [HA_LINK, "aabbccddeeff", HA_LINK])
    assert stat.S_IMODE(f.stat().st_mode) == 0o600
    assert json.loads(f.read_text())["protect"] == ["119112725266", "AABBCCDDEEFF"]
    assert out == ["OK: link created"]
    for secret in (HA_LINK, "AABBCCDDEEFF", str(f)):
        assert secret not in caplog.text and secret not in "".join(out)


@pytest.mark.parametrize("bad", ["12345", "ZZZZZZZZZZZZ", "", "1191127252661"])
def test_bad_protect_aborts_before_lock_or_panel(tmp_path, bad):
    from elk_test_tools.link_lock import lock_path_for

    f = tmp_path / "tool-link.json"
    client = FakeClient()
    env = _env(f)
    with pytest.raises(lr.AbortError, match="--protect") as ei:
        _run_p(tmp_path, client, env, [], [HA_LINK, bad])
    assert client.link_calls == [] and not f.exists()
    assert not lock_path_for(f).exists()
    assert bad not in str(ei.value) or not bad
    assert lc.ENV_ACCESS_CODE in env  # codes not even read


def test_protect_is_repeatable_on_the_cli(tmp_path, monkeypatch):
    f = tmp_path / "tool-link.json"
    monkeypatch.setattr(lc, "VAULT_ROOT", tmp_path / "obsidian")
    for k, v in _env(f).items():
        monkeypatch.setenv(k, v)
    monkeypatch.setattr(lc, "generate_serial", lambda: SERIAL)
    rc = lc.main(
        ["--host", "10.0.0.9", "--protect", HA_LINK, "--protect", "AABBCCDDEEFF"],
        client_factory=FakeClient,
    )
    assert rc == 0
    assert json.loads(f.read_text())["protect"] == [HA_LINK, "AABBCCDDEEFF"]


def test_serial_redrawn_if_it_collides_with_a_protected_serial(tmp_path):
    f = tmp_path / "tool-link.json"
    draws = iter([HA_LINK, SERIAL])
    client = FakeClient()
    assert _run_p(tmp_path, client, _env(f), [], [HA_LINK], serial=lambda: next(draws)) == SERIAL
    assert client.link_calls[0]["client_identity"]["sn"] == SERIAL


def test_real_client_async_link_accepts_the_arguments_used():
    """Pin the link call to the real elke27 signature (not just a fake)."""
    import inspect

    from elke27_lib import Elke27Client

    params = inspect.signature(Elke27Client.async_link).parameters
    assert {"access_code", "passphrase", "client_identity"} <= set(params)
    inspect.signature(Elke27Client.async_link).bind(
        None, "10.0.0.9", 2101, access_code="1", passphrase="p", client_identity={}
    )


def test_draw_serial_redraws_on_leading_zero_protect_match():
    from elk_test_tools import link_command as lc
    from elk_test_tools.link_removal import parse_serials

    draws = iter(["012345678904", "223456789012"])  # dummy serials
    protect = parse_serials([" 12345678904"], "--protect")
    assert lc._draw_serial(lambda: next(draws), protect) == "223456789012"


def test_link_file_stores_protect_serials_as_given(tmp_path):
    """Codex P2: leading zeros are stored as given, and the stored file re-parses."""
    from elk_test_tools.link_removal import protected_serials

    f = tmp_path / "tool-link.json"
    _run_p(tmp_path, FakeClient(), _env(f), [], [" 000012345678 ", "100271709"])  # dummies
    stored = json.loads(f.read_text())["protect"]
    assert stored == ["000012345678", "100271709"]
    assert protected_serials([], frozenset(stored)) == {"12345678", "100271709"}
