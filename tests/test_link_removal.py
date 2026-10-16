from __future__ import annotations

import logging
from pathlib import Path

import pytest

from elk_test_tools import link_removal as lr
from tests.fake_panel import HA_SN, OWN_SN, SECRET, FakePanel

A, B = "246915998877", "727007405425"


class NoTouchEnv(dict):
    def pop(self, *a, **k):
        raise AssertionError("dry-run must not read the installer code")

    def get(self, *a, **k):
        raise AssertionError("dry-run must not read the installer code")

    __getitem__ = get


def go(
    panel,
    removes=(A,),
    names=("Old Link A",),
    apply=False,
    env=None,
    confirm="cc031eb03b20",
    out=None,
):
    return lr.run(
        transport=panel,
        removes=list(removes),
        expect_names=list(names),
        apply=apply,
        env={lr.ENV_INSTALLER_CODE: SECRET} if env is None else env,
        confirm=lambda _p: confirm,
        out=out or (lambda _s: None),
    )


def kinds(panel):
    out = []
    for f in panel.frames:
        out.append("authenticate" if "authenticate" in f else next(iter(f["net_dev"])))
    return out


def test_dry_run_is_default_and_never_reads_code():
    p = FakePanel()
    res = go(p, env=NoTouchEnv())
    assert not res.applied and res.actions == ["dry-run"]
    assert "del_attribs" not in kinds(p) and "authenticate" not in kinds(p)
    assert len(p.devices) == 4


def test_cli_dry_run_default(capsys, monkeypatch):
    monkeypatch.delenv(lr.ENV_INSTALLER_CODE, raising=False)
    p = FakePanel()
    assert lr.main(["--remove", A, "--expect-name", "Old Link A"], transport=p) == 0
    assert "DRY RUN" in capsys.readouterr().out and len(p.devices) == 4


def test_wrong_mac_refuses_before_anything():
    p = FakePanel(mac="00:11:22:33:44:55")
    with pytest.raises(lr.AbortError, match="not the TEST panel"):
        go(p, apply=True)
    assert p.frames == []


def test_expect_name_mismatch_refuses():
    p = FakePanel()
    with pytest.raises(lr.AbortError, match="expect-name"):
        go(p, names=("HA TEST",), apply=True)
    assert "authenticate" not in kinds(p)


def test_expect_name_required_per_target():
    with pytest.raises(lr.AbortError, match="matching --expect-name"):
        go(FakePanel(), removes=(A, B), names=("Old Link A",))


@pytest.mark.parametrize("sn", [HA_SN, HA_SN.lower(), OWN_SN])
def test_protected_links_never_removed(sn):
    p = FakePanel()
    with pytest.raises(lr.AbortError, match="protected"):
        go(p, removes=(sn,), names=("x",), apply=True)
    assert "del_attribs" not in kinds(p) and len(p.devices) == 4


def test_protected_target_aborts_whole_run():
    p = FakePanel()
    with pytest.raises(lr.AbortError, match="protected"):
        go(p, removes=(A, OWN_SN), names=("Old Link A", "elk-test-tools"), apply=True)
    assert len(p.devices) == 4


@pytest.mark.parametrize("bad", ["all", "*", "ALL", "24691599887", "24691599887Z", ""])
def test_no_wildcard_or_all(bad):
    with pytest.raises(lr.AbortError):
        go(FakePanel(), removes=(bad,), names=("x",))


def test_no_remove_all_option_and_no_default_frame():
    with pytest.raises(SystemExit):
        lr.build_parser().parse_args(["--all"])
    opts = {o for a in lr.build_parser()._actions for o in a.option_strings}
    assert not any("all" in o or "default" in o for o in opts)
    src = Path(lr.__file__).read_text()
    assert '"default"' not in src


def test_max_targets():
    sns = [f"{i:012X}" for i in range(1, 8)]
    with pytest.raises(lr.AbortError, match="at most"):
        go(FakePanel(), removes=sns, names=["n"] * 7)


def test_apply_without_code_aborts_before_connect():
    p = FakePanel()
    with pytest.raises(lr.AbortError, match="not set"):
        go(p, apply=True, env={})
    assert not p.connected and p.frames == []


def test_apply_requires_typed_mac():
    p = FakePanel()
    with pytest.raises(lr.AbortError, match="confirmation"):
        go(p, apply=True, confirm="nope")
    assert "authenticate" not in kinds(p)


def test_armed_area_aborts_before_auth():
    p = FakePanel()
    p.areas[2] = "ARMED_AWAY"
    with pytest.raises(lr.AbortError, match="DISARMED"):
        go(p, apply=True)
    assert "authenticate" not in kinds(p)


def test_bad_auth_single_attempt():
    p = FakePanel()
    p.installer_ok = False
    with pytest.raises(lr.AbortError, match="not retrying"):
        go(p, apply=True)
    assert kinds(p).count("authenticate") == 1 and len(p.devices) == 4


def test_slot_reuse_detected_before_delete():
    p = FakePanel()
    seen = []

    def hook(i):
        seen.append(i)
        if i == 3 and seen.count(3) == 2:
            p.devices[3] = {"sn": "0100" + "111111111111", "name": "Other"}

    p.on_get_attribs = hook
    with pytest.raises(lr.AbortError, match="no longer holds"):
        go(p, apply=True)
    assert "del_attribs" not in kinds(p)
    assert kinds(p)[-1] == "logout"


def test_apply_removes_verifies_and_reports_session():
    p = FakePanel()
    lines = []
    res = go(p, removes=(A, B), names=("Old Link A", "Old Link B"), apply=True, out=lines.append)
    assert res.applied and res.removed == [A, B]
    assert set(p.devices) == {1, 2}
    assert res.sessions == {A: "dropped (fake panel)", B: "dropped (fake panel)"}
    assert any("session after delete" in s for s in lines)
    k = kinds(p)
    assert k.count("authenticate") == 1 and k[-1] == "logout"
    assert "logout ok" in res.actions
    assert k.index("authenticate") < k.index("del_attribs")
    auth = [f for f in p.frames if "authenticate" in f]
    dels = [f for f in p.frames if "del_attribs" in f.get("net_dev", {})]
    assert all("pin" not in str(f) for f in dels) and len(auth) == 1


def test_reauth_after_idle():
    p = FakePanel()
    t = iter([0.0, 0.0, 0.0, 100.0, 100.0, 100.0, 100.0])
    lr.run(
        transport=p,
        removes=[A, B],
        expect_names=["Old Link A", "Old Link B"],
        apply=True,
        env={lr.ENV_INSTALLER_CODE: SECRET},
        confirm=lambda _: "cc031eb03b20",
        out=lambda _s: None,
        clock=lambda: next(t),
    )
    assert kinds(p).count("authenticate") == 2


def test_installer_code_never_logged_printed_or_stored(tmp_path, caplog, capsys):
    caplog.set_level(logging.DEBUG)
    env = {lr.ENV_INSTALLER_CODE: SECRET}
    p = FakePanel()
    res = go(p, apply=True, env=env, out=print)
    log_file = tmp_path / "log.md"
    lr.append_log(log_file, lr.TEST_PANEL_MAC, res)
    # Something that tries to log the secret is redacted.
    lr.REDACTOR.add_secret(SECRET)
    logging.getLogger("elke27_lib").debug("frame %s", {"authenticate": {"pin": SECRET}})
    logging.getLogger("elk_test_tools").debug("raw " + SECRET)
    lr.REDACTOR.clear()
    cap = capsys.readouterr()
    blob = cap.out + cap.err + caplog.text + log_file.read_text() + repr(res)
    assert SECRET not in blob
    assert lr.ENV_INSTALLER_CODE not in env  # popped: not inherited by children


def test_secret_not_in_abort_message():
    p = FakePanel()
    p.installer_ok = False
    with pytest.raises(lr.AbortError) as ei:
        go(p, apply=True, env={lr.ENV_INSTALLER_CODE: SECRET})
    assert SECRET not in str(ei.value)
    with pytest.raises(lr.AbortError) as ei:
        go(FakePanel(), apply=True, env={lr.ENV_INSTALLER_CODE: "12ab"})
    assert "12ab" not in str(ei.value)


def test_cli_never_has_pin_argument():
    opts = {o for a in lr.build_parser()._actions for o in a.option_strings}
    assert not any(x in o for o in opts for x in ("pin", "code", "passph"))


def test_live_transport_not_wired():
    with pytest.raises(lr.AbortError, match="pass-through"):
        lr.make_live_transport()


def test_child_logger_with_own_handler_is_redacted():
    import io

    buf = io.StringIO()
    child = logging.getLogger("elke27_lib.transport.test")
    h = logging.StreamHandler(buf)
    child.addHandler(h)
    child.setLevel(logging.DEBUG)
    child.propagate = False
    try:
        p = FakePanel()
        orig = p.request

        def leaky(payload):
            child.debug("tx %s raw=%s", payload, str(payload))
            return orig(payload)

        p.request = leaky
        go(p, apply=True)
    finally:
        child.removeHandler(h)
    assert "authenticate" in buf.getvalue() and SECRET not in buf.getvalue()


def test_logout_sent_even_if_verify_inventory_fails():
    p = FakePanel()
    orig = p.request
    calls = {"n": 0}

    def flaky(payload):
        if "get_list" in payload.get("net_dev", {}):
            calls["n"] += 1
            if calls["n"] == 2:
                return {"net_dev": {"get_list": {"error_code": 9}}}
        return orig(payload)

    p.request = flaky
    with pytest.raises(lr.AbortError):
        go(p, apply=True)
    assert kinds(p)[-1] == "logout" and not p.authed


def test_logout_rejection_is_reported():
    p = FakePanel()
    orig = p.request

    def bad_logout(payload):
        if "logout" in payload.get("net_dev", {}):
            p.frames.append(payload)
            return {"net_dev": {"logout": {"error_code": 3}}}
        return orig(payload)

    p.request = bad_logout
    with pytest.raises(lr.AbortError, match="logout"):
        go(p, apply=True)


def test_partial_deletion_is_logged_on_abort(tmp_path, monkeypatch):
    monkeypatch.setenv(lr.ENV_INSTALLER_CODE, SECRET)
    monkeypatch.setattr("builtins.input", lambda _p: "cc031eb03b20")
    p = FakePanel()
    orig = p.request

    def fail_second(payload):
        nd = payload.get("net_dev", {})
        if "del_attribs" in nd and nd["del_attribs"]["net_dev_id"] == 4:
            p.frames.append(payload)
            return {"net_dev": {"del_attribs": {"error_code": 8}}}
        return orig(payload)

    p.request = fail_second
    log = tmp_path / "log.md"
    rc = lr.main(
        [
            "--remove",
            A,
            "--expect-name",
            "Old Link A",
            "--remove",
            B,
            "--expect-name",
            "Old Link B",
            "--apply",
            "--log-file",
            str(log),
        ],
        transport=p,
    )
    text = log.read_text()
    assert rc == 2 and f"sn={A} ok" in text and "ABORT" in text and SECRET not in text
