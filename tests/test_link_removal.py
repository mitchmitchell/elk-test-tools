from __future__ import annotations

import logging
from pathlib import Path

import pytest

from elk_test_tools import link_removal as lr
from tests.fake_panel import BASELINE_SN, HA_SN, OWN_SN, SECRET, TOUCH_SN, FakePanel

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
    protects=(BASELINE_SN,),
):
    return lr.run(
        transport=panel,
        removes=list(removes),
        expect_names=list(names),
        apply=apply,
        env={lr.ENV_INSTALLER_CODE: SECRET} if env is None else env,
        confirm=lambda _p: confirm,
        protects=list(protects),
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
    assert len(p.devices) == 6


def test_cli_dry_run_default(capsys, monkeypatch):
    monkeypatch.delenv(lr.ENV_INSTALLER_CODE, raising=False)
    p = FakePanel()
    assert (
        lr.main(
            ["--remove", A, "--expect-name", "Old Link A", "--protect", BASELINE_SN], transport=p
        )
        == 0
    )
    assert "DRY RUN" in capsys.readouterr().out and len(p.devices) == 6


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


@pytest.mark.parametrize("sn", [OWN_SN, OWN_SN.lower(), BASELINE_SN])
def test_protected_links_never_removed(sn):
    p = FakePanel()
    with pytest.raises(lr.AbortError, match="protected"):
        go(p, removes=(sn,), names=("x",), apply=True)
    assert "del_attribs" not in kinds(p) and len(p.devices) == 6


def test_protected_target_aborts_whole_run():
    p = FakePanel()
    with pytest.raises(lr.AbortError, match="protected"):
        go(p, removes=(A, OWN_SN), names=("Old Link A", "elk-test-tools"), apply=True)
    assert len(p.devices) == 6


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
    assert kinds(p).count("authenticate") == 1 and len(p.devices) == 6


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
    assert set(p.devices) == {1, 2, 5, 6}
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
        protects=[BASELINE_SN],
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


def test_live_transport_needs_own_link_file(monkeypatch):
    monkeypatch.delenv("ELK_TEST_LINK_FILE", raising=False)
    with pytest.raises(lr.AbortError, match="ELK_TEST_LINK_FILE"):
        lr.make_live_transport([BASELINE_SN])


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

        orig_auth = p.authenticate

        def leaky_auth(code):
            child.debug("authenticate pin=%s raw=%s", code, {"pin": int(code)})
            return orig_auth(code)

        p.request = leaky
        p.authenticate = leaky_auth
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
            "--protect",
            BASELINE_SN,
            "--apply",
            "--log-file",
            str(log),
        ],
        transport=p,
    )
    text = log.read_text()
    assert rc == 2 and f"sn={A} ok" in text and "ABORT" in text and SECRET not in text


def test_late_logger_and_leading_zero_redacted(caplog):
    lr.install_redaction()
    lr.REDACTOR.add_secret("0123")
    try:
        with caplog.at_level(logging.DEBUG):
            logging.getLogger("elke27_lib.created_late_xyz").debug("pin=%s raw=%s", 123, "0123")
        assert caplog.messages and all("123" not in m for m in caplog.messages)
    finally:
        lr.REDACTOR.clear()


def test_leading_zero_code_refused_before_authenticate():
    p = FakePanel()
    with pytest.raises(lr.AbortError, match="leading zero") as ei:
        go(p, apply=True, env={lr.ENV_INSTALLER_CODE: "0123"})
    assert "0123" not in str(ei.value)
    assert "authenticate" not in kinds(p) and len(p.devices) == 6


def test_armed_area_refused_before_authenticate():
    p = FakePanel()
    p.areas[2] = "ARMED_AWAY"
    with pytest.raises(lr.AbortError, match="DISARMED"):
        go(p, apply=True)
    assert "authenticate" not in kinds(p) and len(p.devices) == 6


# --- --protect (Mitch, Oct 16 2026 4:53 PM CT: --protect only, no built-ins) ----
def test_no_built_in_serials():
    assert lr.DEFAULT_PROTECTED_SNS == frozenset()


@pytest.mark.parametrize("bad", ["119112725266", [123], ["xyz"], [""], {"sn": 1}])
def test_parse_serials_rejects_malformed(bad):
    with pytest.raises(lr.AbortError):
        lr.parse_serials(bad, "protect")


def test_runs_without_any_protect_protecting_own_link():
    p = FakePanel()
    res = go(p, protects=(), apply=True)
    assert res.removed == [A]
    with pytest.raises(lr.AbortError, match="protected"):
        go(FakePanel(), removes=(OWN_SN,), names=("elk-test-tools",), protects=())


def test_cli_protect_is_optional(capsys):
    p = FakePanel()
    assert lr.main(["--remove", A, "--expect-name", "Old Link A"], transport=p) == 0
    assert "DRY RUN" in capsys.readouterr().out


def test_link_file_protect_array_is_honoured():
    p = FakePanel()
    p.file_protect = [BASELINE_SN]
    with pytest.raises(lr.AbortError, match="protected"):
        go(p, removes=(BASELINE_SN,), names=("HA TEST 0.2.0",), protects=(), apply=True)
    assert "del_attribs" not in kinds(p)


def test_cli_protect_adds_to_file_protect():
    p = FakePanel()
    p.file_protect = [BASELINE_SN]
    with pytest.raises(lr.AbortError, match="protected"):
        go(p, removes=(A,), names=("Old Link A",), protects=(A,))
    assert lr.protected_serials([A], frozenset({BASELINE_SN})) == {A, BASELINE_SN}


def test_only_exact_remove_serials_are_removed():
    p = FakePanel()
    res = go(p, removes=(B,), names=("Old Link B",), protects=(), apply=True)
    assert res.removed == [B] and set(p.devices) == {1, 2, 3, 5, 6}


def test_repeated_protect_all_apply():
    p = FakePanel()
    for sn in (A, B):
        with pytest.raises(lr.AbortError, match="protected"):
            go(p, removes=(sn,), names=("x",), protects=(BASELINE_SN, A, B))
    assert lr.protected_serials([BASELINE_SN, A.lower(), B]) == {BASELINE_SN, A, B}


@pytest.mark.parametrize("bad", ["", "xyz", "1234567890", "1234567890123", "11911272526G"])
def test_bad_protect_serial_refused(bad):
    p = FakePanel()
    with pytest.raises(lr.AbortError, match="--protect"):
        go(p, protects=(BASELINE_SN, bad))
    assert p.frames == []


def test_unprotected_link_is_removable_only_if_named():
    # No built-in serials: an HA link is removable when named and not --protect'ed.
    p = FakePanel()
    res = go(p, removes=(HA_SN,), names=("HA TEST",), apply=True)
    assert res.removed == [HA_SN]


# --- touch screens: hard-blocked by type (get_list mn) ----------------------------
def test_touch_screen_target_refused():
    p = FakePanel()
    with pytest.raises(lr.AbortError, match="touch screen"):
        go(p, removes=(TOUCH_SN,), names=("Frnt Door Tblt",), apply=True)
    assert "del_attribs" not in kinds(p) and len(p.devices) == 6


@pytest.mark.parametrize("mn", [None, "", "999", "100"])
def test_unknown_or_missing_type_is_protected(mn):
    p = FakePanel()
    if mn is None:
        p.devices[3].pop("mn")
    else:
        p.devices[3]["mn"] = mn
    with pytest.raises(lr.AbortError, match="touch screen"):
        go(p, apply=True)  # target A sits in slot 3
    assert "del_attribs" not in kinds(p)


def test_dry_run_lists_touch_screen_as_protected():
    p = FakePanel()
    lines: list[str] = []
    go(p, out=lines.append)
    row = next(line for line in lines[0].splitlines() if lr.canonical_sn(TOUCH_SN) in line)
    assert "PROTECT" in row and "[touch screen]" in row


def test_touch_screen_reason_classification():
    assert lr.Slot(1, A, "x", "222").touch_screen_reason is None
    assert lr.Slot(1, A, "x", " 100").touch_screen_reason == "touch screen"
    assert lr.Slot(1, A, "x", None).touch_screen_reason == "touch screen (type unknown)"


def test_list_shape_also_parsed():
    reply = {"list": [{"net_dev_id": 4, "name": "n", "mn": "222"}, {"net_dev_id": 5, "name": ""}]}
    assert lr._list_entries(reply) == [(4, "n", "222")]


def test_protected_link_absent_before_does_not_fail_verify():
    p = FakePanel()
    del p.devices[5]  # --protect'ed baseline not on the panel
    res = go(p, apply=True)
    assert res.removed == [A]


def test_wrong_mac_cli_never_prints_or_logs_other_mac(tmp_path, capsys, caplog):
    caplog.set_level(logging.DEBUG)
    log = tmp_path / "log.md"
    p = FakePanel(mac="00:11:22:33:44:55")
    rc = lr.main(
        ["--remove", A, "--expect-name", "Old Link A", "--log-file", str(log)], transport=p
    )
    captured = capsys.readouterr()
    assert rc != 0 and "panel is not the TEST panel" in captured.err
    text = captured.out + captured.err + caplog.text + (log.read_text() if log.exists() else "")
    for form in ("001122334455", "00:11:22:33:44:55"):
        assert form not in text.lower()


def test_own_link_missing_from_panel_refuses():
    p = FakePanel()
    p.devices.pop(2)  # the tool's own link
    with pytest.raises(lr.AbortError, match="own link is not on this panel"):
        go(p)


# --- own link serial never printed or logged (Architect should-fix, #2) ----------
def test_own_link_serial_shown_as_label_in_table_and_log(tmp_path):
    lines: list[str] = []
    res = go(FakePanel(), out=lines.append)
    text = "\n".join(lines)
    assert OWN_SN not in text and "(own link)" in text
    log_file = tmp_path / "log.md"
    lr.append_log(log_file, lr.TEST_PANEL_MAC, res)
    logged = log_file.read_text()
    assert OWN_SN not in logged and "(own link)" in logged
    assert A in logged  # other serials are still listed


def test_own_link_serial_hidden_after_apply(tmp_path):
    lines: list[str] = []
    res = go(FakePanel(), apply=True, out=lines.append)
    assert res.applied
    assert OWN_SN not in "\n".join(lines)


# --- serial normalization (leading zero / leading space) -------------------------
# Dummy serials only. The panel lists a 12-digit serial that starts with 0 as 11
# digits with a leading space; both sides must compare equal.
LZ_SN = "012345678901"  # as recorded by the tool
LZ_PANEL = " 12345678901"  # as the panel lists it


@pytest.mark.parametrize(
    "raw", ["012345678901", " 12345678901", "12345678901", " 0123 4567 8901\t", "\t12345678901 "]
)
def test_canonical_sn_equates_leading_zero_and_space_forms(raw):
    assert lr.canonical_sn(raw) == "12345678901"


def test_canonical_sn_rejects_malformed_and_keeps_hex():
    assert lr.canonical_sn("0aabbccddeef") == "AABBCCDDEEF"
    for bad in ("", "   ", "12-345", "1234567890123", "11911272526G", None, 12345678901):
        assert lr.canonical_sn(bad) is None
    assert lr.canonical_sn("1234567890", min_len=lr.USER_SN_MIN_LEN) is None
    assert lr.panel_sn("0100" + LZ_SN) == "12345678901"
    assert lr.panel_sn("0100" + LZ_PANEL) == "12345678901"


def _lz_panel(name="Leading Zero Link"):
    p = FakePanel()
    p.devices[7] = {"sn": LZ_PANEL, "name": name, "mn": "222"}
    return p


@pytest.mark.parametrize("given", [LZ_SN, LZ_PANEL, "12345678901"])
def test_dry_run_matches_leading_zero_target(given):
    p = _lz_panel()
    lines: list[str] = []
    res = go(p, removes=(given,), names=("Leading Zero Link",), out=lines.append)
    assert res.actions == ["dry-run"]
    row = next(line for line in lines[0].splitlines() if "Leading Zero Link" in line)
    assert "DELETE" in row


def test_apply_removes_leading_zero_target():
    p = _lz_panel()
    res = go(p, removes=(LZ_SN,), names=("Leading Zero Link",), apply=True)
    assert res.removed == ["12345678901"]
    assert 7 not in p.devices


@pytest.mark.parametrize("protect", [LZ_SN, LZ_PANEL])
def test_protect_matches_leading_zero_link(protect):
    p = _lz_panel()
    with pytest.raises(lr.AbortError, match="protected"):
        go(p, removes=(LZ_SN,), names=("Leading Zero Link",), protects=(BASELINE_SN, protect))


def test_file_protect_matches_leading_zero_link():
    p = _lz_panel()
    p.file_protect = [LZ_SN]
    with pytest.raises(lr.AbortError, match="protected"):
        go(p, removes=(LZ_PANEL,), names=("Leading Zero Link",))


def test_own_link_with_leading_zero_is_found_and_hard_blocked(monkeypatch):
    p = FakePanel()
    p.devices[2] = {"sn": "0100" + LZ_PANEL, "name": "elk-test-tools", "mn": "222"}
    monkeypatch.setattr(p, "own_link_sn", lambda: LZ_SN)
    # The tool's own link is located on the panel despite the format difference...
    res = go(p)
    assert res.actions == ["dry-run"]
    # ...and can never be targeted, in either form.
    for given in (LZ_SN, LZ_PANEL):
        with pytest.raises(lr.AbortError, match="protected"):
            go(p, removes=(given,), names=("elk-test-tools",))


def test_touch_screen_with_leading_zero_still_blocked_by_type():
    p = FakePanel()
    p.devices[7] = {"sn": LZ_PANEL, "name": "Kitchen Keypad", "mn": "100"}
    with pytest.raises(lr.AbortError, match="touch screen"):
        go(p, removes=(LZ_SN,), names=("Kitchen Keypad",), apply=True)
    assert 7 in p.devices


def test_panel_line_with_mn_prefix_keeps_serial():
    # Exact TEST-panel Network Devices line from Tester (TEST panel link serial).
    assert lr.panel_sn("222: 16685521139") == "16685521139"
    assert lr.panel_sn("222: 16685521139") == lr.canonical_sn("016685521139")
    assert lr.panel_sn("222:016685521139") == "16685521139"
    assert lr.panel_sn("222:") == ""


def test_dry_run_matches_mn_prefixed_panel_serial():
    p = FakePanel()
    p.devices[7] = {"sn": "222: 16685521139", "name": "Tester Link", "mn": "222"}
    lines: list[str] = []
    res = go(p, removes=("016685521139",), names=("Tester Link",), out=lines.append)
    assert res.actions == ["dry-run"]
    assert lr.DEFAULT_PROTECTED_SNS == frozenset()  # protection only via --protect
