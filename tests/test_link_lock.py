"""The link/remove lock: one run at a time, so no orphaned or raced panel links."""

from __future__ import annotations

import stat
import subprocess
import sys
import threading

import pytest

from elk_test_tools import link_removal as lr
from elk_test_tools.link_lock import exclusive_link_lock, lock_path_for
from tests.fake_panel import FakePanel
from tests.test_link_command import FakeClient, _env, _run

A = "246915998877"


def test_second_link_run_aborts_before_touching_the_panel(tmp_path):
    f = tmp_path / "tool-link.json"
    client = FakeClient()
    with exclusive_link_lock(f), pytest.raises(lr.AbortError, match="in progress") as ei:
        _run(tmp_path, client, _env(f), [])
    assert client.link_calls == [] and not f.exists()
    assert str(tmp_path) not in str(ei.value)


def test_concurrent_link_runs_provision_exactly_one_link(tmp_path):
    """Two runs racing: one links and saves its keys, the other aborts unlinked."""
    f = tmp_path / "tool-link.json"
    entered, release = threading.Event(), threading.Event()

    class SlowClient(FakeClient):
        async def async_link(self, host, port, **kw):  # type: ignore[no-untyped-def]
            entered.set()
            release.wait(5)
            return await super().async_link(host, port, **kw)

    first, second = SlowClient(), FakeClient()
    errors: list[BaseException] = []

    def run_first() -> None:
        try:
            _run(tmp_path, first, _env(f), [])
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    th = threading.Thread(target=run_first)
    th.start()
    assert entered.wait(5)
    with pytest.raises(lr.AbortError, match="in progress"):
        _run(tmp_path, second, _env(f), [])
    release.set()
    th.join(5)
    assert errors == []
    assert len(first.link_calls) == 1 and second.link_calls == []
    assert f.exists()


def test_lock_is_released_after_a_run(tmp_path):
    f = tmp_path / "tool-link.json"
    _run(tmp_path, FakeClient(), _env(f), [])
    with exclusive_link_lock(f):  # free again
        pass
    assert stat.S_IMODE(lock_path_for(f).stat().st_mode) == 0o600


def test_lock_held_by_another_process_blocks(tmp_path):
    f = tmp_path / "tool-link.json"
    holder = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import fcntl,os,sys,time;"
            "fd=os.open(sys.argv[1],os.O_RDWR|os.O_CREAT,0o600);"
            "fcntl.flock(fd,fcntl.LOCK_EX);print('locked',flush=True);time.sleep(30)",
            str(lock_path_for(f)),
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    try:
        assert holder.stdout is not None and holder.stdout.readline().strip() == "locked"
        client = FakeClient()
        with pytest.raises(lr.AbortError, match="in progress"):
            _run(tmp_path, client, _env(f), [])
        assert client.link_calls == []
    finally:
        holder.kill()
        holder.wait()


def test_remove_run_aborts_while_a_link_run_holds_the_lock(tmp_path, monkeypatch, capsys):
    f = tmp_path / "tool-link.json"
    monkeypatch.setenv("ELK_TEST_LINK_FILE", str(f))
    p = FakePanel()
    with exclusive_link_lock(f):
        rc = lr.main(["--remove", A, "--expect-name", "Old Link A"], transport=p)
    err = capsys.readouterr().err
    assert rc == 2 and "in progress" in err and str(tmp_path) not in err
    assert p.frames == []


def test_remove_run_holds_the_lock_against_a_link_run(tmp_path, monkeypatch):
    f = tmp_path / "tool-link.json"
    monkeypatch.setenv("ELK_TEST_LINK_FILE", str(f))
    seen: list[str] = []

    class LockProbePanel(FakePanel):
        def panel_mac(self) -> str:
            try:
                with exclusive_link_lock(f):
                    seen.append("free")
            except lr.AbortError:
                seen.append("held")
            return super().panel_mac()

    assert lr.main(["--remove", A, "--expect-name", "Old Link A"], transport=LockProbePanel()) == 0
    assert seen == ["held"]
