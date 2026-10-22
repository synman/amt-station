"""amt_images: set_root (persisted), list and background fetch of the IDE-R image root."""
import asyncio
import functools
import hashlib
import http.server
import threading
import time

import pytest

import amt_tools
import amt_write

PAYLOAD = b"\x01" * 4096


@pytest.fixture
def web(tmp_path):
    served = tmp_path / "web"
    served.mkdir()
    (served / "boot.iso").write_bytes(PAYLOAD)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=str(served))
    handler.log_message = lambda *a, **k: None
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_port}"
    srv.shutdown()


def _wait(name, timeout=10):
    end = time.time() + timeout
    while time.time() < end:
        jobs = {f["name"]: f for f in amt_write.ider_list()["fetches"]}
        if jobs.get(name, {}).get("state") not in (None, "running"):
            return jobs[name]
        time.sleep(0.05)
    raise AssertionError("fetch did not finish")


def test_set_root_creates_persists_and_wins_over_the_env(tmp_path, monkeypatch):
    monkeypatch.setenv(amt_write.IMAGE_ROOT_ENV, str(tmp_path / "env-root"))
    out = amt_write.ider_set_root(str(tmp_path / "tool-root"))
    assert out["previous_source"] == "env" and (tmp_path / "tool-root").is_dir()
    assert amt_write._image_root() == (tmp_path / "tool-root").resolve()
    assert '"image_root"' in amt_write._settings_path().read_text()   # survives a restart


def test_list_shows_images_and_whether_each_can_mount(tmp_path):
    root = tmp_path / "imgs"
    amt_write.ider_set_root(str(root))
    (root / "good.iso").write_bytes(b"\x00" * 2048)
    (root / "odd.img").write_bytes(b"\x00" * 100)
    (root / "notes.txt").write_text("x")
    out = amt_write.ider_list()
    got = {i["path"]: i["mountable"] for i in out["images"]}
    assert got == {"good.iso": True, "odd.img": False} and out["source"] == "tool"


def test_list_without_a_root_reports_why_instead_of_failing(monkeypatch):
    monkeypatch.delenv(amt_write.IMAGE_ROOT_ENV, raising=False)
    out = amt_write.ider_list()
    assert out["images"] == [] and "ider_image_root_unset" in out["error"]


def test_fetch_downloads_verifies_and_lands_in_the_root(tmp_path, web):
    amt_write.ider_set_root(str(tmp_path / "imgs"))
    want = hashlib.sha256(PAYLOAD).hexdigest()
    started = amt_write.ider_fetch(f"{web}/boot.iso", sha256=want)
    assert started["state"] == "running"
    job = _wait("boot.iso")
    assert job["state"] == "done" and job["sha256"] == want and job["bytes"] == len(PAYLOAD)
    assert (tmp_path / "imgs" / "boot.iso").read_bytes() == PAYLOAD
    assert {i["path"] for i in amt_write.ider_list()["images"]} == {"boot.iso"}


def test_fetch_sha_mismatch_deletes_the_download(tmp_path, web):
    amt_write.ider_set_root(str(tmp_path / "imgs"))
    amt_write.ider_fetch(f"{web}/boot.iso", name="bad.iso", sha256="0" * 64)
    job = _wait("bad.iso")
    assert job["state"] == "failed" and "sha256_mismatch" in job["error"]
    assert list((tmp_path / "imgs").iterdir()) == []          # no file, no .part


@pytest.mark.parametrize("kw,err", [
    ({"url": "ftp://x/a.iso"}, "http_or_https"),
    ({"url": "https://x/a.exe"}, "plain_.iso_or_.img"),
    ({"url": "https://x/a.iso", "name": "../a.iso"}, "plain_.iso_or_.img"),
    ({"url": "https://x/a.iso", "sha256": "abc"}, "64_hex"),
])
def test_fetch_rejects_bad_requests(tmp_path, kw, err):
    amt_write.ider_set_root(str(tmp_path / "imgs"))
    with pytest.raises(ValueError, match=err):
        amt_write.ider_fetch(**kw)


def test_fetch_will_not_clobber_without_overwrite(tmp_path):
    root = tmp_path / "imgs"
    amt_write.ider_set_root(str(root))
    (root / "a.iso").write_bytes(b"\x00" * 512)
    with pytest.raises(ValueError, match="ider_fetch_exists"):
        amt_write.ider_fetch("https://x/a.iso")


def test_corrupt_settings_are_reported_not_ignored():
    path = amt_write._settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("{not json")
    with pytest.raises(ValueError, match="amt_settings_file_unreadable"):
        amt_write._image_root()


@pytest.mark.parametrize("kw", [{"action": "set_root", "root": "/tmp/x"},
                                {"action": "fetch", "url": "https://x/a.iso"}])
def test_set_root_and_fetch_refuse_without_confirmed(kw, tmp_path):
    with pytest.raises(amt_tools.ConfirmationRequired):
        asyncio.run(amt_write.amt_images(**kw))
    assert not amt_write._settings_path().exists()


def test_list_needs_no_confirmation(tmp_path):
    amt_write.ider_set_root(str(tmp_path / "imgs"))
    assert asyncio.run(amt_write.amt_images(action="list"))["source"] == "tool"
