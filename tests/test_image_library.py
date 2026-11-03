"""amt_images library actions: verify, rename, delete and the one-time upload url.

Uploads go through the real HTTP app ``amt_server.build_http_app`` builds, so the tests prove
the route is mounted and reachable without the bearer. A mount is faked by a live ``_Mount``
whose media holds an open descriptor on the image, which is exactly what ``_busy_reason`` reads.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import threading
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import amt_handoff
import amt_redir
import amt_server
import amt_tools
import amt_upload
import amt_write

BASE = "https://nas.example.com:8443"
BODY = os.urandom(4096)


@pytest.fixture
def root(tmp_path):
    r = tmp_path / "iso"
    amt_write.ider_set_root(str(r))
    (r / "a.iso").write_bytes(BODY)
    amt_upload._OFFERS.clear()
    amt_upload._RESULTS.clear()
    return r


@pytest.fixture
def client(monkeypatch, root):
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, BASE)
    monkeypatch.setenv(amt_server.TRANSPORT_ENV, "http")
    return TestClient(amt_server.build_http_app(amt_server.mcp))


@pytest.fixture
def mounted(root):
    """A live mount holding a.iso open, as _ider_mount leaves it."""
    fd = os.open(root / "a.iso", os.O_RDONLY)
    stop = threading.Event()
    mount = amt_write._Mount(session=None, images={"iso": "a.iso"}, media=[amt_redir.Media(len(BODY), fd)])
    mount.thread = threading.Thread(target=stop.wait, daemon=True)
    mount.thread.start()
    amt_write._MOUNTS["my-server-1"] = mount
    yield mount
    stop.set()
    amt_write._MOUNTS.pop("my-server-1", None)
    os.close(fd)


def _path(url):
    return url.removeprefix(BASE)


# -- verify, rename, delete ------------------------------------------------------------------

def test_verify_hashes_and_compares_without_confirmation(root):
    want = hashlib.sha256(BODY).hexdigest()
    out = asyncio.run(amt_write.amt_images(action="verify", path="a.iso", sha256=want.upper()))
    assert out["sha256"] == want and out["matches"] is True and out["mountable"] is True
    assert amt_write.ider_verify("a.iso", "0" * 64)["matches"] is False
    assert amt_write.ider_verify("a.iso")["matches"] is None


def test_rename_moves_within_the_folder_and_never_clobbers(root):
    (root / "b.iso").write_bytes(b"x" * 512)
    with pytest.raises(ValueError, match="ider_rename_target_exists:b.iso"):
        amt_write.ider_rename("a.iso", "b.iso")
    assert (root / "b.iso").read_bytes() == b"x" * 512
    out = amt_write.ider_rename("a.iso", "c.iso")
    assert out == {"renamed": "a.iso", "to": "c.iso"}
    assert not (root / "a.iso").exists() and (root / "c.iso").read_bytes() == BODY


def test_delete_removes_one_image(root):
    assert amt_write.ider_delete("a.iso") == {"deleted": "a.iso", "bytes": len(BODY)}
    assert not (root / "a.iso").exists()


@pytest.mark.parametrize("path,err", [("../a.iso", "relative_to_the_image_root"),
                                      ("/etc/passwd", "relative_to_the_image_root"),
                                      ("nope.iso", "ider_image_not_found"),
                                      ("notes.txt", "not_a_regular_.iso_or_.img")])
def test_paths_must_be_images_inside_the_root(root, path, err):
    (root / "notes.txt").write_text("x")
    with pytest.raises(ValueError, match=err):
        amt_write.ider_delete(path)


def test_a_symlink_is_never_followed_out_of_the_root(root, tmp_path):
    outside = tmp_path / "outside.iso"
    outside.write_bytes(BODY)
    (root / "link.iso").symlink_to(outside)
    with pytest.raises(ValueError, match="not_a_regular"):
        amt_write.ider_delete("link.iso")
    assert outside.exists()


@pytest.mark.parametrize("bad", ["x/y.iso", ".hidden.iso", "a.exe", "", None])
def test_rename_needs_a_plain_image_name(root, bad):
    with pytest.raises(ValueError, match="ider_rename_name_must_be"):
        amt_write.ider_rename("a.iso", bad)


def test_a_mounted_image_cannot_be_renamed_deleted_or_overwritten(root, mounted, client):
    for call in (lambda: amt_write.ider_delete("a.iso"), lambda: amt_write.ider_rename("a.iso", "z.iso"),
                 lambda: amt_write.ider_upload("a.iso", len(BODY), overwrite=True)):
        with pytest.raises(ValueError, match="busy:a.iso:mounted_on:my-server-1"):
            call()
    assert (root / "a.iso").read_bytes() == BODY


@pytest.mark.parametrize("kw", [{"action": "rename", "path": "a.iso", "new_name": "b.iso"},
                                {"action": "delete", "path": "a.iso"},
                                {"action": "upload", "name": "n.iso", "size_bytes": 512}])
def test_writes_refuse_without_confirmed(root, kw):
    with pytest.raises(amt_tools.ConfirmationRequired):
        asyncio.run(amt_write.amt_images(**kw))
    assert sorted(p.name for p in root.iterdir()) == ["a.iso"]
    assert not amt_upload._OFFERS


# -- upload ----------------------------------------------------------------------------------

def test_upload_lands_once_and_is_reported(root, client):
    want = hashlib.sha256(BODY).hexdigest()
    out = asyncio.run(amt_write.amt_images(action="upload", name="new.iso", size_bytes=len(BODY),
                                           sha256=want, confirmed=True))
    assert out["url"].startswith(BASE + "/uploads/") and out["method"] == "PUT"
    listed = amt_write.ider_list()["uploads"]["open"]
    assert listed == [{"name": "new.iso", "state": "waiting", "bytes": 0, "size_bytes": len(BODY),
                       "sha256_expected": want}]
    assert not any(out["url"].rsplit("/", 1)[1] in str(v) for v in listed), "list never shows a token"
    r = client.put(_path(out["url"]), content=BODY)
    assert r.status_code == 201 and r.json() == {"name": "new.iso", "bytes": len(BODY), "sha256": want}
    assert (root / "new.iso").read_bytes() == BODY
    assert client.put(_path(out["url"]), content=BODY).status_code == 404, "single use"
    lib = amt_write.ider_list()
    assert lib["uploads"]["open"] == [] and lib["uploads"]["finished"][0]["state"] == "done"
    assert "new.iso" in {i["path"] for i in lib["images"]}
    assert not [p for p in root.iterdir() if p.name.startswith(".")], "no part file left"


@pytest.mark.parametrize("body,sha,err", [
    (lambda: iter([BODY[:-1]]), None, "body_shorter"),          # chunked: no Content-Length
    (lambda: iter([BODY, b"x"]), None, "body_larger"),
    (lambda: BODY + b"x", None, "content_length_not_declared_size"),
    (lambda: BODY, "0" * 64, "sha256_mismatch")])
def test_a_bad_upload_leaves_nothing(root, client, body, sha, err):
    out = amt_write.ider_upload("new.iso", len(BODY), sha)
    r = client.put(_path(out["url"]), content=body())
    assert r.status_code == 400 and err in r.text
    assert not (root / "new.iso").exists()
    assert not [p for p in root.iterdir() if p.name.startswith(".")]
    assert amt_write.ider_list()["uploads"]["finished"][0]["state"] == "failed"


def test_upload_refusals(root, client, monkeypatch):
    with pytest.raises(ValueError, match="ider_upload_exists:a.iso"):
        amt_write.ider_upload("a.iso", 512)
    with pytest.raises(ValueError, match="ider_upload_needs_size_bytes"):
        amt_write.ider_upload("n.iso", 0)
    monkeypatch.setenv(amt_upload.MAX_BYTES_ENV, "1024")
    with pytest.raises(ValueError, match="ider_upload_too_large"):
        amt_write.ider_upload("n.iso", 2048)
    amt_write.ider_upload("n.iso", 512)
    with pytest.raises(ValueError, match="ider_upload_image_busy:n.iso:being_uploaded"):
        amt_write.ider_upload("n.iso", 512)
    monkeypatch.delenv(amt_handoff.BASE_URL_ENV)
    with pytest.raises(ValueError, match="ider_upload_needs_AMT_PUBLIC_BASE_URL"):
        amt_write.ider_upload("m.iso", 512)


def test_an_open_upload_blocks_rename_onto_it_and_an_expired_one_is_404(root, client, monkeypatch):
    out = amt_write.ider_upload("n.iso", len(BODY))
    with pytest.raises(ValueError, match="ider_rename_image_busy:n.iso:being_uploaded"):
        amt_write.ider_rename("a.iso", "n.iso")
    assert (root / "a.iso").exists() and not (root / "n.iso").exists()
    for o in amt_upload._OFFERS.values():
        o.expires = 0
    assert client.put(_path(out["url"]), content=BODY).status_code == 404
    assert not (root / "n.iso").exists()


def test_a_malformed_token_is_404(client):
    assert client.put("/uploads/short", content=b"x").status_code == 404


def test_fetch_overwrite_of_an_idle_image_starts_and_a_mounted_one_is_refused(root, mounted, client):
    """The overwrite path checks busy without holding _FETCHES_LOCK (it once deadlocked here)."""
    (root / "b.iso").write_bytes(BODY)
    done = []
    t = threading.Thread(target=lambda: done.append(
        amt_write.ider_fetch("http://127.0.0.1:9/b.iso", overwrite=True)), daemon=True)
    t.start()
    t.join(5)
    assert done and done[0]["name"] == "b.iso", "fetch overwrite hung or failed"
    with pytest.raises(ValueError, match="ider_fetch_image_busy:a.iso:mounted_on:my-server-1"):
        amt_write.ider_fetch("http://127.0.0.1:9/a.iso", overwrite=True)
    amt_write.ider_list()                 # the library still answers
