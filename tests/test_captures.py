"""``amt_captures``: the files the tools wrote, listed and handed back as one-time urls.

The listing reads two real temporary folders; a fetch goes through ``amt_handoff`` and the real HTTP
app, so the single-use claim is the route's own. Every refusal has a tripwire: it also asserts the
handoff directory stayed empty, so a refused name cannot have minted a url on the way out.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
from pathlib import Path
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

import amt_captures
import amt_handoff
import amt_mirror
import amt_serial
import amt_server

BASE = "https://amt.example.test"
SHOT = "amt-my-server-1-20261020T101500123456Z-0123456789abcdef.png"
SHOT_OLD = "amt-lab-20261019T101500123456Z-fedcba9876543210.png"
MP4 = "amt-my-server-1-20261020T102000Z.mp4"
CAST = "my-server-1-serial-20261020T103000.123456Z.cast"


@pytest.fixture
def shots() -> Path:
    return Path(os.environ["AMT_SHOT_DIR"])


@pytest.fixture
def recs(tmp_path, monkeypatch) -> Path:
    d = tmp_path / "recordings"
    d.mkdir()
    monkeypatch.setattr(amt_mirror, "recording_dir", lambda: d)
    return d


def _make(path: Path, body: bytes, age: float = 0.0) -> Path:
    path.write_bytes(body)
    stamp = time.time() - age
    os.utime(path, (stamp, stamp))
    return path


@pytest.fixture
def populated(shots, recs):
    _make(shots / SHOT_OLD, b"old-shot", age=5000)
    _make(shots / SHOT, b"new-shot", age=300)
    _make(recs / MP4, b"mp4-bytes", age=200)
    _make(recs / CAST, b"cast-bytes", age=100)
    return shots, recs


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, BASE)
    monkeypatch.setenv(amt_server.TRANSPORT_ENV, "http")
    return TestClient(amt_server.build_http_app(amt_server.mcp))


def _handoffs() -> list[str]:
    d = Path(os.environ["AMT_STATE_DIR"]) / "handoffs"
    return sorted(p.name for p in d.iterdir()) if d.exists() else []


def _names(out: dict) -> list[str]:
    return [c["name"] for c in out["captures"]]


# -- list ---------------------------------------------------------------------------------------

def test_list_names_every_kind_newest_first_with_device_and_the_folders_searched(populated):
    shots, recs = populated
    out = amt_captures.captures("list", None, 0, 50)
    assert _names(out) == [CAST, MP4, SHOT, SHOT_OLD]
    by_name = {c["name"]: c for c in out["captures"]}
    assert by_name[CAST]["kind"] == "serial_cast" and by_name[CAST]["device"] == "my-server-1"
    assert by_name[MP4]["kind"] == "recording" and by_name[MP4]["bytes"] == len(b"mp4-bytes")
    assert by_name[SHOT_OLD]["kind"] == "screenshot" and by_name[SHOT_OLD]["device"] == "lab"
    assert by_name[SHOT]["modified"].endswith("Z") and len(by_name[SHOT]["modified"]) == 20
    assert out["total"] == 4 and out["next_offset"] is None
    assert out["searched"] == [{"dir": str(shots), "kinds": ["screenshot"], "found": True},
                               {"dir": str(recs), "kinds": ["recording", "serial_cast"], "found": True}]
    assert all("path" not in c for c in out["captures"]), "a listing never names a path on the disk"


def test_list_pages_without_dropping_or_repeating(populated):
    first = amt_captures.captures("list", None, 0, 3)
    assert _names(first) == [CAST, MP4, SHOT] and first["next_offset"] == 3 and first["total"] == 4
    second = amt_captures.captures("list", None, first["next_offset"], 3)
    assert _names(second) == [SHOT_OLD] and second["next_offset"] is None
    assert _names(amt_captures.captures("list", None, 9, 3)) == []


def test_list_skips_what_is_not_a_finished_capture(populated, shots, recs, tmp_path):
    _make(shots / "notes.txt", b"x")
    _make(shots / "amt-my-server-1-20261020T101500123456Z-0123456789abcdef.png.part", b"x")
    _make(recs / "amt-my-server-1-20261020T110000Z.mjpeg", b"raw")
    _make(recs / "amt-my-server-1-20261020T110000Z.times", b"0")
    # An MP4 whose raw pair still exists is being encoded: not finished.
    _make(recs / "amt-my-server-1-20261020T110000Z.mp4", b"half")
    (recs / ".encode-abc").mkdir()
    outside = _make(tmp_path / "elsewhere.png", b"secret")
    (shots / "amt-my-server-1-20261020T120000123456Z-aaaaaaaaaaaaaaaa.png").symlink_to(outside)
    out = amt_captures.captures("list", None, 0, 50)
    assert _names(out) == [CAST, MP4, SHOT, SHOT_OLD]


def test_list_leaves_out_a_cast_a_live_terminal_is_still_writing(populated, recs, monkeypatch):
    term = SimpleNamespace(recording={"path": str(recs / CAST)})
    monkeypatch.setitem(amt_serial._TERMS, "my-server-1", term)
    assert CAST not in _names(amt_captures.captures("list", None, 0, 50))
    term.recording = None
    assert CAST in _names(amt_captures.captures("list", None, 0, 50))


def test_list_with_no_folders_reports_what_it_could_not_find(shots, recs):
    shots.rmdir()
    recs.rmdir()
    out = amt_captures.captures("list", None, 0, 50)
    assert out["total"] == 0 and out["captures"] == []
    assert [s["found"] for s in out["searched"]] == [False, False]


def test_a_symlinked_screenshot_directory_is_not_searched(tmp_path, monkeypatch, recs):
    real = tmp_path / "real"
    real.mkdir()
    _make(real / SHOT, b"x")
    link = tmp_path / "link"
    link.symlink_to(real)
    monkeypatch.setenv("AMT_SHOT_DIR", str(link))
    out = amt_captures.captures("list", None, 0, 50)
    assert out["total"] == 0 and out["searched"][0]["found"] is False


def test_a_symlinked_recordings_directory_is_searched(tmp_path, monkeypatch, shots):
    real = tmp_path / "real-recs"
    real.mkdir()
    _make(real / MP4, b"mp4-bytes")
    link = tmp_path / "recs-link"
    link.symlink_to(real)
    monkeypatch.setattr(amt_mirror, "recording_dir", lambda: link)
    out = amt_captures.captures("list", None, 0, 50)
    assert [c["name"] for c in out["captures"]] == [MP4] and out["searched"][1]["found"] is True


def test_unknown_action_is_refused():
    with pytest.raises(ValueError, match="unknown_captures_action"):
        amt_captures.captures("delete", None, 0, 50)


# -- fetch --------------------------------------------------------------------------------------

def test_fetch_returns_a_one_time_url_that_serves_the_file_once(populated, client):
    out = amt_captures.captures("fetch", MP4, 0, 50)
    assert out["name"] == MP4 and out["kind"] == "recording"
    assert out["sha256"] == hashlib.sha256(b"mp4-bytes").hexdigest() and out["expires_in_s"] == 900
    assert out["url"].startswith(BASE + "/handoffs/")
    got = client.get(out["url"][len(BASE):])       # no bearer: the token is the key
    assert got.status_code == 200 and got.content == b"mp4-bytes"
    assert client.get(out["url"][len(BASE):]).status_code == 404, "a fetched url is single use"
    assert (populated[1] / MP4).read_bytes() == b"mp4-bytes", "the original stays"
    assert _handoffs() == []


def test_each_fetch_mints_a_fresh_url(populated, client):
    a = amt_captures.captures("fetch", SHOT, 0, 50)["url"]
    b = amt_captures.captures("fetch", SHOT, 0, 50)["url"]
    assert a != b
    assert client.get(a[len(BASE):]).content == b"new-shot"
    assert client.get(b[len(BASE):]).content == b"new-shot", "the first url being used does not spend the second"


def test_fetch_without_a_public_base_url_names_the_path_instead(populated):
    out = amt_captures.captures("fetch", SHOT, 0, 50)
    assert "url" not in out and amt_handoff.BASE_URL_ENV in out["path_note"]
    assert out["path"] == str(populated[0] / SHOT)


@pytest.mark.parametrize("name", [
    "../" + SHOT, "/etc/passwd", "sub/" + SHOT, "..", ".", ".hidden.png", "a" * 300,
    SHOT + "/", "..\\" + SHOT, "%2e%2e/x.png", "x\x00.png", " " + SHOT])
def test_a_name_that_is_not_a_bare_listed_name_is_refused_and_mints_nothing(populated, client, name):
    with pytest.raises(ValueError, match="capture_name_invalid"):
        amt_captures.captures("fetch", name, 0, 50)
    assert _handoffs() == []


def test_a_well_formed_name_outside_the_listing_is_refused(populated, shots, recs, tmp_path, client):
    ghost = "amt-my-server-1-20260101T000000123456Z-0000000000000000.png"
    _make(recs / "readme.txt", b"x")
    outside = _make(tmp_path / "elsewhere.png", b"secret")
    link = "amt-my-server-1-20261020T120000123456Z-aaaaaaaaaaaaaaaa.png"
    (shots / link).symlink_to(outside)
    for name in (ghost, "readme.txt", link, "elsewhere.png"):
        with pytest.raises(ValueError, match="capture_not_found"):
            amt_captures.captures("fetch", name, 0, 50)
    assert _handoffs() == []


def test_fetch_needs_a_name(populated):
    for name in (None, ""):
        with pytest.raises(ValueError, match="capture_name_required"):
            amt_captures.captures("fetch", name, 0, 50)


def test_the_tool_is_read_only_titled_and_bounds_its_page_size():
    tool = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}["amt_captures"]
    assert tool.annotations.title == "AMT Captures" and tool.annotations.readOnlyHint is True
    assert "confirmed" not in tool.inputSchema["properties"]
    limit = tool.inputSchema["properties"]["limit"]
    assert (limit["minimum"], limit["maximum"]) == (1, amt_captures.MAX_LIMIT)
    assert tool.inputSchema["properties"]["offset"]["minimum"] == 0
    out = asyncio.run(amt_captures.amt_captures(action="list"))
    assert out["offset"] == 0 and "searched" in out
