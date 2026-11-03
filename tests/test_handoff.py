"""Download handoffs (``amt_handoff``): a file a tool wrote, fetched once over HTTP.

Every fetch goes through the real HTTP app ``amt_server.build_http_app`` builds, so the tests
prove the route is mounted, reachable without the bearer, and outside the Host allowlist's
reach only where intended. A tripwire on the claim step proves the route ran its single-fetch
path rather than a fixture supplying the 404.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import amt_handoff
import amt_server

BASE = "https://nas.example.com:8443"


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, BASE)
    monkeypatch.setenv(amt_server.TRANSPORT_ENV, "http")
    return TestClient(amt_server.build_http_app(amt_server.mcp))


@pytest.fixture
def made(tmp_path):
    f = tmp_path / "amt-my-server-1-shot.png"
    f.write_bytes(b"\x89PNG\r\n\x1a\n" + os.urandom(2048))
    return f


def _path_of(url: str) -> str:
    assert url.startswith(BASE + "/handoffs/")
    return url[len(BASE):]


def test_no_base_url_offers_nothing_and_says_why(monkeypatch, made):
    monkeypatch.delenv(amt_handoff.BASE_URL_ENV, raising=False)
    assert amt_handoff.offer(made) == {}
    out = amt_handoff.describe(made)
    assert set(out) == {"path_note"} and amt_handoff.BASE_URL_ENV in out["path_note"]


@pytest.mark.parametrize("bad", ["nas.example.com", "ftp://x", "https://x/sub", " "])
def test_a_base_url_that_is_not_scheme_and_host_is_ignored(monkeypatch, made, bad):
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, bad)
    assert amt_handoff.offer(made) == {}


def test_first_get_returns_the_file_unauthenticated_then_404(client, made, monkeypatch):
    claims = []
    real_rename = os.rename
    monkeypatch.setattr(amt_handoff.os, "rename", lambda a, b: (claims.append(b), real_rename(a, b)))
    out = amt_handoff.offer(made)
    assert out["expires_in_s"] == amt_handoff.TTL_SECONDS
    assert out["sha256"] == hashlib.sha256(made.read_bytes()).hexdigest()
    r = client.get(_path_of(out["url"]))          # no Authorization header
    assert r.status_code == 200 and r.content == made.read_bytes()
    assert hashlib.sha256(r.content).hexdigest() == out["sha256"]
    assert r.headers["cache-control"] == "no-store"
    assert made.name in r.headers["content-disposition"]
    assert len(claims) == 1, "the route must claim the handoff atomically"
    again = client.get(_path_of(out["url"]))
    assert again.status_code == 404
    assert made.exists(), "a fetch deletes the handoff link, never the tool's own file"
    left = list((Path(os.environ["AMT_STATE_DIR"]) / "handoffs").iterdir())
    assert left == [], left


def test_an_expired_handoff_is_404_and_removed(client, made, monkeypatch):
    out = amt_handoff.offer(made)
    d = Path(os.environ["AMT_STATE_DIR"]) / "handoffs"
    (meta,) = d.glob("*.json")
    m = json.loads(meta.read_text())
    meta.write_text(json.dumps({**m, "expires": time.time() - 1}))
    assert client.get(_path_of(out["url"])).status_code == 404
    assert list(d.iterdir()) == []


def test_unfetched_expired_handoffs_are_reaped_on_the_next_offer(made, monkeypatch):
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, BASE)
    amt_handoff.offer(made)
    d = Path(os.environ["AMT_STATE_DIR"]) / "handoffs"
    (meta,) = d.glob("*.json")
    meta.write_text(json.dumps({**json.loads(meta.read_text()), "expires": 0}))
    amt_handoff.offer(made)
    assert len(list(d.glob("*.json"))) == 1 and len([p for p in d.iterdir() if p.suffix != ".json"]) == 1


@pytest.mark.parametrize("token", ["short", "a" * 44, "..%2F..%2Fetc%2Fpasswd", "A" * 42 + "."])
def test_malformed_or_unknown_tokens_are_404(client, token):
    assert client.get(f"/handoffs/{token}").status_code == 404
    assert client.get("/handoffs/" + "A" * 43).status_code == 404


def test_the_handoff_directory_must_be_private(monkeypatch, made, tmp_path):
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, BASE)
    state = tmp_path / "state"
    state.mkdir()
    (state / "handoffs").symlink_to(tmp_path)
    monkeypatch.setenv(amt_handoff.STATE_DIR_ENV, str(state))
    with pytest.raises(PermissionError, match="handoff_dir_unsafe"):
        amt_handoff.offer(made)


def test_handoffs_are_created_private(made, monkeypatch):
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, BASE)
    amt_handoff.offer(made)
    d = Path(os.environ["AMT_STATE_DIR"]) / "handoffs"
    assert d.stat().st_mode & 0o777 == 0o700
    for p in d.iterdir():
        assert p.stat().st_mode & 0o077 == 0, p


def test_a_name_that_is_not_a_token_cannot_touch_the_store(client, made):
    """The token pattern is the only thing standing between a crafted name and the store's own
    files: without it, GET .../<token>.json would claim and destroy the metadata and kill the
    real handoff. An unknown well-formed token is 404 by a second mechanism (no such file), so
    the malformed-token cases above stay green with the pattern removed; this one does not."""
    out = amt_handoff.offer(made)
    path = _path_of(out["url"])
    assert client.get(path + ".json").status_code == 404
    r = client.get(path)
    assert r.status_code == 200 and r.content == made.read_bytes()
