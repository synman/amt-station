"""The capture store (immutable 11): a one-time url is fetched exactly once by the backend, verified against the
tool's sha256, and served from the console's own route; the browser never sees the url or its token."""
import hashlib
import json
import os
import time

import pytest

import captures

PNG = b"\x89PNG\r\n\x1a\n" + b"console-capture-bytes" * 50


def shot(console, fake, data=PNG, name="shot-1.png", **kw):
    fake.results["amt_screenshot"] = lambda a: fake.offer(data, name, **kw)
    return console.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": "my-server-1"}})


def token_of(fake):
    return next(iter(fake.fetches))


def test_a_screenshot_is_fetched_once_verified_and_served_from_the_console(signed_in, fake_amt):
    r = shot(signed_in, fake_amt)
    cap = r.json()["structured"]["capture"]
    assert cap["status"] == "ready" and cap["sha256"] == hashlib.sha256(PNG).hexdigest() and cap["bytes"] == len(PNG)
    assert list(fake_amt.fetches.values()) == [1]                       # fetched exactly once
    got = signed_in.get(f"/captures/{cap['id']}")
    assert got.status == 200 and got.data == PNG
    assert got.headers["Content-Type"] == "image/png" and got.headers["Content-Disposition"] == "attachment; filename*=UTF-8''shot-1.png"
    assert got.headers["X-Content-Type-Options"] == "nosniff"
    assert [c["id"] for c in signed_in.get("/api/captures").json()["captures"]] == [cap["id"]]


def test_the_browser_never_sees_the_url_or_its_token(signed_in, fake_amt):
    r = shot(signed_in, fake_amt)
    token = token_of(fake_amt)
    everything = r.text + signed_in.get("/api/captures").text
    assert "handoffs/" not in everything and token not in everything and fake_amt.base not in everything
    assert "url" not in r.json()["structured"] and "url_note" not in r.json()["structured"]
    assert captures.mask_one_time_urls(f"fetch {fake_amt.base}/handoffs/{token} now") == "fetch [one-time url withheld] now"


def test_the_handoff_request_carries_no_bearer(signed_in, fake_amt):
    shot(signed_in, fake_amt)
    gets = [h for method, _, h in fake_amt.requests if method == "GET"]
    assert len(gets) == 1 and "Authorization" not in gets[0]


def test_the_same_result_is_not_fetched_twice(signed_in, fake_amt):
    first = shot(signed_in, fake_amt).json()["structured"]["capture"]
    # the tool returns the SAME one-time link again (a retried call): the store answers from its record
    result = fake_amt.offer(PNG, "shot-1.png", token=token_of(fake_amt))
    fake_amt.results["amt_screenshot"] = lambda a: result
    second = signed_in.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": "my-server-1"}}).json()["structured"]["capture"]
    assert second["id"] == first["id"] and list(fake_amt.fetches.values()) == [1]


def test_a_link_that_is_gone_is_shown_as_expired_never_missing(signed_in, fake_amt):
    fake_amt.results["amt_screenshot"] = lambda a: {**fake_amt.offer(PNG, "late.png"), "url": f"{fake_amt.base}/handoffs/{'Z' * 43}"}
    cap = signed_in.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": "x"}}).json()["structured"]["capture"]
    assert cap["status"] == "expired" and cap["reason"] == "not fetched within 15 minutes"
    assert [c["status"] for c in signed_in.get("/api/captures").json()["captures"]] == ["expired"]   # listed, not absent
    assert signed_in.get(f"/captures/{cap['id']}").status == 404                                    # but there is nothing to save


def test_a_body_that_does_not_match_the_tools_sha256_is_not_kept(signed_in, fake_amt, tmp_path):
    fake_amt.results["amt_screenshot"] = lambda a: {**fake_amt.offer(PNG, "bad.png"), "sha256": hashlib.sha256(b"other").hexdigest()}
    cap = signed_in.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": "x"}}).json()["structured"]["capture"]
    assert (cap["status"], cap["reason"]) == ("failed", "sha256_mismatch")
    assert not list((signed_in.data / "captures").glob("*.bin"))         # the body is deleted
    assert signed_in.get(f"/captures/{cap['id']}").status == 404


@pytest.mark.parametrize("url", [
    "http://evil.example.test/handoffs/" + "A" * 43,                     # another host
    "http://127.0.0.1:1/handoffs/" + "A" * 43,                           # another port
    "https://{base}/handoffs/" + "A" * 43,                               # another scheme
    "{base_url}/handoffs/" + "A" * 43 + "?x=1",                          # a query
    "http://user:pw@{base}/handoffs/" + "A" * 43,
    "{base_url}/handoffs/" + "A" * 43 + "#frag",                       # a fragment
    "{base_url}/prefix/handoffs/" + "A" * 43,                          # a handoff path that is not at the root
    "{base_url}/handoffs/" + "A" * 43 + "/extra",                      # and one with a tail
])
def test_only_amt_mcps_own_handoffs_are_fetched(signed_in, fake_amt, url):
    url = url.replace("{base_url}", fake_amt.base).replace("{base}", fake_amt.base.split("//")[1])
    fake_amt.results["amt_screenshot"] = lambda a: {"url": url, "sha256": "0" * 64, "path": "/x/a.png"}
    r = signed_in.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": "x"}})
    structured = r.json()["structured"]
    assert structured["capture"]["status"] == "failed" and structured["capture"]["reason"] == "handoff_url_not_from_amt_mcp"
    assert [m for m, _, _ in fake_amt.requests if m == "GET"] == []


@pytest.mark.parametrize("path", ["/other/" + "A" * 43, "/handoffs/../mcp", "/handoffs/short"])
def test_a_url_that_is_not_on_a_handoff_path_is_not_a_handoff_at_all(signed_in, fake_amt, path):
    fake_amt.results["amt_screenshot"] = lambda a: {"url": fake_amt.base + path, "sha256": "0" * 64}
    structured = signed_in.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": "x"}}).json()["structured"]
    assert "capture" not in structured and [m for m, _, _ in fake_amt.requests if m == "GET"] == []


def test_a_result_that_is_not_a_handoff_passes_through_untouched(signed_in, fake_amt):
    fake_amt.results["amt_status"] = lambda a: {"power": "on", "url": "https://amt-viewer.example.test/m/abc/", "sha256": "x"}
    r = signed_in.post("/api/call", {"tool": "amt_status", "arguments": {"device": "x"}})
    assert r.json()["structured"]["url"] == "https://amt-viewer.example.test/m/abc/" and "capture" not in r.json()["structured"]


def test_captures_are_deleted_after_the_retention(tmp_path, fake_amt):
    clock = [1000.0]
    store = captures.CaptureStore(tmp_path / "caps", fake_amt.base, retention_hours=24, now=lambda: clock[0])
    rec = store.ingest(fake_amt.offer(PNG, "old.png"))
    assert rec["status"] == "ready" and store.get(rec["id"]) is not None
    clock[0] += 24 * 3600 - 1
    assert [c["id"] for c in store.list()] == [rec["id"]]
    clock[0] += 2
    assert store.list() == [] and store.get(rec["id"]) is None
    assert os.listdir(tmp_path / "caps") == []                           # the record and the file are both gone


def test_retention_defaults_to_24_hours_and_files_are_private(signed_in, fake_amt):
    assert signed_in.app.captures.retention == 24 * 3600
    cap = shot(signed_in, fake_amt).json()["structured"]["capture"]
    path = signed_in.data / "captures" / f"{cap['id']}.bin"
    assert oct(path.stat().st_mode & 0o777) == "0o600" and oct(path.parent.stat().st_mode & 0o777) == "0o700"


@pytest.mark.parametrize("cid", ["../server", "..%2fserver", "a" * 21, "a" * 23, "a" * 22 + "/x", "%00" + "a" * 20])
def test_a_capture_id_is_looked_up_never_joined_onto_a_path(signed_in, cid):
    assert signed_in.get(f"/captures/{cid}").status == 404


def test_capture_list_is_newest_first_and_hides_the_url_hash(signed_in, fake_amt):
    ids = []
    for i in range(3):
        data = PNG + bytes([i])
        fake_amt.results["amt_screenshot"] = lambda a, d=data, i=i: fake_amt.offer(d, f"s{i}.png")
        ids.append(signed_in.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": "x"}}).json()["structured"]["capture"]["id"])
        time.sleep(1.05)                                                 # taken_at is whole seconds
    listed = signed_in.get("/api/captures").json()["captures"]
    assert [c["id"] for c in listed] == ids[::-1] and all("urlhash" not in c for c in listed)


def test_a_capture_name_is_cut_to_a_plain_file_name(signed_in, fake_amt):
    fake_amt.results["amt_screenshot"] = lambda a: {**fake_amt.offer(PNG, "x.png"), "path": "/data/../../etc/we ird\r\nSet-Cookie: a=b\".png"}
    cap = signed_in.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": "x"}}).json()["structured"]["capture"]
    assert cap["name"].startswith("we ird")                              # the path in front of the file name is gone
    assert "/" not in cap["name"] and "\r" not in cap["name"] and "\n" not in cap["name"] and '"' not in cap["name"]
    got = signed_in.get(f"/captures/{cap['id']}")
    assert got.status == 200 and "\r" not in got.headers["Content-Disposition"] and "Set-Cookie" not in got.headers


def test_a_capture_id_with_a_path_in_it_finds_nothing_outside_the_store(tmp_path, fake_amt):
    store = captures.CaptureStore(tmp_path / "caps", fake_amt.base)
    (tmp_path / "planted.json").write_text('{"id": "planted", "status": "ready", "name": "x.png", "taken_at": 4102444800}')
    (tmp_path / "planted.bin").write_bytes(b"outside the store")
    assert store.get("../planted") is None and store.get("..") is None and store.get("") is None


def test_a_body_over_the_size_cap_is_not_kept(tmp_path, fake_amt, monkeypatch):
    monkeypatch.setattr(captures, "MAX_BYTES", 1000)
    store = captures.CaptureStore(tmp_path / "caps", fake_amt.base)
    rec = store.ingest(fake_amt.offer(b"x" * 5000, "big.png"))
    assert (rec["status"], rec["reason"]) == ("failed", "too_large")
    assert not list((tmp_path / "caps").glob("*.bin"))


# -- every other one-time url is withheld too (immutables 11, 12 and 21) --------------------------------------------------

VIEW, CTRL, SERIAL, UPLOAD, INTAKE = ("V" * 32, "C" * 32, "S" * 32, "U" * 43, "I" * 43)


def mirror_result(a):
    return {"device": "my-server-1", "live": True,
            "urls": [f"https://amt-viewer.example.test/m/{VIEW}/", f"http://127.0.0.1:8123/m/{VIEW}/"],
            "control_urls": [f"https://amt-viewer.example.test/m/{CTRL}/", f"http://127.0.0.1:8123/m/{CTRL}/"],
            "note": f"watch at https://amt-viewer.example.test/m/{VIEW}/ now"}


@pytest.mark.parametrize("tool,args,result,tokens", [
    ("amt_mirror_link", {"device": "my-server-1", "action": "start", "confirmed": True}, mirror_result, [VIEW, CTRL]),
    ("amt_serial_link", {"device": "my-server-1", "action": "status"},
     lambda a: {"urls": [f"https://amt-viewer.example.test/s/{SERIAL}/"], "control_urls": [f"http://10.0.0.9:8123/s/{CTRL}/"]}, [SERIAL, CTRL]),
    ("amt_images", {"action": "upload", "name": "a.iso", "confirmed": True},
     lambda a: {"name": "a.iso", "url": "https://amt.example.test/uploads/" + UPLOAD, "method": "PUT", "url_note": "send the raw file once"}, [UPLOAD]),
    ("amt_identity_manage", {"action": "intake", "name": "n", "confirmed": True},
     lambda a: {"name": "n", "url": "https://amt.example.test/intake/" + INTAKE, "method": "PUT"}, [INTAKE]),
])
def test_a_viewer_upload_or_intake_token_never_reaches_the_browser(signed_in, fake_amt, tool, args, result, tokens):
    fake_amt.results[tool] = result
    raw = json.dumps(result(args))
    assert all(t in raw for t in tokens)                                  # positive control: the tool did send them
    r = signed_in.post("/api/call", {"tool": tool, "arguments": args})
    assert r.status == 200
    for t in tokens:
        assert t not in r.text, t                                         # neither in `text` nor in `structured`
    assert "[one-time url withheld]" in r.json()["text"] and "[one-time url withheld]" in json.dumps(r.json()["structured"])


def test_masking_covers_every_one_time_route_and_leaves_other_text_alone():
    for route, token in (("handoffs", "H" * 43), ("uploads", "U" * 43), ("intake", "I" * 43), ("m", "V" * 32), ("s", "S" * 32)):
        assert captures.mask_one_time_urls(f"go https://front.example.test/{route}/{token}/ ok") == "go [one-time url withheld] ok", route
        assert captures.mask_one_time_urls(f"path /{route}/{token}") == "path [one-time url withheld]", route
    for text in ("https://amt-viewer.example.test/m/abc/", "https://x.example.test/uploads/short", "https://x.example.test/other/" + "A" * 43,
                 "https://x.example.test/images/ubuntu.iso", "plain text"):
        assert captures.mask_one_time_urls(text) == text
