"""The Media tab and the Images section (packet C5): mounts with the start-mode predicate, unmount with the still-held state, the
library with fetch progress, the upload through the console to the one-time url, verify, rename, delete with the hold, busy
refusals, set root and the no-root refusal.

Every amt-mcp answer is scripted (console_fakes.FakeAmt). Where it matters the scripted answer IS amt-mcp's own code: the
library tool runs the real ``amt_write.ider_*`` functions against a temp image root and the one-time PUT lands in the real
``amt_upload.receive`` (so a size or hash refusal and the part file's removal are amt-mcp's, not this file's). Nothing here
reaches a host, the NAS or any 198.51.100.x address, and no mount is ever made on a real host.
Immutables 4, 5 (mount `now`, delete), 9 (no token in a response or a log) and 19 (coverage), plus the backend rules the page rests on."""
import asyncio
import json
import logging
import os
import socket
import threading
import time
from http.client import HTTPConnection

import pytest

import amt_handoff
import amt_redir
import amt_upload
import amt_write
import images
from console_fakes import BEARER, Authenticator, Console, check_mockups, enroll_first_passkey
from test_console_fleet import KEY, STATUS, device, tool_error, fc, me, settle, calls  # noqa: F401 - fixtures
from test_console_fleet_browser import open_page, text

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed: the browser immutables are NOT checked")

BODY = os.urandom(4096)


def sha(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()


# -- amt-mcp's own library code behind the fake ---------------------------------------------------------------------------------

class RealImages:
    """amt_images answered by the real ``amt_write.ider_*`` functions (fetch is scripted: no network), and the one-time PUT by the real
    ``amt_upload.receive``. ``minted`` keeps every upload result the way the tool returned it, url and all."""

    def __init__(self, fake, root, monkeypatch, tmp_path):
        monkeypatch.setenv(amt_write.STATE_DIR_ENV, str(tmp_path / "amt-state"))
        monkeypatch.setenv(amt_handoff.BASE_URL_ENV, fake.base)
        monkeypatch.delenv(amt_write.IMAGE_ROOT_ENV, raising=False)
        amt_upload._OFFERS.clear(); amt_upload._RESULTS.clear(); amt_write._FETCHES.clear()
        self.root, self.fake, self.minted = root, fake, []
        amt_write.ider_set_root(str(root))
        fake.results["amt_images"] = self.tool
        fake.put_handler = self.put

    def tool(self, a):
        try:
            act = a["action"]
            if act == "list":
                return amt_write.ider_list()
            if act == "verify":
                return amt_write.ider_verify(a.get("path"), a.get("sha256"))
            if act == "set_root":
                return amt_write.ider_set_root(a.get("root") or "")
            if act == "upload":
                out = amt_write.ider_upload(a.get("name"), a.get("size_bytes"), a.get("sha256"), a.get("overwrite", False))
                self.minted.append(out)
                return out
            if act == "rename":
                return amt_write.ider_rename(a.get("path"), a.get("new_name"))
            if act == "delete":
                return amt_write.ider_delete(a.get("path"))
        except ValueError as ex:
            return tool_error(f"Error executing tool amt_images: {ex}")
        raise AssertionError(f"unscripted action {a}")

    @staticmethod
    def put(path, headers, body):
        """The body as it arrived (maybe short, if the sender stopped) handed to amt-mcp's real receive with the headers it was sent."""
        from starlette.requests import Request
        scope = {"type": "http", "method": "PUT", "path": path, "query_string": b"", "path_params": {"token": path.rsplit("/", 1)[-1]},
                 "headers": [(b"content-length", headers["Content-Length"].encode())]}
        sent = []

        async def receive():
            if sent:
                return {"type": "http.disconnect"}
            sent.append(1)
            return {"type": "http.request", "body": body, "more_body": False}
        resp = asyncio.run(amt_upload.receive(Request(scope, receive)))
        return resp.status_code, resp.body, resp.media_type or "text/plain"

    def mount(self, name, key="my-server-1"):
        """A live mount holding ``name`` open, as _ider_mount leaves it: what the tool's busy check reads."""
        fd = os.open(self.root / name, os.O_RDONLY)
        stop = threading.Event()
        mount = amt_write._Mount(session=None, images={"iso": name}, media=[amt_redir.Media((self.root / name).stat().st_size, fd)])
        mount.thread = threading.Thread(target=stop.wait, daemon=True)
        mount.thread.start()
        amt_write._MOUNTS[key] = mount
        self.undo = lambda: (stop.set(), amt_write._MOUNTS.pop(key, None), os.close(fd))

    def cleanup(self):
        getattr(self, "undo", lambda: None)()
        amt_upload._OFFERS.clear(); amt_upload._RESULTS.clear(); amt_write._FETCHES.clear()


@pytest.fixture()
def amt(tmp_path, fake_amt, monkeypatch):
    root = tmp_path / "iso"
    real = RealImages(fake_amt, root, monkeypatch, tmp_path)
    (root / "a.iso").write_bytes(BODY)
    yield real
    real.cleanup()


def upload_call(name="new.iso", size=len(BODY), extra=None):
    return {"tool": "amt_images", "arguments": {"action": "upload", "name": name, "size_bytes": size, "confirmed": True, **(extra or {})}}


def mint(me, name="new.iso", size=len(BODY), extra=None):
    reply = me.post("/api/call", upload_call(name, size, extra))
    assert reply.status == 200, reply.text
    return reply


def stream(me, uid, data, *, length=None, ctype="application/octet-stream", headers=None, **kw):
    head = {"Content-Type": ctype, "Content-Length": str(len(data) if length is None else length), **(headers or {})}
    return me.request("POST", f"/api/images/upload/{uid}", raw=data, headers=head, **kw)


def stream_short(me, uid, declared, sent):
    """The browser stops after ``len(sent)`` of ``declared`` bytes: it closes its sending side and still reads the answer."""
    conn = HTTPConnection("127.0.0.1", me.port, timeout=15)
    conn.putrequest("POST", f"/api/images/upload/{uid}")
    for k, v in {"Host": f"{me.host}:{me.port}", "Origin": me.origin, "Cookie": f"amt_console_session={me.cookie}", "X-CSRF-Token": me.csrf,
                 "Content-Type": "application/octet-stream", "Content-Length": str(declared)}.items():
        conn.putheader(k, v)
    conn.endheaders()
    conn.send(sent)
    conn.sock.shutdown(socket.SHUT_WR)
    resp = conn.getresponse()
    out = (resp.status, json.loads(resp.read() or b"{}"))
    conn.close()
    return out


def wait_for(fn, what, seconds=8):
    end = time.time() + seconds
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


def token_of(amt):
    return amt.minted[-1]["url"].rsplit("/", 1)[1]


# -- the minting: the url stays in the console ---------------------------------------------------------------------------------

def test_a_minted_upload_reaches_the_browser_as_an_id_never_as_a_url(me, fake_amt, amt):
    reply = mint(me)
    s = reply.json()["structured"]
    token = token_of(amt)
    assert token and token not in reply.text and "/uploads/" not in reply.text.replace("[one-time url withheld]", "")
    assert set(s) >= {"upload_id", "name", "size_bytes", "expires_in_s"} and s["name"] == "new.iso" and s["size_bytes"] == len(BODY)
    assert len(s["upload_id"]) == 22 and s["upload_id"] != token and "url" in s and s["url"] == "[one-time url withheld]"
    assert [(t, a) for t, a, _ in fake_amt.calls] == [("amt_images", {"action": "upload", "name": "new.iso", "size_bytes": len(BODY), "confirmed": True})]
    assert fake_amt.calls[0][2] == f"Bearer {BEARER}"


@pytest.mark.parametrize("url", [
    "https://amt.example.test/uploads/" + "A" * 43,                    # another origin
    "FAKE/uploads/" + "A" * 42,                                        # a token one character short
    "FAKE/uploads/" + "A" * 43 + "?x=1", "FAKE/uploads/" + "A" * 43 + "#f", "FAKE/other/" + "A" * 43, "FAKE/uploads/" + "A" * 43 + "/more",
    "ftp://127.0.0.1/uploads/" + "A" * 43, "not a url", None, 7])
def test_a_url_that_is_not_amt_mcps_own_one_time_upload_is_never_kept(me, fake_amt, url):
    if isinstance(url, str):
        url = url.replace("FAKE", fake_amt.base)
    fake_amt.results["amt_images"] = lambda a: {"name": "n.iso", "size_bytes": 512, "url": url, "method": "PUT", "expires_in_s": 900}
    s = me.post("/api/call", upload_call("n.iso", 512)).json()["structured"]
    assert "upload_id" not in s and s["upload_refused"] in ("upload_url_not_from_amt_mcp", "upload_result_unreadable")
    assert me.app.uploads._offers == {}                                 # nothing is waiting for a file


@pytest.mark.parametrize("result", [
    {"name": "n.iso", "url": "FAKE/uploads/" + "A" * 43},                                       # no size
    {"name": "n.iso", "size_bytes": 0, "url": "FAKE/uploads/" + "A" * 43},
    {"name": "n.iso", "size_bytes": True, "url": "FAKE/uploads/" + "A" * 43},                   # a boolean is not a size
    {"name": "n.iso", "size_bytes": "512", "url": "FAKE/uploads/" + "A" * 43},
    {"size_bytes": 512, "url": "FAKE/uploads/" + "A" * 43},                                     # no name
    {"name": 7, "size_bytes": 512, "url": "FAKE/uploads/" + "A" * 43}])
def test_an_upload_result_that_does_not_say_its_name_and_size_is_never_kept(me, fake_amt, result):
    fake_amt.results["amt_images"] = lambda a: {**result, "url": result["url"].replace("FAKE", fake_amt.base)}
    s = me.post("/api/call", upload_call("n.iso", 512)).json()["structured"]
    assert "upload_id" not in s and s["upload_refused"] == "upload_result_unreadable" and me.app.uploads._offers == {}


def test_a_url_with_userinfo_or_another_port_is_not_amt_mcps_origin(me, fake_amt):
    host = fake_amt.base.split("//")[1]
    for bad in (f"http://u:p@{host}/uploads/" + "A" * 43, f"http://127.0.0.1:{fake_amt.port + 1}/uploads/" + "A" * 43):
        fake_amt.results["amt_images"] = lambda a, bad=bad: {"name": "n.iso", "size_bytes": 512, "url": bad}
        assert me.post("/api/call", upload_call("n.iso", 512)).json()["structured"]["upload_refused"] == "upload_url_not_from_amt_mcp"


def test_a_refused_mint_is_the_tools_own_text_with_no_offer_kept(me, fake_amt, amt):
    (amt.root / "taken.iso").write_bytes(BODY)
    reply = me.post("/api/call", upload_call("taken.iso")).json()
    assert reply["isError"] and "ider_upload_exists:taken.iso" in reply["text"] and "upload_id" not in json.dumps(reply)
    assert me.app.uploads._offers == {}


# -- the stream: the browser's bytes go to the url, the answer comes back verbatim ---------------------------------------------------

def test_an_upload_streams_through_to_the_image_root_and_amt_mcp_records_it(me, fake_amt, amt):
    uid = mint(me).json()["structured"]["upload_id"]
    reply = stream(me, uid, BODY)
    assert reply.status == 200 and reply.json() == {"ok": True, "name": "new.iso", "bytes": len(BODY), "sha256": sha(BODY)}
    assert (amt.root / "new.iso").read_bytes() == BODY and not list(amt.root.glob(".*.upload"))
    assert fake_amt.puts == [(f"/uploads/{token_of(amt)}", len(BODY), len(BODY))]
    listed = me.post("/api/call", {"tool": "amt_images", "arguments": {"action": "list"}}).json()["structured"]
    assert listed["uploads"]["open"] == [] and listed["uploads"]["finished"][0]["state"] == "done" and listed["uploads"]["finished"][0]["sha256"] == sha(BODY)
    assert {i["path"] for i in listed["images"]} == {"a.iso", "new.iso"}


def test_a_hash_the_file_does_not_have_is_refused_verbatim_and_the_part_file_is_gone(me, fake_amt, amt):
    wrong = "0" * 64
    uid = mint(me, extra={"sha256": wrong}).json()["structured"]["upload_id"]
    reply = stream(me, uid, BODY)
    j = reply.json()
    assert reply.status == 200 and j["ok"] is False and j["status"] == 400
    assert f"sha256_mismatch:got {sha(BODY)}" in j["text"]
    assert not (amt.root / "new.iso").exists() and not list(amt.root.glob(".*.upload"))
    failed = me.post("/api/call", {"tool": "amt_images", "arguments": {"action": "list"}}).json()["structured"]["uploads"]["finished"][0]
    assert failed["state"] == "failed" and "sha256_mismatch" in failed["error"]


def test_a_browser_that_stops_short_leaves_a_refused_upload_and_no_part_file(me, fake_amt, amt):
    """The size refusal: the console declared the file's size, the browser sent less. amt-mcp's real receive refuses the short body."""
    uid = mint(me).json()["structured"]["upload_id"]
    status, j = stream_short(me, uid, len(BODY), BODY[:1000])
    assert status == 200 and j == {"ok": False, "code": "browser_stream_ended_early", "sent": 1000, "size_bytes": len(BODY)}
    failed = wait_for(lambda: [u for u in amt_upload.snapshot()["finished"] if u["state"] == "failed"], "amt-mcp to record the refusal")[0]
    assert failed["error"] == f"ValueError:body_shorter_than_declared_size:1000!={len(BODY)}"
    assert not (amt.root / "new.iso").exists() and not list(amt.root.glob(".*.upload"))        # the part file is gone
    assert fake_amt.puts == [(f"/uploads/{token_of(amt)}", len(BODY), 1000)]


def test_amt_mcps_size_refusal_is_returned_verbatim_whatever_its_cause(me, fake_amt, amt):
    uid = mint(me).json()["structured"]["upload_id"]
    fake_amt.put_handler = lambda path, headers, body: (400, b"content_length_not_declared_size:99!=4096", "text/plain")
    j = stream(me, uid, BODY).json()
    assert j == {"ok": False, "status": 400, "text": "content_length_not_declared_size:99!=4096"}


def test_a_one_time_url_in_amt_mcps_put_answer_never_reaches_the_browser(me, fake_amt, amt):
    uid = mint(me).json()["structured"]["upload_id"]
    token = token_of(amt)
    echoed = f"refused for {fake_amt.base}/uploads/{token} and /uploads/{token}".encode()
    fake_amt.put_handler = lambda path, headers, body: (400, echoed, "text/plain")
    reply = stream(me, uid, BODY)
    j = reply.json()
    assert j["ok"] is False and j["status"] == 400 and j["text"] == "refused for [one-time url withheld] and [one-time url withheld]"
    assert token not in reply.text and "/uploads/" not in reply.text


def test_a_length_that_is_not_the_declared_size_sends_nothing_and_keeps_the_id(me, fake_amt, amt):
    uid = mint(me).json()["structured"]["upload_id"]
    bad = stream(me, uid, BODY[:100])
    assert bad.status == 400 and bad.json() == {"error": "size_not_the_declared_size"} and fake_amt.puts == []
    assert stream(me, uid, BODY).json()["ok"] is True                    # the right file still goes


def test_an_id_is_used_up_by_its_first_stream(me, fake_amt, amt):
    uid = mint(me).json()["structured"]["upload_id"]
    assert stream(me, uid, BODY).json()["ok"] is True
    again = stream(me, uid, BODY)
    assert again.status == 404 and again.json() == {"error": "unknown_upload"} and len(fake_amt.puts) == 1


def test_an_unknown_or_malformed_id_is_a_404_and_sends_nothing(me, fake_amt, amt):
    for uid in ("A" * 22, "short", "A" * 23, "../../x"):
        assert stream(me, uid, BODY).status == 404
    assert fake_amt.puts == []


def test_an_expired_id_is_gone(me, fake_amt, amt):
    uid = mint(me).json()["structured"]["upload_id"]
    real = me.app.uploads.now
    me.app.uploads.now = lambda: real() + 901
    try:
        assert stream(me, uid, BODY).status == 404 and fake_amt.puts == []
    finally:
        me.app.uploads.now = real


def test_the_stream_route_needs_the_session_the_csrf_token_and_the_same_origin(me, fake_amt, amt):
    uid = mint(me).json()["structured"]["upload_id"]
    assert stream(me, uid, BODY, cookie=False).status == 401
    assert stream(me, uid, BODY, csrf=False).status == 403
    assert stream(me, uid, BODY, origin=False).status == 403
    assert stream(me, uid, BODY, headers={"Origin": "https://evil.example.test"}).status == 403
    assert stream(me, uid, BODY, ctype="application/json").status == 415
    assert fake_amt.puts == []
    assert stream(me, uid, BODY).json()["ok"] is True                    # none of the refusals used the id up


def test_the_stream_route_wants_a_content_length(me, fake_amt, amt):
    uid = mint(me).json()["structured"]["upload_id"]
    conn = HTTPConnection("127.0.0.1", me.port, timeout=10)
    conn.putrequest("POST", f"/api/images/upload/{uid}")
    for k, v in {"Host": f"{me.host}:{me.port}", "Origin": me.origin, "Cookie": f"amt_console_session={me.cookie}", "X-CSRF-Token": me.csrf,
                 "Content-Type": "application/octet-stream"}.items():
        conn.putheader(k, v)
    conn.endheaders()
    assert conn.getresponse().status == 411 and fake_amt.puts == []
    conn.close()


def test_an_unreachable_amt_mcp_sends_nothing_and_keeps_the_id():
    up = images.Uploads("http://127.0.0.1:1")
    s = up.register({"name": "n.iso", "size_bytes": 4, "url": "http://127.0.0.1:1/uploads/" + "B" * 43})
    with pytest.raises(images.UploadError) as ex:
        up.stream(s["upload_id"], 4, lambda n: b"abcd")
    assert ex.value.status == 502 and ex.value.code.startswith("amt_mcp_unreachable:") and s["upload_id"] in up._offers


def test_the_registry_is_bounded_and_forgets_the_oldest(me):
    up = images.Uploads("http://127.0.0.1:9")
    first = up.register({"name": "n.iso", "size_bytes": 4, "url": "http://127.0.0.1:9/uploads/" + "B" * 43})["upload_id"]
    for _ in range(images.MAX_OFFERS):
        up.register({"name": "n.iso", "size_bytes": 4, "url": "http://127.0.0.1:9/uploads/" + "B" * 43})
    assert len(up._offers) == images.MAX_OFFERS and first not in up._offers


def test_an_offer_lives_as_long_as_amt_mcp_says_and_never_longer_than_its_own_fifteen_minutes():
    up = images.Uploads("http://127.0.0.1:9", now=lambda: 1000.0)
    url = "http://127.0.0.1:9/uploads/" + "B" * 43
    life = lambda expires: up._offers[up.register({"name": "n.iso", "size_bytes": 4, "url": url, "expires_in_s": expires})["upload_id"]]["expires"] - 1000.0
    assert life(30) == 30.0 and life(900) == 900.0
    assert life(5000) == 900.0 and life(0) == 900.0 and life(-5) == 900.0 and life("soon") == 900.0 and life(None) == 900.0 and life(True) == 900.0


def test_an_upstream_that_drops_the_connection_is_reported_as_not_answering_not_as_a_refusal(me, fake_amt, amt):
    uid = mint(me).json()["structured"]["upload_id"]

    def drop(path, headers, body):
        raise RuntimeError("the connection ends here")
    fake_amt.put_handler = drop
    j = stream(me, uid, BODY).json()
    assert j["ok"] is False and j["code"].startswith("amt_mcp_unreachable:") and "status" not in j and "text" not in j


def test_a_refusal_made_before_the_body_was_read_closes_the_connection(me, fake_amt, amt):
    """The unread body must not be taken for the next request on the same connection. Held redundantly: the handler speaks HTTP/1.0, which
    closes after every response, AND the refusal sets close_connection. Removing either alone leaves this green; only HTTP/1.1 together with
    the flag removed turns it red. Do not delete one of them as dead."""
    sock = socket.create_connection(("127.0.0.1", me.port), timeout=5)
    head = (f"POST /api/images/upload/{'A' * 22} HTTP/1.1\r\nHost: {me.host}:{me.port}\r\nOrigin: {me.origin}\r\nCookie: amt_console_session={me.cookie}\r\n"
            f"X-CSRF-Token: {me.csrf}\r\nContent-Type: application/octet-stream\r\nContent-Length: 64\r\n\r\n").encode()
    sock.sendall(head + b"G" * 64)
    seen = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break                                                  # the console closed the connection after its answer
            seen += chunk
    except socket.timeout:
        raise AssertionError("the console kept the connection open after refusing an unread body") from None
    finally:
        sock.close()
    assert seen.startswith(b"HTTP/1.0 404") or seen.startswith(b"HTTP/1.1 404")
    assert b"unknown_upload" in seen


# -- immutable 9: the one-time token is in no response and no log -------------------------------------------------------------------

def leaks(token, *haystacks):
    return [i for i, h in enumerate(haystacks) if token in h]


def test_the_scripted_token_is_in_no_response_header_body_or_log(me, fake_amt, amt, caplog):
    caplog.set_level(logging.DEBUG)
    seen = []
    first = mint(me)
    seen += [first.text, json.dumps(first.headers)]
    uid = first.json()["structured"]["upload_id"]
    token = token_of(amt)
    for reply in (stream(me, uid, BODY), stream(me, uid, BODY), me.post("/api/call", {"tool": "amt_images", "arguments": {"action": "list"}}),
                  me.get("/api/fleet"), me.get("/images"), me.get(f"/server/{KEY}/media")):
        seen += [reply.text, json.dumps(reply.headers)]
    refused = mint(me, "new.iso")                                          # the same name again: amt-mcp refuses, the file exists now
    seen += [refused.text]
    assert fake_amt.puts and token in fake_amt.puts[0][0]                  # positive control: the token really went to the url
    assert leaks(token, *seen) == [] and token not in caplog.text and uid not in caplog.text
    assert leaks(token, "x" + token + "x") == [0]                          # the scan catches a planted copy


def test_the_upload_id_is_in_no_log_line_even_when_the_request_is_refused_or_faults(me, fake_amt, amt, caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    uid = mint(me).json()["structured"]["upload_id"]
    assert stream(me, uid, BODY, headers={"Origin": "https://evil.example.test"}).status == 403            # the cross-site refusal logs its path
    monkeypatch.setattr(me.app.uploads, "stream", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert stream(me, uid, BODY).status == 500                                                              # a handler fault logs its path
    assert "cross-site POST refused" in caplog.text and "handler fault RuntimeError" in caplog.text
    assert uid not in caplog.text and "/api/images/upload/<id>" in caplog.text


def test_the_log_of_an_upload_names_no_url_and_no_file(me, fake_amt, amt, caplog):
    caplog.set_level(logging.DEBUG)
    uid = mint(me).json()["structured"]["upload_id"]
    stream(me, uid, BODY)
    assert "/uploads/" not in caplog.text and "new.iso" not in caplog.text and "127.0.0.1" not in caplog.text


# -- the busy refusals are the tool's own, and the console passes them verbatim --------------------------------------------------------

def test_a_rename_of_a_mounted_image_is_refused_by_the_tool_and_shown_as_it_said_it(me, fake_amt, amt):
    amt.mount("a.iso")
    reply = me.post("/api/call", {"tool": "amt_images", "arguments": {"action": "rename", "path": "a.iso", "new_name": "b.iso", "confirmed": True}}).json()
    assert reply["isError"] and "ider_rename_image_busy:a.iso:mounted_on:my-server-1" in reply["text"]
    assert (amt.root / "a.iso").exists() and not (amt.root / "b.iso").exists()
    gone = me.post("/api/call", {"tool": "amt_images", "arguments": {"action": "delete", "path": "a.iso", "confirmed": True}}).json()
    assert gone["isError"] and "ider_delete_image_busy:a.iso:mounted_on" in gone["text"] and (amt.root / "a.iso").exists()


def test_the_no_root_refusal_is_the_tools_own(me, fake_amt, amt, monkeypatch):
    settings = amt_write._settings_path()
    settings.write_text("{}")
    listed = me.post("/api/call", {"tool": "amt_images", "arguments": {"action": "list"}}).json()["structured"]
    assert listed["image_root"] is None and listed["images"] == [] and "ider_image_root_unset" in listed["error"]


# -- the mount's state follows into the fleet: since, start, and the chip --------------------------------------------------------------

def test_a_mount_through_the_console_records_its_start_and_since_and_refreshes_the_views(me, fake_amt):
    settle(me)
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": True, "images": {"iso": "a.iso"}, "start": a.get("start")}
    before = len(calls(fake_amt, "amt_ider", KEY))
    reply = me.post("/api/call", {"tool": "amt_ider", "arguments": {"device": KEY, "action": "mount", "iso_path": "a.iso", "start": "next_boot", "confirmed": True}})
    assert reply.status == 200 and len(calls(fake_amt, "amt_ider", KEY)) == before + 2        # the mount, then the view re-read at once
    ider = me.app.fleet.public(KEY)["sessions"]["ider"]
    assert ider["mounted"] is True and ider["start"] == "next_boot" and ider["since"] == me.clock()


def test_an_unmount_that_cannot_stop_the_thread_leaves_the_mount_recorded(me, fake_amt):
    settle(me)
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": True, "images": {"iso": "a.iso"}}
    me.post("/api/call", {"tool": "amt_ider", "arguments": {"device": KEY, "action": "mount", "iso_path": "a.iso", "start": "now", "confirmed": True}})
    fake_amt.results["amt_ider"] = lambda a: tool_error("ider_unmount_timeout: the serving thread did not stop; the IDE-R session is STILL HELD (not unmounted).") \
        if a["action"] == "unmount" else {"device": a["device"], "mounted": True, "images": {"iso": "a.iso"}}
    reply = me.post("/api/call", {"tool": "amt_ider", "arguments": {"device": KEY, "action": "unmount", "confirmed": True}}).json()
    assert reply["isError"] and "STILL HELD" in reply["text"]
    assert me.app.fleet.public(KEY)["sessions"]["ider"]["start"] == "now"
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
    me.post("/api/call", {"tool": "amt_ider", "arguments": {"device": KEY, "action": "unmount", "confirmed": True}})
    assert me.app.fleet.public(KEY)["sessions"]["ider"] == {"mounted": False}


def test_an_image_that_was_unmounted_elsewhere_is_no_longer_recorded(me, fake_amt):
    settle(me)
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": True, "images": {"iso": "a.iso"}}
    me.post("/api/call", {"tool": "amt_ider", "arguments": {"device": KEY, "action": "mount", "iso_path": "a.iso", "confirmed": True, "start": "next_boot"}})
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
    me.app.fleet.refresh_sessions(KEY)
    assert "ider:" + KEY not in me.app.fleet.started and me.app.fleet.public(KEY)["sessions"]["ider"] == {"mounted": False}


def test_a_mount_an_agent_makes_later_does_not_inherit_the_start_of_an_ended_console_mount(me, fake_amt):
    settle(me)
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": True, "images": {"iso": "a.iso"}}
    me.post("/api/call", {"tool": "amt_ider", "arguments": {"device": KEY, "action": "mount", "iso_path": "a.iso", "confirmed": True, "start": "next_boot"}})
    assert me.app.fleet.public(KEY)["sessions"]["ider"]["start"] == "next_boot"
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
    me.app.fleet.refresh_sessions(KEY)
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": True, "images": {"iso": "b.iso"}}      # an agent's mount, not ours
    me.app.fleet.refresh_sessions(KEY)
    ider = me.app.fleet.public(KEY)["sessions"]["ider"]
    assert ider["mounted"] is True and ider["images"] == {"iso": "b.iso"} and "start" not in ider and "since" not in ider


# -- the pages: built, and not inline-styled (the CSP forbids it) -----------------------------------------------------------------------

def test_the_media_tab_and_the_images_section_are_built_from_one_page(me):
    tab = me.get(f"/server/{KEY}/media").text
    assert 'id="media-page" data-server="my-server-1"' in tab and "/static/media.js" in tab and "built in a later step" not in tab and "@@" not in tab
    assert 'id="media-pick" hidden' in tab
    sect = me.get("/images").text
    assert 'id="media-page" data-server=""' in sect and "/static/media.js" in sect and "built in a later step" not in sect and "@@" not in sect
    assert 'id="media-pick"' in sect and 'id="media-pick" hidden' not in sect
    for page in (tab, sect):
        assert "style=" not in page.split('id="media-page"')[1].split("</main>")[0]
    assert me.get("/images", cookie=False).status == 302


def test_a_static_script_names_no_url_and_no_token(me):
    src = open(os_path("static/media.js")).read()
    assert "/uploads/" not in src and "url_note" not in src and "upload_id" in src


def os_path(rel):
    return os.path.join(os.path.dirname(images.__file__), rel)


# ============================== the page, in a real browser (headless Chromium) ====================================================

WIDTHS = [360, 600, 1024, 1440]
ALL_WRITES = ("amt_ider", "amt_images")
ISO = "debian-13.3-netinst.iso"
UBUNTU = "ubuntu-24.04.3-live-server.iso"


def library(images=None, fetches=None, open_uploads=None, finished=None, root="/iso", error=None):
    out = {"image_root": root, "source": "tool", "images": images if images is not None else [
        {"path": ISO, "bytes": 702545920, "mib": 670.0, "mountable": True},
        {"path": UBUNTU, "bytes": 3435973632, "mib": 3276.8, "mountable": True},
        {"path": "freedos-boot.img", "bytes": 1474560, "mib": 1.4, "mountable": True},
        {"path": "odd.iso", "bytes": 1000, "mib": 0.0, "mountable": False}],
        "fetches": fetches or [], "uploads": {"open": open_uploads or [], "finished": finished or [], "max_bytes": 17179869184}}
    if error:
        out["error"] = error
    return out


DOWNLOADING = {"name": "systemrescue-11.03.iso", "url": "https://mirror.example.test/sr.iso", "state": "running", "bytes": 682_000_000, "total_bytes": 1_100_000_000,
               "sha256": None, "sha256_expected": "ab" * 32, "error": None}
UPLOADING = {"name": "win11-24h2.iso", "state": "receiving", "bytes": 1_181_116_006, "size_bytes": 5_632_172_032, "sha256_expected": "5e2b" + "0" * 60}
FAILED_FETCH = {"name": "broken.iso", "url": "https://mirror.example.test/b.iso", "state": "failed", "bytes": 10, "total_bytes": None, "sha256": None,
                "sha256_expected": "cd" * 32, "error": "ValueError:sha256_mismatch:got " + "ef" * 32}
FAILED_UPLOAD = {"name": "win11-23h2.iso", "state": "failed", "bytes": 4096, "sha256": None, "error": "ValueError:body_shorter_than_declared_size:4096!=8216", "at": 1_760_000_000}


def scripted(fake, lib=None, mounted=None):
    """The library and the IDE-R view, scripted and changeable from the test: ``fake.lib`` and ``fake.mount`` (None or {"iso": name})."""
    fake.lib, fake.mount, fake.media_calls = lib or library(), mounted, []

    def ider(a):
        fake.media_calls.append(a)
        if a["action"] == "mount":
            fake.mount = {k: v.split("/")[-1] for k, v in (("iso", a.get("iso_path")), ("floppy", a.get("floppy_path"))) if v}
            return {"device": a["device"], "mounted": True, "images": fake.mount, "start": a["start"], "note": "the host's redirection session is held until amt_ider unmount"}
        if a["action"] == "unmount":
            images, fake.mount = fake.mount, None
            return {"device": a["device"], "mounted": False, "images": images, "bytes_to_host": 8192, "ended_with_error": None}
        return {"device": a["device"], "mounted": bool(fake.mount), "images": fake.mount or {}, "bytes_to_host": 4096, "error": None} if fake.mount else {"device": a["device"], "mounted": False}

    def imgs(a):
        fake.media_calls.append(a)
        if a["action"] == "list":
            return fake.lib
        if a["action"] == "verify":
            return {"path": a["path"], "bytes": 512, "sha256": sha(a["path"].encode()), "sha256_expected": None, "matches": None, "mountable": True}
        raise AssertionError(f"unscripted amt_images {a}")
    fake.results["amt_ider"], fake.results["amt_images"] = ider, imgs


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as ex:  # noqa: BLE001
            pytest.skip(f"headless Chromium is not installed ({type(ex).__name__}): the browser immutables are NOT checked")
        yield b
        b.close()


@pytest.fixture()
def mb(tmp_path, fake_amt):
    """A signed-in console, the server read once, the library scripted (three images, one not 512-aligned)."""
    console = Console(tmp_path, fake_amt)
    enroll_first_passkey(console, Authenticator(console.app.cfg.rp_id, console.origin))
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device()]}
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"]}
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_serial_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_identities"] = lambda a: {"identities": []}
    scripted(fake_amt)
    console.app.fleet.refresh_devices()
    console.app.fleet.refresh(KEY)
    yield console
    console.close()


def media_page(browser, mb, path=f"/server/{KEY}/media", width=1024, scheme="light", **kw):
    ctx, pg = open_page(browser, mb, path, width=width, scheme=scheme, **kw)
    pg.set_default_timeout(8000)
    until(pg, "() => !/^Reading/.test(document.getElementById('lib-note').textContent) && document.getElementById('mounted-chip').children.length > 0")
    return ctx, pg


def until(pg, expr, seconds=8):
    """Poll an expression in the page (wait_for_function evaluates a string, which the console's CSP refuses)."""
    end = time.time() + seconds
    while time.time() < end:
        if pg.evaluate(expr):
            return True
        time.sleep(0.05)
    raise AssertionError(f"timed out waiting for {expr}")


def sheet_kind(pg):
    return pg.evaluate("() => { const s = Array.from(document.querySelectorAll('.sheet.open')).pop(); return s ? { force: s.hasAttribute('data-force-sheet'), plain: s.hasAttribute('data-confirm-sheet'), call: s.querySelector('.call').textContent, title: s.querySelector('h2').textContent, say: s.querySelector('.consequence').textContent } : null; }")


def hold_force(pg):
    pg.wait_for_timeout(400)
    b = pg.query_selector(".sheet.open .force-control[data-hold]").bounding_box()
    pg.mouse.move(b["x"] + b["width"] / 2, b["y"] + b["height"] / 2)
    pg.mouse.down(); pg.wait_for_timeout(1400); pg.mouse.up(); pg.wait_for_timeout(150)


def confirm_plain(pg):
    pg.click(".sheet.open [data-confirm]")


def results(pg, slot):
    return [pg.inner_text(f"#{slot} .result:nth-child({i})").replace("\n", " ") for i in range(1, pg.locator(f"#{slot} .result").count() + 1)]


def row(name):
    return f'#lib-rows tr[data-name="{name}"]'


def sent(fake, tool):
    return [a for a in fake.media_calls if a.get("confirmed")] if tool == "any" else [a for t, a, _ in fake.calls if t == tool and a.get("confirmed")]


def writes(fake):
    return [(t, a) for t, a, _ in fake.calls if t in ALL_WRITES and a.get("confirmed")]


# -- the library: every state from a scripted result (immutable 19: the coverage is the result's own) ------------------------------

def test_the_library_shows_a_download_an_upload_and_failures_from_the_scripted_list(browser, mb, fake_amt):
    scripted(fake_amt, library(fetches=[DOWNLOADING, FAILED_FETCH], open_uploads=[UPLOADING], finished=[FAILED_UPLOAD]), mounted={"iso": ISO})
    mb.app.fleet.refresh_sessions(KEY)
    ctx, pg = media_page(browser, mb)
    try:
        until(pg, "() => document.querySelectorAll('#lib-rows tr').length === 6")
        # the download: a progress bar at 62 %, no Mount or Verify, Rename and Delete greyed with the reason
        r = row("systemrescue-11.03.iso")
        assert pg.get_attribute(f"{r} .progress", "aria-valuenow") == "62" and "62% · sha256 checked on completion" in text(pg, f"{r} td:nth-child(4)")
        assert text(pg, f"{r} td:nth-child(3)") == "downloading…" and text(pg, f"{r} td:nth-child(2)") == "size unknown"
        assert pg.eval_on_selector(f"{r} .progress i", "e => e.style.width") == "62%"
        acts = pg.eval_on_selector_all(f"{r} td.acts button", "els => els.map(e => [e.textContent, e.getAttribute('aria-disabled')])")
        assert acts == [["Rename", "true"], ["Delete", "true"]]
        assert pg.eval_on_selector_all(f"{r} td.acts .reason", "els => els.map(e => e.textContent)") == ["downloading", "downloading"]
        # the upload: declared size, progress from amt-mcp's own count
        u = row("win11-24h2.iso")
        assert pg.get_attribute(f"{u} .progress", "aria-valuenow") == "21" and "uploading from this browser · 1.10 GB of 5.25 GB" in text(pg, f"{u} td:nth-child(4)")
        assert "exact size and sha256 checked when the PUT ends" in text(pg, f"{u} td:nth-child(4)") and text(pg, f"{u} td:nth-child(3)") == "expected 5e2b…"
        assert pg.eval_on_selector_all(f"{u} td.acts .reason", "els => els.map(e => e.textContent)") == ["uploading", "uploading"]
        # the mounted image: Mount and Verify stay, Rename and Delete grey with "mounted"
        m = row(ISO)
        assert "mounted on my-server-1" in text(pg, f"{m} td:nth-child(4)") and "512-aligned" in text(pg, f"{m} td:nth-child(4)")
        assert pg.eval_on_selector_all(f"{m} td.acts button", "els => els.map(e => [e.textContent, e.getAttribute('aria-disabled')])") == [["Mount", "true"], ["Verify", None], ["Rename", "true"], ["Delete", "true"]]
        assert pg.eval_on_selector_all(f"{m} td.acts .reason", "els => els.map(e => e.textContent)") == ["unmount first", "mounted", "mounted"]
        # a free image and one that cannot be mounted
        f = row(UBUNTU)
        assert pg.eval_on_selector_all(f"{f} td.acts button", "els => els.map(e => [e.textContent, e.getAttribute('aria-disabled')])") == [["Mount", "true"], ["Verify", None], ["Rename", None], ["Delete", None]]
        assert text(pg, f"{f} td:nth-child(3)") == "not verified yet"
        odd = row("odd.iso")
        assert "not 512-aligned · cannot be mounted" in text(pg, f"{odd} td:nth-child(4)") and pg.eval_on_selector(f"{odd} td.acts button", "e => e.getAttribute('aria-disabled')") == "true"
        # the two failed transfers, verbatim, until a later attempt succeeds
        failures = [pg.inner_text(f"#lib-failures .result:nth-child({i})").replace("\n", " ") for i in (1, 2)]
        assert "fetch broken.iso · failed: ValueError:sha256_mismatch:got " + "ef" * 32 in failures[0] and "nothing was kept" in failures[0]
        assert "upload win11-23h2.iso · refused by the one-time url: ValueError:body_shorter_than_declared_size:4096!=8216 · amt-mcp deleted the part file · mint a new upload" in failures[1]
        # the coverage line: counts, root, source
        note = text(pg, "#lib-note")
        assert note.startswith("Listed 4 .iso/.img files under /iso (tool)") and "1 download and 1 upload in progress" in note
        assert pg.errors == []
    finally:
        ctx.close()


def test_an_arrival_hash_is_shown_only_for_a_file_of_the_size_that_arrived(browser, mb, fake_amt):
    same = {"name": UBUNTU, "state": "done", "bytes": 3435973632, "sha256": "ab" * 32, "error": None, "at": 1_760_000_000}
    other = {"name": ISO, "state": "done", "bytes": 4096, "sha256": "cd" * 32, "error": None, "at": 1_760_000_000}      # an earlier file of that name, since deleted
    scripted(fake_amt, library(finished=[same, other]))
    ctx, pg = media_page(browser, mb)
    try:
        until(pg, "() => document.querySelectorAll('#lib-rows tr').length === 4")
        assert text(pg, f"{row(UBUNTU)} td:nth-child(3)").startswith("abab abab abab abab") and "checked on arrival" in text(pg, f"{row(UBUNTU)} td:nth-child(3)")
        assert text(pg, f"{row(ISO)} td:nth-child(3)") == "not verified yet"
        assert pg.errors == []
    finally:
        ctx.close()


def test_a_disabled_row_action_ignores_a_click_and_a_busy_row_sends_nothing(browser, mb, fake_amt):
    scripted(fake_amt, library(fetches=[DOWNLOADING], open_uploads=[UPLOADING]), mounted={"iso": ISO})
    mb.app.fleet.refresh_sessions(KEY)
    ctx, pg = media_page(browser, mb)
    try:
        until(pg, "() => document.querySelectorAll('#lib-rows tr').length === 6")
        for sel in ('button[aria-disabled="true"]',):
            for i in range(pg.locator(f"#lib-rows {sel}").count()):
                el = pg.locator(f"#lib-rows {sel}").nth(i)
                assert el.evaluate("e => e.tabIndex") >= 0                                         # focusable, immutable 18
                el.click(force=True)
                assert pg.query_selector(".sheet.open") is None
        assert pg.evaluate("() => window.__callCount()") == 0 and writes(fake_amt) == []
    finally:
        ctx.close()


def test_an_empty_library_says_why_and_a_failed_read_is_never_called_empty(browser, mb, fake_amt):
    scripted(fake_amt, library(images=[]))
    ctx, pg = media_page(browser, mb)
    try:
        assert "No images under the root: nothing is in the library yet" in text(pg, "#lib-empty") and pg.is_visible("#lib-empty")
        assert text(pg, "#lib-note").startswith("Listed 0 .iso/.img files under /iso")
        assert pg.locator("#lib-rows tr").count() == 0
    finally:
        ctx.close()
    fake_amt.results["amt_images"] = lambda a: tool_error("Error executing tool amt_images: ConnectError: amt-mcp is restarting")
    ctx, pg = media_page(browser, mb)
    try:
        note = text(pg, "#lib-note")
        assert "The library could not be read: Error executing tool amt_images: ConnectError: amt-mcp is restarting · this is not an empty library" in note
        assert not pg.is_visible("#lib-empty")
    finally:
        ctx.close()


def test_with_no_image_root_the_page_says_so_and_every_mount_is_greyed_with_the_reason(browser, mb, fake_amt):
    scripted(fake_amt, library(images=[], root=None, error="ider_image_root_unset: set it with amt_images action=set_root (or the AMT_IMAGE_ROOT env)"))
    fake_amt.lib["source"] = None
    ctx, pg = media_page(browser, mb)
    try:
        assert pg.is_visible("#noroot") and pg.get_attribute("#noroot", "data-state") == "noroot"
        said = text(pg, "#noroot-text")
        assert said.startswith("No image root is set: every mount is refused until one is.") and "ider_image_root_unset" in said
        assert pg.get_attribute("#mount-go", "aria-disabled") == "true" and text(pg, "#mount-wrap .reason") == "no image root"
        assert text(pg, "#lib-root-chip") == "image root · not set"
        pg.click("#mount-go", force=True)
        assert pg.query_selector(".sheet.open") is None and writes(fake_amt) == []
        assert text(pg, "#lib-note") == "Listed 0 images: ider_image_root_unset: set it with amt_images action=set_root (or the AMT_IMAGE_ROOT env)"
    finally:
        ctx.close()


def test_a_mount_with_no_root_that_the_page_did_not_know_about_is_refused_by_the_tool_verbatim(browser, mb, fake_amt):
    base = fake_amt.results["amt_ider"]
    fake_amt.results["amt_ider"] = lambda a: tool_error("Error executing tool amt_ider: ider_image_root_unset: set it with amt_images action=set_root") if a["action"] == "mount" else base(a)
    ctx, pg = media_page(browser, mb)
    try:
        pg.select_option("#mount-iso", ISO)
        pg.click("#mount-go"); confirm_plain(pg)
        pg.wait_for_selector("#mount-results .result.error")
        got = results(pg, "mount-results")[0]
        assert "refused: Error executing tool amt_ider: ider_image_root_unset: set it with amt_images action=set_root · nothing was mounted" in got
    finally:
        ctx.close()


# -- immutable 4 and 5: mounts, the start mode decides the sheet, one call each --------------------------------------------------------

def test_a_mount_at_next_boot_is_a_plain_sheet_with_the_exact_call_and_follows_into_the_card_and_the_header_chip(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb)
    try:
        assert pg.get_attribute("#mount-go", "aria-disabled") == "true" and text(pg, "#mount-wrap .reason") == "pick an image"
        assert [o for o in pg.eval_on_selector_all("#mount-iso option", "els => els.map(e => e.textContent)")] == ["none", ISO, UBUNTU]     # odd.iso is not offered
        assert pg.eval_on_selector_all("#mount-floppy option", "els => els.map(e => e.textContent)") == ["none", "freedos-boot.img"]
        pg.select_option("#mount-iso", ISO)
        assert pg.get_attribute("#mount-go", "aria-disabled") is None
        pg.click("#mount-go")
        k = sheet_kind(pg)
        assert k["plain"] and not k["force"] and k["title"] == f"Mount {ISO} on {KEY}"
        assert k["call"] == f'tools/call amt_ider {{device: "{KEY}", action: "mount", iso_path: "{ISO}", start: "next_boot", confirmed: true}}'
        assert "is not reset" in k["say"] and "held until you unmount" in k["say"] and writes(fake_amt) == []
        confirm_plain(pg)
        pg.wait_for_selector("#mount-results .result.ok")
        assert writes(fake_amt) == [("amt_ider", {"device": KEY, "action": "mount", "iso_path": ISO, "start": "next_boot", "confirmed": True})]
        got = results(pg, "mount-results")[0]
        assert f"mount {ISO} · mounted on {KEY} · start next_boot · the host's IDE-R session is held until unmount" in got
        # the Mounted card: image with its size, the start mode and its meaning, since, the link to boot from it
        until(pg, "() => document.querySelector('#mounted-body .kv')")
        body = text(pg, "#mounted-body")
        assert f"{ISO} · 670" in body and "next_boot · the host sees the drive at its next boot; it was not reset" in body and "session held until unmount · KVM works beside it" in body
        assert pg.get_attribute("#mounted-body a", "href") == f"/server/{KEY}/power" and text(pg, "#mounted-body a") == "set next boot cd_ider, then reset"
        assert "IDE-R held" in text(pg, "#mounted-chip") and pg.get_attribute("#mounted-chip .chip", "data-session") == "ider"
        assert pg.get_attribute("#unmount", "aria-disabled") is None
        assert pg.get_attribute("#mount-go", "aria-disabled") == "true" and text(pg, "#mount-wrap .reason") == "unmount first"
        until(pg, "() => document.querySelector('#srv-chips [data-session=ider]')", 9)                                       # the header's chip follows
        assert "IDE-R" in text(pg, "#srv-chips [data-session=ider]")
        assert pg.evaluate("() => window.__callCount()") == 1
    finally:
        ctx.close()


def test_graceful_is_a_plain_confirm_and_now_is_the_hold_and_the_call_carries_the_start(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb)
    try:
        pg.select_option("#mount-iso", ISO)
        pg.click('[data-start="graceful"]')
        pg.click("#mount-go")
        k = sheet_kind(pg)
        assert k["plain"] and 'start: "graceful"' in k["call"] and "the same act as Restart" in k["say"] and k["title"] == f"Mount {ISO} on {KEY} and reset it"
        pg.evaluate("() => window.__closeSheets()")
        pg.click('[data-start="now"]')
        assert pg.get_attribute('[data-start="now"]', "aria-checked") == "true" and pg.get_attribute('[data-start="graceful"]', "aria-checked") == "false"
        pg.click("#mount-go")
        k = sheet_kind(pg)
        assert k["force"] and not k["plain"] and 'start: "now"' in k["call"] and k["title"] == f"Mount {ISO} and HARD reset {KEY} now"
        assert "reset at once without asking the OS: unsaved work is lost" in k["say"] and writes(fake_amt) == []
        hold_force(pg)
        pg.wait_for_selector("#mount-results .result.ok")
        assert writes(fake_amt) == [("amt_ider", {"device": KEY, "action": "mount", "iso_path": ISO, "start": "now", "confirmed": True})]
        assert pg.evaluate("() => window.__forceFireCount()") == 1 and "start now" in results(pg, "mount-results")[0]
        assert "now · the host was hard reset when the image was mounted" in text(pg, "#mounted-body")
    finally:
        ctx.close()


def test_a_row_mount_chooses_that_image_and_opens_the_sheet_for_the_form_as_it_stands(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb)
    try:
        pg.select_option("#mount-floppy", "freedos-boot.img")
        pg.click(f'{row(UBUNTU)} button:has-text("Mount")')
        k = sheet_kind(pg)
        assert pg.input_value("#mount-iso") == UBUNTU
        assert k["call"] == f'tools/call amt_ider {{device: "{KEY}", action: "mount", iso_path: "{UBUNTU}", floppy_path: "freedos-boot.img", start: "next_boot", confirmed: true}}'
        assert "a CD and a floppy drive" in k["say"]
    finally:
        ctx.close()


def test_every_mount_sheet_follows_the_predicate_for_every_start(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb)
    try:
        pg.select_option("#mount-iso", ISO)
        got = {}
        for start in ("next_boot", "graceful", "now"):
            pg.click(f'[data-start="{start}"]'); pg.click("#mount-go")
            got[start] = pg.evaluate("() => { const s = document.querySelector('.sheet.open'); return [s.hasAttribute('data-force-sheet'), window.__destructiveCall({ tool: 'amt_ider', arguments: { start: " + json.dumps(start) + " } })]; }")
            pg.evaluate("() => window.__closeSheets()")
        assert got == {"next_boot": [False, False], "graceful": [False, False], "now": [True, True]}
        assert writes(fake_amt) == []
    finally:
        ctx.close()


def test_the_start_radios_work_from_the_keyboard(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb)
    try:
        pg.focus('[data-start="next_boot"]')
        pg.keyboard.press("ArrowDown")
        assert pg.get_attribute('[data-start="graceful"]', "aria-checked") == "true" and pg.evaluate("() => document.activeElement.getAttribute('data-start')") == "graceful"
        pg.keyboard.press("ArrowUp"); pg.keyboard.press("ArrowUp")
        assert pg.get_attribute('[data-start="now"]', "aria-checked") == "true"
        pg.keyboard.press("Enter")
        assert pg.get_attribute('[data-start="now"]', "aria-checked") == "true" and writes(fake_amt) == []
    finally:
        ctx.close()


# -- unmount and the still-held state -----------------------------------------------------------------------------------------------

def mount_via_page(pg):
    pg.select_option("#mount-iso", ISO)
    pg.click("#mount-go"); confirm_plain(pg)
    pg.wait_for_selector("#mount-results .result.ok")
    until(pg, "() => document.querySelector('#mounted-body .kv')")


def test_unmount_is_a_plain_sheet_and_its_result_lands_in_the_card_and_frees_the_mount_button(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb)
    try:
        assert pg.get_attribute("#unmount", "aria-disabled") == "true" and text(pg, "#unmount ~ .reason") == "nothing mounted"
        mount_via_page(pg)
        pg.click("#unmount")
        k = sheet_kind(pg)
        assert k["plain"] and k["call"] == f'tools/call amt_ider {{device: "{KEY}", action: "unmount", confirmed: true}}' and k["title"] == f"Unmount the image from {KEY}"
        confirm_plain(pg)
        pg.wait_for_selector("#mounted-results .result.ok")
        assert "unmounted · 8,192 bytes were served to the host" in results(pg, "mounted-results")[0]
        until(pg, "() => /Nothing is mounted/.test(document.getElementById('mounted-body').textContent)")
        assert "not mounted" in text(pg, "#mounted-chip") and pg.get_attribute("#mount-go", "aria-disabled") is None
        assert [a["action"] for _, a in writes(fake_amt)] == ["mount", "unmount"]
    finally:
        ctx.close()


def test_an_unmount_the_serving_thread_will_not_complete_says_the_session_is_still_held(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb)
    try:
        mount_via_page(pg)
        base = fake_amt.results["amt_ider"]
        held = "Error executing tool amt_ider: ider_unmount_timeout: the serving thread did not stop; the IDE-R session is STILL HELD (not unmounted). Call unmount again, or check amt_ider status"
        fake_amt.results["amt_ider"] = lambda a: tool_error(held) if a["action"] == "unmount" else base(a)
        pg.click("#unmount"); confirm_plain(pg)
        pg.wait_for_selector('#mounted-results [data-session="unmount_held"]')
        got = text(pg, '#mounted-results [data-session="unmount_held"]')
        assert "Unmount requested; the serving thread has not stopped yet, so the session is still held. Check status again in a few seconds." in got and held in got
        assert "IDE-R held" in text(pg, "#mounted-chip") and pg.get_attribute("#unmount", "aria-disabled") is None        # still mounted: Unmount stays
        fake_amt.results["amt_ider"] = base
        pg.click("#mounted-status")
        pg.wait_for_selector("#mounted-results .result:not([data-session]):has-text('status of')")
        assert f"status of {KEY} · mounted: {ISO} · 4,096 bytes served to the host so far" in results(pg, "mounted-results")[0]
    finally:
        ctx.close()


def test_a_mount_the_console_did_not_make_says_its_start_is_not_recorded(browser, mb, fake_amt):
    scripted(fake_amt, mounted={"iso": ISO})
    mb.app.fleet.refresh_sessions(KEY)
    ctx, pg = media_page(browser, mb)
    try:
        body = text(pg, "#mounted-body")
        assert "not recorded here: this console did not start the mount, or restarted since" in body and f"{ISO} · 670" in body
    finally:
        ctx.close()


# -- busy refusals and the other library writes ---------------------------------------------------------------------------------------

def test_a_rename_refused_because_the_image_is_busy_is_shown_as_the_tool_said_it_and_nothing_changes(browser, mb, fake_amt):
    base = fake_amt.results["amt_images"]
    busy = f"Error executing tool amt_images: ider_rename_image_busy:{UBUNTU}:mounted_on:my-server-1"
    fake_amt.results["amt_images"] = lambda a: tool_error(busy) if a["action"] == "rename" else base(a)
    ctx, pg = media_page(browser, mb)
    try:
        pg.click(f'{row(UBUNTU)} button:has-text("Rename")')
        assert sheet_kind(pg)["plain"] and pg.get_attribute(".sheet.open [data-confirm]", "aria-disabled") == "true"      # same name: not a call yet
        assert text(pg, ".sheet.open .btn-wrap .reason") == "enter a different name"
        pg.fill(".sheet.open [data-field=new_name]", "ubuntu-24.04.3-server.iso")
        assert sheet_kind(pg)["call"] == f'tools/call amt_images {{action: "rename", path: "{UBUNTU}", new_name: "ubuntu-24.04.3-server.iso", confirmed: true}}'
        confirm_plain(pg)
        pg.wait_for_selector("#lib-results .result.error")
        got = results(pg, "lib-results")[0]
        assert f"rename {UBUNTU} · refused: {busy} · the image is mounted on my-server-1 · nothing changed" in got
        assert pg.locator(row(UBUNTU)).count() == 1 and sent(fake_amt, "amt_images")[-1]["new_name"] == "ubuntu-24.04.3-server.iso"
    finally:
        ctx.close()


@pytest.mark.parametrize("bad", ["", "no-extension", "a/b.iso", ".hidden.iso", "x.txt", UBUNTU])
def test_a_rename_that_the_tool_would_refuse_never_becomes_a_call(browser, mb, fake_amt, bad):
    ctx, pg = media_page(browser, mb)
    try:
        pg.click(f'{row(UBUNTU)} button:has-text("Rename")')
        pg.fill(".sheet.open [data-field=new_name]", bad)
        assert pg.get_attribute(".sheet.open [data-confirm]", "aria-disabled") == "true"
        pg.click(".sheet.open [data-confirm]", force=True)
        assert sent(fake_amt, "amt_images") == [] and pg.evaluate("() => window.__callCount()") == 0
    finally:
        ctx.close()


def test_verify_is_a_read_it_needs_no_sheet_and_records_the_hash(browser, mb, fake_amt):
    digest = "a1b2c3d4e5f60718" + "0" * 48
    base = fake_amt.results["amt_images"]
    fake_amt.results["amt_images"] = lambda a: {"path": a["path"], "bytes": 3435973632, "sha256": digest, "sha256_expected": None, "matches": None, "mountable": True} if a["action"] == "verify" else base(a)
    ctx, pg = media_page(browser, mb)
    try:
        pg.click(f'{row(UBUNTU)} button:has-text("Verify")')
        pg.wait_for_selector("#lib-results .result.ok")
        assert pg.query_selector(".sheet.open") is None
        verify = [a for t, a, _ in fake_amt.calls if t == "amt_images" and a["action"] == "verify"]
        assert verify == [{"action": "verify", "path": UBUNTU}]                                          # a read: no confirmed, no device
        got = results(pg, "lib-results")[0]
        assert f"verify {UBUNTU} · sha256 recomputed {' '.join(digest[i:i + 4] for i in range(0, 64, 4))} · 512-byte aligned" in got
        until(pg, f"() => /verified/.test(document.querySelector('{row(UBUNTU)} td:nth-child(3)').textContent)")
        assert text(pg, f"{row(UBUNTU)} td:nth-child(3)").startswith("a1b2 c3d4 e5f6 0718 …") and pg.evaluate("() => window.__callCount()") == 0
    finally:
        ctx.close()


def test_delete_is_the_hold_and_the_call_names_the_path(browser, mb, fake_amt):
    base = fake_amt.results["amt_images"]
    fake_amt.results["amt_images"] = lambda a: {"deleted": a["path"], "bytes": 3435973632} if a["action"] == "delete" else base(a)
    ctx, pg = media_page(browser, mb)
    try:
        pg.click(f'{row(UBUNTU)} button:has-text("Delete")')
        k = sheet_kind(pg)
        assert k["force"] and not k["plain"] and k["title"] == f"Delete {UBUNTU}"
        assert k["call"] == f'tools/call amt_images {{action: "delete", path: "{UBUNTU}", confirmed: true}}'
        assert "There is no undo" in k["say"] and sent(fake_amt, "amt_images") == []
        hold_force(pg)
        pg.wait_for_selector("#lib-results .result.ok")
        assert sent(fake_amt, "amt_images") == [{"action": "delete", "path": UBUNTU, "confirmed": True}]
        assert f"delete {UBUNTU} · deleted · 3.20 GB" in results(pg, "lib-results")[0] and pg.evaluate("() => window.__forceFireCount()") == 1
    finally:
        ctx.close()


def test_a_delete_refused_while_the_image_is_busy_is_verbatim(browser, mb, fake_amt):
    base = fake_amt.results["amt_images"]
    text_ = f"Error executing tool amt_images: ider_delete_image_busy:{UBUNTU}:being_downloaded"
    fake_amt.results["amt_images"] = lambda a: tool_error(text_) if a["action"] == "delete" else base(a)
    ctx, pg = media_page(browser, mb)
    try:
        pg.click(f'{row(UBUNTU)} button:has-text("Delete")'); hold_force(pg)
        pg.wait_for_selector("#lib-results .result.error")
        assert f"refused: {text_} · the image is being downloaded · nothing changed" in results(pg, "lib-results")[0]
    finally:
        ctx.close()


def test_fetch_takes_its_fields_in_the_sheet_and_the_call_is_what_they_say(browser, mb, fake_amt):
    base = fake_amt.results["amt_images"]
    fake_amt.results["amt_images"] = lambda a: {**DOWNLOADING, "name": a.get("name") or "x.iso", "note": "downloading in the background; poll with amt_images action=list"} if a["action"] == "fetch" else base(a)
    ctx, pg = media_page(browser, mb)
    try:
        pg.click("#lib-fetch")
        c = ".sheet.open [data-confirm]"
        assert pg.get_attribute(c, "aria-disabled") == "true" and text(pg, ".sheet.open .btn-wrap .reason") == "enter an http(s) URL"
        pg.fill(".sheet.open [data-field=url]", "ftp://mirror.example.test/x.iso")
        assert pg.get_attribute(c, "aria-disabled") == "true"
        pg.fill(".sheet.open [data-field=url]", "https://mirror.example.test/sr.iso")
        pg.fill(".sheet.open [data-field=sha256]", "xyz")
        assert text(pg, ".sheet.open .btn-wrap .reason") == "the SHA-256 is 64 hex characters" and pg.get_attribute(c, "aria-disabled") == "true"
        pg.fill(".sheet.open [data-field=sha256]", "AB" * 32)
        pg.fill(".sheet.open [data-field=name]", "systemrescue-11.03.iso")
        assert sheet_kind(pg)["call"] == ('tools/call amt_images {action: "fetch", url: "https://mirror.example.test/sr.iso", name: "systemrescue-11.03.iso", '
                                          'sha256: "' + "ab" * 32 + '", overwrite: false, confirmed: true}')
        confirm_plain(pg)
        pg.wait_for_selector("#lib-results .result")
        assert sent(fake_amt, "amt_images") == [{"action": "fetch", "url": "https://mirror.example.test/sr.iso", "name": "systemrescue-11.03.iso", "sha256": "ab" * 32, "overwrite": False, "confirmed": True}]
        assert "fetch systemrescue-11.03.iso · downloading in the background · progress is in the table" in results(pg, "lib-results")[0]
    finally:
        ctx.close()


def test_set_root_from_the_library_and_from_the_no_root_banner_is_one_confirmed_call(browser, mb, fake_amt):
    base = fake_amt.results["amt_images"]
    fake_amt.results["amt_images"] = lambda a: {"image_root": a["root"], "previous": "/iso", "previous_source": "env", "persisted_to": "/data/state/settings.json"} if a["action"] == "set_root" else base(a)
    ctx, pg = media_page(browser, mb)
    try:
        pg.click("#lib-root-change")
        assert pg.input_value(".sheet.open [data-field=root]") == "/iso"
        pg.fill(".sheet.open [data-field=root]", "")
        assert pg.get_attribute(".sheet.open [data-confirm]", "aria-disabled") == "true"
        pg.fill(".sheet.open [data-field=root]", "/srv/iso")
        assert sheet_kind(pg)["call"] == 'tools/call amt_images {action: "set_root", root: "/srv/iso", confirmed: true}'
        confirm_plain(pg)
        pg.wait_for_selector("#lib-results .result.ok")
        assert "set root · image root is now /srv/iso (was /iso, set by env) · persisted" in results(pg, "lib-results")[0]
        assert sent(fake_amt, "amt_images") == [{"action": "set_root", "root": "/srv/iso", "confirmed": True}]
    finally:
        ctx.close()


def test_a_tools_refusal_text_is_rendered_as_text_never_as_markup(browser, mb, fake_amt):
    evil = '<img src=x onerror="window.pwned=1"><b>bold</b>'
    base = fake_amt.results["amt_images"]
    fake_amt.results["amt_images"] = lambda a: tool_error(evil) if a["action"] == "rename" else base(a)
    ctx, pg = media_page(browser, mb)
    try:
        pg.click(f'{row(UBUNTU)} button:has-text("Rename")'); pg.fill(".sheet.open [data-field=new_name]", "z.iso"); confirm_plain(pg)
        pg.wait_for_selector("#lib-results .result.error")
        assert evil in text(pg, "#lib-results .result.error") and pg.evaluate("() => window.pwned") is None and pg.locator("#lib-results img, #lib-results b").count() == 0
    finally:
        ctx.close()


# -- the upload: the file goes through the console to amt-mcp's own receive -----------------------------------------------------------

@pytest.fixture()
def up(mb, fake_amt, amt):
    """The console with amt-mcp's real library code behind it (a temp image root), the IDE-R view scripted."""
    base = lambda a: {"device": a["device"], "mounted": False}
    fake_amt.results["amt_ider"] = base
    return mb


def pick_file(pg, name, data, sha_text=None):
    pg.click("#lib-upload")
    pg.set_input_files(".sheet.open input[type=file]", {"name": name, "mimeType": "application/octet-stream", "buffer": data})
    if sha_text is not None:
        pg.fill(".sheet.open [data-field=sha256]", sha_text)


def test_an_upload_from_the_browser_is_sent_once_through_the_console_and_lands_with_its_hash(browser, up, fake_amt, amt):
    ctx, pg = media_page(browser, up)
    try:
        pick_file(pg, "new.iso", BODY)
        k = sheet_kind(pg)
        assert k["plain"] and k["title"] == "Upload new.iso from this computer"
        assert k["call"] == f'tools/call amt_images {{action: "upload", name: "new.iso", size_bytes: {len(BODY)}, confirmed: true}}'
        assert "new.iso · 4,096 bytes (read from the file; the url accepts exactly this many)" in text(pg, ".sheet.open .field .help")
        assert "url never reaches this page" in k["say"] and fake_amt.puts == []
        confirm_plain(pg)
        pg.wait_for_selector("#lib-results .result.ok")
        assert (amt.root / "new.iso").read_bytes() == BODY
        got = results(pg, "lib-results")[0]
        digest = sha(BODY)
        assert f"upload new.iso · received 4,096 bytes (the declared size) · sha256 {' '.join(digest[i:i + 4] for i in range(0, 64, 4))} recorded by amt-mcp" in got
        assert [(t, a) for t, a, _ in fake_amt.calls if t == "amt_images" and a.get("confirmed")] == [("amt_images", {"action": "upload", "name": "new.iso", "size_bytes": 4096, "confirmed": True})]
        assert pg.evaluate("() => window.__callCount()") == 1
        until(pg, f"() => document.querySelector('{row('new.iso')}')")
        assert text(pg, f"{row('new.iso')} td:nth-child(3)").startswith(" ".join(digest[i:i + 4] for i in range(0, 16, 4)))
        assert "checked on arrival" in text(pg, f"{row('new.iso')} td:nth-child(3)")
        # the url and its token never reached the page: not in the DOM, not in a request
        token = token_of(amt)
        assert token not in pg.content() and not [u for u in pg.requests if token in u or "/uploads/" in u]
        assert sorted({u.split("/")[2] for u in pg.requests if u.startswith("http")}) == [pb_host(up)]
        assert pg.errors == []
    finally:
        ctx.close()


def pb_host(console):
    return console.origin.split("//")[1]


def test_an_upload_whose_hash_is_wrong_is_refused_verbatim_and_leaves_no_part_file(browser, up, fake_amt, amt):
    ctx, pg = media_page(browser, up)
    try:
        pick_file(pg, "new.iso", BODY, "0" * 64)
        confirm_plain(pg)
        pg.wait_for_selector("#lib-results .result.error")
        got = results(pg, "lib-results")[0]
        assert f"upload new.iso · refused by the one-time url: ValueError:sha256_mismatch:got {sha(BODY)} · amt-mcp deleted the part file · mint a new upload" in got
        assert not (amt.root / "new.iso").exists() and not list(amt.root.glob(".*.upload"))
        until(pg, "() => document.querySelectorAll('#lib-failures .result').length === 1")
        assert "sha256_mismatch" in text(pg, "#lib-failures .result") and pg.locator(row("new.iso")).count() == 0
    finally:
        ctx.close()


def test_an_upload_the_tool_will_not_mint_is_refused_verbatim_and_sends_no_file(browser, up, fake_amt, amt):
    (amt.root / "taken.iso").write_bytes(BODY)
    ctx, pg = media_page(browser, up)
    try:
        pick_file(pg, "taken.iso", BODY)
        confirm_plain(pg)
        pg.wait_for_selector("#lib-results .result.error")
        got = results(pg, "lib-results")[0]
        assert "refused: Error executing tool amt_images: ider_upload_exists:taken.iso" in got and "no upload url was minted" in got
        assert fake_amt.puts == []
    finally:
        ctx.close()


@pytest.mark.parametrize("name,data,sha_text,why", [("notes.txt", b"x", None, "the file must be a plain .iso or .img"), ("empty.iso", b"", None, "the file is empty"),
                                                    ("ok.iso", b"x", "12", "the SHA-256 is 64 hex characters")])
def test_a_file_or_hash_the_tool_would_refuse_never_becomes_a_call(browser, up, fake_amt, amt, name, data, sha_text, why):
    ctx, pg = media_page(browser, up)
    try:
        pick_file(pg, name, data, sha_text)
        assert pg.get_attribute(".sheet.open [data-confirm]", "aria-disabled") == "true" and text(pg, ".sheet.open .btn-wrap .reason") == why
        pg.click(".sheet.open [data-confirm]", force=True)
        assert fake_amt.puts == [] and not [c for c in fake_amt.calls if c[0] == "amt_images" and c[1].get("confirmed")]
    finally:
        ctx.close()


def test_a_url_amt_mcp_did_not_own_is_reported_and_nothing_waits_for_the_file(browser, mb, fake_amt):
    base = fake_amt.results["amt_images"]
    fake_amt.results["amt_images"] = lambda a: {"name": "n.iso", "size_bytes": 1, "url": "https://elsewhere.example.test/uploads/" + "A" * 43, "expires_in_s": 900} if a["action"] == "upload" else base(a)
    ctx, pg = media_page(browser, mb)
    try:
        pick_file(pg, "n.iso", b"x")
        confirm_plain(pg)
        pg.wait_for_selector("#lib-results .result.error")
        assert "carried no usable upload url (upload_url_not_from_amt_mcp) · nothing is waiting for the file" in results(pg, "lib-results")[0]
        assert fake_amt.puts == [] and "A" * 43 not in pg.content()
    finally:
        ctx.close()


SENDER_BRANCHES = [
    ("ended-early", dict(status=200, body={"ok": False, "code": "browser_stream_ended_early", "sent": 1000, "size_bytes": 4096}),
     "the browser stopped after 1,000 of 4,096 bytes; amt-mcp refuses a short body and deletes the part file · mint a new upload"),
    ("url-gone", dict(status=200, body={"ok": False, "status": 404, "text": "not found"}),
     "refused by the one-time url: not found · the url was used already or expired · mint a new upload"),
    ("not-answering", dict(status=200, body={"ok": False, "code": "amt_mcp_unreachable:ReadTimeout", "sent": None, "size_bytes": 4096}),
     "amt-mcp did not answer (amt_mcp_unreachable:ReadTimeout) · it is not known how much arrived; read the library before minting a new upload"),
    ("console-refusal", dict(status=404, body={"error": "unknown_upload"}), "refused: unknown_upload · nothing was sent to amt-mcp · mint a new upload"),
    ("amt-refusal", dict(status=200, body={"ok": False, "status": 400, "text": "ValueError:body_larger_than_declared_size:4096"}),
     "refused by the one-time url: ValueError:body_larger_than_declared_size:4096 · amt-mcp deleted the part file · mint a new upload"),
    ("connection-lost", None, "the connection to the console ended before an answer · it is not known how much arrived; read the library for the result, then mint a new upload")]


@pytest.mark.parametrize("name,reply,says", SENDER_BRANCHES, ids=[b[0] for b in SENDER_BRANCHES])
def test_each_way_the_send_can_end_is_reported_in_the_tools_words_in_the_library_card(browser, up, fake_amt, amt, name, reply, says):
    """The mint is the real tool's; the stream route's answer is scripted per branch of the page's own reading of it."""
    ctx, pg = media_page(browser, up)
    try:
        def answer(route):
            if reply is None:
                return route.abort()
            route.fulfill(status=reply["status"], content_type="application/json", body=json.dumps(reply["body"]))
        pg.route("**/api/images/upload/*", answer)
        pick_file(pg, "new.iso", BODY)
        confirm_plain(pg)
        pg.wait_for_selector("#lib-results .result")
        assert says in results(pg, "lib-results")[0]
        assert fake_amt.puts == [] and not (amt.root / "new.iso").exists()
    finally:
        ctx.close()


# -- the Images section: the same page with a server picker ---------------------------------------------------------------------------

def test_the_images_section_picks_the_server_and_every_call_names_it(browser, mb, fake_amt):
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device(), device("alpha", ip="10.0.0.27")]}
    mb.app.fleet.refresh_devices(); mb.app.fleet.refresh("alpha")
    ctx, pg = media_page(browser, mb, path="/images")
    try:
        assert pg.is_visible("#media-pick") and pg.eval_on_selector_all("#media-server option", "els => els.map(e => e.value)") == ["my-server-1", "alpha"]
        assert text(pg, "#mounted-key") == "my-server-1"
        pg.select_option("#media-server", "alpha")
        assert text(pg, "#mounted-key") == "alpha"
        pg.select_option("#mount-iso", ISO)
        pg.click("#mount-go")
        assert f'device: "alpha", action: "mount"' in sheet_kind(pg)["call"]
        confirm_plain(pg)
        pg.wait_for_selector("#mount-results .result.ok")
        assert writes(fake_amt) == [("amt_ider", {"device": "alpha", "action": "mount", "iso_path": ISO, "start": "next_boot", "confirmed": True})]
        until(pg, "() => /alpha/.test(document.querySelector('#lib-rows tr td:nth-child(4)').textContent)")
        assert "mounted on alpha" in text(pg, f"{row(ISO)} td:nth-child(4)")
        assert pg.get_attribute("nav a[aria-current=page], .navrail a[aria-current=page]", "href") == "/images"
    finally:
        ctx.close()


def test_the_images_section_with_no_servers_says_so_and_greys_the_mount(browser, tmp_path, fake_amt):
    console = Console(tmp_path, fake_amt)
    enroll_first_passkey(console, Authenticator(console.app.cfg.rp_id, console.origin))
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": []}
    scripted(fake_amt)
    console.app.fleet.refresh_devices()
    ctx, pg = open_page(browser, console, "/images")
    try:
        until(pg, "() => /no servers are registered/.test(document.getElementById('media-server').textContent)")
        assert "No server is registered, so nothing can be mounted." in text(pg, "#mounted-body")
        assert pg.get_attribute("#mount-go", "aria-disabled") == "true" and text(pg, "#mount-wrap .reason") == "no server"
        assert pg.get_attribute("#unmount", "aria-disabled") == "true" and text(pg, "#unmount ~ .reason") == "no server"
    finally:
        ctx.close()
        console.close()


def test_the_server_tab_has_no_picker_the_server_is_the_one_in_its_header(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb)
    try:
        assert not pg.is_visible("#media-pick") and text(pg, "#mounted-key") == KEY
        assert pg.get_attribute(".srvhead .tabs [aria-current=page]", "href") == f"/server/{KEY}/media"
    finally:
        ctx.close()


# -- immutable 4 and 5 on the page ------------------------------------------------------------------------------------------------------

SWEEP = "#media-page button, #media-page select, #media-page input, #media-page [role=radio], #media-page a[href]"


def test_a_bare_click_on_any_control_outside_a_sheet_writes_nothing(browser, mb, fake_amt):
    scripted(fake_amt, library(fetches=[DOWNLOADING], open_uploads=[UPLOADING]), mounted={"iso": ISO})
    mb.app.fleet.refresh_sessions(KEY)
    ctx, pg = media_page(browser, mb)
    try:
        pg.evaluate("() => document.addEventListener('click', e => { const a = e.target.closest('a[href]'); if (a) e.preventDefault(); }, true)")
        until(pg, "() => document.querySelectorAll('#lib-rows tr').length >= 5")
        n = pg.eval_on_selector_all(SWEEP, "els => els.length")
        assert n >= 20
        for i in range(n):
            pg.evaluate("([sel, i]) => { const el = document.querySelectorAll(sel)[i]; if (el) el.click(); window.__closeSheets(); }", [SWEEP, i])
        assert pg.evaluate("() => window.__callCount()") == 0 and pg.evaluate("() => window.__forceFireCount()") == 0
        assert writes(fake_amt) == [] and [c for c in fake_amt.media_calls if c.get("confirmed")] == []
        assert pg.errors == []
    finally:
        ctx.close()


def build_every_force_sheet(pg):
    """The mount-now sheet and the delete sheet, so both force controls are in the document."""
    pg.select_option("#mount-iso", ISO); pg.click('[data-start="now"]'); pg.click("#mount-go"); pg.evaluate("() => window.__closeSheets()")
    pg.click(f'{row(UBUNTU)} button:has-text("Delete")'); pg.evaluate("() => window.__closeSheets()")
    assert pg.eval_on_selector_all(".force-control[data-hold]", "els => els.length") == 2


EXPECTED_FORCE = {"click": (0, True), "hold600": 0, "hold1400_slideoff": 0, "swipe": 0, "hold1400_release": 1,
                  "click_450_click": (0, True), "click_700_click": (0, True), "dblclick": (0, True), "click_click_wait_confirm": (1, "true"),
                  "enter_held": (0, False), "enter_wait_enter": (0, False), "enter_release_550_tab_enter": (1, "true"),
                  "enter_held_600_not_armed": ("false", 0)}


@pytest.mark.parametrize("index,width", [(0, 1024), (1, 1024), (0, 360), (1, 360)])
def test_the_force_matrix_on_the_mount_now_and_delete_controls(browser, mb, fake_amt, index, width):
    ctx, pg = media_page(browser, mb, width=width)
    try:
        build_every_force_sheet(pg)
        got = check_mockups().force_matrix(pg, index)
        assert got is not None, "no force control was found"
        assert got["opener_point"] != "CONFIRM", "the second sheet's confirm sits under the opener's point"
        got.pop("opener_point")
        assert got == EXPECTED_FORCE
    finally:
        ctx.close()


def test_a_tap_then_a_tap_500_ms_later_never_fires_the_delete_hold(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb, width=360, has_touch=True)
    try:
        build_every_force_sheet(pg)
        assert check_mockups().tap_matrix(pg, 1) == (0, True)
        assert writes(fake_amt) == []
    finally:
        ctx.close()


def test_every_destructive_call_the_page_sent_was_preceded_by_a_force_fire(browser, mb, fake_amt):
    base = fake_amt.results["amt_images"]
    fake_amt.results["amt_images"] = lambda a: {"deleted": a["path"], "bytes": 1} if a["action"] == "delete" else base(a)
    ctx, pg = media_page(browser, mb)
    try:
        pg.select_option("#mount-iso", ISO)
        pg.click("#mount-go"); confirm_plain(pg); pg.wait_for_selector("#mount-results .result")                         # plain
        pg.click("#unmount"); confirm_plain(pg); pg.wait_for_selector("#mounted-results .result")                         # plain
        pg.click('[data-start="now"]'); pg.click("#mount-go"); hold_force(pg); pg.wait_for_timeout(100)                    # forced by its argument
        pg.click(f'{row(UBUNTU)} button:has-text("Delete")'); hold_force(pg); pg.wait_for_timeout(100)                    # forced
        spy = pg.evaluate("() => window.__calls().map(c => ({ forced: c.forced, destructive: window.__destructiveCall({ tool: c.tool, arguments: c.arguments, then: c.then }, c.ctx), text: c.text }))")
        assert [c["destructive"] for c in spy] == [False, False, True, True] and [c["forced"] for c in spy] == [False, False, True, True]
        assert all('device: "my-server-1"' in c["text"] for c in spy[:3])                                                  # every ider call names the device
    finally:
        ctx.close()


def test_the_plain_sheets_of_the_page_send_one_call_per_activation_and_manage_focus(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb)
    try:
        pg.select_option("#mount-iso", ISO)
        pg.click("#mount-go"); pg.evaluate("() => window.__closeSheets()")                 # the mount sheet, closed again: the driver reopens it
        checks = check_mockups().confirm_checks(pg)
        assert len(checks) == 1, checks
        c = checks[0]
        assert c["click"] == 1 and c["enter_held"] == 1, c                                   # one activation, one call
        assert c["focus_key"] == {"inSheet": True, "isCancel": True} and c["focus_ptr"] and c["trapped"], c
    finally:
        ctx.close()


# -- the page itself: layout at every width, contrast, nothing from outside --------------------------------------------------------------

@pytest.mark.parametrize("width", WIDTHS)
def test_the_page_fits_every_width_with_hit_areas_and_a_16_px_gutter(browser, mb, fake_amt, width):
    cm = check_mockups()
    scripted(fake_amt, library(fetches=[DOWNLOADING, FAILED_FETCH], open_uploads=[UPLOADING], finished=[FAILED_UPLOAD]), mounted={"iso": ISO})
    mb.app.fleet.refresh_sessions(KEY)
    ctx, pg = media_page(browser, mb, width=width)
    try:
        until(pg, "() => document.querySelectorAll('#lib-rows tr').length === 6 && document.querySelector('#mounted-body .kv')")
        pg.wait_for_timeout(250)
        r = pg.evaluate(cm.JS_WALK)
        bottom, anim = pg.evaluate(cm.JS_BOTTOM), pg.evaluate(cm.JS_ANIMATED)
        bad = []
        if r["scrollWidth"] > r["inner"]: bad.append(("overflow", r["scrollWidth"], r["inner"]))
        if r["gutter"] is not None and r["gutter"] != 16: bad.append(("gutter", r["gutter"]))
        if r["currentTab"] and not r["currentTab"]["ok"]: bad.append(("current-tab", r["currentTab"]))
        bad += [("letter-wrapped", x) for x in r["narrow"]]
        if width < 600: bad += [("control-offscreen", x) for x in r["offscreen"]]
        bad += [("fixed-over-control", x) for x in r["fixedOverlap"]] + [("under-bottom-bar", x) for x in bottom]
        bad += [("animated-without-data-motion", x) for x in anim["missing"]]
        for t in r["targets"]:
            if not ((t["w"] >= 48 and t["h"] >= 48) or (t["chip"] and t["w"] >= 24 and t["h"] >= 24)): bad.append(("target", t))
        assert bad == [], bad
        assert len(r["targets"]) >= 25 and r["text"], "the walk saw nothing: it would pass on an empty page"
        assert pg.errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_every_text_and_ring_on_the_page_clears_the_contrast_floors(browser, mb, fake_amt, scheme):
    cm = check_mockups()
    scripted(fake_amt, library(fetches=[DOWNLOADING, FAILED_FETCH], open_uploads=[UPLOADING], finished=[FAILED_UPLOAD]), mounted={"iso": ISO})
    mb.app.fleet.refresh_sessions(KEY)
    ctx, pg = media_page(browser, mb, scheme=scheme)
    try:
        until(pg, "() => document.querySelectorAll('#lib-rows tr').length === 6 && document.querySelector('#mounted-body .kv')")
        pg.wait_for_timeout(250)
        r = pg.evaluate(cm.JS_WALK)
        low = [(t["snippet"], t["ratio"], t["ex"]) for t in r["text"] if t["ratio"] < (3.0 if t["large"] else 4.5)]
        assert low == [], low
        assert len(r["text"]) > 40, "the walk saw too little text: it would pass on an empty page"
        assert pg.errors == []
    finally:
        ctx.close()


def test_the_page_loads_nothing_from_outside_the_console_and_never_touches_amt_mcp(browser, mb, fake_amt):
    ctx, pg = media_page(browser, mb)
    try:
        origins = {u.split("/")[0] + "//" + u.split("/")[2] for u in pg.requests if u.startswith("http")}
        assert origins == {mb.origin}, origins
        assert not [u for u in pg.requests if fake_amt.base in u or u.endswith("/mcp")]
        body = pg.content()
        assert BEARER not in body and 'type="password"' not in body and "handoffs/" not in body and "/uploads/" not in body
    finally:
        ctx.close()


def test_a_row_sheet_that_stays_open_across_a_poll_still_gives_focus_back_to_its_opener(browser, mb, fake_amt):
    """The page re-reads the fleet every 5 s and rebuilds the table; a sheet opened from a row must not lose its opener to that."""
    ctx, pg = media_page(browser, mb)
    try:
        pg.click(f'{row(UBUNTU)} button:has-text("Delete")')
        pg.wait_for_timeout(6500)
        pg.keyboard.press("Escape")
        until(pg, f"() => document.activeElement && document.activeElement.getAttribute('aria-label') === 'Delete {UBUNTU}'")
        pg.wait_for_timeout(1600)                                      # the deferred rebuild has run by now: focus is on the new button
        assert pg.evaluate("() => document.activeElement.getAttribute('aria-label')") == f"Delete {UBUNTU}"
        assert pg.evaluate("() => document.contains(document.activeElement)") and writes(fake_amt) == []
    finally:
        ctx.close()
