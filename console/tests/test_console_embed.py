"""The embeds' backend (packet C4): the relay of amt-mcp's own viewer pages under /embed/<kind>/<server>/, and the rules it keeps.

The viewer front is a fake that serves amt-mcp's REAL embed-mode pages (console_fakes.FakeViewer); every amt-mcp answer is scripted
(console_fakes.FakeAmt). No test starts a KVM or SOL session or reaches a host. Immutables 4 and 12 (request origins, the embed's toolbar), and
the token rule: the viewer's token never reaches the browser, a log line, an exception or a file."""
import http.client
import json
import logging
import time

import pytest

import embed
import server
from console_fakes import Authenticator, Console, FakeViewer, enroll_first_passkey
from test_console_fleet import KEY, STATUS, device, tool_error


class Hosts:
    """The scripted amt-mcp side: at most one mirror and one terminal, live or not, sharing the fake viewer's status. `mirror` and
    `terminal` are None (nothing running) or True (live)."""

    def __init__(self, fake, viewer):
        self.fake, self.viewer = fake, viewer
        self.mirror = self.terminal = None
        self.list_shape = False
        self.reachable = True
        self.recording_path = None
        self.last_recording = None            # amt_serial keeps the last finished recording on the terminal until it is stopped
        fake.results["amt_devices"] = lambda a: {"source": "file", "devices": [device()]}
        fake.results["amt_status"] = lambda a: {**STATUS, "device": a["device"]}
        fake.results["amt_mirror_link"] = lambda a: self.tool("m", a)
        fake.results["amt_serial_link"] = lambda a: self.tool("s", a)
        fake.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
        fake.results["amt_identities"] = lambda a: {"identities": []}

    def live(self, prefix):
        return self.mirror if prefix == "m" else self.terminal

    def view(self, prefix):
        v = dict(self.viewer.status[prefix])
        direct = f"http://127.0.0.1:8766/{prefix}/"
        front = [self.viewer.url(prefix, False)] if self.reachable else []
        ctl = [self.viewer.url(prefix, True)] if self.reachable else []
        v["urls"] = front + [direct + self.viewer.view[prefix] + "/"]
        v["control_urls"] = ctl + [direct + self.viewer.control[prefix] + "/"]
        return v

    def tool(self, prefix, a):
        act, key = a["action"], "mirrors" if prefix == "m" else "terminals"
        if act == "status":
            if not self.live(prefix):
                return {key: [], "server": None, "recording_dir": "/r"} if self.list_shape else {"device": a["device"], "live": False}
            return {key: [self.view(prefix)], "server": {"bind": "0.0.0.0", "port": 8766}, "recording_dir": "/r"} if self.list_shape else self.view(prefix)
        if act == "start":
            already = bool(self.live(prefix))
            self.set(prefix, True)
            return {**self.view(prefix), **({"note": "already live; returning the existing link"} if already else {})}
        if act == "stop":
            self.set(prefix, None)
            last, self.last_recording = self.last_recording, None
            if self.viewer.status[prefix]["recording"] and self.recording_path and prefix == "s":
                last = {"path": self.recording_path, "ended": True}      # a recording still running is closed by the stop
            self.viewer.status[prefix]["recording"] = None
            return {"device": a["device"], "stopped": True, "session_released": True, "frames": 1, "error": None, "recording": last if prefix == "s" else None}
        if act == "record_start":
            self.viewer.status[prefix]["recording"] = {"path": "/r/x", "frames": 0, "bytes": 0, "started": 1.0, "seconds": 2.0, "ended": False}
            return {"device": a["device"], "recording": self.viewer.status[prefix]["recording"]}
        if act == "record_stop":
            self.viewer.status[prefix]["recording"] = None
            self.last_recording = {"path": self.recording_path, "ended": True} if self.recording_path else None
            return {"device": a["device"], "recording": self.last_recording}
        return tool_error("unscripted")

    def set(self, prefix, value):
        if prefix == "m":
            self.mirror = value
        else:
            self.terminal = value


@pytest.fixture()
def viewer():
    v = FakeViewer()
    yield v
    v.close()


@pytest.fixture()
def hosts(fake_amt, viewer):
    return Hosts(fake_amt, viewer)


@pytest.fixture()
def ec(tmp_path, fake_amt, viewer, hosts):
    c = Console(tmp_path, fake_amt, viewer_origin=viewer.base, fleet_poll=False)
    enroll_first_passkey(c, Authenticator(c.app.cfg.rp_id, c.origin))
    yield c
    c.close()


def all_tokens(v):
    out = set(FakeViewer.CONTROL.values()) | set(FakeViewer.VIEW.values()) | set(v.control.values()) | set(v.view.values())
    return sorted(out | {t.replace("Sentinel", "Rotated") for t in out})


def stream_head(console, path, want=1, timeout=15):
    """Open a stream through the console and read its first bytes; returns (connection, response, first chunk)."""
    conn = http.client.HTTPConnection("127.0.0.1", console.port, timeout=timeout)
    conn.request("GET", path, headers={"Host": f"{console.host}:{console.port}"})      # no cookie: the key in the path is the credential
    resp = conn.getresponse()
    return conn, resp, resp.read1(want * 64) if resp.status == 200 else b""


# -- the relay: the viewer's embed-mode page, under the console's own path --------------------------------------------------

def test_the_embed_page_is_the_viewers_embed_mode_page_under_the_consoles_path(ec, hosts, viewer):
    hosts.mirror = True
    r = ec.get(f"{ec.embed('mirror')}/")
    assert r.status == 200 and r.headers["Content-Type"].startswith("text/html")
    for gone in ("id=shot", "id=mgrp", "id=hbar", "id=pgrp", "data-a=", "Screenshot", "Download"):
        assert gone not in r.text, gone                                      # the page the viewer served for embed=1: its standalone regions are not in it
    assert "Take control" in r.text and 'src="stream"' in r.text
    assert viewer.seen("GET") == [f"/m/{viewer.control['m']}/?embed=1"]       # one request, the control url, in embed mode, with the token only upstream
    assert [(t, a["action"]) for t, a, _ in hosts.fake.calls if t == "amt_mirror_link"] == [("amt_mirror_link", "status")]


def test_the_embed_responses_may_be_framed_by_a_console_page_and_nothing_else(ec, hosts):
    hosts.mirror = True
    r = ec.get(f"{ec.embed('mirror')}/")
    csp = r.headers["Content-Security-Policy"]
    assert "frame-ancestors 'self'" in csp and "default-src 'none'" in csp and f"connect-src {ec.origin}/embed/;" in csp   # the framed page reaches /embed/ only
    assert "'self'" not in csp.replace("frame-ancestors 'self'", "") and "form-action 'none'" in csp      # an opaque document has no 'self': absolute sources
    assert csp.endswith("sandbox allow-scripts allow-forms") and "allow-same-origin" not in csp        # opaque in a tab too, not only in the console's frame
    assert r.headers["X-Frame-Options"] == "SAMEORIGIN" and r.headers["Referrer-Policy"] == "no-referrer" and r.headers["Cache-Control"] == "no-store"
    assert r.headers["X-Content-Type-Options"] == "nosniff"
    for other in ("/", f"/server/{KEY}/console", "/api/session"):             # every other console response still refuses a frame
        h = ec.get(other).headers
        assert h["X-Frame-Options"] == "DENY" and "frame-ancestors 'none'" in h["Content-Security-Policy"], other


def test_no_script_or_page_of_the_console_ever_grants_a_frame_the_console_s_origin():
    import re
    from pathlib import Path
    root = Path(server.__file__).parent
    files = list((root / "static").glob("*.js")) + list((root / "pages").glob("*.html"))
    grant = re.compile(r"""sandbox['"]?\s*[:=]\s*['"][^'"]*allow-same-origin""")
    assert [f.name for f in files if grant.search(f.read_text())] == []
    assert grant.search("h('iframe', { sandbox: 'allow-scripts allow-same-origin' })") and grant.search('<iframe sandbox="allow-same-origin">')      # the scan finds a grant
    flags = re.search(r"sandbox: '([^']*)'", (root / "static" / "embed.js").read_text()).group(1).split()
    assert sorted(flags) == ["allow-forms", "allow-scripts"]


def test_the_relay_asks_amt_mcp_with_status_only_and_never_opens_a_session(ec, hosts, viewer):
    hosts.mirror = hosts.terminal = True
    for path in (f"{ec.embed('mirror')}/", f"{ec.embed('mirror')}/status.json", f"{ec.embed('serial')}/", f"{ec.embed('serial')}/xterm.js", f"{ec.embed('mirror')}/frame.jpg"):
        assert ec.get(path).status == 200, path
    ec.request("POST", f"{ec.embed('mirror')}/input", raw=b'{"events":[]}', csrf=False)
    hosts.mirror = hosts.terminal = None
    for path in (f"{ec.embed('mirror')}/", f"{ec.embed('serial')}/", f"/api/embed/mirror/{KEY}"):
        ec.get(path)
    sessions = [(t, a) for t, a, _ in hosts.fake.calls if t in ("amt_mirror_link", "amt_serial_link")]
    assert sessions and all(a["action"] == "status" and a["device"] == KEY for _, a in sessions), sessions
    assert not [a for _, a in sessions if a["action"] in ("start", "stop", "record_start")]


@pytest.mark.parametrize("list_shape", [False, True])
def test_a_status_for_the_default_device_is_a_list_and_is_read_the_same(ec, hosts, list_shape):
    hosts.mirror = True
    hosts.list_shape = list_shape
    assert ec.get(f"{ec.embed('mirror')}/").status == 200
    assert ec.get(f"/api/embed/mirror/{KEY}").json()["reachable"] is True


# -- the allowlist: only what the embed page uses; the standalone page's routes are never relayed -----------------------------

STANDALONE = ["media.json", "power.json", "ider", "power", "boot", "record", "record.json", "..", "x/y", "%2e%2e", "Status.json", "stream/", ""]


@pytest.mark.parametrize("rest", [r for r in STANDALONE if r != ""])
@pytest.mark.parametrize("method", ["GET", "POST"])
def test_a_standalone_or_unknown_route_is_refused_here_and_nothing_goes_upstream(ec, hosts, viewer, rest, method):
    hosts.mirror = True
    r = ec.request(method, f"{ec.embed('mirror')}/{rest}", raw=b"{}" if method == "POST" else None, csrf=False)
    assert r.status in (404, 400), (rest, r.status)
    assert viewer.requests == [], viewer.requests


def test_a_route_of_the_other_kind_is_refused_too(ec, hosts, viewer):
    hosts.mirror = hosts.terminal = True
    for path in (f"{ec.embed('mirror')}/events", f"{ec.embed('mirror')}/xterm.js", f"{ec.embed('serial')}/stream", f"{ec.embed('serial')}/frame.jpg"):
        assert ec.get(path).status == 404, path
    assert viewer.requests == []


def test_the_allowlist_is_the_embed_page_s_routes_of_the_real_viewer():
    import amt_mirror
    import amt_serial
    standalone = {"media.json", "power.json", "ider", "power", "boot"}
    assert embed.GET_ROUTES["mirror"] == set(amt_mirror.ROUTES) - standalone - {"record"}      # ROUTES lists record, but it is a POST route: a GET of it is a 404
    # Record is a viewer route on the standalone page only: in the console it is a confirmed amt_*_link tools/call (M1 of the sprint review)
    assert embed.POST_ROUTES["mirror"] == set(amt_mirror.POST_ROUTES) - standalone - {"record"} == {"input"}
    assert embed.GET_ROUTES["serial"] == set(amt_serial.ROUTES) and embed.POST_ROUTES["serial"] == set(amt_serial.POST_ROUTES) - {"record"} == {"input"}
    assert not standalone & (embed.GET_ROUTES["mirror"] | embed.POST_ROUTES["mirror"] | embed.GET_ROUTES["serial"] | embed.POST_ROUTES["serial"])
    assert embed.STREAM_ROUTES == {"stream", "events"}


def test_every_upstream_request_says_embed_mode(ec, hosts, viewer):
    hosts.mirror = hosts.terminal = True
    ec.get(f"{ec.embed('mirror')}/")
    ec.get(f"{ec.embed('mirror')}/status.json")
    ec.get(f"{ec.embed('serial')}/xterm.css")
    ec.request("POST", f"{ec.embed('mirror')}/input", raw=b'{"events":[]}', csrf=False)
    ec.request("POST", f"{ec.embed('serial')}/input", raw=b'{"data":"x"}', csrf=False)
    assert len(viewer.requests) == 5 and all("embed=1" in p for p in viewer.seen()), viewer.seen()


# -- what is forwarded: no cookie, no bearer, no CSRF token; the body as it came ---------------------------------------------

def test_the_console_s_cookie_bearer_and_csrf_token_are_never_sent_to_the_viewer(ec, hosts, viewer):
    hosts.mirror = hosts.terminal = True
    ec.get(f"{ec.embed('mirror')}/", headers={"Authorization": "Bearer attacker", "X-CSRF-Token": "x"})
    ec.request("POST", f"{ec.embed('mirror')}/input", raw=b'{"events":[["k",97,1]]}', csrf=True, headers={"X-CSRF-Token": ec.csrf})
    sent = [h for _, _, h, _ in viewer.requests]
    assert len(sent) == 2
    for h in sent:
        lower = {k.lower() for k in h}
        assert not lower & {"cookie", "authorization", "x-csrf-token", "origin", "referer", "x-forwarded-for"}, h
    assert ec.cookie not in json.dumps(sent) and ec.csrf not in json.dumps(sent)


def test_a_post_is_relayed_whole_and_only_the_input_route_is_relayed(ec, hosts, viewer):
    hosts.mirror = True
    body = b'{"events":[["k",65293,1],["k",65293,0]]}'
    r = ec.request("POST", f"{ec.embed('mirror')}/input?on=1&evil=%2e%2e", raw=body, csrf=False)
    assert r.status == 200 and r.json() == {"sent": len(body)}
    posts = [(p, b) for m, p, _, b in viewer.requests if m == "POST"]
    assert posts == [(f"/m/{viewer.control['m']}/input?embed=1", body)]            # the query is never forwarded: the console's own flag only


@pytest.mark.parametrize("kind", ["mirror", "serial"])
@pytest.mark.parametrize("query", ["", "?on=1", "?on=0", "?embed=0&on=1"])
def test_record_is_not_a_relayed_route_it_is_a_tool_call_so_the_post_is_a_404_and_nothing_goes_upstream(ec, hosts, viewer, kind, query):
    """Sprint review M1: POST /embed/<kind>/<server>/record used to reach the viewer's record route, a write with no tools/call, no sheet and no
    `confirmed`. Recording is amt_mirror_link / amt_serial_link record_start (confirmed) and record_stop from the console's own chrome."""
    hosts.mirror = hosts.terminal = True
    r = ec.request("POST", f"{ec.embed(kind)}/record{query}", raw=b"", csrf=False)
    assert r.status == 404 and r.json() == {"error": "not_found"}
    assert viewer.requests == [], viewer.requests
    assert [a for t, a, _ in hosts.fake.calls if t in ("amt_mirror_link", "amt_serial_link") and a["action"] != "status"] == []


def test_last_event_id_resumes_a_stream_and_other_values_are_dropped(ec, hosts, viewer):
    hosts.terminal = True
    for value, kept in (("40", True), ("40; drop", False)):
        viewer.requests.clear()
        viewer.hold.set()                                              # the stream ends at once: this test is about the request
        conn = http.client.HTTPConnection("127.0.0.1", ec.port, timeout=15)
        conn.request("GET", f"{ec.embed('serial')}/events", headers={"Host": f"{ec.host}:{ec.port}", "Last-Event-ID": value})
        conn.getresponse().read()
        conn.close()
        assert ("Last-Event-ID" in viewer.requests[0][2]) is kept


def test_a_post_body_is_bounded_and_must_be_json_or_empty(ec, hosts, viewer):
    hosts.mirror = True
    assert ec.request("POST", f"{ec.embed('mirror')}/input", raw=b"x" * (embed.MAX_BODY + 1), csrf=False).status == 413
    assert ec.request("POST", f"{ec.embed('mirror')}/input", raw=b"events=1", csrf=False, headers={"Content-Type": "text/plain"}).status == 415
    assert viewer.requests == []


# -- who may ask: the embed key in the path, not the cookie ------------------------------------------------------------------------

def bare(console, method, path, headers=None, raw=None):
    """A request the way the opaque-origin frame makes it: no cookie, no CSRF token, `Origin: null` on a POST, cross-site by fetch metadata."""
    h = {"Sec-Fetch-Site": "cross-site", **({"Origin": "null"} if method in ("POST", "OPTIONS") else {}), **(headers or {})}
    return console.request(method, path, raw=raw, cookie=False, csrf=False, origin=False, headers=h)


def test_the_key_alone_authenticates_a_get_and_the_cookie_alone_does_not(ec, hosts, viewer):
    hosts.mirror = True
    base = ec.embed("mirror")
    assert bare(ec, "GET", f"{base}/status.json").status == 200                # no cookie, cross-site: the key in the path is the credential
    assert bare(ec, "POST", f"{base}/input", raw=b'{"events":[]}').status == 200
    wrong = "/embed/mirror/" + KEY + "/" + "A" * 43
    r = ec.get(f"{wrong}/status.json")                                          # the session cookie rides along and is worth nothing here
    assert (r.status, r.json()) == (404, {"error": "not_found"})
    assert ec.get(f"/embed/mirror/{KEY}/").status == 404                        # the old keyless path is gone
    assert len(viewer.requests) == 2, viewer.seen()                             # only the two keyed requests reached the viewer


def test_a_wrong_key_is_a_404_with_nothing_sent_upstream_and_no_cors_grant(ec, hosts, viewer):
    hosts.mirror = True
    good = ec.embed("mirror").rsplit("/", 1)[1]
    flipped = good[:-1] + ("A" if good[-1] != "A" else "B")
    for key in (flipped, "A" * 43, "A" * 42, good + "x", good[:20]):
        for method in ("GET", "POST", "OPTIONS"):
            r = bare(ec, method, f"/embed/mirror/{KEY}/{key}/status.json" if method != "POST" else f"/embed/mirror/{KEY}/{key}/input", raw=b"{}" if method == "POST" else None)
            assert (r.status, r.json()) == (404, {"error": "not_found"}), (key, method, r.status)
            assert "Access-Control-Allow-Origin" not in r.headers, (key, method)
    assert viewer.requests == [] and not [c for c in hosts.fake.calls if c[0] == "amt_mirror_link"]


def test_a_key_works_for_its_own_kind_and_server_only(ec, hosts, viewer, fake_amt):
    hosts.mirror = hosts.terminal = True
    key = ec.embed("mirror").rsplit("/", 1)[1]
    assert bare(ec, "GET", f"/embed/serial/{KEY}/{key}/status.json").status == 404       # the mirror's key on the terminal
    ec.app.fleet.devices = {**ec.app.fleet.devices, "other-host": ec.app.fleet.devices[KEY]}
    assert bare(ec, "GET", f"/embed/mirror/other-host/{key}/status.json").status == 404   # the same kind, another server
    assert viewer.requests == []
    assert bare(ec, "GET", f"/embed/mirror/{KEY}/{key}/status.json").status == 200


def test_the_mint_route_needs_the_session_the_csrf_token_and_a_known_server_and_kind(ec, hosts):
    path = "/api/embed/key"
    assert ec.request("POST", path, {"kind": "mirror", "device": KEY}, cookie=False).status == 401
    assert ec.request("POST", path, {"kind": "mirror", "device": KEY}, csrf=False).status == 403
    assert ec.request("POST", path, {"kind": "mirror", "device": KEY}, origin=False).status == 403
    assert ec.post(path, {"kind": "mirror", "device": "nonesuch"}).status == 404
    for body in ({"kind": "kvm", "device": KEY}, {"kind": "mirror"}, {"kind": "mirror", "device": "Bad_Key"}, {"kind": 1, "device": KEY}):
        assert ec.post(path, body).status == 400, body
    r = ec.post(path, {"kind": "mirror", "device": KEY})
    assert r.status == 200 and set(r.json()) == {"key"} and len(r.json()["key"]) == 43
    assert ec.get(path).status == 404                                            # GET is not a route
    assert ec.mint_embed_key("mirror") != ec.mint_embed_key("mirror")            # one per page view


def test_a_key_dies_at_sign_out_and_with_an_idle_session(ec, hosts, viewer):
    hosts.mirror = True
    base = ec.embed("mirror")
    assert bare(ec, "GET", f"{base}/status.json").status == 200
    assert ec.post("/auth/signout").status == 200
    assert ec.app.keys._keys == []                                                # revoked at once (not merely dead because its session is), not at its next use
    r = bare(ec, "GET", f"{base}/status.json")
    assert (r.status, r.json()) == (404, {"error": "not_found"})
    assert len(viewer.requests) == 1


def test_a_key_dies_when_its_session_idles_out(ec, hosts, viewer):
    hosts.mirror = True
    base = ec.embed("mirror")
    assert bare(ec, "GET", f"{base}/status.json").status == 200
    ec.app.auth.now = lambda: __import__("time").time() + ec.app.auth.idle_seconds + 5      # the session's own clock runs past its idle limit
    assert bare(ec, "GET", f"{base}/status.json").status == 404
    assert len(viewer.requests) == 1


def test_a_key_expires_after_its_idle_limit_and_a_use_restarts_the_clock(ec, hosts, viewer):
    hosts.mirror = True
    clock = [1000.0]
    ec.app.keys.now = lambda: clock[0]
    base = ec.mint_embed_key("mirror")
    path = f"/embed/mirror/{KEY}/{base}/status.json"
    for _ in range(3):                                                           # used every 9 minutes: alive well past one idle limit
        clock[0] += embed.KEY_TTL_IDLE - 60
        assert bare(ec, "GET", path).status == 200
    clock[0] += embed.KEY_TTL_IDLE + 1                                           # then left alone for longer than the limit
    r = bare(ec, "GET", path)
    assert (r.status, r.json()) == (404, {"error": "not_found"})
    assert len(ec.app.keys) == 0 and len(viewer.requests) == 3


def test_the_page_s_poll_keeps_its_keys_alive_and_reports_whether_one_is_live(ec, hosts, viewer):
    hosts.mirror = True
    clock = [1000.0]
    ec.app.keys.now = lambda: clock[0]
    assert ec.get(f"/api/embed/mirror/{KEY}").json()["key_live"] is False        # no key was minted for this page yet
    key = ec.mint_embed_key("mirror")
    for _ in range(4):
        clock[0] += embed.KEY_TTL_IDLE - 60
        assert ec.get(f"/api/embed/mirror/{KEY}").json()["key_live"] is True     # the open page's poll is the keep-alive
    assert bare(ec, "GET", f"/embed/mirror/{KEY}/{key}/status.json").status == 200
    clock[0] += embed.KEY_TTL_IDLE + 1                                           # the page went away
    assert ec.get(f"/api/embed/mirror/{KEY}").json()["key_live"] is False
    assert bare(ec, "GET", f"/embed/mirror/{KEY}/{key}/status.json").status == 404
    assert key not in ec.get(f"/api/embed/mirror/{KEY}").text                    # only the boolean


def test_keys_are_capped_and_the_oldest_unused_goes_first(ec, hosts):
    clock = [1000.0]
    ec.app.keys.now = lambda: clock[0]
    first = ec.mint_embed_key("mirror")
    for _ in range(embed.KEYS_MAX):
        clock[0] += 0.001
        ec.mint_embed_key("serial")
    assert len(ec.app.keys) == embed.KEYS_MAX
    hosts.mirror = True
    assert bare(ec, "GET", f"/embed/mirror/{KEY}/{first}/status.json").status == 404


def test_the_key_check_compares_in_constant_time_against_every_kept_digest():
    import hmac
    seen = []
    keys = embed.Keys(lambda ref: True)
    first = keys.mint("ref", "mirror", KEY)                    # the key that would be found first in the list
    for _ in range(5):
        keys.mint("ref", "mirror", KEY)
    real = hmac.compare_digest
    try:
        hmac.compare_digest = lambda a, b: seen.append(1) or real(a, b)
        assert keys.check(first, "mirror", KEY) is True
        assert len(seen) == 6                                  # a hit on the first of six still compared all six: no early exit
        seen.clear()
        assert keys.check("A" * 43, "mirror", KEY) is False
        assert len(seen) == 6
    finally:
        hmac.compare_digest = real


def test_a_post_needs_a_null_or_the_consoles_own_origin_and_no_other(ec, hosts, viewer):
    hosts.mirror = True
    path = f"{ec.embed('mirror')}/input"
    assert bare(ec, "POST", path, raw=b"{}", headers={"Origin": "https://evil.example"}).status == 403
    assert bare(ec, "POST", path, raw=b"{}", headers={"Origin": "https://evil.example"}).json() == {"error": "cross_site_refused"}
    assert ec.request("POST", path, raw=b"{}", csrf=False, origin=False).status == 403          # no Origin at all
    assert viewer.requests == []
    assert bare(ec, "POST", path, raw=b'{"events":[]}').status == 200                            # the opaque frame: Origin null, cross-site metadata
    assert ec.request("POST", path, raw=b'{"events":[]}', csrf=False).status == 200              # the console's own origin (a tab of the page)


def test_a_key_authed_embed_path_answers_cors_without_credentials_and_nothing_else_does(ec, hosts, viewer):
    hosts.mirror = hosts.terminal = True
    base = ec.embed("mirror")
    pre = bare(ec, "OPTIONS", f"{base}/input", headers={"Access-Control-Request-Method": "POST", "Access-Control-Request-Headers": "content-type"})
    assert pre.status == 204 and pre.headers["Access-Control-Allow-Origin"] == "*" and "POST" in pre.headers["Access-Control-Allow-Methods"]
    assert "content-type" in pre.headers["Access-Control-Allow-Headers"].lower() and "last-event-id" in pre.headers["Access-Control-Allow-Headers"].lower()
    assert pre.data == b"" and viewer.requests == []                              # a preflight is answered here, never relayed
    for r in (pre, bare(ec, "GET", f"{base}/status.json"), bare(ec, "POST", f"{base}/input", raw=b'{"events":[]}'), bare(ec, "GET", f"{base}/nope"),
              bare(ec, "POST", f"{base}/input", raw=b"x" * (embed.MAX_BODY + 1))):
        assert r.headers["Access-Control-Allow-Origin"] == "*" and "Access-Control-Allow-Credentials" not in r.headers
    assert bare(ec, "OPTIONS", f"{base}/media.json").status == 404               # a route the relay does not carry gets no preflight grant
    for other in ("/api/session", "/api/fleet", "/static/components.js", "/signin", "/", f"/server/{KEY}"):
        r = bare(ec, "GET", other)
        assert not [h for h in r.headers if h.lower().startswith("access-control-")], other      # the exact-Origin, cookie and CSRF rules stand elsewhere
        assert bare(ec, "OPTIONS", other).status == 501, other
    r = ec.post("/api/call", {"tool": "amt_status", "arguments": {"device": KEY}}, headers={"Origin": "null"}, origin=False)
    assert r.status == 403 and "Access-Control-Allow-Origin" not in r.headers


def test_the_host_header_is_still_checked_on_the_embed_paths(ec, hosts, viewer):
    hosts.mirror = True
    for method in ("GET", "POST", "OPTIONS"):
        r = bare(ec, method, f"{ec.embed('mirror')}/status.json" if method != "POST" else f"{ec.embed('mirror')}/input", headers={"Host": "evil.example"}, raw=b"{}" if method == "POST" else None)
        assert r.status == 421, method
    assert viewer.requests == []


def test_an_unknown_server_or_kind_is_refused_before_anything_is_asked(ec, hosts, viewer):
    hosts.mirror = True
    key = ec.embed("mirror").rsplit("/", 1)[1]
    assert ec.get("/embed/mirror/nonesuch/").status == 404
    assert bare(ec, "GET", f"/embed/mirror/nonesuch/{key}/status.json").status == 404
    assert bare(ec, "GET", f"/embed/kvm/{KEY}/{key}/status.json").status == 404
    assert bare(ec, "GET", f"/embed/mirror/Bad_Key/{key}/status.json").status == 404
    assert ec.get("/api/embed/mirror/nonesuch").status == 404
    assert viewer.requests == [] and not [c for c in hosts.fake.calls if c[0] == "amt_mirror_link"]
    r = bare(ec, "GET", ec.embed("mirror"))                                      # a missing slash is a 404, not a redirect that would repeat the key
    assert (r.status, r.json()) == (404, {"error": "not_found"}) and "Location" not in r.headers


# -- not live, not reachable, restarted, down ---------------------------------------------------------------------------------

def test_no_session_is_a_409_for_every_route(ec, hosts, viewer):
    for path in (f"{ec.embed('mirror')}/", f"{ec.embed('mirror')}/status.json", f"{ec.embed('serial')}/events"):
        r = ec.get(path)
        assert (r.status, r.json()["error"]) == (409, "session_not_live"), path
    assert viewer.requests == []
    assert ec.get(f"/api/embed/mirror/{KEY}").json() == {"live": False, "reachable": False, "key_live": True}


def test_an_agents_session_on_the_default_bind_is_not_reachable_from_here(ec, hosts, viewer):
    hosts.mirror = True
    hosts.reachable = False
    r = ec.get(f"{ec.embed('mirror')}/")
    assert (r.status, r.json()) == (409, {"error": "viewer_not_reachable", "bind": "127.0.0.1"})
    st = ec.get(f"/api/embed/mirror/{KEY}").json()
    assert st["live"] is True and st["reachable"] is False and st["bind"] == "127.0.0.1" and "urls" not in st and "control_urls" not in st
    assert viewer.requests == []


@pytest.mark.parametrize("url", ["https://elsewhere.example.test/m/VWRctrlM-Sentinel-0123456789abcdefghij/", "http://127.0.0.1:1/m/VWRctrlM-Sentinel-0123456789abcdefghij/",
                                 "ftp://x/m/VWRctrlM-Sentinel-0123456789abcdefghij/", "{viewer}/m/short/", "{viewer}/s/VWRctrlM-Sentinel-0123456789abcdefghij/",
                                 "{viewer}/m/VWRctrlM-Sentinel-0123456789abcdefghij/extra", "{viewer}/m/VWRctrlM-Sentinel-0123456789abcdefghij/?x=1",
                                 "http://u:p@{host}/m/VWRctrlM-Sentinel-0123456789abcdefghij/"])
def test_only_a_control_url_on_the_viewer_front_is_ever_relayed(ec, hosts, viewer, url):
    hosts.mirror = True
    bad = url.replace("{viewer}", viewer.base).replace("{host}", viewer.base.split("//")[1])
    hosts.view = lambda prefix, bad=bad: {**viewer.status[prefix], "urls": [], "control_urls": [bad]}
    r = ec.get(f"{ec.embed('mirror')}/")
    assert r.status == 409 and r.json()["error"] == "viewer_not_reachable"
    assert viewer.requests == []


def test_a_restarted_session_gets_a_fresh_lookup_after_one_404_and_the_old_tokens_are_not_retried(ec, hosts, viewer):
    hosts.mirror = True
    assert ec.get(f"{ec.embed('mirror')}/status.json").status == 200
    old = viewer.control["m"]
    viewer.rotate("m")
    r = ec.get(f"{ec.embed('mirror')}/status.json")
    assert r.status == 200
    paths = viewer.seen()
    assert paths == [f"/m/{old}/status.json?embed=1", f"/m/{old}/status.json?embed=1", f"/m/{viewer.control['m']}/status.json?embed=1"]
    assert old != viewer.control["m"]


def test_a_target_is_reused_until_its_ttl_and_a_stop_or_start_through_the_console_forgets_it(ec, hosts, viewer):
    hosts.mirror = True
    for _ in range(3):
        ec.get(f"{ec.embed('mirror')}/status.json")
    assert len([c for c in hosts.fake.calls if c[0] == "amt_mirror_link"]) == 1            # one status call, not one per sub-resource
    ec.post("/api/call", {"tool": "amt_mirror_link", "arguments": {"device": KEY, "action": "stop", "confirmed": True}})
    assert ec.app.embed._targets == {}
    hosts.fake.calls.clear()
    assert ec.get(f"{ec.embed('mirror')}/status.json").json()["error"] == "session_not_live"


def test_a_viewer_that_is_down_is_a_502_with_a_fixed_code(ec, hosts, viewer):
    hosts.mirror = True
    viewer.close()
    r = ec.get(f"{ec.embed('mirror')}/status.json")
    assert (r.status, r.json()) == (502, {"error": "viewer_unreachable"})


def test_a_viewer_server_error_is_a_502_here_and_a_client_error_keeps_its_code(ec, hosts, viewer):
    hosts.mirror = True
    for code in (500, 503):
        viewer.force = (code, b"viewer broke")
        assert ec.get(f"{ec.embed('mirror')}/status.json").status == 502
    viewer.force = (403, b"embed_mode: not available")
    r = ec.get(f"{ec.embed('mirror')}/status.json")
    assert r.status == 403 and r.data == b"embed_mode: not available"


def test_a_refusal_from_the_viewer_is_cut_to_2000_bytes_and_a_good_answer_is_not(ec, hosts, viewer):
    hosts.mirror = True
    viewer.force = (403, b"x" * 5000)
    assert len(ec.get(f"{ec.embed('mirror')}/status.json").data) == 2000
    viewer.force = (500, b"y" * 5000)
    assert len(ec.get(f"{ec.embed('mirror')}/status.json").data) == 2000
    viewer.force = (200, b"z" * 5000)
    assert len(ec.get(f"{ec.embed('mirror')}/status.json").data) == 5000


def test_a_viewer_redirect_is_not_followed_or_passed_on(ec, hosts, viewer):
    hosts.mirror = True
    ec.get(f"{ec.embed('mirror')}/status.json")
    real = viewer.control["m"]
    ec.app.embed._targets[("mirror", KEY)] = (embed.Target(f"/m/{real}", frozenset({real})), 1e12)     # no trailing slash: the viewer answers 301
    r = ec.get(f"{ec.embed('mirror')}/")
    assert r.status == 502 and r.json()["error"] == "viewer_redirected" and "Location" not in r.headers


def test_a_status_amt_mcp_cannot_give_is_reported_by_code(ec, hosts, viewer, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: tool_error("Error executing tool amt_mirror_link: wsman_auth_failed_401 " + viewer.url("m"))
    r = ec.get(f"/api/embed/mirror/{KEY}")
    assert r.status == 502 and r.json()["error"] == "status_unreadable"
    assert viewer.CONTROL["m"] not in r.text and "wsman_auth_failed_401" in r.text         # the tool's words, with any viewer url masked


def test_a_missing_bearer_is_a_fixed_code(tmp_path, fake_amt, viewer, hosts):
    c = Console(tmp_path, fake_amt, viewer_origin=viewer.base, fleet_poll=False, secrets_cli=str(tmp_path / "nope.py"))
    try:
        enroll_first_passkey(c, Authenticator(c.app.cfg.rp_id, c.origin))
        c.app.fleet.devices = {KEY: device()}
        c.app.fleet.devices_at = 1.0
        r = c.get(f"/api/embed/mirror/{KEY}")
        assert (r.status, r.json()["error"]) == (503, "console_bearer_unavailable")
    finally:
        c.close()


# -- streams pass through while they are open, and end when the browser goes ---------------------------------------------------

def test_the_mjpeg_stream_arrives_while_the_viewer_still_holds_it_open(ec, hosts, viewer):
    hosts.mirror = True
    conn, resp, first = stream_head(ec, f"{ec.embed('mirror')}/stream")
    try:
        assert resp.status == 200 and resp.getheader("Content-Type") == "multipart/x-mixed-replace; boundary=frame"
        assert resp.getheader("Content-Length") is None and resp.getheader("X-Accel-Buffering") == "no"
        assert first.startswith(b"--frame") and not viewer.hold.is_set()              # a frame came through while the stream is open upstream
        assert "frame-ancestors 'self'" in resp.getheader("Content-Security-Policy")
    finally:
        conn.close()


def test_the_serial_event_stream_carries_the_terminal_output_and_the_page_keeps_it_text(ec, hosts, viewer):
    hosts.terminal = True
    conn, resp, first = stream_head(ec, f"{ec.embed('serial')}/events", want=4)
    try:
        assert resp.getheader("Content-Type") == "text/event-stream" and b"retry: 2000" in first
    finally:
        conn.close()


def test_a_stream_the_browser_drops_is_closed_upstream(ec, hosts, viewer, monkeypatch):
    monkeypatch.setattr(embed, "RELAY_IDLE", 0.2)
    hosts.mirror = True
    conn, resp, first = stream_head(ec, f"{ec.embed('mirror')}/stream")
    assert first.startswith(b"--frame")
    resp.close()                                                       # the response holds the socket too: both go
    conn.close()
    assert viewer.upstream_closed.wait(10), "the viewer's stream stayed open after the browser went away"


def read_to_end(conn, resp, seconds):
    """Read a stream until it ends or `seconds` pass: (ended, bytes read). Still open when the time is up means not ended."""
    got, end = b"", time.monotonic() + seconds
    while time.monotonic() < end:
        try:
            chunk = resp.read1(65536)
        except TimeoutError:
            continue
        except (OSError, http.client.HTTPException):
            return True, got
        if not chunk:
            return True, got
        got += chunk
    return False, got


@pytest.mark.parametrize("chatter", [False, True], ids=["quiet-stream", "busy-stream"])
def test_a_stream_already_open_ends_when_its_key_is_revoked_at_sign_out(ec, hosts, viewer, monkeypatch, chatter):
    """Sprint review (B1 follow-up): a key checked once at the start let an open stream keep relaying the host's screen after sign-out. The relay now
    re-asks the key every KEY_RECHECK seconds, whether the viewer is quiet or busy (a busy one never reaches the idle tick)."""
    monkeypatch.setattr(embed, "KEY_RECHECK", 0.2)
    hosts.mirror = True
    viewer.chatter = chatter
    base = ec.embed("mirror")
    conn, resp, first = stream_head(ec, f"{base}/stream", timeout=0.3)
    try:
        assert first.startswith(b"--frame")
        assert ec.post("/auth/signout").status == 200
        ended, _ = read_to_end(conn, resp, 10)
        assert ended, "the stream stayed open after its key was revoked"
        assert viewer.upstream_closed.wait(10), "the viewer's stream stayed open upstream after its key was revoked"
        assert bare(ec, "GET", f"{base}/status.json").status == 404
    finally:
        conn.close()


def test_a_stream_already_open_ends_when_its_session_idles_out(ec, hosts, viewer, monkeypatch):
    monkeypatch.setattr(embed, "KEY_RECHECK", 0.2)
    hosts.terminal = True
    conn, resp, first = stream_head(ec, f"{ec.embed('serial')}/events", want=4, timeout=0.3)
    try:
        assert b"retry: 2000" in first
        ec.app.auth.now = lambda: time.time() + ec.app.auth.idle_seconds + 5
        ended, _ = read_to_end(conn, resp, 10)
        assert ended and viewer.upstream_closed.wait(10)
    finally:
        conn.close()


def test_a_stream_whose_key_stays_live_is_not_cut_by_the_recheck(ec, hosts, viewer, monkeypatch):
    """The control: the recheck must not end a healthy stream (it counts as a use of the key, so the key's own idle limit does not cut it)."""
    monkeypatch.setattr(embed, "KEY_RECHECK", 0.1)
    hosts.mirror = True
    viewer.chatter = True
    conn, resp, first = stream_head(ec, f"{ec.embed('mirror')}/stream", timeout=0.3)
    try:
        ended, got = read_to_end(conn, resp, 1.5)
        assert not ended and len(got) > 50 and not viewer.upstream_closed.is_set()
    finally:
        conn.close()


# -- the token rule: no response, header, log line, exception or file holds it -------------------------------------------------

def scenario(ec, hosts, viewer):
    """Everything the browser can do with the embeds, as (where, text) pairs; the viewer's own status carries a one-time url."""
    hosts.mirror = hosts.terminal = True
    viewer.status["m"]["last_recording"] = {"path": "/r/x.mp4", "encoding": "done", "url": f"https://amt.example.test/handoffs/{'H' * 43}", "sha256": "0" * 64}
    seen = []

    def take(where, r):
        seen.append((where, r.text + repr(sorted(r.headers.items()))))
        return r
    for path in (f"{ec.embed('mirror')}/", f"{ec.embed('mirror')}/status.json", f"{ec.embed('mirror')}/frame.jpg", f"{ec.embed('serial')}/", f"{ec.embed('serial')}/status.json",
                 f"{ec.embed('serial')}/xterm.css", f"/api/embed/mirror/{KEY}", f"/api/embed/serial/{KEY}", f"/api/server/{KEY}", f"/server/{KEY}/console", f"/server/{KEY}/serial",
                 f"{ec.embed('mirror')}/power.json", f"{ec.embed('mirror')}/..", f"{ec.embed('mirror')}"):
        take(path, ec.get(path))
    for path in (f"{ec.embed('mirror')}/input", f"{ec.embed('mirror')}/record?on=1", f"{ec.embed('serial')}/input", f"{ec.embed('mirror')}/power"):
        take("POST " + path, ec.request("POST", path, raw=b'{"events":[],"data":"x"}', csrf=False))
    conn, resp, first = stream_head(ec, f"{ec.embed('mirror')}/stream")
    seen.append(("stream", repr(sorted(resp.getheaders())) + first.decode("latin-1")))
    conn.close()
    hosts.reachable = False
    take("unreachable page", ec.get(f"{ec.embed('mirror')}/"))
    take("unreachable state", ec.get(f"/api/embed/mirror/{KEY}"))
    hosts.reachable = True
    viewer.rotate("m")
    take("after restart", ec.get(f"{ec.embed('mirror')}/status.json"))
    viewer.hold.set()
    viewer.httpd.shutdown(); viewer.httpd.server_close()
    take("viewer down", ec.get(f"{ec.embed('mirror')}/status.json"))
    take("viewer down page", ec.get(f"{ec.embed('serial')}/"))
    return seen


def leaks(ec, hosts, viewer, seen, records):
    tokens = all_tokens(viewer) + ec.minted_keys                # the viewer's tokens and every embed key the scenario minted
    fmt = logging.Formatter()
    found = [where for where, text in seen if any(t in text for t in tokens)]
    found += ["log" for r in records if any(t in fmt.format(r) for t in tokens)]
    found += ["upstream request" for _, path, hdrs, body in viewer.requests if any(k in path + repr(hdrs) + body.decode("latin-1") for k in ec.minted_keys)]
    found += ["amt-mcp request" for _, path, _ in hosts.fake.requests if any(k in path for k in ec.minted_keys)]
    found += ["data folder" for f in ec.data.rglob("*") if f.is_file() and any(t.encode() in f.read_bytes() for t in tokens)]
    found += ["one-time handoff url" for where, text in seen if "H" * 43 in text]
    return found


def test_the_viewer_token_is_in_no_response_header_log_line_exception_or_file(ec, hosts, viewer, caplog):
    caplog.set_level(logging.DEBUG)
    seen = scenario(ec, hosts, viewer)
    assert len(seen) > 20 and any(w == "stream" for w, _ in seen) and any(w == "viewer down" for w, _ in seen)
    assert hosts.viewer.requests, "the viewer was never asked: the scan would pass on an empty run"
    assert leaks(ec, hosts, viewer, seen, caplog.records) == []
    # the tokens DID reach the console (amt-mcp's status result carries them), which is what makes the scan meaningful
    assert any(viewer.CONTROL["m"] in str(path) for _, path, _, _ in viewer.requests)


@pytest.mark.parametrize("path,masked", [
    ("/embed/mirror/my-server-1/" + "A" * 43 + "/status.json", "/embed/mirror/my-server-1/<key>/status.json"),
    ("/embed/serial/my-server-1/" + "a_-" * 14 + "ab/", "/embed/serial/my-server-1/<key>/"),
    ("/embed/mirror/my-server-1/" + "A" * 43, "/embed/mirror/my-server-1/<key>"),
    ("/embed/mirror/my-server-1/" + "A" * 50 + "/stream", "/embed/mirror/my-server-1/<key>/stream"),      # a near miss of a real key is masked too
    ("/embed/mirror/my-server-1/" + "A" * 43 + ".", "/embed/mirror/my-server-1/<key>."),                  # a key with a stray suffix (final review)
    ("/embed/mirror/my-server-1/" + "A" * 43 + "%2Fstatus.json", "/embed/mirror/my-server-1/<key>%2Fstatus.json"),
    ("/embed/mirror/my-server-1/" + "A" * 43 + "~", "/embed/mirror/my-server-1/<key>~"),
    ("/embed/mirror/my-server-1/", "/embed/mirror/my-server-1/"),
    ("/api/embed/mirror/my-server-1", "/api/embed/mirror/my-server-1"),
])
def test_loggable_masks_an_embed_key_wherever_it_sits_in_the_path(path, masked):
    assert server.loggable(path) == masked


@pytest.mark.parametrize("suffix", [".", "%2Fstatus.json", "%2e%2e/", "~", "x.y"])
def test_a_real_key_with_a_stray_suffix_is_refused_and_never_logged(ec, hosts, caplog, suffix):
    """The access log line of the 404 that refuses a keyed path with a stray suffix must not hold the key (final review, finding 2)."""
    caplog.set_level(logging.DEBUG)
    hosts.mirror = True
    base = ec.embed("mirror")
    key = base.rsplit("/", 1)[1]
    assert bare(ec, "GET", f"{base}{suffix}").status == 404
    lines = [logging.Formatter().format(r) for r in caplog.records]
    assert any("<key>" in line for line in lines), lines                    # the refusal was logged, masked: the scan is not vacuous
    assert not [line for line in lines if key in line], lines


def test_a_session_view_s_own_error_is_masked_on_every_route(ec, hosts, viewer):
    """The viewer's status error (a session view's ``error``) reaches /api/embed, /api/server and /api/fleet masked (final review, finding 1)."""
    viewer_token, handoff_token = "Vw" + "9" * 30, "Hq" + "7" * 41
    urls = f"https://amt-viewer.example.test/m/{viewer_token}/ and https://amt.example.test/handoffs/{handoff_token}"
    hosts.mirror = hosts.terminal = True
    viewer.status["m"]["error"] = f"ConnectionError: see {urls}"
    viewer.status["s"]["error"] = f"OSError: see {urls}"
    ec.app.fleet.step()
    texts = {path: ec.get(path).text for path in (f"/api/embed/mirror/{KEY}", f"/api/embed/serial/{KEY}", f"/api/server/{KEY}", "/api/fleet")}
    assert "ConnectionError" in texts[f"/api/embed/mirror/{KEY}"] and "OSError" in texts[f"/api/embed/serial/{KEY}"]   # the field is there
    for path, text in texts.items():
        assert viewer_token not in text and handoff_token not in text, path


def test_the_embed_key_is_in_no_log_line_even_a_refusal_or_a_fault(ec, hosts, viewer, caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    hosts.mirror = True
    base = ec.embed("mirror")
    key = base.rsplit("/", 1)[1]
    bare(ec, "GET", f"{base}/status.json")
    bare(ec, "POST", f"{base}/input", raw=b"{}", headers={"Origin": "https://evil.example"})           # the refusal logs its path
    bare(ec, "GET", f"/embed/mirror/{KEY}/{key[:-1]}Z/status.json")                                       # a wrong key
    monkeypatch.setattr(ec.app.embed, "open", lambda *a, **k: 1 / 0)
    assert bare(ec, "GET", f"{base}/status.json").status == 500                                           # the fault logs its path
    lines = [logging.Formatter().format(r) for r in caplog.records]
    assert not [line for line in lines if key in line], lines
    assert any("/embed/mirror/my-server-1/<key>/status.json" in line for line in lines)
    assert any("cross-site POST refused" in line and "<key>" in line for line in lines)
    assert any("handler fault ZeroDivisionError" in line for line in lines)
    assert all(key not in str(r.args) and key not in str(r.msg) for r in caplog.records)


def test_the_scan_catches_a_planted_embed_key_leak(ec, hosts, viewer, caplog, monkeypatch):
    """Positive control for the key: a debug line that prints it, and an upstream request that carries it, are both reported."""
    caplog.set_level(logging.DEBUG)
    real = ec.app.embed.open

    def noisy(kind, key, method, rest, **kw):
        server.log.error("debug dump %s", ec.minted_keys[0])
        return real(kind, key, method, rest, **kw)
    monkeypatch.setattr(ec.app.embed, "open", noisy)
    real_target = ec.app.embed.target

    def keyed(kind, key, fresh=False):
        t = real_target(kind, key, fresh)
        return embed.Target(t.path + "?leak=" + ec.minted_keys[0], t.tokens)
    monkeypatch.setattr(ec.app.embed, "target", keyed)
    found = leaks(ec, hosts, viewer, scenario(ec, hosts, viewer), caplog.records)
    assert "log" in found and "upstream request" in found


def test_the_scan_catches_a_planted_token_leak(ec, hosts, viewer, caplog, monkeypatch):
    """Positive control: with the masking switched off and a debug line that prints a session token, the same scan reports both."""
    caplog.set_level(logging.DEBUG)
    monkeypatch.setattr(embed, "mask", lambda data, tokens, ctype: data)
    viewer.status["m"]["leak"] = viewer.control["m"]
    real = ec.app.embed.target

    def noisy(kind, key, fresh=False):
        t = real(kind, key, fresh)
        server.log.error("debug dump %s", t.path)
        return t
    monkeypatch.setattr(ec.app.embed, "target", noisy)
    found = leaks(ec, hosts, viewer, scenario(ec, hosts, viewer), caplog.records)
    assert "log" in found and any(f.startswith("/embed/mirror") for f in found)


def test_text_from_the_viewer_has_its_tokens_and_one_time_urls_replaced(ec, hosts, viewer):
    hosts.mirror = True
    viewer.status["m"].update(leak=f"{viewer.base}/m/{viewer.view['m']}/", other=f"see {viewer.control['m']} and /handoffs/{'Z' * 43}")
    body = ec.get(f"{ec.embed('mirror')}/status.json").text
    assert viewer.control["m"] not in body and viewer.view["m"] not in body and "Z" * 43 not in body
    assert "[withheld]" in body and "[one-time url withheld]" in body
    assert json.loads(body)["fps"] == 15                                      # the rest of the document is untouched


def test_the_page_state_route_gives_the_whitelisted_view_and_never_a_url(ec, hosts, viewer):
    hosts.mirror = True
    viewer.status["m"]["in_flight"] = {"tool": "amt_console_input", "started_at": 1_760_000_000.5, "arguments": "SECRET-ARGUMENTS"}
    st = ec.get(f"/api/embed/mirror/{KEY}").json()
    assert st["live"] and st["reachable"] and st["viewer_host"] == "127.0.0.1"
    assert st["in_flight"] == {"tool": "amt_console_input", "started_at": 1_760_000_000.5} and "SECRET-ARGUMENTS" not in json.dumps(st)
    assert (st["width"], st["height"], st["fps"]) == (640, 400, 15)
    assert not any(t in json.dumps(st) for t in all_tokens(viewer))


# -- the fleet sees a start or stop made through the console at once --------------------------------------------------------

def test_a_start_and_a_stop_through_the_console_are_visible_to_the_page_without_waiting_for_the_schedule(ec, hosts, viewer):
    ec.app.fleet.refresh_devices()
    ec.app.fleet.refresh(KEY)
    assert ec.app.fleet.public(KEY)["sessions"]["kvm"] == {"holder": "free"}
    start = {"device": KEY, "action": "start", "bind": "0.0.0.0", "port": 8766, "fps": 15, "quality": 70, "record_on_start": False, "confirmed": True}
    assert ec.post("/api/call", {"tool": "amt_mirror_link", "arguments": start}).json()["isError"] is False
    assert ec.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "console"
    assert ec.post("/api/call", {"tool": "amt_mirror_link", "arguments": {"device": KEY, "action": "stop"}}).status == 200
    assert ec.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "free"


def test_a_refused_start_does_not_read_the_session_views_again(ec, hosts, viewer, fake_amt):
    ec.app.fleet.refresh_devices()
    ec.app.fleet.refresh(KEY)
    fake_amt.results["amt_mirror_link"] = lambda a: tool_error("redir_start_status_1: another session is open")
    before = len(fake_amt.calls)
    start = {"device": KEY, "action": "start", "bind": "0.0.0.0", "port": 8766, "confirmed": True}
    ec.post("/api/call", {"tool": "amt_mirror_link", "arguments": start})
    assert [t for t, _, _ in fake_amt.calls[before:]] == ["amt_mirror_link"]
    assert ec.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "other"


class _Resp:
    """A stand-in upstream response: the given chunks, then end-of-stream (or a long quiet when ``hang``)."""

    def __init__(self, chunks, hang=False):
        self.chunks, self.hang = list(chunks), hang

    def read1(self, n):
        if self.chunks:
            return self.chunks.pop(0)
        if self.hang:
            time.sleep(0.2)
            return b"x"
        return b""


@pytest.mark.parametrize("resp,gone,alive,why", [
    (_Resp([b"a", b"b"]), False, True, "upstream_ended"),
    (_Resp([], hang=True), True, True, "browser_gone"),
    (_Resp([b"a"], hang=True), False, False, "key_dead"),
])
def test_the_relay_says_why_a_stream_ended(resp, gone, alive, why):
    """The relay returns its reason, and the server logs it (``embed stream ended <why>``): a stream that ends early names its cause."""
    got = []
    up = embed.Upstream(resp, 200, "multipart/x-mixed-replace", (), True)
    assert up.relay(got.append, lambda: gone, idle=0.05, alive=lambda: alive, recheck=0.05) == why
    if why == "upstream_ended":
        assert got == [b"a", b"b"]
