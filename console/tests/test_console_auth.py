"""Passkey enrollment, sign-in, sessions, CSRF and the framing headers, against a running console and a
software authenticator."""
import hashlib
import json
import logging
import re
import time

import pytest

import webauthn_min as wa
from console_fakes import Authenticator, enroll_first_passkey

CSP_PREFIX = "default-src 'self'; frame-src 'self'; frame-ancestors 'none'"


def test_enrollment_with_the_code_signs_in_and_consumes_it(console, authn):
    reply = enroll_first_passkey(console, authn)
    assert not (console.data / "enroll.json").exists()                 # consumed on the first enrollment
    cookie = reply.headers["Set-Cookie"]
    assert re.fullmatch(r"amt_console_session=[A-Za-z0-9_-]{43}; Path=/; Secure; HttpOnly; SameSite=Strict", cookie)
    assert console.get("/api/session").status == 200
    assert [p["name"] for p in console.get("/api/passkeys").json()["passkeys"]] == ["Test key"]


def test_the_session_store_holds_a_hash_never_the_cookie(console, authn):
    enroll_first_passkey(console, authn)
    stored = (console.data / "sessions.json").read_text()
    assert console.cookie not in stored and hashlib.sha256(console.cookie.encode()).hexdigest() in stored
    for name in ("passkeys.json", "sessions.json"):
        assert oct((console.data / name).stat().st_mode & 0o777) == "0o600"
    assert oct(console.data.stat().st_mode & 0o777) == "0o700"


def test_a_used_code_cannot_enroll_again(console, authn):
    enroll_first_passkey(console, authn)
    again = console.post("/auth/enroll/options", {"code": "ABCD-EFGH-JKMN", "name": "Second"}, cookie=False)
    assert again.status == 400 and again.json()["error"] == "enroll_not_open"


def test_code_is_accepted_in_any_case_and_with_or_without_dashes(console, authn):
    enroll_first_passkey(console, authn, code="ABCD-EFGH-JKMN")
    # a second console data folder is not needed: re-arm the code and try the lowercase, undashed form
    (console.data / "enroll.json").write_text(json.dumps({"sha256": hashlib.sha256(b"ABCDEFGHJKMN").hexdigest(), "expires": int(time.time()) + 600}))
    assert console.post("/auth/enroll/options", {"code": "abcdefghjkmn", "name": "Second"}, cookie=False).status == 200


def test_wrong_code_is_refused_and_five_wrong_codes_withdraw_it(console, authn):
    console.data.mkdir(parents=True, exist_ok=True)
    digest = hashlib.sha256(b"ABCDEFGHJKMN").hexdigest()
    (console.data / "enroll.json").write_text(json.dumps({"sha256": digest, "expires": int(time.time()) + 600}))
    for _ in range(4):
        r = console.post("/auth/enroll/options", {"code": "AAAA-AAAA-AAAA", "name": "x"}, cookie=False)
        assert (r.status, r.json()["error"]) == (400, "enroll_code_wrong")
    last = console.post("/auth/enroll/options", {"code": "AAAA-AAAA-AAAA", "name": "x"}, cookie=False)
    assert (last.status, last.json()["error"]) == (429, "enroll_locked")
    assert not (console.data / "enroll.json").exists()                 # a guessed-at code is dead
    right = console.post("/auth/enroll/options", {"code": "ABCD-EFGH-JKMN", "name": "x"}, cookie=False)
    assert right.json()["error"] == "enroll_not_open"


def test_an_expired_code_is_refused_and_removed(console):
    console.data.mkdir(parents=True, exist_ok=True)
    (console.data / "enroll.json").write_text(json.dumps({"sha256": hashlib.sha256(b"ABCDEFGHJKMN").hexdigest(), "expires": int(time.time()) - 1}))
    r = console.post("/auth/enroll/options", {"code": "ABCD-EFGH-JKMN", "name": "x"}, cookie=False)
    assert (r.status, r.json()["error"]) == (400, "enroll_code_expired")
    assert not (console.data / "enroll.json").exists()


@pytest.mark.parametrize("content", ['{"sha256": "not-hex", "expires": 9999999999}', "not json", '{"expires": 1}'])
def test_a_malformed_enroll_file_is_not_an_open_enrollment(console, content):
    console.data.mkdir(parents=True, exist_ok=True)
    (console.data / "enroll.json").write_text(content)
    r = console.post("/auth/enroll/options", {"code": "ABCD-EFGH-JKMN", "name": "x"}, cookie=False)
    assert r.status in (400, 500) and r.json().get("error") != "ok"
    assert r.json()["error"] == "enroll_not_open"


def test_enrollment_challenge_is_one_time(console, authn):
    console.data.mkdir(parents=True, exist_ok=True)
    (console.data / "enroll.json").write_text(json.dumps({"sha256": hashlib.sha256(b"ABCDEFGHJKMN").hexdigest(), "expires": int(time.time()) + 600}))
    opts = console.post("/auth/enroll/options", {"code": "ABCD-EFGH-JKMN", "name": "x"}, cookie=False).json()
    reg = authn.register(opts)
    bad = dict(reg, attestationObject=reg["attestationObject"][:-4])    # a failed attempt still burns the challenge
    assert console.post("/auth/enroll/verify", bad, cookie=False).status == 400
    replay = console.post("/auth/enroll/verify", reg, cookie=False)
    assert (replay.status, replay.json()["error"]) == (400, "challenge_unknown")
    assert (console.data / "enroll.json").exists()                       # nothing was consumed


def test_enrollment_fails_if_the_code_file_vanishes_before_the_passkey_is_stored(console, authn):
    console.data.mkdir(parents=True, exist_ok=True)
    (console.data / "enroll.json").write_text(json.dumps({"sha256": hashlib.sha256(b"ABCDEFGHJKMN").hexdigest(), "expires": int(time.time()) + 600}))
    opts = console.post("/auth/enroll/options", {"code": "ABCD-EFGH-JKMN", "name": "x"}, cookie=False).json()
    (console.data / "enroll.json").unlink()
    r = console.post("/auth/enroll/verify", authn.register(opts), cookie=False)
    assert (r.status, r.json()["error"]) == (400, "enroll_not_open")
    assert not console.app.auth.has_passkeys()


def test_a_challenge_issued_for_one_code_cannot_complete_a_newer_code(console, authn):
    """The code file was replaced (a new code minted) between the two calls: the old ceremony must not consume the new one."""
    console.data.mkdir(parents=True, exist_ok=True)
    enroll = console.data / "enroll.json"
    enroll.write_text(json.dumps({"sha256": hashlib.sha256(b"ABCDEFGHJKMN").hexdigest(), "expires": int(time.time()) + 600}))
    opts = console.post("/auth/enroll/options", {"code": "ABCD-EFGH-JKMN", "name": "x"}, cookie=False).json()
    newer = {"sha256": hashlib.sha256(b"PQRSTUVWXYZ2").hexdigest(), "expires": int(time.time()) + 600}
    enroll.write_text(json.dumps(newer))
    r = console.post("/auth/enroll/verify", authn.register(opts), cookie=False)
    assert (r.status, r.json()["error"]) == (400, "enroll_not_open")
    assert json.loads(enroll.read_text()) == newer and not console.app.auth.has_passkeys()


def test_a_registration_for_another_origin_or_without_user_verification_is_refused(console):
    console.data.mkdir(parents=True, exist_ok=True)
    for kw, why in (({"origin": "https://evil.example"}, "origin_mismatch"), ({"flags": 0x41}, "user_verification_required")):
        (console.data / "enroll.json").write_text(json.dumps({"sha256": hashlib.sha256(b"ABCDEFGHJKMN").hexdigest(), "expires": int(time.time()) + 600}))
        opts = console.post("/auth/enroll/options", {"code": "ABCD-EFGH-JKMN", "name": "x"}, cookie=False).json()
        r = console.post("/auth/enroll/verify", Authenticator(console.app.cfg.rp_id, console.origin).register(opts, **kw), cookie=False)
        assert r.status == 400 and r.json()["error"] == f"registration_refused:{why}"
        assert not console.app.auth.has_passkeys()


# -- sign-in ---------------------------------------------------------------------------------------------------

def signin(console, authn, **kw):
    opts = console.post("/auth/signin/options", cookie=False).json()
    return console.post("/auth/signin/verify", authn.assert_(opts, **kw), cookie=False)


def test_signin_with_an_enrolled_passkey(console, authn):
    enroll_first_passkey(console, authn)
    console.cookie = console.csrf = None
    r = signin(console, authn)
    assert r.status == 200 and "Secure; HttpOnly; SameSite=Strict" in r.headers["Set-Cookie"]
    console.adopt(r)
    assert console.get("/api/session").status == 200


def test_signin_options_ask_for_discoverable_user_verifying_passkeys(console):
    pk = console.post("/auth/signin/options", cookie=False).json()["publicKey"]
    assert pk["userVerification"] == "required" and pk["allowCredentials"] == [] and pk["rpId"] == console.app.cfg.rp_id


def test_an_unenrolled_passkey_is_refused_logs_its_id_only_and_sends_nothing(console, authn, fake_amt, caplog):
    enroll_first_passkey(console, authn)
    stranger = Authenticator(console.app.cfg.rp_id, console.origin)
    caplog.set_level(logging.INFO)
    r = signin(console, stranger)
    assert (r.status, r.json()["error"]) == (403, "passkey_not_enrolled")
    assert "Set-Cookie" not in r.headers and fake_amt.calls == []
    logged = " ".join(rec.getMessage() for rec in caplog.records)
    assert wa.b64u_encode(stranger.cred_id)[:22] in logged


@pytest.mark.parametrize("kw,why", [({"origin": "https://evil.example"}, "origin_mismatch"), ({"flags": 0x01}, "user_verification_required"),
                                    ({"rp_id": "evil.example"}, "rp_id_mismatch"), ({"typ": "webauthn.create"}, "wrong_ceremony_type")])
def test_signin_refusals_name_their_check_and_set_no_cookie(console, authn, kw, why):
    enroll_first_passkey(console, authn)
    r = signin(console, authn, **kw)
    assert r.status == 400 and r.json()["error"] == f"assertion_refused:{why}" and "Set-Cookie" not in r.headers


def test_signin_challenge_is_one_time(console, authn):
    enroll_first_passkey(console, authn)
    opts = console.post("/auth/signin/options", cookie=False).json()
    ass = authn.assert_(opts)
    assert console.post("/auth/signin/verify", ass, cookie=False).status == 200
    again = console.post("/auth/signin/verify", ass, cookie=False)
    assert (again.status, again.json()["error"]) == (400, "challenge_unknown")


def test_a_counter_that_does_not_advance_is_refused(console, authn):
    enroll_first_passkey(console, authn)
    assert signin(console, authn, count=7).status == 200
    assert signin(console, authn, count=7).status == 400
    assert signin(console, authn, count=3).status == 400
    assert signin(console, authn, count=8).status == 200


# -- sessions --------------------------------------------------------------------------------------------------

def test_a_session_idles_out_after_twelve_hours_and_says_so(console, authn):
    enroll_first_passkey(console, authn)
    start = time.time()
    console.app.auth.now = lambda: start + 12 * 3600 + 1
    r = console.get("/", headers={})
    assert r.status == 302 and r.headers["Location"] == "/signin?expired=1" and "Max-Age=0" in r.headers["Set-Cookie"]
    assert console.get("/api/session").status == 401
    page = console.get("/signin?expired=1", cookie=False).text
    assert "signed out after 12 hours idle" in page and "Nothing on the hosts changed" in page and "still held by amt-mcp" in page


def test_activity_keeps_a_session_alive(console, authn):
    enroll_first_passkey(console, authn)
    start = time.time()
    for hours in (11, 22, 33):
        console.app.auth.now = lambda h=hours: start + h * 3600
        assert console.get("/api/session").status == 200               # each visit restarts the idle clock


def test_signout_ends_the_session(console, authn):
    enroll_first_passkey(console, authn)
    cookie = console.cookie
    out = console.post("/auth/signout")
    assert out.status == 200 and "Max-Age=0" in out.headers["Set-Cookie"]
    console.cookie = cookie
    assert console.get("/api/session").status == 401
    assert console.get("/", cookie=True).headers["Location"] == "/signin"


def test_pages_need_a_session(console):
    for path in ("/", "/settings", "/manage", "/images"):
        r = console.get(path, cookie=False)
        assert (r.status, r.headers["Location"]) == (302, "/signin")
    for path in ("/api/session", "/api/passkeys", "/api/captures", "/captures/" + "a" * 22):
        assert console.get(path, cookie=False).status == 401


def test_the_shell_marks_the_current_section_and_every_section_is_built(signed_in):
    page = signed_in.get("/settings").text
    assert page.count('aria-current="page"') == 2                       # rail and bottom bar
    for label in ("Fleet", "Manage", "Images", "Settings"):
        assert label in page
    assert "Add a passkey" in page and 'id="passkey-list"' in page
    for path in ("/", "/manage", "/manage/identities", "/images", "/settings"):
        assert "built in a later step" not in signed_in.get(path).text, path


# -- CSRF, cross-site, framing ----------------------------------------------------------------------------------

def test_a_cross_site_post_is_refused_and_nothing_is_sent(signed_in, fake_amt):
    body = {"tool": "amt_status", "arguments": {"device": "my-server-1"}}
    for headers in ({"Origin": "https://evil.example"}, {"Sec-Fetch-Site": "cross-site"}, {"Sec-Fetch-Site": "same-site"}):
        r = signed_in.post("/api/call", body, headers=headers)
        assert (r.status, r.json()["error"]) == (403, "cross_site_refused")
    assert signed_in.post("/api/call", body, origin=False).status == 403   # a POST with no Origin at all
    assert fake_amt.calls == []
    # a cross-site sign-out must not end the session either
    assert signed_in.post("/auth/signout", headers={"Origin": "https://evil.example"}).status == 403
    assert signed_in.get("/api/session").status == 200


def test_a_same_origin_post_is_accepted(signed_in, fake_amt):
    r = signed_in.post("/api/call", {"tool": "amt_status", "arguments": {"device": "my-server-1"}}, headers={"Sec-Fetch-Site": "same-origin"})
    assert r.status == 200 and len(fake_amt.calls) == 1


def test_a_signed_in_post_without_the_csrf_token_is_refused(signed_in, fake_amt):
    body = {"tool": "amt_status", "arguments": {"device": "my-server-1"}}
    for csrf in (False, True):
        r = signed_in.post("/api/call", body, csrf=csrf, headers={} if not csrf else {"X-CSRF-Token": "x" * 32})
        assert (r.status, r.json()["error"]) == (403, "csrf_token_invalid")
    assert fake_amt.calls == []


def test_a_signed_out_post_to_a_signed_in_route_is_unauthorized(console, fake_amt):
    r = console.post("/api/call", {"tool": "amt_status", "arguments": {"device": "x"}}, cookie=False)
    assert r.status == 401 and fake_amt.calls == []


def test_a_foreign_host_header_is_refused(console):
    assert console.get("/signin", headers={"Host": "evil.example"}).status == 421
    assert console.post("/auth/signin/options", headers={"Host": "evil.example"}).status == 421


def test_post_bodies_must_be_json_objects_of_bounded_size(signed_in):
    assert signed_in.request("POST", "/api/call", None, raw=b"{}", headers={"Content-Type": "text/plain"}).status == 415
    assert signed_in.request("POST", "/api/call", None, raw=b"x" * (64 * 1024 + 1)).status == 413
    for bad in (signed_in.request("POST", "/api/call", [1, 2]), signed_in.request("POST", "/api/call", None, raw=b"{not json")):
        assert (bad.status, bad.json()["error"]) == (400, "bad_json")


def test_every_response_refuses_to_be_framed_and_carries_the_policy(signed_in):
    shots = signed_in.app.captures
    replies = [signed_in.get(p) for p in ("/signin", "/", "/settings", "/static/base.css", "/static/components.js", "/static/icons.svg",
                                          "/api/session", "/api/captures", "/nope", "/static/missing.css")]
    replies += [signed_in.get("/", cookie=False), signed_in.get("/api/session", cookie=False), signed_in.post("/auth/signin/options", cookie=False),
                signed_in.post("/api/call", {}, headers={"Origin": "https://evil.example"})]
    assert len(replies) >= 14
    for r in replies:
        h = r.headers
        assert h["Content-Security-Policy"].startswith(CSP_PREFIX), h
        assert h["X-Frame-Options"] == "DENY" and h["Referrer-Policy"] == "no-referrer" and h["X-Content-Type-Options"] == "nosniff"
        assert h["Cache-Control"] in ("no-store", "no-cache") and h["Cross-Origin-Opener-Policy"] == "same-origin"
        assert "frame-src 'self'" in h["Content-Security-Policy"] and "amt-viewer" not in h["Content-Security-Policy"]   # the viewer origin is never framed from the browser
    assert shots is not None


def test_static_files_are_a_whitelist(console):
    for path in ("/static/../server.py", "/static/%2e%2e/server.py", "/static/..%2fserver.py", "/static/", "/static/server.py",
                 "/static/theme.css/../auth.py", "/static/.hidden"):
        assert console.get(path).status == 404, path
    assert console.get("/static/theme.css").status == 200 and console.get("/static/theme.css").headers["Content-Type"].startswith("text/css")


# -- adding a passkey from a signed-in session -----------------------------------------------------------------

def test_add_a_passkey_from_a_signed_in_session(signed_in):
    second = Authenticator(signed_in.app.cfg.rp_id, signed_in.origin)
    opts = signed_in.post("/api/passkeys/options", {"name": "Phone"}).json()
    assert len(opts["publicKey"]["excludeCredentials"]) == 1             # the enrolled key is not offered again
    r = signed_in.post("/api/passkeys/verify", second.register(opts))
    assert r.status == 200 and r.json()["passkey"]["name"] == "Phone"
    names = [p["name"] for p in signed_in.get("/api/passkeys").json()["passkeys"]]
    assert names == ["Test key", "Phone"]
    assert "x" not in signed_in.get("/api/passkeys").json()["passkeys"][0]    # no key material in the list
    signed_in.cookie = signed_in.csrf = None
    assert signin(signed_in, second).status == 200                       # and the new key signs in


def test_add_a_passkey_needs_a_session_a_csrf_token_and_a_name(console, authn, signed_in):
    assert signed_in.post("/api/passkeys/options", {"name": ""}).json()["error"] == "bad_passkey_name"
    assert signed_in.post("/api/passkeys/options", {"name": "x" * 65}).status == 400
    assert signed_in.post("/api/passkeys/options", {"name": "ok"}, csrf=False).status == 403
    assert signed_in.post("/api/passkeys/options", {"name": "ok"}, cookie=False).status == 401


def test_the_same_passkey_cannot_be_added_twice(signed_in, authn):
    opts = signed_in.post("/api/passkeys/options", {"name": "Again"}).json()
    r = signed_in.post("/api/passkeys/verify", authn.register(opts))
    assert (r.status, r.json()["error"]) == (400, "passkey_already_enrolled")


def test_an_add_challenge_cannot_finish_an_enrollment(signed_in):
    other = Authenticator(signed_in.app.cfg.rp_id, signed_in.origin)
    opts = signed_in.post("/api/passkeys/options", {"name": "Phone"}).json()
    r = signed_in.post("/auth/enroll/verify", other.register(opts), cookie=False)
    assert (r.status, r.json()["error"]) == (400, "challenge_unknown")


def test_an_unexpected_fault_is_a_500_without_detail(signed_in, monkeypatch):
    monkeypatch.setattr(signed_in.app.auth, "passkeys", lambda: 1 / 0)
    r = signed_in.get("/api/passkeys")
    assert (r.status, r.json()) == (500, {"error": "internal"})


# -- the guards on the challenge store and the session file (a clock the test moves) ----------------------------------

@pytest.fixture()
def clock(console):
    now = [time.time()]
    console.app.auth.now = lambda: now[0]
    return now


def test_a_challenge_is_good_for_five_minutes_and_no_longer(console, authn, clock):
    enroll_first_passkey(console, authn)
    console.cookie = console.csrf = None
    opts = console.post("/auth/signin/options", cookie=False).json()
    clock[0] += 299
    assert console.post("/auth/signin/verify", authn.assert_(opts), cookie=False).status == 200      # inside the window
    opts = console.post("/auth/signin/options", cookie=False).json()
    clock[0] += 301
    late = console.post("/auth/signin/verify", authn.assert_(opts), cookie=False)
    assert (late.status, late.json()["error"]) == (400, "challenge_unknown")


def test_pending_challenges_are_capped_and_expiry_makes_room(console, clock):
    import auth
    for _ in range(auth.MAX_PENDING):
        assert console.post("/auth/signin/options", cookie=False).status == 200
    full = console.post("/auth/signin/options", cookie=False)
    assert (full.status, full.json()["error"]) == (429, "too_many_pending")
    clock[0] += 301                                                                                  # every one of them expired
    assert console.post("/auth/signin/options", cookie=False).status == 200


def test_an_expired_session_is_kept_as_a_tombstone_for_a_week_and_then_dropped(signed_in, clock):
    store = signed_in.app.auth
    key = hashlib.sha256(signed_in.cookie.encode()).hexdigest()
    sessions = lambda: json.loads((signed_in.data / "sessions.json").read_text())      # noqa: E731
    clock[0] += 13 * 3600
    assert store.lookup(signed_in.cookie) == ("expired", None)
    assert sessions()[key]["state"] == "expired"
    clock[0] += 6 * 86400                                                              # 6 days after it expired: still kept
    live_cookie, _ = store.new_session()
    live_key = hashlib.sha256(live_cookie.encode()).hexdigest()
    assert key in sessions() and live_key in sessions()
    clock[0] += 2 * 86400                                                              # 8 days: the tombstone goes, the live record stays
    store.new_session()
    assert key not in sessions() and live_key in sessions()


def test_the_enrollment_code_alphabet_and_length_match_the_admin_tool_that_mints_them():
    import importlib.util
    from pathlib import Path
    import auth
    spec = importlib.util.spec_from_file_location("amt_admin_pin", Path(__file__).resolve().parents[2] / "deploy" / "amt_admin.py")
    admin = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(admin)
    assert auth.ENROLL_ALPHABET == admin.ENROLL_ALPHABET and auth.ENROLL_LENGTH == admin.ENROLL_LENGTH
    assert len(set(auth.ENROLL_ALPHABET)) == len(auth.ENROLL_ALPHABET) == 31


# -- responses http.server writes itself carry the same headers; a request it rejects unparsed does not crash the handler --

def raw_exchange(console, data: bytes) -> bytes:
    import socket
    with socket.create_connection(("127.0.0.1", console.port), timeout=10) as s:
        s.sendall(data)
        s.shutdown(socket.SHUT_WR)
        out = b""
        while chunk := s.recv(65536):
            out += chunk
    return out


def test_a_request_line_rejected_before_it_is_parsed_gets_the_headers_and_a_log_line(console, caplog):
    caplog.set_level(logging.INFO, logger="amt_console")
    out = raw_exchange(console, b"GET /a b HTTP/1.1\r\n\r\n")                  # four words: refused before a path exists
    head = out.partition(b"\r\n\r\n")[0].decode("latin-1")
    assert head.split("\r\n")[0].endswith(" 400 Bad Request"), out                # an answer, not a dropped connection
    headers = {k.lower(): v for k, v in (ln.split(": ", 1) for ln in head.split("\r\n")[1:])}
    assert headers["content-security-policy"].startswith(CSP_PREFIX) and headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert out.endswith(b'{"error": "bad_request"}')
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert "-  400" in [r.getMessage() for r in caplog.records]


@pytest.mark.parametrize("raw,error", [(b"GARBAGE\r\n\r\n", "bad_request"), (b"GET / HTTP/9.9\r\n\r\n", "http_version_not_supported")])
def test_an_http_0_9_style_rejection_is_answered_with_the_error_body_not_dropped(console, caplog, raw, error):
    caplog.set_level(logging.INFO, logger="amt_console")                     # HTTP/0.9 has no header block to carry anything
    assert raw_exchange(console, raw) == json.dumps({"error": error}).encode()
    assert not [r for r in caplog.records if r.levelno >= logging.ERROR]


@pytest.mark.parametrize("method", ["HEAD", "PUT", "DELETE", "OPTIONS", "PATCH"])
def test_a_method_with_no_handler_is_refused_with_the_headers(console, method):
    r = console.request(method, "/signin", cookie=False)
    assert r.status == 501
    assert r.headers["Content-Security-Policy"].startswith(CSP_PREFIX) and r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["Referrer-Policy"] == "no-referrer" and r.headers["X-Content-Type-Options"] == "nosniff"
    if method != "HEAD":
        assert r.json() == {"error": "not_implemented"}
