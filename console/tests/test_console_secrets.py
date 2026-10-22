"""No secret value is rendered, returned, logged or sent where it must not go (immutables 9 and 22): the console's
bearer is a sentinel, a scan covers every response body and header, every log record, every url amt-mcp saw, and
the client bundle. A planted leak is the positive control for each scan."""
import logging
import re
from pathlib import Path

import pytest

import server
from console_fakes import BEARER, Authenticator, enroll_first_passkey

CONSOLE = Path(server.__file__).parent
TOKEN_SHAPE = re.compile(r"[A-Za-z0-9_-]{32,}")           # a viewer token is 32 (token_urlsafe(24)), a handoff, upload or intake token 43
# Names the client prints on purpose that are as long as a token: exact strings (a new long name fails the scan until it is listed, which is the point).
NOT_TOKENS = frozenset({"changes_must_be_a_nonempty_object", "configure_instance_not_round_trippable", "AMT_SetupAndConfigurationService",
                        "AMT_EnvironmentDetectionSettingData", "CIM_AssociatedPowerManagementService", "CIM_FilterCollectionSubscription"})   # the last three: the WS-MAN class list


def scenario(c, fake, sentinel=BEARER):
    """Everything the browser can do, collected as (where, text) pairs."""
    seen = []

    def take(where, reply):
        seen.append((where, reply.text + repr(sorted(reply.headers.items()))))
        return reply
    a = Authenticator(c.app.cfg.rp_id, c.origin)
    take("enroll", enroll_first_passkey(c, a))
    for path in ("/signin", "/", "/settings", "/manage", "/api/session", "/api/passkeys", "/api/captures", "/api/fleet",
                 "/api/server/my-server-1", "/server/my-server-1", "/nope"):
        take(path, c.get(path))
    for path in sorted(p.name for p in (CONSOLE / "static").iterdir()):
        take("/static/" + path, c.get("/static/" + path))
    fake.results["amt_screenshot"] = lambda args: fake.offer(b"png-bytes", "s.png")
    fake.results["amt_status"] = lambda args: {"content": [{"type": "text", "text": "wsman_auth_failed_401"}], "isError": True}
    cap = take("shot", c.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": "my-server-1"}}))
    take("refused", c.post("/api/call", {"tool": "amt_status", "arguments": {"device": "my-server-1"}}))
    take("bad call", c.post("/api/call", {"tool": "amt_status", "arguments": {}}))
    take("download", c.get("/captures/" + cap.json()["structured"]["capture"]["id"]))
    take("cross-site", c.post("/api/call", {}, headers={"Origin": "https://evil.example"}))
    take("signout", c.post("/auth/signout"))
    return seen


def leaks(c, fake, seen, records, sentinel=BEARER):
    found = [where for where, text in seen if sentinel in text]
    found += ["log" for r in records if sentinel in r.getMessage() or sentinel in str(r.args)]
    found += ["amt-mcp url" for _, path, _ in fake.requests if sentinel in path]
    found += ["data folder" for f in c.data.rglob("*") if f.is_file() and sentinel.encode() in f.read_bytes()]
    return found


def test_the_bearer_appears_nowhere_a_browser_log_or_url_can_reach(console, fake_amt, caplog):
    caplog.set_level(logging.DEBUG)
    seen = scenario(console, fake_amt)
    assert len(seen) > 20 and any(c[0] == "download" for c in seen)
    assert fake_amt.calls and all(auth == f"Bearer {BEARER}" for _, _, auth in fake_amt.calls)   # it DID go to amt-mcp
    assert leaks(console, fake_amt, seen, caplog.records) == []


def test_the_scan_catches_a_planted_bearer_leak(console, fake_amt, caplog, monkeypatch):
    """Positive control: a deliberately broken route echoes the bearer; the same scan reports it."""
    caplog.set_level(logging.DEBUG)
    real = console.app.mcp.call

    def leaky(tool, arguments):
        res = real(tool, arguments)
        res.text += " " + console.app.mcp._token()
        server.log.error("debug dump %s", console.app.mcp._token())
        return res
    monkeypatch.setattr(console.app.mcp, "call", leaky)
    found = leaks(console, fake_amt, scenario(console, fake_amt), caplog.records)
    assert "shot" in found and "log" in found


def embed_key_leaks(c, fake, seen, records, key):
    found = [where for where, text in seen if key in text]
    found += ["log" for r in records if key in r.getMessage() or key in str(r.args)]
    found += ["amt-mcp url" for _, path, _ in fake.requests if key in path]
    found += ["data folder" for f in c.data.rglob("*") if f.is_file() and key.encode() in f.read_bytes()]
    return found


def embed_key_scenario(c, fake):
    """Every way the browser (or an opaque frame) can use an embed key, collected as (where, text) pairs; the mint reply is the one place the key is."""
    from test_console_fleet import device
    fake.results["amt_devices"] = lambda a: {"source": "file", "devices": [device()]}
    key = c.mint_embed_key("mirror")
    base = f"/embed/mirror/my-server-1/{key}"
    seen = []
    for method, path, extra in (("GET", base + "/", {}), ("GET", base + "/status.json", {}), ("GET", base + "/nope", {}), ("GET", base, {}), ("POST", base + "/input", {"Origin": "null"}),
                                ("POST", base + "/input", {"Origin": "https://evil.example"}), ("POST", base + "/record", {"Origin": "null"}), ("OPTIONS", base + "/input", {"Origin": "null"}),
                                ("GET", f"/embed/mirror/my-server-1/{key[:-1]}Z/status.json", {}), ("GET", "/api/embed/mirror/my-server-1", {}), ("GET", "/api/server/my-server-1", {})):
        r = c.request(method, path, raw=b"{}" if method == "POST" else None, cookie=path.startswith("/api"), csrf=False, origin=False, headers=extra)
        seen.append((f"{method} {path.split(key)[0]}<key>", r.text + repr(sorted(r.headers.items()))))
    r = c.post("/auth/signout")
    seen.append(("signout", r.text + repr(sorted(r.headers.items()))))
    return key, seen


def test_an_embed_key_is_in_no_response_log_amt_mcp_url_or_file_but_its_mint_reply(signed_in, fake_amt, caplog):
    caplog.set_level(logging.DEBUG)
    key, seen = embed_key_scenario(signed_in, fake_amt)
    assert len(seen) > 10 and any(w.startswith("POST") for w, _ in seen) and signed_in.minted_keys == [key]
    assert embed_key_leaks(signed_in, fake_amt, seen, caplog.records, key) == []
    assert any("<key>" in r.getMessage() or "<key>" in str(r.args) for r in caplog.records), "the access log never saw an embed path: the scan would pass on an empty run"


def test_the_embed_key_scan_catches_a_planted_leak(signed_in, fake_amt, caplog, monkeypatch):
    """Positive control: a debug line that prints the key, and an amt-mcp call whose path carries it, are both reported."""
    caplog.set_level(logging.DEBUG)
    real = signed_in.app.keys.check

    def noisy(candidate, kind, server):
        server_log = __import__("server").log
        server_log.error("debug dump %s", candidate)
        return real(candidate, kind, server)
    monkeypatch.setattr(signed_in.app.keys, "check", noisy)
    key, seen = embed_key_scenario(signed_in, fake_amt)
    fake_amt.requests.append(("POST", f"/mcp?k={key}", "x"))
    assert set(embed_key_leaks(signed_in, fake_amt, seen, caplog.records, key)) >= {"log", "amt-mcp url"}


def test_the_bearer_is_not_in_the_environment_or_the_bundle(console, fake_amt):
    import os
    scenario(console, fake_amt)
    assert BEARER not in "\n".join(os.environ.values())
    header = re.compile(r"\bAuthorization\b")                   # the header name as a word: a class name such as AMT_AuthorizationService is not one
    assert header.search("headers: {Authorization: 'Bearer x'}") and header.search("h.set('Authorization', b)") and not header.search("AMT_AuthorizationService")
    for f in list((CONSOLE / "static").iterdir()) + list((CONSOLE / "pages").iterdir()):
        assert BEARER not in f.read_text() and not header.search(f.read_text()), f.name
    assert "amt-console-token" not in "".join(f.read_text() for f in (CONSOLE / "static").iterdir() if f.suffix == ".js")


def test_the_browser_never_calls_amt_mcp(console, fake_amt):
    """The pages and scripts name no amt-mcp endpoint: the only calls go to the console's own routes."""
    text = "".join(f.read_text() for f in list((CONSOLE / "static").glob("*.js")) + list((CONSOLE / "pages").glob("*.html")))
    assert "/mcp" not in text and "amt.example.com" not in text and "handoffs" not in text
    for url in re.findall(r"""fetch\(\s*['"]([^'"]+)['"]""", text):
        assert url.startswith("/"), url


# -- no password field anywhere in the auth flow (immutable 22), no token-shaped string or handoff url in a page --

def bad_markup(text):
    found = []
    if re.search(r"""type\s*=\s*["']?password""", text, re.I): found.append("password field")
    if "new-password" in text: found.append("autocomplete=new-password")
    if re.search(r"""(src|href)\s*=\s*["'][^"']*handoffs/""", text): found.append("handoffs/ in src/href")
    if any(m.group(0) not in NOT_TOKENS for m in TOKEN_SHAPE.finditer(re.sub(r"<svg.*?</svg>", "", text, flags=re.S))): found.append("token-shaped string")
    return found


def test_no_password_field_no_handoff_href_no_token_shaped_string_in_the_client():
    for f in sorted((CONSOLE / "pages").iterdir()) + sorted((CONSOLE / "static").glob("*.js")):
        assert bad_markup(f.read_text()) == [], f.name


@pytest.mark.parametrize("planted,expect", [
    ('<input type="password">', "password field"), ("<input type=password>", "password field"),
    ('<input autocomplete="new-password">', "autocomplete=new-password"),
    ('<a href="https://x/handoffs/abc">', "handoffs/ in src/href"),
    ("<p>" + "A" * 43 + "</p>", "token-shaped string"),
    ("<p>" + "A" * 32 + "</p>", "token-shaped string"),                  # a viewer token (token_urlsafe(24)) is 32 characters
])
def test_the_markup_scan_reports_what_it_looks_for(planted, expect):
    assert expect in bad_markup(planted)


def test_the_markup_scan_passes_a_string_one_short_of_a_token():
    assert bad_markup("<p>" + "A" * 31 + "</p>") == []


def test_a_real_viewer_token_is_reported_and_a_listed_name_is_not():
    import secrets
    viewer_token = secrets.token_urlsafe(24)
    assert len(viewer_token) == 32 and "token-shaped string" in bad_markup(f"<script>var u = '/m/{viewer_token}/';</script>")
    assert bad_markup("<p>AMT_SetupAndConfigurationService</p>") == []
    assert "token-shaped string" in bad_markup("<p>AMT_SetupAndConfigurationServiceX</p>")           # a listed name is exact, not a prefix


def test_every_listed_name_is_still_in_the_client():
    text = "".join(f.read_text() for f in list((CONSOLE / "pages").iterdir()) + list((CONSOLE / "static").glob("*.js")))
    assert [n for n in sorted(NOT_TOKENS) if n not in text] == []


def test_the_served_pages_carry_no_token_shaped_string(signed_in):
    for path in ("/signin", "/", "/settings", "/manage", "/server/my-server-1", "/server/my-server-1/console", "/server/my-server-1/serial", "/server/my-server-1/logs", "/server/my-server-1/inventory"):
        assert bad_markup(signed_in.get(path).text) == [], path
