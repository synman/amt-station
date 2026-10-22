"""The KVM and SOL tabs in a real browser (headless Chromium), against scripted amt-mcp answers and a fake viewer front that serves
amt-mcp's real embed-mode pages (packet C4).

Immutables 4 and 5 (the sheets and the stop predicate), 6 (every macro call validates against the live schema), 7 (an abort, no retry), 8 (the
holder, the in-flight strip, held_other), 12 (request origins and the embed's toolbar groups), and the page walk of 13, 14 and 18. No test
starts a real session or reaches a host: a call only ever goes to the fake amt-mcp."""
import functools
import json
import re

import pytest

from console_fakes import Authenticator, Console, check_mockups, enroll_first_passkey
from test_console_embed import KEY, Hosts, all_tokens, hosts, viewer  # noqa: F401 - fixtures
from test_console_fleet import STATUS, tool_error
from test_console_fleet_browser import WIDTHS, browser, calls, open_page, read_all, text, walk  # noqa: F401 - fixtures

MP4 = "my-server-1-20261020T094000Z.mp4"
sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed: the browser immutables are NOT checked")


@pytest.fixture()
def eb(tmp_path, fake_amt, viewer, hosts):
    """A signed-in console whose fleet is read by hand (read_all); the fake viewer is its viewer front."""
    console = Console(tmp_path, fake_amt, viewer_origin=viewer.base)
    enroll_first_passkey(console, Authenticator(console.app.cfg.rp_id, console.origin))
    fake_amt.results["amt_captures"] = lambda a: {"total": 0, "offset": 0, "captures": [], "next_offset": None,
                                                  "searched": [{"dir": "/s", "kinds": ["screenshot"], "found": True}, {"dir": "/r", "kinds": ["recording", "serial_cast"], "found": True}]}
    yield console
    console.close()


def start_by_console(eb, prefix="m"):
    """The session as the console starts it: a confirmed start through /api/call, so the fleet records it as the console's."""
    tool, extra = ("amt_mirror_link", {"fps": 15, "quality": 70}) if prefix == "m" else ("amt_serial_link", {})
    args = {"device": KEY, "action": "start", "bind": "0.0.0.0", "port": 8766, "record_on_start": False, "confirmed": True, **extra}
    assert eb.post("/api/call", {"tool": tool, "arguments": args}).json()["isError"] is False


def seat(eb, hosts, prefix, holder):
    """Put the host in one of the session states: 'console' (started through the console), 'agent' (live, started elsewhere), 'free'."""
    hosts.set(prefix, None)
    read_all(eb)
    if holder == "console":
        start_by_console(eb, prefix)
    elif holder == "agent":
        hosts.set(prefix, True)
    read_all(eb)


def violations(pg):
    pg.evaluate("() => { window.__csp = []; document.addEventListener('securitypolicyviolation', e => window.__csp.push(e.violatedDirective + ' ' + e.blockedURI)); }")


def sheet_text(pg, sel=".sheet.open"):
    return pg.inner_text(sel).replace("\n", " ")


def confirm_plain(pg):
    pg.click(".sheet.open [data-confirm]")


# -- the frame: amt-mcp's own page, in embed mode, through the console's route ---------------------------------------------------

def test_the_mirror_is_framed_through_the_console_with_the_embed_toolbar_and_no_token(browser, eb, hosts, viewer):
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        violations(pg)
        pg.wait_for_selector("#kvm-screen iframe")
        frame_el = pg.query_selector("#kvm-screen iframe")
        assert re.fullmatch(rf"/embed/mirror/{KEY}/[A-Za-z0-9_-]{{43}}/", frame_el.get_attribute("src"))      # the per-page-view embed key is in the path
        assert frame_el.get_attribute("referrerpolicy") == "no-referrer"
        assert frame_el.get_attribute("sandbox") == "allow-scripts allow-forms"                             # opaque origin: no allow-same-origin (sprint review B1)
        frame = frame_el.content_frame()
        frame.wait_for_selector("#ctl", state="attached")
        assert frame.evaluate("() => window.origin") == "null"                                              # the effect, not only the attribute
        groups = frame.evaluate("""() => Array.from(document.querySelectorAll('nav.bar .grp')).map(g => ({
          label: g.querySelector('.lbl').textContent, buttons: Array.from(g.querySelectorAll('button')).map(b => b.textContent.trim()) }))""")
        assert [g["label"] for g in groups] == ["View", "Control"]                 # no Capture group: Record is a confirmed tool call from the console's chrome
        assert groups[0]["buttons"] == ["Fit", "1:1"]
        assert groups[1]["buttons"] == ["Take control", "Ctrl+Alt+Del", "Esc", "Del", "F2", "F7", "F10", "F11", "F12", "Win"]
        for gone in ("#rec", "#rect", "#shot", "#mgrp", "#hbar", "#pgrp", "#forceB", "#mount", "[data-a]", "#dl", "select"):
            assert frame.query_selector(gone) is None, gone                       # no Record, Power, Boot, Media, Screenshot or download in the frame
        assert "Record" not in frame.inner_text("nav.bar") and text(pg, "#kvm-session button") == "Start recording"
        pg.wait_for_function("() => document.querySelector('#kvm-foot').textContent.includes('15 fps')")
        assert frame_el.get_attribute("title") == f"Live console of {KEY}, 640 by 400"           # the geometry is in the frame's name
        assert "127.0.0.1 · /m/…/" in text(pg, "#kvm-foot") and "embed mode: no Power, Boot or Media rows, no downloads" in text(pg, "#kvm-foot")
        # immutable 12: every request is to the console; nothing is a viewer, amt-mcp or handoff url, and the token is nowhere in the page
        origins = {u.split("/")[0] + "//" + u.split("/")[2] for u in pg.requests if u.startswith("http")}
        assert origins == {eb.origin}, origins
        assert not [u for u in pg.requests if viewer.base in u or "/mcp" in u or "handoffs" in u]
        html = pg.content() + frame.content()
        assert not any(t in html for t in all_tokens(viewer)) and not any(t in u for u in pg.requests for t in all_tokens(viewer))
        assert pg.evaluate("() => window.__csp") == [] and pg.errors == []
        assert "Screenshot" not in pg.inner_text("#kvm-embed")
    finally:
        ctx.close()


PROBE = """async () => {
  const out = { origin: window.origin };
  const attempt = async (name, fn) => { try { out[name] = await fn(); } catch (e) { out[name] = 'blocked:' + e.name; } };
  const call = { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ tool: 'amt_power', arguments: { device: 'my-server-1', action: 'hard_reset', confirmed: true } }) };
  await attempt('parent.amtc', () => String(parent.amtc));
  await attempt('parent.csrf', () => parent.amtc.csrf);
  await attempt('parent.document', () => parent.document.querySelector('h1').textContent = 'PWNED');
  await attempt('parent.fetch', () => parent.fetch('/api/call', call).then(r => r.status));
  await attempt('top.document', () => top.document.body.innerHTML.length);
  await attempt('cookie', () => document.cookie);
  await attempt('localStorage', () => localStorage.length);
  await attempt('own fetch /api/session', () => fetch('/api/session', { credentials: 'same-origin' }).then(r => r.status));
  await attempt('own fetch /api/call', () => fetch('/api/call', call).then(r => r.status));
  await attempt('own fetch /static', () => fetch('/static/components.js').then(r => r.status));
  return out;
}"""


def drop_response_sandbox(served, route):
    """Serve a framed document without the `sandbox` directive of its Content-Security-Policy, so only the iframe's own attribute is left to hold it."""
    if route.request.resource_type != "document":
        return route.continue_()
    resp = route.fetch()
    headers = dict(resp.headers)
    csp = headers["content-security-policy"]
    headers["content-security-policy"] = re.sub(r";\s*sandbox[^;]*$", "", csp)
    assert headers["content-security-policy"] != csp and "sandbox" not in headers["content-security-policy"]
    served.append(route.request.url)
    route.fulfill(response=resp, headers=headers)


def test_the_framed_page_is_an_opaque_origin_that_cannot_reach_the_console_page_or_its_session(browser, eb, hosts, viewer, fake_amt):
    """Sprint review B1, the review's own probe run from inside the frame, with the response's CSP sandbox taken away: the iframe's `sandbox` attribute
    (no allow-same-origin) must hold the opaque origin ALONE, so putting allow-same-origin back on the frame turns this red by itself. The next test
    holds the other mechanism alone (the response's CSP sandbox, with no iframe at all)."""
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        served = []
        ctx.route("**/embed/**", functools.partial(drop_response_sandbox, served))
        pg.reload()                                                                     # the frame mounts again, now served without the CSP sandbox
        pg.wait_for_selector("#kvm-screen iframe")
        frame = pg.query_selector("#kvm-screen iframe").content_frame()
        frame.wait_for_selector("#ctl", state="attached")
        assert served, "the framed document was not served through the sandbox-dropping route, so the attribute was not tested alone"
        heading = pg.inner_text("h1")
        out = frame.evaluate(PROBE)
        assert out["origin"] == "null"
        for name in ("parent.amtc", "parent.csrf", "parent.document", "parent.fetch", "top.document", "cookie", "localStorage",
                     "own fetch /api/session", "own fetch /api/call", "own fetch /static"):
            assert str(out[name]).startswith("blocked:"), (name, out[name])
        assert pg.inner_text("h1") == heading and "PWNED" not in pg.content()          # the console page was not rewritten
        assert [a for t, a, _ in fake_amt.calls if t == "amt_power"] == []             # and no write went through /api/call from the frame
        assert pg.evaluate("() => typeof window.amtc.csrf") == "string"                # the parent still has its own session (the control)
    finally:
        ctx.close()


ESCAPE_PROBE = """async () => {
  const out = {};
  const attempt = async (name, fn) => { try { out[name] = await fn(); } catch (e) { out[name] = 'blocked:' + e.name; } };
  await attempt('top.location assign', () => { top.location = '/signin'; return 'assigned'; });
  await attempt('top.location.href assign', () => { top.location.href = '/signin'; return 'assigned'; });
  await attempt('window.open', () => String(window.open('/')));
  await attempt('anchor _top', () => { const a = document.createElement('a'); a.href = '/signin'; a.target = '_top'; document.body.appendChild(a); a.click(); return 'clicked'; });
  await attempt('anchor _blank', () => { const a = document.createElement('a'); a.href = '/'; a.target = '_blank'; a.rel = 'opener'; document.body.appendChild(a); a.click(); return 'clicked'; });
  await attempt('form post signout', () => { const f = document.createElement('form'); f.method = 'post'; f.action = '/auth/signout'; document.body.appendChild(f); f.submit(); return 'submitted'; });
  return out;
}"""


def test_the_framed_page_cannot_move_the_top_window_open_a_popup_or_submit_a_form(browser, eb, hosts, viewer):
    """The flags the frame's sandbox leaves out, asserted by their effect (final review, finding 3): no allow-top-navigation, no allow-popups, and
    form-action 'none'. A sandbox attribute that gained either flag would let the relayed page move or open a console page. The response's CSP
    sandbox is taken away, as in the probe test above, so the attribute holds this alone (the two layers are redundant: either one alone keeps it
    green, and the tab test holds the CSP layer's window.open)."""
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        served = []
        ctx.route("**/embed/**", functools.partial(drop_response_sandbox, served))
        pg.reload()
        pg.wait_for_selector("#kvm-screen iframe")
        frame = pg.query_selector("#kvm-screen iframe").content_frame()
        frame.wait_for_selector("#ctl", state="attached")
        assert served, "the framed document was not served through the sandbox-dropping route, so the attribute was not tested alone"
        url_before = pg.url
        out = frame.evaluate(ESCAPE_PROBE)
        pg.wait_for_timeout(800)
        assert str(out["top.location assign"]).startswith("blocked:") and str(out["top.location.href assign"]).startswith("blocked:"), out
        assert out["window.open"] == "null", out
        assert pg.url == url_before and len(ctx.pages) == 1, (pg.url, [p.url for p in ctx.pages])     # no top navigation, no popup
        assert eb.get("/api/session").status == 200                                                   # the form did not sign the session out
    finally:
        ctx.close()


def test_a_frame_that_navigates_itself_to_a_foreign_origin_is_stopped_and_its_key_stays_home(browser, eb, hosts, viewer):
    """The relayed page sending its own location (with the key in the path) elsewhere: the console page's frame-src 'self' stops it before any
    request leaves (final review, finding 3)."""
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    outside = []
    ctx.route("https://elsewhere.example.test/**", lambda r: (outside.append(r.request.url), r.fulfill(status=200, content_type="text/html", body="<p>out</p>")))
    try:
        violations(pg)
        pg.wait_for_selector("#kvm-screen iframe")
        frame = pg.query_selector("#kvm-screen iframe").content_frame()
        frame.wait_for_selector("#ctl", state="attached")
        frame.evaluate("() => { location.href = 'https://elsewhere.example.test/?k=' + encodeURIComponent(location.pathname); }")
        pg.wait_for_timeout(1500)
        assert outside == [], outside
        assert any(v.startswith("frame-src") for v in pg.evaluate("() => window.__csp")), "the parent's frame-src did not refuse the navigation"
    finally:
        ctx.close()


def test_a_relayed_page_opened_in_a_tab_is_an_opaque_origin_too(browser, eb, hosts, viewer, fake_amt):
    """The Open in a tab link loads the same keyed path as a top-level document, signed in: no iframe attribute is in play, so the CSP sandbox of the
    response alone must hold it (a same-origin tab could window.open a console page and drive /api/call through it)."""
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector('#kvm-session a:has-text("Open in a tab")[href]')
        href = pg.get_attribute('#kvm-session a:has-text("Open in a tab")', "href")
        assert href == pg.get_attribute("#kvm-screen iframe", "src")
        tab = ctx.new_page()
        tab.goto(eb.origin + href)
        tab.wait_for_selector("#ctl", state="attached")
        out = tab.evaluate(PROBE)
        assert out["origin"] == "null" and str(out["cookie"]).startswith("blocked:")
        assert str(out["own fetch /api/session"]).startswith("blocked:") and str(out["own fetch /api/call"]).startswith("blocked:")
        assert tab.evaluate("() => { const w = window.open('/api/session'); return w === null; }")           # no popup: a console page cannot be opened and driven
        assert [a for t, a, _ in fake_amt.calls if t == "amt_power"] == []
    finally:
        ctx.close()


def test_the_framed_page_still_streams_reads_status_and_posts_input_for_the_mirror(browser, eb, hosts, viewer):
    """What the opaque frame must keep doing through CORS without credentials: the MJPEG stream (an image), status.json (fetch) and live input (a
    JSON POST with a preflight), all on the keyed path."""
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#kvm-screen iframe")
        frame = pg.query_selector("#kvm-screen iframe").content_frame()
        frame.wait_for_selector("#ctl", state="attached")
        frame.wait_for_function("() => { const i = document.getElementById('view'); return !!i && i.naturalWidth > 0; }", timeout=15000)    # frames arrived
        status = frame.evaluate("async () => { const r = await fetch('status.json', { cache: 'no-store' }); return [r.status, (await r.json()).fps]; }")
        assert status == [200, 15]
        key = pg.get_attribute("#kvm-screen iframe", "src").rstrip("/").rsplit("/", 1)[1]
        assert frame.evaluate("() => location.pathname").endswith(f"/{key}/")
        posted = frame.evaluate("""async () => (await fetch('input', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ events: [] }) })).status""")
        assert posted == 200
        assert [p for m, p, _, _ in viewer.requests if m == "POST"] == [f"/m/{viewer.control['m']}/input?embed=1"]
        sent = [h for _, _, h, _ in viewer.requests]
        assert sent and not [h for h in sent if {"cookie", "origin", "referer", "authorization"} & {k.lower() for k in h}]      # nothing of the browser goes upstream
        assert not any(key in json.dumps(h) or key in p for _, p, h, _ in viewer.requests)                                   # nor the key
    finally:
        ctx.close()


def test_a_frame_whose_key_is_gone_is_mounted_again_with_a_fresh_one(browser, eb, hosts, viewer):
    """An idle limit or a console restart ends the key the frame holds; the page's own poll learns it (key_live: false) and mounts a new frame."""
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#kvm-screen iframe")
        first = pg.get_attribute("#kvm-screen iframe", "src")
        pg.query_selector("#kvm-screen iframe").content_frame().wait_for_selector("#ctl", state="attached")
        eb.app.keys.revoke_session(eb.app.auth.session_ref(eb.cookie))                  # every key of the session is gone, as after a restart
        pg.wait_for_function("(old) => { const f = document.querySelector('#kvm-screen iframe'); return !!f && f.getAttribute('src') !== old; }", arg=first, timeout=8000)
        second = pg.get_attribute("#kvm-screen iframe", "src")
        assert second != first and re.fullmatch(rf"/embed/mirror/{KEY}/[A-Za-z0-9_-]{{43}}/", second)
        pg.query_selector("#kvm-screen iframe").content_frame().wait_for_selector("#ctl", state="attached")        # the new frame is alive
        assert pg.get_attribute('#kvm-session a:has-text("Open in a tab")', "href") == second
    finally:
        ctx.close()


def test_the_framed_terminal_streams_output_reads_status_and_posts_typed_input(browser, eb, hosts, viewer):
    seat(eb, hosts, "s", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.wait_for_selector("#sol-screen iframe")
        frame = pg.query_selector("#sol-screen iframe").content_frame()
        frame.wait_for_selector("#term")
        frame.wait_for_function("() => document.querySelector('#term').textContent.includes('login:')", timeout=15000)       # the EventSource stream, cross-origin
        assert frame.evaluate("() => document.featurePolicy.allowsFeature('clipboard-write')") is True       # the Copy button keeps working in an opaque frame
        assert frame.evaluate("async () => (await (await fetch('status.json', { cache: 'no-store' })).json()).total") == 40
        frame.click("#ctl")
        assert frame.inner_text("#ctl").strip() == "Release control"
        frame.click("#term")
        pg.keyboard.type("ls")
        for _ in range(60):
            posts = [b for m, p, _, b in viewer.requests if m == "POST" and "/input?embed=1" in p]
            if posts:
                break
            pg.wait_for_timeout(100)
        assert posts and "l" in json.loads(posts[0])["data"], viewer.seen()
    finally:
        ctx.close()


def test_take_control_in_the_frame_reaches_the_host_through_the_relay(browser, eb, hosts, viewer):
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#kvm-screen iframe")
        frame = pg.query_selector("#kvm-screen iframe").content_frame()
        frame.wait_for_selector("#ctl", state="visible")
        frame.click("#ctl")
        frame.click('button[data-k="f2"]')
        pg.wait_for_function("() => true")
        deadline_posts = []
        for _ in range(40):
            deadline_posts = [b for m, p, _, b in viewer.requests if m == "POST" and "/input?embed=1" in p]
            if deadline_posts:
                break
            pg.wait_for_timeout(100)
        assert deadline_posts, viewer.seen()
        events = json.loads(deadline_posts[0])["events"]
        assert ["k", 0xFFBF, 1] in events                                          # F2 down, as the viewer sends it, through the console's relay
        assert all(p.startswith(f"/m/{viewer.control['m']}/") for p in viewer.seen())
    finally:
        ctx.close()


def test_the_serial_terminal_is_framed_with_the_embed_toolbar_and_shows_the_hosts_output(browser, eb, hosts, viewer):
    seat(eb, hosts, "s", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        violations(pg)
        pg.wait_for_selector("#sol-screen iframe")
        frame = pg.query_selector("#sol-screen iframe").content_frame()
        frame.wait_for_selector("#term")
        groups = frame.evaluate("""() => Array.from(document.querySelectorAll('nav.bar .grp')).map(g => ({
          label: g.querySelector('.lbl').textContent, buttons: Array.from(g.querySelectorAll('button')).map(b => b.getAttribute('aria-label') || b.textContent.trim()) }))""")
        assert [g["label"] for g in groups] == ["View", "Control"]                 # no Capture group: Record is a confirmed tool call from the console's chrome
        assert groups[0]["buttons"] == ["Smaller text", "Larger text", "Copy", "Clear"]
        assert groups[1]["buttons"] == ["Take control", "Ctrl+C", "Ctrl+D", "Ctrl+Z", "Ctrl+L", "Esc", "Tab", "Arrow up", "Arrow down", "Arrow left", "Arrow right"]
        assert frame.query_selector("#dl") is None and frame.query_selector("#rec") is None   # no Download .txt, no Record
        assert "Record" not in frame.inner_text("nav.bar") and pg.inner_text("#sol-session button") == "Start recording"
        frame.wait_for_function("() => document.querySelector('#term').textContent.includes('login:')", timeout=15000)
        origins = {u.split("/")[0] + "//" + u.split("/")[2] for u in pg.requests if u.startswith("http")}
        assert origins == {eb.origin}, origins
        assert not any(t in pg.content() + frame.content() for t in all_tokens(viewer))
        assert pg.evaluate("() => window.__csp") == [] and pg.errors == []
    finally:
        ctx.close()


# -- the session card: the five states of the mirror (immutable 8) ----------------------------------------------------------

def session_text(pg):
    return pg.inner_text("#kvm-session").replace("\n", " ")


def test_a_mirror_the_console_started_is_yours_with_open_in_a_tab_and_a_plain_stop(browser, eb, hosts):
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector('#kvm-session[data-mirror-state="console"] [data-session="held_console"]')
        assert text(pg, '#kvm-session [data-session="held_console"]').startswith("KVM · you (console) · ")
        assert "agents share this session while it runs" in session_text(pg)
        link = pg.query_selector('#kvm-session a:has-text("Open in a tab")')
        pg.wait_for_selector('#kvm-session a:has-text("Open in a tab")[href]')      # shown once the frame's key is minted
        link = pg.query_selector('#kvm-session a:has-text("Open in a tab")')
        assert re.fullmatch(rf"/embed/mirror/{KEY}/[A-Za-z0-9_-]{{43}}/", link.get_attribute("href"))
        assert (link.get_attribute("href"), link.get_attribute("target"), link.get_attribute("rel")) == (pg.get_attribute("#kvm-screen iframe", "src"), "_blank", "noopener")
        assert text(pg, "[data-stop=mirror]") == "Stop mirror"
        # the same holder on the page header (immutable 8: the same word on every surface)
        assert pg.get_attribute('.srvhead [data-session="held_console"]', "data-session") == "held_console"
    finally:
        ctx.close()


def test_a_mirror_an_agent_started_is_the_agents_and_stopping_it_says_so(browser, eb, hosts):
    seat(eb, hosts, "m", "agent")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector('#kvm-session[data-mirror-state="agent"] [data-session="held_agent"]')
        assert text(pg, '#kvm-session [data-session="held_agent"]').startswith("KVM · agent via mirror")
        assert "the console attached to it: watch, take control" in session_text(pg)
        assert text(pg, "[data-stop=mirror]") == "Stop the agent's mirror"
        pg.wait_for_selector("#kvm-screen iframe")                                  # the console attaches: it frames the agent's mirror too
    finally:
        ctx.close()


def test_an_agents_mirror_on_the_default_bind_is_said_to_be_unreachable_and_is_not_framed(browser, eb, hosts, viewer):
    hosts.reachable = False
    seat(eb, hosts, "m", "agent")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector('#kvm-screen [data-screen-state="unreachable"]')
        assert "Held by an agent · not reachable from here · bind 127.0.0.1" in text(pg, "#kvm-screen")
        assert pg.query_selector("#kvm-screen iframe") is None and pg.query_selector('#kvm-session a:has-text("Open in a tab")') is None
        assert "not reachable from here" in session_text(pg) and text(pg, "[data-stop=mirror]") == "Stop the agent's mirror"
        assert viewer.requests == []
    finally:
        ctx.close()


def test_no_mirror_offers_start_and_frames_nothing(browser, eb, hosts, viewer):
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector('#kvm-session[data-mirror-state="stopped"]')
        assert "no mirror running · KVM free" in session_text(pg) and text(pg, "#start-mirror-btn") == "Start mirror"
        assert pg.query_selector("#kvm-screen iframe") is None and "No mirror is running" in text(pg, "#kvm-screen")
        assert pg.query_selector("[data-stop]") is None and viewer.requests == []
    finally:
        ctx.close()


def test_another_client_holding_the_kvm_is_held_other_with_opens_refused(browser, eb, hosts, fake_amt):
    seat(eb, hosts, "m", "free")
    fake_amt.results["amt_mirror_link"] = lambda a: tool_error("Error executing tool amt_mirror_link: redir_start_status_1 (another session is open)") if a["action"] == "start" else hosts.tool("m", a)
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.click("#start-mirror-btn")
        confirm_plain(pg)
        pg.wait_for_selector('#kvm-session[data-mirror-state="other"] [data-session="held_other"]')
        assert "another session is open" in text(pg, '#kvm-session [data-session="held_other"]') and "Opens refused" in text(pg, '#kvm-session [data-session="held_other"]')
        assert "refused: Error executing tool amt_mirror_link: redir_start_status_1 (another session is open)" in text(pg, "#session-results")
        assert "another client holds this host's session: opens refused" in text(pg, "#session-results")
        assert pg.query_selector("#start-mirror-btn") is None and pg.query_selector("#kvm-screen iframe") is None
        assert pg.get_attribute('.srvhead [data-session="held_other"]', "data-session") == "held_other"
    finally:
        ctx.close()


def test_a_consent_code_on_the_hosts_screen_is_the_consent_pending_state(browser, eb, hosts, fake_amt):
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "user_consent": {**STATUS["user_consent"], "state_code": 1, "state": "requested", "required_for": "kvm", "required_code": 1}}
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector('#kvm-session[data-mirror-state="consent"] [data-session="consent_pending"]')
        t = text(pg, '#kvm-session [data-session="consent_pending"]')
        assert "a code is on its screen" in t and pg.get_attribute('#kvm-session [data-session="consent_pending"] a', "href") == f"/server/{KEY}/wsman"
        assert pg.query_selector("#start-mirror-btn") is None and pg.query_selector("#kvm-screen iframe") is None
    finally:
        ctx.close()


# -- Record: a confirmed tool call from the console's own chrome, never the framed page's route (sprint review M1) ------------------

def unavailable_record(pg, card):
    """The greyed Record in a session card with no live session: the button, whether it is disabled, and the reason beside it as text."""
    btn = pg.query_selector(f"{card} [data-record=unavailable] button")
    return btn.inner_text(), btn.get_attribute("aria-disabled"), text(pg, f"{card} [data-record=unavailable] .reason")


def test_record_is_greyed_with_its_reason_when_no_mirror_is_live_and_opens_nothing(browser, eb, hosts, fake_amt):
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector('#kvm-session[data-mirror-state="stopped"]')
        assert unavailable_record(pg, "#kvm-session") == ("Start recording", "true", "no mirror is running")
        assert pg.query_selector("#rec-start-btn") is None and pg.query_selector("#rec-stop-btn") is None
        before = [a for a in calls(fake_amt, "amt_mirror_link", KEY) if a["action"] != "status"]
        pg.click("#kvm-session [data-record=unavailable] button", force=True)
        pg.wait_for_timeout(300)
        assert pg.query_selector(".sheet.open") is None and spy(pg) == [] and before == []
        assert [a for a in calls(fake_amt, "amt_mirror_link", KEY) if a["action"] != "status"] == []
    finally:
        ctx.close()


def test_record_is_greyed_with_its_reason_when_a_consent_code_holds_the_session(browser, eb, hosts, fake_amt):
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "user_consent": {**STATUS["user_consent"], "state_code": 1, "state": "requested", "required_for": "kvm", "required_code": 1}}
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector('#kvm-session[data-mirror-state="consent"]')
        assert unavailable_record(pg, "#kvm-session") == ("Start recording", "true", "no mirror is running")
    finally:
        ctx.close()


def test_record_is_greyed_with_its_reason_when_no_terminal_is_live(browser, eb, hosts, fake_amt):
    seat(eb, hosts, "s", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.wait_for_selector('#sol-session[data-serial-state="stopped"]')
        assert unavailable_record(pg, "#sol-session") == ("Start recording", "true", "no terminal is running")
        pg.click("#sol-session [data-record=unavailable] button", force=True)
        pg.wait_for_timeout(300)
        assert pg.query_selector(".sheet.open") is None and spy(pg) == []
        assert [a for a in calls(fake_amt, "amt_serial_link", KEY) if a["action"] != "status"] == []
    finally:
        ctx.close()


def test_a_mirror_recording_is_started_and_stopped_by_sheets_and_never_through_the_viewer(browser, eb, hosts, viewer, fake_amt):
    hosts.recording_path = f"/data/recordings/{MP4}"
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#rec-start-btn")
        assert [b.inner_text() for b in pg.query_selector_all("#kvm-session button")] == ["Start recording", "Stop mirror"]
        pg.click("#rec-start-btn")
        s = sheet_text(pg)
        assert s.startswith("Record this mirror") and 'tools/call amt_mirror_link {device: "my-server-1", action: "record_start", confirmed: true}' in s
        assert "Writes the live view to a file in the NAS recordings folder until you stop it" in s and pg.query_selector(".sheet.open .force-control") is None
        assert [a for a in calls(fake_amt, "amt_mirror_link", KEY) if a["action"] == "record_start"] == []      # nothing is sent until Confirm
        confirm_plain(pg)
        pg.wait_for_selector("#rec-stop-btn", timeout=8000)                    # the session card now offers Stop recording
        assert [a for a in calls(fake_amt, "amt_mirror_link", KEY) if a["action"] == "record_start"] == [{"device": KEY, "action": "record_start", "confirmed": True}]
        assert "recording to the NAS recordings folder until stopped" in text(pg, "#session-results")
        pg.wait_for_function("() => document.querySelector('#kvm-session').textContent.includes('recording · ')")
        assert spy(pg)[-1]["forced"] is False and len(spy(pg)) == 1
        pg.click("#rec-stop-btn")
        assert sheet_text(pg).startswith(f"Stop recording the mirror of {KEY}") and 'tools/call amt_mirror_link {device: "my-server-1", action: "record_stop", confirmed: true}' in sheet_text(pg)
        confirm_plain(pg)
        pg.wait_for_selector("#rec-start-btn", timeout=8000)                   # the card re-read: no recording runs now
        assert "stopped · it is finished and encoded in the background and is listed under Recordings when ready" in text(pg, "#session-results")
        assert [a["action"] for a in calls(fake_amt, "amt_mirror_link", KEY) if a["action"].startswith("record")] == ["record_start", "record_stop"]
        # the viewer front never saw a record route, from the card or from anywhere: it is a tool action, not a viewer route
        assert not [p for _, p, _, _ in viewer.requests if "/record" in p], viewer.seen()
        assert [p for m, p, _, _ in viewer.requests if m == "POST"] == []
    finally:
        ctx.close()


def test_the_framed_page_cannot_start_a_recording_even_by_posting_to_the_old_route(browser, eb, hosts, viewer, fake_amt):
    for prefix, kind, page in (("m", "mirror", "console"), ("s", "serial", "serial")):
        seat(eb, hosts, prefix, "console")
        ctx, pg = open_page(browser, eb, f"/server/{KEY}/{page}")
        try:
            pg.wait_for_selector(f"#{'kvm' if prefix == 'm' else 'sol'}-screen iframe")
            frame = pg.query_selector(f"#{'kvm' if prefix == 'm' else 'sol'}-screen iframe").content_frame()
            frame.wait_for_selector("#ctl", state="attached") if prefix == "m" else frame.wait_for_selector("#term")
            viewer.requests.clear()
            posted = frame.evaluate("""async () => { try { return (await fetch('record?on=1', { method: 'POST', credentials: 'same-origin' })).status; } catch (e) { return 'blocked'; } }""")
            assert posted == 404 and not [p for m, p, _, _ in viewer.requests if m == "POST"], (kind, posted, viewer.seen())
            assert [a for a in calls(fake_amt, f"amt_{kind}_link", KEY) if a["action"].startswith("record")] == []
        finally:
            ctx.close()


# -- Start and Stop: the sheets (immutables 4 and 5) ------------------------------------------------------------------------

def spy(pg):
    return pg.evaluate("() => window.__calls()")


def hold_to_fire(pg, ms=1400):
    pg.wait_for_timeout(450)                                            # the sheet slides in for 300 ms: measure where it rests
    box = pg.query_selector(".sheet.open .force-control").bounding_box()
    pg.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2)
    pg.mouse.down()
    pg.wait_for_timeout(ms)
    pg.mouse.up()


def test_start_mirror_is_a_plain_sheet_with_the_exact_call_and_one_call_per_confirm(browser, eb, hosts, fake_amt):
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.click("#start-mirror-btn")
        s = sheet_text(pg)
        assert s.startswith(f"Start a mirror of {KEY}") and "Opens the host's single KVM session" in s
        assert ('tools/call amt_mirror_link {device: "my-server-1", action: "start", bind: "0.0.0.0", port: 8766, fps: 15, quality: 70, record_on_start: false, confirmed: true}'
                in s)
        assert pg.query_selector(".sheet.open .force-control") is None and pg.evaluate("() => document.activeElement.textContent") == "Cancel"
        assert calls(fake_amt, "amt_mirror_link", KEY) == [{"device": KEY, "action": "status"}] * len(calls(fake_amt, "amt_mirror_link", KEY))
        before = len(calls(fake_amt, "amt_mirror_link", KEY))
        confirm_plain(pg)
        pg.wait_for_selector('#kvm-session[data-mirror-state="console"]')
        sent = [a for a in calls(fake_amt, "amt_mirror_link", KEY) if a["action"] == "start"]
        assert sent == [{"device": KEY, "action": "start", "bind": "0.0.0.0", "port": 8766, "fps": 15, "quality": 70, "record_on_start": False, "confirmed": True}]
        assert len(spy(pg)) == 1 and spy(pg)[0]["forced"] is False and before >= 0
        assert " · started · 15 fps · 640×400 · the control page is framed above" in text(pg, "#session-results")
        pg.wait_for_selector("#kvm-screen iframe")
    finally:
        ctx.close()


def test_a_mirror_that_was_already_running_is_attached_not_claimed(browser, eb, hosts):
    seat(eb, hosts, "m", "agent")
    hosts.mirror = None
    read_all(eb)                                                       # the page opens on "no mirror"; an agent starts one meanwhile
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector('#kvm-session[data-mirror-state="stopped"]')
        hosts.mirror = True
        pg.click("#start-mirror-btn")
        confirm_plain(pg)
        pg.wait_for_selector("#session-results .result")
        assert "a mirror was already running; the console attached to it (it did not start it)" in text(pg, "#session-results")
        assert eb.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "agent"
    finally:
        ctx.close()


def test_stopping_the_consoles_own_idle_mirror_is_a_plain_confirm(browser, eb, hosts, fake_amt):
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("[data-stop=mirror]")
        pg.click("[data-stop=mirror]")
        s = sheet_text(pg)
        assert s.startswith(f"Stop the mirror of {KEY}") and "Releases the host's KVM session" in s and "tools/call amt_mirror_link {device: \"my-server-1\", action: \"stop\", confirmed: true}" in s
        assert pg.query_selector(".sheet.open .force-control") is None
        confirm_plain(pg)
        pg.wait_for_selector('#kvm-session[data-mirror-state="stopped"]')
        assert [a for a in calls(fake_amt, "amt_mirror_link", KEY) if a["action"] == "stop"] == [{"device": KEY, "action": "stop", "confirmed": True}]
        assert spy(pg)[0]["ctx"] == {"startedByAgent": False, "callInFlight": False} and spy(pg)[0]["forced"] is False
        assert "stopped · KVM session released" in text(pg, "#session-results")
        pg.wait_for_function("() => !document.querySelector('#kvm-screen iframe')")
    finally:
        ctx.close()


def test_stopping_a_mirror_an_agent_started_is_the_hold_and_only_a_hold_sends_it(browser, eb, hosts, fake_amt):
    seat(eb, hosts, "m", "agent")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("[data-stop=mirror]")
        pg.click("[data-stop=mirror]")
        assert pg.query_selector(".sheet.open[data-force-sheet] .force-control") is not None
        assert "stopping it ends the session under that agent's call, which then fails mid-sequence" in sheet_text(pg)
        assert pg.inner_text(".sheet.open .force-control .lbl") == "Hold to stop"
        pg.click(".sheet.open .force-control")                          # a click only opens the second sheet
        assert pg.evaluate("() => window.__forceFireCount()") == 0 and spy(pg) == []
        assert [a for a in calls(fake_amt, "amt_mirror_link", KEY) if a["action"] == "stop"] == []
        pg.keyboard.press("Escape")
        pg.click("[data-stop=mirror]")
        hold_to_fire(pg)
        pg.wait_for_selector('#kvm-session[data-mirror-state="stopped"]')
        assert pg.evaluate("() => window.__forceFireCount()") == 1
        assert [a for a in calls(fake_amt, "amt_mirror_link", KEY) if a["action"] == "stop"] == [{"device": KEY, "action": "stop", "confirmed": True}]
        assert spy(pg)[0]["forced"] is True and spy(pg)[0]["ctx"]["startedByAgent"] is True
    finally:
        ctx.close()


def test_stopping_any_mirror_while_an_agents_call_is_using_it_is_the_hold(browser, eb, hosts, viewer):
    seat(eb, hosts, "m", "console")
    viewer.status["m"]["in_flight"] = {"tool": "amt_remote_logon", "started_at": 1_760_000_000.0}
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#agent-strip:not([hidden])", timeout=8000)
        pg.click("[data-stop=mirror]")
        assert pg.query_selector(".sheet.open[data-force-sheet]") is not None
        assert sheet_text(pg).startswith(f"Stop the mirror on {KEY} while an agent's call is using it") and "An agent's call is using this mirror right now" in sheet_text(pg)
        pg.keyboard.press("Escape")
        viewer.status["m"]["in_flight"] = None                         # the call returned: the same button is a plain confirm again
        pg.wait_for_selector("#agent-strip", state="hidden", timeout=8000)
        pg.click("[data-stop=mirror]")
        assert pg.query_selector(".sheet.open[data-confirm-sheet]") is not None and pg.query_selector(".sheet.open .force-control") is None
    finally:
        ctx.close()


# -- the agent-typing strip (immutable 8) -----------------------------------------------------------------------------------

def test_an_agents_call_in_flight_shows_the_strip_and_takes_the_operators_control_away(browser, eb, hosts, viewer):
    seat(eb, hosts, "m", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#kvm-screen iframe")
        frame = pg.query_selector("#kvm-screen iframe").content_frame()
        frame.wait_for_selector("#ctl", state="visible")
        assert pg.is_hidden("#agent-strip") and pg.evaluate("() => document.querySelector('#kvm-screen iframe').inert") is False
        frame.click("#ctl")
        assert frame.inner_text("#ctl").strip() == "Release control"                  # the operator is controlling
        viewer.status["m"]["in_flight"] = {"tool": "amt_console_input", "started_at": 1_760_000_000.0}
        pg.wait_for_selector("#agent-strip:not([hidden])", timeout=8000)
        t = text(pg, "#agent-strip")
        assert t.startswith("AGENT TYPING · an agent's call holds this session for a moment · your keys and mouse are paused until it returns") and "amt_console_input" in t
        assert pg.get_attribute("#agent-strip", "data-session") == "agent_typing"
        assert pg.evaluate("() => document.querySelector('#kvm-screen iframe').inert") is True
        assert pg.evaluate("""() => { const f = document.querySelector('#kvm-screen iframe'), r = f.getBoundingClientRect();
          return document.elementFromPoint(r.left + r.width / 2, r.top + r.height / 2) !== f; }""")          # the pointer cannot reach the frame
        frame.wait_for_function("() => document.querySelector('#ctl').textContent.trim() === 'Take control'", timeout=5000)   # the viewer released control on blur
        viewer.status["m"]["in_flight"] = None
        pg.wait_for_selector("#agent-strip", state="hidden", timeout=8000)
        assert pg.evaluate("() => document.querySelector('#kvm-screen iframe').inert") is False
    finally:
        ctx.close()


# -- the macro grid, the screen guard and the text step (immutable 6) -------------------------------------------------------

def live_input_schema():
    """The live amt_console_input schema, read in a thread of its own (the browser fixture's event loop owns this one)."""
    import asyncio
    from concurrent.futures import ThreadPoolExecutor

    def read():
        import amt_server
        return {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}["amt_console_input"].inputSchema
    with ThreadPoolExecutor(1) as pool:
        return pool.submit(read).result()


def validator():
    jsonschema = pytest.importorskip("jsonschema", reason="jsonschema is not installed: the macro schema check is NOT run")
    return jsonschema.Draft202012Validator(live_input_schema())


def lit(v):                                                             # the sheet's literal form of an argument (components.js lit)
    if v is None or not isinstance(v, (dict, list)):
        return json.dumps(v)
    if isinstance(v, list):
        return "[" + ", ".join(lit(x) for x in v) + "]"
    return "{" + ", ".join(f"{k}: {lit(x)}" for k, x in v.items()) + "}"


GUARD_LABELS = ["desktop", "windows-signin", "linux-console", "bios-setup", "grub", "text-installer", "mok-manager"]


def input_results(fake):
    return [a for t, a, _ in fake.calls if t == "amt_console_input"]


def test_every_macro_grid_entry_sends_its_exact_call_and_validates_against_the_live_schema(browser, eb, hosts, fake_amt):
    v = validator()
    fake_amt.results["amt_console_input"] = lambda a: {"device": a["device"], "steps_run": len(a["actions"]), "kinds": ["macro"], "screenshot": None}
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#macro-grid button")
        entries = pg.evaluate("() => Array.from(document.querySelectorAll('#macro-grid button')).map(b => ({ label: b.textContent, json: JSON.parse(b.getAttribute('data-json')) }))")
        assert len(entries) == 26 and len({e["label"] for e in entries}) == 26
        for i, e in enumerate(entries):
            pg.click(f"#macro-grid button:nth-child({i + 1})")
            s = sheet_text(pg)
            assert s.startswith(f"Send {e['label']} to {KEY}") and f"tools/call amt_console_input {{device: \"{KEY}\", actions: [{lit(e['json'])}], confirmed: true}}" in s, (e, s)
            assert pg.query_selector(".sheet.open .force-control") is None
            confirm_plain(pg)
            pg.wait_for_function(f"() => window.__callCount() === {i + 1}")
        sent = input_results(fake_amt)
        assert len(sent) == 26
        for e, args in zip(entries, sent):
            assert args == {"device": KEY, "actions": [e["json"]], "confirmed": True}
            assert list(v.iter_errors(args)) == [], (e, [x.message for x in v.iter_errors(args)])
        assert all(a["actions"][0]["kind"] in ("macro", "key") for a in sent) and not [a for a in sent if "expect" in a]
        assert {a["actions"][0]["macro"] for a in sent if a["actions"][0]["kind"] == "macro"} == {
            "ctrl_alt_del", "win", "win_l", "win_r", "alt_tab", "alt_f4", "f2", "f10", "f12"}
        assert len(text(pg, "#input-results")) > 0 and pg.errors == []
    finally:
        ctx.close()


def test_the_schema_check_rejects_an_entry_the_live_schema_does_not_allow():
    """Positive control: the validator the grid test uses is not vacuous."""
    v = validator()
    for bad in ({"kind": "macro", "macro": "ctrl_alt_f1"}, {"kind": "key", "key": "a", "modifiers": ["meta"]}, {"kind": "macro", "macro": "win", "extra": 1}, {"kind": "press", "key": "a"}):
        assert list(v.iter_errors({"device": KEY, "actions": [bad], "confirmed": True})), bad


@pytest.mark.parametrize("guard", GUARD_LABELS)
def test_a_screen_guard_becomes_the_tools_expect_and_any_sends_none(browser, eb, hosts, fake_amt, guard):
    v = validator()
    fake_amt.results["amt_console_input"] = lambda a: {"device": a["device"], "steps_run": 1, "kinds": ["macro"], "screenshot": None}
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#macro-grid button")
        assert pg.get_attribute('[data-guard="any"]', "aria-pressed") == "true"
        pg.click(f'[data-guard="{guard}"]')
        assert [pg.get_attribute(f'[data-guard="{g}"]', "aria-pressed") for g in ["any"] + GUARD_LABELS].count("true") == 1
        pg.click("#macro-grid button:nth-child(15)")                    # F2
        s = sheet_text(pg)
        assert f'actions: [{{kind: "macro", macro: "f2"}}], expect: ["{guard}"], confirmed: true' in s and f"unless the screen is {guard}, nothing is sent" in s
        confirm_plain(pg)
        pg.wait_for_selector("#input-results .result")
        args, = input_results(fake_amt)
        assert args == {"device": KEY, "actions": [{"kind": "macro", "macro": "f2"}], "expect": [guard], "confirmed": True} and list(v.iter_errors(args)) == []
        assert f"F2 with guard {guard}" in text(pg, "#input-results")
        pg.click('[data-guard="any"]')
        pg.click("#macro-grid button:nth-child(15)")
        assert "expect" not in sheet_text(pg) and "No screen guard is set" in sheet_text(pg)
    finally:
        ctx.close()


def test_a_guard_that_sees_another_screen_is_an_abort_rendered_verbatim_with_no_retry(browser, eb, hosts, fake_amt):
    reason = "Error executing tool amt_console_input: screen_not_expected:saw=linux-console:expected=grub"
    fake_amt.results["amt_console_input"] = lambda a: tool_error(reason)
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#macro-grid button")
        pg.click('[data-guard="grub"]')
        pg.click("#macro-grid button:nth-child(15)")
        confirm_plain(pg)
        pg.wait_for_selector("#input-results .result.error")
        t = text(pg, "#input-results .result.error")
        assert f"F2 with guard grub · refused: {reason} · no key, click or text was sent" in t
        assert not [b for b in pg.query_selector_all("#input-results button, #input-results a") if "retry" in b.inner_text().lower() or "again" in b.inner_text().lower()]
        assert len(input_results(fake_amt)) == 1                       # one attempt: nothing sent it a second time
    finally:
        ctx.close()


def test_the_text_step_types_printable_ascii_up_to_500_characters_and_nothing_else(browser, eb, hosts, fake_amt):
    v = validator()
    fake_amt.results["amt_console_input"] = lambda a: {"device": a["device"], "steps_run": 1, "kinds": ["text"], "screenshot": None}
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#type-text")
        assert pg.get_attribute("#type-text", "aria-disabled") == "true" and "type the text to send" in text(pg, "#field-text ~ .btn-wrap .reason, .btn-wrap:has(#type-text) .reason")
        for bad, why in (("héllo", "printable ASCII only"), ("a\tb", "printable ASCII only"), ("x" * 501, "at most 500 characters (this is 501)")):
            pg.fill("#txt", bad)
            assert pg.get_attribute("#type-text", "aria-disabled") == "true"
            assert why in text(pg, "#field-text .help") and why in text(pg, ".btn-wrap:has(#type-text) .reason")
            pg.click("#type-text", force=True)
            assert pg.query_selector(".sheet.open") is None              # a disabled control ignores activation
        pg.fill("#txt", "x" * 500)
        assert pg.get_attribute("#type-text", "aria-disabled") is None
        pg.fill("#txt", "ls -la /boot")
        assert pg.query_selector(".btn-wrap:has(#type-text) .reason") is None
        pg.click("#type-text")
        assert 'actions: [{kind: "text", text: "ls -la /boot"}], confirmed: true' in sheet_text(pg) and "Never a credential" in sheet_text(pg)
        confirm_plain(pg)
        pg.wait_for_selector("#input-results .result.ok")
        args, = input_results(fake_amt)
        assert args == {"device": KEY, "actions": [{"kind": "text", "text": "ls -la /boot"}], "confirmed": True} and list(v.iter_errors(args)) == []
        assert not [c for c in spy(pg) if any(a.get("kind") == "secret" for a in c["arguments"].get("actions", []))]
    finally:
        ctx.close()


def test_the_console_has_no_raw_secret_step_anywhere():
    import re
    from pathlib import Path
    static = Path(__file__).resolve().parent.parent / "static"
    for name in ("console.js", "serial.js", "embed.js"):
        src = (static / name).read_text()
        assert not re.search(r"""kind\s*:\s*['"]secret|host_password|host_user|secret\s*:""", src), name


# -- host sign-in: one attempt, no retry control (immutable 7) ---------------------------------------------------------------

LOGON_OK = {"aborted": False, "device": KEY, "screen_label": "linux-console", "ocr_backend": "tesseract", "login_incorrect": False, "logged_in": True,
            "logged_in_basis": "classifier: the Linux console's last line after the password (a shell prompt, or Login incorrect / a new login prompt)", "screenshot": None}
LOGON_ABORT = {"aborted": True, "reason": "console_not_at_login_prompt", "device": KEY, "typed_nothing": True, "screen_label": "linux-console", "ocr_backend": "tesseract",
               "note": "the last line was a Password: prompt someone else started", "screenshot": None}


def no_retry(pg, root):
    return [b.inner_text() for b in pg.query_selector_all(f"{root} button, {root} a") if any(w in b.inner_text().lower() for w in ("retry", "again"))]


def test_host_sign_in_sends_its_exact_call_once_and_shows_what_was_read_and_typed(browser, eb, hosts, fake_amt):
    fake_amt.results["amt_remote_logon"] = lambda a: LOGON_OK
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.click("#signin-btn")
        s = sheet_text(pg)
        assert s.startswith(f"Sign in to {KEY}'s console") and f'tools/call amt_remote_logon {{device: "{KEY}", console: "kvm", confirmed: true}}' in s
        confirm_plain(pg)
        pg.wait_for_selector("#signin-results .result.ok")
        t = text(pg, "#signin-results .result.ok")
        assert "sign in · name and password typed once · logged_in: true" in t and "screen linux-console" in t and "ocr tesseract" in t
        assert [a for t_, a, _ in fake_amt.calls if t_ == "amt_remote_logon"] == [{"device": KEY, "console": "kvm", "confirmed": True}]
        assert pg.get_attribute("#signin-btn", "aria-disabled") is None
        pg.click("#signout-btn")
        assert f'tools/call amt_remote_logoff {{device: "{KEY}", console: "kvm", confirmed: true}}' in sheet_text(pg) and sheet_text(pg).startswith(f"Sign out of {KEY}'s console")
    finally:
        ctx.close()


def test_a_sign_in_that_aborts_shows_its_reason_and_what_was_typed_and_offers_no_retry(browser, eb, hosts, fake_amt):
    fake_amt.results["amt_remote_logon"] = lambda a: LOGON_ABORT
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.click("#signin-btn")
        confirm_plain(pg)
        pg.wait_for_selector("#signin-results .result.error")
        t = text(pg, "#signin-results .result.error")
        assert "sign in · aborted: console_not_at_login_prompt · typed nothing · the last line was a Password: prompt someone else started" in t
        assert "screen linux-console" in t and "ocr tesseract" in t and "not retried: look at the console and try again yourself" in t
        assert no_retry(pg, "#signin-btn ~ *, .card:has(#signin-btn)") == []
        assert [b.inner_text() for b in pg.query_selector_all(".card:has(#signin-btn) button")] == ["Sign in to host", "Sign out"]
    finally:
        ctx.close()


def test_a_wrong_password_is_logged_in_false_and_not_retried(browser, eb, hosts, fake_amt):
    fake_amt.results["amt_remote_logon"] = lambda a: {**LOGON_OK, "logged_in": False, "login_incorrect": True}
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.click("#signin-btn")
        confirm_plain(pg)
        pg.wait_for_selector("#signin-results .result.error")
        assert "logged_in: false (Login incorrect) · not retried" in text(pg, "#signin-results .result.error")
        assert no_retry(pg, ".card:has(#signin-btn)") == []
    finally:
        ctx.close()


def test_a_sign_in_is_one_attempt_the_control_ignores_a_second_while_the_first_is_out(browser, eb, hosts, fake_amt):
    import threading
    gate = threading.Event()

    def slow(a):
        gate.wait(10)
        return LOGON_OK
    fake_amt.results["amt_remote_logon"] = slow
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.click("#signin-btn")
        confirm_plain(pg)
        pg.wait_for_function("() => document.querySelector('#signin-btn').getAttribute('aria-disabled') === 'true'")
        assert "one attempt: waiting for amt-mcp" in text(pg, ".card:has(#signin-btn)")
        pg.click("#signin-btn", force=True)
        assert pg.query_selector(".sheet.open") is None                 # the disabled control opens nothing
        gate.set()
        pg.wait_for_selector("#signin-results .result.ok")
        assert pg.get_attribute("#signin-btn", "aria-disabled") is None and len([1 for t, _, _ in fake_amt.calls if t == "amt_remote_logon"]) == 1
    finally:
        gate.set()
        ctx.close()


def test_a_held_enter_on_a_macro_opens_one_sheet_and_sends_nothing(browser, eb, hosts, fake_amt):
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#macro-grid button")
        pg.focus("#macro-grid button:nth-child(1)")
        pg.evaluate("() => { window.__opens = 0; document.addEventListener('sheet-open', () => window.__opens++, true); }")
        pg.keyboard.down("Enter")
        for _ in range(20):
            pg.keyboard.down("Enter"); pg.wait_for_timeout(33)
        pg.keyboard.up("Enter")
        assert pg.evaluate("() => window.__opens") == 1                         # one deliberate activation opened one sheet
        assert pg.evaluate("() => window.__callCount()") == 0 and input_results(fake_amt) == []
    finally:
        ctx.close()


# =================================== the Serial tab ====================================================================

CAST = "my-server-1-serial-20261020T094000.123456Z.cast"


def sol_text(pg):
    return pg.inner_text("#sol-session").replace("\n", " ")


def sol_calls(fake, tool="amt_serial_link"):
    return [a for t, a, _ in fake.calls if t == tool]


def test_a_terminal_the_console_started_is_yours_and_has_recording_stop_and_open_in_a_tab(browser, eb, hosts):
    seat(eb, hosts, "s", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.wait_for_selector('#sol-session[data-serial-state="console"] [data-session="held_console"]')
        assert text(pg, '#sol-session [data-session="held_console"]').startswith("SOL · you (console) · ")
        assert [b.inner_text() for b in pg.query_selector_all("#sol-session button")] == ["Start recording", "Stop terminal"]
        pg.wait_for_selector('#sol-session a:has-text("Open in a tab")[href]')
        link = pg.query_selector('#sol-session a:has-text("Open in a tab")')
        assert re.fullmatch(rf"/embed/serial/{KEY}/[A-Za-z0-9_-]{{43}}/", link.get_attribute("href"))
        assert (link.get_attribute("href"), link.get_attribute("target")) == (pg.get_attribute("#sol-screen iframe", "src"), "_blank")
        assert "amt_sol shares this session while it runs" in sol_text(pg)
    finally:
        ctx.close()


def test_a_terminal_an_agent_started_is_the_agents_and_none_offers_start(browser, eb, hosts):
    seat(eb, hosts, "s", "agent")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.wait_for_selector('#sol-session[data-serial-state="agent"] [data-session="held_agent"]')
        assert text(pg, '#sol-session [data-session="held_agent"]').startswith("SOL · agent via terminal")
        assert text(pg, "[data-stop=terminal]") == "Stop the agent's terminal"
        assert text(pg, "#sol-session").count("the console attached to it") == 1
    finally:
        ctx.close()
    seat(eb, hosts, "s", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.wait_for_selector('#sol-session[data-serial-state="stopped"]')
        assert "no terminal running · SOL free" in sol_text(pg) and text(pg, "#start-terminal-btn") == "Start terminal"
        assert pg.query_selector("#sol-screen iframe") is None and "No terminal is running" in text(pg, "#sol-screen")
    finally:
        ctx.close()


def test_start_terminal_is_a_plain_sheet_with_the_exact_call(browser, eb, hosts, fake_amt):
    seat(eb, hosts, "s", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.click("#start-terminal-btn")
        s = sheet_text(pg)
        assert s.startswith(f"Start a serial terminal of {KEY}") and ('tools/call amt_serial_link {device: "my-server-1", action: "start", bind: "0.0.0.0", port: 8766, record_on_start: false, confirmed: true}' in s)
        assert pg.query_selector(".sheet.open .force-control") is None
        confirm_plain(pg)
        pg.wait_for_selector('#sol-session[data-serial-state="console"]')
        assert [a for a in sol_calls(fake_amt) if a["action"] == "start"] == [{"device": KEY, "action": "start", "bind": "0.0.0.0", "port": 8766, "record_on_start": False, "confirmed": True}]
        pg.wait_for_selector("#sol-screen iframe")
        assert len(spy(pg)) == 1
    finally:
        ctx.close()


def test_stopping_a_terminal_is_plain_for_the_consoles_own_idle_one_and_the_hold_for_an_agents_or_one_in_use(browser, eb, hosts, fake_amt, viewer):
    seat(eb, hosts, "s", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.wait_for_selector("[data-stop=terminal]")
        pg.click("[data-stop=terminal]")
        assert pg.query_selector(".sheet.open[data-confirm-sheet]") is not None and "Releases the host's SOL session" in sheet_text(pg)
        assert 'tools/call amt_serial_link {device: "my-server-1", action: "stop", confirmed: true}' in sheet_text(pg)
        pg.keyboard.press("Escape")
        viewer.status["s"]["in_flight"] = {"tool": "amt_sol", "started_at": 1_760_000_000.0}
        pg.wait_for_selector("#agent-strip:not([hidden])", timeout=8000)
        assert "your keys are paused" in text(pg, "#agent-strip") and "amt_sol" in text(pg, "#agent-strip")
        pg.click("[data-stop=terminal]")
        assert pg.query_selector(".sheet.open[data-force-sheet]") is not None and sheet_text(pg).startswith(f"Stop the terminal on {KEY} while an agent's call is using it")
        pg.keyboard.press("Escape")
        viewer.status["s"]["in_flight"] = None
        pg.wait_for_selector("#agent-strip", state="hidden", timeout=8000)
        pg.click("[data-stop=terminal]")
        confirm_plain(pg)
        pg.wait_for_selector('#sol-session[data-serial-state="stopped"]')
        assert [a for a in sol_calls(fake_amt) if a["action"] == "stop"] == [{"device": KEY, "action": "stop", "confirmed": True}]
    finally:
        ctx.close()
    seat(eb, hosts, "s", "agent")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.wait_for_selector("[data-stop=terminal]")
        pg.click("[data-stop=terminal]")
        assert pg.query_selector(".sheet.open[data-force-sheet]") is not None and sheet_text(pg).startswith(f"Stop the terminal an agent started on {KEY}")
        hold_to_fire(pg)
        pg.wait_for_selector('#sol-session[data-serial-state="stopped"]')
        assert pg.evaluate("() => window.__forceFireCount()") == 1 and spy(pg)[0]["forced"] is True
    finally:
        ctx.close()


def test_a_recording_is_started_and_stopped_by_sheets_and_the_finished_cast_becomes_a_capture(browser, eb, hosts, fake_amt):
    hosts.recording_path = f"/data/recordings/{CAST}"
    item = {"name": CAST, "kind": "serial_cast", "device": KEY, "bytes": 18_000, "modified": "2026-10-20T13:52:00Z"}
    listed = []
    fake_amt.results["amt_captures"] = lambda a: ({"total": len(listed), "offset": 0, "captures": listed, "next_offset": None,
                                                   "searched": [{"dir": "/r", "kinds": ["recording", "serial_cast"], "found": True}]} if a["action"] == "list"
                                                  else fake_amt.offer(b"CAST-DATA", a["name"]))
    seat(eb, hosts, "s", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.wait_for_selector("#rec-start-btn")
        assert "amt_captures · read-only" in text(pg, "#rec-h") and "lists no serial casts" in text(pg, "#rec-list")
        pg.click("#rec-start-btn")
        assert sheet_text(pg).startswith("Record this terminal") and 'tools/call amt_serial_link {device: "my-server-1", action: "record_start", confirmed: true}' in sheet_text(pg)
        confirm_plain(pg)
        pg.wait_for_selector("#rec-stop-btn", timeout=8000)                    # the session card now offers Stop recording
        assert "recording · " in text(pg, "#sol-session")
        listed.append(item)                                                    # amt-mcp lists the cast once it is closed
        pg.click("#rec-stop-btn")
        assert 'tools/call amt_serial_link {device: "my-server-1", action: "record_stop", confirmed: true}' in sheet_text(pg)
        confirm_plain(pg)
        pg.wait_for_selector("#session-results .result.ok:has-text('verified')")
        t = text(pg, "#session-results")
        assert f"recording · {CAST} · 9 B · sha256 " in t and "verified · listed by amt_captures · fetched once, kept in the capture store" in t
        assert [a for a in calls(fake_amt, "amt_captures") if a["action"] == "fetch"] == [{"action": "fetch", "name": CAST}]
        href = pg.get_attribute("#session-results a.btn", "href")
        assert eb.get(href).data == b"CAST-DATA" and "handoffs" not in pg.content()
        pg.wait_for_selector("#rec-list li a.btn")                             # the Recordings list shows the same capture, saved
        assert "serial cast · 2026-10-20 09:52:00 EDT · 18 KB" in text(pg, "#rec-list") and "verified · kept in the capture store" in text(pg, "#rec-list")
        assert list(fake_amt.fetches.values()) == [1]
    finally:
        ctx.close()


def captures_scripted(fake_amt):
    fake_amt.results["amt_captures"] = lambda a: ({"total": 0, "offset": 0, "captures": [], "next_offset": None, "searched": []} if a["action"] == "list"
                                                  else fake_amt.offer(b"CAST-DATA", a["name"]))


def test_stopping_the_terminal_saves_the_recording_it_closed_but_not_one_already_stopped_and_saved(browser, eb, hosts, fake_amt):
    hosts.recording_path = f"/data/recordings/{CAST}"
    captures_scripted(fake_amt)
    seat(eb, hosts, "s", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.click("#rec-start-btn")
        confirm_plain(pg)
        pg.wait_for_selector("#rec-stop-btn", timeout=8000)
        pg.click("#rec-stop-btn")
        confirm_plain(pg)
        pg.wait_for_selector("#session-results .result.ok:has-text('verified')")
        pg.wait_for_selector("#rec-start-btn")                                 # the card re-read: no recording runs now
        pg.click("[data-stop=terminal]")                                       # amt_serial's stop still returns the last recording
        confirm_plain(pg)
        pg.wait_for_selector('#sol-session[data-serial-state="stopped"]')
        pg.wait_for_selector("#session-results .result:has-text('stop terminal')")
        assert [a["name"] for a in calls(fake_amt, "amt_captures") if a["action"] == "fetch"] == [CAST]
        assert pg.locator(f"#session-results .result:has-text('recording · {CAST}')").count() == 1
    finally:
        ctx.close()
    seat(eb, hosts, "s", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.click("#rec-start-btn")
        confirm_plain(pg)
        pg.wait_for_selector("#rec-stop-btn", timeout=8000)
        pg.click("[data-stop=terminal]")                                       # a recording still running is closed by the stop and kept
        confirm_plain(pg)
        pg.wait_for_selector("#session-results .result.ok:has-text('verified')")
        assert [a["name"] for a in calls(fake_amt, "amt_captures") if a["action"] == "fetch"] == [CAST, CAST]
    finally:
        ctx.close()


def test_a_recording_that_amt_mcp_cannot_hand_over_yet_is_reported_not_claimed(browser, eb, hosts, fake_amt):
    hosts.recording_path = f"/data/recordings/{CAST}"
    fake_amt.results["amt_captures"] = lambda a: {"total": 0, "offset": 0, "captures": [], "next_offset": None, "searched": []} if a["action"] == "list" else tool_error("capture_not_found: not listed yet")
    seat(eb, hosts, "s", "console")
    viewer_rec = {"path": "/r/x", "frames": 0, "bytes": 0, "started": 1.0, "seconds": 2.0, "ended": False}
    hosts.viewer.status["s"]["recording"] = viewer_rec
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.click("#rec-stop-btn")
        confirm_plain(pg)
        pg.wait_for_selector("#session-results .result.live:has-text('not kept as a capture yet')")
        assert "capture_not_found: not listed yet" in text(pg, "#session-results") and "Recordings when amt-mcp lists it" in text(pg, "#session-results")
    finally:
        ctx.close()


# -- Send a line ------------------------------------------------------------------------------------------------------------

def test_send_a_line_sends_the_exact_amt_sol_call_and_shows_the_output_as_text(browser, eb, hosts, fake_amt):
    out = "$ id\r\nuid=0(root) <img src=x onerror=window.pwned=1> &amp;"
    fake_amt.results["amt_sol"] = lambda a: {"device": a["device"], "sent_chars": len(a["text"]), "window_seconds": 3.0, "bytes": len(out), "truncated": False, "shared_terminal": True, "output": out}
    seat(eb, hosts, "s", "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.fill("#sl", "id")
        pg.click("#send-line")
        s = sheet_text(pg)
        assert s.startswith(f"Send a line to {KEY}'s serial console") and 'tools/call amt_sol {device: "my-server-1", text: "id\\n", read_seconds: 3, confirmed: true}' in s
        assert "Never a credential" in s and pg.query_selector(".sheet.open .force-control") is None
        confirm_plain(pg)
        pg.wait_for_selector("#line-results pre.out")
        assert [a for a in sol_calls(fake_amt, "amt_sol")] == [{"device": KEY, "text": "id\n", "read_seconds": 3, "confirmed": True}]
        assert pg.inner_text("#line-results pre.out") == out.replace("\r\n", "\n") or out in pg.text_content("#line-results pre.out")
        assert pg.query_selector("#line-results img") is None and pg.evaluate("() => window.pwned") is None     # the host's output is text, never markup
        assert "3 chars sent" in text(pg, "#line-results") and "through the live terminal: the viewer shows it" in text(pg, "#line-results")
        pg.click("#append-enter")                                                       # append Enter off: the text goes as typed
        pg.click("#send-line")
        assert 'text: "id", read_seconds: 3' in sheet_text(pg)
    finally:
        ctx.close()


def test_a_line_may_be_as_long_as_amt_sol_takes_with_its_enter_and_no_longer(browser, eb, hosts, fake_amt):
    import amt_write
    fake_amt.results["amt_sol"] = lambda a: {"device": a["device"], "sent_chars": len(a["text"]), "window_seconds": 3.0, "bytes": 0, "truncated": False, "output": ""}
    seat(eb, hosts, "s", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        longest = amt_write.MAX_SOL_SEND - 1                                          # the appended Enter is the last character the tool takes
        pg.fill("#sl", "a" * (longest + 1))
        assert pg.get_attribute("#send-line", "aria-disabled") == "true" and f"at most {longest} characters (this is {longest + 1})" in text(pg, ".btn-wrap:has(#send-line) .reason")
        pg.fill("#sl", "a" * longest)
        assert pg.get_attribute("#send-line", "aria-disabled") is None
        pg.click("#send-line")
        confirm_plain(pg)
        pg.wait_for_selector("#line-results .result.ok")
        assert [len(a["text"]) for a in sol_calls(fake_amt, "amt_sol")] == [amt_write.MAX_SOL_SEND]
    finally:
        ctx.close()


def test_a_line_must_be_printable_ascii_and_a_refusal_is_verbatim(browser, eb, hosts, fake_amt):
    fake_amt.results["amt_sol"] = lambda a: tool_error("Error executing tool amt_sol: another session is open")
    seat(eb, hosts, "s", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.fill("#sl", "café")
        assert pg.get_attribute("#send-line", "aria-disabled") == "true" and "printable ASCII only" in text(pg, ".btn-wrap:has(#send-line) .reason")
        pg.click("#send-line", force=True)
        assert pg.query_selector(".sheet.open") is None
        pg.fill("#sl", "ls")
        assert pg.get_attribute("#send-line", "aria-disabled") is None
        pg.click("#send-line")
        confirm_plain(pg)
        pg.wait_for_selector("#line-results .result.error")
        assert "send a line · refused: Error executing tool amt_sol: another session is open" in text(pg, "#line-results")
        assert pg.get_attribute("#send-line", "aria-disabled") is None
    finally:
        ctx.close()


# -- host sign-in on the serial getty ---------------------------------------------------------------------------------------

def test_serial_sign_in_and_out_send_console_serial_and_an_abort_has_no_retry(browser, eb, hosts, fake_amt):
    fake_amt.results["amt_remote_logon"] = lambda a: {"device": KEY, "console": "serial", "shared_terminal": True, "enter_sent_to_find_prompt": False, "aborted": True,
                                                      "reason": "console_not_at_login_prompt", "typed_nothing": True, "console_prompt": "password"}
    fake_amt.results["amt_remote_logoff"] = lambda a: {"device": KEY, "console": "serial", "shared_terminal": False, "enter_sent_to_find_prompt": True, "aborted": False,
                                                       "logoff_submitted": True, "console_prompt": "login", "logged_off": True, "logged_off_basis": "classifier: the serial console's last line after exit"}
    seat(eb, hosts, "s", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/serial")
    try:
        pg.click("#signin-btn")
        assert sheet_text(pg).startswith(f"Sign in to {KEY} over serial") and f'tools/call amt_remote_logon {{device: "{KEY}", console: "serial", confirmed: true}}' in sheet_text(pg)
        confirm_plain(pg)
        pg.wait_for_selector("#signin-results .result.error")
        t = text(pg, "#signin-results .result.error")
        assert "sign in (SOL) · aborted: console_not_at_login_prompt · typed nothing" in t and "last line password" in t and "through the live terminal" in t
        assert no_retry(pg, ".card:has(#signin-btn)") == []
        pg.click("#signout-btn")
        assert f'tools/call amt_remote_logoff {{device: "{KEY}", console: "serial", confirmed: true}}' in sheet_text(pg)
        confirm_plain(pg)
        pg.wait_for_selector("#signin-results .result.ok")
        assert "exit sent · logged_off: true" in text(pg, "#signin-results .result.ok") and "one Enter sent to find the prompt" in text(pg, "#signin-results .result.ok")
        assert [a for t_, a, _ in fake_amt.calls if t_ in ("amt_remote_logon", "amt_remote_logoff")] == [
            {"device": KEY, "console": "serial", "confirmed": True}, {"device": KEY, "console": "serial", "confirmed": True}]
    finally:
        ctx.close()


# -- immutables 13, 14 and the contrast floor on both pages (the design's own page walk) -------------------------------------

def busy_page(eb, hosts, viewer, prefix):
    viewer.status[prefix]["in_flight"] = {"tool": "amt_console_input" if prefix == "m" else "amt_sol", "started_at": 1_760_000_000.0}
    seat(eb, hosts, prefix, "console")


@pytest.mark.parametrize("scheme", ["light", "dark"])
@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("tab,prefix,screen", [("console", "m", "#kvm-screen"), ("serial", "s", "#sol-screen")])
def test_the_console_and_serial_pages_fit_every_width_with_hit_areas_and_gutters(browser, eb, hosts, viewer, fake_amt, tab, prefix, screen, width, scheme):
    cm = check_mockups()
    fake_amt.results["amt_console_input"] = lambda a: tool_error("Error executing tool amt_console_input: screen_not_expected:saw=linux-console:expected=grub")
    fake_amt.results["amt_remote_logon"] = lambda a: LOGON_ABORT
    busy_page(eb, hosts, viewer, prefix)
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/{tab}", width=width, scheme=scheme)
    try:
        pg.wait_for_selector(f"{screen} iframe")
        pg.wait_for_selector("#agent-strip:not([hidden])", timeout=8000)
        pg.click("#signin-btn")
        confirm_plain(pg)
        pg.wait_for_selector("#signin-results .result")
        if tab == "console":
            pg.click('[data-guard="grub"]')
            pg.click("#macro-grid button:nth-child(15)")
            confirm_plain(pg)
            pg.wait_for_selector("#input-results .result.error")
        r, bottom, anim = walk(pg, cm)
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
        assert len(r["targets"]) >= 8 and r["text"], "the walk saw nothing: it would pass on an empty page"
        assert pg.errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
@pytest.mark.parametrize("tab,prefix,screen", [("console", "m", "#kvm-screen"), ("serial", "s", "#sol-screen")])
def test_every_text_and_ring_on_the_console_and_serial_pages_clears_the_contrast_floors(browser, eb, hosts, viewer, fake_amt, tab, prefix, screen, scheme):
    cm = check_mockups()
    fake_amt.results["amt_remote_logon"] = lambda a: LOGON_ABORT
    busy_page(eb, hosts, viewer, prefix)
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/{tab}", width=1024, scheme=scheme)
    try:
        pg.wait_for_selector(f"{screen} iframe")
        pg.wait_for_selector("#agent-strip:not([hidden])", timeout=8000)
        pg.click("#signin-btn")
        confirm_plain(pg)
        pg.wait_for_selector("#signin-results .result")
        r, _, _ = walk(pg, cm)
        low = [(t["snippet"], t["ratio"], t["ex"]) for t in r["text"] if t["ratio"] < (3.0 if t["large"] else 4.5)]
        assert low == [], low
        assert len(r["text"]) > 20
    finally:
        ctx.close()


def test_a_disabled_control_on_these_pages_is_focusable_and_says_why(browser, eb, hosts):
    seat(eb, hosts, "m", "free")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/console")
    try:
        pg.wait_for_selector("#type-text")
        info = pg.evaluate("() => { const b = document.querySelector('#type-text'); b.focus(); return { disabled: b.getAttribute('aria-disabled'), tab: b.tabIndex, focused: document.activeElement === b, reason: b.parentNode.querySelector('.reason').textContent }; }")
        assert info == {"disabled": "true", "tab": 0, "focused": True, "reason": "type the text to send"}
    finally:
        ctx.close()


# -- immutable 4: nothing outside a sheet sends a write on a bare click -----------------------------------------------------

WRITE_TOOLS = {"amt_power", "amt_set_next_boot", "amt_console_input", "amt_sol", "amt_ider", "amt_images", "amt_configure", "amt_wsman_invoke",
               "amt_remote_logon", "amt_remote_logoff", "amt_device_manage", "amt_identity_manage"}


def sent_writes(fake, since=0):
    reads = ("status", "list", "verify")                                 # the actions that read or release only (note 9, immutable 6)
    return [(t, a) for t, a, _ in fake.calls[since:] if (t in WRITE_TOOLS or t in ("amt_mirror_link", "amt_serial_link")) and a.get("action") not in reads]


@pytest.mark.parametrize("tab,prefix,screen", [("console", "m", "#kvm-screen"), ("serial", "s", "#sol-screen")])
def test_a_bare_click_on_any_control_of_these_pages_sends_no_write_and_fires_no_force(browser, eb, hosts, fake_amt, tab, prefix, screen):
    seat(eb, hosts, prefix, "console")
    ctx, pg = open_page(browser, eb, f"/server/{KEY}/{tab}")
    try:
        pg.wait_for_selector(f"{screen} iframe")
        pg.fill("#txt" if tab == "console" else "#sl", "ls")
        since = len(fake_amt.calls)                                    # the console's own start (the setup) is behind us
        count = pg.evaluate("() => document.querySelectorAll('.content button, .content [role=checkbox]').length")
        assert count >= (30 if tab == "console" else 6), count
        for i in range(count):
            el = pg.query_selector_all(".content button, .content [role=checkbox]")[i]
            if el.get_attribute("aria-disabled") == "true":
                continue
            el.click()
            pg.keyboard.press("Escape")
        assert pg.evaluate("() => window.__callCount()") == 0 and pg.evaluate("() => window.__forceFireCount()") == 0
        assert sent_writes(fake_amt, since) == []
    finally:
        ctx.close()
