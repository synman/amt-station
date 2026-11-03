"""The fleet and server pages in a real browser (headless Chromium), against scripted amt-mcp answers (packet C2).

Immutables 7 (the refusal and the paused card), 8 (the holder on the header, the card and the sessions panel), 13 and 14
(layout and hit areas at every width), 18 (a disabled control), 19 (coverage), plus the screenshot sheet and the past
captures. The design's own page walk (design/check_mockups.py JS_WALK) runs against the built pages."""
import pytest

from console_fakes import Authenticator, Console, check_mockups, enroll_first_passkey
from test_console_fleet import KEY, LEAF, MIRROR, STATUS, device, tool_error

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed: the browser immutables are NOT checked")

WIDTHS = [360, 600, 1024, 1440]


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
def fb(tmp_path, fake_amt):
    """A signed-in console whose servers are read by hand (read_all), every view idle."""
    console = Console(tmp_path, fake_amt)
    enroll_first_passkey(console, Authenticator(console.app.cfg.rp_id, console.origin))
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device()]}
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"]}
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_serial_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
    fake_amt.results["amt_identities"] = lambda a: {"identities": []}
    fake_amt.results["amt_captures"] = lambda a: {"total": 0, "offset": 0, "captures": [], "next_offset": None,
                                                  "searched": [{"dir": "/s", "kinds": ["screenshot"], "found": True}, {"dir": "/r", "kinds": ["recording", "serial_cast"], "found": True}]}
    yield console
    console.close()


def read_all(console):
    f = console.app.fleet
    f.refresh_devices()
    for k in list(f.order):
        f.refresh(k)


def open_page(browser, console, path, width=1024, scheme="light", **kw):
    ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme, **kw)
    ctx.add_cookies([{"name": "amt_console_session", "value": console.cookie, "domain": console.host, "path": "/",
                      "httpOnly": True, "secure": True, "sameSite": "Strict"}])
    pg = ctx.new_page()
    pg.errors, pg.requests = [], []
    pg.on("console", lambda m: pg.errors.append(m.text) if m.type == "error" else None)
    pg.on("pageerror", lambda e: pg.errors.append(str(e)))
    pg.on("request", lambda r: pg.requests.append(r.url))
    pg.goto(f"{console.origin}{path}")
    return ctx, pg


def text(pg, sel):
    return pg.inner_text(sel).replace("\n", " ")


def calls(fake, tool, key=None):
    return [a for t, a, _ in fake.calls if t == tool and (key is None or a.get("device") == key)]


# -- the fleet page: every state from a scripted result ---------------------------------------------------------------------

def test_a_live_server_card_has_the_pill_the_session_chips_the_pin_and_the_four_actions(browser, fb, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: MIRROR
    fake_amt.results["amt_ider"] = lambda a: {"device": KEY, "mounted": True, "images": {"iso": "debian-13.3-netinst.iso"}}
    fb.app.fleet.started[f"mirror:{KEY}"] = fb.app.fleet.now()
    read_all(fb)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector('.scard[data-fleet-state="live"]')
        card = '.scard[data-key="my-server-1"]'
        assert pg.get_attribute(f"{card} .pill", "data-power") == "on" and "On" in text(pg, f"{card} .pill")
        assert text(pg, f'{card} [data-session="held_console"]').startswith("KVM · you · 00:1")
        assert "IDE-R mounted" in text(pg, f'{card} [data-session="ider"]')
        assert text(pg, f'{card} [data-pin="matches"]') == "pin matches"
        assert "10.0.0.26 · AMT 19.0.5" in text(pg, f"{card} .slot-line") and "status read" in text(pg, f"{card} .slot-pin")
        acts = {a.inner_text().strip(): a.get_attribute("href") for a in pg.query_selector_all(f"{card} .acts a")}
        assert acts == {"KVM": "/server/my-server-1/console", "Power": "/server/my-server-1/power", "SOL": "/server/my-server-1/serial"}
        assert pg.get_attribute(f"{card} .acts button", "aria-label") == "Screenshot of my-server-1"
        banner = text(pg, "#fleet-banner")
        assert banner.startswith("1 session held by you: KVM on my-server-1, control, 00:1") and "1 IDE-R mount (my-server-1, debian-13.3-netinst.iso)" in banner and "no recording" in banner
        assert pg.get_attribute("#fleet-banner-open", "href") == "/server/my-server-1/console"
        assert text(pg, "#fleet-count") == "1 server" and "auto-refresh 30 s" in text(pg, "#fleet-note")
        assert pg.errors == []
    finally:
        ctx.close()


def test_an_agents_session_is_not_in_the_you_banner_and_a_free_one_says_free(browser, fb, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: MIRROR
    read_all(fb)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector(".scard")
        assert text(pg, '.scard [data-session="held_agent"]').startswith("KVM · agent via mirror · 00:1")
        assert pg.is_hidden("#fleet-banner")
    finally:
        ctx.close()
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": KEY, "live": False}
    fb.app.fleet.refresh(KEY)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector(".scard")
        assert text(pg, '.scard [data-session="free"]') == "KVM free"
    finally:
        ctx.close()


def test_an_unreachable_server_shows_the_tools_error_verbatim_and_the_retry(browser, fb, fake_amt):
    err = "amt_status failed: connect timed out (10 s). The pin was not checked because no TLS leaf was presented."
    fake_amt.results["amt_status"] = lambda a: tool_error(err)
    read_all(fb)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector('.scard[data-fleet-state="unreachable"]')
        card = ".scard"
        assert pg.get_attribute(f"{card} .pill", "data-power") == "unreachable" and "Unreachable" in text(pg, f"{card} .pill")
        assert err in text(pg, f"{card} .result.error") and "Next automatic read in" in text(pg, f"{card} .result.error")
        assert pg.get_attribute(f"{card} [data-pin]", "data-pin") == "unchecked"
        assert [b.inner_text().strip() for b in pg.query_selector_all(f"{card} .slot-acts .btn")] == ["Retry now", "Power", "Edit server"]
        assert pg.query_selector(f"{card} .acts") is None                       # no Console / Shot while it cannot be read
        # Retry now reads once, and a recovered host turns the card live
        fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"]}
        before = len(calls(fake_amt, "amt_status"))
        pg.click(f"{card} .slot-acts button")
        pg.wait_for_selector('.scard[data-fleet-state="live"]')
        assert len(calls(fake_amt, "amt_status")) == before + 1
    finally:
        ctx.close()


def test_a_paused_server_says_why_stops_reading_and_offers_one_retry(browser, fb, fake_amt):
    """Immutable 7: the 401 is shown with the one-attempt sentence, the card is paused, and no further amt_status follows."""
    fake_amt.results["amt_status"] = lambda a: tool_error("Error executing tool amt_status: wsman_auth_failed_401")
    read_all(fb)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector('.scard[data-fleet-state="paused"]')
        card = ".scard"
        assert pg.get_attribute(f"{card} .pill", "data-power") == "unknown"
        assert text(pg, f'{card} [data-session="paused"]') == "paused · credential refused"
        res = text(pg, f"{card} .result.error")
        assert "wsman_auth_failed_401" in res and "One Digest attempt, no further attempts: the account can lock." in res
        assert [b.inner_text().strip() for b in pg.query_selector_all(f"{card} .slot-acts .btn")] == ["Retry once", "Identities"]
        assert "no automatic reads" in text(pg, f"{card} .slot-pin")
        pg.wait_for_timeout(300)
        assert len(calls(fake_amt, "amt_status")) == 1
        pg.click(f"{card} .slot-acts button")                                   # Retry once: one attempt, refused again, still paused
        for _ in range(50):
            if len(calls(fake_amt, "amt_status")) == 2:
                break
            pg.wait_for_timeout(100)
        pg.wait_for_selector(f'{card}[data-fleet-state="paused"]')
        assert len(calls(fake_amt, "amt_status")) == 2
    finally:
        ctx.close()


def test_a_pin_mismatch_is_paused_with_the_pin_chip_in_the_error_state(browser, fb, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("tls_leaf_pin_mismatch")
    read_all(fb)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector('.scard[data-fleet-state="paused"]')
        assert text(pg, '.scard [data-pin="differs"]') == "pin differs · every call refused"
        assert "re-pinned in Manage" in text(pg, ".scard .result.error")
    finally:
        ctx.close()


def test_another_client_holding_kvm_is_an_error_chip_with_opens_refused(browser, fb, fake_amt):
    read_all(fb)
    fake_amt.results["amt_screenshot"] = lambda a: tool_error("another session is open")
    fb.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": KEY}})
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector(".scard")
        assert text(pg, '.scard [data-session="held_other"]') == "KVM · another client · opens refused"
        assert pg.inner_text(".scard .acts") != ""                              # the actions stay: the host itself is fine
    finally:
        ctx.close()


def test_a_server_not_read_yet_shows_a_reading_card_not_a_blank_one(browser, fb):
    fb.app.fleet.refresh_devices()                                              # listed, not yet read
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector('.scard[data-fleet-state="loading"]')
        assert "Reading" in text(pg, ".scard .pill") and pg.query_selector(".scard .progress") is not None
    finally:
        ctx.close()


def test_an_empty_fleet_says_why_and_a_failed_list_says_that(browser, fb, fake_amt):
    fake_amt.results["amt_devices"] = lambda a: {"source": "built-in", "devices": []}
    fb.app.fleet.refresh_devices()
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector("#fleet-empty:not([hidden])")
        assert "amt-mcp refuses to run with none" in text(pg, "#fleet-empty") and text(pg, "#fleet-count") == "0 servers"
    finally:
        ctx.close()
    fake_amt.results["amt_devices"] = lambda a: tool_error("devices file malformed")
    fb.app.fleet.refresh_devices()
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector("#fleet-error:not([hidden])")
        assert "amt-mcp could not list its servers: devices file malformed" in text(pg, "#fleet-error")
    finally:
        ctx.close()


def test_the_filters_narrow_by_text_and_by_state(browser, fb, fake_amt):
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device("alpha", ip="10.0.0.1"), device("bravo", ip="10.0.0.2"), device("charlie", ip="10.0.0.3")]}
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"], "power": {"state": "off_soft" if a["device"] == "bravo" else "on", "code": 8}} \
        if a["device"] != "charlie" else tool_error("connect timed out")
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": a["device"] == "alpha", "images": {"iso": "x.iso"}}
    read_all(fb)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector(".scard[data-key='charlie']:not([data-fleet-state='loading'])")
        shown = lambda: sorted(c.get_attribute("data-key") for c in pg.query_selector_all(".scard") if c.is_visible())
        assert shown() == ["alpha", "bravo", "charlie"]
        pg.fill("#q", "10.0.0.2"); assert shown() == ["bravo"]
        pg.fill("#q", "19.0.5"); assert shown() == ["alpha", "bravo"]               # the AMT version; charlie was never read
        pg.fill("#q", "zzz"); assert shown() == [] and pg.is_visible("#fleet-nomatch")
        pg.fill("#q", "")
        pg.click('[data-show="on"]'); assert shown() == ["alpha"]
        pg.click('[data-show="held"]'); assert shown() == ["alpha"]                   # the IDE-R mount
        pg.click('[data-show="problems"]'); assert shown() == ["charlie"]
        assert pg.get_attribute('[data-show="problems"]', "aria-pressed") == "true" and pg.get_attribute('[data-show="all"]', "aria-pressed") == "false"
        pg.click('[data-show="all"]'); assert len(shown()) == 3
    finally:
        ctx.close()


def test_the_problems_filter_includes_a_server_another_client_holds_the_kvm_of(browser, fb, fake_amt):
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device("alpha", ip="10.0.0.1"), device("bravo", ip="10.0.0.2")]}
    read_all(fb)
    fb.app.fleet.observe("amt_screenshot", {"device": "bravo"}, True, "Error executing tool amt_screenshot: redir_start_status_3")
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector('.scard[data-key="bravo"] [data-session="held_other"]')
        shown = lambda: sorted(c.get_attribute("data-key") for c in pg.query_selector_all(".scard") if c.is_visible())
        pg.click('[data-show="problems"]'); assert shown() == ["bravo"]
        pg.click('[data-show="all"]'); assert shown() == ["alpha", "bravo"]
    finally:
        ctx.close()


def test_a_retry_that_is_waiting_ignores_a_second_activation(browser, fb, fake_amt):
    """Immutable 18 on the card's Retry: while its read is out the button is aria-disabled and a second activation sends nothing.
    Two mechanisms hold this line, retryButton's own check and the document-level guard in components.js that swallows a
    click on any aria-disabled control, so only removing both turns this red."""
    import threading
    gate = threading.Event()
    fake_amt.results["amt_status"] = lambda a: tool_error("connect timed out")
    read_all(fb)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector('.scard[data-fleet-state="unreachable"]')

        def slow(a):
            gate.wait(5)
            return {**STATUS, "device": a["device"]}
        fake_amt.results["amt_status"] = slow
        pg.click(".scard .slot-acts button")
        pg.wait_for_selector(".scard .slot-acts button[aria-disabled=true]")
        pg.click(".scard .slot-acts button[aria-disabled=true]", force=True)       # activation while the read is waiting
        pg.wait_for_timeout(150)
        assert len([u for u in pg.requests if u.endswith("/api/fleet/refresh")]) == 1
        gate.set()
        pg.wait_for_selector('.scard[data-fleet-state="live"]')
    finally:
        gate.set()
        ctx.close()


def test_refresh_all_asks_the_backend_to_read_the_non_paused_servers(browser, fb, fake_amt):
    read_all(fb)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector(".scard")
        pg.click("#fleet-refresh")
        for _ in range(50):
            if fb.app.fleet.entries[KEY]["next_due"] <= fb.app.fleet.now():
                break
            pg.wait_for_timeout(50)
        assert fb.app.fleet.entries[KEY]["next_due"] <= fb.app.fleet.now()
    finally:
        ctx.close()


# -- the screenshot sheet and the capture card -------------------------------------------------------------------------------

def shot(fake, data=b"\x89PNG-bytes", name="amt-my-server-1-shot.png"):
    out = fake.offer(data, name)
    return {**out, "device": KEY, "width": 1280, "height": 800, "bytes": len(data), "iterations": 3, "stable": True, "delta_bits": 0}


def test_the_screenshot_sheet_is_a_plain_confirm_that_sends_the_read_tool_once(browser, fb, fake_amt):
    read_all(fb)
    fake_amt.results["amt_screenshot"] = lambda a: shot(fake_amt)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector(".scard .acts button")
        pg.click(".scard .acts button")
        pg.wait_for_selector(".sheet.open")
        assert pg.evaluate("() => window.__callCount()") == 0 and not calls(fake_amt, "amt_screenshot")      # opening is not a call
        assert pg.evaluate("() => document.activeElement.hasAttribute('data-close')")                          # focus on Cancel
        sheet = text(pg, ".sheet.open")
        assert "Take a screenshot of my-server-1" in sheet and "tools/call amt_screenshot {device: \"my-server-1\"}" in sheet and "confirmed" not in sheet
        assert "single KVM session" in sheet and "It sends no input." in sheet and not pg.query_selector(".sheet.open [data-hold]")
        pg.click(".sheet.open [data-confirm]")
        pg.wait_for_selector(".scard .shot .result.ok")
        assert pg.evaluate("() => window.__callCount()") == 1
        assert calls(fake_amt, "amt_screenshot") == [{"device": KEY}]                                              # no confirmed: it is a read
        res = text(pg, ".scard .shot .result.ok")
        assert "my-server-1" in res and "1280×800" in res and "stable after 3 frames" in res and "verified" in res and "kept in the capture store for 24 h" in res
        save = pg.get_attribute(".scard .shot a.btn", "href")
        assert save.startswith("/captures/")
        body = fb.get(save)                                                                                        # the console's own authenticated route
        assert body.status == 200 and body.data == b"\x89PNG-bytes"
        assert list(fake_amt.fetches.values()) == [1]                                                             # the url was fetched once, by the console
        assert "handoffs" not in pg.content() and not [u for u in pg.requests if "handoffs" in u]
    finally:
        ctx.close()


def test_a_held_enter_on_shot_opens_one_sheet_and_sends_nothing(browser, fb, fake_amt):
    read_all(fb)
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector(".scard .acts button")
        pg.focus(".scard .acts button")
        pg.evaluate("() => { window.__opens = 0; document.addEventListener('sheet-open', () => window.__opens++, true); }")
        pg.keyboard.down("Enter")
        for _ in range(20):
            pg.keyboard.down("Enter"); pg.wait_for_timeout(33)
        pg.keyboard.up("Enter")
        assert pg.evaluate("() => window.__opens") == 1                         # one deliberate activation opened one sheet
        assert pg.evaluate("() => window.__callCount()") == 0 and not calls(fake_amt, "amt_screenshot")
    finally:
        ctx.close()


def test_a_refused_screenshot_renders_the_reason_verbatim_and_a_busy_host_becomes_another_client(browser, fb, fake_amt):
    read_all(fb)
    fake_amt.results["amt_screenshot"] = lambda a: tool_error("another session is open")
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector(".scard .acts button")
        pg.click(".scard .acts button"); pg.click(".sheet.open [data-confirm]")
        pg.wait_for_selector(".scard .shot .result.error")
        res = text(pg, ".scard .shot .result.error")
        assert "another session is open" in res and "no input was sent" in res and "refused" in res
        assert pg.query_selector(".scard .shot a.btn") is None
    finally:
        ctx.close()
    ctx, pg = open_page(browser, fb, "/")                                        # the next load: the holder is another client
    try:
        pg.wait_for_selector('.scard [data-session="held_other"]')
    finally:
        ctx.close()


def test_a_screenshot_whose_link_expired_is_expired_not_missing(browser, fb, fake_amt):
    read_all(fb)

    def gone(a):
        out = shot(fake_amt)
        fake_amt.handoffs.clear()
        return out
    fake_amt.results["amt_screenshot"] = gone
    ctx, pg = open_page(browser, fb, "/")
    try:
        pg.wait_for_selector(".scard .acts button")
        pg.click(".scard .acts button"); pg.click(".sheet.open [data-confirm]")
        pg.wait_for_selector(".scard .shot .result.error")
        assert "the one-time link expired: it was not fetched within 15 minutes" in text(pg, ".scard .shot .result.error")
    finally:
        ctx.close()


# -- the server page ---------------------------------------------------------------------------------------------------------

def test_the_server_header_and_status_cards_show_each_value_with_its_code(browser, fb, fake_amt):
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#status-cards .card")
        assert text(pg, ".srvhead h1") == KEY and pg.get_attribute("#srv-pill .pill", "data-power") == "on"
        assert text(pg, "#srv-line").startswith("10.0.0.26 · AMT 19.0.5 · read ")
        assert text(pg, '#srv-chips [data-session="free"]') == "KVM free" and text(pg, '#srv-chips [data-session="sol_free"]') == "SOL free"
        assert text(pg, '#srv-chips [data-pin="matches"]') == "pin matches · a1b2 c3d4 e5f6 0718"
        assert [a.inner_text().strip() for a in pg.query_selector_all(".srvhead .tabs a")] == ["Status", "Power & boot", "KVM", "SOL", "Media", "Logs", "Inventory", "AMT settings", "Advanced"]
        cards = {c.query_selector("h2").inner_text().strip(): c.inner_text().replace("\n", " ") for c in pg.query_selector_all("#status-cards .card")}
        assert [k.split("\n")[0].split(" ")[0] for k in cards] == ["Power", "AMT", "Redirection", "User", "Coverage", "Identity"]
        power, amt, redir, consent, cov, ident = [pg.inner_text(f"#status-cards .card:nth-child({i})").replace("\n", " ") for i in range(1, 7)]
        assert "State On code 2" in power and "normal (no override reported)" in power
        assert "version 19.0.5 · build 1234 · sku 16392" in amt and "client · post provisioning · admin control mode" in amt and "Zero-touch disabled" in amt
        assert "Listener enabled" in redir and "enabled (state 2) · port 5900 closed · session timeout 3 min" in redir and "SOL enabled" in redir and "IDE-R enabled" in redir
        assert "Required for none code 0" in consent and "State not started code 0" in consent and "can be changed · AMT settings · kvm" in consent
        assert "Unavailable none" in cov and "Truncated none" in cov
        assert pg.inner_text("#status-cards .card:nth-child(6) .fp").replace("\n", " ") == "a1b2 c3d4 e5f6 0718 " + " ".join(LEAF[i:i + 4] for i in range(16, 64, 4))
        bold = [b.inner_text() for b in pg.query_selector_all("#status-cards .card:nth-child(6) .fp b")]
        assert bold == ["a1b2", "c3d4", "e5f6", "0718"]                                         # the stored 16-hex prefix, in bold
        assert "matches on every connection" in ident and "against the fingerprint MEBx shows" in ident
        assert pg.errors == []
    finally:
        ctx.close()


def test_coverage_shows_unavailable_classes_as_dashed_chips_and_truncated_classes(browser, fb, fake_amt):
    """Immutable 19, the page half: what the tool reported is what the card says; a read that reported none says none."""
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "unavailable": ["CIM_PhysicalMedia"], "truncated": ["CIM_Processor"],
                                                "unavailable_reasons": {"CIM_PhysicalMedia": "Unsupported (not exposed)"}}
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#status-cards .card:nth-child(5)")
        cov = pg.inner_text("#status-cards .card:nth-child(5)").replace("\n", " ")
        assert "Unavailable CIM_PhysicalMedia Unsupported (not exposed) its section is empty, the rest was read" in cov
        assert "Truncated CIM_Processor cut at the item cap: more exist than were read" in cov
        assert "dashed" in pg.get_attribute("#status-cards .card:nth-child(5) dd .chip", "class")
    finally:
        ctx.close()


def test_a_host_that_cannot_be_read_marks_the_last_good_values_stale_and_keeps_power(browser, fb, fake_amt):
    read_all(fb)
    fake_amt.results["amt_status"] = lambda a: tool_error("connect timed out (10 s)")
    fb.app.fleet.refresh(KEY)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector('#srv-state [data-state="unreachable"]')
        state = text(pg, "#srv-state")
        assert "Host unreachable" in state and "connect timed out (10 s)" in state and "marked stale" in state and "Power actions stay available" in state
        assert pg.get_attribute("#srv-pill .pill", "data-power") == "unreachable"
        assert len(pg.query_selector_all("#status-cards .card h2 .chip.dashed")) >= 5          # every card with values says stale
        assert "stale · last good" in pg.inner_text("#status-cards .card:nth-child(1) h2")
        assert pg.get_attribute("#status-cards .card:nth-child(1) h2 a", "href") == f"/server/{KEY}/power"
        assert "last good read" in text(pg, "#read-note")
    finally:
        ctx.close()


def test_a_paused_server_page_says_so_and_offers_one_retry(browser, fb, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("wsman_auth_failed_401")
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector('#srv-state [data-state="paused"]')
        assert "Paused · credential refused" in text(pg, "#srv-state") and "Retry once" in text(pg, "#srv-state")
        assert text(pg, '#srv-chips [data-session="paused"]') == "paused · credential refused"
        assert pg.query_selector("#status-cards .card") is None                                  # nothing was ever read, so nothing is shown
    finally:
        ctx.close()


def test_consent_pending_points_at_the_advanced_template(browser, fb, fake_amt):
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "user_consent": {**STATUS["user_consent"], "required_for": "kvm", "required_code": 1, "state": "displayed", "state_code": 2}}
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#status-cards .result.live")
        res = text(pg, "#status-cards .result.live")
        assert "A consent code is showing on the host's screen" in res and "Advanced → Send a consent code" in res
        assert pg.get_attribute("#status-cards .result.live a", "href") == f"/server/{KEY}/wsman"
    finally:
        ctx.close()


@pytest.mark.parametrize("holder", ["console", "agent", "other", "free"])
def test_the_holder_is_the_same_on_the_header_chip_the_card_chip_and_the_sessions_panel(browser, fb, fake_amt, holder):
    """Immutable 8: from scripted session status, the chip text and data-session agree on every surface."""
    fake_amt.results["amt_mirror_link"] = lambda a: MIRROR if holder in ("console", "agent") else {"device": KEY, "live": False}
    if holder == "console":
        fb.app.fleet.started[f"mirror:{KEY}"] = fb.app.fleet.now()
    read_all(fb)
    if holder == "other":
        fake_amt.results["amt_screenshot"] = lambda a: tool_error("another session is open")
        fb.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": KEY}})
    want = {"console": ("held_console", "KVM · you"), "agent": ("held_agent", "KVM · agent via mirror"), "other": ("held_other", "KVM · another client · opens refused"),
            "free": ("free", "KVM free")}[holder]
    panel = {"console": "held by you", "agent": "held by an agent via the mirror", "other": "held by another client", "free": "KVM · free"}[holder]
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#sessions-body li")
        assert text(pg, f'#srv-chips [data-session="{want[0]}"]').startswith(want[1])
        assert panel in text(pg, "#sessions-body li:nth-child(1)")
        if holder == "other":
            assert "the console cannot take it over" in text(pg, "#sessions-body li:nth-child(1)")
        pg.goto(f"{fb.origin}/")
        pg.wait_for_selector(".scard")
        assert text(pg, f'.scard [data-session="{want[0]}"]').startswith(want[1])
    finally:
        ctx.close()


def test_the_sessions_panel_names_the_mirror_the_terminal_the_mount_and_the_recording(browser, fb, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: {**MIRROR, "recording": {"seconds": 61.0, "frames": 900, "bytes": 5_000_000, "started": 1.0},
                                                     "in_flight": {"tool": "amt_console_input", "started_at": 1_760_000_000.0}}
    fake_amt.results["amt_serial_link"] = lambda a: {"device": KEY, "live": True, "uptime_s": 70.0, "viewers": 1, "recording": None, "recording_dir": "/data/recordings"}
    fake_amt.results["amt_ider"] = lambda a: {"device": KEY, "mounted": True, "images": {"iso": "debian-13.3-netinst.iso"}}
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#sessions-body li:nth-child(4)")
        rows = [text(pg, f"#sessions-body li:nth-child({i})") for i in range(1, 5)]
        assert "KVM · held by an agent via the mirror" in rows[0] and "15 fps" in rows[0] and "2 viewers" in rows[0] and "an agent's call (amt_console_input) is using this session since" in rows[0]
        assert "SOL · held by an agent via the terminal" in rows[1] and "1 viewer" in rows[1]
        assert "IDE-R · debian-13.3-netinst.iso mounted" in rows[2] and "held until unmount; KVM keeps working beside it" in rows[2]
        assert "Recording · mirror" in rows[3] and "900 frames" in rows[3] and "not to the browser" in rows[3]
        assert "AMT allows one KVM session per host" in text(pg, "#sessions-body")
        assert "TOKEN" not in pg.content()
    finally:
        ctx.close()


def test_when_the_session_views_could_not_be_read_the_panel_says_unknown_not_free(browser, fb, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: tool_error("mirror status failed")
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#sessions-body li")
        assert "KVM · unknown" in text(pg, "#sessions-body li:nth-child(1)") and "mirror status failed" in text(pg, "#sessions-body li:nth-child(1)")
        assert text(pg, '#srv-chips [data-session="unknown"]') == "KVM unknown"
    finally:
        ctx.close()


def test_the_capture_card_takes_a_screenshot_and_lists_it_among_the_past_captures(browser, fb, fake_amt):
    read_all(fb)
    fake_amt.results["amt_screenshot"] = lambda a: shot(fake_amt)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#srv-shot")
        pg.click("#srv-shot"); pg.click(".sheet.open [data-confirm]")
        pg.wait_for_selector("#capture-results .result.ok")
        res = text(pg, "#capture-results .result.ok")
        assert "my-server-1 · " in res and "1280×800" in res and "stable after 3 frames" in res and "verified" in res
        actions = [a.inner_text().strip() for a in pg.query_selector_all("#capture-results .row .btn")]
        assert actions == ["Save", "Copy sha256", "Open in console"]
        assert pg.get_attribute("#capture-results .row a:last-child", "href") == f"/server/{KEY}/console"
    finally:
        ctx.close()


def capture_listing(items):
    return {"total": len(items), "offset": 0, "captures": items, "next_offset": None,
            "searched": [{"dir": "/s", "kinds": ["screenshot"], "found": True}, {"dir": "/r", "kinds": ["recording", "serial_cast"], "found": True}]}


def test_past_captures_are_fetched_once_each_and_then_saved(browser, fb, fake_amt):
    items = [{"name": "amt-my-server-1-20261020T142431000000Z-aaaaaaaaaaaaaaaa.png", "kind": "screenshot", "device": KEY, "bytes": 212_000, "modified": "2026-10-20T14:24:31Z"},
             {"name": "amt-my-server-1-20261020T091200Z.mp4", "kind": "recording", "device": KEY, "bytes": 48_000_000, "modified": "2026-10-20T13:12:00Z"},
             {"name": "amt-other-20261020T091200Z.mp4", "kind": "recording", "device": "other", "bytes": 1, "modified": "2026-10-20T13:12:00Z"}]
    fake_amt.results["amt_captures"] = lambda a: capture_listing(items) if a["action"] == "list" else fake_amt.offer(b"PNG-DATA" if a["name"].endswith(".png") else b"MP4-DATA", a["name"])
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#past-captures li")
        rows = pg.query_selector_all("#past-captures li")
        assert len(rows) == 2                                                    # this server's, not the other's
        assert "screenshot · 2026-10-20 10:24:31 EDT · 207 KB" in rows[0].inner_text().replace("\n", " ")
        assert "mirror recording · 2026-10-20 09:12:00 EDT · 45.8 MB" in rows[1].inner_text().replace("\n", " ")
        assert "sha256 is shown once fetched" in rows[0].inner_text()
        assert "Listed 2 for my-server-1 of 3 that amt-mcp holds" in text(pg, "#past-captures")
        pg.click("#past-captures li:nth-child(1) button")
        pg.wait_for_selector("#past-captures li:nth-child(1) a.btn")
        first = text(pg, "#past-captures li:nth-child(1)")
        assert "verified · kept in the capture store" in first and "Save" in first
        href = pg.get_attribute("#past-captures li:nth-child(1) a.btn", "href")
        assert fb.get(href).data == b"PNG-DATA"
        assert len(calls(fake_amt, "amt_captures")) == 2 and [a for a in calls(fake_amt, "amt_captures") if a["action"] == "fetch"] == [{"action": "fetch", "name": items[0]["name"]}]
        pg.reload()                                                              # a reload still knows it is in the store
        pg.wait_for_selector("#past-captures li:nth-child(1) a.btn")
        assert pg.query_selector("#past-captures li:nth-child(2) button") is not None
        assert "handoffs" not in pg.content() and list(fake_amt.fetches.values()) == [1]
    finally:
        ctx.close()


def test_a_refused_fetch_says_so_and_a_missing_folder_is_disclosed(browser, fb, fake_amt):
    item = {"name": "amt-my-server-1-20261020T091200Z.mp4", "kind": "recording", "device": KEY, "bytes": 5, "modified": "2026-10-20T13:12:00Z"}
    listing = capture_listing([item])
    listing["searched"][1]["found"] = False
    fake_amt.results["amt_captures"] = lambda a: listing if a["action"] == "list" else tool_error("capture_not_found: not in the list")
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#past-captures li")
        assert "a folder was not found: recording and serial_cast" in text(pg, "#past-captures")
        pg.click("#past-captures li button")
        for _ in range(50):
            if "refused" in text(pg, "#past-captures li"):
                break
            pg.wait_for_timeout(100)
        assert "refused: " in text(pg, "#past-captures li") and "capture_not_found" in text(pg, "#past-captures li") and "nothing was fetched" in text(pg, "#past-captures li")
        assert pg.query_selector("#past-captures li button") is not None            # it can be tried again
    finally:
        ctx.close()


def test_no_captures_says_why_and_a_failed_listing_is_not_an_empty_one(browser, fb, fake_amt):
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#past-captures p")
        assert "amt-mcp lists no screenshots, recordings or casts for my-server-1 (it searched 2 folders)" in text(pg, "#past-captures")
    finally:
        ctx.close()
    fake_amt.results["amt_captures"] = lambda a: tool_error("captures folder unreadable")
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#past-captures .result.error")
        assert "captures folder unreadable" in text(pg, "#past-captures") and "not an empty list" in text(pg, "#past-captures")
    finally:
        ctx.close()


def test_an_unknown_server_says_so_and_the_other_tabs_keep_the_header(browser, fb):
    read_all(fb)
    ctx, pg = open_page(browser, fb, "/server/nonesuch")
    try:
        pg.wait_for_selector("#srv-state .card")
        assert "No server named nonesuch" in text(pg, "#srv-state")
    finally:
        ctx.close()
    ctx, pg = open_page(browser, fb, f"/server/{KEY}/wsman")
    try:
        pg.wait_for_selector("#srv-pill .pill")
        assert text(pg, ".content").startswith("No per-class safeguard beyond your confirmation.") and "built in a later step" not in text(pg, ".content")
        assert pg.get_attribute(".srvhead .tabs [aria-current=page]", "href") == f"/server/{KEY}/wsman"
    finally:
        ctx.close()


# -- immutable 18: a disabled control ----------------------------------------------------------------------------------------

def test_a_busy_control_is_aria_disabled_focusable_ignores_activation_and_says_why(browser, fb, fake_amt):
    item = {"name": "amt-my-server-1-20261020T091200Z.mp4", "kind": "recording", "device": KEY, "bytes": 5, "modified": "2026-10-20T13:12:00Z"}
    import threading
    gate = threading.Event()

    def slow(a):
        if a["action"] == "list":
            return capture_listing([item])
        gate.wait(5)
        return fake_amt.offer(b"MP4", a["name"])
    fake_amt.results["amt_captures"] = slow
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#past-captures li button")
        pg.click("#past-captures li button")
        pg.wait_for_selector("#past-captures li button[aria-disabled=true]")
        info = pg.evaluate("""() => { const b = document.querySelector('#past-captures li button[aria-disabled=true]');
          return { tab: b.tabIndex, reason: (b.parentElement.querySelector('.reason') || {}).textContent || '' }; }""")
        assert info["tab"] >= 0 and "amt-mcp" in info["reason"]
        before = len(calls(fake_amt, "amt_captures"))
        pg.click("#past-captures li button[aria-disabled=true]", force=True)
        pg.wait_for_timeout(150)
        assert len(calls(fake_amt, "amt_captures")) == before                        # ignored activation: no second fetch
        gate.set()
        pg.wait_for_selector("#past-captures li a.btn")
    finally:
        gate.set()
        ctx.close()


# -- immutables 13 and 14: layout and hit areas at every width, in both themes ------------------------------------------------

def walk(pg, cm):
    pg.wait_for_timeout(250)
    r = pg.evaluate(cm.JS_WALK)
    return r, pg.evaluate(cm.JS_BOTTOM), pg.evaluate(cm.JS_ANIMATED)


@pytest.mark.parametrize("scheme", ["light", "dark"])
@pytest.mark.parametrize("width", WIDTHS)
@pytest.mark.parametrize("path", ["/", f"/server/{KEY}", f"/server/{KEY}/wsman"])
def test_the_pages_fit_every_width_with_hit_areas_gutters_and_the_current_tab_in_view(browser, fb, fake_amt, path, width, scheme):
    cm = check_mockups()
    fake_amt.results["amt_mirror_link"] = lambda a: {**MIRROR, "in_flight": {"tool": "amt_console_input", "started_at": 1_760_000_000.0}}
    fake_amt.results["amt_ider"] = lambda a: {"device": KEY, "mounted": True, "images": {"iso": "debian-13.3-netinst.iso"}}
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "unavailable": ["CIM_PhysicalMedia"], "truncated": ["CIM_Processor"]}
    fb.app.fleet.started[f"mirror:{KEY}"] = fb.app.fleet.now()
    read_all(fb)
    ctx, pg = open_page(browser, fb, path, width=width, scheme=scheme)
    try:
        pg.wait_for_selector(".scard, #srv-pill .pill")
        pg.wait_for_selector(".scard .pill, #srv-pill .pill")
        if path == f"/server/{KEY}":
            pg.wait_for_selector("#past-captures p, #past-captures li")
        r, bottom, anim = walk(pg, cm)
        bad = []
        if path != "/":                                                           # the VISIBLE section row: one of the two navs, its current entry in view
            seen = pg.evaluate("""() => Array.from(document.querySelectorAll('.srvhead nav')).filter(n => n.offsetParent !== null).map(n => {
              const c = n.querySelector('[aria-current="page"]').getBoundingClientRect(); return { cls: n.className, l: Math.round(c.left), r: Math.round(c.right), w: innerWidth }; })""")
            if len(seen) != 1 or seen[0]["cls"] != ("chips-scroll" if width < 600 else "tabs") or seen[0]["l"] < 0 or seen[0]["r"] > seen[0]["w"]: bad.append(("section-row", seen))
        if r["scrollWidth"] > r["inner"]: bad.append(("overflow", r["scrollWidth"], r["inner"]))
        if r["gutter"] is not None and r["gutter"] != 16: bad.append(("gutter", r["gutter"]))
        if r["currentTab"] and not r["currentTab"]["ok"]: bad.append(("current-tab", r["currentTab"]))
        bad += [("letter-wrapped", x) for x in r["narrow"]]
        if width < 600: bad += [("control-offscreen", x) for x in r["offscreen"]]
        bad += [("fixed-over-control", x) for x in r["fixedOverlap"]] + [("under-bottom-bar", x) for x in bottom]
        bad += [("animated-without-data-motion", x) for x in anim["missing"]]
        for t in r["targets"]:
            if not ((t["w"] >= 48 and t["h"] >= 48) or (t["chip"] and t["w"] >= 24 and t["h"] >= 24)): bad.append(("target", t))
        if width in cm.PHONE_HEIGHT_CEILING and r["docHeight"] > cm.PHONE_HEIGHT_CEILING[width]: bad.append(("page-height", r["docHeight"]))
        assert bad == [], bad
        assert len(r["targets"]) >= 8 and r["text"], "the walk saw nothing: it would pass on an empty page"
        assert pg.errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
@pytest.mark.parametrize("path", ["/", f"/server/{KEY}"])
def test_every_text_and_ring_on_the_pages_clears_the_contrast_floors(browser, fb, fake_amt, path, scheme):
    cm = check_mockups()
    fake_amt.results["amt_mirror_link"] = lambda a: MIRROR
    fb.app.fleet.started[f"mirror:{KEY}"] = fb.app.fleet.now()
    read_all(fb)
    ctx, pg = open_page(browser, fb, path, width=1024, scheme=scheme)
    try:
        pg.wait_for_selector(".scard .pill, #srv-pill .pill")
        if path != "/":
            pg.wait_for_selector("#past-captures p")
        r, _, _ = walk(pg, cm)
        text_low = [(t["snippet"], t["ratio"], t["ex"]) for t in r["text"] if t["ratio"] < (3.0 if t["large"] else 4.5)]
        assert text_low == [], text_low
        assert len(r["text"]) > 20, "the walk saw too little text: it would pass on an empty page"
    finally:
        ctx.close()


def test_the_pages_load_nothing_from_outside_the_console_and_never_touch_amt_mcp(browser, fb, fake_amt):
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#past-captures p")
        pg.goto(f"{fb.origin}/")
        pg.wait_for_selector(".scard .pill")
        origins = {u.split("/")[0] + "//" + u.split("/")[2] for u in pg.requests if u.startswith("http")}
        assert origins == {fb.origin}, origins
        assert not [u for u in pg.requests if fake_amt.base in u or u.endswith("/mcp")]
    finally:
        ctx.close()


def test_the_pages_have_no_secret_value_and_no_token_in_their_markup(browser, fb, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: MIRROR
    read_all(fb)
    ctx, pg = open_page(browser, fb, f"/server/{KEY}")
    try:
        pg.wait_for_selector("#sessions-body li")
        body = pg.content()
        assert "TOKEN" not in body and "type=\"password\"" not in body and "handoffs/" not in body
        from console_fakes import BEARER
        assert BEARER not in body
    finally:
        ctx.close()
