"""The Power & boot tab (packet C3): what AMT offers, the power actions and the Force tray, the next-boot form with its
argument-computed sheet kind, the combined entries and their order and the results.

Every amt-mcp answer is scripted (console_fakes.FakeAmt); no test reaches a host, and a power action is only ever sent to
the fake. Immutables 4, 5 (the matrix and the boot predicate cases) and 20, plus the backend rules the page rests on."""
import json
import threading

import pytest

import amt_write
import mcp_client
import power
from console_fakes import BEARER, Authenticator, Console, check_mockups, enroll_first_passkey
from test_console_fleet import KEY, STATUS, device, tool_error, fc, me, settle, calls  # noqa: F401 - fixtures
from test_console_fleet_browser import open_page, text

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed: the browser immutables are NOT checked")

# the states a running OS offers (the mockup's): everything but the hard-graceful pair, power on, light sleep and the immediate two
OFFERED_CODES = ["14", "12", "15", "4", "7", "10", "6", "9", "11"]
OFFERED_NAMES = ["restart", "shutdown", "power_cycle", "sleep_deep", "hibernate", "hard_power_off", "hard_power_cycle", "hard_reset", "nmi"]
BOOT_MENU_REFUSAL = ("power_state_not_available: AMT does not offer shutdown now; it offers hard_reset, nmi. Nothing was sent. "
                     "A boot menu or an OS without the AMT agent offers only the hard actions.")
POWER_TOOL = lambda a: {"device": a["device"], "action": a["action"], "applied": True, "requested_state": 14, "power_state_requested": 14,
                        "graceful": a["action"] in ("restart", "shutdown", "power_cycle"), "return_value": 0, "readback": "ok",
                        "power_state_after": "on", "power_state_after_code": 2,
                        "note": "AMT applies the change asynchronously; power_state_after can still show the old state"}
BOOT_TOOL = lambda a: {"device": a["device"], "target": a["target"], "options": sorted(a.get("options") or {}), "steps": ["clear_boot_order", "put", "set_boot_config_role"],
                       "readback": {"BIOSSetup": True, "SecureErase": False}, "note": "one-time request; it applies at the host's next boot or power cycle"}


def wsman_get(codes=OFFERED_CODES):
    return lambda a: {"device": a["device"], "class": a["class_name"], "operation": "get",
                      "instance": {"PowerState": "2", "AvailableRequestedPowerStates": codes}}


def written(fake):
    """The write calls amt-mcp received, in order."""
    return [(t, a) for t, a, _ in fake.calls if t in ("amt_power", "amt_set_next_boot")]


# -- the table the page and the tool share --------------------------------------------------------------------------------

def test_the_power_codes_are_the_tools_own_table():
    assert power.POWER_CODES == {name: state for name, (state, _) in amt_write.POWER_ACTIONS.items()}


def test_the_page_copy_names_every_tool_action_and_the_force_set_is_the_predicates():
    js = (power.__file__.rsplit("/", 1)[0] + "/static/power.js")
    src = open(js).read()
    for name in amt_write.POWER_ACTIONS:
        assert f"    {name}: {{ group:" in src, name
    forced = {n for n, (s, _) in amt_write.POWER_ACTIONS.items() if s in amt_write.UNGRACEFUL_STATES}
    in_tray = {n for n in amt_write.POWER_ACTIONS if f"    {n}: {{ group: 'force'" in src}
    comp = open(js.replace("power.js", "components.js")).read()
    assert in_tray == forced and all(f"'{n}'" in comp for n in forced)


def test_offered_actions_reads_one_code_or_a_list_in_the_tools_order_and_refuses_a_guess():
    assert power.offered_actions(OFFERED_CODES) == OFFERED_NAMES == [n for n in power.POWER_CODES if n in OFFERED_NAMES]
    assert power.offered_actions("10") == ["hard_reset"] and power.offered_actions(11) == ["nmi"]
    assert power.offered_actions([]) == [] and power.offered_actions(None) is None
    for bad in (["10", "ten"], ["10", None], [True], {"a": 1}, "", ["10", ["11"]]):
        with pytest.raises(ValueError, match="offered_state_not_a_code"):
            power.offered_actions(bad)


# -- the offered set: one named read, only when the page asks ------------------------------------------------------------------

def test_the_offered_set_is_one_named_read_of_the_power_service(me, fake_amt):
    fake_amt.results["amt_wsman_get"] = wsman_get()
    body = me.get(f"/api/server/{KEY}/power").json()
    assert body["offered"] == OFFERED_NAMES and body["error"] is None and body["paused"] is None and body["read_at"] == body["now"]
    reads = [(t, a, h) for t, a, h in fake_amt.calls if t == "amt_wsman_get"]
    assert reads == [("amt_wsman_get", {"device": KEY, "class_name": "CIM_AssociatedPowerManagementService", "operation": "get"}, f"Bearer {BEARER}")]
    assert written(fake_amt) == []                                           # a read: nothing was written


def test_an_unreadable_offered_set_says_why_and_greys_nothing(me, fake_amt):
    fake_amt.results["amt_wsman_get"] = lambda a: tool_error("Error executing tool amt_wsman_get: ConnectError: unreachable")
    body = me.get(f"/api/server/{KEY}/power").json()
    assert body["offered"] is None and "ConnectError: unreachable" in body["error"] and body["read_at"] is None
    fake_amt.results["amt_wsman_get"] = lambda a: {"device": KEY, "instance": {"PowerState": "2"}}
    body = me.get(f"/api/server/{KEY}/power").json()
    assert body["offered"] is None and "no AvailableRequestedPowerStates" in body["error"]
    fake_amt.results["amt_wsman_get"] = lambda a: {"device": KEY, "instance": {"AvailableRequestedPowerStates": ["2", "soon"]}}
    body = me.get(f"/api/server/{KEY}/power").json()
    assert body["offered"] is None and body["error"] == "offered_state_not_a_code"
    fake_amt.results["amt_wsman_get"] = lambda a: {"device": KEY}
    assert me.get(f"/api/server/{KEY}/power").json()["error"] == "amt_wsman_get returned no instance"


def test_an_empty_list_is_offered_nothing_not_unknown(me, fake_amt):
    fake_amt.results["amt_wsman_get"] = wsman_get([])
    body = me.get(f"/api/server/{KEY}/power").json()
    assert body["offered"] == [] and body["error"] is None


def test_a_paused_server_is_not_read_for_its_offered_set(me, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("Error executing tool amt_status: wsman_auth_failed_401")
    settle(me)
    assert me.app.fleet.public(KEY)["state"] == "paused"
    fake_amt.results["amt_wsman_get"] = wsman_get()
    body = me.get(f"/api/server/{KEY}/power").json()
    assert body["paused"]["reason"] == "credential refused" and body["offered"] is None
    assert [t for t, _, _ in fake_amt.calls if t == "amt_wsman_get"] == []


def test_a_401_in_the_offered_read_pauses_the_server_and_it_is_not_read_again(me, fake_amt):
    fake_amt.results["amt_wsman_get"] = lambda a: tool_error("Error executing tool amt_wsman_get: wsman_auth_failed_401")
    settle(me)                                                                 # the server is known to the fleet and live
    first = me.get(f"/api/server/{KEY}/power").json()
    assert "wsman_auth_failed_401" in first["error"] and first["paused"]["reason"] == "credential refused"
    again = me.get(f"/api/server/{KEY}/power").json()
    assert again["paused"] and [t for t, _, _ in fake_amt.calls if t == "amt_wsman_get"] == ["amt_wsman_get"]   # one attempt, no second


def test_the_offered_route_answers_only_a_signed_in_operator_about_a_known_server(me, fake_amt):
    fake_amt.results["amt_wsman_get"] = wsman_get()
    assert me.get("/api/server/nope/power").status == 404
    assert me.get(f"/api/server/{KEY}/power", cookie=False).status == 401
    assert [t for t, _, _ in fake_amt.calls if t == "amt_wsman_get"] == []


# -- the combined entries: boot first, power only if the boot step was accepted -------------------------------------------------

def steps(action="hard_reset", boot_extra=None, power_extra=None, device_name=KEY):
    return [{"tool": "amt_set_next_boot", "arguments": {"device": device_name, "target": "bios_setup", "confirmed": True, **(boot_extra or {})}},
            {"tool": "amt_power", "arguments": {"device": device_name, "action": action, "confirmed": True, **(power_extra or {})}}]


@pytest.mark.parametrize("action", ["power_on", "hard_reset"])
def test_a_combined_entry_sends_the_boot_step_and_then_the_power_step(me, fake_amt, action):
    fake_amt.results["amt_set_next_boot"] = BOOT_TOOL
    fake_amt.results["amt_power"] = POWER_TOOL
    reply = me.post("/api/sequence", {"steps": steps(action, boot_extra={"options": {"firmware_verbosity": 2}})})
    assert reply.status == 200
    assert written(fake_amt) == [("amt_set_next_boot", {"device": KEY, "target": "bios_setup", "options": {"firmware_verbosity": 2}, "confirmed": True}),
                                 ("amt_power", {"device": KEY, "action": action, "confirmed": True})]
    first, second = reply.json()["steps"]
    assert first["sent"] and not first["reply"]["isError"] and first["reply"]["structured"]["target"] == "bios_setup"
    assert second["sent"] and second["reply"]["structured"]["action"] == action


def test_a_refused_boot_step_leaves_the_power_step_unsent(me, fake_amt):
    fake_amt.results["amt_set_next_boot"] = lambda a: tool_error("Error executing tool amt_set_next_boot: boot_target_not_allowed:'usb'")
    fake_amt.results["amt_power"] = POWER_TOOL
    reply = me.post("/api/sequence", {"steps": steps("hard_reset")})
    first, second = reply.json()["steps"]
    assert first["reply"]["isError"] and "boot_target_not_allowed" in first["reply"]["text"]
    assert second == {"tool": "amt_power", "sent": False, "skipped": "boot_step_not_accepted"}
    assert [t for t, _ in written(fake_amt)] == ["amt_set_next_boot"]          # amt_power never reached amt-mcp


def test_a_boot_step_that_could_not_be_made_leaves_the_power_step_unsent(me, fake_amt):
    fake_amt.results["amt_power"] = POWER_TOOL
    bad = steps("hard_reset")
    del bad[0]["arguments"]["confirmed"]                                         # refused by the client before it is sent
    reply = me.post("/api/sequence", {"steps": bad})
    first, second = reply.json()["steps"]
    assert first == {"tool": "amt_set_next_boot", "sent": False, "error": "confirmed_not_true"}
    assert second["skipped"] == "boot_step_not_accepted" and written(fake_amt) == []


def test_an_accepted_boot_step_stands_when_the_power_step_is_refused(me, fake_amt):
    fake_amt.results["amt_set_next_boot"] = BOOT_TOOL
    fake_amt.results["amt_power"] = lambda a: tool_error("Error executing tool amt_power: " + BOOT_MENU_REFUSAL)
    first, second = me.post("/api/sequence", {"steps": steps("power_on")}).json()["steps"]
    assert not first["reply"]["isError"] and second["reply"]["isError"] and "power_state_not_available" in second["reply"]["text"]
    assert [t for t, _ in written(fake_amt)] == ["amt_set_next_boot", "amt_power"]


def test_a_401_in_the_power_step_pauses_the_server(me, fake_amt):
    fake_amt.results["amt_set_next_boot"] = BOOT_TOOL
    fake_amt.results["amt_power"] = lambda a: tool_error("Error executing tool amt_power: wsman_auth_failed_401")
    settle(me)
    me.post("/api/sequence", {"steps": steps("hard_reset")})
    assert me.app.fleet.public(KEY)["state"] == "paused"


def test_a_sequence_with_no_bearer_or_no_amt_mcp_sends_nothing_and_says_which_it_is_not_sure_of(tmp_path, fake_amt):
    """A missing bearer was refused before anything left (sent false); an unreachable amt-mcp may or may not have been reached
    (sent "unknown"); neither lets the power step go, and neither reply names the vault entry or carries a value."""
    for sub, kw, error, sent in (("a", {"secrets_cli": None}, "console_bearer_unavailable", False),
                                 ("b", {"mcp_url": "http://127.0.0.1:9/mcp"}, "amt_mcp_unreachable:", "unknown")):
        (tmp_path / sub).mkdir()
        c = Console(tmp_path / sub, fake_amt, **kw)
        try:
            enroll_first_passkey(c, Authenticator(c.app.cfg.rp_id, c.origin))
            reply = c.post("/api/sequence", {"steps": steps("hard_reset")})
            first, second = reply.json()["steps"]
            assert reply.status == 200 and first["error"].startswith(error) and first["sent"] == sent and "reply" not in first
            assert second == {"tool": "amt_power", "sent": False, "skipped": "boot_step_not_accepted"}
            assert "amt-console-token" not in reply.text and BEARER not in reply.text
        finally:
            c.close()
    assert written(fake_amt) == []


@pytest.mark.parametrize("bad,code", [
    ("not a list", "sequence_needs_two_steps"),
    ([], "sequence_needs_two_steps"),
    (steps()[:1], "sequence_needs_two_steps"),
    (steps() + steps(), "sequence_needs_two_steps"),
    ([None, None], "sequence_needs_two_steps"),
    (steps()[::-1], "sequence_order_not_allowed"),
    ([steps()[0], steps()[0]], "sequence_order_not_allowed"),
    (steps("hard_power_off"), "sequence_power_action_not_allowed"),
    (steps("restart"), "sequence_power_action_not_allowed"),
    (steps("nmi"), "sequence_power_action_not_allowed"),
    ([steps()[0], {"tool": "amt_power", "arguments": {"device": "other", "action": "hard_reset", "confirmed": True}}], "sequence_devices_differ"),
    ([{"tool": "amt_set_next_boot", "arguments": "x"}, steps()[1]], "arguments_not_an_object"),
])
def test_only_the_two_combined_entries_are_a_sequence(me, fake_amt, bad, code):
    reply = me.post("/api/sequence", {"steps": bad})
    assert reply.status == 400 and reply.json() == {"error": code}
    assert written(fake_amt) == []


def test_the_sequence_route_needs_the_session_and_the_csrf_token(me, fake_amt):
    assert me.post("/api/sequence", {"steps": steps()}, cookie=False).status == 401
    assert me.post("/api/sequence", {"steps": steps()}, csrf=False).status == 403
    assert me.post("/api/sequence", {"steps": steps()}, origin=False).status == 403
    assert written(fake_amt) == []


def test_the_power_tab_is_built_and_a_tab_loads_only_its_own_script(me):
    page = me.get(f"/server/{KEY}/power").text
    assert 'id="power-page"' in page and "/static/power.js" in page and "built in a later step" not in page
    assert 'href="/server/my-server-1/wsman"' in page and "@@" not in page          # the Advanced link carries the server
    other = me.get(f"/server/{KEY}/wsman").text
    assert "built in a later step" not in other and 'id="wsman-page"' in other and "/static/power.js" not in other


# ============================== the page, in a real browser (headless Chromium) ====================================================

WIDTHS = [360, 600, 1024, 1440]
FORCE_TRAY = ["hard_reset", "hard_power_off", "hard_power_cycle", "immediate_shutdown", "immediate_power_cycle", "nmi"]


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
def pb(tmp_path, fake_amt):
    """A signed-in console, the server read once (powered on), what AMT offers scripted, every write answered by the fake."""
    console = Console(tmp_path, fake_amt)
    enroll_first_passkey(console, Authenticator(console.app.cfg.rp_id, console.origin))
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device()]}
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"]}
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_serial_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
    fake_amt.results["amt_identities"] = lambda a: {"identities": []}
    fake_amt.results["amt_wsman_get"] = wsman_get()
    fake_amt.results["amt_power"] = POWER_TOOL
    fake_amt.results["amt_set_next_boot"] = BOOT_TOOL
    console.app.fleet.refresh_devices()
    console.app.fleet.refresh(KEY)
    yield console
    console.close()


def power_page(browser, pb, width=1024, scheme="light", **kw):
    ctx, pg = open_page(browser, pb, f"/server/{KEY}/power", width=width, scheme=scheme, **kw)
    pg.set_default_timeout(8000)                           # a control that never becomes clickable fails in seconds, not half a minute
    pg.wait_for_selector("#offered-banner strong, #offered-banner.error")
    return ctx, pg


def sheet_kind(pg):
    return pg.evaluate("() => { const s = Array.from(document.querySelectorAll('.sheet.open')).pop(); return s ? { force: s.hasAttribute('data-force-sheet'), plain: s.hasAttribute('data-confirm-sheet'), call: s.querySelector('.call').textContent, title: s.querySelector('h2').textContent, say: s.querySelector('.consequence').textContent } : null; }")


def hold_force(pg):
    pg.wait_for_timeout(400)                               # the sheet slides up for 300 ms: measure the control where it rests
    k = pg.query_selector(".sheet.open .force-control[data-hold]")
    b = k.bounding_box()
    pg.mouse.move(b["x"] + b["width"] / 2, b["y"] + b["height"] / 2)
    pg.mouse.down(); pg.wait_for_timeout(1400); pg.mouse.up(); pg.wait_for_timeout(150)


def confirm_plain(pg):
    pg.click(".sheet.open [data-confirm]")


def results(pg, slot):
    return [pg.inner_text(f"#{slot} .result:nth-child({i})").replace("\n", " ") for i in range(1, pg.locator(f"#{slot} .result").count() + 1)]


def open_options(pg):
    if not pg.evaluate("() => document.querySelector('#boot-card details').open"):
        pg.click("#boot-card details > summary")


def tick(pg, name):
    open_options(pg)
    pg.click(f'[data-opt="{name}"]')


def untick_all(pg):
    pg.evaluate("() => { document.querySelectorAll('#boot-options .check').forEach(c => c.setAttribute('aria-checked', 'false')); document.querySelectorAll('#boot-options input').forEach(i => { i.value = '0'; i.dispatchEvent(new Event('input')); }); }")


# -- what AMT offers comes first --------------------------------------------------------------------------------------------

def test_every_power_control_waits_for_the_offered_set_and_then_greys_what_amt_does_not_offer(browser, pb, fake_amt):
    gate = threading.Event()
    fake_amt.results["amt_wsman_get"] = lambda a: (gate.wait(10), wsman_get()(a))[1]
    ctx, pg = open_page(browser, pb, f"/server/{KEY}/power")
    try:
        pg.wait_for_selector('[data-action="restart"]')
        assert "Reading what AMT offers" in text(pg, "#offered-text")
        assert pg.get_attribute('[data-action="restart"]', "aria-disabled") == "true" and "reading what AMT offers" in text(pg, '[data-action="restart"] ~ .reason')
        pg.click('[data-action="restart"]', force=True)
        assert pg.query_selector(".sheet.open") is None                         # nothing opens before the set is known
        gate.set()
        pg.wait_for_selector("#offered-banner strong")
        assert "AMT offers right now: " + " ".join(OFFERED_NAMES) in text(pg, "#offered-banner")
        assert "read" in text(pg, "#offered-text") and "AvailableRequestedPowerStates" in text(pg, "#offered-text")
        for name in OFFERED_NAMES:
            assert pg.get_attribute(f'[data-action="{name}"]', "aria-disabled") is None, name
        for name in ("shutdown_hard_graceful", "power_cycle_hard_graceful", "power_on", "sleep_light", "immediate_shutdown", "immediate_power_cycle"):
            assert pg.get_attribute(f'[data-action="{name}"]', "aria-disabled") == "true", name
            assert text(pg, f'[data-action="{name}"] ~ .reason') == "not offered by AMT right now"
            pg.click(f'[data-action="{name}"]', force=True)
            assert pg.query_selector(".sheet.open") is None
        assert written(fake_amt) == []
        look = lambda sel: pg.eval_on_selector(sel, "e => { const c = getComputedStyle(e); return [c.backgroundColor, c.opacity]; }")
        assert look('[data-action="restart"]')[0] != "rgba(0, 0, 0, 0)"                           # an offered tonal button keeps its fill
        for name in ("shutdown_hard_graceful", "power_on", "immediate_shutdown"):                  # a tonal, an outlined and a text button, each greyed
            assert look(f'[data-action="{name}"]') == ["rgba(0, 0, 0, 0)", "1"], name
    finally:
        ctx.close()


def test_a_boot_menu_offers_only_the_hard_actions_and_the_tools_own_refusal_is_shown_verbatim(browser, pb, fake_amt):
    fake_amt.results["amt_wsman_get"] = wsman_get(["10", "11"])
    ctx, pg = power_page(browser, pb)
    try:
        assert "AMT offers right now: hard_reset nmi" in text(pg, "#offered-banner")
        enabled = pg.eval_on_selector_all("#power-card [data-action]:not([aria-disabled])", "els => els.map(e => e.getAttribute('data-action'))")
        assert sorted(enabled) == ["hard_reset", "nmi"]
        # the set read earlier goes stale: the host changed, and the tool's own refusal is what the operator reads
        fake_amt.results["amt_wsman_get"] = wsman_get()
        pg.click("#offered-reread"); pg.wait_for_selector('[data-action="restart"]:not([aria-disabled])')
        fake_amt.results["amt_power"] = lambda a: tool_error("Error executing tool amt_power: " + BOOT_MENU_REFUSAL)
        pg.click('[data-action="shutdown"]'); confirm_plain(pg)
        pg.wait_for_selector("#power-results .result.error")
        row = text(pg, "#power-results .result.error")
        assert BOOT_MENU_REFUSAL in row and row.count("Nothing was sent") == 1 and "nothing sent" not in row.replace("Nothing was sent", "")   # verbatim, once
        assert "shutdown · refused:" in row
    finally:
        ctx.close()


def test_an_unreadable_offered_set_leaves_the_actions_to_the_tool_and_says_so(browser, pb, fake_amt):
    fake_amt.results["amt_wsman_get"] = lambda a: tool_error("Error executing tool amt_wsman_get: ConnectError")
    ctx, pg = power_page(browser, pb)
    try:
        banner = text(pg, "#offered-banner")
        assert "What AMT offers could not be read (Error executing tool amt_wsman_get: ConnectError)" in banner and "refuses one AMT does not offer" in banner
        assert pg.eval_on_selector_all("#power-card [data-action][aria-disabled]", "els => els.length") == 0
    finally:
        ctx.close()


def test_a_paused_server_offers_no_action_and_the_page_says_why(browser, pb, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("Error executing tool amt_status: wsman_auth_failed_401")
    pb.app.fleet.refresh(KEY)
    ctx, pg = power_page(browser, pb)
    try:
        assert "paused" in text(pg, "#offered-banner").lower() and "Retry once" in text(pg, "#offered-banner")
        every = pg.eval_on_selector_all("#power-card [data-action], #boot-actions button", "els => els.map(e => e.getAttribute('aria-disabled'))")
        assert every and all(v == "true" for v in every)
        assert "paused · credential refused" in text(pg, '[data-action="restart"] ~ .reason') and "paused · credential refused" in text(pg, "#boot-set ~ .reason")
        assert [t for t, _, _ in fake_amt.calls if t == "amt_wsman_get"] == []
    finally:
        ctx.close()


# -- immutable 20: the tray, the default, the greyed set ----------------------------------------------------------------------

def test_forced_actions_live_only_in_the_force_tray_and_the_default_restart_is_graceful(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        outside = pg.eval_on_selector_all('[data-action^=hard_], [data-action^=immediate_], [data-action=nmi]', "els => els.filter(e => !e.closest('.force-tray')).length")
        inside = pg.eval_on_selector_all('.force-tray [data-action]', "els => els.map(e => e.getAttribute('data-action'))")
        assert outside == 0 and inside == FORCE_TRAY
        assert pg.eval_on_selector_all('.force-tray [data-action]', "els => els.length") == 6
        # the first power control on the page is the graceful restart, and its sheet names a graceful call
        assert pg.eval_on_selector("#power-card [data-action]", "e => e.getAttribute('data-action')") == "restart"
        pg.click('[data-action="restart"]')
        k = sheet_kind(pg)
        assert k["plain"] and 'action: "restart"' in k["call"] and "never downgraded to a hard reset" in k["say"] and "hard_reset" not in k["call"]
        assert "Force" in text(pg, ".force-tray summary") and "hold to confirm" in text(pg, ".force-tray summary")
    finally:
        ctx.close()


# -- immutable 4: nothing writes on a bare click; one activation sends one call --------------------------------------------------

SWEEP = "#power-page button, #power-page summary, #power-page [role=checkbox], #power-page a[href], #power-page select, #power-page input"


def test_a_bare_click_on_any_control_outside_a_sheet_sends_nothing(browser, pb, fake_amt):
    """Immutable 4, over this page's own controls (the shell's sign-out is not one of them)."""
    ctx, pg = power_page(browser, pb)
    try:
        pg.evaluate("() => document.addEventListener('click', e => { const a = e.target.closest('a[href]'); if (a) e.preventDefault(); }, true)")
        n = pg.eval_on_selector_all(SWEEP, "els => els.length")
        assert n >= 30
        for i in range(n):
            pg.evaluate("([sel, i]) => { const el = document.querySelectorAll(sel)[i]; if (el) el.click(); window.__closeSheets(); }", [SWEEP, i])
        assert pg.evaluate("() => window.__callCount()") == 0 and pg.evaluate("() => window.__forceFireCount()") == 0
        assert written(fake_amt) == []
        assert pg.errors == []
    finally:
        ctx.close()


def test_a_restart_goes_through_a_sheet_once_and_lands_in_its_card_with_the_readback(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        pg.click('[data-action="restart"]')
        k = sheet_kind(pg)
        assert k["plain"] and k["call"] == 'tools/call amt_power {device: "my-server-1", action: "restart", confirmed: true}'
        assert written(fake_amt) == []                                           # an open sheet is not a write
        confirm_plain(pg)
        pg.wait_for_selector("#power-results .result.ok")
        assert written(fake_amt) == [("amt_power", {"device": KEY, "action": "restart", "confirmed": True})]
        row = text(pg, "#power-results .result.ok")
        assert " EDT · restart" in row or " EST · restart" in row
        assert "accepted, ReturnValue 0" in row and "graceful" in row and "power state read back: on (code 2)" in row
        assert "AMT applies the change asynchronously" in row                      # the tool's own caveat, not hidden
        assert pg.evaluate("() => window.__callCount()") == 1
    finally:
        ctx.close()


@pytest.mark.parametrize("rv,applied,read,kind,needle", [
    (0, True, "unavailable", "live", "readback unavailable (ConnectError)"),
    (2, "unknown", "ok", "live", "sent; ReturnValue 2 (not 0): AMT did not confirm it"),
    ("unknown", "unknown", "unavailable", "live", "the device replied without a ReturnValue: the outcome is unknown"),
])
def test_a_result_without_a_confirmed_readback_says_what_is_not_known(browser, pb, fake_amt, rv, applied, read, kind, needle):
    fake_amt.results["amt_power"] = lambda a: {**POWER_TOOL(a), "applied": applied, "return_value": rv, "readback": read, "readback_error": "ConnectError"}
    ctx, pg = power_page(browser, pb)
    try:
        pg.click('[data-action="restart"]'); confirm_plain(pg)
        pg.wait_for_selector(f"#power-results .result.{kind}")
        assert needle in text(pg, "#power-results .result")
        assert pg.query_selector("#power-results .result.ok") is None
    finally:
        ctx.close()


def test_a_call_the_console_could_not_make_is_not_reported_as_a_refusal_by_the_tool(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        pg.route(f"{pb.origin}/api/call", lambda route: route.fulfill(status=502, content_type="application/json", body=json.dumps({"error": "amt_mcp_unreachable:ConnectionRefusedError"})))
        pg.click('[data-action="restart"]'); confirm_plain(pg)
        pg.wait_for_selector("#power-results .result.live")
        row = text(pg, "#power-results .result")
        assert "amt_mcp_unreachable:ConnectionRefusedError" in row and "not known whether the request was sent" in row
    finally:
        ctx.close()


def test_a_tool_text_is_rendered_as_text_never_as_markup(browser, pb, fake_amt):
    fake_amt.results["amt_power"] = lambda a: tool_error("<img src=x onerror=window.__hit=1><b>bold</b>")
    ctx, pg = power_page(browser, pb)
    try:
        pg.click('[data-action="restart"]'); confirm_plain(pg)
        pg.wait_for_selector("#power-results .result.error")
        assert "<img src=x onerror=window.__hit=1><b>bold</b>" in text(pg, "#power-results .result.error")
        assert pg.evaluate("() => window.__hit === undefined && document.querySelector('#power-results img, #power-results b') === null")
    finally:
        ctx.close()


@pytest.mark.parametrize("name", FORCE_TRAY)
def test_each_forced_action_has_its_force_sheet_and_a_hold_sends_exactly_that_call(browser, pb, fake_amt, name):
    fake_amt.results["amt_wsman_get"] = wsman_get([str(c) for c in power.POWER_CODES.values()])     # an OS that offers everything
    ctx, pg = power_page(browser, pb)
    try:
        pg.click(f'[data-action="{name}"]')
        k = sheet_kind(pg)
        assert k["force"] and not k["plain"] and k["call"] == f'tools/call amt_power {{device: "my-server-1", action: "{name}", confirmed: true}}'
        assert "NOT asked" in k["say"] or name == "nmi"
        assert pg.query_selector(".sheet.open .force-control") is not None and pg.query_selector(".sheet.open [data-confirm]") is None
        assert written(fake_amt) == []
        hold_force(pg)
        pg.wait_for_selector("#power-results .result")
        assert written(fake_amt) == [("amt_power", {"device": KEY, "action": name, "confirmed": True})]
        assert pg.evaluate("() => window.__forceFireCount()") == 1 and pg.evaluate("() => window.__calls()")[0]["forced"] is True
        assert "ungraceful: the OS was not asked" in text(pg, "#power-results .result") or POWER_TOOL({"device": KEY, "action": name})["graceful"] is False
    finally:
        ctx.close()


FORCE_LABELS = {"hard_reset": ("Hold to hard reset", "Hard reset now"), "hard_power_off": ("Hold to power off", "Hard power off now"),
                "hard_power_cycle": ("Hold to power cycle", "Hard power cycle now"), "immediate_shutdown": ("Hold to shut down", "Shut down now"),
                "immediate_power_cycle": ("Hold to power cycle", "Power cycle now"), "nmi": ("Hold to send NMI", "Send NMI now")}


def test_each_force_sheet_reads_as_the_mockup_does_and_its_second_sheet_repeats_the_call(browser, pb, fake_amt):
    fake_amt.results["amt_wsman_get"] = wsman_get([str(c) for c in power.POWER_CODES.values()])
    ctx, pg = power_page(browser, pb)
    try:
        for name, (hold, now) in FORCE_LABELS.items():
            pg.click(f'[data-action="{name}"]'); pg.evaluate("() => window.__closeSheets()")
            assert pg.text_content(f"#pw-{name} .force-control .lbl") == hold, name
            assert pg.text_content(f"#pw-{name}-sheet2 [data-confirm]") == now, name
            assert pg.text_content(f"#pw-{name}-sheet2 .call") == pg.text_content(f"#pw-{name} .call"), name
    finally:
        ctx.close()


def test_the_offered_set_is_read_when_the_page_opens_and_when_asked_never_on_a_timer(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        reads = lambda: len([1 for t, _, _ in fake_amt.calls if t == "amt_wsman_get"])
        assert reads() == 1
        pg.wait_for_timeout(5600)                                               # past the page's own 5 s refresh of the cached status
        assert reads() == 1
        pg.click("#offered-reread"); pg.wait_for_timeout(300)
        assert reads() == 2
    finally:
        ctx.close()


def test_a_combined_entry_the_console_could_not_send_is_not_reported_as_refused_by_the_tool(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        pg.route(f"{pb.origin}/api/sequence", lambda route: route.fulfill(status=502, content_type="application/json", body=json.dumps({"error": "amt_mcp_unreachable:TimeoutError"})))
        pg.click("#boot-reset"); hold_force(pg)
        pg.wait_for_selector("#boot-results .result.live")
        row = text(pg, "#boot-results .result")
        assert "reset into target" in row and "amt_mcp_unreachable:TimeoutError" in row and "not known whether the request was sent" in row
        assert written(fake_amt) == []
    finally:
        ctx.close()


def test_the_force_sheets_name_the_consequence_of_each_forced_action(browser, pb, fake_amt):
    fake_amt.results["amt_wsman_get"] = wsman_get([str(c) for c in power.POWER_CODES.values()])
    ctx, pg = power_page(browser, pb)
    try:
        said = {}
        for name in FORCE_TRAY:
            pg.click(f'[data-action="{name}"]'); said[name] = sheet_kind(pg); pg.evaluate("() => window.__closeSheets()")
        assert "reset button were pressed" in said["hard_reset"]["say"] and "Power is cut at once" in said["hard_power_off"]["say"]
        assert "as if the plug were pulled" in said["hard_power_cycle"]["say"] and "powered off at once" in said["immediate_shutdown"]["say"]
        assert "powered off and on at once" in said["immediate_power_cycle"]["say"] and "crashes the kernel for a dump" in said["nmi"]["say"]
        assert said["hard_reset"]["title"] == "Hard reset my-server-1" and said["nmi"]["title"] == "Send NMI to my-server-1"
    finally:
        ctx.close()


# -- immutable 5: the force matrix on every force sheet this page builds ---------------------------------------------------------

def build_every_force_sheet(pg):
    """Open each forced power sheet, then the boot sheets that are forced (secure_erase ticked, and Reset), so all eight force
    controls are in the document, in a known order."""
    for name in FORCE_TRAY:
        pg.click(f'[data-action="{name}"]'); pg.evaluate("() => window.__closeSheets()")
    tick(pg, "secure_erase")
    pg.click("#boot-set"); pg.evaluate("() => window.__closeSheets()")
    pg.click("#boot-reset"); pg.evaluate("() => window.__closeSheets()")
    assert pg.eval_on_selector_all(".force-control[data-hold]", "els => els.length") == 8


EXPECTED_FORCE = {"click": (0, True), "hold600": 0, "hold1400_slideoff": 0, "swipe": 0, "hold1400_release": 1,
                  "click_450_click": (0, True), "click_700_click": (0, True), "dblclick": (0, True), "click_click_wait_confirm": (1, "true"),
                  "enter_held": (0, False), "enter_wait_enter": (0, False), "enter_release_550_tab_enter": (1, "true"),
                  "enter_held_600_not_armed": ("false", 0)}


@pytest.mark.parametrize("index,width", [(i, 1024) for i in range(8)] + [(0, 360), (7, 360)])
def test_the_force_matrix_on_every_force_control_of_the_page(browser, pb, fake_amt, index, width):
    fake_amt.results["amt_wsman_get"] = wsman_get([str(c) for c in power.POWER_CODES.values()])
    ctx, pg = power_page(browser, pb, width=width)
    try:
        build_every_force_sheet(pg)
        got = check_mockups().force_matrix(pg, index)
        assert got is not None, "no force control was found"
        assert got["opener_point"] != "CONFIRM", "the second sheet's confirm sits under the opener's point"
        got.pop("opener_point")
        assert got == EXPECTED_FORCE
    finally:
        ctx.close()


def test_a_tap_then_a_tap_500_ms_later_never_fires_a_power_force_control(browser, pb, fake_amt):
    fake_amt.results["amt_wsman_get"] = wsman_get([str(c) for c in power.POWER_CODES.values()])
    ctx, pg = power_page(browser, pb, width=360, has_touch=True)
    try:
        build_every_force_sheet(pg)
        assert check_mockups().tap_matrix(pg, 5) == (0, True)
        assert written(fake_amt) == []
    finally:
        ctx.close()


# -- immutable 5: the boot predicate cases, through the form -----------------------------------------------------------------------

def test_set_next_boot_with_secure_erase_opens_the_hold_and_its_call_carries_it(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        tick(pg, "secure_erase")
        pg.click("#boot-set")
        k = sheet_kind(pg)
        assert k["force"] and not k["plain"]
        assert k["call"] == 'tools/call amt_set_next_boot {device: "my-server-1", target: "bios_setup", options: {secure_erase: true}, confirmed: true}'
        assert k["title"] == "Set the next boot of my-server-1 to BIOS setup with secure_erase"
        assert "the host's storage is erased" in k["say"] and "cannot be undone" in k["say"] and "not touched now" in k["say"]
        assert written(fake_amt) == []
        hold_force(pg)
        pg.wait_for_selector("#boot-results .result")
        assert written(fake_amt) == [("amt_set_next_boot", {"device": KEY, "target": "bios_setup", "options": {"secure_erase": True}, "confirmed": True})]
        assert pg.evaluate("() => window.__forceFireCount()") == 1
    finally:
        ctx.close()


@pytest.mark.parametrize("option,says", [("secure_erase", "the host's storage is erased"), ("reflash_bios", "the BIOS is reflashed"),
                                         ("configuration_data_reset", "the firmware configuration is reset")])
def test_each_of_the_three_destructive_options_makes_the_sheet_the_hold(browser, pb, fake_amt, option, says):
    ctx, pg = power_page(browser, pb)
    try:
        tick(pg, option)
        for button, forced in (("#boot-set", True), ("#boot-reset", True)):
            pg.click(button)
            k = sheet_kind(pg)
            assert k["force"] == forced and f"{option}: true" in k["call"] and says in k["say"], (button, k)
            pg.evaluate("() => window.__closeSheets()")
    finally:
        ctx.close()


def test_a_number_option_or_a_lock_alone_leaves_the_sheet_plain_and_the_call_carries_it(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        open_options(pg)
        pg.fill("#opt-firmware_verbosity", "2")
        pg.click("#boot-set")
        k = sheet_kind(pg)
        assert k["plain"] and 'options: {firmware_verbosity: 2}' in k["call"] and "secure_erase" not in k["call"]
        assert "host is not touched now" in k["say"] and "Only the one-time boot target changes" in k["say"]
        pg.evaluate("() => window.__closeSheets()")
        pg.fill("#opt-boot_media_index", "7"); untick_all(pg); pg.fill("#opt-boot_media_index", "7")
        pg.click("#boot-set")
        assert sheet_kind(pg)["plain"] and "options: {boot_media_index: 7}" in sheet_kind(pg)["call"]
        pg.evaluate("() => window.__closeSheets()")
        untick_all(pg); tick(pg, "lock_power_button")                    # the design's destructive set is the three; a lock is a plain confirm
        pg.click("#boot-set")
        assert sheet_kind(pg)["plain"] and "lock_power_button: true" in sheet_kind(pg)["call"]
    finally:
        ctx.close()


def test_no_option_ticked_sends_no_options_key_and_the_sheet_agrees_with_the_predicate_for_every_combination(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        pg.click("#boot-set")
        k = sheet_kind(pg)
        assert k["plain"] and k["call"] == 'tools/call amt_set_next_boot {device: "my-server-1", target: "bios_setup", confirmed: true}'
        pg.evaluate("() => window.__closeSheets()")
        # the sheet kind and the one predicate over the call agree for each single option and each target
        names = pg.eval_on_selector_all("#boot-options [data-opt]", "els => els.map(e => e.getAttribute('data-opt'))")
        assert len(names) == 14
        for name in names:
            untick_all(pg); tick(pg, name)
            pg.click("#boot-set")
            k = sheet_kind(pg)
            expect = name in ("secure_erase", "reflash_bios", "configuration_data_reset")
            predicate = pg.evaluate("n => window.__destructiveCall({tool: 'amt_set_next_boot', arguments: {device: 'x', target: 'pxe', options: {[n]: true}}})", name)
            assert k["force"] == expect == predicate, name
            pg.evaluate("() => window.__closeSheets()")
    finally:
        ctx.close()


def test_normal_boot_sends_no_options_and_clears(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        tick(pg, "secure_erase")
        pg.select_option("#boot-target", "clear")
        pg.click("#boot-set")
        k = sheet_kind(pg)
        assert k["plain"] and k["call"] == 'tools/call amt_set_next_boot {device: "my-server-1", target: "clear", confirmed: true}'
        assert "Cancels a pending one-time boot request" in k["say"] and k["title"] == "Clear the pending next boot of my-server-1"
    finally:
        ctx.close()


def test_an_option_the_tool_would_refuse_never_opens_a_sheet(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        open_options(pg)
        for bad, field in (("4", "firmware_verbosity"), ("256", "boot_media_index"), ("-1", "firmware_verbosity"), ("1.5", "boot_media_index")):
            pg.fill(f"#opt-{field}", bad)
            assert pg.get_attribute("#boot-set", "aria-disabled") == "true" and pg.get_attribute("#boot-reset", "aria-disabled") == "true"
            assert f"{field} must be a whole number from" in text(pg, f"#field-{field} .help") and "err" in pg.get_attribute(f"#field-{field}", "class")
            assert "firmware_verbosity must be 0-3" in text(pg, "#boot-set ~ .reason") or "boot_media_index must be 0-255" in text(pg, "#boot-set ~ .reason")
            pg.click("#boot-set", force=True)
            assert pg.query_selector(".sheet.open") is None
            pg.fill(f"#opt-{field}", "0")
        assert pg.get_attribute("#boot-set", "aria-disabled") is None
        assert written(fake_amt) == []
    finally:
        ctx.close()


# -- immutable 20: the combined entries, in order, and skipped on a refusal --------------------------------------------------------

def test_reset_to_target_is_always_the_hold_and_sends_boot_then_hard_reset(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        pg.select_option("#boot-target", "pxe")
        pg.click("#boot-reset")
        k = sheet_kind(pg)
        assert k["force"] and k["title"] == "Reset my-server-1 into PXE"
        assert k["call"] == ('tools/call amt_set_next_boot {device: "my-server-1", target: "pxe", confirmed: true} · '
                             'then amt_power {device: "my-server-1", action: "hard_reset", confirmed: true}')
        assert "HARD resets the host" in k["say"] and "if the first is refused the second is not sent" in k["say"]
        assert written(fake_amt) == []
        hold_force(pg)
        pg.wait_for_selector("#boot-results .result")
        assert written(fake_amt) == [("amt_set_next_boot", {"device": KEY, "target": "pxe", "confirmed": True}),
                                     ("amt_power", {"device": KEY, "action": "hard_reset", "confirmed": True})]
        assert pg.evaluate("() => window.__callCount()") == 1 and pg.evaluate("() => window.__forceFireCount()") == 1   # one activation, one request
        rows = results(pg, "boot-results")
        assert len(rows) == 2 and "hard_reset" in rows[0] and "accepted, ReturnValue 0" in rows[0] and "set next boot" in rows[1] and "readback" in rows[1]
    finally:
        ctx.close()


def test_reset_with_a_destructive_option_carries_it_in_the_boot_step(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        tick(pg, "reflash_bios")
        pg.click("#boot-reset")
        k = sheet_kind(pg)
        assert k["force"] and "options: {reflash_bios: true}" in k["call"] and "the BIOS is reflashed at that boot" in k["say"]
        assert k["title"] == "Reset my-server-1 into BIOS setup with reflash_bios"
        hold_force(pg); pg.wait_for_selector("#boot-results .result")
        assert written(fake_amt)[0] == ("amt_set_next_boot", {"device": KEY, "target": "bios_setup", "options": {"reflash_bios": True}, "confirmed": True})
    finally:
        ctx.close()


def test_a_refused_boot_step_leaves_the_power_step_unsent_and_the_page_says_so(browser, pb, fake_amt):
    fake_amt.results["amt_set_next_boot"] = lambda a: tool_error("Error executing tool amt_set_next_boot: boot_readback_mismatch:BIOSSetup:completed=clear_boot_order,put")
    ctx, pg = power_page(browser, pb)
    try:
        pg.click("#boot-reset"); hold_force(pg)
        pg.wait_for_selector("#boot-results .result.error")
        assert [t for t, _ in written(fake_amt)] == ["amt_set_next_boot"]          # amt_power never reached amt-mcp
        rows = results(pg, "boot-results")
        assert len(rows) == 2
        assert "not sent: the boot step was not accepted, so the host was not touched" in rows[0] and "hard_reset" in rows[0]
        assert "boot_readback_mismatch:BIOSSetup:completed=clear_boot_order,put" in rows[1] and "part of the sequence ran before it stopped" in rows[1]
    finally:
        ctx.close()


def power_off_host(console, fake):
    fake.results["amt_status"] = lambda a: {**STATUS, "device": a["device"], "power": {"state": "off_soft", "code": 8}}
    console.app.fleet.refresh(KEY)


def test_power_on_to_target_is_disabled_with_the_reason_while_the_host_is_on(browser, pb, fake_amt):
    fake_amt.results["amt_wsman_get"] = wsman_get([str(c) for c in power.POWER_CODES.values()])
    ctx, pg = power_page(browser, pb)
    try:
        assert pg.get_attribute("#boot-poweron", "aria-disabled") == "true" and text(pg, "#boot-poweron ~ .reason") == "host is already on"
        assert "Power on → BIOS setup" in text(pg, "#boot-poweron")
        pg.click("#boot-poweron", force=True)
        assert pg.query_selector(".sheet.open") is None and written(fake_amt) == []
    finally:
        ctx.close()


def test_power_on_to_target_sends_boot_then_power_on_in_a_plain_sheet(browser, pb, fake_amt):
    power_off_host(pb, fake_amt)
    fake_amt.results["amt_wsman_get"] = wsman_get(["2", "10", "11"])
    ctx, pg = power_page(browser, pb)
    try:
        pg.select_option("#boot-target", "pxe")
        assert "Power on → PXE" in text(pg, "#boot-poweron") and pg.get_attribute("#boot-poweron", "aria-disabled") is None
        pg.click("#boot-poweron")
        k = sheet_kind(pg)
        assert k["plain"] and k["title"] == "Power on my-server-1 into PXE"
        assert k["call"] == ('tools/call amt_set_next_boot {device: "my-server-1", target: "pxe", confirmed: true} · '
                             'then amt_power {device: "my-server-1", action: "power_on", confirmed: true}')
        confirm_plain(pg)
        pg.wait_for_selector("#boot-results .result")
        assert written(fake_amt) == [("amt_set_next_boot", {"device": KEY, "target": "pxe", "confirmed": True}),
                                     ("amt_power", {"device": KEY, "action": "power_on", "confirmed": True})]
        assert pg.evaluate("() => window.__callCount()") == 1 and pg.evaluate("() => window.__forceFireCount()") == 0
    finally:
        ctx.close()


def test_power_on_to_target_with_a_destructive_option_is_the_hold(browser, pb, fake_amt):
    power_off_host(pb, fake_amt)
    fake_amt.results["amt_wsman_get"] = wsman_get([str(c) for c in power.POWER_CODES.values()])
    ctx, pg = power_page(browser, pb)
    try:
        tick(pg, "configuration_data_reset")
        pg.click("#boot-poweron")
        k = sheet_kind(pg)
        assert k["force"] and "options: {configuration_data_reset: true}" in k["call"] and "then amt_power" in k["call"] and "cannot be undone" in k["say"]
    finally:
        ctx.close()


def test_power_on_to_target_needs_power_on_to_be_offered(browser, pb, fake_amt):
    power_off_host(pb, fake_amt)
    fake_amt.results["amt_wsman_get"] = wsman_get(["10", "11"])
    ctx, pg = power_page(browser, pb)
    try:
        assert pg.get_attribute("#boot-poweron", "aria-disabled") == "true" and text(pg, "#boot-poweron ~ .reason") == "not offered by AMT right now"
        assert pg.get_attribute("#boot-reset", "aria-disabled") is None and pg.get_attribute("#boot-set", "aria-disabled") is None
    finally:
        ctx.close()


def test_reset_to_target_needs_hard_reset_to_be_offered(browser, pb, fake_amt):
    fake_amt.results["amt_wsman_get"] = wsman_get(["14"])
    ctx, pg = power_page(browser, pb)
    try:
        assert pg.get_attribute("#boot-reset", "aria-disabled") == "true" and text(pg, "#boot-reset ~ .reason") == "not offered by AMT right now"
        assert pg.get_attribute("#boot-set", "aria-disabled") is None
    finally:
        ctx.close()


# -- the next-boot results and the chip ------------------------------------------------------------------------------------------

CHIP_PENDING = "() => document.getElementById('boot-chip').textContent.indexOf('BIOS setup pending') !== -1"


def test_set_next_boot_lands_in_its_card_with_the_readback_and_the_chip_follows(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        assert text(pg, "#boot-chip") == "AMT reports: normal"
        fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"], "next_boot": {"BIOSSetup": True, "BootMediaIndex": 0}}
        pg.click("#boot-set"); confirm_plain(pg)
        pg.wait_for_selector("#boot-results .result.ok")
        row = text(pg, "#boot-results .result.ok")
        assert "set next boot bios_setup" in row and "clear_boot_order, put, set_boot_config_role accepted" in row and "readback: 2 BootSettingData flags as sent" in row
        assert "one-time request" in row
        assert written(fake_amt) == [("amt_set_next_boot", {"device": KEY, "target": "bios_setup", "confirmed": True})]
        pg.wait_for_function(CHIP_PENDING, timeout=3000)   # inside the 5 s poll: only the page's own status read can get it there
    finally:
        ctx.close()


def test_the_chip_follows_an_accepted_reset_to_target_inside_the_poll_interval(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        assert text(pg, "#boot-chip") == "AMT reports: normal"
        fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"], "next_boot": {"BIOSSetup": True, "BootMediaIndex": 0}}
        pg.click("#boot-reset"); hold_force(pg)
        pg.wait_for_selector("#boot-results .result.ok")
        pg.wait_for_function(CHIP_PENDING, timeout=3000)       # the 5 s poll cannot be what moved it
    finally:
        ctx.close()


def test_the_chip_follows_an_accepted_power_on_to_target_inside_the_poll_interval(browser, pb, fake_amt):
    power_off_host(pb, fake_amt)
    fake_amt.results["amt_wsman_get"] = wsman_get(["2", "10", "11"])
    ctx, pg = power_page(browser, pb)
    try:
        assert text(pg, "#boot-chip") == "AMT reports: normal"
        fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"], "power": {"state": "off_soft", "code": 8}, "next_boot": {"BIOSSetup": True, "BootMediaIndex": 0}}
        pg.click("#boot-poweron"); confirm_plain(pg)
        pg.wait_for_selector("#boot-results .result.ok")
        pg.wait_for_function(CHIP_PENDING, timeout=3000)
    finally:
        ctx.close()


def test_a_refused_next_boot_names_what_already_ran(browser, pb, fake_amt):
    fake_amt.results["amt_set_next_boot"] = lambda a: tool_error("Error executing tool amt_set_next_boot: boot_target_not_allowed:'usb'")
    ctx, pg = power_page(browser, pb)
    try:
        pg.click("#boot-set"); confirm_plain(pg)
        pg.wait_for_selector("#boot-results .result.error")
        row = text(pg, "#boot-results .result.error")
        assert "refused: Error executing tool amt_set_next_boot: boot_target_not_allowed:'usb'" in row and row.endswith("nothing sent")
    finally:
        ctx.close()


# -- the spy: every destructive call the page sent was forced, and the predicate's controls hold -----------------------------------

def test_every_destructive_call_the_page_sent_was_preceded_by_a_force_fire(browser, pb, fake_amt):
    fake_amt.results["amt_wsman_get"] = wsman_get([str(c) for c in power.POWER_CODES.values()])
    ctx, pg = power_page(browser, pb)
    try:
        pg.click('[data-action="restart"]'); confirm_plain(pg); pg.wait_for_selector("#power-results .result")      # plain
        pg.click('[data-action="sleep_deep"]'); confirm_plain(pg); pg.wait_for_timeout(100)
        pg.click('[data-action="nmi"]'); hold_force(pg); pg.wait_for_timeout(100)                                   # forced
        pg.click("#boot-set"); confirm_plain(pg); pg.wait_for_timeout(100)                                          # plain
        tick(pg, "secure_erase"); pg.click("#boot-set"); hold_force(pg); pg.wait_for_timeout(100)                   # forced by its argument
        untick_all(pg)
        pg.click("#boot-reset"); hold_force(pg); pg.wait_for_timeout(100)                                           # forced sequence
        spy = pg.evaluate("() => window.__calls().map(c => ({ forced: c.forced, destructive: window.__destructiveCall({ tool: c.tool, arguments: c.arguments, then: c.then }, c.ctx), tool: c.tool, text: c.text }))")
        assert len(spy) == 6
        assert [c["destructive"] for c in spy] == [False, False, True, False, True, True]
        assert [c for c in spy if c["destructive"] and not c["forced"]] == []
        assert [c for c in spy if c["forced"] and not c["destructive"]] == []
        controls = pg.evaluate("""() => [
          window.__destructiveCall({ tool: 'amt_set_next_boot', arguments: { options: { reflash_bios: true } } }),
          window.__destructiveCall({ tool: 'amt_set_next_boot', arguments: { options: { firmware_verbosity: 2 } } }),
          window.__destructiveCall({ tool: 'amt_set_next_boot', arguments: { target: 'pxe' }, then: { tool: 'amt_power', arguments: { action: 'hard_reset' } } }),
          window.__destructiveCall({ tool: 'amt_set_next_boot', arguments: { target: 'pxe' }, then: { tool: 'amt_power', arguments: { action: 'power_on' } } }),
          window.__destructiveCall({ tool: 'amt_power', arguments: { action: 'restart' } })]""")
        assert controls == [True, False, True, False, False]
    finally:
        ctx.close()


def test_every_plain_confirm_sheet_of_the_page_sends_one_call_and_manages_focus(browser, pb, fake_amt):
    power_off_host(pb, fake_amt)
    fake_amt.results["amt_wsman_get"] = wsman_get([str(c) for c in power.POWER_CODES.values()])
    ctx, pg = power_page(browser, pb)
    try:
        for sel in ('[data-action="restart"]', '[data-action="hibernate"]', "#boot-set", "#boot-poweron"):
            pg.click(sel); pg.evaluate("() => window.__closeSheets()")
        checks = check_mockups().confirm_checks(pg)
        assert len(checks) == 4, checks
        for c in checks:
            assert c["click"] == 1 and c["enter_held"] == 1, c                    # one activation, one request (the sequence is one)
            assert c["focus_key"] == {"inSheet": True, "isCancel": True} and c["focus_ptr"] and c["trapped"], c
    finally:
        ctx.close()


# -- no outside menu on this page (operator 2026-10-21: "we do not need this ... there should be no reference to meshcommander") --------

def test_the_page_carries_no_menu_of_other_places_and_no_meshcommander_reference(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        assert pg.query_selector("#rest-h, #platform-erase") is None
        assert "meshcommander" not in pg.content().lower()
    finally:
        ctx.close()


# -- the page itself: layout at every width, the design's walk, contrast, nothing from outside ---------------------------------------

@pytest.mark.parametrize("width", WIDTHS)
def test_the_page_fits_every_width_with_hit_areas_and_a_16_px_gutter(browser, pb, fake_amt, width):
    cm = check_mockups()
    ctx, pg = power_page(browser, pb, width=width)
    try:
        pg.wait_for_selector("#power-pill .pill")
        open_options(pg)                                   # the 14 checkboxes and 2 number fields are part of the layout
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
        assert len(r["targets"]) >= 30 and r["text"], "the walk saw nothing: it would pass on an empty page"
        assert pg.errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_every_text_and_ring_on_the_page_clears_the_contrast_floors(browser, pb, fake_amt, scheme):
    cm = check_mockups()
    ctx, pg = power_page(browser, pb, scheme=scheme)
    try:
        pg.wait_for_selector("#power-pill .pill")
        open_options(pg)
        pg.wait_for_timeout(250)
        r = pg.evaluate(cm.JS_WALK)
        low = [(t["snippet"], t["ratio"], t["ex"]) for t in r["text"] if t["ratio"] < (3.0 if t["large"] else 4.5)]
        rings = [(x["ex"], x["ratio"]) for x in r["rings"] if x["ratio"] < 3.0 and x["kind"] != "decor"]
        assert low == [], low
        assert len(r["text"]) > 40, "the walk saw too little text: it would pass on an empty page"
        assert pg.errors == [] and rings is not None
    finally:
        ctx.close()


def test_the_page_loads_nothing_from_outside_the_console_and_never_touches_amt_mcp(browser, pb, fake_amt):
    ctx, pg = power_page(browser, pb)
    try:
        origins = {u.split("/")[0] + "//" + u.split("/")[2] for u in pg.requests if u.startswith("http")}
        assert origins == {pb.origin}, origins
        assert not [u for u in pg.requests if fake_amt.base in u or u.endswith("/mcp")]
        body = pg.content()
        assert BEARER not in body and "type=\"password\"" not in body and "handoffs/" not in body
    finally:
        ctx.close()


def test_the_offered_read_error_is_masked(me, fake_amt):
    """Sprint review M2: a one-time url in the tool's error text never reaches the browser through the power route."""
    from test_console_fleet import HANDOFF_TOKEN, VIEWER_TOKEN, assert_masked
    fake_amt.results["amt_wsman_get"] = lambda a: tool_error(
        f"Error executing tool amt_wsman_get: wsman_auth_failed_401 https://amt.example.test/handoffs/{HANDOFF_TOKEN} "
        f"and https://amt-viewer.example.test/m/{VIEWER_TOKEN}/")
    settle(me)
    r = me.get(f"/api/server/{KEY}/power")
    assert "wsman_auth_failed_401" in r.json()["error"] and r.json()["paused"]["reason"] == "credential refused"
    assert_masked(r.text)


def test_the_offered_transport_error_is_masked(me, fake_amt, monkeypatch):
    """The transport branch of the offered read (an McpError, not a tool error) masks and cuts the same way: its message is a code
    today, so the test hands it a one-time url to prove the branch withholds one, and one that the 300-character cut lands inside."""
    from test_console_fleet import HANDOFF_TOKEN, VIEWER_TOKEN, assert_masked
    settle(me)
    real = me.app.mcp.call
    pad = "x" * (300 - len("https://amt-viewer.example.test/m/") - 20 - 5)

    def call(tool, arguments):
        if tool == "amt_wsman_get":
            raise mcp_client.McpError(f"amt_mcp_unreachable https://amt.example.test/handoffs/{HANDOFF_TOKEN} {pad} "
                                      f"https://amt-viewer.example.test/m/{VIEWER_TOKEN}/")
        return real(tool, arguments)
    monkeypatch.setattr(me.app.mcp, "call", call)
    r = me.get(f"/api/server/{KEY}/power")
    assert r.json()["error"].startswith("amt_mcp_unreachable") and r.json()["offered"] is None
    assert_masked(r.text)
    assert VIEWER_TOKEN[:12] not in r.text and HANDOFF_TOKEN[:12] not in r.text
