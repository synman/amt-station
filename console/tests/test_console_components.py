"""The built client in a real browser (headless Chromium): the confirmation sheets, the force control and the one
destructive-call predicate (immutables 4, 5 and 6), framing refusal, the theme (16), the sign-in page (22) and a
whole passkey ceremony against Chrome's virtual authenticator. The design's own matrix drivers
(design/check_mockups.py) run against this client; the page that hosts the controls is served through
Playwright's route at the console's origin, so /static and /api/call are the console's real ones."""
import hashlib
import json
import re
import time

import pytest

from console_fakes import Authenticator, Console, FakeAmt, BEARER, check_mockups, enroll_first_passkey

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed: the browser immutables are NOT checked")

HARNESS = """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>harness</title><link rel="stylesheet" href="/static/theme.css"><link rel="stylesheet" href="/static/base.css">
<script src="/static/theme-init.js"></script></head><body>
<div class="product"><main><section class="content"><div class="row">
<button class="btn tonal" id="b-restart">Restart</button><button class="btn outlined" id="b-reset">Hard reset</button>
<button class="btn text" id="b-disabled" aria-disabled="true">Disabled</button></div></section></main></div>
<div id="scrim" class="scrim"></div>
<script src="/static/components.js"></script><script src="/static/app.js"></script></body></html>"""

BIND = """() => {
  const spec = (title, verb, consequence, action) => () => ({ title, verb, consequence, call: { tool: 'amt_power', arguments: { device: 'my-server-1', action } } });
  amtc.bindWrite(document.getElementById('b-restart'), spec('Restart my-server-1 (graceful)', 'Restart', 'The OS is asked to restart; unsaved work is saved by the OS.', 'restart'));
  amtc.bindWrite(document.getElementById('b-reset'), spec('Hard reset my-server-1', 'hard reset', 'The OS is NOT asked. The host resets at once.', 'hard_reset'));
}"""

EXPECTED_FORCE = {"click": (0, True), "hold600": 0, "hold1400_slideoff": 0, "swipe": 0, "hold1400_release": 1,
                  "click_450_click": (0, True), "click_700_click": (0, True), "dblclick": (0, True), "click_click_wait_confirm": (1, "true"),
                  "enter_held": (0, False), "enter_wait_enter": (0, False), "enter_release_550_tab_enter": (1, "true"),
                  "enter_held_600_not_armed": ("false", 0)}


@pytest.fixture(scope="module")
def stack(tmp_path_factory):
    fake = FakeAmt()
    tmp = tmp_path_factory.mktemp("c1-browser")
    console = Console(tmp, fake)
    authn = Authenticator(console.app.cfg.rp_id, console.origin)
    enroll_first_passkey(console, authn)
    yield console, fake
    console.close()
    fake.close()


@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as ex:  # noqa: BLE001
            pytest.skip(f"headless Chromium is not installed ({type(ex).__name__}): the browser immutables are NOT checked")
        yield b
        b.close()


def signed_context(browser, console, **kw):
    ctx = browser.new_context(**kw)
    ctx.add_cookies([{"name": "amt_console_session", "value": console.cookie, "domain": console.host, "path": "/",
                      "httpOnly": True, "secure": True, "sameSite": "Strict"}])
    return ctx


def harness(ctx, console):
    pg = ctx.new_page()
    pg.route(f"{console.origin}/__harness", lambda route: route.fulfill(status=200, content_type="text/html", body=HARNESS))
    pg.goto(f"{console.origin}/__harness")
    pg.wait_for_function("window.amtc && window.amtc.csrf")
    pg.evaluate(BIND)
    return pg


def open_force_sheet(pg):
    pg.click("#b-reset")
    pg.wait_for_selector(".sheet[data-force-sheet].open")
    pg.evaluate("() => window.__closeSheets()")


def wait_js(pg, expr, seconds=8):
    """Poll an expression in the page (wait_for_function evaluates a string, which the console's CSP refuses)."""
    return wait_for(lambda: pg.evaluate(expr), seconds)


def wait_for(pred, seconds=5):
    end = time.time() + seconds
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.05)
    return False


# -- immutable 5: the force matrix, the opener's point, the holding state ---------------------------------------------

@pytest.mark.parametrize("width", [1024, 360])
def test_the_force_matrix_on_the_component(browser, stack, width):
    console, _ = stack
    cm = check_mockups()
    ctx = signed_context(browser, console, viewport={"width": width, "height": 900})
    try:
        pg = harness(ctx, console)
        open_force_sheet(pg)
        got = cm.force_matrix(pg, 0)
        assert got is not None, "no force control was found"
        assert got["opener_point"] != "CONFIRM", "the second sheet's confirm sits under the opener's point"
        got.pop("opener_point")
        assert got == EXPECTED_FORCE
    finally:
        ctx.close()


def test_a_tap_then_a_tap_500_ms_later_never_fires(browser, stack):
    console, _ = stack
    ctx = signed_context(browser, console, viewport={"width": 360, "height": 900}, has_touch=True)
    try:
        pg = harness(ctx, console)
        open_force_sheet(pg)
        assert check_mockups().tap_matrix(pg, 0) == (0, True)
    finally:
        ctx.close()


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_the_holding_state_clears_the_contrast_floors(browser, stack, theme):
    console, _ = stack
    cm = check_mockups()
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900}, color_scheme=theme)
    try:
        pg = harness(ctx, console)
        open_force_sheet(pg)
        held = cm.hold_contrast(pg, 0)
        assert held and held["text"], "the held control showed no label"
        assert all(t["ratio"] >= 4.5 for t in held["text"]), held
        assert held["bar"]["ratio"] >= 3.0 and held["bg"] == cm.tok(theme, "ext.hold.fill"), held
    finally:
        ctx.close()


# -- immutable 4: nothing writes on a bare click; one activation sends one call --------------------------------------

def test_confirm_sheets_send_one_call_per_activation_and_manage_focus(browser, stack):
    console, _ = stack
    cm = check_mockups()
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900})
    try:
        pg = harness(ctx, console)
        pg.click("#b-restart")
        pg.evaluate("() => window.__closeSheets()")
        checks = cm.confirm_checks(pg)
        assert len(checks) == 1, checks
        c = checks[0]
        assert c["click"] == 1 and c["enter_held"] == 1, c
        assert c["focus_key"] == {"inSheet": True, "isCancel": True} and c["focus_ptr"] and c["trapped"], c
    finally:
        ctx.close()


@pytest.mark.parametrize("opener", ["#b-restart", "#b-reset"])
@pytest.mark.parametrize("opened_by", ["pointer", "key"])
@pytest.mark.parametrize("closed_by", ["escape", "cancel"])
def test_a_sheet_closes_on_escape_or_cancel_and_focus_returns_to_the_control_that_opened_it(browser, stack, opener, opened_by, closed_by):
    console, fake = stack
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900})
    try:
        pg = harness(ctx, console)
        before = len(fake.calls)
        if opened_by == "pointer":
            pg.click(opener)
        else:
            pg.focus(opener)
            pg.keyboard.press("Enter")
        pg.wait_for_selector(".sheet.open")
        assert pg.evaluate("() => document.activeElement.hasAttribute('data-close')")        # focus went to Cancel, inside the sheet
        if closed_by == "escape":
            pg.keyboard.press("Escape")
        else:
            pg.click(".sheet.open [data-close]")
        assert wait_js(pg, "() => document.querySelectorAll('.sheet.open').length === 0"), "the sheet is still open"
        assert wait_js(pg, f"() => document.activeElement === document.querySelector('{opener}')"), pg.evaluate("() => document.activeElement.outerHTML")
        assert len(fake.calls) == before and pg.evaluate("() => window.__callCount()") == 0      # closing sends nothing
    finally:
        ctx.close()


def test_a_bare_click_outside_a_sheet_sends_nothing_and_fires_nothing(browser, stack):
    console, fake = stack
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900})
    try:
        pg = harness(ctx, console)
        before = len(fake.calls)
        swept = check_mockups().outside_sweep(pg)
        assert swept["controls"] >= 3 and swept["calls"] == 0 and swept["fires"] == 0, swept
        pg.click("#b-restart"); pg.click(".sheet.open [data-close]")            # opening a sheet is not a write
        assert len(fake.calls) == before and pg.evaluate("() => window.__callCount()") == 0
    finally:
        ctx.close()


def test_a_disabled_control_ignores_activation(browser, stack):
    console, _ = stack
    ctx = signed_context(browser, console)
    try:
        pg = harness(ctx, console)
        pg.evaluate("""() => { window.__hit = 0; const b = document.getElementById('b-disabled'); b.addEventListener('click', () => window.__hit++); amtc.bindWrite(b, () => ({ title: 't', verb: 'v', consequence: 'c', call: { tool: 'amt_power', arguments: { device: 'x', action: 'restart' } } })); }""")
        pg.click("#b-disabled", force=True)
        assert pg.evaluate("() => window.__hit") == 0 and pg.query_selector(".sheet.open") is None
        assert pg.evaluate("() => document.getElementById('b-disabled').tabIndex") >= 0
    finally:
        ctx.close()


def test_a_held_enter_on_an_opener_opens_one_sheet_and_sends_nothing(browser, stack):
    console, _ = stack
    ctx = signed_context(browser, console)
    try:
        pg = harness(ctx, console)
        pg.focus("#b-restart")
        pg.evaluate("() => { window.__opens = 0; document.addEventListener('sheet-open', () => window.__opens++, true); }")
        pg.keyboard.down("Enter")
        for _ in range(20):
            pg.keyboard.down("Enter"); pg.wait_for_timeout(33)
        pg.keyboard.up("Enter")
        assert pg.evaluate("() => window.__callCount()") == 0
        assert pg.evaluate("() => window.__opens") == 1                  # one deliberate activation opened one sheet, not one per repeat
    finally:
        ctx.close()


# -- the force control's finer rules: arming, cancel, the swallowed click, key repeat -----------------------------------------

def center(el):
    b = el.bounding_box()
    return b["x"] + b["width"] / 2, b["y"] + b["height"] / 2


def force_page(browser, console, **kw):
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900}, **kw)
    pg = harness(ctx, console)
    pg.click("#b-reset")                                    # builds the force sheets; the host sheet is now open
    pg.wait_for_timeout(350)
    return ctx, pg


def armed(pg):
    return pg.evaluate("() => { const b = document.querySelector('.sheet[data-force-sheet2].open [data-confirm]'); return b && b.getAttribute('data-armed'); }")


def test_the_second_sheet_arms_400_ms_after_a_release_that_followed_its_opening(browser, stack):
    console, _ = stack
    ctx, pg = force_page(browser, console)
    try:
        pg.focus(".sheet.open .force-control")
        pg.keyboard.press("Enter")                          # keydown opens the second sheet, keyup is the release
        pg.wait_for_timeout(150)
        assert armed(pg) == "false"                         # 150 ms after the release: not yet
        pg.wait_for_timeout(450)
        assert armed(pg) == "true"
        pg.evaluate("() => window.__closeSheets()")
        pg.click("#b-reset"); pg.wait_for_timeout(350)
        x, y = center(pg.query_selector(".sheet.open .force-control"))
        pg.mouse.click(x, y)                                # a pointer open: its pointerup came BEFORE the sheet opened
        pg.wait_for_timeout(800)
        assert armed(pg) == "false"                         # no timer starts from the opening activation
        x, y = center(pg.query_selector(".sheet[data-force-sheet2].open h2"))
        pg.mouse.click(x, y)                                # a later release (on the sheet's title) arms it
        pg.wait_for_timeout(100)
        assert armed(pg) == "false"
        pg.wait_for_timeout(450)
        assert armed(pg) == "true"
    finally:
        ctx.close()


def test_a_pointer_that_went_down_before_the_confirm_armed_cannot_fire_it(browser, stack):
    console, _ = stack
    ctx, pg = force_page(browser, console)
    try:
        pg.focus(".sheet.open .force-control")
        pg.keyboard.press("Enter")                          # t0: the sheet is open and the release happened
        pg.wait_for_timeout(250)
        assert armed(pg) == "false"
        x, y = center(pg.query_selector(".sheet.open [data-confirm]"))
        pg.mouse.move(x, y); pg.mouse.down()                # pointerdown while NOT armed
        pg.wait_for_timeout(350)
        assert armed(pg) == "true"                          # armed while the pointer is still down
        pg.mouse.up()
        pg.wait_for_timeout(100)
        assert pg.evaluate("() => window.__forceFireCount()") == 0 and pg.query_selector(".sheet[data-force-sheet2].open")
        pg.mouse.click(x, y)                                # a deliberate click on the visibly armed button fires
        pg.wait_for_timeout(100)
        assert pg.evaluate("() => window.__forceFireCount()") == 1
    finally:
        ctx.close()


@pytest.mark.parametrize("event", ["pointercancel", "pointerleave", "pointermove-away"])
def test_cancel_leave_and_moving_off_each_reset_a_hold(browser, stack, event):
    console, _ = stack
    ctx, pg = force_page(browser, console)
    try:
        k = pg.query_selector(".sheet.open .force-control")
        x, y = center(k)
        pg.mouse.move(x, y); pg.mouse.down(); pg.wait_for_timeout(1400)
        assert "armed" in k.get_attribute("class")
        pg.evaluate("""([e]) => { const k = document.querySelector('.sheet.open .force-control');
            if (e === 'pointermove-away') k.dispatchEvent(new PointerEvent('pointermove', { clientX: -50, clientY: -50, bubbles: true }));
            else k.dispatchEvent(new PointerEvent(e, { bubbles: true })); }""", [event])
        assert "armed" not in k.get_attribute("class") and "holding" not in k.get_attribute("class")
        pg.mouse.up(); pg.wait_for_timeout(100)
        assert pg.evaluate("() => window.__forceFireCount()") == 0
    finally:
        ctx.close()


def test_the_click_after_a_fired_hold_does_not_open_the_second_sheet(browser, stack):
    console, _ = stack
    ctx, pg = force_page(browser, console)
    try:
        x, y = center(pg.query_selector(".sheet.open .force-control"))
        pg.mouse.move(x, y); pg.mouse.down(); pg.wait_for_timeout(1400); pg.mouse.up(); pg.wait_for_timeout(200)
        assert pg.evaluate("() => window.__forceFireCount()") == 1
        assert pg.query_selector(".sheet.open") is None
    finally:
        ctx.close()


def test_key_repeat_is_ignored_by_the_confirm_the_force_control_and_the_armed_second_confirm(browser, stack):
    """A key already held when focus lands on the control: Playwright marks the next keydown as an auto-repeat."""
    console, _ = stack
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900})
    try:
        pg = harness(ctx, console)
        calls = lambda: pg.evaluate("() => window.__callCount()")
        # a plain confirm
        pg.evaluate("() => document.activeElement && document.activeElement.blur()")
        pg.keyboard.down("Enter")
        pg.evaluate("() => amtc.openWrite({ title: 'T', verb: 'Restart', consequence: 'C', call: { tool: 'amt_power', arguments: { device: 'my-server-1', action: 'restart' } } })")
        pg.focus(".sheet.open [data-confirm]")
        pg.keyboard.down("Enter"); pg.keyboard.up("Enter")
        assert calls() == 0 and pg.query_selector(".sheet.open [data-confirm]")
        pg.evaluate("() => window.__closeSheets()")
        # the force control
        pg.evaluate("() => document.activeElement && document.activeElement.blur()")
        pg.keyboard.down("Enter")
        pg.click("#b-reset"); pg.wait_for_timeout(350)
        pg.focus(".sheet.open .force-control")
        pg.keyboard.down("Enter"); pg.keyboard.up("Enter")
        assert pg.query_selector(".sheet[data-force-sheet2].open") is None
        # the armed second confirm: arm it with a pointer release, keep Enter held, focus the confirm, Enter again
        pg.evaluate("() => document.activeElement && document.activeElement.blur()")
        pg.keyboard.down("Enter")
        pg.evaluate("() => { const k = document.querySelector('.sheet.open .force-control'); k.click(); }")
        x, y = center(pg.query_selector(".sheet[data-force-sheet2].open h2"))
        pg.mouse.click(x, y); pg.wait_for_timeout(600)      # a pointer release on the title arms it; Enter stays held
        assert armed(pg) == "true"
        pg.focus(".sheet[data-force-sheet2].open [data-confirm]")
        pg.keyboard.down("Enter"); pg.keyboard.up("Enter"); pg.wait_for_timeout(100)
        assert pg.evaluate("() => window.__forceFireCount()") == 0 and calls() == 0
    finally:
        ctx.close()


# -- the destructive predicate (5) and the request spy (4, 6) --------------------------------------------------------

POWER = lambda action: ("amt_power", {"device": "my-server-1", "action": action}, {})
PREDICATE_CASES = [
    *[(*POWER(a), True) for a in ("hard_reset", "hard_power_off", "hard_power_cycle", "immediate_shutdown", "immediate_power_cycle", "nmi")],
    *[(*POWER(a), False) for a in ("restart", "shutdown", "power_cycle", "shutdown_hard_graceful", "power_cycle_hard_graceful", "power_on", "sleep_light", "sleep_deep", "hibernate")],
    ("amt_power", {"device": "x"}, {}, False),                                                           # the default is the graceful restart
    ("amt_set_next_boot", {"device": "x", "target": "pxe", "options": {"secure_erase": True}}, {}, True),
    ("amt_set_next_boot", {"device": "x", "target": "pxe", "options": {"reflash_bios": True, "use_sol": True}}, {}, True),
    ("amt_set_next_boot", {"device": "x", "target": "bios_setup", "options": {"configuration_data_reset": True}}, {}, True),
    ("amt_set_next_boot", {"device": "x", "target": "pxe", "options": {"firmware_verbosity": 2}}, {}, False),
    ("amt_set_next_boot", {"device": "x", "target": "pxe", "options": {"secure_erase": False}}, {}, False),
    ("amt_set_next_boot", {"device": "x", "target": "pxe", "options": {"secure_erase": "true"}}, {}, False),   # only the JSON boolean
    ("amt_set_next_boot", {"device": "x", "target": "pxe", "options": None}, {}, False),
    ("amt_set_next_boot", {"device": "x", "target": "clear"}, {}, False),
    ("amt_ider", {"device": "x", "action": "mount", "iso_path": "a.iso", "start": "now"}, {}, True),
    ("amt_ider", {"device": "x", "action": "mount", "iso_path": "a.iso", "start": "next_boot"}, {}, False),
    ("amt_ider", {"device": "x", "action": "mount", "iso_path": "a.iso", "start": "graceful"}, {}, False),
    ("amt_ider", {"device": "x", "action": "unmount"}, {}, False),
    ("amt_images", {"action": "delete", "name": "a.iso"}, {}, True),
    ("amt_images", {"action": "rename", "name": "a.iso", "new_name": "b.iso"}, {}, False),
    ("amt_images", {"action": "fetch", "url": "https://x/a.iso"}, {}, False),
    ("amt_device_manage", {"action": "remove", "device": "x"}, {}, True),
    ("amt_device_manage", {"action": "edit", "device": "x", "repin": True}, {}, True),
    ("amt_device_manage", {"action": "edit", "device": "x", "repin": False}, {}, False),
    ("amt_device_manage", {"action": "add", "device": "x"}, {}, False),
    ("amt_identity_manage", {"action": "remove", "name": "n"}, {}, True),
    ("amt_identity_manage", {"action": "intake", "name": "n"}, {}, False),
    ("amt_wsman_invoke", {"device": "x", "operation": "invoke", "class_name": "AMT_SetupAndConfigurationService", "method": "Unprovision"}, {}, True),
    ("amt_wsman_invoke", {"device": "x", "operation": "invoke", "class_name": "CIM_PowerManagementService", "method": "RequestPowerStateChange"}, {}, False),
    ("amt_mirror_link", {"device": "x", "action": "stop"}, {"startedByAgent": True}, True),
    ("amt_mirror_link", {"device": "x", "action": "stop"}, {"callInFlight": True}, True),
    ("amt_serial_link", {"device": "x", "action": "stop"}, {"startedByAgent": True}, True),
    ("amt_serial_link", {"device": "x", "action": "stop"}, {"callInFlight": True}, True),
    ("amt_mirror_link", {"device": "x", "action": "stop"}, {}, False),                                   # the console's own idle session: a plain confirm
    ("amt_mirror_link", {"device": "x", "action": "stop"}, {"startedByAgent": False, "callInFlight": False}, False),
    ("amt_mirror_link", {"device": "x", "action": "start"}, {"startedByAgent": True}, False),
    ("amt_serial_link", {"device": "x", "action": "status"}, {"callInFlight": True}, False),
    ("amt_status", {"device": "x"}, {}, False),
    ("not_a_tool", {}, {}, False),
]


def test_the_destructive_predicate_decides_from_the_arguments(browser, stack):
    console, _ = stack
    ctx = signed_context(browser, console)
    try:
        pg = harness(ctx, console)
        wrong = []
        for tool, args, cctx, expected in PREDICATE_CASES:
            got = pg.evaluate("([t, a, c]) => amtc.destructiveCall({ tool: t, arguments: a }, c)", [tool, args, cctx])
            if got is not expected:
                wrong.append((tool, args, cctx, got))
        assert wrong == []
        assert pg.evaluate("() => [amtc.destructiveCall(null), amtc.destructiveCall({}), window.__destructiveCall === amtc.destructiveCall]") == [False, False, True]
    finally:
        ctx.close()


def test_the_sheet_kind_follows_the_arguments_and_shows_the_exact_call(browser, stack):
    console, _ = stack
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900})
    try:
        pg = harness(ctx, console)
        for tool, args, cctx, expected in PREDICATE_CASES:
            if tool == "not_a_tool":
                continue
            kind = pg.evaluate("""([t, a, c]) => { window.__closeSheets(); const s = amtc.openWrite({ title: 'T', verb: 'Go', consequence: 'C', call: { tool: t, arguments: a }, ctx: c });
                return { force: s.hasAttribute('data-force-sheet'), plain: s.hasAttribute('data-confirm-sheet'), call: s.querySelector('.call').textContent,
                         destructiveLine: s.querySelector('.consequence').classList.contains('destructive'), hasControl: !!s.querySelector('.force-control'), hasConfirm: !!s.querySelector('[data-confirm]') }; }""", [tool, args, cctx])
            assert kind["force"] is expected and kind["plain"] is not expected, (tool, args, kind)
            assert kind["destructiveLine"] is expected and kind["hasControl"] is expected and kind["hasConfirm"] is (not expected), (tool, args, kind)
            assert kind["call"].startswith(f"tools/call {tool} {{") and "confirmed: true" in kind["call"], kind["call"]
            if "device" in args:
                assert f'device: "{args["device"]}"' in kind["call"], kind["call"]
    finally:
        ctx.close()


def test_every_sent_call_names_the_device_carries_confirmed_and_was_forced_when_destructive(browser, stack):
    console, fake = stack
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900})
    try:
        pg = harness(ctx, console)
        base = len(fake.calls)
        pg.click("#b-restart"); pg.click("[data-confirm]")                  # one plain write
        assert wait_for(lambda: len(fake.calls) == base + 1)
        pg.click("#b-reset")                                                # one forced write: hold 1.4 s, release
        pg.wait_for_timeout(350)                                            # the sheet slides up for 300 ms; a user waits too
        k = pg.query_selector(".sheet.open .force-control")
        box = k.bounding_box()
        pg.mouse.move(box["x"] + box["width"] / 2, box["y"] + box["height"] / 2); pg.mouse.down(); pg.wait_for_timeout(1400); pg.mouse.up()
        assert wait_for(lambda: len(fake.calls) == base + 2)
        sent = fake.calls[base:]
        assert [(t, a["action"], a["device"], a["confirmed"]) for t, a, _ in sent] == [
            ("amt_power", "restart", "my-server-1", True), ("amt_power", "hard_reset", "my-server-1", True)]
        assert {auth for _, _, auth in sent} == {f"Bearer {BEARER}"}       # the console bearer, added by the backend, not the page
        spied = pg.evaluate("() => window.__calls()")
        assert [(c["tool"], c["forced"]) for c in spied] == [("amt_power", False), ("amt_power", True)]
        unforced = [c for c in spied if pg.evaluate("c => amtc.destructiveCall({ tool: c.tool, arguments: c.arguments }, c.ctx)", c) and not c["forced"]]
        assert unforced == []
        assert pg.evaluate("() => window.__forceFireCount()") == 1
        assert all("bearer" not in json.dumps(c).lower() for c in spied)   # the page never held it
    finally:
        ctx.close()


FIELDS = """() => {
  window.__got = [];
  const spec = () => ({ id: 'sheet-fields', title: 'Rename a.iso', verb: 'Rename', consequence: 'Renames the file.',
    call: { tool: 'amt_images', arguments: { action: 'rename', path: 'a.iso' } },
    fields: [{ name: 'new_name', label: 'New name', value: 'a.iso', mono: true }, { name: 'file', label: 'File', type: 'file', accept: '.iso' }],
    build: (v) => {
      const n = (v.new_name || '').trim();
      if (n === 'DESTROY') return { call: { tool: 'amt_images', arguments: { action: 'delete', path: 'a.iso' } } };
      if (!n || n === 'a.iso') return { error: 'enter a different name', title: 'Rename a.iso (waiting)' };
      return { call: { tool: 'amt_images', arguments: { action: 'rename', path: 'a.iso', new_name: n } }, title: 'Rename a.iso to ' + n, notes: { new_name: 'will be ' + n, file: v.file ? v.file.name : '' } };
    },
    onResult: (r, values) => window.__got.push({ status: r.status, name: values.new_name, file: values.file ? values.file.name : null }) });
  const b = document.createElement('button'); b.id = 'b-fields'; b.className = 'btn tonal'; b.textContent = 'Rename';
  document.querySelector('.content .row').appendChild(b);
  amtc.bindWrite(b, spec);
}"""


def test_a_sheet_with_fields_rebuilds_its_call_from_what_is_typed_and_sends_that_call_once(browser, stack):
    console, fake = stack
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900})
    try:
        pg = harness(ctx, console)
        pg.evaluate(FIELDS)
        before = len(fake.calls)
        pg.click("#b-fields")
        sheet = ".sheet.open"
        assert pg.evaluate("() => document.activeElement.hasAttribute('data-close')")                          # Cancel first, never a field or Confirm
        assert pg.get_attribute(f"{sheet} [data-confirm]", "aria-disabled") == "true"
        assert pg.inner_text(f"{sheet} .btn-wrap .reason") == "enter a different name" and pg.inner_text(f"{sheet} h2") == "Rename a.iso (waiting)"
        assert pg.inner_text(f"{sheet} .call") == 'tools/call amt_images {action: "rename", path: "a.iso", confirmed: true}'
        pg.click(f"{sheet} [data-confirm]", force=True)
        assert len(fake.calls) == before and pg.evaluate("() => window.__callCount()") == 0                   # a disabled Confirm sends nothing
        pg.fill(f"{sheet} [data-field=new_name]", "b.iso")
        assert pg.get_attribute(f"{sheet} [data-confirm]", "aria-disabled") is None and pg.inner_text(f"{sheet} h2") == "Rename a.iso to b.iso"
        assert pg.inner_text(f"{sheet} .call") == 'tools/call amt_images {action: "rename", path: "a.iso", new_name: "b.iso", confirmed: true}'
        assert pg.inner_text(f"{sheet} .field .help") == "will be b.iso"
        pg.set_input_files(f"{sheet} input[type=file]", {"name": "x.iso", "mimeType": "application/octet-stream", "buffer": b"abc"})
        pg.keyboard.press("Tab")
        pg.focus(f"{sheet} [data-confirm]")
        pg.keyboard.down("Enter")
        for _ in range(20):
            pg.keyboard.down("Enter")                                                                           # a held Enter repeats: one call, not many
        pg.keyboard.up("Enter")
        assert wait_js(pg, "() => window.__got.length === 1"), pg.evaluate("() => window.__got")
        assert pg.evaluate("() => window.__got") == [{"status": 200, "name": "b.iso", "file": "x.iso"}]
        sent = [(t, a) for t, a, _ in fake.calls[before:]]
        assert sent == [("amt_images", {"action": "rename", "path": "a.iso", "new_name": "b.iso", "confirmed": True})]
        assert pg.evaluate("() => window.__callCount()") == 1
    finally:
        ctx.close()


def test_a_sheet_with_fields_can_never_be_the_destructive_one(browser, stack):
    console, fake = stack
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900})
    try:
        pg = harness(ctx, console)
        pg.evaluate(FIELDS)
        before = len(fake.calls)
        pg.click("#b-fields")
        pg.fill(".sheet.open [data-field=new_name]", "DESTROY")                                                   # a form whose value makes the call a delete
        assert pg.get_attribute(".sheet.open [data-confirm]", "aria-disabled") == "true"
        assert "needs the hold" in pg.inner_text(".sheet.open .btn-wrap .reason") and pg.evaluate("() => document.querySelectorAll('.force-control').length") == 0
        pg.click(".sheet.open [data-confirm]", force=True)
        assert len(fake.calls) == before and pg.evaluate("() => window.__callCount()") == 0
        thrown = pg.evaluate("""() => { try { amtc.openWrite({ title: 't', verb: 'v', consequence: 'c', call: { tool: 'amt_images', arguments: { action: 'delete', path: 'a.iso' } },
          fields: [{ name: 'x', label: 'x' }], build: () => ({ error: 'e' }) }); return null; } catch (e) { return String(e.message); } }""")
        assert thrown == "a sheet with fields cannot be a force sheet"
    finally:
        ctx.close()


def test_the_spy_would_catch_a_destructive_call_sent_without_the_force_step(browser, stack):
    """Positive control: a hard reset pushed through the plain path (bypassing the force sheet) is reported by the same check."""
    console, _ = stack
    ctx = signed_context(browser, console)
    try:
        pg = harness(ctx, console)
        pg.evaluate("""() => { const a = { device: 'my-server-1', action: 'hard_reset', confirmed: true };
            const s = amtc.openWrite({ title: 'T', verb: 'Go', consequence: 'C', call: { tool: 'amt_power', arguments: { device: 'my-server-1', action: 'restart' } } });
            s.querySelector('[data-confirm]').click(); }""")
        # re-label the recorded call as the destructive one to model a mis-routed send
        calls = pg.evaluate("() => window.__calls().map(c => Object.assign({}, c, { arguments: { device: 'my-server-1', action: 'hard_reset' } }))")
        bad = [c for c in calls if pg.evaluate("c => amtc.destructiveCall({ tool: c.tool, arguments: c.arguments }, c.ctx)", c) and not c["forced"]]
        assert len(bad) == 1
    finally:
        ctx.close()


def test_a_session_in_the_browser_makes_no_request_outside_the_console_and_none_to_amt_mcp(browser, stack):
    """The receipt's network log, scripted: every request of a sign-in-to-write session goes to the console's own origin, and
    none to amt-mcp's MCP endpoint (the console backend makes that call)."""
    console, fake = stack
    ctx = signed_context(browser, console, viewport={"width": 1024, "height": 900})
    try:
        seen = []
        ctx.on("request", lambda r: seen.append(r.url))
        pg = ctx.new_page()
        for path in ("/signin", "/", "/settings", "/manage"):
            pg.goto(f"{console.origin}{path}"); pg.wait_for_timeout(150)
        h = harness(ctx, console)
        base = len(fake.calls)
        h.click("#b-restart"); h.click("[data-confirm]")
        assert wait_for(lambda: len(fake.calls) == base + 1)           # amt-mcp was reached, by the backend
        origins = {u.split("/")[0] + "//" + u.split("/")[2] for u in seen if u.startswith("http")}
        assert origins == {console.origin}, origins
        assert not [u for u in seen if u.endswith("/mcp") or "/mcp?" in u or fake.base in u], seen
        assert len(seen) > 25
    finally:
        ctx.close()


# -- framing (the console refuses to render in a frame) and the policy's frame-src ----------------------------------------

def test_the_console_refuses_to_render_in_a_frame(browser, stack):
    console, _ = stack
    ctx = signed_context(browser, console)
    try:
        pg = ctx.new_page()
        pg.route("http://evil.example.test/", lambda r: r.fulfill(status=200, content_type="text/html",
                 body=f'<iframe id="f" src="{console.origin}/signin" width="400" height="300"></iframe><iframe id="g" src="{console.origin}/settings"></iframe>'))
        pg.goto("http://evil.example.test/")
        pg.wait_for_timeout(800)
        urls = [f.url for f in pg.frames[1:]]
        assert len(urls) == 2 and all(u.startswith("chrome-error://") for u in urls), urls
        same = harness(ctx, console)
        same.evaluate("() => { const f = document.createElement('iframe'); f.src = '/signin'; document.body.appendChild(f); }")
        same.wait_for_timeout(800)
        assert all(f.url.startswith("chrome-error://") for f in same.frames[1:]), [f.url for f in same.frames]   # even the console's own origin
    finally:
        ctx.close()


def test_the_policy_lets_the_console_frame_only_itself_never_the_viewer_origin_or_a_foreign_one(browser, stack):
    """The viewer pages are relayed under the console's own /embed/ path (packet C4), so no frame of another origin is ever allowed. A frame at
    that path is allowed by frame-src, which is exactly why the relayed response must make its document opaque by itself (sprint review B1): the
    page below creates the frame WITHOUT a sandbox attribute, and the relay's own response headers still leave it with the origin `null`."""
    console, _ = stack
    ctx = signed_context(browser, console)
    try:
        pg = ctx.new_page()
        pg.route("https://amt-viewer.example.test/**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>viewer</p>"))
        pg.route("https://elsewhere.example.test/**", lambda r: r.fulfill(status=200, content_type="text/html", body="<p>elsewhere</p>"))
        pg.goto(f"{console.origin}/settings")
        pg.evaluate("() => { window.__violations = []; document.addEventListener('securitypolicyviolation', e => window.__violations.push(e.violatedDirective)); }")
        pg.evaluate("() => { for (const u of ['https://amt-viewer.example.test/m/x/', 'https://elsewhere.example.test/']) { const f = document.createElement('iframe'); f.src = u; document.body.appendChild(f); } }")
        pg.wait_for_timeout(800)
        assert pg.evaluate("() => window.__violations") == ["frame-src", "frame-src"]       # both foreign frames were refused
        pg.route(re.compile(r".*/embed/mirror/my-server-1/[A-Za-z0-9_-]{43}/$"), lambda r: r.fulfill(
            status=200, content_type="text/html", headers=console.app.embed_headers, body="<script>parent.postMessage({origin: window.origin}, '*')</script>"))
        pg.evaluate("() => { window.__framed = null; addEventListener('message', e => { window.__framed = e.data.origin; }); }")
        pg.evaluate("() => { const f = document.createElement('iframe'); f.src = '/embed/mirror/my-server-1/' + 'k'.repeat(43) + '/'; document.body.appendChild(f); }")
        pg.wait_for_function("() => window.__framed !== null", timeout=5000)
        assert pg.evaluate("() => window.__framed") == "null"                               # opaque although the page asked for no sandbox
        assert pg.evaluate("() => window.__violations.length") == 2                         # the console's own relay path was not refused
        pg.evaluate("() => { const s = document.createElement('script'); s.src = 'https://elsewhere.example.test/x.js'; document.body.appendChild(s); }")
        pg.wait_for_timeout(300)
        assert pg.evaluate("() => window.__violations.length") == 3                         # and a foreign script too
    finally:
        ctx.close()


# -- immutable 16: follows the system, a manual override persists across reload ------------------------------------------

@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_the_theme_follows_the_system_and_a_manual_override_persists(browser, stack, scheme):
    console, _ = stack
    other = "light" if scheme == "dark" else "dark"
    ctx = signed_context(browser, console, color_scheme=scheme)
    try:
        pg = ctx.new_page()
        pg.goto(f"{console.origin}/settings")
        assert wait_js(pg, "() => !!(document.querySelector('[data-theme-set]') && window.amtc && window.amtc.csrf)")
        css = lambda: pg.evaluate("() => getComputedStyle(document.documentElement).colorScheme")
        assert css() == scheme and pg.evaluate("() => document.documentElement.getAttribute('data-theme')") is None
        pg.click(f'[data-theme-set="{other}"]')
        pg.reload()
        assert pg.evaluate("() => document.documentElement.getAttribute('data-theme')") == other and css() == other
        pg.click('[data-theme-set="system"]')
        pg.reload()
        assert pg.evaluate("() => document.documentElement.getAttribute('data-theme')") is None and css() == scheme
        for want in ("light", "dark", None):                                    # the rail button cycles system -> light -> dark -> system
            pg.click("#theme-toggle")
            assert pg.evaluate("() => document.documentElement.getAttribute('data-theme')") == want
        pg.evaluate("() => localStorage.removeItem('amt-console-theme')")
    finally:
        ctx.close()


def test_the_saved_theme_is_applied_before_the_app_script_runs(browser, stack):
    """theme-init.js (in the head) applies a manual override alone: with app.js blocked the override still holds."""
    console, _ = stack
    ctx = signed_context(browser, console, color_scheme="light")
    try:
        pg = ctx.new_page()
        pg.route("**/static/app.js", lambda r: r.abort())
        pg.add_init_script("try { localStorage.setItem('amt-console-theme', 'dark'); } catch (e) {}")
        pg.goto(f"{console.origin}/settings")
        assert pg.evaluate("() => document.documentElement.getAttribute('data-theme')") == "dark"
        assert pg.evaluate("() => getComputedStyle(document.documentElement).colorScheme") == "dark"
    finally:
        ctx.close()


# -- immutable 22 and the sign-in page ------------------------------------------------------------------------------------

def test_the_sign_in_page_has_no_password_field_and_five_states(browser, stack):
    console, _ = stack
    ctx = browser.new_context()
    try:
        pg = ctx.new_page()
        pg.goto(f"{console.origin}/signin")
        assert pg.evaluate("() => document.querySelectorAll('input[type=password], [autocomplete*=password]').length") == 0
        shown = {}
        for state in ("signin", "waiting", "enroll", "expired", "refused"):
            pg.evaluate("s => document.documentElement.setAttribute('data-auth', s)", state)
            shown[state] = pg.evaluate("() => Array.from(document.querySelectorAll('[data-auth-state]')).filter(e => e.offsetParent !== null).map(e => e.getAttribute('data-auth-state'))")
        assert shown == {s: [s] for s in shown}
        pg.goto(f"{console.origin}/signin?expired=1")
        assert pg.evaluate("() => document.documentElement.getAttribute('data-auth')") == "expired"
        text = pg.inner_text(".authcard:visible")
        assert "signed out after 12 hours idle" in text and "Nothing on the hosts changed" in text and "still held by amt-mcp" in text
    finally:
        ctx.close()


# -- a whole passkey ceremony in Chrome (virtual authenticator): enrollment, sign-out, sign-in, add, refused ----------------

@pytest.fixture()
def localhost_stack(tmp_path):
    fake = FakeAmt()
    console = Console(tmp_path, fake, host="localhost")      # an IP is not a WebAuthn RP id; localhost is
    yield console, fake
    console.close()
    fake.close()


def virtual_authenticator(ctx, pg):
    cdp = ctx.new_cdp_session(pg)
    cdp.send("WebAuthn.enable")
    made = cdp.send("WebAuthn.addVirtualAuthenticator", {"options": {"protocol": "ctap2", "transport": "internal", "hasResidentKey": True,
                    "hasUserVerification": True, "isUserVerified": True, "automaticPresenceSimulation": True}})
    return cdp, made["authenticatorId"]


def test_a_real_browsers_passkey_enrolls_signs_out_signs_in_and_adds_another(browser, localhost_stack):
    console, _ = localhost_stack
    console.data.mkdir(parents=True, exist_ok=True)
    (console.data / "enroll.json").write_text(json.dumps({"sha256": hashlib.sha256(b"ABCDEFGHJKMN").hexdigest(), "expires": int(time.time()) + 600}))
    ctx = browser.new_context()
    try:
        pg = ctx.new_page()
        cdp, first = virtual_authenticator(ctx, pg)
        pg.goto(f"{console.origin}/signin")
        pg.click("text=First time here")
        for i, part in enumerate(("ABCD", "EFGH", "JKMN")):
            pg.fill(f"#enroll-code input >> nth={i}", part)
        pg.fill("#pkname", "Virtual key")
        pg.click("#enroll-go")
        pg.wait_for_url(f"{console.origin}/")
        assert not (console.data / "enroll.json").exists()
        cookie = next(c for c in ctx.cookies() if c["name"] == "amt_console_session")
        assert cookie["secure"] and cookie["httpOnly"] and cookie["sameSite"] == "Strict"
        pg.goto(f"{console.origin}/settings")
        pg.wait_for_selector("#passkey-list li")
        assert "Virtual key" in pg.inner_text("#passkey-list")
        # add a second passkey from the signed-in session, through the sheet (on a second authenticator: the first already holds
        # the enrolled credential and the options exclude it)
        cdp.send("WebAuthn.removeVirtualAuthenticator", {"authenticatorId": first})
        virtual_authenticator(ctx, pg)
        pg.click("[data-open=pk-add]")
        pg.fill("#pkn", "Second key")
        pg.click("#pk-add-go")
        assert wait_js(pg, "() => document.querySelectorAll('#passkey-list li').length === 2"), pg.inner_text("#passkey-result")
        assert "Passkey added" in pg.inner_text("#passkey-result")
        assert "Second key" in pg.inner_text("#passkey-list") and "Virtual key" in pg.inner_text("#passkey-list")
        # sign out, then sign in with the discoverable credential
        pg.click("main [data-signout]")
        pg.wait_for_url(f"{console.origin}/signin")
        pg.click(".authcard[data-auth-state=signin] [data-signin]")
        pg.wait_for_url(f"{console.origin}/")
        # a passkey the console does not know: refused card, nothing sent to any host
        (console.data / "passkeys.json").write_text("[]")
        pg.click("[data-signout] >> nth=0")
        pg.wait_for_url(f"{console.origin}/signin")
        pg.click(".authcard[data-auth-state=signin] [data-signin]")
        assert wait_js(pg, "() => document.documentElement.getAttribute('data-auth') === 'refused'")
        assert "not enrolled on this console" in pg.inner_text(".authcard:visible")
    finally:
        ctx.close()
