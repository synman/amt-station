"""The built client's own verifier (packet C8): design/check_mockups.py run against every page of the console.

Every page (sign-in, Fleet, Manage, Identities, Images, Settings, and the nine server sections) is rendered in headless Chromium at 360, 600, 1024 and 1440
in both themes, in front of the same scripted amt-mcp the per-page tests use (console_fakes.FakeAmt, the fake viewer front), and walked with the verifier's
own probes (``JS_WALK`` and the rest) and its one failure builder, ``check_mockups.layout_fails``. The aggregate test prints ``FAILS n`` like the script and
asserts 0.

  - immutable 13: the three layouts (bottom bar below 600, rail from 600, section chips or tabs), no horizontal scroll, the 16 px gutter, every control
    inside the viewport at 360, no letter-wrapped box, the phone height ceiling, no fixed element over a control, nothing under the bottom bar, tables
    card-per-row on the phone and in a scroller on the tablet, a confirmation sheet that is a bottom sheet on the phone;
  - immutable 14: every control's hit area; immutable 15: reduced motion on every page (and every animated element carries ``data-motion``);
  - immutable 18: every ``aria-disabled`` control is focusable, shows its reason and ignores activation;
  - 0 console errors, 0 request that leaves the console's origin, and axe-core 4.11.4 (vendored, test-only) with no violation on any page in either theme.

The keyboard shortcuts of design note 5.5 are tested here too, and the shared failure builder is unit-tested branch by branch so that a green aggregate cannot
come from a builder that stopped looking."""
import hashlib
import json
import re
import subprocess
import sys
import time
from pathlib import Path

import pytest

import amt_tools
from console_fakes import Authenticator, Console, check_mockups, enroll_first_passkey
from test_console_embed import Hosts, hosts, viewer  # noqa: F401 - fixtures
from test_console_embed_browser import seat
from test_console_fleet import KEY, STATUS, device, tool_error
from test_console_fleet_browser import browser, open_page, read_all, text  # noqa: F401 - fixtures
from test_console_logs_inventory import Log, inventory_tool, mixed_events
from test_console_media import ISO, scripted, until
from test_console_power import BOOT_TOOL, OFFERED_CODES, POWER_TOOL, wsman_get
from test_console_settings import Host, identities
from test_console_wsman import Wsman

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed: the browser immutables are NOT checked")

CONSOLE = Path(__file__).resolve().parent.parent
AXE = Path(__file__).resolve().parent / "vendor" / "axe-core"
AXE_SHA256 = "fb83a4378d978ecb7d2dae48a3a3778a84c971ac692f3afd45d714fba89c0f0d"   # axe.min.js 4.11.4, the published SRI of that release
WIDTHS = [360, 600, 1024, 1440]
THEMES = ["light", "dark"]
HEAVY = (360, 1440)             # the sheet, disabled-control and axe passes run at the two ends; the layout walk runs at all four

# axe rules turned off, each with the immutable or design decision it conflicts with. None for color-contrast (immutable 1 is checked by the
# per-page contrast walks AND by axe). An empty table is the state this packet ships in: a rule is added here only with its reason written beside it.
AXE_OFF: dict[str, str] = {}


# ============================== the world: every page has something to show ==================================================================

@pytest.fixture()
def vw(tmp_path, fake_amt, viewer, hosts):
    """A signed-in console, one server read, a mirror and a terminal held (the console's own), everything else scripted as the per-page tests script it."""
    console = Console(tmp_path, fake_amt, viewer_origin=viewer.base)
    enroll_first_passkey(console, Authenticator(console.app.cfg.rp_id, console.origin))
    r = fake_amt.results
    r["amt_identities"] = identities(f"{KEY}-amt", f"{KEY}-amt-user-viewer")
    r["amt_captures"] = lambda a: {"total": 0, "offset": 0, "captures": [], "next_offset": None,
                                   "searched": [{"dir": "/s", "kinds": ["screenshot"], "found": True}, {"dir": "/r", "kinds": ["recording", "serial_cast"], "found": True}]}
    scripted(fake_amt, mounted={"iso": ISO})
    fake_amt.log = Log(mixed_events())
    r["amt_logs"] = fake_amt.log
    r["amt_inventory"] = inventory_tool()
    fake_amt.settings_host = Host()
    r["amt_settings"], r["amt_configure"] = fake_amt.settings_host.read, fake_amt.settings_host.configure
    fake_amt.wsman_host = Wsman()
    power_get = wsman_get(OFFERED_CODES)
    r["amt_wsman_get"] = lambda a: power_get(a) if a["class_name"] == "CIM_AssociatedPowerManagementService" else fake_amt.wsman_host.get(a)
    r["amt_wsman_invoke"] = fake_amt.wsman_host.invoke
    r["amt_power"], r["amt_set_next_boot"] = POWER_TOOL, BOOT_TOOL
    viewer.status["m"]["in_flight"] = {"tool": "amt_console_input", "started_at": 1_760_000_000.0}      # the agent-typing strip is part of the page
    viewer.status["s"]["in_flight"] = {"tool": "amt_sol", "started_at": 1_760_000_000.0}
    seat(console, hosts, "m", "console")
    seat(console, hosts, "s", "console")
    yield console
    console.close()


# ============================== the pages ====================================================================================================

def sign_in_states(pg):
    """The five cards of the sign-in page as (state, setter) pairs, one after the other (the page's own states, set the way its script sets them)."""
    return [(s, lambda s=s: pg.evaluate("s => document.documentElement.setAttribute('data-auth', s)", s)) for s in ("signin", "enroll", "expired", "refused", "waiting")]


PAGES = [  # name, path, the selector that says the page has its content; sheets: the page carries components.js
    ("signin", "/signin", "[data-signin]", False),
    ("fleet", "/", ".scard .pill", True),
    ("manage", "/manage", "#srv-rows tr", True),
    ("identities", "/manage/identities", "#id-list li", True),
    ("images", "/images", "#mounted-chip *", True),
    ("settings", "/settings", "#passkey-list li", True),
    ("status", f"/server/{KEY}", "#srv-pill .pill", True),
    ("power", f"/server/{KEY}/power", "#offered-banner strong, #offered-banner.error", True),
    ("console", f"/server/{KEY}/console", "#kvm-screen iframe", True),
    ("serial", f"/server/{KEY}/serial", "#sol-screen iframe", True),
    ("media", f"/server/{KEY}/media", "#mounted-chip *", True),
    ("logs", f"/server/{KEY}/logs", "#log-counts:not(:empty), #log-state .result", True),
    ("inventory", f"/server/{KEY}/inventory", "#inv-cards .card, #inv-state .result", True),
    ("amt-settings", f"/server/{KEY}/settings", "#set-cards .card, #set-state .result", True),
    ("wsman", f"/server/{KEY}/wsman", "#ws-templates li", True),
]
IDLE = {"logs": "#log-read", "inventory": "#inv-reread", "amt-settings": "#set-reread"}


def open_built(browser, vw, name, path, ready, width, scheme, **kw):
    """The page in a fresh context (signed out for the sign-in page), settled: its content is in and no read of the page is out."""
    if name == "signin":
        ctx = browser.new_context(viewport={"width": width, "height": 900}, color_scheme=scheme, **kw)
        pg = ctx.new_page()
        pg.errors, pg.requests = [], []
        pg.on("console", lambda m: pg.errors.append(m.text) if m.type == "error" else None)
        pg.on("pageerror", lambda e: pg.errors.append(str(e)))
        pg.on("request", lambda r: pg.requests.append(r.url))
        pg.goto(f"{vw.origin}{path}")
    else:
        ctx, pg = open_page(browser, vw, path, width=width, scheme=scheme, **kw)
    pg.set_default_timeout(15000)
    pg.wait_for_selector(ready, state="attached")
    if name in IDLE:
        pg.wait_for_function("sel => !document.querySelector(sel).hasAttribute('aria-disabled')", arg=IDLE[name])
    if name == "console":
        pg.wait_for_selector("#agent-strip:not([hidden])")
    if name == "serial":
        pg.wait_for_selector("#agent-strip:not([hidden])")
    if name in ("status", "fleet"):
        pg.wait_for_selector(".scard .pill, #srv-pill .pill")
    pg.wait_for_timeout(300)
    return ctx, pg


# ============================== the probes that are not in the mockup verifier ===============================================================

JS_DISABLED = "() => {" + check_mockups().JS_HELPERS + r"""
  const CONTROLS = 'button, a[href], input, select, textarea, [role=button], [role=switch], [role=checkbox], [role=radio], [role=tab], summary, [tabindex]';
  const txt = (n) => (n && visible(n)) ? n.textContent.replace(/\s+/g, ' ').trim() : '';
  const out = [];
  document.querySelectorAll('[aria-disabled="true"]').forEach((el, i) => {
    if (!el.matches(CONTROLS) || inMock(el) || !visible(el) || el.closest('.sheet:not(.open)')) return;
    let reason = '';
    const by = el.getAttribute('aria-describedby'); if (by) reason = by.split(' ').map(id => txt(document.getElementById(id))).join(' ').trim();
    if (!reason && el.parentElement) { const q = el.parentElement.querySelector(':scope > .reason'); reason = txt(q); }
    if (!reason) reason = txt(el.querySelector('.reason, .sub'));
    if (!reason && el.nextElementSibling && el.nextElementSibling.matches('.reason, .sub, .help')) reason = txt(el.nextElementSibling);
    if (!reason && el.closest('.btn-wrap')) reason = txt(el.closest('.btn-wrap').querySelector('.reason'));
    if (!reason) { const row = el.closest('li, .row, label, .field'); if (row) reason = txt(row.querySelector('.reason, .sub, .help')); }
    const cs = getComputedStyle(el); const bc = toRGBA(cs.borderTopColor);
    el.setAttribute('data-verifier-i', String(i));
    out.push({ i: i, ex: cls(el) + (el.getAttribute('aria-label') ? '[' + el.getAttribute('aria-label') + ']' : '') + ':' + txt(el).slice(0, 24), tab: el.tabIndex, reason: reason, opacity: cs.opacity,
               btn: el.classList.contains('btn'), borderAlpha: bc ? bc[3] : null, borderStyle: cs.borderTopStyle });
  });
  return out;
}"""

JS_SHEET = """id => { const s = document.getElementById(id); const r = s.getBoundingClientRect(), cs = getComputedStyle(s), h = s.querySelector('.handle');
  return { pos: cs.position, l: r.left, r: r.right, t: r.top, b: r.bottom, w: innerWidth, h: innerHeight, handle: !!h && h.getBoundingClientRect().width > 0, role: s.getAttribute('role'), modal: s.getAttribute('aria-modal') }; }"""

JS_MOTION = """() => Array.from(document.querySelectorAll('[data-motion]')).map(el => { const cs = getComputedStyle(el);
  return { name: el.getAttribute('data-motion'), anim: cs.animationName, trans: cs.transitionDuration.split(',').map(s => s.trim()), ex: el.tagName.toLowerCase() + (el.className ? '.' + String(el.className).trim().split(/\\s+/).join('.') : '') }; })"""

PLAIN = {"id": "verifier-plain", "title": "Verifier probe", "verb": "Restart", "consequence": "Probe only: nothing is sent.",
         "call": {"tool": "amt_power", "arguments": {"device": KEY, "action": "restart"}}}
FORCE = {"id": "verifier-force", "title": "Verifier probe", "verb": "hard reset", "consequence": "Probe only: nothing is sent.",
         "call": {"tool": "amt_power", "arguments": {"device": KEY, "action": "hard_reset"}}}


def merge(r, rr):
    """The walk of one more state or sheet folded into the render's walk (the mockup verifier's own merge)."""
    for key in ("text", "rings", "targets", "motion", "states", "narrow", "offscreen", "fixedOverlap"):
        r[key] += rr[key]
    r["scrollWidth"] = max(r["scrollWidth"], rr["scrollWidth"])
    r["docHeight"] = max(r["docHeight"], rr["docHeight"])


def open_probe(pg, spec):
    pg.evaluate("spec => { window.amtc.openWrite(spec); }", spec)
    pg.wait_for_timeout(380)                                         # the sheet's 300 ms rise is over


def close_probes(pg):
    pg.evaluate("() => { window.amtc.closeSheets(); ['verifier-plain', 'verifier-force', 'verifier-force-sheet2'].forEach(id => { const e = document.getElementById(id); if (e) e.remove(); }); }")


def sheet_fails(pg, cm, name, th, w, r, anim, kind, sid=None):
    """A confirmation sheet opened on the page: its controls are walked (hit areas), it animates under data-motion, and on the phone it is a bottom sheet."""
    bad = []
    sid = sid or "verifier-" + kind
    g = pg.evaluate(JS_SHEET, sid)
    if g["role"] != "dialog" or g["modal"] != "true" or not g["handle"]: bad.append((name, th, w, "sheet-not-a-dialog", kind, g))
    if w < 600 and not (g["pos"] == "fixed" and abs(g["l"]) <= 0.5 and abs(g["r"] - g["w"]) <= 0.5 and abs(g["b"] - g["h"]) <= 0.5 and g["t"] >= 0):
        bad.append((name, th, w, "sheet-not-a-bottom-sheet", kind, g))
    merge(r, pg.evaluate(cm.JS_WALK))
    a2 = pg.evaluate(cm.JS_ANIMATED)
    anim["missing"] += a2["missing"]; anim["animated"] += a2["animated"]
    if kind == "force":                                              # the hold animates its bar: that too carries data-motion
        k = pg.query_selector(".sheet.open .force-control[data-hold]"); b = k.bounding_box(); cx, cy = b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
        pg.mouse.move(cx, cy); pg.mouse.down(); pg.wait_for_timeout(250)
        a3 = pg.evaluate(cm.JS_ANIMATED)
        anim["missing"] += a3["missing"]; anim["animated"] += a3["animated"]
        pg.mouse.move(cx + 400, cy + 300, steps=3); pg.mouse.up()
    return bad


def disabled_fails(pg, fake_amt, name, th, w):
    """Immutable 18 on the page as it stands: every aria-disabled control is focusable, has its reason as visible text, keeps its outline at full alpha
    (a button) and ignores activation: no call, no sheet, no new request to amt-mcp, the same address."""
    bad = []
    found = pg.evaluate(JS_DISABLED)
    for d in found:
        if d["tab"] < 0: bad.append((name, th, w, "disabled-not-focusable", d["ex"]))
        if not d["reason"]: bad.append((name, th, w, "disabled-without-reason", d["ex"]))
        if d["btn"] and (d["opacity"] != "1" or d["borderStyle"] == "none" or d["borderAlpha"] != 1): bad.append((name, th, w, "disabled-outline-faded", d["ex"], d["opacity"], d["borderAlpha"]))
    url = pg.url
    # What a click could send is the page's own write request (a POST); the backend's scheduled status reads reach the fake amt-mcp on their own
    # clock, so counting fake_amt.calls here made the probe flaky whenever one landed inside the window.
    sent = []
    on_request = lambda r: sent.append(r.url) if r.method != "GET" else None
    pg.on("request", on_request)
    base_calls, base_sheets, base_spy = 0, pg.evaluate("() => document.querySelectorAll('.sheet.open').length"), pg.evaluate("() => window.__callCount ? window.__callCount() : 0")
    for d in found:
        pg.evaluate("i => { const el = document.querySelector('[data-verifier-i=\"' + i + '\"]'); el.focus(); el.click(); }", d["i"])
        focused = pg.evaluate("i => document.activeElement === document.querySelector('[data-verifier-i=\"' + i + '\"]')", d["i"])
        if not focused: bad.append((name, th, w, "disabled-cannot-take-focus", d["ex"]))
    pg.wait_for_timeout(120)
    pg.remove_listener("request", on_request)
    after = (len(sent), pg.evaluate("() => document.querySelectorAll('.sheet.open').length"), pg.evaluate("() => window.__callCount ? window.__callCount() : 0"))
    if after != (base_calls, base_sheets, base_spy) or pg.url != url: bad.append((name, th, w, "disabled-did-something", (base_calls, base_sheets, base_spy), after, pg.url))
    return bad, len(found)


def axe_fails(pg, name, th, w):
    """axe on the console's own document. `iframes: false` is the one narrowing: the framed page is amt-mcp's own viewer page (relayed, in embed mode),
    not a console page, and axe is not injected into it; the frame ELEMENT (its title, its role) is still checked."""
    pg.evaluate((AXE / "axe.min.js").read_text())
    off = {rule: {"enabled": False} for rule in AXE_OFF}
    found = pg.evaluate("""async (rules) => { const r = await axe.run(document, { resultTypes: ['violations'], iframes: false, rules: rules });
      return r.violations.map(v => ({ id: v.id, impact: v.impact, help: v.help, nodes: v.nodes.slice(0, 4).map(n => n.target.join(' ') + ' :: ' + (n.failureSummary || '').split('\\n').slice(0, 3).join(' | ')) })); }""", off)
    return [(name, th, w, "axe", v["id"], v["impact"], v["help"], v["nodes"]) for v in found]


def verify_render(browser, vw, fake_amt, cm, spec, th, w, stats):
    name, path, ready, sheets = spec
    ctx, pg = open_built(browser, vw, name, path, ready, w, th)
    fails = []
    try:
        states = sign_in_states(pg) if name == "signin" else [(None, None)]
        r = None
        for state, apply in states:
            if apply: apply(); pg.wait_for_timeout(60)
            rr = pg.evaluate(cm.JS_WALK)
            if r is None: r = rr
            else: merge(r, rr)
            if state and w in HEAVY:                            # axe sees only the card on screen: each of the five is axe'd while it is the one shown
                fails += axe_fails(pg, f"{name}[{state}]", th, w); stats["axe"] += 1
        bottom, anim = pg.evaluate(cm.JS_BOTTOM), pg.evaluate(cm.JS_ANIMATED)
        nav, tables = pg.evaluate(cm.JS_NAV), pg.evaluate(cm.JS_TABLES)
        stats["tables"] += len(tables["tables"]); stats["rows"] += len(tables["lists"])
        if w in HEAVY:
            if sheets:
                for kind, probe in (("plain", PLAIN), ("force", FORCE)):
                    open_probe(pg, probe)
                    fails += sheet_fails(pg, cm, name, th, w, r, anim, kind)
                    close_probes(pg)
                    stats["sheets"] += 1
            bad, n = disabled_fails(pg, fake_amt, name, th, w)
            fails += bad; stats["disabled"] += n
            if name != "signin":                                # the sign-in page's cards were each axe'd above
                fails += axe_fails(pg, name, th, w); stats["axe"] += 1
            if sheets:                                          # the shortcuts list (key ?) is a sheet with a table: walked, laid out and axe'd like the others
                pg.keyboard.press("?")
                pg.wait_for_selector("#shortcuts-sheet.open"); pg.wait_for_timeout(380)
                fails += sheet_fails(pg, cm, name, th, w, r, anim, "shortcuts", "shortcuts-sheet")
                shown = pg.evaluate(cm.JS_TABLES)
                tables["tables"] += shown["tables"]
                fails += axe_fails(pg, name, th, w); stats["axe"] += 1
                pg.keyboard.press("Escape")
        stats["animated"] += anim["animated"]; stats["targets"] += len(r["targets"])
        nm, nb = cm.name_map(th), cm.name_map(th, for_bg=True)         # immutable 1 and the DOM half of 3, by the mockup run's own functions
        fails += cm.contrast_fails(name, th, w, r, nm, nb) + cm.state_fails(name, th, w, r)
        stats["text"] += len(r["text"]); stats["rings"] += len(r["rings"]); stats["states"] += len(r["states"])
        external = [u for u in pg.requests if re.match(r"(https?|wss?)://", u) and not u.startswith(vw.origin + "/")]
        fails += cm.layout_fails(name, th, w, r, bottom, anim, pg.errors, external, nav, tables, shell=name != "signin")
        if len(r["targets"]) < 1 or not r["text"]: fails.append((name, th, w, "the walk saw nothing", len(r["targets"])))
    finally:
        ctx.close()
    stats["renders"] += 1
    return fails


def reduced_motion_fails(browser, vw, cm, spec, th, stats):
    """Immutable 15: with prefers-reduced-motion: reduce, every data-motion element of the page (an open sheet included) resolves to no animation and 0 s."""
    name, path, ready, sheets = spec
    ctx, pg = open_built(browser, vw, name, path, ready, 1024, th, reduced_motion="reduce")
    bad = []
    try:
        if not pg.evaluate("() => matchMedia('(prefers-reduced-motion: reduce)').matches"): bad.append((name, th, "reduced-motion-not-emulated"))
        if sheets:
            open_probe(pg, PLAIN)
        named = set(json.load(open(cm.TOK))["motion"]["named"])
        got = pg.evaluate(JS_MOTION)
        for m in got:
            if m["name"] not in named: bad.append((name, th, "unnamed-motion", m))
            if m["anim"] != "none" or any(t != "0s" for t in m["trans"]): bad.append((name, th, "motion-not-reduced", m))
        if not got: bad.append((name, th, "no data-motion element on the page: the check would pass on nothing"))
        stats["motion"] += len(got)
        if sheets:
            close_probes(pg)
    finally:
        ctx.close()
    return bad


# ============================== the aggregate: FAILS 0 =======================================================================================

# What each page's probes see nothing of, pinned per page: the run is split by page and theme so the pieces go side by side, and this keeps the
# whole-run vacuity guard (every probe saw something somewhere) as a stricter per-page one: a probe that goes blind on a page fails that page.
PROBE_KEYS = ("tables", "rows", "sheets", "disabled", "axe", "animated", "targets", "motion", "text", "rings", "states")
SEES_NOTHING = {"signin": ("disabled", "rows", "sheets", "states", "tables"), "fleet": ("disabled", "rows", "tables"), "manage": ("rows",),
                "identities": ("states", "tables"), "images": ("rows",), "settings": ("disabled", "states", "tables"), "status": ("disabled", "tables"),
                "power": ("rows", "tables"), "console": ("rows", "tables"), "serial": ("disabled", "rows", "tables"), "media": ("rows",), "logs": ("rows",),
                "inventory": ("disabled", "rows", "tables"), "amt-settings": ("rows", "tables"), "wsman": ("tables",)}
VERIFY_PIECES = [(spec, th) for spec in PAGES for th in THEMES]


def test_every_probe_sees_something_on_some_page():
    """The whole-run guard, kept: no probe is blind on every page."""
    assert [k for k in PROBE_KEYS if all(k in SEES_NOTHING.get(spec[0], ()) for spec in PAGES)] == []


@pytest.mark.parametrize("spec,th", VERIFY_PIECES, ids=[f"{spec[0]}-{th}" for spec, th in VERIFY_PIECES])
def test_the_built_client_passes_the_page_verifier_at_every_width_in_both_themes(browser, vw, fake_amt, spec, th):
    cm = check_mockups()
    stats = dict(renders=0, tables=0, rows=0, sheets=0, disabled=0, axe=0, animated=0, targets=0, motion=0, text=0, rings=0, states=0)
    fails = []
    for w in WIDTHS:
        fails += verify_render(browser, vw, fake_amt, cm, spec, th, w, stats)
    fails += reduced_motion_fails(browser, vw, cm, spec, th, stats)
    print("stats", spec[0], th, json.dumps(stats))
    print("FAILS", len(fails))
    for f in fails[:120]:
        print("  ", f)
    assert len(fails) == 0, f"FAILS {len(fails)}: {fails[:6]}"
    assert stats["renders"] == len(WIDTHS)
    assert sorted(k for k in PROBE_KEYS if stats[k] == 0) == sorted(SEES_NOTHING.get(spec[0], ())), (spec[0], stats)


# ============================== the shared failure builder: each check bites ==================================================================

def clean_render(w=360):
    phone = w < 600
    r = {"scrollWidth": w, "inner": w, "gutter": 16, "currentTab": {"ok": True}, "docHeight": 1000, "narrow": [], "offscreen": [], "fixedOverlap": [],
         "targets": [{"w": 48, "h": 48, "chip": False, "ex": "button"}, {"w": 30, "h": 30, "chip": True, "ex": "a.chip"}]}
    nav = {"rail": not phone, "bar": phone, "inner": w,
           "rows": [{"kind": "chips", "shown": phone, "l": 16, "r": 90}, {"kind": "tabs", "shown": not phone, "l": 16, "r": 90}]}
    tables = {"tables": [{"ex": "table.tbl", "display": "block" if phone else "table", "head": "none" if phone else "table-header-group", "rowDisplay": "flex" if phone else "table-row",
                          "cells": 3, "unlabeled": 0, "scroller": not phone, "right": w - 16, "left": 16}], "lists": [{"ex": "li", "over": 0}]}
    return r, [], {"missing": [], "animated": 1}, nav, tables


def builder(w, mutate=None, errors=(), external=(), shell=False):
    cm = check_mockups()
    r, bottom, anim, nav, tables = clean_render(w)
    if mutate: mutate(r, bottom, anim, nav, tables)
    return [f[3] for f in cm.layout_fails("p", "light", w, r, bottom, anim, errors, external, nav, tables, shell=shell)]


@pytest.mark.parametrize("w", WIDTHS)
def test_a_clean_render_has_no_failure_at_any_width(w):
    assert builder(w) == []


CASES = [  # width, what is broken, the check that must say so
    (360, lambda r, b, a, n, t: r.update(scrollWidth=420), "overflow"),
    (1440, lambda r, b, a, n, t: r.update(scrollWidth=1500), "overflow"),
    (360, lambda r, b, a, n, t: r.update(gutter=12), "gutter"),
    (1024, lambda r, b, a, n, t: r.update(gutter=24), "gutter"),
    (360, lambda r, b, a, n, t: r.update(currentTab={"ok": False}), "current-tab-offscreen"),
    (360, lambda r, b, a, n, t: r.update(docHeight=5201), "page-height"),
    (360, lambda r, b, a, n, t: r["narrow"].append({"ex": "span"}), "letter-wrapped"),
    (360, lambda r, b, a, n, t: r["offscreen"].append({"ex": "button", "l": 300, "r": 400}), "control-offscreen"),
    (360, lambda r, b, a, n, t: r["fixedOverlap"].append({"fixed": "div", "over": "button"}), "fixed-over-control"),
    (360, lambda r, b, a, n, t: b.append("button"), "under-bottom-bar"),
    (360, lambda r, b, a, n, t: a["missing"].append({"ex": "i"}), "animated-without-data-motion"),
    (360, lambda r, b, a, n, t: r["targets"].append({"w": 40, "h": 48, "chip": False, "ex": "button"}), "target"),
    (360, lambda r, b, a, n, t: r["targets"].append({"w": 20, "h": 30, "chip": True, "ex": "a.chip"}), "target"),
    (360, lambda r, b, a, n, t: n.update(bar=False), "navigation"),
    (360, lambda r, b, a, n, t: n.update(rail=True), "navigation"),
    (600, lambda r, b, a, n, t: n.update(bar=True), "navigation"),
    (1024, lambda r, b, a, n, t: n.update(rail=False), "navigation"),
    (360, lambda r, b, a, n, t: n["rows"][0].update(shown=False), "section-row"),
    (1024, lambda r, b, a, n, t: n["rows"][0].update(shown=True), "section-row"),
    (360, lambda r, b, a, n, t: n["rows"][0].update(r=420), "section-row-current-offscreen"),
    (1440, lambda r, b, a, n, t: n["rows"][1].update(l=-30), "section-row-current-offscreen"),
    (360, lambda r, b, a, n, t: t["tables"][0].update(display="table"), "table-not-card-per-row"),
    (360, lambda r, b, a, n, t: t["tables"][0].update(head="table-header-group"), "table-not-card-per-row"),
    (360, lambda r, b, a, n, t: t["tables"][0].update(rowDisplay="table-row"), "table-not-card-per-row"),
    (360, lambda r, b, a, n, t: t["tables"][0].update(unlabeled=1), "table-not-card-per-row"),
    (360, lambda r, b, a, n, t: t["tables"][0].update(right=400), "table-not-card-per-row"),
    (600, lambda r, b, a, n, t: t["tables"][0].update(scroller=False, right=700), "table-not-scrollable"),
    (360, lambda r, b, a, n, t: t["lists"][0].update(over=30), "list-row-overflow"),
]


@pytest.mark.parametrize("w,mutate,expect", CASES, ids=[f"{c[0]}-{c[2]}-{i}" for i, c in enumerate(CASES)])
def test_each_check_of_the_shared_builder_reports_its_break(w, mutate, expect):
    assert expect in builder(w, mutate)


def test_a_shell_page_that_lost_its_navigation_or_its_content_column_fails_and_the_sign_in_page_does_not():
    gone = lambda r, b, a, n, t: n.update(rail=None, bar=None, rows=[])
    no_column = lambda r, b, a, n, t: r.update(gutter=None)
    for w in WIDTHS:
        assert builder(w, gone, shell=True) == ["navigation"]
        assert builder(w, no_column, shell=True) == ["gutter"]
        assert builder(w, gone, shell=False) == [] and builder(w, no_column, shell=False) == []      # the sign-in page has neither, by design
        assert builder(w, shell=True) == []                                                         # a clean shell page is clean


def test_a_console_error_and_a_request_that_left_the_origin_are_failures():
    assert builder(360, errors=["boom"]) == ["console"]
    assert builder(360, external=["https://cdn.example.test/x.js"]) == ["network"]


# ============================== immutable 1 and the DOM half of 3 on the build: the mockup run's own functions ================================

def contrast_state_fails(r, w=1024, th="light"):
    cm = check_mockups()
    return [f[3] for f in cm.contrast_fails("p", th, w, r, cm.name_map(th), cm.name_map(th, for_bg=True)) + cm.state_fails("p", th, w, r)]


def text_node(ratio, large=False, fg="#000000", bg="#ffffff"):
    return {"fg": fg, "bg": bg, "ratio": ratio, "large": large, "ex": "p", "snippet": "x"}


def state_node(attr, value, bg, th="light"):
    return {"attr": attr, "value": value, "bg": bg, "dashed": False, "ex": "span.chip"}


def test_a_clean_walk_has_no_contrast_or_state_failure():
    cm = check_mockups()
    ok = cm.tok("light", "ext.ok.container")
    r = {"text": [text_node(4.5), text_node(3.0, large=True)], "rings": [{"fg": "#000000", "bg": "#ffffff", "ratio": 3.0, "ex": "b"}],
         "states": [state_node("data-pin", "matches", ok), state_node("data-pin", "unchecked", "#ffffff")]}
    assert contrast_state_fails(r) == []


def test_text_below_its_floor_a_ring_below_three_and_a_wrong_state_color_are_each_reported():
    cm = check_mockups()
    err = cm.tok("light", "m3.error_container")
    ring = lambda ratio, fg="#000000": {"fg": fg, "bg": "#ffffff", "ratio": ratio, "ex": "b"}
    assert contrast_state_fails({"text": [text_node(4.49)], "rings": [], "states": []}) == ["contrast-text"]
    assert contrast_state_fails({"text": [text_node(2.99, large=True)], "rings": [], "states": []}) == ["contrast-text"]
    assert contrast_state_fails({"text": [], "rings": [ring(2.99)], "states": []}) == ["contrast-ring"]
    assert contrast_state_fails({"text": [], "rings": [ring(1.2, cm.tok("light", "m3.outline_variant"))], "states": []}) == []     # the decorative hairline
    assert contrast_state_fails({"text": [], "rings": [], "states": [state_node("data-pin", "matches", err)]}) == ["state-color"]
    assert contrast_state_fails({"text": [], "rings": [], "states": [state_node("data-pin", "bogus", err)]}) == ["state-unknown"]
    assert contrast_state_fails({"text": [], "rings": [], "states": [state_node("data-pin", "unchecked", err)]}) == ["state-neutral-hued"]


@pytest.mark.parametrize("th", THEMES)
def test_a_state_attribute_on_a_row_key_is_reported_on_a_real_page(browser, vw, fake_amt, th):
    """The Manage page once put data-pin on its table row as a key: the walk read it as a state chip, and the row paints the surface colour. The
    build's walk reports a planted copy of that, on the real page, so the rename (data-pin-row) cannot be undone unseen."""
    cm = check_mockups()
    name, path, ready, sheets = next(p for p in PAGES if p[0] == "manage")
    ctx, pg = open_built(browser, vw, name, path, ready, 1024, th)
    try:
        before = cm.state_fails(name, th, 1024, pg.evaluate(cm.JS_WALK))
        assert before == []
        pg.evaluate("() => { document.querySelector('tr[data-key]').setAttribute('data-pin', 'matches'); }")
        after = cm.state_fails(name, th, 1024, pg.evaluate(cm.JS_WALK))
        assert [f[3] for f in after] == ["state-color"] and after[0][5] == "matches"
    finally:
        ctx.close()


@pytest.mark.parametrize("th", THEMES)
def test_text_and_a_ring_below_their_floors_are_reported_on_a_real_page(browser, vw, fake_amt, th):
    cm = check_mockups()
    name, path, ready, sheets = next(p for p in PAGES if p[0] == "manage")
    ctx, pg = open_built(browser, vw, name, path, ready, 1024, th)
    try:
        nm, nb = cm.name_map(th), cm.name_map(th, for_bg=True)
        assert cm.contrast_fails(name, th, 1024, pg.evaluate(cm.JS_WALK), nm, nb) == []
        pg.evaluate("""() => { const m = getComputedStyle(document.body).backgroundColor.match(/\\d+/g).map(Number);
          const near = 'rgb(' + m.slice(0, 3).map(v => v > 128 ? v - 30 : v + 30).join(',') + ')';     // 30 steps from the page: far below 4.5:1 and 3:1
          const d = document.createElement('div'); d.textContent = 'planted faint text'; d.style.cssText = 'border:2px solid ' + near + ';color:' + near + ';padding:8px;margin:8px';
          document.body.appendChild(d); }""")
        got = {f[3] for f in cm.contrast_fails(name, th, 1024, pg.evaluate(cm.JS_WALK), nm, nb)}
        assert {"contrast-text", "contrast-ring"} <= got
    finally:
        ctx.close()


def test_the_page_run_asks_the_contrast_and_state_checks_of_every_render(browser, vw, fake_amt):
    """The checks are unit-tested above; this proves verify_render calls them on what it walked and returns what they say."""
    import types
    cm = check_mockups()
    seen = []
    stand_in = types.SimpleNamespace(**vars(cm))
    stand_in.contrast_fails = lambda n, th, w, r, nm, nb, audit=None: seen.append(("contrast", len(r["text"]), len(r["rings"]))) or [(n, th, w, "contrast-sentinel")]
    stand_in.state_fails = lambda n, th, w, r: seen.append(("state", len(r["states"]))) or [(n, th, w, "state-sentinel")]
    spec = next(p for p in PAGES if p[0] == "manage")
    stats = dict(renders=0, tables=0, rows=0, sheets=0, disabled=0, axe=0, animated=0, targets=0, motion=0, text=0, rings=0, states=0)
    got = verify_render(browser, vw, fake_amt, stand_in, spec, "light", 1024, stats)
    assert [f[3] for f in got if f[3].endswith("-sentinel")] == ["contrast-sentinel", "state-sentinel"]
    assert seen[0][1] > 0 and seen[0][2] > 0 and seen[1][1] > 0 and stats["text"] > 0 and stats["rings"] > 0 and stats["states"] > 0


@pytest.mark.parametrize("length,reported", [(32, True), (43, True), (31, False)])
def test_the_mockup_secret_scan_reports_a_token_shaped_string_from_32_characters(tmp_path, length, reported):
    """A viewer token is 32 characters (token_urlsafe(24)), a handoff, upload or intake token 43: the static scan reports both and not a 31-character word."""
    page = tmp_path / "planted.html"
    page.write_text("<html><body><p>" + "Q" * length + "</p><script></script></body></html>")
    found = check_mockups().secret_scan(str(page))
    assert (any(f.startswith("token-shaped string") for f in found)) is reported


def test_the_mockup_scan_reports_a_real_viewer_token_and_every_listed_name_is_still_on_a_mockup():
    import secrets
    cm = check_mockups()
    viewer_token = secrets.token_urlsafe(24)
    assert len(viewer_token) == 32 and cm.token_shaped(f"see /m/{viewer_token}/ now") == [viewer_token]
    assert cm.token_shaped("AMT_SetupAndConfigurationService") == [] and cm.token_shaped("AMT_SetupAndConfigurationServiceX") != []
    pages = "".join(p.read_text() for p in Path(cm.D).glob("*.html"))
    assert [n for n in sorted(cm.NOT_TOKENS) if n not in pages] == []


def test_the_mockup_secret_scan_skips_a_listed_name_and_still_reports_an_unlisted_one(tmp_path):
    """secret_scan goes through token_shaped, so a name on NOT_TOKENS is not reported on a page and a same-length name that is not listed is."""
    cm = check_mockups()
    listed = "--md-sys-color-on-tertiary-container"
    assert len(listed) >= 32 and listed in cm.NOT_TOKENS
    page = tmp_path / "listed.html"
    page.write_text(f"<html><body><p>{listed}</p><script></script></body></html>")
    assert not [f for f in cm.secret_scan(str(page)) if f.startswith("token-shaped string")]
    page.write_text(f"<html><body><p>{listed}x</p><script></script></body></html>")
    assert [f for f in cm.secret_scan(str(page)) if f.startswith("token-shaped string")]


# ============================== the vendored axe-core ========================================================================================

def test_axe_core_is_the_pinned_test_only_file_and_is_never_served_or_shipped(console):
    src = (AXE / "axe.min.js").read_bytes()
    assert hashlib.sha256(src).hexdigest() == AXE_SHA256
    assert src.startswith(b"/*! axe v4.11.4") and b"Mozilla Public" in src[:400]
    assert "Mozilla Public License, version 2.0" in (AXE / "LICENSE").read_text()
    assert console.get("/static/axe.min.js").status == 404 and console.get("/static/vendor/axe-core/axe.min.js").status == 404
    assert not list((CONSOLE / "static").rglob("axe*"))
    docker = (CONSOLE / "Dockerfile").read_text()
    assert "axe" not in docker and "tests" not in docker                    # the image copies the modules, pages and static files, never a test file


def test_every_axe_rule_turned_off_names_its_reason_and_color_contrast_is_never_off():
    assert all(isinstance(why, str) and len(why) > 20 for why in AXE_OFF.values())
    assert "color-contrast" not in AXE_OFF


def test_axe_reports_a_planted_violation_on_a_real_page(browser, vw):
    ctx, pg = open_built(browser, vw, "fleet", "/", ".scard .pill", 1024, "light")
    try:
        assert axe_fails(pg, "fleet", "light", 1024) == []
        pg.evaluate("() => { document.querySelector('.content').appendChild(document.createElement('button')); }")      # a control with no accessible name
        assert [f[4] for f in axe_fails(pg, "fleet", "light", 1024)] == ["button-name"]
    finally:
        ctx.close()


# ============================== the probes bite on a planted break ===========================================================================

def test_the_hit_area_and_disabled_probes_report_a_planted_control(browser, vw, fake_amt):
    cm = check_mockups()
    ctx, pg = open_built(browser, vw, "fleet", "/", ".scard .pill", 360, "light")
    try:
        pg.evaluate("""() => { const c = document.querySelector('.content');
          const small = document.createElement('button'); small.textContent = 'x'; small.id = 'planted-small'; small.style.width = '20px'; small.style.height = '20px'; c.appendChild(small);
          const dis = document.createElement('button'); dis.textContent = 'dead'; dis.setAttribute('aria-disabled', 'true'); dis.tabIndex = -1; c.appendChild(dis);
          const live = document.createElement('button'); live.textContent = 'live'; live.setAttribute('aria-disabled', 'true'); c.appendChild(live);
          live.addEventListener('click', () => window.amtc.openWrite({ title: 't', verb: 'v', consequence: 'c', call: { tool: 'amt_power', arguments: { device: 'x', action: 'restart' } } })); }""")
        r = pg.evaluate(cm.JS_WALK)
        got = [f[3] for f in cm.layout_fails("fleet", "light", 360, r, [], {"missing": [], "animated": 1}, [], [])]
        assert "target" in got
        bad, n = disabled_fails(pg, fake_amt, "fleet", "light", 360)
        kinds = sorted({f[3] for f in bad})
        assert n >= 2 and "disabled-not-focusable" in kinds and "disabled-without-reason" in kinds
        assert "disabled-outline-faded" not in kinds and "disabled-did-something" not in kinds      # the console's own click guard held the planted control still
    finally:
        ctx.close()


def test_a_disabled_button_with_a_faded_outline_is_reported(browser, vw, fake_amt):
    ctx, pg = open_built(browser, vw, "fleet", "/", ".scard .pill", 360, "light")
    try:
        pg.evaluate("""() => { const box = document.createElement('div'); box.className = 'btn-wrap'; document.querySelector('.content').appendChild(box);
          const b = document.createElement('button'); b.className = 'btn tonal'; b.textContent = 'faded'; b.setAttribute('aria-disabled', 'true'); b.style.opacity = '0.38'; box.appendChild(b);
          const why = document.createElement('span'); why.className = 'reason'; why.textContent = 'planted'; box.appendChild(why); }""")
        kinds = {f[3] for f in disabled_fails(pg, fake_amt, "fleet", "light", 360)[0]}
        assert kinds == {"disabled-outline-faded"}
    finally:
        ctx.close()


def test_a_disabled_control_that_sends_a_request_is_reported_and_a_background_read_is_not(browser, vw, fake_amt):
    """The request half of "ignore activation": a planted disabled control whose capture listener POSTs is named; the page's own GET polls,
    which run on their own clock, are not counted as something the click did."""
    ctx, pg = open_built(browser, vw, "fleet", "/", ".scard .pill", 360, "light")
    try:
        pg.evaluate("""() => { const c = document.querySelector('.content');
          const b = document.createElement('button'); b.className = 'btn tonal'; b.textContent = 'leaky'; b.setAttribute('aria-disabled', 'true'); b.id = 'planted-post'; c.appendChild(b);
          const why = document.createElement('span'); why.className = 'reason'; why.textContent = 'planted'; b.after(why);
          window.addEventListener('click', (e) => { if (e.target === b) { fetch('/api/fleet'); fetch('/api/call', { method: 'POST', body: '{}' }); } }, true); }""")
        bad, n = disabled_fails(pg, fake_amt, "fleet", "light", 360)
        did = [f for f in bad if f[3] == "disabled-did-something"]
        assert n >= 1 and did and did[0][5][0] == 1, bad                       # one request counted: the POST, not the GET beside it
    finally:
        ctx.close()


def test_a_disabled_control_that_does_something_despite_the_click_guard_is_reported(browser, vw, fake_amt):
    """The positive control of the "ignore activation" half of immutable 18: the aggregate cannot show this branch firing (the console's guard and its
    per-control handlers both hold), so a planted control whose handler runs before the guard (a capture listener on window) opens a sheet, and
    the check must name it."""
    ctx, pg = open_built(browser, vw, "fleet", "/", ".scard .pill", 360, "light")
    try:
        pg.evaluate("""() => { const c = document.querySelector('.content');
          const b = document.createElement('button'); b.className = 'btn tonal'; b.textContent = 'leaky'; b.setAttribute('aria-disabled', 'true'); b.id = 'planted-leaky'; c.appendChild(b);
          const why = document.createElement('span'); why.className = 'reason'; why.textContent = 'planted'; b.after(why);
          window.addEventListener('click', (e) => { if (e.target === b) window.amtc.openWrite({ title: 't', verb: 'v', consequence: 'c', call: { tool: 'amt_power', arguments: { device: 'x', action: 'restart' } } }); }, true); }""")
        bad, n = disabled_fails(pg, fake_amt, "fleet", "light", 360)
        assert n >= 1 and "disabled-did-something" in {f[3] for f in bad}, bad
    finally:
        ctx.close()


# ============================== immutable 15: the force hold keeps its 1200 ms and counts down ==============================================

def test_under_reduced_motion_the_force_hold_keeps_1200_ms_with_a_countdown_and_no_bar(browser, vw):
    ctx, pg = open_built(browser, vw, "fleet", "/", ".scard .pill", 1024, "light", reduced_motion="reduce")
    try:
        open_probe(pg, FORCE)
        k = pg.query_selector(".sheet.open .force-control[data-hold]"); b = k.bounding_box(); cx, cy = b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
        base = pg.evaluate("() => window.__forceFireCount()")
        pg.mouse.move(cx, cy); pg.mouse.down(); pg.wait_for_timeout(600)
        held = pg.evaluate("""() => { const k = document.querySelector('.sheet.open .force-control'); const f = k.querySelector('.fill'), n = k.querySelector('.count');
          return { count: getComputedStyle(n).display, text: n.textContent, anim: getComputedStyle(f).animationName, fillW: f.getBoundingClientRect().width, holding: k.classList.contains('holding') }; }""")
        pg.mouse.up(); pg.wait_for_timeout(60)
        assert held["holding"] and held["count"] != "none" and held["text"] in ("3", "2", "1") and held["anim"] == "none" and held["fillW"] == 0
        assert pg.evaluate("() => window.__forceFireCount()") == base                                 # 600 ms of a 1200 ms hold fires nothing
        open_probe(pg, FORCE)
        pg.mouse.move(cx, cy); pg.mouse.down(); pg.wait_for_timeout(1400); pg.mouse.up(); pg.wait_for_timeout(100)
        assert pg.evaluate("() => window.__forceFireCount()") == base + 1                              # the full hold still fires, once
    finally:
        ctx.close()


# ============================== immutable 13: the three layouts by width =====================================================================

def test_the_cards_go_one_two_and_three_up_and_the_console_keeps_its_side_panel_from_1440(browser, vw):
    cols = {}
    for w in WIDTHS:
        ctx, pg = open_built(browser, vw, "status", f"/server/{KEY}", "#srv-pill .pill", w, "light")
        try:
            cols[w] = pg.evaluate("() => getComputedStyle(document.querySelector('.content .grid')).gridTemplateColumns.split(' ').length")
        finally:
            ctx.close()
    assert cols == {360: 1, 600: 1, 1024: 2, 1440: 3}, cols
    side = {}
    for w in (1024, 1440):
        ctx, pg = open_built(browser, vw, "console", f"/server/{KEY}/console", "#kvm-screen iframe", w, "light")
        try:
            side[w] = pg.evaluate("() => getComputedStyle(document.querySelector('.content.split')).gridTemplateColumns.split(' ').length")
        finally:
            ctx.close()
    assert side == {1024: 1, 1440: 2}, side


def test_a_wide_table_scrolls_inside_its_wrapper_on_the_tablet_and_the_page_does_not(browser, vw):
    ctx, pg = open_built(browser, vw, "logs", f"/server/{KEY}/logs", "#log-counts:not(:empty), #log-state .result", 600, "light")
    try:
        info = pg.evaluate("""() => { const w = document.querySelector('.tbl-wrap'); return { overflow: getComputedStyle(w).overflowX, scroll: w.scrollWidth, client: w.clientWidth, page: document.scrollingElement.scrollWidth, inner: innerWidth }; }""")
        assert info["overflow"] == "auto" and info["scroll"] > info["client"] and info["page"] <= info["inner"], info
    finally:
        ctx.close()


def test_the_section_row_scrolls_so_the_current_chip_is_in_view_on_the_phone(browser, vw):
    ctx, pg = open_built(browser, vw, "wsman", f"/server/{KEY}/wsman", "#ws-templates li", 360, "light")
    try:
        info = pg.evaluate("""() => { const n = document.querySelector('.chips-scroll'), c = n.querySelector('[aria-current="page"]'), r = c.getBoundingClientRect();
          return { scrolled: n.scrollLeft, overflows: n.scrollWidth > n.clientWidth, l: r.left, r: r.right, w: innerWidth }; }""")
        assert info["overflows"] and info["scrolled"] > 0 and info["l"] >= 0 and info["r"] <= info["w"], info    # the last section: it is scrolled into view, not left off screen
    finally:
        ctx.close()


# ============================== the keyboard shortcuts (design note 5.5) =====================================================================

def goes(pg, keys, to):
    with pg.expect_navigation():
        for k in keys:
            pg.keyboard.press(k)
    assert pg.url.endswith(to), pg.url


def stays(pg, keys, wait=350):
    here = pg.url
    for k in keys:
        pg.keyboard.press(k)
    pg.wait_for_timeout(wait)
    assert pg.url == here, pg.url


def test_g_then_a_letter_opens_fleet_manage_and_the_console_and_power_of_the_server_you_are_on(browser, vw):
    for keys, to in ((["g", "f"], "/"), (["g", "m"], "/manage"), (["g", "c"], f"/server/{KEY}/console"), (["g", "p"], f"/server/{KEY}/power")):
        ctx, pg = open_built(browser, vw, "status", f"/server/{KEY}", "#srv-pill .pill", 1024, "light")
        try:
            goes(pg, keys, to)
        finally:
            ctx.close()


def test_g_c_and_g_p_do_nothing_off_a_server_page_and_an_unknown_second_key_does_nothing(browser, vw):
    ctx, pg = open_built(browser, vw, "fleet", "/", ".scard .pill", 1024, "light")
    try:
        stays(pg, ["g", "c"]); stays(pg, ["g", "p"]); stays(pg, ["g", "z"])
        stays(pg, ["g"], 1700); stays(pg, ["m"])                        # the pair lapses after 1.5 s: an m later is nothing
    finally:
        ctx.close()


def test_every_shortcut_has_an_on_screen_control_that_goes_to_the_same_place(browser, vw):
    ctx, pg = open_built(browser, vw, "status", f"/server/{KEY}", "#srv-pill .pill", 1024, "light")
    try:
        for href in ("/", "/manage"):
            assert pg.is_visible(f'.navrail a[href="{href}"]')
        for tab in ("console", "power"):
            assert pg.is_visible(f'.srvhead .tabs a[href="/server/{KEY}/{tab}"]')
    finally:
        ctx.close()
    ctx, pg = open_built(browser, vw, "fleet", "/", ".scard .pill", 360, "light")
    try:
        for href in ("/", "/manage"):
            assert pg.is_visible(f'.bottomnav a[href="{href}"]')
        assert pg.evaluate("() => document.querySelector('#q').matches('[data-shortcut-filter]')") and pg.is_visible("#q")
    finally:
        ctx.close()
    ctx, pg = open_built(browser, vw, "settings", "/settings", "#passkey-list li", 360, "light")
    try:
        assert pg.is_visible("[data-shortcuts-list]") and pg.is_visible("[data-pref-shortcuts]")
    finally:
        ctx.close()


def test_slash_focuses_the_filter_and_question_mark_opens_the_list_that_escape_closes(browser, vw):
    ctx, pg = open_built(browser, vw, "fleet", "/", ".scard .pill", 1024, "light")
    try:
        pg.keyboard.press("/")
        assert pg.evaluate("() => document.activeElement.id") == "q" and pg.input_value("#q") == ""      # focused, and the slash itself was not typed
        pg.evaluate("() => document.activeElement.blur()")
        pg.keyboard.press("?")
        pg.wait_for_selector("#shortcuts-sheet.open")
        info = pg.evaluate("""() => { const s = document.getElementById('shortcuts-sheet'); return { role: s.getAttribute('role'), modal: s.getAttribute('aria-modal'),
          title: document.getElementById(s.getAttribute('aria-labelledby')).textContent, focus: document.activeElement.hasAttribute('data-close'),
          keys: Array.from(s.querySelectorAll('tbody th')).map(t => t.textContent), ths: s.querySelectorAll('th[scope]').length }; }""")
        assert info["role"] == "dialog" and info["modal"] == "true" and info["title"] == "Keyboard shortcuts" and info["focus"]
        assert info["keys"] == ["g f", "g m", "g c", "g p", "/", "?", "Esc"] and info["ths"] >= 10
        pg.keyboard.press("Escape")
        assert pg.evaluate("() => !!document.querySelector('.sheet.open')") is False
    finally:
        ctx.close()


def test_no_shortcut_fires_while_typing_in_a_field_with_a_modifier_with_a_sheet_open_or_in_the_embedded_viewer(browser, vw):
    ctx, pg = open_built(browser, vw, "fleet", "/", ".scard .pill", 1024, "light")
    try:
        pg.click("#q"); stays(pg, ["g", "f", "g", "m", "/", "?"])
        assert pg.input_value("#q") == "gfgm/?"                                                                 # every key was typed into the field
        pg.evaluate("() => document.activeElement.blur()")
        stays(pg, ["Control+g", "m"]); stays(pg, ["Meta+g", "m"]); stays(pg, ["Alt+g", "m"])
        pg.keyboard.press("?"); pg.wait_for_selector("#shortcuts-sheet.open")
        stays(pg, ["g", "m"])                                                                                    # a sheet is open: the keys are the sheet's
        pg.keyboard.press("Escape")
        stays(pg, ["m"])                                                                                         # and the sheet's g left no half pair behind
    finally:
        ctx.close()
    ctx, pg = open_built(browser, vw, "console", f"/server/{KEY}/console", "#kvm-screen iframe", 1024, "light")
    try:
        pg.evaluate("() => { const f = document.querySelector('#kvm-screen iframe'); f.inert = false; f.focus(); }")      # the scripted agent holds the frame inert: release it
        assert pg.evaluate("() => document.activeElement.tagName") == "IFRAME"
        here = pg.url
        pg.evaluate("() => ['g', 'f'].forEach(k => document.dispatchEvent(new KeyboardEvent('keydown', { key: k, bubbles: true })))")
        pg.wait_for_timeout(350)
        assert pg.url == here
    finally:
        ctx.close()


def test_the_shortcuts_switch_in_settings_turns_them_off_for_this_browser_and_the_list_button_still_works(browser, vw):
    ctx, pg = open_built(browser, vw, "settings", "/settings", "#passkey-list li", 1024, "light")
    try:
        assert pg.get_attribute("[data-pref-shortcuts]", "aria-checked") == "true"
        pg.click("[data-pref-shortcuts]")
        assert pg.get_attribute("[data-pref-shortcuts]", "aria-checked") == "false"
        assert pg.evaluate("() => localStorage.getItem('amt-console-shortcuts')") == "off"
        stays(pg, ["g", "f"])
        pg.reload(); pg.wait_for_selector("#passkey-list li")
        assert pg.get_attribute("[data-pref-shortcuts]", "aria-checked") == "false"                              # held across a reload
        stays(pg, ["g", "m"]); stays(pg, ["?"])
        assert pg.evaluate("() => !!document.getElementById('shortcuts-sheet')") is False
        pg.click("[data-shortcuts-list]"); pg.wait_for_selector("#shortcuts-sheet.open")                         # its on-screen control works while they are off
        pg.keyboard.press("Escape")
        pg.focus("[data-pref-shortcuts]"); pg.keyboard.press("Space")
        assert pg.get_attribute("[data-pref-shortcuts]", "aria-checked") == "true"
        goes(pg, ["g", "f"], "/")
    finally:
        ctx.close()


def test_with_browser_storage_blocked_the_switch_still_turns_the_shortcuts_off_for_this_page(browser, vw):
    ctx, pg = open_built(browser, vw, "settings", "/settings", "#passkey-list li", 1024, "light")
    try:
        pg.evaluate("""() => { const no = () => { throw new DOMException('blocked', 'SecurityError'); }; Storage.prototype.getItem = no; Storage.prototype.setItem = no; }""")
        pg.click("[data-pref-shortcuts]")
        assert pg.get_attribute("[data-pref-shortcuts]", "aria-checked") == "false"
        stays(pg, ["g", "f"])                                                                                    # what the switch shows is what the keys do
        pg.focus("[data-pref-shortcuts]"); pg.keyboard.press("Space")
        assert pg.get_attribute("[data-pref-shortcuts]", "aria-checked") == "true"
        goes(pg, ["g", "f"], "/")
    finally:
        ctx.close()


# ============================== immutable 23: the mockups still pass their own verifier ======================================================

MOCKUPS = sorted(f.name for f in (CONSOLE.parent / "design").glob("*.html"))
FORCE_CONTROLS = {"console.html": 1, "identities.html": 1, "media.html": 2, "power-boot.html": 8, "serial.html": 1, "servers.html": 2, "wsman.html": 1}
STILL = {"sign-in.html", "swatches.html"}          # the two mockups with no animated element; every other one must show motion to the motion check
# One mockup's run split so the pieces go side by side (check_mockups.py --part): `base` is everything but the force matrices, and each force
# control is one piece per width. Together they are the whole run of that mockup.
PARTS = [(m, "base") for m in MOCKUPS] + [(m, f"force:{w}:{i}") for m, n in sorted(FORCE_CONTROLS.items()) for i in range(n) for w in (1024, 360)]


def run_mockup_check(*args):
    design = CONSOLE.parent / "design"
    done = subprocess.run([sys.executable, str(design / "check_mockups.py"), *args], capture_output=True, text=True, timeout=1200,
                          env=dict(__import__("os").environ, PYTHONDONTWRITEBYTECODE="1"))
    tail = "\n".join(done.stdout.splitlines()[-12:])
    print(tail)
    assert done.returncode == 0 and re.search(r"^FAILS 0$", done.stdout, re.M), tail + done.stderr[-500:]
    return done.stdout, tail


def test_the_mockup_run_covers_all_sixteen_mockups():
    assert len(MOCKUPS) == 16                                                         # a new or lost mockup is a deliberate change to this list
    assert set(FORCE_CONTROLS) <= set(MOCKUPS) and STILL <= set(MOCKUPS)


@pytest.mark.parametrize("mockup,part", PARTS, ids=[f"{m}-{p}" for m, p in PARTS])
def test_each_mockup_passes_the_mockup_verifier_with_fails_0(mockup, part):
    """The script the built-client run shares its failure builder with, one mockup piece per test so they run side by side: both themes at four
    widths, the confirm sheets, the call and secret scans and the positive controls in `base`, and one force matrix per force piece. A change to the
    shared code that stopped the mockup run looking would show here, not in a hand run."""
    out, tail = run_mockup_check("--part", part, mockup)
    if part == "base":
        assert "SKIPPED" not in out                                                  # the macro-grid schema check ran against the live schema
        assert re.search(r"stats \{'renders': 8,", out), tail                        # 2 themes x 4 widths: it walked this mockup whole
        assert re.search(rf"^{re.escape(mockup)} force controls: {FORCE_CONTROLS.get(mockup, 0)}$", out, re.M), tail   # every force control has its pieces
        animated = int(re.search(r"'animated': (\d+)", out).group(1))
        assert (animated == 0) == (mockup in STILL), animated                         # the motion check saw motion wherever the mockup has it
    else:
        assert re.search(r"'force_controls': 1,", out), tail                          # the one matrix ran


def test_a_force_piece_past_the_last_control_fails():
    """The split's own positive control: a force index the page does not have is a failure, never a vacuous pass."""
    design = CONSOLE.parent / "design"
    done = subprocess.run([sys.executable, str(design / "check_mockups.py"), "--part", "force:1024:9", "wsman.html"], capture_output=True, text=True,
                          timeout=300, env=dict(__import__("os").environ, PYTHONDONTWRITEBYTECODE="1"))
    assert done.returncode == 1 and "no such force control" in done.stdout
