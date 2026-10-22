#!/usr/bin/env python3
"""amt-console mockup verifier: the runnable half of the Design Immutables, first subject design/*.html.

For every page x theme x width (360, 600, 1024, 1440): console errors, network requests, horizontal overflow, the
16 px gutter, the DOM contrast walk (effective background composited up the ancestor chain; borders and outlines
against the parent's background), the state-color walk over [data-power], [data-pin] and [data-session], hit
areas, every interactive control inside the viewport at 360, the current section chip inside the viewport, the
phone text-box and page-height checks, fixed elements never over a control, and the color-literal extractor.
Per page: reduced motion (every animated element carries data-motion and resolves to none), prefers-color-scheme
following and override persistence, the force matrix on EVERY force control (pointer and keyboard, including
click-wait-click and tap-wait-tap, the opener's point never over the confirm, both at 1024 and 360), the holding
state's contrast, every plain confirm sheet (one call per activation, focus inside the sheet on open), the
outside-sheet click sweep (0 calls), the argument-computed destructiveness predicate and the call spy (every
destructive call was preceded by a force fire), the device / confirmed call scan, the secret-field scan, the
no-token scan, and the macro grid validated against the live amt_console_input schema. Merges audit pairs into
tokens.json `pairs` with --merge.

Run: python3 check_mockups.py [--merge] [--part base|force:<width>:<index>] [page.html ...]
--part splits one page's run so the pieces can run side by side: `base` is everything but the force matrices (it prints how many force controls
the page has), `force:<width>:<index>` is the one force matrix at that width. No --part is the whole run, as before.
Needs: playwright with chromium, jsonschema (design/requirements.txt); the schema check imports amt_server from
the repo root and is reported as skipped when it cannot.
"""
from __future__ import annotations
import json, os, re, sys
from playwright.sync_api import sync_playwright

D = os.path.dirname(os.path.abspath(__file__))
TOK = os.path.join(D, "tokens.json")
WIDTHS = [360, 600, 1024, 1440]
THEMES = ["light", "dark"]
PHONE_HEIGHT_CEILING = {360: 5200, 600: 5200}   # px, fixture renders only (mockups, the verifier's scripted host): a regression tripwire, never
# compared to a live host, whose height is its data. Re-derived as the fixture's measured height + 10 %, rounded up to 100, when a fixture is
# deliberately enlarged (designer ruling 2026-10-22; the live heights and the rule are in docs/ux-design-2026-10-20.md, Phone).
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{32,}")       # the shape of a viewer token (32, secrets.token_urlsafe(24)) or a handoff / upload / intake token (43, token_urlsafe(32))

# Names that are 32 or more url-safe characters and are not tokens: a CSS custom property of the swatch sheet and an AMT class name. Exact strings,
# each a name the pages print on purpose; a new long name fails the scan until it is listed here, which is the point.
NOT_TOKENS = frozenset({
    "AMT_SetupAndConfigurationService", "--md-sys-color-on-error-container", "--md-sys-color-tertiary-container",
    "--md-sys-color-on-tertiary-container", "--md-sys-color-primary-container", "--md-sys-color-on-primary-container"})


def token_shaped(text):
    """The token-shaped strings of `text`, in order: 32 or more url-safe characters that are not a listed name."""
    return [m.group(0) for m in TOKEN_RE.finditer(text) if m.group(0) not in NOT_TOKENS]


tokens = json.load(open(TOK))


def name_map(theme, for_bg=False):
    m = {}
    m[tokens[theme]["m3"]["outline_variant"].lower()] = "m3.outline_variant"
    items = [(f"m3.{k}", v) for k, v in tokens[theme]["m3"].items()]
    items += [(f"ext.{r}.{k}", v) for r, d in tokens[theme]["ext"].items() for k, v in d.items() if isinstance(v, str) and v.startswith("#")]
    def pref(name):
        is_surface = "surface" in name or "container" in name or name.endswith(".fill")
        is_on = ".on_" in name or name.endswith("on_color")
        return (0 if (is_surface if for_bg else not is_surface and not (for_bg)) else 1, 0 if (not is_on if for_bg else is_on) else 1, name)
    for name, v in sorted(items, key=lambda nv: pref(nv[0])):
        m.setdefault(v.lower(), name)
    return m


def tok(theme, ref):
    tier, *rest = ref.split("."); node = tokens[theme][tier]
    for r in rest: node = node[r]
    return node.lower()


ALLOWED_LITERALS = set()
for th in THEMES:
    ALLOWED_LITERALS.update(v.lower() for v in tokens[th]["m3"].values())
    for d in tokens[th]["ext"].values():
        ALLOWED_LITERALS.update(v.lower() for v in d.values() if isinstance(v, str) and v.startswith("#"))
ALLOWED_LITERALS.update(v.lower() for k, v in tokens["overlay"].items() if k != "note")
LIT_RE = re.compile(r"#[0-9a-fA-F]{3,8}\b|rgba?\([^)]*\)|hsla?\([^)]*\)|color-mix\((?:[^()]|\([^()]*\))*\)")

# immutable 3: the state attribute -> the token its background must be (dashed states: the neutral surface + a dashed outline ring)
STATE_BG = {
    "data-power": {"on": "ext.ok.container", "sleep": "m3.tertiary_container", "hibernate": "m3.tertiary_container", "off": "m3.surface_container_highest",
                   "unknown": "m3.surface_container_highest", "unreachable": "m3.error_container"},
    "data-pin": {"matches": "ext.ok.container", "mismatch": "m3.error_container", "differs": "m3.error_container", "unpinned": "m3.error_container", "unchecked": None},
    "data-session": {"held_console": "ext.live.container", "held_agent": "ext.live.container", "ider": "ext.live.container", "recording": "ext.live.container",
                     "controlling": "ext.live.container", "consent_pending": "ext.live.container", "unmount_held": "ext.live.container",
                     "held_other": "m3.error_container", "paused": "m3.error_container", "agent_typing": "m3.surface_container_highest",
                     "sol_free": None, "unknown": None},
}
# immutable 6: tools whose `device` is optional or absent; write tools and the actions that need no confirmed
NO_DEVICE = {"amt_images", "amt_devices", "amt_identities", "amt_identity_manage", "amt_captures"}
READ_TOOLS = {"amt_status", "amt_screenshot", "amt_inventory", "amt_logs", "amt_settings", "amt_wsman_get", "amt_devices", "amt_identities", "amt_captures"}
UNCONFIRMED_ACTIONS = {"amt_mirror_link": {"stop", "status", "record_stop"}, "amt_serial_link": {"stop", "status", "record_stop"}, "amt_ider": {"status"}, "amt_images": {"list", "verify"}}


def literal_check(path):
    text = open(path).read()
    return sorted({m.group(0).lower() for m in LIT_RE.finditer(text) if m.group(0).lower() not in ALLOWED_LITERALS})


JS_HELPERS = r"""
  const toRGBA = (s) => { const m = s.match(/rgba?\(([^)]+)\)/); if (!m) return null; const p = m[1].split(',').map(x => parseFloat(x)); return [p[0], p[1], p[2], p.length > 3 ? p[3] : 1]; };
  const lum = (c) => { const f = (v) => { v /= 255; return v <= 0.03928 ? v / 12.92 : Math.pow((v + 0.055) / 1.055, 2.4); }; return 0.2126 * f(c[0]) + 0.7152 * f(c[1]) + 0.0722 * f(c[2]); };
  const ratio = (a, b) => { const l1 = lum(a), l2 = lum(b); return (Math.max(l1, l2) + 0.05) / (Math.min(l1, l2) + 0.05); };
  const over = (top, under) => { const a = top[3]; return [top[0] * a + under[0] * (1 - a), top[1] * a + under[1] * (1 - a), top[2] * a + under[2] * (1 - a), 1]; };
  const hex = (c) => '#' + [0, 1, 2].map(i => Math.round(c[i]).toString(16).padStart(2, '0')).join('');
  const visible = (el) => { const cs = getComputedStyle(el); if (cs.display === 'none' || cs.visibility === 'hidden' || parseFloat(cs.opacity) === 0) return false; const r = el.getBoundingClientRect(); return r.width > 0 && r.height > 0; };
  const inMock = (el) => !!el.closest('.mock-bar');
  const disabled = (el) => !!el.closest('[aria-disabled="true"]');
  const effBg = (el) => {
    let acc = null; let node = el;
    while (node && node !== document.documentElement.parentNode) {
      const cs = getComputedStyle(node); const bg = toRGBA(cs.backgroundColor);
      if (bg && bg[3] > 0) { acc = acc ? over(acc, bg) : (bg[3] >= 1 ? bg : null); if (acc && acc[3] >= 1) return acc; if (!acc) acc = bg; }
      node = node.parentElement;
    }
    const body = toRGBA(getComputedStyle(document.body).backgroundColor);
    return acc ? over(acc, body) : body;
  };
  const effFg = (el, color) => { const c = toRGBA(color); if (!c) return null; if (c[3] >= 1) return c; return over(c, effBg(el)); };
  const cls = (el) => el.tagName.toLowerCase() + (el.className && typeof el.className === 'string' ? '.' + el.className.trim().split(/\s+/).join('.') : '');
"""

JS_WALK = "() => {" + JS_HELPERS + r"""
  const out = { text: [], rings: [], targets: [], motion: [], states: [], narrow: [], offscreen: [] };
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  let n;
  while ((n = walker.nextNode())) {
    const t = n.textContent.replace(/\s+/g, ''); if (!t) continue;
    const el = n.parentElement; if (!el || inMock(el) || disabled(el) || !visible(el)) continue;
    if (el.closest('script, style, title, .vh')) continue;
    const cs = getComputedStyle(el); const fg = effFg(el, cs.color); const bg = effBg(el);
    if (!fg) continue;
    const size = parseFloat(cs.fontSize), weight = parseInt(cs.fontWeight, 10) || 400;
    const large = size >= 24 || (size >= 18.66 && weight >= 700);
    out.text.push({ fg: hex(fg), bg: hex(bg), ratio: Math.round(ratio(fg, bg) * 100) / 100, large, size, weight, ex: cls(el), snippet: t.slice(0, 24) });
    // M1: a text box narrower than 100 px whose line count exceeds its word count (words broken) or runs past six lines (a squeezed column)
    const rg = document.createRange(); rg.selectNodeContents(n); const r = rg.getBoundingClientRect(); const lh = parseFloat(cs.lineHeight) || size * 1.4; const words = n.textContent.trim().split(/\s+/).length; const lines = r.height / lh;
    if (n.textContent.trim().length >= 12 && r.width < 100 && (lines > words + 1.2 || lines > 6)) out.narrow.push({ ex: cls(el), w: Math.round(r.width), h: Math.round(r.height), words, snippet: t.slice(0, 24) });
  }
  document.querySelectorAll('body *').forEach(el => {
    if (inMock(el) || disabled(el) || !visible(el)) return;
    const cs = getComputedStyle(el);
    const parentBg = el.parentElement ? effBg(el.parentElement) : effBg(el);
    ['Top', 'Right', 'Bottom', 'Left'].forEach(side => {
      const w = parseFloat(cs['border' + side + 'Width']); const st = cs['border' + side + 'Style'];
      if (w > 0 && st !== 'none') { const c = toRGBA(cs['border' + side + 'Color']); if (c && c[3] > 0) { const fg = c[3] >= 1 ? c : over(c, parentBg);
        out.rings.push({ fg: hex(fg), bg: hex(parentBg), ratio: Math.round(ratio(fg, parentBg) * 100) / 100, ex: cls(el), kind: 'border' }); } }
    });
    if (cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0) { const c = toRGBA(cs.outlineColor); if (c && c[3] > 0) out.rings.push({ fg: hex(c), bg: hex(parentBg), ratio: Math.round(ratio(c, parentBg) * 100) / 100, ex: el.tagName.toLowerCase(), kind: 'outline' }); }
  });
  // hit targets (inline links are measured with their ::after extension, never skipped)
  document.querySelectorAll('button, a[href], [role=button], [role=switch], [role=checkbox], [role=radio], input, select, textarea, summary, [tabindex="0"]').forEach(el => {
    if (inMock(el) || !visible(el)) return;
    const r = el.getBoundingClientRect(); let w = r.width, h = r.height;
    const a = getComputedStyle(el, '::after');
    if (a && a.content !== 'none' && a.position === 'absolute') { const top = parseFloat(a.top) || 0, bot = parseFloat(a.bottom) || 0, l = parseFloat(a.left) || 0, rr = parseFloat(a.right) || 0; h += Math.max(0, -top) + Math.max(0, -bot); w += Math.max(0, -l) + Math.max(0, -rr); }
    const chip = el.classList.contains('chip') || el.closest('.seg') || el.closest('.tabs') || el.closest('.chips-scroll');
    out.targets.push({ w: Math.round(w), h: Math.round(h), chip: !!chip, ex: cls(el) + (el.getAttribute('aria-label') ? '[' + el.getAttribute('aria-label') + ']' : '') });
    // M3: every control is inside the viewport horizontally (the section chip row is a scroller; its current chip is checked separately)
    if (!el.closest('.sheet') && !el.closest('.tabs') && !el.closest('.chips-scroll') && (r.left < -1 || r.right > window.innerWidth + 1)) out.offscreen.push({ ex: cls(el), l: Math.round(r.left), r: Math.round(r.right) });
  });
  document.querySelectorAll('[data-motion]').forEach(el => { const cs = getComputedStyle(el); out.motion.push({ name: el.getAttribute('data-motion'), anim: cs.animationName, trans: cs.transitionDuration }); });
  // immutable 3: the state-bearing pills, chips, strips and results
  ['data-power', 'data-pin', 'data-session'].forEach(attr => document.querySelectorAll('[' + attr + ']').forEach(el => {
    if (inMock(el) || !visible(el)) return; const cs = getComputedStyle(el);
    out.states.push({ attr, value: el.getAttribute(attr), bg: hex(effBg(el)), dashed: cs.borderTopStyle === 'dashed', ex: cls(el) });
  }));
  out.scrollWidth = document.scrollingElement.scrollWidth; out.inner = window.innerWidth; out.docHeight = document.scrollingElement.scrollHeight;
  const c = document.querySelector('.content, .product.auth'); out.gutter = c ? Math.round(c.getBoundingClientRect().left + parseFloat(getComputedStyle(c).paddingLeft) - (document.querySelector('.navrail') && getComputedStyle(document.querySelector('.navrail')).display !== 'none' ? document.querySelector('.navrail').getBoundingClientRect().right : 0)) : null;
  // M4: the current section chip is inside the viewport
  const cur = document.querySelector('.tabs [aria-current="page"], .chips-scroll [aria-current="page"]');
  out.currentTab = cur ? (() => { const r = cur.getBoundingClientRect(); return { l: Math.round(r.left), r: Math.round(r.right), ok: r.left >= 0 && r.right <= window.innerWidth }; })() : null;
  // M2: a fixed element (other than the bottom bar, which the content scrolls under) never covers a control in the first viewport
  out.fixedOverlap = [];
  const fixed = Array.from(document.querySelectorAll('body *')).filter(el => getComputedStyle(el).position === 'fixed' && visible(el) && !el.classList.contains('bottomnav') && !el.classList.contains('sheet') && !el.classList.contains('scrim') && !el.closest('.sheet'));
  const ctrls = Array.from(document.querySelectorAll('button, a[href], input, select, [role=button]')).filter(el => visible(el) && !inMock(el) && !el.closest('.sheet'));
  fixed.forEach(f => { const fr = f.getBoundingClientRect(); ctrls.forEach(c => { if (f === c || f.contains(c)) return; const r = c.getBoundingClientRect(); if (r.bottom > window.innerHeight) return; if (r.left < fr.right && r.right > fr.left && r.top < fr.bottom && r.bottom > fr.top) out.fixedOverlap.push({ fixed: cls(f), over: cls(c) }); }); });
  return out;
}"""

# M2 (second half): scrolled to the bottom, no control sits under the bottom navigation bar
JS_BOTTOM = "() => {" + JS_HELPERS + r"""
  window.scrollTo(0, document.scrollingElement.scrollHeight);
  const bar = document.querySelector('.bottomnav'); if (!bar || getComputedStyle(bar).display === 'none') return [];
  const br = bar.getBoundingClientRect(); const out = [];
  document.querySelectorAll('button, a[href], input, select, [role=button]').forEach(c => { if (!visible(c) || inMock(c) || c.closest('.sheet') || bar.contains(c)) return; const r = c.getBoundingClientRect(); if (r.top < br.bottom && r.bottom > br.top && r.left < br.right && r.right > br.left) out.push(cls(c)); });
  window.scrollTo(0, 0); return out;
}"""

# immutable 15 (positive direction): every visibly animated element carries data-motion
JS_ANIMATED = "() => {" + JS_HELPERS + r"""
  const out = []; let count = 0;
  document.querySelectorAll('body *').forEach(el => { if (inMock(el) || !visible(el)) return; const cs = getComputedStyle(el);
    const anim = cs.animationName && cs.animationName !== 'none'; const trans = cs.transitionDuration && cs.transitionDuration.split(',').some(d => parseFloat(d) > 0);
    if (anim || trans) { count += 1; if (!el.hasAttribute('data-motion')) out.push({ ex: cls(el), anim: cs.animationName, trans: cs.transitionDuration }); } });
  return { missing: out, animated: count };
}"""

# M23: the text inside a held force control, measured while it is holding
JS_HOLD = "() => {" + JS_HELPERS + r"""
  const k = document.querySelector('.force-control.holding'); if (!k) return null;
  const out = { text: [], bar: null, bg: hex(effBg(k)) };
  k.querySelectorAll('.lbl, .count').forEach(el => { if (!visible(el)) return; const cs = getComputedStyle(el); const fg = effFg(el, cs.color); out.text.push({ ex: cls(el), fg: hex(fg), bg: hex(effBg(el)), ratio: Math.round(ratio(fg, effBg(el)) * 100) / 100 }); });
  const bar = k.querySelector('.fill'); if (bar) { const c = toRGBA(getComputedStyle(bar).backgroundColor); out.bar = { fg: hex(c), bg: hex(effBg(k)), ratio: Math.round(ratio(c, effBg(k)) * 100) / 100 }; }
  return out;
}"""


# immutable 13, the three layouts: which navigation is on screen, and whether the section row's current entry is inside the viewport
JS_NAV = "() => {" + JS_HELPERS + r"""
  const shown = (el) => !!el && getComputedStyle(el).display !== 'none' && el.getBoundingClientRect().width > 0;
  const rail = document.querySelector('.navrail'), bar = document.querySelector('.bottomnav');
  const rows = Array.from(document.querySelectorAll('.tabs, .chips-scroll')).map(n => {
    const cur = n.querySelector('[aria-current="page"]'); const r = cur ? cur.getBoundingClientRect() : null;
    return { kind: n.classList.contains('tabs') ? 'tabs' : 'chips', shown: shown(n), l: r ? Math.round(r.left) : null, r: r ? Math.round(r.right) : null };
  });
  return { rail: rail ? shown(rail) : null, bar: bar ? shown(bar) : null, rows: rows, inner: window.innerWidth };
}"""

# immutable 13, tables and list rows: card-per-row below 600 (thead gone, a column name before every value), a scroller from 600 to 1099
JS_TABLES = "() => {" + JS_HELPERS + r"""
  const out = [];
  document.querySelectorAll('table').forEach(t => {
    if (inMock(t) || !visible(t)) return;
    const cs = getComputedStyle(t); const head = t.querySelector('thead'); const body = t.querySelector('tbody') || t;
    const cells = Array.from(body.querySelectorAll('tr:first-child > td, tr:first-child > th')).filter(td => getComputedStyle(td).display !== 'none');
    const unlabeled = cells.filter(td => { const c = getComputedStyle(td, '::before').content; return !c || c === 'none' || c === 'normal' || c === '""'; }).length;
    let sc = t.parentElement, scroller = false;
    while (sc && sc !== document.body) { const o = getComputedStyle(sc).overflowX; if (o === 'auto' || o === 'scroll') { scroller = true; break; } sc = sc.parentElement; }
    const r = t.getBoundingClientRect();
    out.push({ ex: cls(t), display: cs.display, head: head ? getComputedStyle(head).display : null, rowDisplay: (t.querySelector('tbody tr') ? getComputedStyle(t.querySelector('tbody tr')).display : null),
               cells: cells.length, unlabeled: unlabeled, scroller: scroller, right: Math.round(r.right), left: Math.round(r.left) });
  });
  const lists = [];
  document.querySelectorAll('.list li').forEach(li => { if (inMock(li) || !visible(li)) return; lists.push({ ex: cls(li), over: li.scrollWidth - li.clientWidth }); });
  return { tables: out, lists: lists };
}"""


def layout_fails(n, th, w, r, bottom, anim, errors=(), external=(), nav=None, tables=None, shell=False):
    """The per-render failures of immutables 13 and 14 and the positive half of 15, as (page, theme, width, check, detail...) tuples. One definition for
    the mockups (main below) and the built client (console/tests/test_console_verifier.py): `errors` are the console errors, `external` the
    requests that left the page's own origin (for a mockup: any non-file request), `nav` the JS_NAV result and `tables` the JS_TABLES result
    (both optional: a page without them is only checked on the rest). `shell` says the page is a shell page (navigation and a content column): then a
    missing navigation or content column is itself a failure, where for a page without a shell (sign-in) it is the expected state."""
    bad = []
    if errors: bad.append((n, th, w, "console", list(errors)[:3]))
    if external: bad.append((n, th, w, "network", list(external)[:3]))
    if r["scrollWidth"] > r["inner"]: bad.append((n, th, w, "overflow", r["scrollWidth"], r["inner"]))
    if r["gutter"] is not None and r["gutter"] != 16: bad.append((n, th, w, "gutter", r["gutter"]))
    if shell and r["gutter"] is None: bad.append((n, th, w, "gutter", "no content column"))
    if r["currentTab"] and not r["currentTab"]["ok"]: bad.append((n, th, w, "current-tab-offscreen", r["currentTab"]))
    if w in PHONE_HEIGHT_CEILING and r["docHeight"] > PHONE_HEIGHT_CEILING[w]: bad.append((n, th, w, "page-height", r["docHeight"]))
    bad += [(n, th, w, "letter-wrapped", x) for x in r["narrow"]]
    if w < 600:  # phone: every control inside the viewport without scrolling a descendant (compact keeps the table scroller)
        bad += [(n, th, w, "control-offscreen", x) for x in r["offscreen"]]
    bad += [(n, th, w, "fixed-over-control", x) for x in r["fixedOverlap"]]
    bad += [(n, th, w, "under-bottom-bar", x) for x in bottom]
    bad += [(n, th, w, "animated-without-data-motion", x) for x in anim["missing"]]
    for t in r["targets"]:
        if not ((t["w"] >= 48 and t["h"] >= 48) or (t["chip"] and t["w"] >= 24 and t["h"] >= 24)): bad.append((n, th, w, "target", t))
    if shell and not (nav and (nav["rail"] is not None or nav["bar"] is not None)): bad.append((n, th, w, "navigation", "no navigation on a shell page"))
    if nav and (nav["rail"] is not None or nav["bar"] is not None):          # a page without a shell (sign-in) has neither
        phone = w < 600
        if bool(nav["bar"]) != phone or bool(nav["rail"]) == phone: bad.append((n, th, w, "navigation", {"rail": nav["rail"], "bottom_bar": nav["bar"]}))
        for row in nav["rows"]:
            if row["shown"] != (row["kind"] == ("chips" if phone else "tabs")): bad.append((n, th, w, "section-row", row["kind"], row["shown"]))
            if row["shown"] and (row["l"] is None or row["l"] < 0 or row["r"] > nav["inner"]): bad.append((n, th, w, "section-row-current-offscreen", row))
    if tables:
        for t in tables["tables"]:
            if w < 600:
                if t["display"] != "block" or t["head"] not in (None, "none") or t["rowDisplay"] == "table-row" or t["unlabeled"] or t["right"] > w: bad.append((n, th, w, "table-not-card-per-row", t))
            elif w < 1100 and not t["scroller"] and t["right"] > w: bad.append((n, th, w, "table-not-scrollable", t))
        bad += [(n, th, w, "list-row-overflow", x) for x in tables["lists"] if x["over"] > 1]
    return bad


def contrast_fails(n, th, w, r, nm, nb, audit=None):
    """Immutable 1 on one render: every text node at its floor (4.5, large text 3) and every ring at 3:1 (outline_variant, the decorative hairline, excepted),
    as (page, theme, width, check, detail...) tuples. One definition for the mockups (main below) and the built client (console/tests/test_console_verifier.py).
    `nm` / `nb` are name_map(th) and name_map(th, for_bg=True); `audit`, when given, collects the lowest ratio seen per (foreground, background, kind) pair."""
    bad = []
    for t in r["text"]:
        floor = 3.0 if t["large"] else 4.5
        key = (nm.get(t["fg"], t["fg"]), nb.get(t["bg"], t["bg"]), "large-text" if t["large"] else "text")
        if audit is not None:
            prev = audit.get(key)
            if not prev or t["ratio"] < prev["ratio"]:
                audit[key] = {"ratio": t["ratio"], "fg_hex": t["fg"], "bg_hex": t["bg"], "ex": f"{n[:-5]}:{t['ex']}", "min": floor}
        if t["ratio"] < floor: bad.append((n, th, w, "contrast-text", key, t["ratio"], t["ex"], t["snippet"]))
    for g in r["rings"]:
        key = (nm.get(g["fg"], g["fg"]), nb.get(g["bg"], g["bg"]), "non-text")
        if audit is not None:
            prev = audit.get(key)
            if not prev or g["ratio"] < prev["ratio"]:
                audit[key] = {"ratio": g["ratio"], "fg_hex": g["fg"], "bg_hex": g["bg"], "ex": f"{n[:-5]}:{g['ex']}", "min": 3.0}
        if g["ratio"] < 3.0 and key[0] not in ("m3.outline_variant",): bad.append((n, th, w, "contrast-ring", key, g["ratio"], g["ex"]))
    return bad


def state_fails(n, th, w, r):
    """Immutable 3, the DOM half, on one render: every [data-power] / [data-pin] / [data-session] element paints its state's token (a neutral state
    borrows no status hue), as (page, theme, width, check, detail...) tuples. One definition for the mockups and the built client."""
    bad = []
    for s in r["states"]:
        want = STATE_BG.get(s["attr"], {})
        if s["value"] not in want: bad.append((n, th, w, "state-unknown", s["attr"], s["value"], s["ex"])); continue
        ref = want[s["value"]]
        if ref is None:  # a neutral state never borrows a status hue
            if s["bg"] in {tok(th, x) for x in ("ext.ok.container", "ext.live.container", "m3.error_container", "m3.tertiary_container")}: bad.append((n, th, w, "state-neutral-hued", s["attr"], s["value"], s["bg"], s["ex"]))
            continue
        if s["bg"] != tok(th, ref): bad.append((n, th, w, "state-color", s["attr"], s["value"], s["bg"], "want " + ref, s["ex"]))
    return bad


def settle(pg):
    """An opened sheet's 300 ms entrance animation, finished at once instead of slept through (it was a fixed 350 ms wait before every case)."""
    pg.evaluate("() => document.querySelectorAll('.sheet.open').forEach(s => s.getAnimations({ subtree: true }).forEach(a => { if (a.effect.getComputedTiming().iterations !== Infinity) a.finish(); }))")
    pg.wait_for_timeout(20)


def force_matrix(pg, index=0, touch_ctx=None):
    """The destructive-control matrix on force control `index`: pointer, keyboard, press-wait-press, the opener's
    point, and the second sheet's confirm never under it. The control lives in a confirmation sheet, so the host
    sheet is re-opened before every case. The control's arming runs on setTimeout / setInterval, so the waits between
    events run on Playwright's clock (run_for) instead of the wall clock: the same timers fire in the same order, in
    milliseconds. The two positive cases (a held release fires; a deliberate third click fires) prove the timers ran."""
    res = {}
    ks = pg.query_selector_all('.force-control[data-hold]')
    if index >= len(ks):
        return None
    k = ks[index]
    host = k.evaluate("e => { const s = e.closest('.sheet'); return s ? s.id : null; }")
    pg.clock.install()
    wait = pg.clock.run_for
    def prep():
        pg.evaluate("() => window.__closeSheets()")
        if host:
            pg.evaluate("id => window.__openSheet(id, {byKey:false})", host)
        settle(pg); wait(20)
        b = k.bounding_box(); return b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
    def fires(): return pg.evaluate("() => window.__forceFireCount()")
    def sheet2_open(): return pg.evaluate("() => !!document.querySelector('.sheet[data-force-sheet2].open')")
    def armed(): return pg.evaluate("() => { const b = document.querySelector('.sheet[data-force-sheet2].open [data-confirm]'); return b && b.getAttribute('data-armed'); }")
    def under(x, y): return pg.evaluate("([x, y]) => { const e = document.elementFromPoint(x, y); return e ? (e.closest('[data-confirm]') ? 'CONFIRM' : (e.closest('[data-close]') ? 'cancel' : e.tagName.toLowerCase())) : null; }", [x, y])
    base = fires()
    cx, cy = prep(); pg.mouse.click(cx, cy); wait(50); res["click"] = (fires() - base, sheet2_open())
    res["opener_point"] = under(cx, cy)                           # B1: never the confirm
    cx, cy = prep(); pg.mouse.move(cx, cy); pg.mouse.down(); wait(600); pg.mouse.up(); wait(50); res["hold600"] = fires() - base
    cx, cy = prep(); pg.mouse.move(cx, cy); pg.mouse.down(); wait(1400); pg.mouse.move(cx + 400, cy + 300, steps=5); pg.mouse.up(); wait(50); res["hold1400_slideoff"] = fires() - base
    cx, cy = prep(); pg.mouse.move(cx, cy); pg.mouse.down(); pg.mouse.move(cx + 300, cy, steps=10); pg.mouse.up(); wait(50); res["swipe"] = fires() - base
    cx, cy = prep(); pg.mouse.move(cx, cy); pg.mouse.down(); wait(1400); pg.mouse.up(); wait(100); res["hold1400_release"] = fires() - base; base = fires()
    # B1: click, wait, click at the same point (two slow taps) must never fire
    cx, cy = prep(); pg.mouse.click(cx, cy); wait(450); pg.mouse.click(cx, cy); wait(50); res["click_450_click"] = (fires() - base, sheet2_open())
    cx, cy = prep(); pg.mouse.click(cx, cy); wait(700); pg.mouse.click(cx, cy); wait(50); res["click_700_click"] = (fires() - base, sheet2_open())
    cx, cy = prep(); pg.mouse.dblclick(cx, cy); wait(50); res["dblclick"] = (fires() - base, sheet2_open())
    # the third deliberate click on the visibly armed confirm does fire (the positive control of the arming rule)
    cx, cy = prep(); pg.mouse.click(cx, cy); wait(100); pg.mouse.click(cx, cy); wait(500)
    cb = pg.query_selector('.sheet[data-force-sheet2].open [data-confirm]'); a1 = armed()
    if cb: bb = cb.bounding_box(); pg.mouse.click(bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2); wait(50)
    res["click_click_wait_confirm"] = (fires() - base, a1); base = fires()
    prep(); k.focus(); pg.keyboard.down("Enter")
    for _ in range(45): pg.keyboard.down("Enter"); wait(33)
    pg.keyboard.up("Enter"); wait(50); res["enter_held"] = (fires() - base, sheet2_open())
    pg.evaluate("() => window.__closeSheets()")
    prep(); k.focus(); pg.keyboard.press("Enter"); wait(450); pg.keyboard.press("Enter"); wait(50)
    res["enter_wait_enter"] = (fires() - base, sheet2_open())
    prep(); k.focus(); pg.keyboard.press("Enter"); wait(550); a = armed()
    pg.keyboard.press("Tab"); pg.keyboard.press("Enter"); wait(50); res["enter_release_550_tab_enter"] = (fires() - base, a); base = fires()
    prep(); k.focus(); pg.keyboard.down("Enter"); wait(600); a2 = armed(); pg.keyboard.up("Enter"); wait(50)
    res["enter_held_600_not_armed"] = (a2, fires() - base)
    pg.evaluate("() => window.__closeSheets()")
    pg.clock.resume()
    return res


def tap_matrix(pg, index):
    """Touch: tap, wait 500 ms, tap at the same point (a touch context)."""
    ks = pg.query_selector_all('.force-control[data-hold]')
    if index >= len(ks): return None
    k = ks[index]; host = k.evaluate("e => { const s = e.closest('.sheet'); return s ? s.id : null; }")
    pg.evaluate("() => window.__closeSheets()")
    if host: pg.evaluate("id => window.__openSheet(id, {byKey:false})", host)
    settle(pg); b = k.bounding_box(); cx, cy = b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
    base = pg.evaluate("() => window.__forceFireCount()")
    pg.touchscreen.tap(cx, cy); pg.wait_for_timeout(500); pg.touchscreen.tap(cx, cy); pg.wait_for_timeout(50)
    r = (pg.evaluate("() => window.__forceFireCount()") - base, pg.evaluate("() => !!document.querySelector('.sheet[data-force-sheet2].open')"))
    pg.evaluate("() => window.__closeSheets()")
    return r


def hold_contrast(pg, index):
    """M23: the label and progress bar of a held force control, 600 ms into the hold."""
    ks = pg.query_selector_all('.force-control[data-hold]')
    if index >= len(ks): return None
    k = ks[index]; host = k.evaluate("e => { const s = e.closest('.sheet'); return s ? s.id : null; }")
    pg.evaluate("() => window.__closeSheets()")
    if host: pg.evaluate("id => window.__openSheet(id, {byKey:false})", host)
    settle(pg); b = k.bounding_box(); cx, cy = b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
    pg.mouse.move(cx, cy); pg.mouse.down(); pg.wait_for_timeout(600)
    r = pg.evaluate(JS_HOLD)
    pg.mouse.move(cx + 400, cy + 300, steps=3); pg.mouse.up(); pg.evaluate("() => window.__closeSheets()")
    return r


def confirm_checks(pg):
    """Every plain confirm sheet: one call per click, one for a held Enter, focus inside the sheet (on Cancel) after
    a keyboard open and after a pointer open, Tab trapped inside."""
    out = []
    for s in pg.query_selector_all('.sheet[data-confirm-sheet]'):
        sid = s.get_attribute("id"); inline = "inline" in (s.get_attribute("class") or "")
        def opn(by_key):
            pg.evaluate("() => window.__closeSheets()")
            opener = next((o for o in pg.query_selector_all(f'[data-open="{sid}"]:not([aria-disabled="true"])') if o.bounding_box()), None)
            if opener and not inline:
                opener.focus()
                if by_key: pg.keyboard.press("Enter")
                else: bb = opener.bounding_box(); pg.mouse.click(bb["x"] + bb["width"] / 2, bb["y"] + bb["height"] / 2)
            elif not inline:
                pg.evaluate("([id, k]) => window.__openSheet(id, {byKey: k})", [sid, by_key])
            pg.wait_for_timeout(60)
        opn(True)
        foc_key = pg.evaluate(f"() => {{ const a = document.activeElement; const s = document.getElementById('{sid}'); return {{ inSheet: !!(a && s.contains(a)), isCancel: !!(a && a.hasAttribute('data-close')) }}; }}")
        pg.keyboard.press("Tab"); pg.keyboard.press("Tab"); pg.keyboard.press("Tab"); pg.keyboard.press("Tab")
        trapped = pg.evaluate(f"() => {{ const a = document.activeElement; const s = document.getElementById('{sid}'); return !!(a && s.contains(a)); }}")
        opn(False)
        foc_ptr = pg.evaluate(f"() => {{ const a = document.activeElement; const s = document.getElementById('{sid}'); return !!(a && s.contains(a)); }}")
        btn = pg.query_selector(f'#{sid} [data-confirm]')
        base = pg.evaluate("() => window.__callCount()")
        btn.click(); pg.wait_for_timeout(30)
        one = pg.evaluate("() => window.__callCount()") - base
        opn(False); btn.focus(); base = pg.evaluate("() => window.__callCount()")
        pg.keyboard.down("Enter")
        for _ in range(45): pg.keyboard.down("Enter"); pg.wait_for_timeout(33)
        pg.keyboard.up("Enter"); pg.wait_for_timeout(30)
        held = pg.evaluate("() => window.__callCount()") - base
        pg.evaluate("() => window.__closeSheets()")
        out.append({"sheet": sid, "click": one, "enter_held": held, "focus_key": foc_key, "focus_ptr": foc_ptr, "trapped": trapped})
    return out


def outside_sweep(pg):
    """Immutable 4: a click on every control outside a sheet sends 0 calls and fires 0 force controls."""
    pg.evaluate("() => { document.addEventListener('click', e => { const a = e.target.closest('a[href]'); if (a) e.preventDefault(); }, true); }")
    n = pg.evaluate("() => { const ctrls = Array.from(document.querySelectorAll('button, a[href], [role=button], [role=switch], [role=checkbox], [role=radio], summary')).filter(el => !el.closest('.sheet') && !el.closest('.mock-bar')); return ctrls.length; }")
    base_c = pg.evaluate("() => window.__callCount()"); base_f = pg.evaluate("() => window.__forceFireCount()")
    for i in range(n):
        pg.evaluate(f"() => {{ const ctrls = Array.from(document.querySelectorAll('button, a[href], [role=button], [role=switch], [role=checkbox], [role=radio], summary')).filter(el => !el.closest('.sheet') && !el.closest('.mock-bar')); const el = ctrls[{i}]; if (el) el.click(); window.__closeSheets(); }}")
    return {"controls": n, "calls": pg.evaluate("() => window.__callCount()") - base_c, "fires": pg.evaluate("() => window.__forceFireCount()") - base_f}


def predicate_checks(pg, name):
    """B3: the sheet kind follows the ARGUMENTS; the call spy sees every destructive call preceded by a force fire."""
    out = {}
    def opened(): return pg.evaluate("() => { const s = Array.from(document.querySelectorAll('.sheet.open')).pop(); return s ? { id: s.id, force: s.hasAttribute('data-force-sheet'), call: (s.querySelector('.call') || {}).textContent || '' } : null; }")
    def click_by(key):
        pg.evaluate("() => window.__closeSheets()")
        pg.evaluate(f"() => {{ const el = Array.from(document.querySelectorAll('[data-open-by=\"{key}\"]:not([aria-disabled=\"true\"])')).find(e => e.offsetParent !== null); el.click(); }}")
        pg.wait_for_timeout(50); return opened()
    def fire_open():
        """hold the open sheet's force control and release: one fire, one forced call"""
        k = pg.query_selector('.sheet.open .force-control[data-hold]'); b = k.bounding_box(); cx, cy = b["x"] + b["width"] / 2, b["y"] + b["height"] / 2
        pg.mouse.move(cx, cy); pg.mouse.down(); pg.wait_for_timeout(1400); pg.mouse.up(); pg.wait_for_timeout(60)
    if name == "power-boot.html":
        # the outside-sheet sweep toggled every checkbox: start from the form's safe defaults
        pg.evaluate("() => { document.querySelectorAll('.opts .check').forEach(c => c.setAttribute('aria-checked', 'false')); document.querySelectorAll('.opts input[type=number]').forEach(i => i.value = '0'); }")
        pg.evaluate("() => { document.querySelector('[data-opt=\"secure_erase\"]').setAttribute('aria-checked', 'true'); }")
        r = click_by("boot-set"); out["set_with_secure_erase"] = (r["force"], "secure_erase: true" in r["call"]); fire_open()
        pg.evaluate("() => { document.querySelector('[data-opt=\"secure_erase\"]').setAttribute('aria-checked', 'false'); document.getElementById('opt-firmware_verbosity').value = '2'; }")
        r = click_by("boot-set"); out["set_plain_with_verbosity"] = (not r["force"], "firmware_verbosity: 2" in r["call"] and "secure_erase" not in r["call"])
        pg.evaluate("() => { document.querySelector('[data-opt=\"reflash_bios\"]').setAttribute('aria-checked', 'true'); }")
        r = click_by("boot-reset"); out["reset_with_reflash"] = (r["force"], "reflash_bios: true" in r["call"] and "hard_reset" in r["call"]); fire_open()
    elif name == "media.html":
        for start in ("next_boot", "graceful", "now"):
            pg.evaluate(f"() => document.querySelectorAll('.check[role=radio]').forEach(o => o.setAttribute('aria-checked', String(o.getAttribute('data-start') === '{start}')))")
            r = click_by("mount"); out["mount_" + start] = (r["force"] == (start == "now"), f'start: "{start}"' in r["call"])
            if start == "now": fire_open()
    elif name == "console.html":
        r = click_by("stop-mirror"); out["stop_console_idle"] = (not r["force"], 'action: "stop"' in r["call"])
        pg.evaluate("() => document.documentElement.setAttribute('data-agent', 'typing')")
        r = click_by("stop-mirror"); out["stop_in_flight"] = (r["force"], "in flight" in r["call"]); fire_open()
        pg.evaluate("() => { document.documentElement.setAttribute('data-agent', 'idle'); document.documentElement.setAttribute('data-mirror', 'agent'); }")
        r = click_by("stop-mirror"); out["stop_agent_started"] = (r["force"], "started by an agent" in r["call"])
        pg.evaluate("() => { document.documentElement.removeAttribute('data-mirror'); document.querySelector('[data-guard=\"grub\"]').click(); }")
        r = click_by("macro"); out["macro_with_guard"] = (not r["force"], 'expect: ["grub"]' in r["call"] and "ctrl_alt_del" in r["call"])
    elif name == "serial.html":
        r = click_by("stop-terminal"); out["stop_console"] = (not r["force"], 'action: "stop"' in r["call"])
        pg.evaluate("() => document.documentElement.setAttribute('data-serial', 'agent')")
        r = click_by("stop-terminal"); out["stop_agent_started"] = (r["force"], "started by an agent" in r["call"]); fire_open()
    pg.evaluate("() => window.__closeSheets()")
    return out


def spy_check(pg):
    """Every call the page sent whose text satisfies the destructive predicate was forced; plus the predicate's controls."""
    calls = pg.evaluate("() => window.__calls()")
    bad = [c for c in calls if pg.evaluate("t => window.__destructiveCall(t)", c["text"]) and not c["forced"]]
    pos = pg.evaluate("() => window.__destructiveCall('tools/call amt_ider {device: \"x\", action: \"mount\", iso_path: \"a.iso\", start: \"now\", confirmed: true}') && window.__destructiveCall('tools/call amt_set_next_boot {device: \"x\", target: \"pxe\", options: {reflash_bios: true}, confirmed: true}') && window.__destructiveCall('tools/call amt_device_manage {action: \"edit\", device: \"x\", repin: true, confirmed: true}')")
    neg = pg.evaluate("() => !window.__destructiveCall('tools/call amt_ider {device: \"x\", action: \"mount\", iso_path: \"a.iso\", start: \"next_boot\", confirmed: true}') && !window.__destructiveCall('tools/call amt_power {device: \"x\", action: \"restart\", confirmed: true}') && !window.__destructiveCall('tools/call amt_mirror_link {device: \"x\", action: \"stop\"}')")
    forced = sum(1 for c in calls if c["forced"]); destructive = sum(1 for c in calls if pg.evaluate("t => window.__destructiveCall(t)", c["text"]))
    return {"calls": len(calls), "destructive": destructive, "forced": forced, "unforced_destructive": [c["text"][:80] for c in bad], "predicate_controls": pos and neg}


def _calls_in(line):
    """(tool, argument text) for every `amt_x {...}` in a call line, braces matched by depth (arguments nest: actions: [{...}])."""
    out = []
    for m in re.finditer(r"(amt_[a-z_]+) \{", line):
        i = m.end(); depth = 1
        while i < len(line) and depth:
            depth += {"{": 1, "}": -1}.get(line[i], 0); i += 1
        out.append((m.group(1), line[m.end():i - 1]))
    return out


def calls_scan(path):
    """Immutable 6: every .call to a tool that needs `device` names it; every write names confirmed: true unless its action needs none."""
    text = open(path).read(); bad = []
    for m in re.finditer(r'class="call">(.*?)</p>', text, re.S):
        line = re.sub(r"<[^>]+>", "", m.group(1))
        for tool, args in _calls_in(line):
            if tool not in NO_DEVICE and "device:" not in args: bad.append(("no device", tool, line[:70]))
            act = re.search(r'action: "([a-z_]+)"', args)
            if tool not in READ_TOOLS and "confirmed: true" not in args and not (act and act.group(1) in UNCONFIRMED_ACTIONS.get(tool, set())): bad.append(("no confirmed", tool, line[:70]))
    return bad


def secret_scan(path):
    """Immutable 9 / M18 / M13 / immutable 11: no password field, no new-password hint, every secret field outside a form with
    autocomplete off and no value; no handoffs/ in src/href; no token-shaped string anywhere."""
    text = open(path).read(); bad = []
    if re.search(r'type="password"', text): bad.append("input type=password")
    if "new-password" in text: bad.append("autocomplete=new-password")
    for m in re.finditer(r'<input[^>]*class="secret"[^>]*>', text):
        tag = m.group(0)
        if 'autocomplete="off"' not in tag: bad.append("secret field without autocomplete=off")
        if re.search(r'\svalue=', tag): bad.append("secret field with a value")
        if "<form" in text[:m.start()] and "</form>" not in text[text.rfind("<form", 0, m.start()):m.start()]: bad.append("secret field inside a form")
    if re.search(r'(src|href)="[^"]*handoffs/', text): bad.append("handoffs/ url in src/href")
    body = text[text.index("<body"):text.index("<script")]
    for t in token_shaped(re.sub(r"<svg.*?</svg>", "", body, flags=re.S)): bad.append("token-shaped string: " + t[:12] + "…")
    return bad


def dom_scan(path):
    """Immutables 10 and 20, static: fingerprints in groups of 4 with a bold stored prefix, the mismatch state and the
    disabled Remove with its reason on the servers page; no forced power action outside the Force tray, and no power or
    boot control inside the embed, on the pages that carry them."""
    text = open(path).read(); name = os.path.basename(path); bad = []
    if name == "servers.html":
        fps = [re.sub(r"<[^>]+>", "", m.group(1)) for m in re.finditer(r'<span class="fp">(.*?)</span>', text, re.S)]
        if not fps: bad.append("no fingerprint on the servers page")
        for fp in fps:
            if any(not re.fullmatch(r"[0-9a-f]{4}", g) for g in fp.replace("…", "").split()): bad.append("fingerprint not in groups of 4: " + fp[:30])
        if not re.search(r'<span class="fp"><b>[0-9a-f]{4}( [0-9a-f]{4}){3}</b> [0-9a-f]{4}', text): bad.append("no full fingerprint with its 16-hex stored prefix in bold")
        if 'data-pin-state="mismatch"' not in text: bad.append("no presented-leaf-differs state")
        if not re.search(r'<button class="btn text" aria-disabled="true">Remove</button><span class="reason">', text): bad.append("the last server's Remove is not aria-disabled with a reason")
    if name == "power-boot.html":
        body = text[text.index("<body"):text.index("<script")]
        tray = re.search(r'<details class="force-tray".*?</details>', body, re.S).group(0)
        outside = body.replace(tray, "")
        for m in re.finditer(r'data-action="(hard_[a-z_]+|immediate_[a-z_]+|nmi)"', outside): bad.append("forced action outside the Force tray: " + m.group(1))
    if name in ("console.html", "serial.html"):
        embed = re.search(r'<div class="embed".*?<div class="foot">', text, re.S).group(0)
        for word in ("Power", "Boot", "Media", "Screenshot", "Download", "data-action", "data-a="):
            if re.search(r">\s*" + word + r"\b|" + word + "=", embed): bad.append("embed carries " + word)
    return bad


def schema_check(path):
    """M7: every macro grid entry's data-json validates against the live amt_console_input ConsoleAction schema."""
    text = open(path).read()
    entries = [json.loads(m.group(1).replace("&quot;", '"')) for m in re.finditer(r"data-json='([^']*)'", text)]
    if not entries: return None
    try:
        sys.path.insert(0, os.path.dirname(D)); import asyncio, amt_server, jsonschema
        tools = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}
        schema = tools["amt_console_input"].inputSchema
        item = schema["properties"]["actions"]["items"]; defs = schema.get("$defs", {})
        v = jsonschema.Draft202012Validator({**item, "$defs": defs})
        errs = [(e, sorted(x.message for x in v.iter_errors(e))) for e in entries]
        return {"entries": len(entries), "invalid": [x for x in errs if x[1]], "source": "live schema"}
    except Exception as ex:  # the live schema is not importable here: report, never pass silently
        return {"entries": len(entries), "invalid": None, "source": f"SKIPPED: {type(ex).__name__}: {ex}"}


def main():
    merge = "--merge" in sys.argv
    part = sys.argv[sys.argv.index("--part") + 1] if "--part" in sys.argv else None
    force_only = tuple(int(x) for x in part.split(":")[1:]) if part and part.startswith("force:") else None
    named = [a for a in sys.argv[1:] if a.endswith(".html")]
    names = named or sorted(f for f in os.listdir(D) if f.endswith(".html"))
    fails = []
    audit_pairs = {th: {} for th in THEMES}
    stats = {"renders": 0, "text": 0, "rings": 0, "targets": 0, "motion": 0, "states": 0, "state_colors": 0, "animated": 0, "force_controls": 0, "tap_cases": 0, "hold_renders": 0, "confirm_sheets": 0, "outside_controls": 0, "predicate_cases": 0, "calls_scanned": 0, "macro_entries": 0}
    heights = {}
    exp = {"click": (0, True), "opener_point": None, "hold600": 0, "hold1400_slideoff": 0, "swipe": 0, "hold1400_release": 1,
           "click_450_click": (0, True), "click_700_click": (0, True), "dblclick": (0, True), "click_click_wait_confirm": (1, "true"),
           "enter_held": (0, False), "enter_wait_enter": (0, False), "enter_release_550_tab_enter": (1, "true"), "enter_held_600_not_armed": ("false", 0)}
    schema_results = {n: schema_check(os.path.join(D, n)) for n in names}
    with sync_playwright() as p:
        b = p.chromium.launch()
        for n in names:
            if force_only:                                     # --part force:<width>:<index>: that one matrix and nothing else
                fw, fi = force_only
                ctx = b.new_context(viewport={"width": fw, "height": 900}); pg = ctx.new_page(); pg.goto(f"file://{D}/{n}"); pg.wait_for_timeout(50)
                fm = force_matrix(pg, fi)
                if fm is None: fails.append((n, fw, "force-matrix", fi, "no such force control"))
                else:
                    bad = {k: v for k, v in fm.items() if (k == "opener_point" and v == "CONFIRM") or (k != "opener_point" and v != exp[k])}
                    print(n, fw, "force matrix", fi, ":", fm, "FAIL" if bad else "ok")
                    stats["force_controls"] += 1
                    if bad: fails.append((n, fw, "force-matrix", fi, bad))
                pg.close(); ctx.close()
                continue
            lits = literal_check(os.path.join(D, n))
            if lits: fails.append((n, "literals", lits))
            for item in calls_scan(os.path.join(D, n)): fails.append((n, "call-scan", item))
            stats["calls_scanned"] += len(re.findall(r'class="call">', open(os.path.join(D, n)).read()))
            for item in secret_scan(os.path.join(D, n)): fails.append((n, "secret-scan", item))
            for item in dom_scan(os.path.join(D, n)): fails.append((n, "dom-scan", item))
            sc = schema_results[n]
            if sc:
                stats["macro_entries"] += sc["entries"]; print(n, "macro schema:", sc["entries"], "entries,", sc["source"], "invalid:", sc["invalid"])
                if sc["invalid"] is None or sc["invalid"]: fails.append((n, "macro-schema", sc["source"], sc["invalid"]))
            for th in THEMES:
                nm = name_map(th); nb = name_map(th, for_bg=True)
                for w in WIDTHS:
                    ctx = b.new_context(viewport={"width": w, "height": 900}, color_scheme=th)
                    pg = ctx.new_page()
                    errors, reqs = [], []
                    pg.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
                    pg.on("pageerror", lambda e: errors.append(str(e)))
                    pg.on("request", lambda r: reqs.append(r.url) if not r.url.startswith("file://") else None)
                    pg.goto(f"file://{D}/{n}")
                    pg.evaluate("t => { document.documentElement.setAttribute('data-theme', t); try{localStorage.removeItem('amt-console-theme')}catch(e){} }", th)
                    pg.wait_for_timeout(100)
                    states = pg.evaluate("() => { const m = {}; document.querySelectorAll('[data-state-key]').forEach(b => { (m[b.getAttribute('data-state-key')] = m[b.getAttribute('data-state-key')] || []).push(b.getAttribute('data-state-set')); }); return m; }")
                    combos = [None] + [(k, v) for k, vs in states.items() for v in vs]
                    hidden_demo = pg.evaluate("() => document.querySelectorAll('[hidden][data-state], [hidden][data-session], [hidden][data-empty]').length")
                    r = None
                    for combo in combos + ["hidden"]:
                        if combo == "hidden":
                            if not hidden_demo: continue
                            pg.evaluate("() => document.querySelectorAll('[hidden][data-state], [hidden][data-session], [hidden][data-empty]').forEach(e => e.hidden = false)")
                        elif combo:
                            pg.evaluate("([k, v]) => document.documentElement.setAttribute(k, v)", list(combo))
                        rr = pg.evaluate(JS_WALK)
                        stats["states"] += 1
                        if combo and combo != "hidden" and rr["currentTab"] and not rr["currentTab"]["ok"]: fails.append((n, th, w, "current-tab-offscreen", rr["currentTab"]))
                        if r is None: r = rr
                        else:
                            for key in ("text", "rings", "targets", "motion", "states", "narrow", "offscreen", "fixedOverlap"): r[key] += rr[key]
                            r["scrollWidth"] = max(r["scrollWidth"], rr["scrollWidth"]); r["docHeight"] = max(r["docHeight"], rr["docHeight"])
                    bottom = pg.evaluate(JS_BOTTOM)
                    anim = pg.evaluate(JS_ANIMATED)
                    first = pg.query_selector('.sheet[data-confirm-sheet], .sheet[data-force-sheet]')
                    if first:
                        pg.evaluate("id => window.__openSheet(id, {byKey:false})", first.get_attribute("id")); pg.wait_for_timeout(30)
                        a2 = pg.evaluate(JS_ANIMATED); anim["missing"] += a2["missing"]; anim["animated"] += a2["animated"]; pg.evaluate("() => window.__closeSheets()")
                    stats["renders"] += 1; stats["text"] += len(r["text"]); stats["rings"] += len(r["rings"]); stats["targets"] += len(r["targets"]); stats["motion"] += len(r["motion"]); stats["state_colors"] += len(r["states"]); stats["animated"] += anim["animated"]
                    heights[(n, w)] = max(heights.get((n, w), 0), r["docHeight"])
                    fails += layout_fails(n, th, w, r, bottom, anim, errors, reqs)   # the nav and table probes are the built client's (the -phone mockups are phone-only by design)
                    fails += contrast_fails(n, th, w, r, nm, nb, audit_pairs[th])
                    fails += state_fails(n, th, w, r)
                    pg.close(); ctx.close()
                # reduced motion (one width)
                ctx = b.new_context(viewport={"width": 1024, "height": 900}, color_scheme=th, reduced_motion="reduce")
                pg = ctx.new_page(); pg.goto(f"file://{D}/{n}"); pg.evaluate("t => document.documentElement.setAttribute('data-theme', t)", th); pg.wait_for_timeout(50)
                first = pg.query_selector('.sheet[data-confirm-sheet], .sheet[data-force-sheet]')
                if first: pg.evaluate("id => window.__openSheet(id, {byKey:false})", first.get_attribute("id")); pg.wait_for_timeout(30)
                for m in pg.evaluate(JS_WALK)["motion"]:
                    if m["anim"] != "none" or m["trans"] not in ("0s",): fails.append((n, th, "reduced-motion", m))
                pg.close(); ctx.close()
            # immutable 16: follows prefers-color-scheme without an override; a manual override persists across reload
            for scheme in THEMES:
                ctx = b.new_context(viewport={"width": 1024, "height": 900}, color_scheme=scheme); pg = ctx.new_page(); pg.goto(f"file://{D}/{n}")
                pg.evaluate("() => { try { localStorage.removeItem('amt-console-theme'); } catch (e) {} document.documentElement.removeAttribute('data-theme'); }"); pg.wait_for_timeout(30)
                got = pg.evaluate("() => ({ cs: getComputedStyle(document.documentElement).colorScheme, bg: getComputedStyle(document.body).backgroundColor })")
                if got["cs"] != scheme: fails.append((n, scheme, "follows-prefers-color-scheme", got))
                other = "light" if scheme == "dark" else "dark"
                pg.click(f'[data-theme-set="{other}"]'); pg.reload(); pg.wait_for_timeout(50)
                held = pg.evaluate("() => document.documentElement.getAttribute('data-theme')")
                if held != other: fails.append((n, scheme, "override-not-persisted", held))
                pg.evaluate("() => { try { localStorage.removeItem('amt-console-theme'); } catch (e) {} }")
                pg.close(); ctx.close()
            # force matrix at 1024 and 360 (light), the tap case in a touch context, the holding-state contrast in both themes
            for w in (() if part == "base" else (1024, 360)):
                ctx = b.new_context(viewport={"width": w, "height": 900}); pg = ctx.new_page(); pg.goto(f"file://{D}/{n}"); pg.wait_for_timeout(50)
                idx = 0
                while True:
                    fm = force_matrix(pg, idx)
                    if fm is None: break
                    bad = {k: v for k, v in fm.items() if (k == "opener_point" and v == "CONFIRM") or (k != "opener_point" and v != exp[k])}
                    print(n, w, "force matrix", idx, ":", fm, "FAIL" if bad else "ok")
                    if w == 1024: stats["force_controls"] += 1
                    if bad: fails.append((n, w, "force-matrix", idx, bad))
                    idx += 1
                pg.close(); ctx.close()
            ctx = b.new_context(viewport={"width": 360, "height": 900}, has_touch=True); pg = ctx.new_page(); pg.goto(f"file://{D}/{n}"); pg.wait_for_timeout(50)
            print(n, "force controls:", len(pg.query_selector_all('.force-control[data-hold]')))
            idx = 0
            while True:
                tm = tap_matrix(pg, idx)
                if tm is None: break
                stats["tap_cases"] += 1
                if tm != (0, True): fails.append((n, "tap-500-tap", idx, tm))
                idx += 1
            pg.close(); ctx.close()
            for th in THEMES:
                ctx = b.new_context(viewport={"width": 1024, "height": 900}, color_scheme=th); pg = ctx.new_page(); pg.goto(f"file://{D}/{n}")
                pg.evaluate("t => document.documentElement.setAttribute('data-theme', t)", th); pg.wait_for_timeout(50)
                idx = 0
                while True:
                    hc = hold_contrast(pg, idx)
                    if hc is None: break
                    stats["hold_renders"] += 1
                    for t in hc["text"]:
                        if t["ratio"] < 4.5: fails.append((n, th, "hold-contrast", idx, t))
                    if hc["bar"] and hc["bar"]["ratio"] < 3.0: fails.append((n, th, "hold-bar-contrast", idx, hc["bar"]))
                    if hc["bg"] != tok(th, "ext.hold.fill"): fails.append((n, th, "hold-bg", idx, hc["bg"]))
                    idx += 1
                pg.close(); ctx.close()
            # confirm sheets, the outside sweep, the predicate cases and the call spy (light, 1024)
            ctx = b.new_context(viewport={"width": 1024, "height": 900}); pg = ctx.new_page(); pg.goto(f"file://{D}/{n}"); pg.wait_for_timeout(50)
            for cc in confirm_checks(pg):
                stats["confirm_sheets"] += 1
                ok = cc["click"] == 1 and cc["enter_held"] == 1 and cc["focus_key"]["inSheet"] and cc["focus_key"]["isCancel"] and cc["focus_ptr"] and cc["trapped"]
                print(n, "confirm:", cc, "ok" if ok else "FAIL")
                if not ok: fails.append((n, "confirm", cc))
            sw = outside_sweep(pg); stats["outside_controls"] += sw["controls"]
            print(n, "outside-sheet sweep:", sw, "ok" if sw["calls"] == 0 and sw["fires"] == 0 else "FAIL")
            if sw["calls"] or sw["fires"]: fails.append((n, "outside-sweep", sw))
            pc = predicate_checks(pg, n)
            if pc:
                stats["predicate_cases"] += len(pc)
                bad = {k: v for k, v in pc.items() if not all(v)}
                print(n, "predicate:", pc, "FAIL" if bad else "ok")
                if bad: fails.append((n, "predicate", bad))
            sp = spy_check(pg)
            print(n, "spy:", sp, "ok" if not sp["unforced_destructive"] and sp["predicate_controls"] else "FAIL")
            if sp["unforced_destructive"] or not sp["predicate_controls"]: fails.append((n, "spy", sp))
            pg.close(); ctx.close()
        b.close()
    print("stats", stats)
    print("page heights at 360:", {k[0]: v for k, v in heights.items() if k[1] == 360})
    if not named and stats["animated"] == 0: fails.append(("motion-vacuous", "no animated element was seen in any render"))   # a one-page run's motion is the caller's to pin
    # positive control for the literal extractor: a planted #123456 must be reported, once
    import tempfile, shutil
    src = os.path.join(D, names[0]); fd, tmp = tempfile.mkstemp(suffix=".html", prefix="amt-console-control-"); os.close(fd)   # unique: runs go side by side
    shutil.copy(src, tmp); open(tmp, "a").write("<style>.planted{color:#123456}</style>")
    pc = literal_check(tmp); os.remove(tmp)
    print("literal positive control:", pc, "ok" if pc == ["#123456"] else "FAIL")
    if pc != ["#123456"]: fails.append(("literal-positive-control", pc))
    # positive control for the secret scan: a planted password field and a planted token must be reported
    shutil.copy(src, tmp); open(tmp, "a").write('<input type="password"><a href="x/handoffs/abc">x</a>')
    sc = secret_scan(tmp); os.remove(tmp)
    print("secret-scan positive control:", sc, "ok" if "input type=password" in sc and "handoffs/ url in src/href" in sc else "FAIL")
    if not ("input type=password" in sc and "handoffs/ url in src/href" in sc): fails.append(("secret-scan-positive-control", sc))
    for th in THEMES:
        print(th, "distinct audit pairs:", len(audit_pairs[th]), "below floor:", sum(1 for k, v in audit_pairs[th].items() if v["ratio"] < v["min"] and k[0] != "m3.outline_variant"))
    print("FAILS", len(fails))
    for f in fails[:120]:
        print("  ", f)
    if merge:
        for th in THEMES:
            have = {(p["fg"], p["bg"], p["kind"]) for p in tokens[th]["pairs"]}
            added = 0
            for (fg, bg, kind), v in sorted(audit_pairs[th].items()):
                if (fg, bg, kind) in have or fg.startswith("#") or bg.startswith("#") or fg == "m3.outline_variant":
                    continue
                tokens[th]["pairs"].append({"fg": fg, "bg": bg, "fg_hex": v["fg_hex"], "bg_hex": v["bg_hex"], "min": v["min"], "kind": kind, "ratio": v["ratio"], "pass": v["ratio"] >= v["min"], "source": "audit", "example": v["ex"]})
                added += 1
            print(th, "merged audit pairs:", added, "total", len(tokens[th]["pairs"]))
        json.dump(tokens, open(TOK, "w"), indent=1)
    unknown = sorted({k[0] for th in THEMES for k in audit_pairs[th] if k[0].startswith("#")} | {k[1] for th in THEMES for k in audit_pairs[th] if k[1].startswith("#")})
    if unknown:
        print("non-token colors seen in the DOM:", unknown)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
