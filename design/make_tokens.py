#!/usr/bin/env python3
"""amt-console design tokens: M3 scheme from one seed, re-toned error palette, three extended roles,
the four-band color predicate over every value, ring-hue separation, and the contrast `pairs` list.

Writes design/tokens.json. Run: python3 make_tokens.py [--check-only]  (needs material-color-utilities 0.2.6, pinned in
design/requirements.txt; on a node where the venv lacks it: pip install --target <dir> -r design/requirements.txt and run with
PYTHONPATH=<dir>; writes tokens.json beside this file). Every number printed is computed (material-color-utilities 0.2.6,
WCAG 2.x relative luminance).
"""
from __future__ import annotations
import json, sys, itertools
from material_color_utilities import Hct, TonalPalette, get_contrast_ratio, theme_from_color, Variant

import os
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "tokens.json")

# Seed: blue (HCT hue 265, chroma 48, tone 40), far from the three extended hues (live amber 88,
# ok green 155, error red 25). TONAL_SPOT derives tertiary at seed hue + 60 = 325, which is the
# pink/magenta band (15 offenders on the first run), so the tertiary palette is re-derived at hue 195
# (cyan, chroma 24, the M3 tertiary chroma) at the M3 tertiary tones. Stated in the design note.
SEED = TonalPalette(265, 48).get(40)
TERTIARY = TonalPalette(195, 24)

ROLES = ["primary", "on_primary", "primary_container", "on_primary_container", "secondary", "on_secondary",
         "secondary_container", "on_secondary_container", "tertiary", "on_tertiary", "tertiary_container",
         "on_tertiary_container", "error", "on_error", "error_container", "on_error_container", "surface",
         "on_surface", "surface_variant", "on_surface_variant", "surface_dim", "surface_bright",
         "surface_container_lowest", "surface_container_low", "surface_container", "surface_container_high",
         "surface_container_highest", "inverse_surface", "inverse_on_surface", "inverse_primary", "outline",
         "outline_variant", "shadow", "scrim", "surface_tint", "background", "primary_fixed", "primary_fixed_dim",
         "on_primary_fixed", "on_primary_fixed_variant", "secondary_fixed", "secondary_fixed_dim",
         "on_secondary_fixed", "on_secondary_fixed_variant", "tertiary_fixed", "tertiary_fixed_dim",
         "on_tertiary_fixed", "on_tertiary_fixed_variant"]

# Extended roles: hue, chroma. Tones follow the M3 custom-color convention (light 40/100/90/10,
# dark 80/20/30/90). `live` = a held redirection session / recording; `ok` = on, matching, verified.
EXT = {"live": (88, 60), "ok": (155, 50)}
ERROR_HUE, ERROR_CHROMA = 25, 84          # M3 error hue, re-toned (house rule): light 40/100/35/100, dark 55/5/45/100


def hct(hex_):
    h = Hct(hex_)
    return h.hue, h.chroma, h.tone


def band(hex_):
    """The operator's color rule as a predicate (house rule)."""
    hue, chroma, tone = hct(hex_)
    if 300 <= hue < 360 and chroma > 10: return "pink_magenta"
    if 0 <= hue < 65 and tone > 65 and chroma > 10: return "salmon_peach"
    if 15 <= hue < 65 and 58 <= tone <= 75 and chroma > 40: return "coral"
    if (hue >= 340 or hue < 15) and tone < 45 and 10 < chroma < 60: return "burgundy"
    return None


def m3(scheme):
    d = {r: getattr(scheme, r) for r in ROLES}
    d["background"] = d["surface"]
    t = TERTIARY
    if scheme.is_dark:
        d.update(tertiary=t.get(80), on_tertiary=t.get(20), tertiary_container=t.get(30), on_tertiary_container=t.get(90))
    else:
        d.update(tertiary=t.get(40), on_tertiary=t.get(100), tertiary_container=t.get(90), on_tertiary_container=t.get(10))
    d.update(tertiary_fixed=t.get(90), tertiary_fixed_dim=t.get(80), on_tertiary_fixed=t.get(10), on_tertiary_fixed_variant=t.get(30))
    return d


def ext_roles(dark: bool):
    out = {}
    for name, (hue, chroma) in EXT.items():
        p = TonalPalette(hue, chroma)
        if dark:
            out[name] = {"color": p.get(80), "on_color": p.get(20), "container": p.get(30), "on_container": p.get(90), "hue": hue}
        else:
            out[name] = {"color": p.get(40), "on_color": p.get(100), "container": p.get(90), "on_container": p.get(10), "hue": hue}
    return out


def error_roles(dark: bool):
    p = TonalPalette(ERROR_HUE, ERROR_CHROMA)
    if dark:
        return {"error": p.get(55), "on_error": p.get(5), "error_container": p.get(45), "on_error_container": p.get(100)}
    return {"error": p.get(40), "on_error": p.get(100), "error_container": p.get(35), "on_error_container": p.get(100)}


def mix_black(hex_, frac):
    r, g, b = int(hex_[1:3], 16), int(hex_[3:5], 16), int(hex_[5:7], 16)
    f = 1 - frac
    return "#%02x%02x%02x" % (round(r * f), round(g * f), round(b * f))


def build():
    t = theme_from_color(SEED, 0.0, Variant.TONALSPOT)
    themes = {}
    for name, scheme, dark in (("light", t.schemes.light, False), ("dark", t.schemes.dark, True)):
        roles = m3(scheme)
        roles.update(error_roles(dark))
        ext = ext_roles(dark)
        ext["hold"] = {"fill": mix_black(roles["error"], 0.30), "note": "30% black over m3.error: the whole background of a destructive control while it is held (its label and progress bar are on_error_container)"}
        themes[name] = {"m3": roles, "ext": ext}
    return themes


SURFACES = ["surface", "surface_container_lowest", "surface_container_low", "surface_container",
            "surface_container_high", "surface_container_highest"]


def design_pairs(theme: dict, dark: bool):
    """Every fg/bg pair the design uses (the mockup DOM audit adds any it finds)."""
    pairs = []
    def add(fg, bg, kind="text"):
        pairs.append((fg, bg, kind))
    for s in SURFACES + ["surface_dim", "surface_bright"]:
        add("m3.on_surface", f"m3.{s}")
    for s in SURFACES:
        add("m3.on_surface_variant", f"m3.{s}")
        add("m3.primary", f"m3.{s}")
        add("m3.outline", f"m3.{s}", "non-text")
    for role in ("primary", "secondary", "tertiary", "error"):
        add(f"m3.on_{role}", f"m3.{role}")
        add(f"m3.on_{role}_container", f"m3.{role}_container")
        add(f"m3.{role}", "m3.surface")
    add("m3.inverse_on_surface", "m3.inverse_surface")
    add("m3.inverse_primary", "m3.inverse_surface")
    add("m3.on_primary_fixed", "m3.primary_fixed")
    add("m3.on_primary_fixed_variant", "m3.primary_fixed")
    add("m3.on_secondary_fixed", "m3.secondary_fixed")
    add("m3.on_tertiary_fixed", "m3.tertiary_fixed")
    # error text is permitted on surface, lowest and low only (dark tone-55 red reaches ~4.4 on higher tiers)
    add("m3.error", "m3.surface_container_lowest")
    add("m3.error", "m3.surface_container_low")
    for s in ("surface_container", "surface_container_high", "surface_container_highest"):
        add("m3.error", f"m3.{s}", "non-text")
    # error containers are placed only on surface through surface_container (dark tone-45 red is < 3:1 above that)
    for s in ("surface", "surface_container_lowest", "surface_container_low", "surface_container"):
        add("m3.error_container", f"m3.{s}", "non-text")
    add("m3.on_error_container", "ext.hold.fill")            # the label of a held force control (the whole control is hold.fill while holding)
    add("m3.on_error_container", "ext.hold.fill", "non-text")  # its progress bar
    for role in EXT:
        add(f"ext.{role}.on_color", f"ext.{role}.color")
        add(f"ext.{role}.on_container", f"ext.{role}.container")
        for s in SURFACES:
            add(f"ext.{role}.color", f"m3.{s}")
            add(f"ext.{role}.color", f"m3.{s}", "non-text")
        add("m3.on_surface_variant", f"ext.{role}.container")
    return pairs


def resolve(theme, ref):
    tier, *rest = ref.split(".")
    node = theme[tier]
    for r in rest:
        node = node[r]
    return node


def main(check_only=False):
    themes = build()
    offenders = []
    for tn, th in themes.items():
        for tier, d in th.items():
            for k, v in (d.items() if tier == "m3" else [(f"{r}.{kk}", vv) for r, rr in d.items() for kk, vv in rr.items()]):
                if isinstance(v, str) and v.startswith("#"):
                    b = band(v)
                    if b:
                        offenders.append((tn, tier, k, v, b, [round(x, 1) for x in hct(v)]))
    print("palette offenders:", len(offenders))
    for o in offenders:
        print("  ", o)
    # ring hues: live, ok, error, primary (both themes)
    for tn, th in themes.items():
        hues = {"live": EXT["live"][0], "ok": EXT["ok"][0], "error": hct(th["m3"]["error"])[0], "primary": hct(th["m3"]["primary"])[0]}
        gaps = []
        for a, b in itertools.combinations(hues, 2):
            d = abs(hues[a] - hues[b]) % 360
            d = min(d, 360 - d)
            gaps.append((round(d, 1), a, b))
        print(tn, "ring hue min gap:", min(gaps), "hues:", {k: round(v, 1) for k, v in hues.items()})
    out = {
        "$schema_note": "amt-console design tokens, 2026-10-20. M3 TONAL_SPOT from the seed; the error palette is M3's error hue re-toned (light 40/100/35/100, dark 55/5/45/100) and the extended roles are own tonal palettes at the M3 custom-color tones, so that no value in either theme is pink, salmon, peach, coral or burgundy (see `predicates`). `pairs` lists every foreground/background pair the UI uses with its computed WCAG ratio; pairs with source=audit were found by walking the rendered mockups. Design artifact, not app code.",
        "seed": SEED, "variant": "TONAL_SPOT", "contrast_level": 0.0,
        "predicates": {
            "pink_magenta": {"rule": "HCT hue in [300,360) and chroma > 10, at any tone", "applies_to": "every color value, both themes, both tiers"},
            "salmon_peach": {"rule": "HCT hue in [0,65) and tone > 65 and chroma > 10", "applies_to": "every color value, both themes, both tiers"},
            "coral": {"rule": "HCT hue in [15,65) and 58 <= tone <= 75 and chroma > 40", "applies_to": "every color value, both themes, both tiers"},
            "burgundy": {"rule": "HCT hue >= 340 or < 15, tone < 45, 10 < chroma < 60", "applies_to": "every color value, both themes, both tiers"},
            "ring_hue_separation": {"rule": "the chromatic status roles live, ok, error and primary are pairwise >= 60 degrees apart in HCT hue (circular), both themes", "applies_to": "roles that paint a status ring, pill or chip"},
        },
    }
    for tn, th in themes.items():
        pairs = []
        for fg, bg, kind in design_pairs(th, tn == "dark"):
            fh, bh = resolve(th, fg), resolve(th, bg)
            ratio = round(get_contrast_ratio(fh, bh), 2)
            floor = 4.5 if kind == "text" else 3.0
            pairs.append({"fg": fg, "bg": bg, "fg_hex": fh, "bg_hex": bh, "min": floor, "kind": kind, "source": "design", "ratio": ratio, "pass": ratio >= floor})
        fails = [p for p in pairs if not p["pass"]]
        print(tn, "design pairs:", len(pairs), "below floor:", len(fails))
        for f in fails:
            print("   FAIL", f["fg"], f["bg"], f["ratio"], f["min"])
        out[tn] = {"m3": th["m3"], "ext": th["ext"], "pairs": pairs}
    out["overlay"] = {
        "scrim": "rgba(0,0,0,0.32)", "hatch": "rgba(0,0,0,0.45)",
        "shadow_key": "rgba(0,0,0,0.30)", "shadow_ambient": "rgba(0,0,0,0.15)",
        "live_pulse_low": "color-mix(in srgb, var(--ext-live-color) 55%, transparent)",
        "disabled_fg": "color-mix(in srgb, var(--md-sys-color-on-surface) 38%, transparent)",
        "note": "The only non-token color literals a mockup or the client may contain; the color-literal extractor allow-lists exactly these strings. disabled_fg is the M3 disabled label (on_surface at 38 %, WCAG-exempt); a disabled control keeps its outline at full alpha so the box can be found.",
    }
    out["typography"] = {
        "family": {"brand": "Roboto Flex, Roboto, system-ui, sans-serif", "plain": "Roboto, system-ui, sans-serif", "mono": "Roboto Mono, ui-monospace, Menlo, monospace"},
        "scale": {
            "display-small": {"size": 36, "line": 44, "weight": 400, "tracking": 0},
            "headline-large": {"size": 32, "line": 40, "weight": 400, "tracking": 0},
            "headline-medium": {"size": 28, "line": 36, "weight": 400, "tracking": 0},
            "headline-small": {"size": 24, "line": 32, "weight": 400, "tracking": 0},
            "title-large": {"size": 22, "line": 28, "weight": 400, "tracking": 0},
            "title-medium": {"size": 16, "line": 24, "weight": 500, "tracking": 0.15},
            "title-small": {"size": 14, "line": 20, "weight": 500, "tracking": 0.1},
            "body-large": {"size": 16, "line": 24, "weight": 400, "tracking": 0.5},
            "body-medium": {"size": 14, "line": 20, "weight": 400, "tracking": 0.25},
            "body-small": {"size": 12, "line": 16, "weight": 400, "tracking": 0.4},
            "label-large": {"size": 14, "line": 20, "weight": 500, "tracking": 0.1},
            "label-medium": {"size": 12, "line": 16, "weight": 500, "tracking": 0.5},
            "label-small": {"size": 11, "line": 16, "weight": 500, "tracking": 0.5},
            "data": {"size": 13, "line": 20, "weight": 400, "tracking": 0.2, "family": "mono", "note": "extended: fingerprints, addresses, hex, counts, next-boot flags; groups of 4 for a fingerprint"},
            "terminal": {"size": 14, "line": 20, "weight": 400, "tracking": 0, "family": "mono", "note": "extended: the serial terminal and log raw data; user-scalable 12-20"},
            "consequence": {"size": 16, "line": 24, "weight": 500, "tracking": 0.15, "note": "extended: the plain-words consequence line of every write confirmation; never smaller than body-large"},
        },
    }
    out["shape"] = {"none": 0, "extra-small": 4, "small": 8, "medium": 12, "large": 16, "extra-large": 28, "full": 9999,
                    "card": 12, "chip": 8, "server-card": 16, "sheet-top": 28, "force-control": 9999,
                    "note": "force-control (the hold-to-confirm destructive control) is the only pill with a text label among the action controls; everyday action buttons are 8 px (small) rounded rectangles, so a destructive control reads as different by shape alone."}
    out["elevation"] = {"level0": "none",
                        "level1": "0 1px 2px rgba(0,0,0,0.30), 0 1px 3px 1px rgba(0,0,0,0.15)",
                        "level2": "0 1px 2px rgba(0,0,0,0.30), 0 2px 6px 2px rgba(0,0,0,0.15)",
                        "level3": "0 1px 3px rgba(0,0,0,0.30), 0 4px 8px 3px rgba(0,0,0,0.15)",
                        "note": "Dark theme uses surface-container tiers for elevation; shadows only on menus, dialogs and the confirm sheet."}
    out["breakpoints"] = {"phone": "< 600 px: bottom navigation bar (Fleet, Manage, Images, Settings), server sections as a scrolling chip row, every panel a bottom sheet, server cards 1-up, tables card-per-row, no FAB (Add server in the app bar)",
                          "compact": "600-1099 px: navigation rail (icons + labels), server sections as tabs, cards 1-up below 840 and 2-up from 840 (a 2-up card at 600 is 232 px, too narrow for a key/value grid), tables in a horizontal scroller, the console view fills the width",
                          "full": ">= 1100 px: navigation rail, server header + tabs, 3-up cards; from 1440 the console and serial views keep a 360 px side panel (session, input, media)",
                          "note": "No horizontal page scroll at any width; 16 px side gutters; 328 px content at 360."}
    out["motion"] = {
        "duration": {"short2": 100, "short4": 200, "medium1": 250, "medium2": 300, "long2": 500,
                     "force-hold": 1200, "force-arm": 400, "sheet-open": 300, "sheet-close": 200, "live-pulse": 1500, "state-settle": 200},
        "easing": {"standard": "cubic-bezier(0.2, 0, 0, 1)", "emphasized-decelerate": "cubic-bezier(0.05, 0.7, 0.1, 1)", "emphasized-accelerate": "cubic-bezier(0.3, 0, 0.8, 0.15)", "linear": "linear"},
        "named": ["live-pulse", "force-hold", "sheet-open", "sheet-close", "state-settle", "progress"],
        "reduced_motion": "Every named animation resolves to animation-name: none and transition-duration: 0s under prefers-reduced-motion: reduce; elements carrying one declare it in data-motion (sheets carry sheet-open). The force hold keeps its 1200 ms (a safety delay), paints the whole control hold.fill and shows a 3-2-1 countdown instead of the progress bar.",
    }
    out["states"] = {
        "power": {
            "on": {"pill": "ext.ok.container / ext.ok.on_container", "icon": "power", "label": "On"},
            "sleep": {"pill": "m3.tertiary_container / m3.on_tertiary_container", "icon": "bedtime", "label": "Sleep"},
            "hibernate": {"pill": "m3.tertiary_container / m3.on_tertiary_container", "icon": "bedtime", "label": "Hibernate"},
            "off": {"pill": "m3.surface_container_highest / m3.on_surface, outline ring", "icon": "power_off", "label": "Off"},
            "unknown": {"pill": "m3.surface_container_highest / m3.on_surface_variant, dashed outline", "icon": "help", "label": "Unknown"},
            "unreachable": {"pill": "m3.error_container / m3.on_error_container", "icon": "cloud_off", "label": "Unreachable"},
        },
        "session": {
            "free": {"chip": "m3.surface_container_highest, outline", "icon": "lock_open", "label": "KVM free"},
            "held_console": {"chip": "ext.live.container / ext.live.on_container", "icon": "cast", "label": "KVM · you (console) · since <t>"},
            "held_agent": {"chip": "ext.live.container / ext.live.on_container", "icon": "smart_toy", "label": "KVM · agent via mirror · since <t>"},
            "held_other": {"chip": "m3.error_container / m3.on_error_container", "icon": "lock", "label": "KVM · another client · opens refused"},
            "consent_pending": {"chip": "ext.live.container", "icon": "pin", "label": "consent code pending on the host"},
            "recording": {"chip": "ext.live.container", "icon": "fiber_manual_record", "label": "recording <mm:ss>", "motion": "live-pulse"},
        },
        "write": {
            "idle": {"label": "<action>"},
            "confirming": {"sheet": "consequence line + Confirm", "label": "Confirm <action>"},
            "destructive_confirming": {"sheet": "consequence line + hold-to-confirm (force-control)", "label": "Hold to <action>"},
            "sending": {"icon": "progress_activity", "label": "Sending…", "motion": "progress"},
            "accepted": {"chip": "ext.ok.container", "icon": "check", "label": "Accepted · ReturnValue 0 · readback <state>"},
            "readback_unavailable": {"chip": "ext.live.container", "icon": "schedule", "label": "Accepted · readback unavailable"},
            "refused": {"chip": "m3.error_container / m3.on_error_container", "icon": "block", "label": "Refused · <tool reason verbatim> · nothing sent"},
            "failed": {"chip": "m3.error_container", "icon": "error", "label": "Failed · <error> "},
        },
        "pin": {
            "matches": {"chip": "ext.ok.container", "icon": "verified", "label": "pin matches"},
            "mismatch": {"chip": "m3.error_container", "icon": "gpp_bad", "label": "presented leaf differs · refused"},
            "unpinned": {"chip": "m3.error_container", "icon": "gpp_bad", "label": "no pin · refused"},
            "unchecked": {"chip": "m3.surface_container_highest, dashed outline", "icon": "help", "label": "not checked yet"},
        },
        "identity": {
            "present_synced": {"chip": "ext.ok.container", "icon": "key", "label": "present · synced from the main vault"},
            "present_entered": {"chip": "ext.ok.container", "icon": "key", "label": "present · entered here"},
            "present_unused": {"chip": "ext.ok.container", "icon": "key", "label": "present · unused (removable)"},
            "intake_minted": {"chip": "ext.live.container", "icon": "schedule", "label": "intake minted · expires in <mm:ss> · value not received yet"},
            "missing": {"chip": "m3.error_container", "icon": "key_off", "label": "missing · every call to <server> fails"},
        },
        "fleet_poll": {
            "live": {"label": "status read <n> s ago · next in 30 s"},
            "paused": {"chip": "m3.error_container", "icon": "block", "label": "paused · credential refused (wsman_auth_failed_401 or pin mismatch); no further attempts until the identity is replaced or Retry once"},
        },
        "image": {
            "free": {"label": "<name> · Mount, Verify, Rename, Delete"},
            "mounted": {"chip": "ext.live.container", "icon": "album", "label": "mounted on <server> · Rename and Delete refused"},
            "downloading": {"label": "<percent> · sha256 checked on completion · Rename and Delete refused"},
            "uploading": {"label": "<bytes> of <size> · exact size and sha256 checked when the PUT ends · Rename and Delete refused"},
            "verified": {"chip": "ext.ok.container", "icon": "verified", "label": "verified <time>"},
        },
        "mirror_owner": {
            "console": {"stop": "plain confirm"},
            "agent": {"stop": "force control: stopping it ends the session under the agent's call"},
            "in_flight": {"strip": "AGENT TYPING · your keys and mouse are paused until its call returns", "stop": "force control"},
        },
        "capture": {
            "fetching": {"label": "fetching once from amt-mcp…"},
            "ready": {"icon": "verified", "label": "sha256 verified · saved to the capture store"},
            "expired": {"chip": "m3.error_container", "icon": "timer_off", "label": "expired · the one-time link was not fetched within 15 minutes"},
        },
    }
    if check_only:
        return
    with open(OUT, "w") as fh:
        json.dump(out, fh, indent=1)
    print("wrote", OUT)


if __name__ == "__main__":
    main("--check-only" in sys.argv)
