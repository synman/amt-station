"""The theme layer is generated from design/tokens.json (immutable 16: every token in both themes), the contrast and
hue immutables the token script owns (1, 2, 3), and no color literal outside the tokens in the built CSS (17)."""
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

import make_theme
from console_fakes import check_mockups

REPO = Path(make_theme.__file__).resolve().parent.parent
TOKENS = json.loads((REPO / "design" / "tokens.json").read_text())
CONSOLE = Path(make_theme.__file__).resolve().parent


load_check_mockups = check_mockups


# -- the CSS is the tokens ------------------------------------------------------------------------------------------

def test_theme_css_is_what_the_tokens_produce():
    assert make_theme.main(["--check"]) == 0


def test_a_token_edit_without_regenerating_turns_the_check_red(tmp_path, monkeypatch, capsys):
    edited = json.loads(json.dumps(TOKENS))
    edited["light"]["m3"]["primary"] = "#123456"
    path = tmp_path / "tokens.json"
    path.write_text(json.dumps(edited))
    monkeypatch.setattr(make_theme, "TOKENS", path)
    assert make_theme.main(["--check"]) == 1 and "not what design/tokens.json produces" in capsys.readouterr().out


def test_every_token_is_emitted_for_both_themes_with_its_tokens_value():
    css = (CONSOLE / "static" / "theme.css").read_text()
    blocks = re.findall(r"(:root[^{]*)\{([^}]*)\}", css)
    by_selector = {sel.strip(): dict(re.findall(r"(--[a-z0-9-]+):\s*([^;]+);", body)) for sel, body in blocks}
    light = by_selector[':root, :root[data-theme="light"]']
    dark = by_selector[':root:not([data-theme="light"])']
    assert dark == by_selector[':root[data-theme="dark"]']
    for name, theme in (("light", light), ("dark", dark)):
        for role, value in TOKENS[name]["m3"].items():
            assert theme[f"--md-sys-color-{role.replace('_', '-')}"] == value, (name, role)
        for ext in ("live", "ok"):
            for key, value in TOKENS[name]["ext"][ext].items():
                if key != "hue":
                    assert theme[f"--ext-{ext}-{key.replace('_', '-')}"] == value, (name, ext, key)
        assert theme["--ext-hold-fill"] == TOKENS[name]["ext"]["hold"]["fill"]
    assert "prefers-color-scheme: dark" in css and "color-scheme: light" in css and "color-scheme: dark" in css


def test_every_color_token_has_a_light_and_a_dark_value():
    assert set(TOKENS["light"]["m3"]) == set(TOKENS["dark"]["m3"])
    assert set(TOKENS["light"]["ext"]) == set(TOKENS["dark"]["ext"])
    for theme in ("light", "dark"):
        assert all(re.fullmatch(r"#[0-9a-f]{6}", v) for v in TOKENS[theme]["m3"].values())
        for role in ("live", "ok"):
            assert {"color", "on_color", "container", "on_container"} <= set(TOKENS[theme]["ext"][role])


# -- immutable 1: every listed pair recomputed from its hex ---------------------------------------------------------

def luminance(hex_):
    def f(v):
        v /= 255
        return v / 12.92 if v <= 0.03928 else ((v + 0.055) / 1.055) ** 2.4
    r, g, b = (int(hex_[i:i + 2], 16) for i in (1, 3, 5))
    return 0.2126 * f(r) + 0.7152 * f(g) + 0.0722 * f(b)


def ratio(a, b):
    la, lb = sorted((luminance(a), luminance(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


@pytest.mark.parametrize("theme", ["light", "dark"])
def test_every_recorded_contrast_pair_recomputes_from_its_hex_and_clears_its_floor(theme):
    pairs = TOKENS[theme]["pairs"]
    assert len(pairs) >= 90
    for p in pairs:
        got = ratio(p["fg_hex"], p["bg_hex"])
        assert abs(got - p["ratio"]) < 0.011, p
        assert got >= p["min"] - 0.005 and p["pass"] is True, p
    for p in pairs:                                       # and the hexes are the theme's own tokens
        for side in ("fg", "bg"):
            tier, *rest = p[side].split(".")
            node = TOKENS[theme][tier]
            for r in rest:
                node = node[r]
            assert node == p[f"{side}_hex"], p


def test_a_wrong_recorded_ratio_would_be_caught():
    """Positive control for the check above: a pair edited to a ratio its hexes do not give is detected."""
    p = dict(TOKENS["light"]["pairs"][0])
    p["ratio"] = round(p["ratio"] + 1, 2)
    assert abs(ratio(p["fg_hex"], p["bg_hex"]) - p["ratio"]) >= 0.011


# -- immutables 2 and 3 need material-color-utilities (design/requirements.txt), which the main venv lacks ----------

def run_token_script():
    env = dict(os.environ)
    extra = os.environ.get("AMT_MCU_PATH")
    if extra:
        env["PYTHONPATH"] = extra + os.pathsep + env.get("PYTHONPATH", "")
    probe = subprocess.run([sys.executable, "-c", "import material_color_utilities"], env=env, capture_output=True)
    if probe.returncode:
        pytest.skip("material_color_utilities is not importable here: immutables 2 and 3 (HCT bands, ring hues) are NOT "
                    "checked by this run; set AMT_MCU_PATH to a pip --target of design/requirements.txt to run them")
    return subprocess.run([sys.executable, str(REPO / "design" / "make_tokens.py"), "--check-only"], env=env,
                          capture_output=True, text=True, timeout=300)


def test_the_token_script_finds_no_forbidden_hue_and_separated_ring_hues():
    out = run_token_script()
    assert out.returncode == 0, out.stderr[-500:]
    text = out.stdout
    assert "palette offenders: 0" in text
    gaps = re.findall(r"ring hue min gap: \(([0-9.]+),", text)
    assert len(gaps) == 2 and all(float(g) >= 60 for g in gaps), text
    below = re.findall(r"design pairs: \d+ below floor: (\d+)", text)
    assert below == ["0", "0"], text


# -- immutable 17: no color literal outside the tokens ----------------------------------------------------------------

def test_the_built_client_has_no_color_literal_outside_the_tokens_and_overlays():
    cm = load_check_mockups()
    files = sorted((CONSOLE / "static").glob("*.css")) + sorted((CONSOLE / "pages").glob("*.html")) + sorted((CONSOLE / "static").glob("*.js"))
    assert len(files) >= 8
    for f in files:
        assert cm.literal_check(str(f)) == [], f.name


def test_the_literal_extractor_reports_a_planted_color_exactly_once(tmp_path):
    cm = load_check_mockups()
    planted = tmp_path / "x.css"
    planted.write_text("a { color: #123456; } b { color: var(--md-sys-color-primary); background: rgba(0,0,0,0.32); }")
    assert cm.literal_check(str(planted)) == ["#123456"]
