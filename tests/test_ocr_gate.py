"""The OCR gate's pure logic and backend plumbing, on hand-written fragments and mocked
subprocess/import seams. No recognizer runs here; ``test_screen_context_real_frames.py`` runs the
real ones on real frames.

The fragment coordinates in ``SIGNIN`` are the ones measured on the real 1280x800 sign-in
frames (tile centre x 0.50, field centre x 0.41, field 0.07 of the height below the tile).
"""
import subprocess
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import amt_tools  # noqa: E402
from amt_tools import Fragment  # noqa: E402
from frames import desktop_shot, signin_shot  # noqa: E402

# Structurally right frames for each tool; the recognizer is replaced, so the fragments decide.
LOGON_FRAME, LOGOFF_FRAME = signin_shot(), desktop_shot()

SIGNIN = [Fragment("jdoe", 0.50, 0.50), Fragment("Password", 0.41, 0.58)]


def gate(frags, *, desktop=False, user="jdoe"):
    """``_screen_problem`` (the gate both tools use, which delegates to ``classify_screen``) over
    a structurally valid frame and a recognizer that returns ``frags``."""
    shot = LOGOFF_FRAME if desktop else LOGON_FRAME
    orig = amt_tools.ocr_fragments
    amt_tools.ocr_fragments = lambda fb, w, h: ("t", frags)
    try:
        return amt_tools._screen_problem(shot.fb, shot.width, shot.height, desktop=desktop, user=user)
    finally:
        amt_tools.ocr_fragments = orig


# --- signin_signals -----------------------------------------------------------------------

def test_the_real_signin_layout_is_identified():
    assert amt_tools.signin_signals(SIGNIN, "jdoe") == (True, True, True)


@pytest.mark.parametrize("user", ["jdoe", "JDOE", "MY-SERVER-1\\jdoe", " jdoe "])
def test_the_account_name_is_matched_as_the_tile_spells_it(user):
    assert amt_tools.signin_signals(SIGNIN, user)[2] is True


@pytest.mark.parametrize("name,frags", [
    ("another account", [Fragment("other", 0.50, 0.50), Fragment("Password", 0.41, 0.58)]),
    ("substring of a longer word", [Fragment("jdoesmith", 0.50, 0.50), Fragment("Password", 0.41, 0.58)]),
    ("tile at the console's left margin", [Fragment("jdoe", 0.04, 0.50), Fragment("Password", 0.04, 0.58)]),
    ("bare console prompt line", [Fragment("jdoe", 0.50, 0.50), Fragment("Password:", 0.41, 0.58)]),
    ("field ABOVE the tile", [Fragment("jdoe", 0.50, 0.58), Fragment("Password", 0.41, 0.50)]),
    ("field too far below", [Fragment("jdoe", 0.50, 0.20), Fragment("Password", 0.41, 0.80)]),
    ("tile only", [Fragment("jdoe", 0.50, 0.50)]),
    ("field only", [Fragment("Password", 0.41, 0.58)]),
    ("field is a sentence, not the placeholder", [Fragment("jdoe", 0.50, 0.50),
                                                  Fragment("Enter your password now", 0.41, 0.58)]),
    ("nothing", []),
])
def test_anything_short_of_a_centred_tile_with_a_password_field_below_it_is_not_the_signin(name, frags):
    assert amt_tools.signin_signals(frags, "jdoe")[2] is False, name


def test_an_empty_account_name_matches_nothing():
    assert amt_tools.signin_signals(SIGNIN + [Fragment("", 0.5, 0.5)], "")[2] is False
    assert amt_tools.signin_signals(SIGNIN, "DOMAIN\\")[2] is False


# --- foreign markers and sign-in furniture ---------------------------------------------------

@pytest.mark.parametrize("text", ["ubuntu-server login:", "Login", "GNU GRUB version 2.06", "UEFI Shell",
                                  "BIOS Setup", "Linux version 6.1", "tty1", "Debian GNU/Linux 12",
                                  "Kernel panic", "Ubuntu 22.04.3 LTS"])
def test_foreign_markers_are_found(text):
    assert amt_tools.foreign_marker_found([Fragment(text, 0.1, 0.1)]) is True


@pytest.mark.parametrize("text", ["jdoe", "Password", "Sign-in options", "10:42", "Sunday, October 18",
                                  "Recycle Bin", "Search", "10/18/2026"])
def test_windows_text_carries_no_foreign_marker(text):
    assert amt_tools.foreign_marker_found([Fragment(text, 0.5, 0.5)]) is False


def test_signin_furniture_is_a_centred_password_field_or_the_options_link():
    assert amt_tools.signin_screen_marker(SIGNIN) is True
    assert amt_tools.signin_screen_marker([Fragment("Sign-in options", 0.5, 0.8)]) is True
    assert amt_tools.signin_screen_marker([Fragment("Sign in options", 0.5, 0.8)]) is True
    assert amt_tools.signin_screen_marker([Fragment("Password", 0.05, 0.5)]) is False   # not centred
    assert amt_tools.signin_screen_marker([Fragment("Recycle Bin", 0.04, 0.1)]) is False


# --- _ocr_gate: every non-identification is a refusal ------------------------------------------

def test_gate_identifies_the_signin_for_logon_and_returns_findings_only():
    reason, detail = gate(SIGNIN)
    assert reason is None
    assert detail == {"screen_label": "windows-signin", "ocr_backend": "t", "foreign_markers": False,
                      "user_tile": True, "password_field": True}


@pytest.mark.parametrize("frags,reason", [
    ([], "ocr_no_text"),
    ([Fragment("10:42", 0.5, 0.2)], "signin_not_identified"),
    (SIGNIN + [Fragment("ubuntu-server login:", 0.1, 0.1)], "foreign_console_detected"),
])
def test_gate_refuses_logon_unless_identified(frags, reason):
    assert gate(frags)[0] == reason


def test_gate_foreign_marker_vetoes_even_a_perfect_signin_match():
    reason, detail = gate(SIGNIN + [Fragment("GRUB", 0.2, 0.2)])
    assert reason == "foreign_console_detected" and detail["foreign_markers"] is True


@pytest.mark.parametrize("frags,reason", [
    ([Fragment("Recycle Bin", 0.04, 0.1), Fragment("02:19", 0.95, 0.95)], None),
    ([Fragment("garbled ~ ¢ Ci", 0.5, 0.5)], None),               # OCR noise alone must not abort a desktop
    (SIGNIN, "signin_screen_detected"),
    ([Fragment("Sign-in options", 0.5, 0.8)], "signin_screen_detected"),
    ([Fragment("kali login:", 0.1, 0.1)], "foreign_console_detected"),
    ([], "ocr_no_text"),
])
def test_gate_logoff_needs_text_and_neither_a_console_nor_signin_furniture(frags, reason):
    assert gate(frags, desktop=True)[0] == reason


def test_gate_with_no_backend_is_ocr_unavailable_with_no_backend_named(monkeypatch):
    def raiser(fb, w, h):
        raise amt_tools.OcrUnavailable("no_ocr_backend")
    monkeypatch.setattr(amt_tools, "ocr_fragments", raiser)
    for desktop in (False, True):
        shot = LOGOFF_FRAME if desktop else LOGON_FRAME
        assert amt_tools._screen_problem(shot.fb, shot.width, shot.height, desktop=desktop, user="jdoe") == \
            ("ocr_unavailable", {"screen_label": "unknown", "ocr_backend": None})


@pytest.mark.parametrize("exc", [RuntimeError("boom"), OSError("x"), amt_tools.OcrError("screen_unreadable"),
                                 subprocess.TimeoutExpired("tesseract", 30), ValueError("v")])
def test_gate_treats_any_recognizer_error_as_a_refusal(monkeypatch, exc):
    def raiser(fb, w, h):
        raise exc
    monkeypatch.setattr(amt_tools, "ocr_fragments", raiser)
    assert amt_tools._screen_problem(LOGON_FRAME.fb, LOGON_FRAME.width, LOGON_FRAME.height,
                                     desktop=False, user="jdoe")[0] == "ocr_failed"


def test_screen_problem_runs_the_structural_prefilter_before_recognition(monkeypatch):
    calls = []
    monkeypatch.setattr(amt_tools, "ocr_fragments", lambda fb, w, h: calls.append(1) or ("t", SIGNIN))
    assert amt_tools._screen_problem(bytes(640 * 480 * 3), 640, 480, desktop=False, user="jdoe") == \
        ("not_windows_resolution", {})
    assert calls == []


# --- ocr_fragments: backend order and fail-closed dispatch -----------------------------------------

def test_no_backends_is_unavailable(monkeypatch):
    monkeypatch.setattr(amt_tools, "OCR_BACKENDS", ())
    with pytest.raises(amt_tools.OcrUnavailable):
        amt_tools.ocr_fragments(bytes(4 * 4 * 3), 4, 4)


def test_every_backend_missing_is_unavailable(monkeypatch):
    def missing(fb, w, h):
        raise amt_tools.OcrUnavailable("x")
    monkeypatch.setattr(amt_tools, "OCR_BACKENDS", (("a", missing), ("b", missing)))
    with pytest.raises(amt_tools.OcrUnavailable):
        amt_tools.ocr_fragments(bytes(4 * 4 * 3), 4, 4)


def test_a_missing_backend_falls_through_to_the_next_in_order(monkeypatch):
    def missing(fb, w, h):
        raise amt_tools.OcrUnavailable("x")
    monkeypatch.setattr(amt_tools, "OCR_BACKENDS", (("a", missing), ("b", lambda fb, w, h: [SIGNIN[0]])))
    assert amt_tools.ocr_fragments(bytes(4 * 4 * 3), 4, 4) == ("b", [SIGNIN[0]])


def test_a_backend_that_is_installed_but_fails_is_not_papered_over(monkeypatch):
    def broken(fb, w, h):
        raise RuntimeError("installed but failing")
    second = []
    monkeypatch.setattr(amt_tools, "OCR_BACKENDS", (("a", broken), ("b", lambda fb, w, h: second.append(1) or [])))
    with pytest.raises(RuntimeError):
        amt_tools.ocr_fragments(bytes(4 * 4 * 3), 4, 4)
    assert second == []


@pytest.mark.parametrize("fb,w,h", [(None, 4, 4), (b"\x00" * 5, 4, 4), (bytes(48), 0, 4)])
def test_an_unreadable_frame_is_an_error_not_an_empty_reading(fb, w, h):
    with pytest.raises(amt_tools.OcrError):
        amt_tools.ocr_fragments(fb, w, h)


def test_the_real_backend_order_is_ocrmac_then_tesseract():
    assert [n for n, _ in amt_tools.OCR_BACKENDS] == ["ocrmac", "tesseract"]


# --- the tesseract backend's plumbing (subprocess mocked) -----------------------------------------

TSV_HEAD = "level\tpage_num\tblock_num\tpar_num\tline_num\tword_num\tleft\ttop\twidth\theight\tconf\ttext"


def _tsv(*rows):
    return (TSV_HEAD + "\n" + "\n".join("\t".join(map(str, r)) for r in rows) + "\n").encode()


def test_tesseract_missing_binary_is_unavailable(monkeypatch):
    monkeypatch.setattr(amt_tools.shutil, "which", lambda name: None)
    with pytest.raises(amt_tools.OcrUnavailable, match="tesseract_missing"):
        amt_tools._ocr_tesseract(bytes(4 * 4 * 3), 4, 4)


def test_tesseract_runs_without_a_shell_and_normalizes_boxes_to_the_frame(monkeypatch):
    seen = {}

    def fake_run(cmd, **kw):
        seen["cmd"], seen["kw"] = cmd, kw
        # frame is 100x50, upscaled x2 -> 200x100: a word at left 40 top 20 w 40 h 20
        return subprocess.CompletedProcess(cmd, 0, _tsv(
            (5, 1, 1, 1, 1, 1, 40, 20, 40, 20, 96, "jdoe"),
            (5, 1, 1, 1, 1, 2, 10, 10, 10, 10, 12, "noise"),          # below the confidence floor
            (5, 1, 1, 1, 1, 3, 10, 10, 10, 10, 99, "  "),             # blank text
            (4, 1, 1, 1, 1, 0, 0, 0, 5, 5, "-1", ""),                 # a layout row
        ), b"")
    monkeypatch.setattr(amt_tools.shutil, "which", lambda name: "/usr/bin/tesseract")
    monkeypatch.setattr(amt_tools.subprocess, "run", fake_run)
    frags = amt_tools._ocr_tesseract(bytes(100 * 50 * 3), 100, 50)
    assert frags == [Fragment("jdoe", 0.3, 0.3)]
    assert isinstance(seen["cmd"], list) and seen["cmd"][0] == "/usr/bin/tesseract"
    assert seen["kw"].get("shell") in (None, False) and seen["kw"]["timeout"] == amt_tools.TESSERACT_TIMEOUT
    assert seen["kw"]["input"].startswith(b"\x89PNG")


def test_tesseract_nonzero_exit_is_an_error(monkeypatch):
    monkeypatch.setattr(amt_tools.shutil, "which", lambda name: "/usr/bin/tesseract")
    monkeypatch.setattr(amt_tools.subprocess, "run",
                        lambda cmd, **kw: subprocess.CompletedProcess(cmd, 1, b"", b"boom"))
    with pytest.raises(amt_tools.OcrError, match="tesseract_failed"):
        amt_tools._ocr_tesseract(bytes(4 * 4 * 3), 4, 4)


def test_ocrmac_and_tesseract_without_pillow_are_unavailable(monkeypatch):
    monkeypatch.setitem(sys.modules, "PIL", None)               # makes `from PIL import Image` raise ImportError
    monkeypatch.setattr(amt_tools.shutil, "which", lambda name: "/usr/bin/tesseract")
    with pytest.raises(amt_tools.OcrUnavailable, match="pillow_missing"):
        amt_tools._ocr_tesseract(bytes(4 * 4 * 3), 4, 4)
    monkeypatch.setitem(sys.modules, "ocrmac", None)
    with pytest.raises(amt_tools.OcrUnavailable, match="ocrmac_missing"):
        amt_tools._ocr_ocrmac(bytes(4 * 4 * 3), 4, 4)
