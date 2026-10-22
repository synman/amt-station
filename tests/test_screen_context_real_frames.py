"""The screen-context detectors, grounded on REAL console captures (offline: PNGs decoded to the
RGB framebuffer ``KvmSession.fb`` holds, no host, no socket, neither tool run live).

These replace whole-frame 0/255 fills as the evidence that the taskbar and geometry gates read
what they claim to read. Each frame is classified by what it actually SHOWS (checked by eye when
this file was written), not by its file name; a capture that no longer exists is skipped with its
path in the reason (``pytest -rs``), never replaced by an invented one.

Calibration read from these frames (1280x800): a Windows taskbar shows a horizontal edge over
94-100% of the sampled columns, a sign-in or lock wallpaper at most 3%, so the 85% gate has a
wide margin each side.

The positive gate is grounded here too, with the REAL recognizers (no OCR fake): the sign-in
frames carry the account tile with a "Password" field below it; the lock frames carry a
clock and a date; the desktop frames a tray clock and date. Both backends (ocrmac and tesseract)
are asserted separately, since the container only ever has tesseract. Most console frames
here are SYNTHETIC (text genuinely rendered with PIL in a console layout, then read by the real
recognizer); the real Debian tty frames are in ``tests/real_frames/`` and the local frames below.
"""
import hashlib
import json
import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import amt_kvm  # noqa: E402,F401  (test_composite_tools' fixtures patch it)
import amt_tools  # noqa: E402
from frames import decode_png, rendered_text_shot, run_dialog_shot  # noqa: E402
# Reuse the mocked engine, vault and WS-MAN doubles and the autouse fixture of the composite tests.
from test_composite_tools import (FakeKvm, LOG, VAULT, WIN, R, WIN_PW, env, inputs,  # noqa: E402,F401
                                  assert_aborted_typing_nothing)

REAL_OCR = amt_tools.ocr_fragments      # captured before any fixture swaps in the fake
# The Windows frames are not in the repo (they show an account): AMT_LOCAL_FRAMES names a local folder
# holding them, and AMT_LOCAL_FRAMES_USER the account their sign-in tile shows. Unset, those tests skip.
REAL_USER = os.environ.get("AMT_LOCAL_FRAMES_USER", "jdoe")
_OCR_CACHE: dict = {}


def _ocr_backend_usable(name: str) -> bool:
    run = dict(amt_tools.OCR_BACKENDS)[name]
    try:
        run(bytes(64 * 64 * 3), 64, 64)
        return True
    except amt_tools.OcrUnavailable:
        return False


BACKENDS = [pytest.param(name, id=name, marks=pytest.mark.skipif(
    not _ocr_backend_usable(name), reason=f"OCR backend not installed on this node: {name}"))
    for name, _ in amt_tools.OCR_BACKENDS]
needs_any_ocr = pytest.mark.skipif(
    not any(_ocr_backend_usable(n) for n, _ in amt_tools.OCR_BACKENDS),
    reason="no OCR backend usable on this node (ocrmac, or tesseract + Pillow)")


def _cached_real_ocr(fb, width, height):
    key = (width, height, hashlib.sha1(bytes(fb)).hexdigest())
    if key not in _OCR_CACHE:
        _OCR_CACHE[key] = REAL_OCR(fb, width, height)
    return _OCR_CACHE[key]


@pytest.fixture(autouse=True)
def real_ocr(env, monkeypatch):
    """The composite-tool fake is replaced by the real recognizers, and the vaulted account is the
    one the real sign-in frames show."""
    monkeypatch.setattr(amt_tools, "ocr_fragments", _cached_real_ocr)
    monkeypatch.setitem(VAULT, "my-server-1-os", json.dumps({"user": REAL_USER, "password": WIN_PW}))


def _read(name: str, shot):
    """Fragments from ONE named backend (bypasses the ordered dispatch)."""
    return dict(amt_tools.OCR_BACKENDS)[name](shot.fb, shot.width, shot.height)

SCRATCH = SHOTS = Path(os.environ.get("AMT_LOCAL_FRAMES") or "/nonexistent-amt-local-frames")

# (id, path, what the frame actually shows)
REAL_FRAMES = [
    ("desktop_windows_kvm", SCRATCH / "windows_kvm.png", "desktop"),
    ("desktop_docker_shot_562", SHOTS / "shot-1792332562.png", "desktop"),
    # Briefed as a taskbar desktop, but the capture is the lock-screen clock (no taskbar).
    ("lock_windows_restored", SCRATCH / "windows_restored.png", "lock"),
    ("lock_shot_419", SHOTS / "shot-1792332419.png", "lock"),
    ("signin_shot_557", SHOTS / "shot-1792332557.png", "signin"),
    ("signin_shot_425", SHOTS / "shot-1792332425.png", "signin"),
    ("bios_setup", SCRATCH / "bios_setup.png", "bios"),
]


def _params(kinds):
    return [pytest.param(p, kind, id=i, marks=pytest.mark.skipif(
        not p.exists(), reason=f"real frame missing, not replaced: {p}"))
        for i, p, kind in REAL_FRAMES if kind in kinds]


ALL = _params({"desktop", "lock", "signin", "bios"})
DESKTOPS = _params({"desktop"})
NO_TASKBAR_WINDOWS = _params({"lock", "signin"})
SIGNINS = _params({"signin"})
BIOS = _params({"bios"})


# --- the detector verdicts on real frames ------------------------------------------------

@pytest.mark.parametrize("path,kind", ALL)
def test_detector_verdicts_on_the_real_frame(path, kind):
    shot = decode_png(path)
    assert (shot.width, shot.height) == ((640, 480) if kind == "bios" else (1280, 800))
    assert amt_tools.windows_geometry(shot.width, shot.height) is (kind != "bios")
    assert amt_tools.taskbar_present(shot.fb, shot.width, shot.height) is (kind == "desktop")
    assert amt_tools.frame_is_blank(shot.fb, shot.width, shot.height) is False


@pytest.mark.parametrize("path,kind", DESKTOPS)
def test_a_real_desktop_is_wrong_for_logon_and_right_for_logoff(path, kind):
    s = decode_png(path)
    assert amt_tools._context_problem(s.fb, s.width, s.height, desktop=False) == "host_already_logged_in"
    assert amt_tools._context_problem(s.fb, s.width, s.height, desktop=True) is None


@pytest.mark.parametrize("path,kind", NO_TASKBAR_WINDOWS)
def test_a_real_signin_or_lock_screen_is_right_for_logon_and_wrong_for_logoff(path, kind):
    s = decode_png(path)
    assert amt_tools._context_problem(s.fb, s.width, s.height, desktop=False, check_blank=True) is None
    assert amt_tools._context_problem(s.fb, s.width, s.height, desktop=True) == "no_desktop_taskbar"


@pytest.mark.parametrize("path,kind", BIOS)
def test_a_real_bios_frame_fails_the_geometry_gate_for_both_tools(path, kind):
    s = decode_png(path)
    for desktop in (False, True):
        assert amt_tools._context_problem(s.fb, s.width, s.height, desktop=desktop) == "not_windows_resolution"


# --- classify_screen on the real frames --------------------------------------------------

EXPECTED_LABEL = {"desktop": "desktop", "lock": "lock", "signin": "windows-signin", "bios": "bios-setup"}


@needs_any_ocr
@pytest.mark.parametrize("path,kind", ALL)
def test_classify_screen_labels_the_real_frame(path, kind):
    s = decode_png(path)
    cls = amt_tools.classify_screen(s, REAL_USER)
    assert cls["label"] == EXPECTED_LABEL[kind]
    assert amt_tools.classify_screen(path.read_bytes(), REAL_USER)["label"] == EXPECTED_LABEL[kind], "PNG input"


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("path,kind", ALL)
def test_classify_screen_labels_the_real_frame_for_each_backend(backend, path, kind, monkeypatch):
    run = dict(amt_tools.OCR_BACKENDS)[backend]
    monkeypatch.setattr(amt_tools, "ocr_fragments", lambda fb, w, h: (backend, run(fb, w, h)))
    cls = amt_tools.classify_screen(decode_png(path), REAL_USER)
    assert cls["label"] == EXPECTED_LABEL[kind]
    if kind != "bios":
        assert cls["markers"]["ocr_backend"] == backend


@needs_any_ocr
@pytest.mark.parametrize("path,kind", ALL)
def test_the_real_frame_markers_hold_findings_only(path, kind):
    blob = json.dumps(amt_tools.classify_screen(decode_png(path), REAL_USER))
    for text in ("Sunday", "October", "Recycle", "10/18/2026", "Password", REAL_USER):
        assert text not in blob


@needs_any_ocr
@pytest.mark.parametrize("path,kind", DESKTOPS)
def test_a_real_desktop_with_a_hidden_taskbar_is_unknown_not_a_lock_screen(path, kind, monkeypatch):
    """Its tray clock and date are real text, but they sit in the corner the lock rule excludes."""
    monkeypatch.setattr(amt_tools, "taskbar_present", lambda fb, w, h: False)
    assert amt_tools.classify_screen(decode_png(path), REAL_USER)["label"] == "unknown"


@needs_any_ocr
@pytest.mark.parametrize("path,kind", SIGNINS)
def test_a_real_signin_frame_with_a_forced_taskbar_is_never_a_desktop(path, kind, monkeypatch):
    """The sign-in furniture vetoes `desktop` whatever the taskbar detector claims. (A lock frame
    with a forced taskbar is NOT asserted: the classifier trusts the taskbar detector and has no
    text rule that contradicts it.)"""
    monkeypatch.setattr(amt_tools, "taskbar_present", lambda fb, w, h: True)
    assert amt_tools.classify_screen(decode_png(path), REAL_USER)["label"] != "desktop"


# --- the whole tools fed those real frames -----------------------------------------------

@needs_any_ocr
@pytest.mark.parametrize("path,kind", DESKTOPS)
def test_logon_on_a_real_desktop_is_a_no_op_success_that_types_nothing(path, kind):
    """The operator's directive: a recognized context is HANDLED. The logon goal (a usable session)
    is already met, so the tool succeeds having sent no key, click or clear."""
    shot = decode_png(path)
    FakeKvm.frames = [shot]
    res = amt_tools.remote_logon(confirmed=True)
    assert res["aborted"] is False and res["already_logged_in"] is True
    assert res["logged_in"] is True and res["typed_nothing"] is True and res["screen_label"] == "desktop"
    assert Path(res["screenshot"]["path"]).suffix == ".png"
    assert inputs() == [] and FakeKvm.instances[0].typed == []
    assert WIN_PW not in json.dumps(res)


@pytest.mark.parametrize("path,kind", DESKTOPS)
def test_logoff_proceeds_past_the_taskbar_gate_on_a_real_desktop(path, kind):
    """The real desktop passes the taskbar check, Win+R is sent, and with the Run dialog painted
    over the real frame the tool types logoff."""
    shot = decode_png(path)
    FakeKvm.frames = [shot, run_dialog_shot(shot), shot]
    res = amt_tools.remote_logoff(confirmed=True)
    assert res["aborted"] is False and res["logoff_submitted"] is True
    assert FakeKvm.instances[0].typed == ["logoff"]
    assert inputs()[:3] == [("key", WIN, True), ("tap", R), ("key", WIN, False)]


@pytest.mark.parametrize("path,kind", DESKTOPS)
def test_logoff_on_a_real_desktop_still_aborts_when_no_run_dialog_appears(path, kind):
    """Past the taskbar gate (Win+R WAS sent) and stopped by the dialog check: nothing typed."""
    FakeKvm.frames = [decode_png(path)]
    res = amt_tools.remote_logoff(confirmed=True)
    assert_aborted_typing_nothing(res, "run_dialog_not_detected")
    assert ("tap", R) in LOG


@pytest.mark.parametrize("path,kind", NO_TASKBAR_WINDOWS)
def test_logoff_aborts_on_a_real_signin_or_lock_screen_with_no_key_sent(path, kind):
    FakeKvm.frames = [decode_png(path)]
    res = amt_tools.remote_logoff(confirmed=True)
    assert_aborted_typing_nothing(res, "no_desktop_taskbar")
    assert inputs() == []


@pytest.mark.parametrize("path,kind", SIGNINS)
def test_logon_proceeds_on_a_real_signin_screen_and_types_once(path, kind):
    FakeKvm.frames = [decode_png(path)]          # the same real frame at every grab
    res = amt_tools.remote_logon(confirmed=True)
    assert res["aborted"] is False
    assert FakeKvm.instances[0].typed == [WIN_PW]
    assert res["logged_in"] is False and res["signin_region_changed"] == 0.0


@pytest.mark.parametrize("path,kind", BIOS)
@pytest.mark.parametrize("fn", [amt_tools.remote_logon, amt_tools.remote_logoff])
def test_both_tools_abort_on_the_real_bios_frame_before_any_key(path, kind, fn):
    shot = decode_png(path)
    FakeKvm.size, FakeKvm.frames = (shot.width, shot.height), [shot]
    res = fn(confirmed=True)
    assert_aborted_typing_nothing(res, "not_windows_resolution")
    assert inputs() == []


# --- the positive OCR gate on the real frames, per backend -------------------------------

WINDOWS_KINDS = _params({"desktop", "lock", "signin"})


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("path,kind", WINDOWS_KINDS)
def test_ocr_gate_verdicts_on_the_real_frame_for_each_backend(backend, path, kind):
    """Logon: only the sign-in is identified. Logoff: the sign-in is the one frame refused by the
    OCR half (desktop and lock carry no sign-in furniture; the taskbar detector separates those)."""
    shot = decode_png(path)
    frags = _read(backend, shot)
    assert frags, "the recognizer returned no text from a real Windows frame"
    assert amt_tools.foreign_marker_found(frags) is False

    signin_ok = amt_tools.signin_signals(frags, REAL_USER)[2]
    assert signin_ok is (kind == "signin")
    assert amt_tools.signin_screen_marker(frags) is (kind == "signin")
    if kind == "signin":
        assert amt_tools.signin_signals(frags, REAL_USER) == (True, True, True)
        assert amt_tools.signin_signals(frags, "someone-else")[2] is False, "the tile must be THIS account"


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("path,kind", _params({"desktop"}))
def test_each_backend_reads_the_tray_clock_and_date_of_a_real_desktop(backend, path, kind):
    """The desktop's text is noisy (icon labels, app windows); what it must always show is the
    tray clock and date, which is what separates 'OCR works' from 'OCR returned junk'."""
    shot = decode_png(path)
    text = " ".join(f.text for f in _read(backend, shot))
    assert "10/18/2026" in text


@needs_any_ocr
@pytest.mark.parametrize("path,kind", _params({"signin", "lock", "desktop"}))
def test_the_ordered_dispatch_reads_a_real_frame_and_names_its_backend(path, kind):
    shot = decode_png(path)
    name, frags = REAL_OCR(shot.fb, shot.width, shot.height)
    assert name == next(n for n, _ in amt_tools.OCR_BACKENDS if _ocr_backend_usable(n))
    assert frags


# --- the whole tools on real frames, real OCR --------------------------------------------

@needs_any_ocr
@pytest.mark.parametrize("path,kind", _params({"lock"}))
def test_logon_aborts_on_a_real_lock_screen_that_the_wake_does_not_clear(path, kind):
    """The lock clock passes every structural check; only the missing sign-in signature stops it."""
    FakeKvm.frames = [decode_png(path)]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "signin_not_identified")
    assert inputs() == [("click", 640, 400), ("named_key", "escape")], "wake only"
    assert res["user_tile"] is False and res["password_field"] is False


@needs_any_ocr
@pytest.mark.parametrize("path,kind", DESKTOPS)
def test_a_real_desktop_with_a_hidden_taskbar_still_aborts_logon_by_ocr(path, kind, monkeypatch):
    """Held redundantly with the taskbar detector: neutralise it (an auto-hidden taskbar does) and
    the positive match alone must still refuse the desktop."""
    monkeypatch.setattr(amt_tools, "taskbar_present", lambda fb, w, h: False)
    FakeKvm.frames = [decode_png(path)]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "signin_not_identified")
    assert res["user_tile"] is False


@needs_any_ocr
@pytest.mark.parametrize("path,kind", SIGNINS)
def test_logoff_ocr_half_refuses_a_real_signin_the_taskbar_detector_missed(path, kind, monkeypatch):
    monkeypatch.setattr(amt_tools, "taskbar_present", lambda fb, w, h: True)
    FakeKvm.frames = [decode_png(path)]
    res = amt_tools.remote_logoff(confirmed=True)
    assert_aborted_typing_nothing(res, "signin_screen_detected")
    assert inputs() == []


@needs_any_ocr
@pytest.mark.parametrize("path,kind", SIGNINS)
def test_logon_types_nothing_into_a_real_signin_of_another_account(path, kind, monkeypatch):
    """The tile must be the vaulted account: a different account's tile is not the expected prompt."""
    monkeypatch.setitem(VAULT, "my-server-1-os", json.dumps({"user": "other", "password": WIN_PW}))
    FakeKvm.frames = [decode_png(path)]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "signin_not_identified")
    assert res["user_tile"] is False and res["password_field"] is True


# --- Linux console frames: SYNTHETIC (no real capture exists), real recognizers --------------

CONSOLE_BG = ((110, 20, 80), (16, 0, 16))        # a framebuffer-console wallpaper: not blank
LOGIN_TYPED = ["Ubuntu 22.04.3 LTS ubuntu-server tty1", "", "ubuntu-server login: jdoe", "Password:"]
BARE_PROMPT = ["jdoe", "Password:"]            # no 'login' word: the positive match alone must refuse it
INSTALLER = ["[!!] Select a language", "", "English", "Deutsch", "Francais"]


@needs_any_ocr
def test_a_console_with_the_account_already_typed_is_refused_before_any_input():
    """The hard case: 'login: jdoe' + 'Password:' carries BOTH tokens the sign-in match uses.
    The first frame is read before the wake: a console whose last line is a Password: prompt
    someone else started is not typed into, and neither the Windows wake nor Ctrl+U goes out."""
    shot = rendered_text_shot(LOGIN_TYPED, background=CONSOLE_BG)
    frags = REAL_OCR(shot.fb, shot.width, shot.height)[1]
    assert amt_tools.foreign_marker_found(frags), "apparatus: the recognizer must have read 'login'"
    assert any(f.text.lower().strip(": ") == "password" or "password" in f.text.lower() for f in frags)
    FakeKvm.frames = [shot]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "console_not_at_login_prompt")
    assert inputs() == []
    assert res["screen_label"] == "linux-console" and res["console_prompt"] == "password_prompt"


@needs_any_ocr
def test_the_synthetic_console_frames_are_labelled_by_what_they_ground():
    """Linux login/Password is `linux-console`; a bare prompt carries no marker word and is
    `unknown`. The synthetic installer's `[!!]` title is the text-installer signature, so it is
    `text-installer` when the recognizer reads that title (tesseract does) and `unknown` when it
    does not (ocrmac misreads the brackets): never a console or a Windows label either way."""
    shots = {name: rendered_text_shot(lines, left=left, top=top, background=CONSOLE_BG)
             for name, lines, left, top in (("login", LOGIN_TYPED, 0.02, 0.04),
                                            ("bare", BARE_PROMPT, 0.02, 0.04),
                                            ("installer", INSTALLER, 0.35, 0.35))}
    labels = {name: amt_tools.classify_screen(shot, REAL_USER)["label"] for name, shot in shots.items()}
    shot = shots["installer"]
    read_as_installer = amt_tools.boot_screen(amt_tools.ocr_fragments(shot.fb, shot.width, shot.height)[1])
    assert labels == {"login": "linux-console", "bare": "unknown",
                      "installer": "text-installer" if read_as_installer else "unknown"}


@needs_any_ocr
def test_the_positive_match_alone_refuses_a_console_prompt_with_no_foreign_word():
    """Without the veto firing, a left-margin 'jdoe' / 'Password:' is still not a centred tile
    with a Password field below it."""
    shot = rendered_text_shot(BARE_PROMPT, background=CONSOLE_BG)
    frags = REAL_OCR(shot.fb, shot.width, shot.height)[1]
    assert not amt_tools.foreign_marker_found(frags), "apparatus: this case must not rely on the veto"
    assert any("jdoe" in f.text.lower() for f in frags) and any("password" in f.text.lower() for f in frags)
    assert amt_tools.signin_signals(frags, REAL_USER)[2] is False
    FakeKvm.frames = [shot]
    assert_aborted_typing_nothing(amt_tools.remote_logon(confirmed=True), "signin_not_identified")


@needs_any_ocr
def test_a_text_installer_screen_is_refused():
    shot = rendered_text_shot(INSTALLER, left=0.35, top=0.35, background=CONSOLE_BG)
    FakeKvm.frames = [shot]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "signin_not_identified")
    assert res["user_tile"] is False


@needs_any_ocr
def test_a_flat_black_console_is_read_as_a_console_not_stopped_as_blank():
    """A real black tty is 'blank' to the structural detector; the console path does not apply the
    blank check, and this one's Password: line (someone else's login) still types nothing."""
    FakeKvm.frames = [rendered_text_shot(LOGIN_TYPED)]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "console_not_at_login_prompt")
    assert inputs() == []


# --- the REAL Debian 13 tty1 capture (2026-10-19, my-server-1 after the install) -------------

DEBIAN_LOGIN = SCRATCH / "debian13_tty1_login.png"
needs_debian_frame = pytest.mark.skipif(not DEBIAN_LOGIN.exists(),
                                        reason=f"real frame missing, not replaced: {DEBIAN_LOGIN}")


@needs_debian_frame
@pytest.mark.parametrize("backend", BACKENDS)
def test_each_backend_reads_the_real_debian_getty_prompt(backend, monkeypatch):
    """Black, 1280x800, two lines: the structural detector calls it blank and finds no taskbar.
    Both recognizers misread the hostname's 0 (ocrmac 'ø', tesseract '@'), which is why the
    prompt is matched on how the line ends."""
    shot = decode_png(DEBIAN_LOGIN)
    assert (shot.width, shot.height) == (1280, 800)
    assert amt_tools.frame_is_blank(shot.fb, shot.width, shot.height) is True
    assert amt_tools.taskbar_present(shot.fb, shot.width, shot.height) is False
    frags = _read(backend, shot)
    assert amt_tools.console_prompt(frags) == "login_prompt"
    run = dict(amt_tools.OCR_BACKENDS)[backend]
    monkeypatch.setattr(amt_tools, "ocr_fragments", lambda fb, w, h: (backend, run(fb, w, h)))
    cls = amt_tools.classify_screen(shot, REAL_USER)
    assert cls["label"] == "linux-console" and cls["markers"]["console_prompt"] == "login_prompt"


@needs_debian_frame
@needs_any_ocr
def test_logon_on_the_real_debian_prompt_types_the_account_and_stops_without_a_password_prompt():
    """Fed the real login frame at every read, the tool sends Ctrl+U and the account name, then
    never sees getty's Password: prompt, so the password is never typed."""
    FakeKvm.frames = [decode_png(DEBIAN_LOGIN)]
    res = amt_tools.remote_logon(confirmed=True)
    assert res["aborted"] is True and res["reason"] == "password_prompt_not_identified"
    assert FakeKvm.instances[0].typed == [REAL_USER]
    assert inputs()[:3] == [("key", amt_tools.amt_kvm.KEYSYM["ctrl"], True), ("tap", ord("u")),
                            ("key", amt_tools.amt_kvm.KEYSYM["ctrl"], False)]
    assert ("named_key", "escape") not in LOG and WIN_PW not in json.dumps(res)


@needs_any_ocr
def test_logoff_refuses_a_linux_console_with_no_key_sent():
    """Its last line is a Password: prompt, so exit would be a password attempt: nothing is sent."""
    FakeKvm.frames = [rendered_text_shot(LOGIN_TYPED, background=CONSOLE_BG)]
    res = amt_tools.remote_logoff(confirmed=True)
    assert_aborted_typing_nothing(res, "console_not_at_shell_prompt")
    assert inputs() == []


DEBIAN_LOGGED_IN = SCRATCH / "debian13_tty1_logged_in.png"


@pytest.mark.skipif(not DEBIAN_LOGGED_IN.exists(), reason=f"real frame missing, not replaced: {DEBIAN_LOGGED_IN}")
@pytest.mark.parametrize("backend", BACKENDS)
def test_each_backend_reads_the_real_debian_shell_prompt_after_the_live_logon(backend):
    """The result frame of the live logon (2026-10-19 02:51 EDT): motd, then user@my-server-1:~$."""
    frags = _read(backend, decode_png(DEBIAN_LOGGED_IN))
    assert amt_tools.console_prompt(frags) == "command_prompt"
    assert amt_tools.console_login_incorrect(frags) is False


# --- boot software: GRUB, the Debian text installer, the MOK manager (REAL 800x600 frames) --------
#
# Captured from the my-server-1's KVM during the 2026-10-19 Debian 13 install and the Secure Boot
# MOK enrolment, copied into tests/real_frames/ so the repo keeps them (the capture directory is a
# machine-local temp dir). Each frame was read by BOTH recognizers when its label was calibrated and
# shows what its name says (menu and list screens only; no frame with a password prompt or typed
# text was kept). Original capture names, all `amt-my-server-1-<stamp>.png`:
#   grub-installed-menu 20261019T160706782174Z-705aeb54ddf3224c   GNU GRUB 2.12 menu of the installed system
#   grub-installer-media-menu-a 20261019T054650226791Z-4157776509b329fb   installer media's GRUB menu
#   grub-installer-media-menu-b 20261019T054609585016Z-c3ee933f4932c87c   same menu, other selection
#   text-installer-* 20261019T0610/0627/0625/0525...   d-i dialogs (partition free space, finish,
#                    software selection, keyboard list)
#   mok-* 20261019T1606/1609/1609...   shim "Shim UEFI key management" / "Perform MOK management"
#   neg-bios-*  20261019T0413...  AMI BIOS setup pages (the two the first bucketing called "boot menu")
#   neg-installer-progress-grub-loader 20261019T062651351491Z  "Installing GRUB boot loader 16%"
#   neg-windows-desktop 20261019T022635930730Z   a Windows desktop (Device Manager open)
#   neg-linux-login     the Debian 13 tty1 getty prompt (scratch capture debian13_tty1_login.png)
# No real capture of a firmware boot-device menu (the F7/F12 popup) exists - every "boot menu" frame
# on file is a BIOS setup page - so there is no `boot-menu` label.

FRAMES_DIR = Path(__file__).resolve().parent / "real_frames"

BOOT_FRAMES = [
    ("grub-installed-menu.png", "grub"),
    ("grub-installer-media-menu-a.png", "grub"),
    ("grub-installer-media-menu-b.png", "grub"),
    ("text-installer-partition-free-space.png", "text-installer"),
    ("text-installer-finish.png", "text-installer"),
    ("text-installer-software-selection.png", "text-installer"),
    ("text-installer-keyboard-list.png", "text-installer"),
    ("mok-shim-key-management.png", "mok-manager"),
    ("mok-perform-continue-boot.png", "mok-manager"),
    ("mok-perform-reboot.png", "mok-manager"),
]
# Frames that must NOT take a boot label: (file, the label they do take, geometry).
NOT_BOOT_FRAMES = [
    ("neg-bios-save-exit.png", "bios-setup", (640, 480)),
    ("neg-bios-bbs-priorities.png", "bios-setup", (640, 480)),
    ("neg-installer-progress-grub-loader.png", "bios-setup", (800, 600)),   # geometry fallback, not GRUB
    ("neg-windows-desktop.png", "desktop", (1280, 800)),
    ("neg-linux-login.png", "linux-console", (1280, 800)),
]


def _boot_params(rows):
    return [pytest.param(FRAMES_DIR / row[0], *row[1:], id=row[0][:-4], marks=pytest.mark.skipif(
        not (FRAMES_DIR / row[0]).exists(), reason=f"real frame missing, not replaced: {FRAMES_DIR / row[0]}"))
        for row in rows]


def _classify_with(backend, shot_or_png, monkeypatch):
    run = dict(amt_tools.OCR_BACKENDS)[backend]
    monkeypatch.setattr(amt_tools, "ocr_fragments", lambda fb, w, h: (backend, run(fb, w, h)))
    return amt_tools.classify_screen(shot_or_png, REAL_USER)


def test_the_new_labels_are_in_screen_labels_and_boot_menu_is_not_invented():
    for label in ("grub", "text-installer", "mok-manager"):
        assert label in amt_tools.SCREEN_LABELS and label in amt_tools.BOOT_FIRMWARE_LABELS
    assert "boot-menu" not in amt_tools.SCREEN_LABELS and amt_tools.SCREEN_LABELS[-1] == "unknown"
    assert amt_tools.BOOT_FIRMWARE_LABELS == {"bios-setup", "grub", "text-installer", "mok-manager"}


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("path,label", _boot_params(BOOT_FRAMES))
def test_classify_screen_labels_the_real_boot_frame_for_each_backend(backend, path, label, monkeypatch):
    shot = decode_png(path)
    assert (shot.width, shot.height) == (800, 600)
    cls = _classify_with(backend, shot, monkeypatch)
    assert cls["label"] == label and cls["markers"]["ocr_backend"] == backend
    assert cls["markers"]["boot_screen"] == label and cls["markers"]["foreign_markers"] in (True, False)
    assert _classify_with(backend, path.read_bytes(), monkeypatch)["label"] == label, "PNG input"


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("path,label,geometry", _boot_params(NOT_BOOT_FRAMES))
def test_a_bios_a_windows_a_console_and_an_installer_progress_bar_take_no_boot_label(
        backend, path, label, geometry, monkeypatch):
    shot = decode_png(path)
    assert (shot.width, shot.height) == geometry
    cls = _classify_with(backend, shot, monkeypatch)
    assert cls["label"] == label and cls["label"] not in ("grub", "text-installer", "mok-manager")
    assert cls["markers"]["boot_screen"] is None


@needs_any_ocr
@pytest.mark.parametrize("path,label", _boot_params(BOOT_FRAMES))
def test_the_ordered_dispatch_labels_the_real_boot_frame_and_holds_findings_only(path, label):
    cls = amt_tools.classify_screen(decode_png(path), REAL_USER)
    assert cls["label"] == label
    blob = json.dumps(cls)
    for text in ("Installer menu", "Partition", "Enroll", "keymap", "Keymap", "GNU GRUB", "Shim", "Software"):
        assert text not in blob


@pytest.mark.parametrize("backend", BACKENDS)
@pytest.mark.parametrize("path,label", _boot_params(BOOT_FRAMES))
def test_each_real_boot_frame_matches_exactly_one_signature(backend, path, label):
    text = " ".join(f.text for f in _read(backend, decode_png(path)))
    assert [l for l, pat in amt_tools.BOOT_SIGNATURES if pat.search(text)] == [label]


@needs_any_ocr
@pytest.mark.parametrize("path,label", _boot_params(BOOT_FRAMES))
@pytest.mark.parametrize("fn", [amt_tools.remote_logon, amt_tools.remote_logoff])
def test_both_windows_tools_still_abort_on_a_labelled_real_boot_frame_before_any_key(path, label, fn):
    shot = decode_png(path)
    FakeKvm.size, FakeKvm.frames = (shot.width, shot.height), [shot]
    res = fn(confirmed=True)
    assert_aborted_typing_nothing(res, "not_windows_resolution")
    assert inputs() == [] and FakeKvm.instances[0].typed == []


@pytest.mark.parametrize("backend", BACKENDS)
def test_the_installer_progress_bar_still_trips_the_grub_word_veto_without_being_grub(backend, monkeypatch):
    path = FRAMES_DIR / "neg-installer-progress-grub-loader.png"
    if not path.exists():
        pytest.skip(f"real frame missing, not replaced: {path}")
    shot = decode_png(path)
    read_grub = any("grub" in f.text.lower() for f in _read(backend, shot))
    m = _classify_with(backend, shot, monkeypatch)["markers"]
    assert m["boot_screen"] is None
    assert m["foreign_markers"] is read_grub        # the veto follows what the recognizer read
    if backend == "ocrmac":
        assert read_grub, "apparatus: ocrmac reads GRUB on this frame, so the veto case is exercised"


# Captured live through the NAS container 2026-10-20 10:03 EDT: five stacked getty prompts after
# repeated Enter presses. The container's tesseract, at --psm 11, read "login" without its colon on
# every line, so the logon aborted with console_not_at_login_prompt. A black console is a uniform
# text block, so it is read at --psm 6.
REPEATED_PROMPTS = FRAMES_DIR / "debian13-tty1-repeated-login-prompts.png"


@pytest.mark.parametrize("backend", BACKENDS)
def test_each_backend_reads_a_getty_prompt_under_earlier_prompts(backend):
    shot = decode_png(REPEATED_PROMPTS)
    assert (shot.width, shot.height) == (1280, 800)
    assert amt_tools.console_prompt(_read(backend, shot)) == "login_prompt"
