"""Tests for the composite WRITE tools amt_remote_logon / amt_remote_logoff, with a MOCKED
engine. No test opens a socket, reads the real vault or touches a host: ``KvmSession`` is
replaced by ``FakeKvm``, which records the ORDERED engine calls (and every ``_pause``) in one
shared log, and ``amt_vault.get_secret`` is replaced by an in-memory table.

The typed password necessarily reaches ``type_text``; the fake keeps those arguments in a
separate ``typed`` list so every other surface (result, call log, signature, errors) can be
asserted free of it.

Screen frames: the sequence tests serve small synthetic console frames (``frames.py``); the
detectors that decide whether keys may be sent are grounded on REAL captures in
``test_screen_context_real_frames.py``. A frame fills the framebuffer with a smooth wallpaper,
not a flat 0/255, so a taskbar/sign-in/Run-dialog verdict has to come from structure.

The synthetic frames carry no legible text, so here the OCR seam (``amt_tools.ocr_fragments``)
is replaced by ``fake_ocr``, which reads what a frame STANDS FOR from ``frames.KIND_BY_DIGEST``
and returns the fragments a real recognizer would. A frame the registry does not know reads as
no text. The real recognizers run on real frames in the other test module.
"""
import asyncio
import inspect
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import amt_gate  # noqa: E402
import amt_kvm  # noqa: E402
import amt_server  # noqa: E402
import amt_tools  # noqa: E402
import amt_vault  # noqa: E402
import amt_wsman  # noqa: E402
import frames  # noqa: E402
from frames import (Shot, bios_shot, blank_shot, console_shot, desktop_shot,  # noqa: E402
                    horizon_shot, lock_shot, run_dialog_shot, signin_shot, tty_shot)
from test_skeleton import TOKEN, TOKEN_HASH, _call, _client, _rpc  # noqa: E402

PIN = amt_wsman.amt_registry.get_device("my-server-1").tls_leaf_sha256
AMT_PW = "AMT-SENTINEL-not-real"
WIN_PW = "Win-Sentinel-Pw-17ch"          # 20 chars; the length must appear nowhere
WIN_USER = "sentinel-user-name"
VAULT = {"my-server-1-amt": AMT_PW,
         "my-server-1-os": json.dumps({"user": WIN_USER, "password": WIN_PW})}
LOG: list = []
WIN, R = amt_kvm.KEYSYM["win"], ord("r")
CTRL, A = amt_kvm.KEYSYM["ctrl"], ord("a")
SIGNIN, LOCK, DESKTOP, RUN, BLANK, BIOS = (signin_shot(), lock_shot(), desktop_shot(),
                                           run_dialog_shot(), blank_shot(), bios_shot())
CONSOLE = console_shot()
# Frames served by successive grab_stable calls (the last repeats).
LOGON_OK = [SIGNIN, SIGNIN, SIGNIN, DESKTOP]      # initial, after wake, before typing, result
LOGOFF_OK = [DESKTOP, RUN, DESKTOP]               # initial, after Win+R, result
KEYS = {"click", "key", "tap", "named_key", "type_text", "clear_field"}


OCR_CALLS: list = []
_FAKE_TEXT = {
    # Fragments a real recognizer returns for each kind of frame (centres as ratios, top-left).
    "signin": lambda: [amt_tools.Fragment(WIN_USER, 0.50, 0.50), amt_tools.Fragment("Password", 0.42, 0.58)],
    "lock": lambda: [amt_tools.Fragment("10:42", 0.50, 0.20), amt_tools.Fragment("Sunday, October 18", 0.50, 0.27)],
    "desktop": lambda: [amt_tools.Fragment("Recycle Bin", 0.04, 0.10), amt_tools.Fragment("02:19", 0.95, 0.95),
                        amt_tools.Fragment("10/18/2026", 0.95, 0.98)],
    "console": lambda: [amt_tools.Fragment("ubuntu-server login:", 0.10, 0.30), amt_tools.Fragment("Password:", 0.05, 0.36)],
    # A Debian getty as ocrmac reads it (the hostname's 0 as ø, the cursor as '-'), one stage each.
    **{"tty_" + stage: (lambda lines=lines: [amt_tools.Fragment(t, 0.08, 0.03 + 0.02 * i)
                                             for i, t in enumerate(lines)])
       for stage, lines in {
           "login": ["Debian GNU/Linux 13 host-ø1 tty1", "host-ø1 login: -"],
           "password": ["Debian GNU/Linux 13 host-ø1 tty1", f"host-ø1 login: {WIN_USER}", "Password:"],
           "shell": ["Debian GNU/Linux 13 host-ø1 tty1", f"host-ø1 login: {WIN_USER}", "Password:",
                     "Last login: Mon Oct 19 02:33:12 EDT 2026 on tty1", f"{WIN_USER}@host-ø1:~$ -"],
           "incorrect": ["Debian GNU/Linux 13 host-ø1 tty1", f"host-ø1 login: {WIN_USER}", "Password:",
                         "Login incorrect", "host-ø1 login: -"],
           "motd": ["Debian GNU/Linux 13 host-ø1 tty1", f"host-ø1 login: {WIN_USER}", "Password:",
                    "Linux host-ø1 6.12.48-amd64 x86_64"],
           # A getty run with --noclear keeps an older failure on screen above a fresh prompt.
           "stale_login": ["host-ø1 login: someone", "Password:", "Login incorrect", "host-ø1 login: -"],
           "stale_password": ["host-ø1 login: someone", "Password:", "Login incorrect",
                              f"host-ø1 login: {WIN_USER}", "Password:"],
           "echo": ["Debian GNU/Linux 13 host-ø1 tty1", f"{WIN_USER}@host-ø1:~$ echo login:"],
       }.items()},
}


def fake_ocr(fb, width, height):
    OCR_CALLS.append((width, height))
    kind = frames.KIND_BY_DIGEST.get(frames.digest(fb))
    return "fake", (_FAKE_TEXT[kind]() if kind in _FAKE_TEXT else [])


class FakeKvm:
    instances = []
    presented_fp = PIN
    fail_open = False
    type_error = None
    tap_error = None
    size = (1280, 800)
    frames = LOGON_OK           # Shot (or None: no framebuffer) per successive grab_stable call

    def __init__(self, host, port=16995, pw=None, key_delay=0.02):
        self.host, self.port, self.pw = host, port, pw
        self.closed = False
        self.past_connect = False
        self.cert_fp = None
        self.typed = []
        self.fb = None
        self._grabs = 0
        FakeKvm.instances.append(self)

    def connect(self):
        self.cert_fp = FakeKvm.presented_fp

    def open(self, deadline=None):
        self.connect()
        self.past_connect = True
        LOG.append(("open",))
        if FakeKvm.fail_open:
            raise amt_kvm.AmtError("auth_rejected_no_retry")
        return FakeKvm.size

    def grab_stable(self, **kw):
        shot = FakeKvm.frames[min(self._grabs, len(FakeKvm.frames) - 1)]
        self._grabs += 1
        w, h = FakeKvm.size if shot is None else (shot.width, shot.height)
        self.fb = None if shot is None else bytearray(shot.fb)
        LOG.append(("grab_stable",))
        return w, h, 2, True, 100

    def click(self, x, y, button="left"):
        LOG.append(("click", x, y))

    def named_key(self, name):
        LOG.append(("named_key", name))

    def clear_field(self, max_back=64):
        LOG.append(("clear_field",))

    def type_text(self, text):
        LOG.append(("type_text",))            # the text itself is NOT logged
        self.typed.append(text)
        if FakeKvm.type_error:
            raise FakeKvm.type_error
        return len(text)

    def _key(self, keysym, down):
        LOG.append(("key", keysym, down))

    def tap(self, keysym):
        LOG.append(("tap", keysym))
        if FakeKvm.tap_error:
            raise FakeKvm.tap_error

    def write_png(self, path):
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\nfake")
        return path

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    LOG.clear()
    OCR_CALLS.clear()
    monkeypatch.setattr(amt_tools, "ocr_fragments", fake_ocr)
    FakeKvm.instances, FakeKvm.presented_fp, FakeKvm.fail_open = [], PIN, False
    FakeKvm.type_error = FakeKvm.tap_error = None
    FakeKvm.size, FakeKvm.frames = (1280, 800), LOGON_OK
    FakeWsman.power, FakeWsman.fault, FakeWsman.calls = "2", False, []
    monkeypatch.setenv(amt_gate.HASH_ENV, TOKEN_HASH)
    monkeypatch.delenv(amt_gate.TRANSPORT_ENV, raising=False)
    monkeypatch.setenv(amt_tools.SHOT_DIR_ENV, str(tmp_path / "shots"))
    monkeypatch.setattr(amt_tools.amt_kvm, "KvmSession", FakeKvm)
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: VAULT[key])
    monkeypatch.setattr(amt_tools, "_pause", lambda s: LOG.append(("pause", s)))
    monkeypatch.setattr(amt_wsman, "get", FakeWsman.get)


class FakeWsman:
    """The one WS-MAN read the composite tools make: the host's power state."""
    power = "2"                 # WS-MAN text: 2 on, 3 light sleep, 4 deep sleep, 8 soft off
    fault = False
    calls = []

    @staticmethod
    def get(cls, *, selectors=None, device="my-server-1", password=None):
        FakeWsman.calls.append((cls, device, password))
        if FakeWsman.fault:
            raise amt_wsman.WsmanFault("fault:no_such_class")
        return {"PowerState": FakeWsman.power}


def no_vault(monkeypatch):
    monkeypatch.setattr(amt_vault, "get_secret",
                        lambda key: pytest.fail(f"vault read ({key}) before the guard allowed it"))


LOGON_SEQUENCE = [
    ("open",), ("grab_stable",),
    ("click", 640, 400), ("named_key", "escape"), ("pause", amt_tools.WAKE_SETTLE_SECONDS),
    ("grab_stable",),
    ("click", 640, 460),
    ("key", CTRL, True), ("tap", A), ("key", CTRL, False), ("named_key", "delete"),
    ("grab_stable",),
    ("type_text",), ("named_key", "enter"), ("pause", amt_tools.SUBMIT_SETTLE_SECONDS),
    ("grab_stable",), ("grab_stable",),        # the result check, then the evidence frame
]
LOGOFF_SEQUENCE = [
    ("open",), ("grab_stable",),
    ("key", WIN, True), ("tap", R), ("key", WIN, False),
    ("pause", amt_tools.RUN_DIALOG_SETTLE_SECONDS), ("grab_stable",),
    ("type_text",), ("named_key", "enter"), ("pause", amt_tools.LOGOFF_SETTLE_SECONDS),
    ("grab_stable",),
]


def inputs(log=None):
    """The engine calls that SEND something to the host (everything but open/grab/pause)."""
    return [e for e in (LOG if log is None else log) if e[0] in KEYS]


def assert_aborted_typing_nothing(res, reason):
    assert res["aborted"] is True and res["reason"] == reason and res["typed_nothing"] is True
    assert res["device"] == "my-server-1"
    assert all(s.typed == [] and s.closed for s in FakeKvm.instances)
    assert ("type_text",) not in LOG and ("named_key", "enter") not in LOG
    assert ("clear_field",) not in LOG
    blob = json.dumps(res)
    assert WIN_PW not in blob and WIN_USER not in blob and AMT_PW not in blob


# --- ordered engine calls ---------------------------------------------------------------

def test_logon_runs_dismiss_focus_clear_type_enter_in_order_and_closes():
    out = amt_tools.remote_logon(confirmed=True)
    assert LOG == LOGON_SEQUENCE
    (s,) = FakeKvm.instances
    assert s.typed == [WIN_PW], "the vaulted password is what gets typed, exactly once"
    assert s.pw == AMT_PW and s.pw != WIN_PW, "the session authenticates with the AMT password"
    assert s.closed is True
    assert (s.host, s.port) == ("198.51.100.26", 16995)
    assert out["aborted"] is False
    assert out["device"] == "my-server-1" and (out["width"], out["height"]) == (1280, 800)
    assert Path(out["path"]).suffix == ".png" and out["bytes"] == Path(out["path"]).stat().st_size
    assert out["logged_in"] is True and out["signin_region_changed"] >= amt_tools.SIGNIN_GONE_FRACTION
    assert out["tls_leaf_sha256"] == PIN


def test_logon_clear_is_ctrl_a_then_delete_never_the_backspace_sweep():
    amt_tools.remote_logon(confirmed=True)
    assert ("clear_field",) not in LOG, "clear_field ends in 64 Backspaces: destructive in a focused app"
    assert not [e for e in LOG if e[0] in ("tap", "named_key") and e[1] in (0xFF08, "backspace")]
    keys = inputs()
    i = keys.index(("key", CTRL, True))
    assert keys[i:i + 4] == [("key", CTRL, True), ("tap", A), ("key", CTRL, False), ("named_key", "delete")]


def test_positions_are_ratios_of_the_console_geometry():
    FakeKvm.size = (1920, 1080)
    FakeKvm.frames = [signin_shot(1920, 1080)] * 3 + [desktop_shot(1920, 1080)]
    amt_tools.remote_logon(confirmed=True)
    clicks = [c for c in LOG if c[0] == "click"]
    assert clicks == [("click", 960, 540), ("click", 960, 621)]


def test_logged_in_heuristic_is_best_effort_and_three_valued():
    FakeKvm.frames = [SIGNIN, SIGNIN, SIGNIN, SIGNIN]     # box still there (e.g. wrong password)
    out = amt_tools.remote_logon(confirmed=True)
    assert out["aborted"] is False and out["logged_in"] is False and out["signin_region_changed"] == 0.0
    FakeKvm.frames = LOGON_OK                             # box gone
    assert amt_tools.remote_logon(confirmed=True)["logged_in"] is True
    FakeKvm.frames = [SIGNIN, SIGNIN, SIGNIN, None]       # no result framebuffer: unknown, not False
    out = amt_tools.remote_logon(confirmed=True)
    assert out["logged_in"] is None and out["signin_region_changed"] is None
    assert "heuristic" in out["logged_in_basis"]


def test_logon_makes_exactly_one_attempt_even_when_it_looks_like_a_wrong_password():
    FakeKvm.frames = [SIGNIN] * 4
    amt_tools.remote_logon(confirmed=True)
    assert LOG.count(("type_text",)) == 1 and LOG.count(("named_key", "enter")) == 1
    assert len(FakeKvm.instances) == 1


def test_logoff_runs_win_r_then_logoff_then_enter_in_order_and_closes():
    FakeKvm.frames = LOGOFF_OK
    out = amt_tools.remote_logoff(confirmed=True)
    assert LOG == LOGOFF_SEQUENCE
    (s,) = FakeKvm.instances
    assert s.typed == ["logoff"] and s.closed is True
    assert out["aborted"] is False and out["logoff_submitted"] is True and out["device"] == "my-server-1"
    assert (out["width"], out["height"]) == (1280, 800)


def test_logoff_never_reads_the_windows_credential(monkeypatch):
    FakeKvm.frames = LOGOFF_OK
    seen = []
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: seen.append(key) or VAULT[key])
    amt_tools.remote_logoff(confirmed=True)
    assert seen == ["my-server-1-amt"]


def test_key_combo_releases_the_modifier_even_when_the_tap_fails():
    s = FakeKvm("h")
    FakeKvm.tap_error = amt_kvm.AmtError("boom")
    with pytest.raises(amt_kvm.AmtError):
        amt_tools.key_combo(s, ("win",), "r")
    assert LOG == [("key", WIN, True), ("tap", R), ("key", WIN, False)]


def test_key_combo_rejects_unknown_keys_before_pressing_anything():
    s = FakeKvm("h")
    with pytest.raises(amt_kvm.AmtError, match="unknown_key_hyper"):
        amt_tools.key_combo(s, ("hyper",), "r")
    assert LOG == []


# --- screen-context preconditions: any doubt aborts and types nothing --------------------

@pytest.mark.parametrize("power", ["3", "4", "6", "7", "8", "bogus"])
@pytest.mark.parametrize("fn", [amt_tools.remote_logon, amt_tools.remote_logoff])
def test_host_not_powered_on_aborts_before_a_session_is_even_opened(fn, power):
    FakeWsman.power = power
    res = fn(confirmed=True)
    assert res["aborted"] is True and res["reason"] == "host_not_powered_on" and res["typed_nothing"] is True
    assert res["screenshot"] is None
    assert FakeKvm.instances == [] and LOG == []
    assert FakeWsman.calls == [("CIM_AssociatedPowerManagementService", "my-server-1", AMT_PW)]


@pytest.mark.parametrize("fn", [amt_tools.remote_logon, amt_tools.remote_logoff])
def test_unknown_power_state_is_not_on(fn):
    FakeWsman.fault = True              # the class faults: the state is unknown, which is not "on"
    assert fn(confirmed=True)["reason"] == "host_not_powered_on"
    assert FakeKvm.instances == [] and LOG == []


def test_the_power_abort_names_the_state_and_checks_it_before_any_input():
    FakeWsman.power = "3"
    assert amt_tools.remote_logon(confirmed=True)["power_state"] == "sleep_light"


@pytest.mark.parametrize("fn", [amt_tools.remote_logon, amt_tools.remote_logoff])
def test_bios_resolution_aborts_before_any_key(fn):
    """A 640x480 frame is BIOS/POST, where Delete/Esc/Enter change firmware settings."""
    FakeKvm.size, FakeKvm.frames = (640, 480), [BIOS]
    res = fn(confirmed=True)
    assert_aborted_typing_nothing(res, "not_windows_resolution")
    assert inputs() == [], "not one key or click may be sent to a BIOS screen"
    assert (res["screenshot"]["width"], res["screenshot"]["height"]) == (640, 480)
    assert Path(res["screenshot"]["path"]).suffix == ".png"


def test_logon_on_an_already_logged_in_desktop_is_a_no_op_success_not_an_abort():
    """The classifier labels the console `desktop`: the logon goal (a usable session) is met, so the
    tool succeeds having sent nothing at all, not even the wake click or Esc."""
    FakeKvm.frames = [DESKTOP]
    res = amt_tools.remote_logon(confirmed=True)
    assert res["aborted"] is False and res["already_logged_in"] is True
    assert res["logged_in"] is True and res["typed_nothing"] is True and res["device"] == "my-server-1"
    assert res["screen_label"] == "desktop" and res["ocr_backend"] == "fake"
    assert Path(res["screenshot"]["path"]).suffix == ".png"
    assert "reason" not in res
    assert inputs() == [], "not even the wake click or Esc may reach a desktop"
    assert all(s.typed == [] and s.closed for s in FakeKvm.instances)
    assert ("clear_field",) not in LOG and ("named_key", "delete") not in LOG
    assert len(OCR_CALLS) == 1, "one recognition: the classifier confirming the desktop"
    blob = json.dumps(res)
    assert WIN_PW not in blob and WIN_USER not in blob and AMT_PW not in blob
    assert "Recycle" not in blob and "10/18/2026" not in blob, "findings only, never recognized text"


def test_logon_aborts_when_a_taskbar_is_not_positively_a_desktop_and_sends_nothing(monkeypatch):
    """A taskbar the classifier cannot confirm as a desktop (here: console text on it) keeps the
    old safe abort, with no input sent."""
    monkeypatch.setattr(amt_tools, "taskbar_present", lambda fb, w, h: True)
    FakeKvm.frames = [CONSOLE]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "host_already_logged_in")
    assert inputs() == []


def test_logon_aborts_a_taskbar_desktop_when_no_ocr_backend_can_confirm_it(monkeypatch):
    """Fail closed: without OCR the classifier cannot say `desktop`, so it is the old abort."""
    _no_ocr_backend(monkeypatch)
    FakeKvm.frames = [DESKTOP]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "host_already_logged_in")
    assert inputs() == []


def test_logon_succeeds_as_already_logged_in_when_the_wake_lands_on_a_desktop_and_clears_nothing():
    FakeKvm.frames = [LOCK, DESKTOP]
    res = amt_tools.remote_logon(confirmed=True)
    assert res["aborted"] is False and res["already_logged_in"] is True and res["typed_nothing"] is True
    assert inputs() == [("click", 640, 400), ("named_key", "escape")], "wake only, then stop"
    assert ("key", CTRL, True) not in LOG and ("named_key", "delete") not in LOG
    assert all(s.typed == [] for s in FakeKvm.instances)


def test_logon_aborts_on_a_blank_screen_after_the_wake_before_the_clear():
    """A slow wake leaves a black console: do not type into whatever paints next."""
    FakeKvm.frames = [BLANK, BLANK]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "screen_blank")
    assert inputs() == [("click", 640, 400), ("named_key", "escape")]


def test_a_blank_first_frame_alone_does_not_abort_a_sleeping_display_wake():
    """The initial frame of a sleeping display is blank by nature; only the post-wake one counts."""
    FakeKvm.frames = [BLANK, SIGNIN, SIGNIN, DESKTOP]
    out = amt_tools.remote_logon(confirmed=True)
    assert out["aborted"] is False and FakeKvm.instances[0].typed == [WIN_PW]


def test_logon_rechecks_the_frame_right_before_typing_the_password():
    FakeKvm.frames = [SIGNIN, SIGNIN, DESKTOP]       # a desktop appears after the field click
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "host_already_logged_in")
    FakeKvm.instances.clear(); LOG.clear()
    FakeKvm.frames = [SIGNIN, SIGNIN, BLANK]
    assert_aborted_typing_nothing(amt_tools.remote_logon(confirmed=True), "screen_blank")


@pytest.mark.parametrize("n", [0, 1, 2])
def test_logon_aborts_when_a_frame_has_no_framebuffer(n):
    FakeKvm.frames = [None if i == n else SIGNIN for i in range(4)]
    assert_aborted_typing_nothing(amt_tools.remote_logon(confirmed=True), "screen_unreadable")


@pytest.mark.parametrize("frame,reason", [(SIGNIN, "no_desktop_taskbar"), (LOCK, "no_desktop_taskbar"),
                                          (BLANK, "no_desktop_taskbar")])
def test_logoff_aborts_without_a_desktop_taskbar_before_any_key(frame, reason):
    """No Win+R into a sign-in box: 'logoff' + Enter there is a wrong-password attempt."""
    FakeKvm.frames = [frame]
    res = amt_tools.remote_logoff(confirmed=True)
    assert_aborted_typing_nothing(res, reason)
    assert inputs() == []


def test_logoff_aborts_when_the_frame_has_no_framebuffer():
    FakeKvm.frames = [None]
    assert_aborted_typing_nothing(amt_tools.remote_logoff(confirmed=True), "screen_unreadable")
    assert inputs() == []


def test_logoff_without_a_run_dialog_dismisses_it_with_esc_releases_win_and_types_nothing():
    FakeKvm.frames = [DESKTOP, DESKTOP]              # Win+R changed nothing in the Run region
    res = amt_tools.remote_logoff(confirmed=True)
    assert_aborted_typing_nothing(res, "run_dialog_not_detected")
    assert inputs() == [("key", WIN, True), ("tap", R), ("key", WIN, False), ("named_key", "escape")]
    assert LOG.index(("key", WIN, False)) < LOG.index(("named_key", "escape"))


def test_every_abort_closes_the_session_and_returns_the_current_screen():
    for fn, frames in ((amt_tools.remote_logon, [DESKTOP]), (amt_tools.remote_logoff, [SIGNIN])):
        FakeKvm.frames = frames
        res = fn(confirmed=True)
        shot = res["screenshot"]
        assert shot["path"] and Path(shot["path"]).stat().st_size == shot["bytes"]
        assert (shot["width"], shot["height"]) == (1280, 800)
    assert len(FakeKvm.instances) == 2 and all(s.closed for s in FakeKvm.instances)


def test_an_abort_survives_a_failure_to_take_the_evidence_frame(monkeypatch):
    FakeKvm.frames = [SIGNIN, SIGNIN, DESKTOP]       # a desktop after the field click: still an abort
    monkeypatch.setattr(FakeKvm, "write_png", lambda self, p: (_ for _ in ()).throw(OSError("disk full")))
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "host_already_logged_in")
    assert res["screenshot"] is None and res["screenshot_error"] == "OSError"
    assert "disk full" not in json.dumps(res)


def test_the_already_logged_in_success_survives_a_failure_to_take_the_evidence_frame(monkeypatch):
    FakeKvm.frames = [DESKTOP]
    monkeypatch.setattr(FakeKvm, "write_png", lambda self, p: (_ for _ in ()).throw(OSError("disk full")))
    res = amt_tools.remote_logon(confirmed=True)
    assert res["already_logged_in"] is True and res["typed_nothing"] is True
    assert res["screenshot"] is None and res["screenshot_error"] == "OSError"
    assert "disk full" not in json.dumps(res)


@pytest.mark.parametrize("w,h,ok", [(1280, 800, True), (1920, 1080, True), (1024, 768, True),
                                    (640, 480, False), (800, 600, False), (720, 400, False),
                                    (1023, 800, False), (1280, 719, False)])
def test_windows_geometry_boundary(w, h, ok):
    assert amt_tools.windows_geometry(w, h) is ok


def test_a_hard_horizon_edge_without_a_uniform_strip_is_not_a_taskbar():
    """The edge alone is not the signal: the strip under it must be one colour, as a taskbar's
    background is. Without this clause a wallpaper with a hard edge would read as 'logged in'."""
    h = horizon_shot()
    assert amt_tools.taskbar_present(h.fb, h.width, h.height) is False
    FakeKvm.frames = [h, h, h, DESKTOP]
    assert amt_tools.remote_logon(confirmed=True)["aborted"] is False


@pytest.mark.parametrize("colour", [(16, 32, 58), (240, 243, 249), (40, 40, 40), (250, 250, 250)])
def test_a_taskbar_is_found_in_dark_and_light_themes(colour):
    d = desktop_shot(bar_colour=colour)
    assert amt_tools.taskbar_present(d.fb, d.width, d.height) is True


@pytest.mark.parametrize("w,h", [(1024, 768), (1366, 768), (1920, 1080), (2560, 1440)])
def test_the_taskbar_is_found_at_other_windows_resolutions(w, h):
    d, s = desktop_shot(w, h), signin_shot(w, h)
    assert amt_tools.taskbar_present(d.fb, w, h) is True
    assert amt_tools.taskbar_present(s.fb, w, h) is False


def test_detectors_report_unknown_for_an_unreadable_frame_not_a_verdict():
    assert amt_tools.taskbar_present(None, 1280, 800) is None
    assert amt_tools.taskbar_present(b"\x00" * 10, 1280, 800) is None
    assert amt_tools.frame_is_blank(None, 1280, 800) is None
    assert amt_tools.frame_is_blank(b"\x00" * 10, 1280, 800) is None


# --- the positive OCR gate: only a positively identified screen is typed into -----------

def _no_ocr_backend(monkeypatch, exc=None):
    def raiser(fb, width, height):
        raise exc or amt_tools.OcrUnavailable("no_ocr_backend")
    monkeypatch.setattr(amt_tools, "ocr_fragments", raiser)


def test_logon_types_only_after_two_positive_ocr_matches_and_never_returns_the_text():
    """Three reads: the first frame (to route a Linux console away from the Windows wake), then
    the two positive sign-in matches, after the wake and on the frame right before typing."""
    out = amt_tools.remote_logon(confirmed=True)
    assert out["aborted"] is False and FakeKvm.instances[0].typed == [WIN_PW]
    assert len(OCR_CALLS) == 3, "first frame, after the wake, and right before typing"
    assert LOG.index(("grab_stable",), 2) < LOG.index(("click", 640, 460)), "OCR #2 precedes the field click"


def test_logon_aborts_on_a_console_password_prompt_someone_else_started_before_any_input():
    """The first frame is a Linux console whose last line is ``Password:``: an account name was
    already typed by someone else. Read before the wake, so not even the click or Esc is sent."""
    FakeKvm.frames = [CONSOLE]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "console_not_at_login_prompt")
    assert inputs() == [], "a console is read before the Windows wake, which never goes out"
    assert res["screen_label"] == "linux-console" and res["console_prompt"] == "password_prompt"


def test_logon_aborts_on_a_foreign_console_after_the_wake_and_clears_nothing():
    """A console that appears only AFTER the Windows wake is still refused: the console path is
    taken only from the first frame, so the wake already went out for a Windows screen."""
    FakeKvm.frames = [LOCK, CONSOLE]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "foreign_console_detected")
    assert inputs() == [("click", 640, 400), ("named_key", "escape")], "wake only; no clear, no character"
    assert res["ocr_backend"] == "fake" and res["foreign_markers"] is True
    assert "Windows sign-in was expected" in res["note"]


def test_logon_aborts_when_the_lock_screen_is_still_up_after_the_wake():
    """The wake did not produce a sign-in (clock and date only): no tile, no Password field.
    The tool re-reads WAKE_RECHECKS times, sending nothing more, before giving up."""
    FakeKvm.frames = [LOCK]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "signin_not_identified")
    assert inputs() == [("click", 640, 400), ("named_key", "escape")]
    assert res["user_tile"] is False and res["password_field"] is False
    assert LOG.count(("pause", amt_tools.WAKE_RECHECK_SECONDS)) == amt_tools.WAKE_RECHECKS


def test_logon_waits_out_a_slow_wake_without_sending_anything_more():
    """Live 2026-10-19: the first logon after a cold boot judged the frame while the lock screen
    was still fading. A re-read, with no new input, finds the sign-in and the logon proceeds."""
    FakeKvm.frames = [LOCK, LOCK, SIGNIN, SIGNIN, DESKTOP]
    res = amt_tools.remote_logon(confirmed=True)
    assert res["aborted"] is False and res["logged_in"] is True
    assert inputs()[:2] == [("click", 640, 400), ("named_key", "escape")]
    assert inputs().count(("named_key", "escape")) == 1 and FakeKvm.instances[0].typed == [WIN_PW]


def test_logon_keeps_checking_a_slow_welcome_before_reporting_failure():
    """Live 2026-10-19: the sign-in was still up 3 s after Enter and the desktop came later; the
    tool reported logged_in False. It now re-reads until the box is gone, typing once."""
    FakeKvm.frames = [SIGNIN] * 5 + [DESKTOP]
    res = amt_tools.remote_logon(confirmed=True)
    assert res["logged_in"] is True and FakeKvm.instances[0].typed == [WIN_PW]
    assert inputs().count(("named_key", "enter")) == 1


def test_logon_aborts_when_ocr_reads_no_text_from_a_frame():
    FakeKvm.frames = [SIGNIN, run_dialog_shot(SIGNIN)]      # post-wake frame is not a known screen
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "ocr_no_text")
    assert inputs() == [("click", 640, 400), ("named_key", "escape")]


def test_logon_rechecks_the_text_right_before_typing_the_password():
    """The sign-in was positively read after the wake; a console appears after the field click."""
    FakeKvm.frames = [SIGNIN, SIGNIN, CONSOLE]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "foreign_console_detected")
    assert len(OCR_CALLS) == 3


def test_a_desktop_with_a_hidden_taskbar_still_aborts_logon_by_ocr(monkeypatch):
    """An auto-hidden taskbar defeats the structural detector; the positive match is what stops
    the password going into an app. Held redundantly: neutralise the taskbar pre-filter."""
    monkeypatch.setattr(amt_tools, "taskbar_present", lambda fb, w, h: False)
    FakeKvm.frames = [DESKTOP]
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "signin_not_identified")
    assert inputs() == [("click", 640, 400), ("named_key", "escape")]


def test_logon_aborts_when_no_ocr_backend_is_usable_even_on_a_perfect_signin(monkeypatch):
    """Fail closed: a node that cannot read the screen cannot identify it, so it types nothing."""
    _no_ocr_backend(monkeypatch)
    FakeKvm.frames = LOGON_OK
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "ocr_unavailable")
    assert inputs() == [("click", 640, 400), ("named_key", "escape")]
    assert res["ocr_backend"] is None and "no OCR backend" in res["note"]


def test_logon_aborts_when_the_recognizer_fails_and_leaks_nothing_of_the_error(monkeypatch):
    _no_ocr_backend(monkeypatch, RuntimeError("vision exploded on " + WIN_PW))
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "ocr_failed")
    assert "exploded" not in json.dumps(res)


def test_logoff_aborts_when_no_ocr_backend_is_usable_even_on_a_perfect_desktop(monkeypatch):
    _no_ocr_backend(monkeypatch)
    FakeKvm.frames = LOGOFF_OK
    res = amt_tools.remote_logoff(confirmed=True)
    assert_aborted_typing_nothing(res, "ocr_unavailable")
    assert inputs() == [], "not even Win+R"


def test_logoff_aborts_on_a_console_the_taskbar_detector_mistakes_for_a_desktop(monkeypatch):
    monkeypatch.setattr(amt_tools, "taskbar_present", lambda fb, w, h: True)
    FakeKvm.frames = [CONSOLE]
    res = amt_tools.remote_logoff(confirmed=True)
    assert_aborted_typing_nothing(res, "foreign_console_detected")
    assert inputs() == []


def test_logoff_aborts_on_a_signin_screen_the_taskbar_detector_mistakes_for_a_desktop(monkeypatch):
    monkeypatch.setattr(amt_tools, "taskbar_present", lambda fb, w, h: True)
    FakeKvm.frames = [SIGNIN]
    res = amt_tools.remote_logoff(confirmed=True)
    assert_aborted_typing_nothing(res, "signin_screen_detected")
    assert inputs() == []


def test_logoff_ocr_runs_once_on_the_desktop_it_will_type_into():
    FakeKvm.frames = LOGOFF_OK
    assert amt_tools.remote_logoff(confirmed=True)["aborted"] is False
    assert len(OCR_CALLS) == 1


@pytest.mark.parametrize("scenario", ["bios_logon", "bios_logoff"])
def test_structural_aborts_never_pay_for_recognition(scenario):
    FakeKvm.size, FakeKvm.frames = (640, 480), [BIOS]
    fn = amt_tools.remote_logoff if scenario.endswith("logoff") else amt_tools.remote_logon
    assert fn(confirmed=True)["aborted"] is True
    assert OCR_CALLS == []


def test_a_logoff_without_a_taskbar_reads_once_to_rule_out_a_linux_console():
    FakeKvm.frames = [SIGNIN]
    assert_aborted_typing_nothing(amt_tools.remote_logoff(confirmed=True), "no_desktop_taskbar")
    assert len(OCR_CALLS) == 1 and inputs() == []


def test_a_blank_post_wake_abort_pays_only_for_the_first_frame_read():
    """The first frame is read to route a Linux console; the blank post-wake abort adds no read."""
    FakeKvm.frames = [BLANK, BLANK]
    assert_aborted_typing_nothing(amt_tools.remote_logon(confirmed=True), "screen_blank")
    assert len(OCR_CALLS) == 1


def test_an_abort_result_carries_findings_and_never_recognized_text():
    FakeKvm.frames = [LOCK]
    res = amt_tools.remote_logon(confirmed=True)
    assert set(res) == {"aborted", "reason", "device", "typed_nothing", "screen_label", "ocr_backend",
                        "foreign_markers", "user_tile", "password_field", "note", "screenshot"}
    assert res["screen_label"] == "lock"
    assert "Sunday" not in json.dumps(res) and "10:42" not in json.dumps(res)


# --- the screen classifier: one function names the context; the gates derive from it ------------

def _label(shot, user=WIN_USER, **kw):
    return amt_tools.classify_screen(shot, user, **kw)["label"]


@pytest.mark.parametrize("shot,label", [(SIGNIN, "windows-signin"), (DESKTOP, "desktop"), (LOCK, "lock"),
                                        (CONSOLE, "linux-console")])
def test_classify_screen_labels_each_synthetic_context(shot, label):
    cls = amt_tools.classify_screen(shot, WIN_USER)
    assert cls["label"] == label and label in amt_tools.SCREEN_LABELS
    assert set(cls) == {"label", "markers"}


def test_classify_screen_accepts_an_object_a_tuple_and_a_png():
    from io import BytesIO
    from PIL import Image
    assert _label((SIGNIN.fb, SIGNIN.width, SIGNIN.height)) == "windows-signin"
    buf = BytesIO()
    Image.frombytes("RGB", (DESKTOP.width, DESKTOP.height), DESKTOP.fb).save(buf, "PNG")
    frames.KIND_BY_DIGEST[frames.digest(Image.open(BytesIO(buf.getvalue())).convert("RGB").tobytes())] = "desktop"
    assert amt_tools.classify_screen(buf.getvalue(), WIN_USER)["label"] == "desktop"
    assert _label(object()) == "unknown" and _label(b"\x89PNG\r\n\x1a\nnot a png") == "unknown"
    assert _label(None) == "unknown"


def test_a_640x480_frame_with_no_boot_text_is_the_bios_setup_geometry_fallback():
    """A sub-Windows frame is now READ (GRUB, the installer and MOK are 800x600, so geometry alone
    cannot tell them from a BIOS), but a frame none of the boot signatures claims keeps the
    geometry label. The cheap structural pass the tools run first still never recognizes."""
    assert _label(BIOS) == "bios-setup"
    assert OCR_CALLS == [(BIOS.width, BIOS.height)]
    OCR_CALLS.clear()
    assert _label(BIOS, ocr=False) == "bios-setup" and OCR_CALLS == []


def test_classify_screen_fails_closed_to_unknown(monkeypatch):
    assert _label(Shot(1280, 800, b"")) == "unknown"                          # unreadable frame
    assert _label(BLANK) == "unknown"                                          # no text
    assert _label(run_dialog_shot(SIGNIN)) == "unknown"                        # a frame the fake cannot read
    _no_ocr_backend(monkeypatch)
    for shot in (SIGNIN, DESKTOP, LOCK, CONSOLE):
        cls = amt_tools.classify_screen(shot, WIN_USER)
        assert cls["label"] == "unknown" and cls["markers"]["ocr_problem"] == "ocr_unavailable"
    _no_ocr_backend(monkeypatch, RuntimeError("boom"))
    assert amt_tools.classify_screen(SIGNIN, WIN_USER)["markers"]["ocr_problem"] == "ocr_failed"


def test_classify_screen_without_ocr_never_runs_a_recognizer_and_labels_only_geometry():
    assert _label(SIGNIN, ocr=False) == "unknown" and _label(DESKTOP, ocr=False) == "unknown"
    assert _label(BIOS, ocr=False) == "bios-setup"
    m = amt_tools.classify_screen(DESKTOP, ocr=False)["markers"]
    assert m["taskbar"] is True and m["ocr_backend"] is None and OCR_CALLS == []


def test_the_sign_in_tile_must_be_the_vaulted_account():
    assert _label(SIGNIN, user="someone-else") == "unknown"
    assert _label(SIGNIN, user="DOMAIN\\" + WIN_USER) == "windows-signin"


def _fake_text(monkeypatch, frags, kind_shot):
    monkeypatch.setattr(amt_tools, "ocr_fragments", lambda fb, w, h: ("fake", frags))
    return amt_tools.classify_screen(kind_shot, WIN_USER)


F = amt_tools.Fragment


@pytest.mark.parametrize("name,frags", [
    ("UEFI shell", [F("UEFI Interactive Shell v2.2", 0.1, 0.1)]),
    ("a boot menu with no marker word", [F("Boot Menu", 0.5, 0.1), F("Hard Drive", 0.5, 0.3)]),
    ("a lone boot-loader word is not a GRUB menu", [F("Installing GRUB boot loader", 0.5, 0.2), F("16%", 0.5, 0.3)]),
    ("a lone installer-looking word is not the installer", [F("Select a language", 0.35, 0.35)]),
    ("a lone MOK word is not the MOK manager", [F("MOK", 0.5, 0.2), F("Continue boot", 0.5, 0.45)]),
    ("a GRUB menu AND an installer dialog in one frame is no label",
     [F("GNU GRUB  version 2.06", 0.5, 0.2), F("[!!] Select a language", 0.35, 0.35)]),
    ("a lock clock with no date", [F("10:42", 0.5, 0.23)]),
    ("a lock date with no clock", [F("Sunday, October 18", 0.5, 0.33)]),
    ("the tray clock and date without a taskbar", [F("02:19", 0.97, 0.96), F("10/18/2026", 0.96, 0.98)]),
    ("a tray clock with a LONG date, both in the corner, without a taskbar",
     [F("02:19", 0.97, 0.96), F("Sun Oct 18", 0.93, 0.98)]),
])
def test_boot_loaders_installers_and_half_a_lock_screen_are_unknown_not_a_fabricated_label(monkeypatch, name, frags):
    cls = _fake_text(monkeypatch, frags, SIGNIN)
    assert cls["label"] == "unknown", name


def test_boot_loader_words_are_labelled_grub_and_still_trip_the_foreign_veto(monkeypatch):
    cls = _fake_text(monkeypatch, [F("GNU GRUB  version 2.06", 0.5, 0.2)], SIGNIN)
    assert cls["label"] == "grub" and cls["markers"]["foreign_markers"] is True
    FakeKvm.frames = [SIGNIN]
    assert_aborted_typing_nothing(amt_tools.remote_logon(confirmed=True), "foreign_console_detected")


@pytest.mark.parametrize("label,frags", [
    ("grub", [F("GNU GRUB  version 2.06", 0.5, 0.2), F("*Windows Boot Manager", 0.3, 0.4)]),
    ("text-installer", [F("[!!] Select a language", 0.35, 0.35), F("English", 0.35, 0.45)]),
    ("mok-manager", [F("Perform MOK management", 0.4, 0.15), F("Continue boot", 0.5, 0.45)]),
])
@pytest.mark.parametrize("fn", [amt_tools.remote_logon, amt_tools.remote_logoff])
def test_the_boot_labels_never_pass_either_windows_gate(monkeypatch, label, frags, fn):
    """A labelled boot screen is still a foreign screen: both Windows tools abort with nothing typed,
    whatever the label is called (the gates need ``windows-signin`` / ``desktop``)."""
    assert _fake_text(monkeypatch, frags, SIGNIN)["label"] == label
    FakeKvm.frames = [SIGNIN]
    res = fn(confirmed=True)
    assert res["aborted"] is True and res["typed_nothing"] is True
    assert WIN_PW not in FakeKvm.instances[0].typed


def test_a_boot_word_in_a_taskbar_window_is_not_a_boot_screen(monkeypatch):
    """The label is withheld when a taskbar is present (a terminal window quoting GRUB)."""
    cls = _fake_text(monkeypatch, [F("GNU GRUB  version 2.06", 0.5, 0.2)], DESKTOP)
    assert cls["label"] == "unknown" and cls["markers"]["boot_screen"] == "grub"


def test_console_words_on_a_taskbar_desktop_are_ambiguous_not_a_console(monkeypatch):
    cls = _fake_text(monkeypatch, [F("Ubuntu 22.04 (WSL)", 0.4, 0.4), F("02:19", 0.97, 0.96)], DESKTOP)
    assert cls["label"] == "unknown"
    assert _fake_text(monkeypatch, [F("tty1", 0.1, 0.1)], SIGNIN)["label"] == "linux-console"


def test_signin_furniture_on_a_taskbar_frame_is_not_a_desktop(monkeypatch):
    cls = _fake_text(monkeypatch, [F(WIN_USER, 0.5, 0.5), F("Password", 0.42, 0.58)], DESKTOP)
    assert cls["label"] == "unknown"


def test_a_hidden_taskbar_desktop_is_not_mistaken_for_a_lock_screen(monkeypatch):
    monkeypatch.setattr(amt_tools, "taskbar_present", lambda fb, w, h: False)
    assert _label(DESKTOP) == "unknown"          # its tray clock/date sit in the corner the lock rule excludes


def test_markers_carry_findings_only_never_recognized_text():
    blob = json.dumps(amt_tools.classify_screen(SIGNIN, WIN_USER))
    assert WIN_USER not in blob and "Password" not in blob
    assert all(isinstance(v, (bool, int, str, type(None))) for v in amt_tools.classify_screen(LOCK)["markers"].values())


# The gates derive every screen decision from classify_screen's label: forcing the label from the
# classifier must flip the gate. A gate that re-implemented the logic would ignore the override.

def _force_label(monkeypatch, label, *, only_with_ocr=True):
    real = amt_tools.classify_screen

    def forced(frame, user="", *, ocr=True):
        cls = real(frame, user, ocr=ocr)
        return {**cls, "label": label} if (ocr or not only_with_ocr) and cls["label"] != "bios-setup" else cls
    monkeypatch.setattr(amt_tools, "classify_screen", forced)


def test_the_logon_gate_calls_classify_screen_at_every_stage(monkeypatch):
    seen = []
    real = amt_tools.classify_screen
    monkeypatch.setattr(amt_tools, "classify_screen",
                        lambda frame, user="", *, ocr=True: seen.append(ocr) or real(frame, user, ocr=ocr))
    amt_tools.remote_logon(confirmed=True)
    assert seen.count(False) == 3 and seen.count(True) == 3    # structural x3; full: first frame, after wake, before typing


def test_the_logoff_gate_calls_classify_screen(monkeypatch):
    seen = []
    real = amt_tools.classify_screen
    FakeKvm.frames = LOGOFF_OK
    monkeypatch.setattr(amt_tools, "classify_screen",
                        lambda frame, user="", *, ocr=True: seen.append(ocr) or real(frame, user, ocr=ocr))
    amt_tools.remote_logoff(confirmed=True)
    assert seen == [False, True]


def test_logon_types_only_when_the_classifier_labels_the_frame_windows_signin(monkeypatch):
    _force_label(monkeypatch, "unknown")
    res = amt_tools.remote_logon(confirmed=True)
    assert_aborted_typing_nothing(res, "signin_not_identified")
    assert res["screen_label"] == "unknown"


@pytest.mark.parametrize("label", ["lock", "desktop", "linux-console", "bios-setup", "unknown"])
def test_no_label_but_windows_signin_lets_the_password_be_typed(monkeypatch, label):
    if label == "bios-setup":
        FakeKvm.size, FakeKvm.frames = (640, 480), [BIOS]
        assert_aborted_typing_nothing(amt_tools.remote_logon(confirmed=True), "not_windows_resolution")
        return
    _force_label(monkeypatch, label)
    res = amt_tools.remote_logon(confirmed=True)
    assert res["aborted"] is True and res["typed_nothing"] is True
    assert ("type_text",) not in LOG and all(s.typed == [] for s in FakeKvm.instances)


def test_logon_returns_the_no_op_success_only_when_the_classifier_says_desktop(monkeypatch):
    _force_label(monkeypatch, "unknown")
    assert_aborted_typing_nothing(_run_on(DESKTOP), "host_already_logged_in")
    FakeKvm.instances.clear(); LOG.clear()
    _force_label(monkeypatch, "desktop")
    res = _run_on(DESKTOP)
    assert res["already_logged_in"] is True and res["typed_nothing"] is True and inputs() == []


def _run_on(shot):
    FakeKvm.frames = [shot]
    return amt_tools.remote_logon(confirmed=True)


def test_logoff_proceeds_only_when_the_classifier_says_desktop(monkeypatch):
    FakeKvm.frames = LOGOFF_OK
    _force_label(monkeypatch, "lock")
    assert_aborted_typing_nothing(amt_tools.remote_logoff(confirmed=True), "desktop_not_identified")
    assert inputs() == []
    FakeKvm.instances.clear(); LOG.clear()
    _force_label(monkeypatch, "desktop")
    assert amt_tools.remote_logoff(confirmed=True)["logoff_submitted"] is True


def test_logoff_on_a_desktop_is_unchanged_and_never_reports_already_logged_in():
    FakeKvm.frames = LOGOFF_OK
    res = amt_tools.remote_logoff(confirmed=True)
    assert res["aborted"] is False and res["logoff_submitted"] is True and "already_logged_in" not in res


# --- Linux text console logon (the first frame is a getty) ---------------------------------

TTY = {stage: tty_shot(stage) for stage in frames.TTY_STAGES}
U = ord("u")
CONSOLE_LOGON_SEQUENCE = [
    ("open",), ("grab_stable",),
    ("key", CTRL, True), ("tap", U), ("key", CTRL, False),       # Ctrl+U kills the getty line
    ("type_text",), ("named_key", "enter"),
    ("pause", amt_tools.CONSOLE_SETTLE_SECONDS), ("grab_stable",),
    ("type_text",), ("named_key", "enter"),
    ("pause", amt_tools.CONSOLE_SUBMIT_SECONDS), ("grab_stable",),
    ("grab_stable",),                                            # the evidence frame
]


def _console_run(*stages):
    FakeKvm.frames = [TTY[s] for s in stages]
    return amt_tools.remote_logon(confirmed=True)


def test_console_logon_types_the_account_then_the_password_only_after_a_password_prompt():
    res = _console_run("login", "password", "shell")
    assert LOG == CONSOLE_LOGON_SEQUENCE
    assert FakeKvm.instances[0].typed == [WIN_USER, WIN_PW]
    assert res["aborted"] is False and res["logged_in"] is True and res["login_incorrect"] is False
    assert res["screen_label"] == "linux-console" and res["console_prompt"] == "command_prompt"
    assert ("click", 640, 400) not in LOG and ("named_key", "escape") not in LOG, "no Windows wake"
    assert ("named_key", "delete") not in LOG and ("tap", A) not in LOG, "Ctrl+A is a literal in a tty"
    blob = json.dumps(res)
    assert WIN_PW not in blob and WIN_USER not in blob and AMT_PW not in blob


def test_console_logon_reports_login_incorrect_and_never_retries():
    res = _console_run("login", "password", "incorrect")
    assert res["aborted"] is False and res["logged_in"] is False and res["login_incorrect"] is True
    assert FakeKvm.instances[0].typed == [WIN_USER, WIN_PW], "one account name, one password"
    assert LOG.count(("named_key", "enter")) == 2


def test_console_logon_waits_out_the_motd_before_judging():
    res = _console_run("login", "password", "motd", "motd", "shell")
    assert res["logged_in"] is True and FakeKvm.instances[0].typed == [WIN_USER, WIN_PW]


def test_console_logon_with_no_verdict_in_time_is_unknown_not_false():
    res = _console_run("login", "password", "motd")
    assert res["logged_in"] is None and res["login_incorrect"] is False
    after_password = LOG[[i for i, e in enumerate(LOG) if e == ("type_text",)][1]:]
    assert after_password.count(("pause", amt_tools.CONSOLE_SUBMIT_SECONDS)) == amt_tools.CONSOLE_SUBMIT_CHECKS


def test_console_logon_ignores_an_older_failure_still_on_screen():
    res = _console_run("stale_login", "stale_password", "shell")
    assert res["logged_in"] is True and res["login_incorrect"] is False


def test_console_logon_without_a_password_prompt_never_types_the_password():
    res = _console_run("login", "login")
    assert res["aborted"] is True and res["reason"] == "password_prompt_not_identified"
    assert res["typed_nothing"] is False and res["account_typed"] is True and res["password_typed"] is False
    assert FakeKvm.instances[0].typed == [WIN_USER], "the account name only"
    assert LOG.count(("pause", amt_tools.CONSOLE_SETTLE_SECONDS)) == amt_tools.CONSOLE_PROMPT_CHECKS
    assert WIN_PW not in json.dumps(res) and WIN_USER not in json.dumps(res)


def test_console_already_at_a_shell_prompt_is_the_no_op_success():
    res = _console_run("shell")
    assert res["aborted"] is False and res["already_logged_in"] is True and res["typed_nothing"] is True
    assert res["console_prompt"] == "command_prompt" and "shell prompt" in res["logged_in_basis"]
    assert inputs() == []


@pytest.mark.parametrize("stage", ["password", "motd", "echo"])
def test_console_not_at_a_fresh_login_prompt_aborts_before_any_input(stage):
    """A Password: someone else started, motd text, or a shell line that merely ENDS in 'login:'
    (a typed command) is not getty's prompt: nothing is sent, not even Ctrl+U."""
    res = _console_run(stage)
    assert_aborted_typing_nothing(res, "console_not_at_login_prompt")
    assert inputs() == []


def test_console_logon_hides_the_account_name_when_typing_fails():
    FakeKvm.type_error = amt_kvm.AmtError("cannot type U+00E9 in " + WIN_USER)
    with pytest.raises(amt_kvm.AmtError) as ei:
        _console_run("login", "password", "shell")
    assert str(ei.value) == "logon_type_failed" and WIN_USER not in str(ei.value)
    assert FakeKvm.instances[0].closed is True


F_ = amt_tools.Fragment


@pytest.mark.parametrize("lines,kind", [
    (["host-ø1 login: -"], "login_prompt"),
    (["my-server-1 login:"], "login_prompt"),
    (["Last login: Mon Oct 19 02:33:12 EDT 2026 on tty1"], None),
    (["my-server-1 login: jdoe"], None),                     # someone typed a name already
    (["Password:"], "password_prompt"),
    (["[sudo] password for jdoe:"], None),
    (["user@my-server-1:~$ -"], "command_prompt"),
    (["root@my-server-1:/etc#"], "command_prompt"),
    (["user@my-server-1:~$ echo login:"], None),             # ends like getty, starts like a shell
    (["user@my-server-1:~$ ls"], None),
    (["my-server-1 login: -", "Debian GNU/Linux 13"], None),  # judged on the LAST line only
    ([], None),
])
def test_console_prompt_reads_the_last_line(lines, kind):
    frags = [F_(t, 0.1, 0.05 + 0.03 * i) for i, t in enumerate(lines)]
    assert amt_tools.console_prompt(frags) == kind


def test_console_prompt_joins_the_fragments_of_one_line_left_to_right():
    """tesseract splits a line into words; ocrmac sometimes into phrases."""
    frags = [F_("login:", 0.093, 0.0719), F_("ms-@2-ultra", 0.034, 0.0706), F_("-", 0.122, 0.0788)]
    assert amt_tools.console_prompt(frags) == "login_prompt"


CONSOLE_LOGOFF_SEQUENCE = [
    ("open",), ("grab_stable",),
    ("key", CTRL, True), ("tap", U), ("key", CTRL, False),
    ("type_text",), ("named_key", "enter"),
    ("pause", amt_tools.CONSOLE_SETTLE_SECONDS), ("grab_stable",),
    ("grab_stable",),                                            # the evidence frame
]


def _console_logoff(*stages):
    FakeKvm.frames = [TTY[s] for s in stages]
    return amt_tools.remote_logoff(confirmed=True)


def test_console_logoff_kills_the_line_types_exit_and_sees_getty_return():
    res = _console_logoff("shell", "login")
    assert LOG == CONSOLE_LOGOFF_SEQUENCE
    assert FakeKvm.instances[0].typed == ["exit"]
    assert res["aborted"] is False and res["logoff_submitted"] is True and res["logged_off"] is True
    assert res["console_prompt"] == "login_prompt" and WIN_USER not in json.dumps(res)


def test_console_logoff_from_a_nested_shell_reports_not_logged_off_and_sends_one_exit():
    res = _console_logoff("shell")
    assert res["logged_off"] is False and FakeKvm.instances[0].typed == ["exit"]


@pytest.mark.parametrize("stage", ["login", "password", "motd", "echo"])
def test_console_logoff_types_nothing_unless_the_last_line_is_a_shell_prompt(stage):
    res = _console_logoff(stage)
    assert_aborted_typing_nothing(res, "console_not_at_shell_prompt")
    assert inputs() == []


def test_console_logoff_never_reads_the_host_credential(monkeypatch):
    seen = []
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: seen.append(key) or VAULT[key])
    _console_logoff("shell", "login")
    assert seen == ["my-server-1-amt"]


def test_a_cleared_shell_prompt_alone_is_a_linux_console_but_a_bare_password_line_is_not(monkeypatch):
    assert _fake_text(monkeypatch, [F(f"{WIN_USER}@host:~$", 0.1, 0.03)], SIGNIN)["label"] == "linux-console"
    assert _fake_text(monkeypatch, [F("Password:", 0.1, 0.03)], SIGNIN)["label"] == "unknown"


# --- the confirmed guard ----------------------------------------------------------------

@pytest.mark.parametrize("fn,words", [
    (amt_tools.remote_logon, ("types the vaulted", "logs into the host")),
    (amt_tools.remote_logoff, ("signs the current", "out")),
])
@pytest.mark.parametrize("confirmed", [False, 1, "true", None])
def test_sync_function_demands_the_literal_true_and_nothing_runs_otherwise(fn, words, confirmed, monkeypatch):
    """The SYNC function (what a Python caller reaches) refuses anything but the literal True.
    This is NOT what an HTTP client meets: the schema (StrictBool) rejects non-booleans before the
    function runs; see the over-HTTP tests below for the real surface."""
    no_vault(monkeypatch)
    with pytest.raises(amt_tools.ConfirmationRequired) as ei:
        fn(confirmed=confirmed)
    assert all(w in str(ei.value) for w in words), str(ei.value)
    assert "confirmed=true" in str(ei.value)
    assert FakeKvm.instances == [] and LOG == []


def test_default_call_is_unconfirmed(monkeypatch):
    no_vault(monkeypatch)
    for fn in (amt_tools.remote_logon, amt_tools.remote_logoff):
        with pytest.raises(amt_tools.ConfirmationRequired):
            fn()
    assert FakeKvm.instances == []


def test_coroutines_refuse_without_confirmed_and_never_open_a_session(monkeypatch):
    no_vault(monkeypatch)
    for coro in (amt_tools.amt_remote_logon, amt_tools.amt_remote_logoff):
        with pytest.raises(amt_tools.ConfirmationRequired):
            asyncio.run(coro())
    assert FakeKvm.instances == []


def test_coroutine_refuses_immediately_without_waiting_on_the_session_lock(monkeypatch):
    """An unconfirmed call must not queue behind another holder of the redirection session."""
    no_vault(monkeypatch)

    async def run(coro):
        async with amt_tools._session_lock("my-server-1"):          # someone else holds the session
            with pytest.raises(amt_tools.ConfirmationRequired):
                await asyncio.wait_for(coro(), timeout=1)

    for coro in (amt_tools.amt_remote_logon, amt_tools.amt_remote_logoff):
        asyncio.run(run(coro))
    assert FakeKvm.instances == []


def test_refusal_over_the_gated_http_surface_is_an_error_naming_the_consequence():
    server = amt_server.register_tools(amt_server.build_server())
    with _client(server) as c:
        for name, phrase in (("amt_remote_logon", "logs into the host"),
                             ("amt_remote_logoff", "signs the current")):
            res = _call(c, name, TOKEN)
            assert res["isError"] is True
            assert "confirmation_required" in res["content"][0]["text"] and phrase in res["content"][0]["text"]
    assert FakeKvm.instances == []


def test_confirmed_runs_through_the_coroutine_and_closes():
    out = asyncio.run(amt_tools.amt_remote_logon(confirmed=True))
    assert out["logged_in"] is True and FakeKvm.instances[0].closed is True


def _call_with(client, name, arguments):
    status, msg = _rpc(client, "tools/call", {"name": name, "arguments": arguments}, TOKEN)
    assert status == 200, "a refusal must be an MCP tool error, never an HTTP status"
    return msg["result"]


def _text(res):
    return res["content"][0]["text"]


def _http_server():
    return amt_server.register_tools(amt_server.build_server())


# What a client can actually send over HTTP is decided by the tool's input schema, not by the
# ``is not True`` guard (which only ever sees the validated value). ``confirmed`` is a pydantic
# StrictBool, so ONLY the JSON boolean true runs a tool; "true", "yes", "1" and 1 (which lax bool
# coercion used to turn into True) are rejected before the function runs.
@pytest.mark.parametrize("name,frames", [("amt_remote_logon", LOGON_OK), ("amt_remote_logoff", LOGOFF_OK)])
def test_over_http_the_json_boolean_true_runs_the_tool(name, frames):
    FakeKvm.frames = frames
    with _client(_http_server()) as c:
        res = _call_with(c, name, {"confirmed": True})
    assert not res.get("isError"), _text(res)
    body = json.loads(_text(res))
    assert body["aborted"] is False and body["device"] == "my-server-1"
    assert len(FakeKvm.instances) == 1 and FakeKvm.instances[0].closed is True


@pytest.mark.parametrize("confirmed", ["true", "True", "yes", "1", 1, "false", "no", "0", 0])
@pytest.mark.parametrize("name", ["amt_remote_logon", "amt_remote_logoff"])
def test_over_http_a_coercible_non_boolean_is_rejected_and_nothing_runs(name, confirmed, monkeypatch):
    no_vault(monkeypatch)
    with _client(_http_server()) as c:
        res = _call_with(c, name, {"confirmed": confirmed})
    assert res["isError"] is True
    assert "confirmation_required" not in _text(res), "rejected by the schema, not by the guard"
    assert "confirmed" in _text(res)
    assert FakeKvm.instances == [] and LOG == []


@pytest.mark.parametrize("name,phrase", [("amt_remote_logon", "logs into the host"),
                                         ("amt_remote_logoff", "signs the current")])
def test_over_http_the_json_boolean_false_is_refused_naming_the_consequence(name, phrase, monkeypatch):
    no_vault(monkeypatch)
    with _client(_http_server()) as c:
        res = _call_with(c, name, {"confirmed": False})
    assert res["isError"] is True
    assert "confirmation_required" in _text(res) and phrase in _text(res)
    assert FakeKvm.instances == [] and LOG == []


@pytest.mark.parametrize("confirmed", ["maybe", 2, None, [], {}])
def test_over_http_a_value_that_is_not_a_boolean_never_reaches_the_tool(confirmed, monkeypatch):
    no_vault(monkeypatch)
    with _client(_http_server()) as c:
        res = _call_with(c, "amt_remote_logon", {"confirmed": confirmed})
    assert res["isError"] is True
    assert FakeKvm.instances == [] and LOG == []


def test_over_http_the_guard_still_needs_a_true_to_open_a_session():
    """The guard is the last line, behind the schema: no session without a True."""
    assert amt_tools._require_confirmed(True, "x") is None
    for bad in (False, 0, 1, "true", None, "yes"):
        with pytest.raises(amt_tools.ConfirmationRequired):
            amt_tools._require_confirmed(bad, "x")


# --- the per-device session lock --------------------------------------------------------

def test_the_session_lock_validates_the_device_key_before_it_grows_the_lock_table(monkeypatch):
    no_vault(monkeypatch)

    async def run():
        loop = asyncio.get_running_loop()
        before = dict(amt_tools._SESSION_LOCKS.get(loop, {}))
        for junk in ("nope", "x" * 5000, "", "../../etc/passwd", "my-server-1\x00"):
            with pytest.raises(KeyError, match="unknown_device"):
                amt_tools._session_lock(junk)
            for coro in (amt_tools.amt_remote_logon, amt_tools.amt_remote_logoff):
                with pytest.raises(KeyError, match="unknown_device"):
                    await coro(device=junk, confirmed=True)
        assert dict(amt_tools._SESSION_LOCKS.get(loop, {})) == before
        assert amt_tools._session_lock("my-server-1") is amt_tools._session_lock("my-server-1")
        assert list(amt_tools._SESSION_LOCKS[loop]) == ["my-server-1"]

    asyncio.run(run())
    assert FakeKvm.instances == [] and FakeWsman.calls == []


def test_an_unknown_device_over_http_is_a_tool_error_and_runs_nothing(monkeypatch):
    no_vault(monkeypatch)
    with _client(_http_server()) as c:
        res = _call_with(c, "amt_remote_logon", {"device": "nope", "confirmed": True})
    assert res["isError"] is True and "unknown_device" in _text(res)
    assert FakeKvm.instances == [] and LOG == []


# --- the password never leaves the tool -------------------------------------------------

def test_password_comes_from_the_vault_and_appears_in_no_result_argument_or_log(caplog):
    caplog.set_level(0)
    out = amt_tools.remote_logon(confirmed=True)
    blob = json.dumps(out)
    assert WIN_PW not in blob and WIN_USER not in blob and AMT_PW not in blob
    assert all(WIN_PW not in repr(entry) for entry in LOG)
    assert WIN_PW not in caplog.text
    # No length of the secret: no length-ish key, and no value equal to len(password) or len(AMT pw).
    assert not [k for k in out if "len" in k.lower()]
    assert len(WIN_PW) not in out.values() and len(AMT_PW) not in out.values()
    # The password is not an input of either tool: the only other parameter picks the console.
    for fn in (amt_tools.amt_remote_logon, amt_tools.amt_remote_logoff):
        assert set(inspect.signature(fn).parameters) == {"device", "confirmed", "console"}


@pytest.mark.parametrize("scenario", ["power", "bios", "late_desktop", "blank", "no_taskbar", "no_run_dialog"])
def test_no_abort_path_types_or_leaks_the_password(scenario, caplog):
    caplog.set_level(0)
    fn = amt_tools.remote_logoff if scenario in ("no_taskbar", "no_run_dialog") else amt_tools.remote_logon
    if scenario == "power":
        FakeWsman.power = "8"
    elif scenario == "bios":
        FakeKvm.size, FakeKvm.frames = (640, 480), [BIOS]
    elif scenario == "late_desktop":
        FakeKvm.frames = [SIGNIN, SIGNIN, DESKTOP]      # after the clear: the one desktop that still aborts
    elif scenario == "blank":
        FakeKvm.frames = [BLANK, BLANK]
    elif scenario == "no_taskbar":
        FakeKvm.frames = [SIGNIN]
    else:
        FakeKvm.frames = [DESKTOP, DESKTOP]
    res = fn(confirmed=True)
    assert res["aborted"] is True
    assert ("type_text",) not in LOG and all(s.typed == [] for s in FakeKvm.instances)
    surfaces = json.dumps(res) + caplog.text + "".join(repr(e) for e in LOG)
    assert WIN_PW not in surfaces and WIN_USER not in surfaces and AMT_PW not in surfaces
    assert str(len(WIN_PW)) not in {str(v) for v in res.values() if isinstance(v, int)}


def test_type_failure_is_rewritten_so_no_password_character_code_escapes():
    FakeKvm.type_error = amt_kvm.AmtError("non_ascii_char_0xe9")
    with pytest.raises(amt_kvm.AmtError) as ei:
        amt_tools.remote_logon(confirmed=True)
    assert str(ei.value) == "logon_type_failed" and "e9" not in repr(ei.value)
    assert ei.value.__cause__ is None and ei.value.__suppress_context__ is True
    assert ("named_key", "enter") not in LOG, "a failed type must not be submitted"
    assert FakeKvm.instances[0].closed is True


@pytest.mark.parametrize("raw", ["not json " + WIN_PW, json.dumps({"user": "u"}),
                                 json.dumps({"password": ""}), json.dumps([WIN_PW]),
                                 json.dumps({"password": WIN_PW}),          # no user: nothing to match
                                 json.dumps({"user": "", "password": WIN_PW}),
                                 json.dumps({"password": 12345})])
def test_bad_credential_shape_fails_closed_naming_only_the_key(monkeypatch, raw):
    monkeypatch.setattr(amt_vault, "get_secret",
                        lambda key: raw if key == "my-server-1-os" else AMT_PW)
    with pytest.raises(amt_vault.VaultError) as ei:
        amt_tools.remote_logon(confirmed=True)
    assert str(ei.value) == "vault_bad_credential_shape:my-server-1-os"
    assert WIN_PW not in repr(ei.value) and ei.value.__cause__ is None
    assert FakeKvm.instances == [], "a bad credential must be found before the session opens"


def test_a_device_without_a_host_credential_is_refused_before_the_wire(monkeypatch):
    dev = amt_wsman.amt_registry.Device(key="nohost", amt_ip="192.0.2.9", wsman_port=1, kvm_port=2,
                                        amt_vault_key="my-server-1-amt", tls_leaf_sha256=PIN)
    monkeypatch.setitem(amt_wsman.amt_registry.DEVICES, "nohost", dev)
    with pytest.raises(amt_vault.VaultError, match="no_host_credential:nohost"):
        amt_tools.remote_logon("nohost", confirmed=True)
    assert FakeKvm.instances == []


def test_open_failure_closes_the_session_and_types_nothing():
    FakeKvm.fail_open = True
    for fn in (amt_tools.remote_logon, amt_tools.remote_logoff):
        with pytest.raises(amt_kvm.AmtError, match="auth_rejected_no_retry"):
            fn(confirmed=True)
    assert all(s.closed for s in FakeKvm.instances) and len(FakeKvm.instances) == 2
    assert ("type_text",) not in LOG


# --- the TLS pin ------------------------------------------------------------------------

@pytest.mark.parametrize("fn", [amt_tools.remote_logon, amt_tools.remote_logoff])
def test_pin_match_connects_and_mismatch_is_refused_before_use(fn):
    FakeKvm.frames = LOGON_OK if fn is amt_tools.remote_logon else LOGOFF_OK
    fn(confirmed=True)
    assert FakeKvm.instances[0].past_connect is True
    FakeKvm.instances.clear(); LOG.clear()
    FakeKvm.presented_fp = "0" * 64
    with pytest.raises(amt_kvm.AmtError, match="tls_leaf_pin_mismatch"):
        fn(confirmed=True)
    (s,) = FakeKvm.instances
    assert s.past_connect is False and s.closed is True
    assert LOG == [] and s.typed == [], "nothing may be sent on a connection whose leaf failed the pin"


@pytest.mark.parametrize("fn", [amt_tools.remote_logon, amt_tools.remote_logoff])
def test_unpinned_device_is_refused_before_vault_disk_or_wire(fn, monkeypatch, tmp_path):
    unpinned = amt_wsman.amt_registry.Device(key="u", amt_ip="192.0.2.1", wsman_port=1, kvm_port=2,
                                             amt_vault_key="k", host_vault_key="h", tls_leaf_sha256=None)
    monkeypatch.setitem(amt_wsman.amt_registry.DEVICES, "u", unpinned)
    no_vault(monkeypatch)
    with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
        fn("u", confirmed=True)
    assert FakeKvm.instances == [] and not (tmp_path / "shots").exists()


# --- registration and annotations -------------------------------------------------------

def test_registered_as_write_tools_with_titles_guard_and_described_parameters():
    tools = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}
    for name in ("amt_remote_logon", "amt_remote_logoff"):
        t = tools[name]
        assert t.annotations.readOnlyHint is False and t.annotations.title
        assert t.annotations.idempotentHint is False
        props = t.inputSchema["properties"]
        assert set(props) == {"device", "confirmed", "console"}
        assert props["console"].get("default") == "kvm" and props["console"]["enum"] == ["kvm", "serial"]
        assert props["confirmed"].get("default") is False
        assert all(p.get("description") for p in props.values())
        assert props["device"].get("default") == "my-server-1"
    # Both are destructive: logon issues Delete to clear the field, logoff closes the session.
    assert tools["amt_remote_logoff"].annotations.destructiveHint is True
    assert tools["amt_remote_logon"].annotations.destructiveHint is True
