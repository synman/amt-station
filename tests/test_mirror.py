"""Display mirror: viewer page and stream, token gate, recording, the shared session the console
tools reuse, serialized socket use, failure handling and the confirmed gate. No network to AMT:
the KVM session is a fake; the viewer HTTP server is real (loopback, a free port)."""
import asyncio
import http.client
import json
import subprocess
import threading
import time
import urllib.error
import urllib.request

import pytest
from pathlib import Path

import amt_mirror
import amt_server
import amt_tools
import amt_vault
import amt_write

W, H = 64, 32


class FakeSession:
    instances: list["FakeSession"] = []

    def __init__(self, *a, **k):
        self.width, self.height = W, H
        self.fb = bytearray(b"\x10" * (W * H * 3))
        self.log, self.opened, self.closed, self.grabs = [], 0, False, 0
        self.keys: list = []
        self.in_grab = False
        self.overlap = False
        self.fail_after = None
        self.grab_seconds = 0.01
        self.cert_fp = "pin"
        FakeSession.instances.append(self)

    def open(self, deadline=None):
        self.opened += 1
        return W, H

    def close(self):
        self.closed = True

    def grab_frame(self, deadline=None):
        if self.fail_after is not None and self.grabs >= self.fail_after:
            raise amt_tools.amt_kvm.AmtError("socket closed by AMT")
        self.in_grab = True
        time.sleep(self.grab_seconds)
        self.grabs += 1
        self.fb[0] = self.grabs % 256
        self.log.append("frame complete")
        self.in_grab = False
        return W, H

    def grab_update(self, wait=0.25):
        self.grab_frame()
        self.updates = getattr(self, "updates", 0) + 1
        return True

    def grab_stable(self, *a, **k):
        self.grab_frame()
        return W, H, 1, True, 0

    def write_png(self, path):
        open(path, "wb").write(b"\x89PNG fake")
        return path

    def _key(self, keysym, down):
        if self.in_grab:
            self.overlap = True
        time.sleep(0.002)            # long enough that unserialized input lands mid-grab
        if self.in_grab:
            self.overlap = True
        self.keys.append((keysym, down))

    def tap(self, keysym):
        self._key(keysym, True)
        self._key(keysym, False)

    def pointer(self, x, y, mask=0):
        if self.in_grab:
            self.overlap = True
        self.keys.append(("p", x, y, mask))


@pytest.fixture
def fake(monkeypatch):
    FakeSession.instances = []
    monkeypatch.setattr(amt_tools, "_pinned_kvm_session", lambda dev, pw: FakeSession())
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: "pw")
    yield
    for key in list(amt_mirror._MIRRORS):
        amt_mirror.stop(key)


def _get(url, method="GET"):
    req = urllib.request.Request(url, method=method)
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.headers.get("Content-Type"), r.read()


def _wait(pred, timeout=5):
    end = time.time() + timeout
    while time.time() < end:
        if pred():
            return
        time.sleep(0.02)
    raise AssertionError("condition not reached")


def _start(**kw):
    out = amt_mirror.start(port=0, fps=20, **kw)
    m = amt_mirror._MIRRORS["my-server-1"]
    _wait(lambda: m.seq >= 2)
    return out, m


def test_page_frame_status_and_stream_are_served_with_the_token(fake):
    out, m = _start()
    url = out["urls"][0]
    assert url.startswith("http://127.0.0.1:") and m.token in url
    code, ctype, body = _get(url)
    assert code == 200 and "text/html" in ctype and b"my-server-1" in body
    code, ctype, body = _get(url + "frame.jpg")
    assert code == 200 and ctype == "image/jpeg" and body[:2] == b"\xff\xd8"
    _, _, body = _get(url + "status.json")
    assert b'"live": true' in body
    with urllib.request.urlopen(url + "stream", timeout=5) as r:
        assert r.headers.get("Content-Type").startswith("multipart/x-mixed-replace")
        assert r.headers.get("X-Accel-Buffering") == "no"
        chunk = r.read(4096)
    assert b"--frame" in chunk and b"\xff\xd8" in chunk


def _post(url, body: bytes):
    req = urllib.request.Request(url, data=body, method="POST",
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status, r.read()


def _events(url, events):
    return _post(url + "input", json.dumps({"events": events}).encode())


def test_the_view_link_is_view_only_and_the_control_link_offers_control(fake):
    out, m = _start()
    view, control = out["urls"][0], out["control_urls"][0]
    assert m.token in view and m.control_token in control and m.token != m.control_token
    assert b"const CONTROL=false" in _get(view)[2]
    assert b"const CONTROL=true" in _get(control)[2]
    assert _get(control + "frame.jpg")[0] == 200          # the control link also views


def test_input_from_the_control_link_reaches_the_host_in_order(fake):
    out, m = _start()
    session = FakeSession.instances[0]
    code, body = _events(out["control_urls"][0],
                         [["k", 0xFFE3, 1], ["k", 0x61, 1], ["k", 0x61, 0], ["k", 0xFFE3, 0],
                          ["p", 10, 5, 1], ["p", 10, 5, 0]])
    assert code == 200 and json.loads(body) == {"sent": 6}
    assert session.keys == [(0xFFE3, True), (0x61, True), (0x61, False), (0xFFE3, False),
                            ("p", 10, 5, 1), ("p", 10, 5, 0)]


def test_the_view_link_cannot_send_input(fake):
    out, m = _start()
    with pytest.raises(urllib.error.HTTPError) as ex:
        _events(out["urls"][0], [["k", 0x61, 1]])
    assert ex.value.code == 404 and FakeSession.instances[0].keys == []


@pytest.mark.parametrize("events", [
    [["k", 0x61, 1], ["k", 0x61, 2]],            # down must be 0 or 1
    [["k", 0x61, 1], ["x", 1]],                  # unknown kind
    [["p", -1, 0, 0]],                           # negative coordinate
    [["p", 1, 1, 256]],                          # mask is one byte
    [["k", "a", 1]],                             # keysym must be an int
    [],                                          # empty batch
    [["k", 0x61, 1]] * (amt_mirror.MAX_INPUT_EVENTS + 1),
])
def test_a_bad_batch_is_refused_and_sends_nothing(fake, events):
    out, _ = _start()
    with pytest.raises(urllib.error.HTTPError) as ex:
        _events(out["control_urls"][0], events)
    assert ex.value.code == 400 and FakeSession.instances[0].keys == []


def test_a_malformed_or_oversized_body_is_refused(fake):
    out, _ = _start()
    url = out["control_urls"][0] + "input"
    for body, code in ((b"not json", 400), (b'{"nope": []}', 400),
                       (b"x" * (amt_mirror.MAX_INPUT_BYTES + 1), 413)):
        with pytest.raises(urllib.error.HTTPError) as ex:
            _post(url, body)
        assert ex.value.code == code
    assert FakeSession.instances[0].keys == []


def test_pointer_coordinates_are_clamped_to_the_screen(fake):
    out, _ = _start()
    _events(out["control_urls"][0], [["p", 5000, 5000, 0]])
    assert FakeSession.instances[0].keys == [("p", W - 1, H - 1, 0)]


def test_browser_input_never_overlaps_a_frame_grab(fake):
    out = amt_mirror.start(port=0, fps=30)
    m = amt_mirror._MIRRORS["my-server-1"]
    session = FakeSession.instances[0]
    session.grab_seconds = 0.02
    _wait(lambda: m.seq >= 2)
    batch = [["k", 0x61, 1], ["k", 0x61, 0]] * 100
    for _ in range(2):
        _events(out["control_urls"][0], batch)
    assert len(session.keys) == 400 and session.overlap is False


def test_input_to_a_dead_mirror_is_refused(fake):
    out, m = _start()
    FakeSession.instances[0].fail_after = FakeSession.instances[0].grabs
    _wait(lambda: not m.alive())
    with pytest.raises(urllib.error.HTTPError) as ex:
        _events(out["control_urls"][0], [["k", 0x61, 1]])
    assert ex.value.code == 409


def test_a_wrong_token_or_unknown_route_gets_nothing(fake):
    out, m = _start()
    base = out["urls"][0].rsplit("/m/", 1)[0]
    for path in ("/m/not-the-token/", "/m/not-the-token/frame.jpg", f"/m/{m.token}/secrets", "/"):
        with pytest.raises(urllib.error.HTTPError) as ex:
            _get(base + path)
        assert ex.value.code == 404


def _record(out, m, tmp_path, frames=3):
    amt_mirror.set_recording_dir(str(tmp_path / "rec"))
    _get(out["urls"][0] + "record?on=1", method="POST")
    _wait(lambda: m.recording is not None and m.recording["frames"] >= frames)
    _get(out["urls"][0] + "record?on=0", method="POST")
    _wait(lambda: m.last_recording["encoding"] != "running", timeout=60)
    return m.last_recording


def test_without_ffmpeg_the_raw_mjpeg_and_its_frame_times_are_kept(fake, tmp_path, monkeypatch):
    monkeypatch.setattr(amt_mirror.shutil, "which", lambda name: None)
    out, m = _start()
    rec = _record(out, m, tmp_path)
    assert rec["encoding"].startswith("failed: ffmpeg_missing")
    data = open(rec["path"], "rb").read()
    times = open(rec["timestamps"]).read().split()
    assert rec["path"].endswith(".mjpeg") and data[:2] == b"\xff\xd8"
    assert len(amt_mirror._split_mjpeg(data)) == len(times) == rec["frames"] >= 3


@pytest.mark.skipif(amt_mirror.shutil.which("ffmpeg") is None, reason="needs ffmpeg")
def test_a_stopped_recording_becomes_an_h264_mp4_at_its_real_length(fake, tmp_path):
    out, m = _start()
    rec = _record(out, m, tmp_path, frames=5)
    assert rec["encoding"] == "done" and rec["path"].endswith(".mp4") and rec["raw"] is None
    mp4 = Path(rec["path"])
    assert not mp4.with_suffix(".mjpeg").exists() and not mp4.with_suffix(".times").exists()
    probe = subprocess.run(["ffprobe", "-v", "error", "-select_streams", "v:0", "-show_entries",
                            "stream=codec_name,pix_fmt:format=duration", "-of", "json", str(mp4)],
                           capture_output=True, text=True, check=True)
    info = json.loads(probe.stdout)
    assert info["streams"][0]["codec_name"] == "h264" and info["streams"][0]["pix_fmt"] == "yuv420p"
    assert abs(float(info["format"]["duration"]) - rec["seconds"]) < 1.0


@pytest.mark.skipif(amt_mirror.shutil.which("ffmpeg") is None, reason="needs ffmpeg")
def test_a_still_screen_keeps_its_real_length_in_the_mp4(tmp_path):
    raw = tmp_path / "still.mjpeg"
    jpeg = amt_mirror._encode_jpeg(W, H, bytes(W * H * 3), 70)
    raw.write_bytes(jpeg * 2)
    raw.with_suffix(".times").write_text("100.0\n103.0\n")     # one change, then 3 s and 2 s still
    mp4 = amt_mirror.encode_mp4(raw, end=105.0)
    probe = subprocess.run(["ffprobe", "-v", "error", "-show_entries", "format=duration", "-of",
                            "csv=p=0", str(mp4)], capture_output=True, text=True, check=True)
    assert abs(float(probe.stdout) - 5.0) < 0.3


def test_split_mjpeg_returns_each_frame_whole():
    a = amt_mirror._encode_jpeg(W, H, bytes(W * H * 3), 70)
    b = amt_mirror._encode_jpeg(W, H, b"\xff" * (W * H * 3), 70)
    assert amt_mirror._split_mjpeg(a + b + a) == [a, b, a] and amt_mirror._split_mjpeg(b"") == []


def test_status_names_the_recording_folder_and_host(fake, tmp_path):
    out, _ = _start()
    amt_mirror.set_recording_dir(str(tmp_path / "here"))
    s = json.loads(_get(out["urls"][0] + "status.json")[2])
    assert s["recording_dir"] == str((tmp_path / "here").resolve()) and s["hostname"]


def test_console_tools_reuse_the_live_mirror_session(fake):
    _start()
    amt_tools.screenshot()
    assert len(FakeSession.instances) == 1 and FakeSession.instances[0].opened == 1   # no 2nd session
    shared = amt_tools._kvm_session(amt_mirror.amt_registry.get_device("my-server-1"), "pw")
    shared.open()
    shared.close()
    assert FakeSession.instances[0].closed is False                                     # mirror owns it


def test_shared_grabs_read_the_live_framebuffer_and_never_request_a_full_frame(fake, monkeypatch):
    _, m = _start()
    session = FakeSession.instances[0]
    session.grab_frame = lambda *a, **k: (_ for _ in ()).throw(AssertionError("full request sent"))
    shared = amt_mirror.shared_session("my-server-1")
    m.frame_at = time.time() - 10            # the screen has been still
    w, h, iters, stable, _ = shared.grab_stable(settle=0.01)
    assert (w, h, stable, iters) == (W, H, True, 1)
    assert shared.grab_frame() == (W, H)


def test_shared_grab_stable_waits_while_the_screen_keeps_changing(fake):
    _, m = _start()
    shared = amt_mirror.shared_session("my-server-1")
    stop = threading.Event()

    def churn():
        while not stop.is_set():
            m.frame_at = time.time()
            time.sleep(0.002)
    t = threading.Thread(target=churn)
    t.start()
    try:
        assert shared.grab_stable(max_iters=3, settle=0.02)[3] is False
    finally:
        stop.set()
        t.join()


def test_input_through_the_shared_session_never_overlaps_a_frame_grab(fake):
    # The frame thread grabs ~60% of the time (20 ms of each 33 ms); 400 keys take ~0.8 s, so
    # without the socket lock some key would land mid-grab. Verified by removing the lock.
    out = amt_mirror.start(port=0, fps=30)
    m = amt_mirror._MIRRORS["my-server-1"]
    session = FakeSession.instances[0]
    session.grab_seconds = 0.02
    _wait(lambda: m.seq >= 2)
    shared = amt_mirror.shared_session("my-server-1")
    grabs_before = session.grabs
    for _ in range(200):
        shared.tap(0x61)
    assert len(session.keys) == 400 and session.overlap is False
    assert session.grabs - grabs_before >= 5        # the mirror kept grabbing throughout


def test_stop_releases_the_session_and_falls_back_to_private_sessions(fake):
    _start()
    out = amt_mirror.stop("my-server-1")
    assert out["stopped"] and out["session_released"] and FakeSession.instances[0].closed
    assert amt_mirror.shared_session("my-server-1") is None and amt_mirror._SERVER == {}
    amt_tools.screenshot()
    assert len(FakeSession.instances) == 2     # a fresh private session


def test_a_failing_session_stops_the_mirror_and_reports_why(fake):
    _, m = _start()
    FakeSession.instances[0].fail_after = FakeSession.instances[0].grabs
    _wait(lambda: not m.alive())
    assert "socket closed by AMT" in m.error and FakeSession.instances[0].closed
    assert amt_mirror.shared_session("my-server-1") is None


def test_engine_log_is_bounded_on_a_long_mirror(fake):
    _, m = _start()
    _wait(lambda: m.seq >= amt_mirror.LOG_KEEP + 20)
    assert len(FakeSession.instances[0].log) <= amt_mirror.LOG_KEEP + 1


def test_start_is_idempotent_while_live(fake):
    first, _ = _start()
    again = amt_mirror.start(port=0)
    assert again["note"].startswith("already live") and len(FakeSession.instances) == 1
    assert first["urls"] == again["urls"]


@pytest.mark.parametrize("kw", [{"action": "start"}, {"action": "record_start"}])
def test_start_and_record_start_need_confirmed(fake, kw):
    with pytest.raises(amt_tools.ConfirmationRequired):
        asyncio.run(amt_mirror.amt_mirror_link(**kw))
    assert FakeSession.instances == []


def test_status_and_stop_need_no_confirmation(fake):
    assert asyncio.run(amt_mirror.amt_mirror_link(action="status"))["mirrors"] == []
    assert asyncio.run(amt_mirror.amt_mirror_link(action="stop"))["stopped"] is False


def test_bad_settings_are_refused_before_a_session(fake):
    with pytest.raises(ValueError, match="mirror_bad_settings"):
        amt_mirror.start(fps=0)
    assert FakeSession.instances == []


def test_input_is_not_held_behind_a_frame_period_on_a_still_screen(fake):
    # A still screen: every update wait runs its full length under the socket lock. Input must
    # get in within about one slice, not one frame period (183 ms median live before the fix).
    out = amt_mirror.start(port=0, fps=5)    # the live rate when 183 ms was measured
    m = amt_mirror._MIRRORS["my-server-1"]
    _wait(lambda: m.seq >= 1)
    session = FakeSession.instances[0]
    session.grab_update = lambda wait=0.25: (time.sleep(wait), False)[1]
    time.sleep(0.3)
    took = []
    for _ in range(15):
        began = time.perf_counter()
        amt_mirror.send_input(m, [["p", 1, 1, 0]])
        took.append(time.perf_counter() - began)
        time.sleep(0.011)
    took.sort()
    assert took[len(took) // 2] < 0.06, took


def test_hidden_elements_stay_hidden_despite_their_display_rules():
    # .badge and .grp set display, which beats the browser's own [hidden] rule: without this the
    # REC badge showed while nothing recorded and the Control group would show on a view link.
    assert "[hidden]{display:none!important}" in amt_mirror.PAGE


# --- KVM keepalive -------------------------------------------------------------------------

def test_an_idle_mirror_sends_a_no_op_key_release_so_amt_keeps_the_session(fake, monkeypatch):
    monkeypatch.setattr(amt_mirror, "KVM_KEEPALIVE_SECONDS", 0.05)
    _, m = _start()
    session = FakeSession.instances[0]
    _wait(lambda: session.keys.count((amt_mirror.KEEPALIVE_KEYSYM, False)) >= 2)
    assert set(session.keys) == {(amt_mirror.KEEPALIVE_KEYSYM, False)}    # releases only, nothing pressed


def test_input_from_the_page_or_the_agent_postpones_the_keepalive(fake, monkeypatch):
    monkeypatch.setattr(amt_mirror, "KVM_KEEPALIVE_SECONDS", 0.4)
    out, m = _start()
    session = FakeSession.instances[0]
    shared = amt_mirror.shared_session("my-server-1")
    end = time.time() + 1.0
    while time.time() < end:                  # input every 0.1 s, well inside the keepalive period
        _events(out["control_urls"][0], [["p", 1, 1, 0]])
        shared.tap(0x61)
        time.sleep(0.1)
    assert (amt_mirror.KEEPALIVE_KEYSYM, False) not in session.keys


# --- IDE-R media from the control page ----------------------------------------------------

@pytest.fixture
def images(tmp_path):
    root = tmp_path / "imgs"
    root.mkdir()
    (root / "debian.iso").write_bytes(b"\0" * 2048)
    (root / "odd.iso").write_bytes(b"\0" * 100)            # not a multiple of 512: not offered
    (root / "floppy.img").write_bytes(b"\0" * 1024)        # not an ISO: not offered
    amt_write.ider_set_root(str(root))
    return root


def test_media_routes_answer_only_the_control_link(fake, images):
    out, _ = _start()
    for path, method in (("media.json", "GET"), ("ider", "POST")):
        with pytest.raises(urllib.error.HTTPError) as ex:
            if method == "GET":
                _get(out["urls"][0] + path)
            else:
                _post(out["urls"][0] + path, b'{"action": "unmount"}')
        assert ex.value.code == 404
    listing = json.loads(_get(out["control_urls"][0] + "media.json")[2])
    assert listing["images"] == ["debian.iso"]


def test_the_page_mounts_at_next_boot_only_and_unmounts(fake, images, monkeypatch):
    calls = []

    async def ider(action, **kw):          # the registered tool the page's route dispatches to
        calls.append((action, kw))
        return {"mounted": action == "mount"}
    monkeypatch.setattr(amt_write, "amt_ider", ider)
    out, _ = _start()
    url = out["control_urls"][0] + "ider"
    assert _post(url, b'{"action": "mount", "iso": "debian.iso", "start": "now"}')[0] == 200
    assert _post(url, b'{"action": "unmount"}')[0] == 200
    mounts = [c for c in calls if c[0] in ("mount", "unmount")]
    assert mounts == [("mount", {"iso_path": "debian.iso", "start": "next_boot", "device": "my-server-1",
                                 "confirmed": True}),
                      ("unmount", {"device": "my-server-1", "confirmed": True})]


@pytest.mark.parametrize("body", [b'{"action": "mount", "iso": "odd.iso"}',
                                  b'{"action": "mount", "iso": "../etc/passwd"}',
                                  b'{"action": "mount"}', b'{"action": "reset"}', b'[]'])
def test_the_page_cannot_mount_an_unlisted_image_or_do_anything_else(fake, images, monkeypatch, body):
    calls = []

    async def ider(action, **kw):
        calls.append(action)
        return {}
    monkeypatch.setattr(amt_write, "amt_ider", ider)
    out, _ = _start()
    with pytest.raises(urllib.error.HTTPError) as ex:
        _post(out["control_urls"][0] + "ider", body)
    assert ex.value.code == 409 and [c for c in calls if c != "status"] == []


def test_status_reports_the_mount(fake, images):
    out, _ = _start()
    s = json.loads(_get(out["urls"][0] + "status.json")[2])
    assert s["ider"] == {"device": "my-server-1", "mounted": False}


# --- power and boot from the control page --------------------------------------------------

@pytest.fixture
def host(monkeypatch):
    calls = []

    async def power(action, **kw):         # the registered tools the page's routes dispatch to
        calls.append(("power", action, kw))
        return {"action": action}

    async def set_next_boot(target, **kw):
        calls.append(("boot", target, kw))
        return {"target": target}
    monkeypatch.setattr(amt_write, "amt_power", power)
    monkeypatch.setattr(amt_write, "amt_set_next_boot", set_next_boot)
    reads = {"CIM_AssociatedPowerManagementService": {"PowerState": 2,
                                                        "AvailableRequestedPowerStates": ["10", "11"]},
             "AMT_BootSettingData": {"UseIDER": False}}

    class Reads:
        def __init__(self, device):
            assert device == "my-server-1"

        def get(self, cls):
            calls.append(("read", cls))
            return reads[cls]
    monkeypatch.setattr(amt_tools, "_Reads", Reads)
    return calls


def test_power_and_boot_routes_answer_only_the_control_link(fake, host):
    out, _ = _start()
    for path, method in (("power.json", "GET"), ("power", "POST"), ("boot", "POST")):
        with pytest.raises(urllib.error.HTTPError) as ex:
            if method == "GET":
                _get(out["urls"][0] + path)
            else:
                _post(out["urls"][0] + path, b'{"action": "power_on", "target": "pxe"}')
        assert ex.value.code == 404
    assert host == []
    assert json.loads(_get(out["control_urls"][0] + "power.json")[2]) == {
        "power": {"state": "on", "code": 2}, "actions": ["hard_reset", "nmi"],
        "next_boot": {"UseIDER": False}}
    assert [c for c in host if c[0] == "read"] == [("read", "CIM_AssociatedPowerManagementService"),
                                                   ("read", "AMT_BootSettingData")]   # two reads only


def test_a_power_action_runs_confirmed_on_this_device(fake, host):
    out, _ = _start()
    assert _post(out["control_urls"][0] + "power", b'{"action": "hard_reset"}')[0] == 200
    assert host == [("power", "hard_reset", {"device": "my-server-1", "confirmed": True})]


def test_reset_to_bios_sets_the_boot_then_resets(fake, host):
    out, _ = _start()
    _post(out["control_urls"][0] + "boot", b'{"target": "bios_setup", "then": "hard_reset"}')
    assert host == [("boot", "bios_setup", {"device": "my-server-1", "confirmed": True}),
                    ("power", "hard_reset", {"device": "my-server-1", "confirmed": True})]


@pytest.mark.parametrize("path,body", [
    ("power", b'{"action": "secure_erase"}'), ("power", b'{}'), ("power", b'"hard_reset"'),
    ("boot", b'{"target": "secure_erase"}'), ("boot", b'{"target": "pxe", "then": "explode"}'),
    ("boot", b'{"then": "hard_reset"}'),
])
def test_an_unknown_power_or_boot_name_sends_nothing(fake, host, path, body):
    out, _ = _start()
    with pytest.raises(urllib.error.HTTPError) as ex:
        _post(out["control_urls"][0] + path, body)
    assert ex.value.code == 409 and host == []


@pytest.mark.skipif(amt_mirror.shutil.which("ffmpeg") is None, reason="needs ffmpeg")
def test_a_finished_mp4_is_offered_once_over_http(fake, tmp_path, monkeypatch):
    import hashlib
    import amt_handoff
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, "https://nas.example.com:8443")
    out, m = _start()
    rec = _record(out, m, tmp_path)
    assert rec["encoding"] == "done" and rec["url"].startswith("https://nas.example.com:8443/handoffs/")
    assert rec["sha256"] == hashlib.sha256(Path(rec["path"]).read_bytes()).hexdigest()


def test_viewer_urls_lead_with_the_public_front_only_when_the_page_is_reachable(monkeypatch):
    monkeypatch.setenv(amt_mirror.VIEWER_BASE_ENV, "https://amt-viewer.example.com/")
    wild = amt_mirror._urls("0.0.0.0", 8766, "tok", "198.51.100.26")
    assert wild[0] == "https://amt-viewer.example.com/m/tok/"
    assert amt_mirror._urls("0.0.0.0", 8766, "tok", "198.51.100.26", "s")[0] == \
        "https://amt-viewer.example.com/s/tok/"
    # Bound to loopback inside the container, the front cannot reach the page: no public url.
    assert amt_mirror._urls("127.0.0.1", 8766, "tok", "198.51.100.26") == ["http://127.0.0.1:8766/m/tok/"]
    monkeypatch.setenv(amt_mirror.VIEWER_BASE_ENV, "ftp://nope")
    assert not amt_mirror._urls("0.0.0.0", 8766, "tok", "198.51.100.26")[0].startswith("ftp")


# --- embed mode: the console frames the page without Media, Power, Boot or the download -------

def _embedded(url):
    return url + ("&" if "?" in url else "?") + "embed=1"


@pytest.mark.parametrize("which", ["urls", "control_urls"])
def test_embed_serves_capture_view_and_control_only(fake, which):
    out, _ = _start()
    plain = _get(out[which][0])[2].decode()
    embed = _get(_embedded(out[which][0]))[2].decode()
    # the standalone page keeps every row (the control page; the view page never showed them)
    for marker in ("id=shot", "Screenshot", "id=mgrp", "id=pgrp", "id=bgrp", "id=hbar", "powerAct", "loadPower",
                   "id=rec", "rec.onclick", "fetch('record?on='"):
        assert marker in plain, marker
    # the embed page holds none of them, in markup, style or script, so no route to them is in its source;
    # Record is among them: the console offers it from its own chrome as a tool action (amt_mirror_link record_start)
    for marker in ("id=shot", "Screenshot", "id=mgrp", "id=pgrp", "id=bgrp", "id=hbar", "id=iso", "powerAct",
                   "loadPower", "loadImages", "'ider'", "'power'", "'boot'", "media.json", "power.json",
                   "#mgrp", "#bgrp", "standalone", "id=rec", "id=rect", "rec.onclick", "rec.classList", "fetch('record",
                   "lbl>Capture"):
        assert marker not in embed, marker
    for marker in ("id=fit", "id=one", "id=cgrp", "id=ctl", "data-k=cad", "fetch('input'"):
        assert marker in embed, marker
    assert ("const CONTROL=true" in embed) is (which == "control_urls")
    assert "standalone" not in plain and "<!--" not in plain      # the markers never reach a browser


def test_the_slash_redirect_keeps_the_embed_query(fake):
    out, m = _start()
    host_port = out["urls"][0].split("/")[2]
    conn = http.client.HTTPConnection(host_port, timeout=5)
    conn.request("GET", f"/m/{m.control_token}?embed=1")
    res = conn.getresponse()
    assert res.status == 301 and res.getheader("Location") == f"/m/{m.control_token}/?embed=1"
    conn.close()


@pytest.mark.parametrize("path,body", [("power", b'{"action": "hard_reset"}'),
                                       ("boot", b'{"target": "bios_setup", "then": "hard_reset"}'),
                                       ("ider", b'{"action": "unmount"}')])
def test_an_embed_request_cannot_run_power_boot_or_media(fake, host, monkeypatch, path, body):
    calls = []

    async def ider(action, **kw):
        calls.append(action)
        return {}
    monkeypatch.setattr(amt_write, "amt_ider", ider)
    out, _ = _start()
    for query in ("?embed=1", "?x=1&embed=1"):
        with pytest.raises(urllib.error.HTTPError) as ex:
            _post(out["control_urls"][0] + path + query, body)
        assert ex.value.code == 403 and b"embed_mode" in ex.value.read()
    assert host == [] and calls == []
    # the same request without the flag still runs, and a wrong flag value is not the flag
    assert _post(out["control_urls"][0] + path + "?embed=0", body)[0] == 200
    assert host != [] or calls != []


@pytest.mark.parametrize("which", ["urls", "control_urls"])
@pytest.mark.parametrize("query", ["?embed=1&on=1", "?on=1&embed=1", "?x=1&embed=1&on=1", "?embed=1"])
def test_an_embed_request_cannot_start_or_stop_a_recording(fake, tmp_path, which, query):
    """Recording is a tool action (record_start needs confirmed): the embedded viewer has no Record button and the route refuses it."""
    amt_mirror.set_recording_dir(str(tmp_path / "rec"))
    out, m = _start()
    with pytest.raises(urllib.error.HTTPError) as ex:
        _post(out[which][0] + "record" + query, b"")
    assert ex.value.code == 403 and b"embed_mode" in ex.value.read()
    assert m.recording is None and m.last_recording is None and list((tmp_path / "rec").iterdir()) == []
    m.record_start(tmp_path / "rec")                 # a recording the tool started cannot be stopped from an embedded viewer either
    with pytest.raises(urllib.error.HTTPError) as ex:
        _post(out[which][0] + "record?embed=1&on=0", b"")
    assert ex.value.code == 403 and m.recording is not None
    m.record_stop()
    _wait(lambda: m.last_recording["encoding"] != "running", timeout=60)


def test_an_embed_request_still_needs_the_control_token_and_still_types(fake, host):
    out, _ = _start()
    with pytest.raises(urllib.error.HTTPError) as ex:
        _post(out["urls"][0] + "power?embed=1", b'{"action": "hard_reset"}')
    assert ex.value.code == 404                       # the view token never reaches power, embed or not
    assert _post(out["control_urls"][0] + "input?embed=1", json.dumps({"events": [["k", 0x61, 1]]}).encode())[0] == 200


# --- headers on every viewer response ---------------------------------------------------------

def _raw(url, method="GET"):
    """(status, headers) of one request, redirects not followed, body not read."""
    parts = url.split("/", 3)
    conn = http.client.HTTPConnection(parts[2], timeout=5)
    conn.request(method, "/" + parts[3])
    res = conn.getresponse()
    out = (res.status, {k.lower(): v for k, v in res.getheaders()})
    conn.close()
    return out


def _viewer_urls(out, m):
    base = out["urls"][0]
    root = base.split("/m/")[0]
    return [base, out["control_urls"][0], base + "status.json", base + "frame.jpg", base + "stream",
            out["control_urls"][0] + "?embed=1", f"{root}/m/{m.token}", f"{root}/m/wrong-token/",
            base + "nope"]


def test_every_viewer_response_sends_no_referrer_and_denies_framing_by_default(fake, monkeypatch):
    monkeypatch.delenv("AMT_CONSOLE_ORIGIN", raising=False)
    out, m = _start()
    for url in _viewer_urls(out, m):
        status, headers = _raw(url)
        assert headers.get("referrer-policy") == "no-referrer", (url, status)
        assert headers.get("content-security-policy") == "frame-ancestors 'none'", (url, status)
    assert {_raw(u)[0] for u in _viewer_urls(out, m)} >= {200, 301, 404}      # pages, redirect and refusals alike


def test_the_console_origin_is_the_only_frame_ancestor_when_configured(fake, monkeypatch):
    monkeypatch.setenv("AMT_CONSOLE_ORIGIN", "https://amt-console.example.com")
    out, m = _start()
    for url in _viewer_urls(out, m):
        headers = _raw(url)[1]
        assert headers.get("content-security-policy") == "frame-ancestors https://amt-console.example.com", url
        assert headers.get("referrer-policy") == "no-referrer", url
    monkeypatch.setenv("AMT_CONSOLE_ORIGIN", " http://192.0.2.7:8443/ ")      # trimmed, a trailing slash dropped
    assert _raw(out["urls"][0])[1]["content-security-policy"] == "frame-ancestors http://192.0.2.7:8443"


@pytest.mark.parametrize("bad", ["https://a.test; script-src *", "https://a.test https://b.test", "ftp://a.test",
                                 "https://a.test/path", "javascript:alert(1)", "*", "https://", "a.test",
                                 "https://a.test:99999999"])
def test_a_malformed_console_origin_is_never_copied_into_the_header(fake, monkeypatch, bad):
    monkeypatch.setenv("AMT_CONSOLE_ORIGIN", bad)
    out, _ = _start()
    assert _raw(out["urls"][0])[1]["content-security-policy"] == "frame-ancestors 'none'"


# --- status.json: the agent tool call sharing the session ------------------------------------

def _hold_grab(monkeypatch):
    """Make the shared session's settle wait block until released; returns (reached, release)."""
    reached, release = threading.Event(), threading.Event()
    orig = amt_mirror._Shared.grab_stable

    def grab_stable(self, *a, **k):
        reached.set()
        release.wait(10)
        return orig(self, *a, **k)
    monkeypatch.setattr(amt_mirror._Shared, "grab_stable", grab_stable)
    return reached, release


def _in_flight(out):
    return json.loads(_get(out["urls"][0] + "status.json")[2])["in_flight"]


def test_status_names_the_tool_call_holding_the_shared_session(fake, monkeypatch):
    monkeypatch.setenv("AMT_TRANSPORT", "stdio")
    reached, release = _hold_grab(monkeypatch)
    out, _ = _start()
    assert _in_flight(out) is None
    done = {}
    marker = "zz-typed-marker-zz"

    def agent():
        try:
            asyncio.run(amt_server.mcp.call_tool("amt_console_input", {
                "actions": [{"kind": "text", "text": marker}], "confirmed": True}))
        except Exception as ex:   # noqa: BLE001 - the fake session has no text typing; the call ends either way
            done["error"] = type(ex).__name__
    t = threading.Thread(target=agent)
    t.start()
    assert reached.wait(5)
    before = time.time()
    flight = _in_flight(out)
    assert set(flight) == {"tool", "started_at"} and flight["tool"] == "amt_console_input"
    assert before - 5 < flight["started_at"] <= before + 0.001      # rounded to the millisecond
    assert marker not in _get(out["urls"][0] + "status.json")[2].decode()          # a name and a time, no arguments
    release.set()
    t.join(10)
    assert not t.is_alive() and _in_flight(out) is None          # cleared when the call ends, whether it succeeded or not


def test_a_call_outside_the_gated_dispatch_is_reported_as_unknown(fake, monkeypatch):
    reached, release = _hold_grab(monkeypatch)
    out, _ = _start()
    t = threading.Thread(target=amt_tools.screenshot)
    t.start()
    assert reached.wait(5)
    flight = _in_flight(out)
    assert flight["tool"] == "unknown" and isinstance(flight["started_at"], float)
    release.set()
    t.join(10)
    assert _in_flight(out) is None


def test_the_mirrors_own_frame_thread_is_never_an_in_flight_call(fake):
    out, m = _start()
    time.sleep(0.2)
    assert _in_flight(out) is None and m.seq >= 2


# --- the control page's rows run the registered tools -------------------------------------------

def test_a_click_waits_for_the_session_lock_an_agents_call_holds(fake, monkeypatch):
    calls = []
    monkeypatch.setattr(amt_write, "power", lambda action, device, confirmed: calls.append((action, device, confirmed))
                        or {"action": action})
    loop = asyncio.new_event_loop()
    threading.Thread(target=loop.run_forever, daemon=True).start()
    monkeypatch.setattr(amt_mirror, "_TOOL_LOOP", loop)
    lock = asyncio.run_coroutine_threadsafe(_acquire("my-server-1"), loop).result(5)
    out, _ = _start()
    posted = threading.Thread(target=_post, args=(out["control_urls"][0] + "power", b'{"action": "hard_reset"}'))
    posted.start()
    time.sleep(0.4)
    assert calls == [] and posted.is_alive()                       # held behind the agent's lock
    loop.call_soon_threadsafe(lock.release)
    posted.join(5)
    assert calls == [("hard_reset", "my-server-1", True)]
    loop.call_soon_threadsafe(loop.stop)


async def _acquire(device):
    lock = amt_tools._session_lock(device)
    await lock.acquire()
    return lock


@pytest.mark.parametrize("path,body", [("power", b'{"action": "hard_reset"}'),
                                       ("boot", b'{"target": "pxe"}'),
                                       ("ider", b'{"action": "unmount"}')])
def test_the_routes_reach_the_hardware_only_through_the_tool_coroutines(fake, monkeypatch, path, body):
    seen = []
    for name in ("amt_power", "amt_set_next_boot", "amt_ider"):
        async def spy(*a, _n=name, **kw):
            seen.append(_n)
            return {}
        monkeypatch.setattr(amt_write, name, spy)

    direct = []
    for name in ("power", "set_next_boot", "ider"):
        monkeypatch.setattr(amt_write, name, lambda *a, _n=name, **k: {} if a[:1] == ("status",) else
                            direct.append(_n) or {})
    out, _ = _start()
    assert _post(out["control_urls"][0] + path, body)[0] == 200
    assert seen == [{"power": "amt_power", "boot": "amt_set_next_boot", "ider": "amt_ider"}[path]]
    assert direct == []                      # the tools were spied whole, so nothing reached the sync functions


def test_a_tool_refusal_reaches_the_page_as_it_would_an_agent(fake, monkeypatch):
    def refuse(action, device, confirmed):
        raise ValueError("power_state_not_available: AMT does not offer hard_reset now. Nothing was sent.")
    monkeypatch.setattr(amt_write, "power", refuse)
    out, _ = _start()
    with pytest.raises(urllib.error.HTTPError) as ex:
        _post(out["control_urls"][0] + "power", b'{"action": "hard_reset"}')
    assert ex.value.code == 409 and b"power_state_not_available" in ex.value.read()


def test_the_viewer_tools_hand_their_event_loop_to_the_routes(fake):
    async def check():
        await amt_mirror.amt_mirror_link(action="status")
        assert amt_mirror._TOOL_LOOP is asyncio.get_running_loop()
    amt_mirror._TOOL_LOOP = None
    asyncio.run(check())
