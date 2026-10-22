"""Live display mirror: one AMT KVM session per device, fanned out to browser viewers.

``amt_mirror_link`` opens the device's KVM session once and keeps it. A frame thread grabs the
console at a set rate, JPEG-encodes it and hands it to every viewer of a small HTTP page served
by this process (``/m/<token>/``: the page, an MJPEG ``stream``, a single ``frame.jpg``, a
``status.json`` and a ``record`` toggle). Each mirror has two tokens: the view token serves a
view-only page; the control token serves the same page with a Take control switch, whose keyboard
and mouse events reach the host through ``input``. While a mirror is live, the agent's own console tools
(``amt_screenshot``, ``amt_console_input``, ``amt_remote_logon`` / ``logoff``) do not open a second
session: ``shared_session`` hands them this one, so the operator watches exactly what the agent
does. Every socket operation is serialized on one lock, because a TLS socket is not safe for
concurrent use. Recording appends each frame to an ``.mjpeg`` file with a ``.times`` sidecar of
frame timestamps (crash-safe while it runs); on stop, ffmpeg encodes them to an H.264 ``.mp4`` at
the real frame times, and the raw pair is deleted once the MP4 is written. Without ffmpeg, or if
encoding fails, the raw pair is kept and the status says why.

A url with ``?embed=1`` serves the page for the management console's frame: View and Control only,
with the Capture (Record, Screenshot), Media, Power and Boot groups left out of the page source (see
``render_page``) and the ``record`` route refused: recording is the tool's ``record_start`` /
``record_stop``, which the console offers from its own chrome behind a confirm sheet. Every response sends ``Referrer-Policy: no-referrer`` and a
``frame-ancestors`` policy naming ``AMT_CONSOLE_ORIGIN`` (``'none'`` when unset). The control page's
Power, Boot and Media routes run the registered tools (``run_tool``), not ``amt_write`` directly.

Viewers need a per-mirror token in the URL; nothing is served without it, and ``input``
answers only the control token, so a shared view link never grants control. Nothing is ever
printed to stdout (in stdio mode stdout is the MCP channel).
"""
from __future__ import annotations

import asyncio
import hmac
import html
import http.server
import io
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import threading
import time
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, StrictBool

import amt_handoff
import amt_registry
import amt_tools
import amt_vault
import amt_write
import amt_wsman

DEFAULT_BIND = "127.0.0.1"
DEFAULT_PORT = 8766
DEFAULT_FPS = 15
DEFAULT_QUALITY = 70
LOG_KEEP = 50                 # engine notes kept per session; the engine appends one per frame
STREAM_WAIT_SECONDS = 5.0
# The frame thread holds the socket lock only this long per wait for an update, then lets input
# in: input waits at most one slice instead of a whole frame period (measured live 2026-10-18:
# 183 ms median per input POST with a 200 ms wait, before this).
UPDATE_SLICE_SECONDS = 0.03
# AMT ends a KVM session when the client has sent no keyboard or mouse event for the KVM
# SessionTimeout (3 minutes on my-server-1), whatever the screen does: measured live 2026-10-18,
# a mirror with no input started 23:50:14Z and AMT ended it 23:53:14Z. So an idle mirror sends a
# no-op input: releasing Shift_R, which is not held, changes nothing on the host.
KVM_KEEPALIVE_SECONDS = 60.0
KEEPALIVE_KEYSYM = 0xFFE2
INPUT_METHODS = frozenset({"_key", "tap", "named_key", "type_char", "type_text", "cad", "clear_field",
                           "pointer", "click", "button"})
INPUT_YIELD_SECONDS = 0.002
ENCODE_TIMEOUT_SECONDS = 900
ROUTES = ("", "stream", "frame.jpg", "status.json", "media.json", "power.json", "record")  # GET
POST_ROUTES = ("record", "input", "ider", "power", "boot")      # all under /m/<token>/
CONTROL_ROUTES = ("input", "ider", "power", "boot", "media.json", "power.json")   # control token only
MAX_INPUT_BYTES = 64 * 1024
MAX_INPUT_EVENTS = 500
CONSOLE_ORIGIN_ENV = "AMT_CONSOLE_ORIGIN"     # the one origin allowed to frame a viewer page, e.g. https://amt-console.example.com
MirrorAction = Literal["start", "stop", "status", "record_start", "record_stop"]


def _split_mjpeg(data: bytes) -> list[bytes]:
    """The JPEGs of a concatenated recording. Pillow writes no embedded thumbnail, and entropy
    data stuffs every 0xFF, so EOI immediately followed by SOI only occurs between frames."""
    if not data:
        return []
    parts = data.split(b"\xff\xd9\xff\xd8")
    return [(b"" if i == 0 else b"\xff\xd8") + part + (b"" if i == len(parts) - 1 else b"\xff\xd9")
            for i, part in enumerate(parts)]


def encode_mp4(raw: Path, end: float | None = None) -> Path:
    """Encode a recording's ``.mjpeg`` + ``.times`` to H.264 ``.mp4`` (yuv420p, faststart, so
    QuickTime and browsers play it). Each frame is held until the next one's timestamp, the last
    until ``end`` (the stop time), so still screens keep their real length. Raises on failure and
    leaves the raw files alone; the caller deletes them only after this returns."""
    ffmpeg = shutil.which("ffmpeg")
    if ffmpeg is None:
        raise RuntimeError("ffmpeg_missing: install ffmpeg to get .mp4 recordings")
    frames = _split_mjpeg(raw.read_bytes())
    times = [float(t) for t in raw.with_suffix(".times").read_text().split()]
    count = min(len(frames), len(times))
    if count == 0:
        raise RuntimeError("recording_empty: no frames were recorded")
    stop = max(end if end is not None else times[count - 1] + 1.0, times[count - 1] + 0.04)
    out = raw.with_suffix(".mp4")
    with tempfile.TemporaryDirectory(dir=raw.parent, prefix=".encode-") as tmp:
        lines = []
        for i in range(count):
            frame = Path(tmp) / f"f{i:06d}.jpg"
            frame.write_bytes(frames[i])
            hold = (times[i + 1] if i + 1 < count else stop) - times[i]
            lines += [f"file '{frame.name}'", f"duration {max(hold, 0.001):.3f}"]
        lines.append(f"file 'f{count - 1:06d}.jpg'")   # the concat demuxer drops the last duration otherwise
        listing = Path(tmp) / "frames.txt"
        listing.write_text("\n".join(lines) + "\n")
        done = subprocess.run(
            [ffmpeg, "-hide_banner", "-loglevel", "error", "-y", "-f", "concat", "-safe", "0",
             "-i", str(listing), "-fps_mode", "vfr",
             "-vf", "scale=trunc(iw/2)*2:trunc(ih/2)*2:out_range=tv,format=yuv420p",
             "-c:v", "libx264", "-movflags", "+faststart", str(out)],
            capture_output=True, text=True, timeout=ENCODE_TIMEOUT_SECONDS, check=False)
    if done.returncode != 0 or not out.is_file() or out.stat().st_size == 0:
        out.unlink(missing_ok=True)
        raise RuntimeError(f"ffmpeg_failed: {done.stderr.strip()[-300:]}")
    return out


def _encode_jpeg(width: int, height: int, rgb: bytes, quality: int) -> bytes:
    from PIL import Image   # Pillow: a server dependency (also used by the OCR gate)
    buf = io.BytesIO()
    Image.frombytes("RGB", (width, height), rgb).save(buf, "JPEG", quality=quality)
    return buf.getvalue()


class _Shared:
    """The mirror's session as the console tools see it: open/close are no-ops (the mirror owns
    the session) and every other call runs under the mirror's socket lock."""

    def __init__(self, mirror: "Mirror"):
        self._mirror = mirror

    def open(self, deadline=None):
        self._mirror.in_flight.begin()       # the tool call that opened this holds the session until close
        return self._mirror.session.width, self._mirror.session.height

    def close(self) -> None:
        self._mirror.in_flight.end()

    # The mirror keeps ``fb`` current with incremental updates, and AMT answers a full-frame
    # request only after the outstanding incremental one (which waits for a screen change), so a
    # shared session never sends its own full request: it reads the live framebuffer.
    def grab_frame(self, deadline=None):
        return self._mirror.session.width, self._mirror.session.height

    def grab_stable(self, max_iters=8, settle=0.5, deadline=None):
        """Settled = no incremental update for ``settle`` seconds. Same contract as the engine's:
        (width, height, iterations, stable, delta); delta is not measured here (None)."""
        for i in range(1, max_iters + 1):
            time.sleep(settle)
            last = self._mirror.frame_at or 0.0
            if time.time() - last >= settle:
                return self._mirror.session.width, self._mirror.session.height, i, True, None
        return self._mirror.session.width, self._mirror.session.height, max_iters, False, None

    def __getattr__(self, name: str):
        attr = getattr(self._mirror.session, name)
        if not callable(attr):
            return attr

        def locked(*args, **kwargs):
            with self._mirror.io:
                out = attr(*args, **kwargs)
                if name in INPUT_METHODS:
                    self._mirror.last_input = time.time()
                return out
        return locked


class Mirror:
    def __init__(self, device: str, session, fps: int, quality: int):
        self.device, self.session = device, session
        self.fps, self.quality = fps, quality
        self.token = secrets.token_urlsafe(24)            # view only
        self.control_token = secrets.token_urlsafe(24)    # view plus keyboard and mouse
        self.io = threading.RLock()
        self.cond = threading.Condition()
        self.stop = threading.Event()
        self.jpeg: bytes | None = None
        self.seq = 0
        self.frame_at: float | None = None
        self.started_at = time.time()
        self.last_input = time.time()      # the last keyboard or mouse event sent to the host
        self.error: str | None = None
        self.viewers = 0
        self.in_flight = amt_tools.InFlight()    # agent tool calls sharing this session
        self.recording: dict[str, Any] | None = None
        self.last_recording: dict[str, Any] | None = None
        self.rec_lock = threading.Lock()
        self.encoder: threading.Thread | None = None
        self.thread: threading.Thread | None = None

    def alive(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def run(self) -> None:
        period = 1.0 / self.fps
        first = True
        try:
            while not self.stop.is_set():
                began = time.time()
                with self.io:   # one full frame, then cheap incremental updates (changed tiles)
                    if time.time() - self.last_input >= KVM_KEEPALIVE_SECONDS:
                        self.session._key(KEEPALIVE_KEYSYM, False)
                        self.last_input = time.time()
                    if first:
                        self.session.grab_frame()
                        changed, first = True, False
                    else:
                        changed = self.session.grab_update(wait=UPDATE_SLICE_SECONDS)
                    width, height = self.session.width, self.session.height
                    rgb = bytes(self.session.fb[:width * height * 3]) if changed else None
                    del self.session.log[:-LOG_KEEP]
                if rgb is None:      # nothing yet: step outside the lock so waiting input gets it
                    self.stop.wait(INPUT_YIELD_SECONDS)
                    continue
                jpeg = _encode_jpeg(width, height, rgb, self.quality)
                with self.cond:
                    self.jpeg, self.seq, self.frame_at = jpeg, self.seq + 1, time.time()
                    self.cond.notify_all()
                self._record(jpeg)
                self.stop.wait(max(0.0, period - (time.time() - began)))
        except Exception as ex:   # noqa: BLE001 - reported by status; the engine never puts a secret in one
            self.error = f"{type(ex).__name__}:{ex}"
        finally:
            with self.io:
                self.session.close()
            self.record_stop()
            with self.cond:
                self.cond.notify_all()

    # -- recording ------------------------------------------------------------------------

    def record_start(self, directory: Path) -> dict[str, Any]:
        with self.rec_lock:
            if self.recording is not None:
                return self._rec_info(self.recording)
            directory.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
            path = directory / f"amt-{self.device}-{stamp}.mjpeg"
            self.recording = {"path": path, "fh": open(path, "ab"),
                              "times": open(path.with_suffix(".times"), "a"),
                              "frames": 0, "bytes": 0, "started": time.time()}
            return self._rec_info(self.recording)

    def record_stop(self) -> dict[str, Any] | None:
        with self.rec_lock:
            rec, self.recording = self.recording, None
            if rec is None:
                return None
            rec["fh"].close()
            rec["times"].close()
            info = self._rec_info(rec, ended=True)
            self.last_recording = {**info, "raw": info["path"], "encoding": "running"}
            thread = threading.Thread(target=self._encode, args=(rec["path"], time.time()),
                                      name=f"amt-mirror-encode-{self.device}", daemon=True)
            self.encoder = thread
            thread.start()
            return self.last_recording

    def _encode(self, raw: Path, end: float) -> None:
        """Background: MP4 from the raw pair, then delete the pair. ``last_recording.path`` names
        the MP4 once it exists; on failure it keeps naming the raw file and ``encoding`` says why."""
        try:
            mp4 = encode_mp4(raw, end)
        except Exception as ex:   # noqa: BLE001 - reported in status; ffmpeg output holds no secret
            update = {"encoding": f"failed: {ex}"[:400]}
        else:
            raw.unlink(missing_ok=True)
            raw.with_suffix(".times").unlink(missing_ok=True)
            update = {"encoding": "done", "path": str(mp4), "raw": None,
                      "timestamps": None, "bytes": mp4.stat().st_size}
            try:
                update.update(amt_handoff.offer(mp4))
            except OSError as ex:
                update["url_error"] = f"{type(ex).__name__}: {ex}"[:200]
        with self.rec_lock:
            if self.last_recording is not None and self.last_recording.get("raw") == str(raw):
                self.last_recording = {**self.last_recording, **update}

    def _record(self, jpeg: bytes) -> None:
        with self.rec_lock:
            rec = self.recording
            if rec is None:
                return
            rec["fh"].write(jpeg)
            rec["times"].write(f"{time.time():.3f}\n")
            rec["frames"] += 1
            rec["bytes"] += len(jpeg)

    @staticmethod
    def _rec_info(rec: dict[str, Any], ended: bool = False) -> dict[str, Any]:
        return {"path": str(rec["path"]), "timestamps": str(rec["path"].with_suffix(".times")),
                "frames": rec["frames"], "bytes": rec["bytes"], "started": round(rec["started"], 3),
                "seconds": round(time.time() - rec["started"], 1), "ended": ended}

    def info(self) -> dict[str, Any]:
        return {"device": self.device, "live": self.alive(), "error": self.error, "fps": self.fps,
                "frames": self.seq, "viewers": self.viewers, "in_flight": self.in_flight.snapshot(),
                "last_frame_age_s": round(time.time() - self.frame_at, 1) if self.frame_at else None,
                "uptime_s": round(time.time() - self.started_at, 1),
                "width": self.session.width, "height": self.session.height,
                "recording": self._rec_info(self.recording) if self.recording else None,
                "recording_dir": str(recording_dir()), "hostname": socket.gethostname(),
                "ider": amt_write.ider("status", device=self.device),
                "last_recording": self.last_recording}


_MIRRORS: dict[str, Mirror] = {}
_LOCK = threading.Lock()
_SERVER: dict[str, Any] = {}       # "httpd", "thread", "bind", "port"


def shared_session(device_key: str) -> _Shared | None:
    """The live mirror's session for this device, or None (the caller opens its own)."""
    with _LOCK:
        mirror = _MIRRORS.get(device_key)
    return _Shared(mirror) if mirror is not None and mirror.alive() else None


def _by_token(token: str) -> tuple[Mirror | None, bool]:
    """The mirror a token opens, and whether it is that mirror's control token."""
    with _LOCK:
        mirrors = list(_MIRRORS.values())
    found, control = None, False
    for m in mirrors:            # compare against every token so timing reveals nothing
        if hmac.compare_digest(m.token.encode(), token.encode()):
            found = m
        if hmac.compare_digest(m.control_token.encode(), token.encode()):
            found, control = m, True
    return found, control


def media_list() -> dict[str, Any]:
    """Mountable ISO images under the IDE-R image root, for the control page's picker."""
    listing = amt_write.ider_list()
    return {"image_root": listing.get("image_root"), "error": listing.get("error"),
            "images": [i["path"] for i in listing["images"]
                       if i["mountable"] and i["path"].lower().endswith(".iso")]}


# -- the control page's Power, Boot and Media rows run the registered tools ---------------------

_TOOL_LOOP: asyncio.AbstractEventLoop | None = None


def remember_tool_loop() -> None:
    """Called first thing by the tools that start a viewer, which run on the server's event loop.
    The viewer's own threads hand the registered tools to that loop, so a click on a page takes
    the same per-device session lock an agent's call takes."""
    global _TOOL_LOOP
    _TOOL_LOOP = asyncio.get_running_loop()


def run_tool(tool, **kwargs) -> dict[str, Any]:
    """Run a registered tool's coroutine for a viewer route and return its result; its refusals
    and errors raise here as they do for an agent. ``tool`` is the function the server registers,
    looked up by the caller at call time. With no server loop (a viewer started outside the
    server) it runs on a loop of its own, with its own session lock."""
    loop = _TOOL_LOOP
    if loop is not None and loop.is_running():
        return asyncio.run_coroutine_threadsafe(tool(**kwargs), loop).result()
    return asyncio.run(tool(**kwargs))


def media_action(mirror: Mirror, body: Any) -> dict[str, Any]:
    """Mount or unmount from the control page. A mount is always start=next_boot: the page can
    attach media but never resets the host."""
    if type(body) is not dict or body.get("action") not in ("mount", "unmount"):
        raise ValueError('ider_bad_request: expected {"action": "mount", "iso": name} or {"action": "unmount"}')
    if body["action"] == "unmount":
        return run_tool(amt_write.amt_ider, action="unmount", device=mirror.device, confirmed=True)
    iso = body.get("iso")
    if type(iso) is not str or iso not in media_list()["images"]:
        raise ValueError("ider_unknown_image: pick an ISO listed under the image root")
    return run_tool(amt_write.amt_ider, action="mount", iso_path=iso, start="next_boot",
                    device=mirror.device, confirmed=True)


def power_state(device: str) -> dict[str, Any]:
    """Power state and next-boot settings for the control page: only the two WS-MAN reads it
    needs (amt_status makes nine; with KVM and IDE-R busy that took 30 s live, 2026-10-18)."""
    reads = amt_tools._Reads(device)
    service = reads.get("CIM_AssociatedPowerManagementService")
    code = service.get("PowerState")
    return {"power": {"state": amt_tools._label(amt_tools.POWER_STATES, code), "code": code},
            "actions": amt_write.offered_power_actions(service.get("AvailableRequestedPowerStates")),
            "next_boot": reads.get("AMT_BootSettingData")}


def power_action(mirror: Mirror, body: Any) -> dict[str, Any]:
    """One named amt_power action from the control page; the name must be one amt_power knows."""
    if type(body) is not dict or body.get("action") not in amt_write.POWER_ACTIONS:
        raise ValueError("power_bad_request: expected {\"action\": one of amt_power's actions}")
    return run_tool(amt_write.amt_power, action=body["action"], device=mirror.device, confirmed=True)


def boot_action(mirror: Mirror, body: Any) -> dict[str, Any]:
    """MeshCommander's combined entries ("Reset to BIOS"): set the next boot, then optionally run
    one power action. Both names are checked before anything is sent."""
    if type(body) is not dict or body.get("target") not in amt_write.BOOT_TARGETS:
        raise ValueError("boot_bad_request: expected {\"target\": one of amt_set_next_boot's targets}")
    then = body.get("then")
    if then is not None and then not in amt_write.POWER_ACTIONS:
        raise ValueError("boot_bad_request: \"then\" must be one of amt_power's actions")
    out = {"boot": run_tool(amt_write.amt_set_next_boot, target=body["target"], device=mirror.device,
                            confirmed=True)}
    if then is not None:
        out["power"] = run_tool(amt_write.amt_power, action=then, device=mirror.device, confirmed=True)
    return out


ACTIONS = {"ider": lambda m, b: media_action(m, b), "power": lambda m, b: power_action(m, b),
           "boot": lambda m, b: boot_action(m, b)}


def _uint(value: Any, top: int) -> bool:
    return type(value) is int and 0 <= value <= top


def send_input(mirror: Mirror, events: Any) -> int:
    """Send a browser batch of RFB events in order: ``["k", keysym, down]`` (down 1 or 0) and
    ``["p", x, y, button_mask]``. The whole batch is checked before anything is sent, so a bad
    event sends nothing. Pointer coordinates are clamped to the current screen, which can change
    size between the page's last status poll and this batch."""
    if type(events) is not list or not 0 < len(events) <= MAX_INPUT_EVENTS:
        raise ValueError(f"input_bad_batch: a list of 1-{MAX_INPUT_EVENTS} events")
    calls = []
    for ev in events:
        if type(ev) is list and len(ev) == 3 and ev[0] == "k" and _uint(ev[1], 0xFFFFFFFF) \
                and _uint(ev[2], 1):
            calls.append(("key", ev[1], bool(ev[2])))
        elif type(ev) is list and len(ev) == 4 and ev[0] == "p" and _uint(ev[1], 0xFFFF) \
                and _uint(ev[2], 0xFFFF) and _uint(ev[3], 0xFF):
            calls.append(("pointer", ev[1], ev[2], ev[3]))
        else:
            raise ValueError("input_bad_event: expected [\"k\", keysym, 0|1] or [\"p\", x, y, mask]")
    with mirror.io:
        session = mirror.session
        for call in calls:
            if call[0] == "key":
                session._key(call[1], call[2])
            else:
                session.pointer(min(call[1], session.width - 1), min(call[2], session.height - 1),
                                call[3])
        mirror.last_input = time.time()
    return len(calls)


# -- the viewer page ------------------------------------------------------------------------

PAGE = """<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>AMT mirror</title>
<style>
:root{color-scheme:light dark;--bg:#0b0d12;--fg:#e8eaf0;--mute:#8b93a3;--line:#262c37;--chip:#161a22;--chip2:#1f2531;--rec:#ef4444;--ok:#22c55e;--warn:#f59e0b;--acc:#60a5fa;--stage:#000;--recbg:rgba(239,68,68,.12);--warnbg:rgba(245,158,11,.12);--shadow:0 10px 30px rgba(0,0,0,.45)}
@media (prefers-color-scheme:light){:root{--bg:#f4f5f7;--fg:#14171c;--mute:#5b6372;--line:#d8dce3;--chip:#fff;--chip2:#eceff3;--acc:#2563eb;--stage:#15181e;--shadow:0 10px 30px rgba(0,0,0,.25)}}
*{box-sizing:border-box}
[hidden]{display:none!important}
html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased;overflow-x:hidden}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.num{font-variant-numeric:tabular-nums}
.mute{color:var(--mute)}
.top,.bar,.msg,.stage,footer{padding-left:16px;padding-right:16px}
.top{display:flex;flex-wrap:wrap;align-items:center;gap:6px 12px;padding-top:12px;padding-bottom:8px;min-width:0}
h1{font-size:16px;font-weight:600;margin:0;letter-spacing:-.01em;overflow-wrap:anywhere}
.pill{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;padding:3px 9px;border-radius:999px;border:1px solid var(--line);color:var(--mute);white-space:nowrap}
.pill i{width:7px;height:7px;border-radius:50%;background:currentColor}
.pill.ok{color:var(--ok);border-color:rgba(34,197,94,.45);background:rgba(34,197,94,.08)}
.pill.bad{color:var(--rec);border-color:rgba(239,68,68,.45);background:var(--recbg)}
.pill.off{color:var(--warn);border-color:rgba(245,158,11,.45);background:var(--warnbg)}
.meta{color:var(--mute);white-space:nowrap}
.right{margin-left:auto;display:flex;align-items:center;gap:10px;white-space:nowrap}
.tag{font-size:11px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;border:1px solid var(--line);border-radius:999px;padding:2px 8px;color:var(--mute)}
.bar{display:flex;flex-wrap:wrap;gap:10px 22px;padding-top:6px;padding-bottom:10px;border-bottom:1px solid var(--line)}
.bar.sub{padding-top:10px}
.grp{display:flex;flex-wrap:wrap;gap:6px;align-items:center;min-width:0}
.lbl{font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--mute);margin-right:4px;user-select:none}
button{font:inherit;line-height:1.2;color:var(--fg);background:var(--chip);border:1px solid var(--line);border-radius:7px;padding:6px 12px;cursor:pointer;display:inline-flex;align-items:center;gap:7px;white-space:nowrap}
button:hover:not(:disabled){background:var(--chip2)}
button:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
button:disabled{opacity:.38;cursor:default}
button.sel{border-color:var(--acc);color:var(--acc);background:var(--chip)}
button.primary{border-color:var(--acc);color:var(--acc)}
button.on{background:var(--rec);border-color:var(--rec);color:#fff}
button.on:hover:not(:disabled){background:#dc2626}
button.sm{padding:3px 9px;font-size:12px;border-radius:6px}
button.key{font:600 12px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:8px 9px;border-bottom-width:2px;border-radius:6px}
button.key:active:not(:disabled){transform:translateY(1px);border-bottom-width:1px}
/*standalone*/select{font:inherit;line-height:1.2;color:var(--fg);background:var(--chip);border:1px solid var(--line);border-radius:7px;padding:6px 8px;max-width:min(100%,24em);cursor:pointer}
select:disabled{opacity:.38;cursor:default}
button.arm{border-color:var(--warn);color:var(--warn)}
button.danger{border-color:rgba(239,68,68,.55);color:var(--rec)}
button.danger:hover:not(:disabled){background:var(--recbg)}
button.arm2,button.arm2:hover:not(:disabled){background:var(--rec);border-color:var(--rec);color:#fff}
#mgrp select{flex:1 1 10em;min-width:0;max-width:24em;text-overflow:ellipsis}
#mgrp .path{padding:6px 9px;line-height:1.2;font-variant-numeric:tabular-nums;min-width:11em}
#bgrp select{max-width:13em}
#bgrp .path{padding:6px 9px;line-height:1.2}
.path.warn{cursor:pointer;border-color:rgba(245,158,11,.45)}
.hint{display:inline-flex;align-items:center;gap:6px;font-size:12.5px;color:var(--warn)}
.pwrap{position:relative;display:inline-flex;flex-wrap:wrap;gap:6px}
.pop{position:absolute;top:calc(100% + 6px);left:0;z-index:5;background:var(--chip);border:1px solid rgba(239,68,68,.45);border-radius:9px;padding:8px;display:flex;flex-wrap:wrap;gap:6px;min-width:19em;max-width:calc(100vw - 32px);box-shadow:var(--shadow)}
.poph{flex-basis:100%;font-size:11.5px;font-weight:600;color:var(--rec);padding:0 2px 4px}
@media (max-width:900px){#mgrp{flex-basis:100%}}
@media (max-width:640px){.pwrap{position:static;flex-basis:100%}.pop{position:static;width:100%;max-width:none;min-width:0}}/*/standalone*/
.rdot{width:8px;height:8px;border-radius:50%;background:var(--rec);flex:none}
button.on .rdot{background:#fff;animation:pulse 1.2s ease-in-out infinite}
.rdot.live{animation:pulse 1.2s ease-in-out infinite}
.alert{margin:10px 16px 0;padding:8px 12px;border-radius:8px;border:1px solid rgba(239,68,68,.45);background:var(--recbg);overflow-wrap:anywhere;font-size:13px}
.alert.warn{border-color:rgba(245,158,11,.45);background:var(--warnbg)}
.msg{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;padding-top:9px;padding-bottom:9px;min-height:40px;min-width:0;overflow-wrap:anywhere}
.msg strong{font-weight:600}
.path{display:inline-block;max-width:100%;background:var(--chip);border:1px solid var(--line);border-radius:5px;padding:2px 7px;overflow-wrap:anywhere;color:var(--fg)}
.host{font-size:11px;font-weight:600;letter-spacing:.04em;border-radius:999px;padding:1px 8px;background:var(--chip2);color:var(--mute);white-space:nowrap}
.warn{color:var(--warn)}
.msg input{font:inherit;color:var(--fg);background:var(--chip);border:1px solid var(--line);border-radius:6px;padding:3px 7px;width:min(100%,42em)}
.spin{width:12px;height:12px;border-radius:50%;border:2px solid var(--line);border-top-color:var(--acc);animation:spin .9s linear infinite;flex:none}
.stage{background:var(--stage);padding-top:14px;padding-bottom:14px;display:flex;flex-direction:column;align-items:center;overflow:auto;min-height:120px}
.wrap{position:relative;width:fit-content;max-width:100%;outline:none}
.strip{display:none;font-size:12px;font-weight:600;letter-spacing:.04em;padding:6px 10px;border-radius:6px 6px 0 0;color:#fff;background:var(--rec)}
.strip.paused{background:var(--chip2);color:var(--fg);font-weight:500}
.wrap.live .strip,.wrap.paused .strip{display:block}
.frame{position:relative;width:fit-content;max-width:100%}
img{display:block;max-width:100%;height:auto;border:1px solid #2a2f38;box-shadow:var(--shadow);user-select:none;background:#000}
.stage:not(.one) img{max-height:max(240px,calc(100vh - 240px));max-height:max(240px,calc(100dvh - 240px))}
.stage.one{align-items:flex-start;max-height:max(300px,calc(100vh - 180px));max-height:max(300px,calc(100dvh - 180px))}
.stage.one .wrap,.stage.one .frame{max-width:none}
.stage.one img{max-width:none;max-height:none}
.wrap.live img{outline:2px solid var(--rec);cursor:crosshair}
.wrap.paused img{outline:2px dashed var(--mute)}
.badge{position:absolute;top:10px;left:10px;display:inline-flex;align-items:center;gap:6px;background:var(--rec);color:#fff;font:700 11px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em;padding:5px 8px;border-radius:5px;pointer-events:none;box-shadow:0 2px 8px rgba(0,0,0,.4)}
.badge i{width:7px;height:7px;border-radius:50%;background:#fff;animation:pulse 1.2s ease-in-out infinite}
footer{color:var(--mute);font-size:12px;padding-top:10px;padding-bottom:16px;display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px;overflow-wrap:anywhere}
footer .path{font-size:11.5px;padding:1px 6px}
.toast{position:fixed;left:50%;bottom:18px;transform:translate(-50%,8px);max-width:calc(100% - 32px);background:var(--chip2);border:1px solid var(--line);border-radius:8px;padding:8px 12px;font-size:13px;box-shadow:var(--shadow);pointer-events:none;opacity:0;transition:opacity .18s,transform .18s;overflow-wrap:anywhere}
.toast.show{opacity:1;transform:translate(-50%,0)}
.toast.err{border-color:var(--rec)}
@keyframes pulse{50%{opacity:.3}}
@keyframes spin{to{transform:rotate(360deg)}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media (max-width:480px){.bar{gap:10px 16px}.right{margin-left:0;width:100%}}
</style></head><body>
<header class=top><span class=pill id=pill><i></i><span id=pillt>Connecting</span></span><h1 id=name>__DEVICE__</h1><span class="meta num" id=meta></span>
<span class=right><span class=tag id=tag hidden>view only</span><span class="mute num" id=vw></span></span></header>
<nav class=bar>
<!--standalone--><div class=grp><span class=lbl>Capture</span><button id=rec title="Start recording"><i class=rdot></i><span id=rect>Record</span></button><button id=shot title="Download the current frame as a JPEG">Screenshot</button></div><!--/standalone-->
<div class=grp><span class=lbl>View</span><button id=fit class=sel aria-pressed=true title="Scale the console to fit this window">Fit</button><button id=one aria-pressed=false title="Show the console at its real pixel size">1:1</button></div>
<div class=grp id=cgrp hidden><span class=lbl>Control</span><button id=ctl class=primary>Take control</button>
<button class=key data-k=cad disabled title="Send Ctrl+Alt+Del">Ctrl+Alt+Del</button><button class=key data-k=esc disabled title="Send Escape">Esc</button><button class=key data-k=del disabled title="Delete · BIOS setup on AMI boards">Del</button><button class=key data-k=f2 disabled title="F2 · BIOS setup on many boards">F2</button><button class=key data-k=f7 disabled title="F7 · boot menu on Minisforum boards">F7</button><button class=key data-k=f10 disabled title="F10 · save and exit in BIOS setup">F10</button><button class=key data-k=f11 disabled title="F11">F11</button><button class=key data-k=f12 disabled title="F12 · boot menu on many boards">F12</button><button class=key data-k=win disabled title="Windows key">Win</button></div>
<!--standalone--><div class=grp id=mgrp hidden><span class=lbl>Media</span><select id=iso disabled aria-label="ISO image to mount" title="ISO images in the server's image folder"><option value="">Loading images…</option></select><button id=mount disabled title="Attach the ISO to the host as a USB CD drive; the host is not reset">Mount</button><code class="mono path" id=mnt hidden></code><button id=umount hidden title="Detach the ISO from the host">Unmount</button></div><!--/standalone-->
</nav>
<!--standalone--><nav class="bar sub" id=hbar hidden>
<div class=grp id=pgrp><span class=lbl>Power</span><span class=pill id=ppill title="Host power state, read from AMT every 15 s"><i></i><span id=ppillt>…</span></span>
<button data-a=power_on disabled>Power on</button><button data-a=restart disabled>Restart</button><button data-a=shutdown disabled>Shut down</button><button data-a=power_cycle disabled>Power cycle</button><button data-a=sleep_deep disabled>Sleep</button><button data-a=hibernate disabled>Hibernate</button>
<span class=pwrap><button id=forceB class=danger aria-expanded=false aria-controls=force title="Actions that do not ask the OS first">Force ▾</button>
<div class=pop id=force hidden><div class=poph>Not graceful · the OS is not asked, unsaved work is lost</div>
<button data-a=hard_reset class=danger disabled>Hard reset</button><button data-a=hard_power_off class=danger disabled>Hard power off</button><button data-a=hard_power_cycle class=danger disabled>Hard power cycle</button><button data-a=immediate_shutdown class=danger disabled>Immediate shutdown</button><button data-a=immediate_power_cycle class=danger disabled>Immediate power cycle</button><button data-a=nmi class=danger disabled>NMI</button></div></span></div>
<div class=grp id=bgrp><span class=lbl>Boot</span><select id=target aria-label="Next boot target" title="What the host boots from next time it starts"><option value=bios_setup>BIOS setup</option><option value=pxe>PXE network</option><option value=hard_disk>Hard disk</option><option value=cd_ider>IDE-R CD</option><option value=floppy_ider>IDE-R floppy</option><option value=diagnostic>Diagnostic</option><option value=clear>Normal (clear)</option></select>
<button id=bset disabled title="Set the next boot only; the host is not touched">Set next boot</button><button id=bon disabled>Power on →</button><button id=brst class=danger disabled>Reset →</button>
<code class="mono path" id=nb title="Next boot as AMT reports it">next boot · …</code>
<span class=hint id=bhint hidden><span>No ISO mounted</span><button class=sm id=tomedia title="Jump to the Media group">Mount one in Media</button></span></div>
</nav><!--/standalone-->
<div class=alert id=alert hidden></div>
<div class=msg id=msg></div>
<section class=stage id=stage><div class=wrap id=wrap><div class=strip id=strip></div><div class=frame><img id=view src="stream" alt="live console of __DEVICE__" draggable=false><span class=badge id=badge hidden><i></i><span id=badget>REC</span></span></div></div></section>
<footer id=foot></footer>
<div class=toast id=toast role=status aria-live=polite></div>
<script>
const CONTROL=__CONTROL__;
const $=id=>document.getElementById(id);
const pill=$('pill'),pillt=$('pillt'),nameEl=$('name'),meta=$('meta'),vw=$('vw'),rec=$('rec'),rect=$('rect'),fitB=$('fit'),oneB=$('one');
const alertEl=$('alert'),msg=$('msg'),stage=$('stage'),strip=$('strip'),wrap=$('wrap'),view=$('view'),badge=$('badge'),badget=$('badget'),foot=$('foot'),toastEl=$('toast'),ctl=$('ctl');
const DEV=nameEl.textContent;
/*standalone*/const shot=$('shot');
const mgrp=$('mgrp'),isoSel=$('iso'),mountB=$('mount'),umountB=$('umount'),mnt=$('mnt');
const hbar=$('hbar'),ppill=$('ppill'),ppillt=$('ppillt'),forceB=$('forceB'),force=$('force'),target=$('target'),bset=$('bset'),bon=$('bon'),brst=$('brst'),nb=$('nb'),bhint=$('bhint'),tomedia=$('tomedia');
let mediaBusy=false,isoKey='',armT=0,mediaErr='',mounted=false,applyState=()=>{};/*/standalone*/
let W=0,H=0,HOST='',controlling=false,busy=false,btn=0,lx=0,ly=0,recNow=null,recBusy=false,misses=0,toastT=0,msgKey='',footKey='',recMeta=null,setControl=()=>{};
const q=[],held=new Map();
const el=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e};
const mmss=s=>{s=Math.max(0,Math.round(s||0));return String(Math.floor(s/60)).padStart(2,'0')+':'+String(s%60).padStart(2,'0')};
const size=b=>b>=1048576?(b/1048576).toFixed(1)+' MB':b>=1024?Math.round(b/1024)+' KB':Math.round(b||0)+' B';
const when=t=>t?new Date(t*1000).toLocaleTimeString([],{hour:'numeric',minute:'2-digit',second:'2-digit'}):'';
const refocus=()=>{if(CONTROL&&controlling)wrap.focus({preventScroll:true})};
function toast(text,kind,ms){toastEl.textContent=text;toastEl.className='toast show'+(kind?' '+kind:'');clearTimeout(toastT);toastT=setTimeout(()=>toastEl.classList.remove('show'),ms||5000)}
function setPill(kind,text){pill.className='pill '+kind;pillt.textContent=text}
function pathNode(p){const c=el('code','mono path',p);c.title=p;return c}
function hostChip(){return el('span','host',HOST||'server')}
function copyBtn(p){if(navigator.clipboard&&window.isSecureContext){const b=el('button','sm','Copy path');
b.onclick=async()=>{try{await navigator.clipboard.writeText(p);b.textContent='Copied';toast('Path copied')}catch(e){b.textContent='Copy failed'}setTimeout(()=>{b.textContent='Copy path';refocus()},1500)};return b}
const i=el('input','mono');i.readOnly=true;i.value=p;i.title='select and copy';i.setAttribute('aria-label','recording path');i.onfocus=()=>i.select();return i}
function setMsg(key,nodes){if(key===msgKey)return;msgKey=key;msg.replaceChildren(...nodes)}
function showIdle(){setMsg('idle',[el('span','mute',CONTROL?'Take control to use your keyboard and mouse on '+DEV+'.':'View only. This link cannot send input to '+DEV+'.')])}
function showRecording(r){const key='rec|'+r.path;if(msgKey!==key){recMeta=el('span','num mute');setMsg(key,[el('i','rdot live'),el('strong',null,'Recording'),recMeta,hostChip(),pathNode(r.path)])}
recMeta.textContent=mmss(r.seconds)+' · '+r.frames+' frames · '+size(r.bytes)}
function showSaved(l){const key='saved|'+l.path+'|'+l.encoding;if(key===msgKey)return;const at=l.started?' · started '+when(l.started):'';
if(l.encoding==='running'){setMsg(key,[el('span','spin'),el('strong',null,'Encoding MP4'),el('span','num mute',mmss(l.seconds)+at),hostChip(),pathNode(l.path)]);return}
const failed=!!l.encoding&&l.encoding!=='done';
const nodes=[el('strong',null,failed?'Raw recording kept':'Saved'),el('span','num mute',mmss(l.seconds)+' · '+size(l.bytes)+at),hostChip(),pathNode(l.path),copyBtn(l.path)];
if(failed)nodes.push(el('span','warn','MP4 encoding '+l.encoding+' · the .mjpeg plays in VLC or ffplay'));
setMsg(key,nodes)}
function showFooter(s){const key=s.hostname+'|'+s.recording_dir;if(key===footKey)return;footKey=key;
foot.replaceChildren(el('span',null,'Recordings go to'),hostChip(),pathNode(s.recording_dir),el('span',null,'· change it with amt_mirror_link record_start directory'))}
/*standalone*/async function loadImages(){try{const m=await(await fetch('media.json',{cache:'no-store'})).json(),names=m.images||[],key=names.join('|')+'|'+(m.error||'');
if(key===isoKey)return;isoKey=key;const keep=isoSel.value;
isoSel.replaceChildren(...(names.length?names.map(n=>{const o=el('option',null,n);o.value=n;return o}):[el('option',null,m.error?'image folder unreadable':'no ISO in the image folder')]));
if(names.includes(keep))isoSel.value=keep;isoSel.disabled=mountB.disabled=!names.length}
catch(e){isoSel.replaceChildren(el('option',null,'image list unavailable'));isoSel.disabled=mountB.disabled=true}}
function showMedia(d){if(!d)return;const on=!!d.mounted;isoSel.hidden=mountB.hidden=on;umountB.hidden=mnt.hidden=!on;
if(on){const n=(d.images&&(d.images.iso||d.images.floppy))||'image';mnt.className='mono path';mnt.onclick=null;mediaErr='';mnt.textContent=n+' · '+size(d.bytes_to_host||0)+' sent to host';mnt.title=n+' is attached to the host as a USB CD drive. The host boots from it only when the next boot is set to the CD.'}
else if(d.error&&mediaErr!==d.error){mediaErr=d.error;mnt.hidden=false;mnt.className='mono path warn';mnt.textContent='Mount ended · '+d.error;
mnt.title='Click to dismiss';mnt.onclick=()=>{mnt.hidden=true;mnt.onclick=null;mnt.className='mono path'}}
mounted=on;applyState()}
function disarm(){clearTimeout(armT);umountB.classList.remove('arm');umountB.textContent='Unmount'}
async function media(body){if(mediaBusy)return;mediaBusy=true;const act=body.action==='mount';
const b=act?mountB:umountB,was=act?'Mount':'Unmount';mountB.disabled=umountB.disabled=isoSel.disabled=true;
b.replaceChildren(el('span','spin'),el('span',null,act?'Mounting…':'Unmounting…'));
try{const r=await fetch('ider',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),t=await r.text();
if(!r.ok)toast('Media request refused: '+r.status+' '+t,'err',8000);
else toast(act?'Mounted '+body.iso+' · the host sees a USB CD drive. To boot it, pick IDE-R CD under Boot.':'Unmounted · the CD drive is gone from the host',null,act?9000:5000)}
catch(e){toast('Media request failed','err')}
b.textContent=was;mediaBusy=false;isoSel.disabled=!isoSel.value;mountB.disabled=isoSel.disabled;umountB.disabled=false;disarm();await poll();refocus()}
/*/standalone*/async function poll(){let s;
try{s=await(await fetch('status.json',{cache:'no-store'})).json()}
catch(e){misses++;if(misses>=3){setPill('off','Offline');alertEl.hidden=false;alertEl.className='alert warn';alertEl.textContent='Lost contact with the mirror server. Retrying every second.';if(CONTROL&&controlling)setControl(false)}return}
misses=0;W=s.width;H=s.height;HOST=s.hostname||'';
setPill(s.live?'ok':'bad',s.live?'Live':'Stopped');
meta.textContent=s.width+'×'+s.height+' · '+s.fps+' fps';
meta.title='frame '+s.frames+(s.last_frame_age_s!=null?' · last screen change '+s.last_frame_age_s+'s ago':' · no frame yet');
vw.textContent=s.viewers+(s.viewers===1?' viewer':' viewers');
if(s.live)alertEl.hidden=true;else{alertEl.hidden=false;alertEl.className='alert';alertEl.textContent='Mirror stopped'+(s.error?' · '+s.error:'')+'. Start it again with amt_mirror_link.'}
showFooter(s);/*standalone*/if(CONTROL)showMedia(s.ider);/*/standalone*/
const r=s.recording,l=s.last_recording;recNow=r;
/*standalone*/rec.classList.toggle('on',!!r);rect.textContent=r?'Stop · '+mmss(r.seconds):'Record';
rec.title=r?'Stop recording':'Start recording on '+HOST+' in '+s.recording_dir;/*/standalone*/
badge.hidden=!r;if(r)badget.textContent='REC '+mmss(r.seconds);
document.title=(r?'● REC · ':'')+DEV+' · AMT mirror';
if(r)showRecording(r);else if(l)showSaved(l);else showIdle()}
/*standalone*/rec.onclick=async()=>{if(recBusy)return;recBusy=true;rec.disabled=true;
try{const r=await fetch('record?on='+(recNow?'0':'1'),{method:'POST'});if(!r.ok)toast('Record request refused: '+r.status,'err')}catch(e){toast('Record request failed','err')}
rec.disabled=false;recBusy=false;await poll();refocus()};/*/standalone*/
/*standalone*/shot.onclick=async()=>{shot.disabled=true;
try{const r=await fetch('frame.jpg',{cache:'no-store'});if(!r.ok){toast('No frame yet','err')}else{
const stamp=new Date().toISOString().slice(0,19).replace(/[-:]/g,'')+'Z',fname='amt-'+DEV+'-'+stamp+'.jpg';
const url=URL.createObjectURL(await r.blob()),a=el('a');a.href=url;a.download=fname;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),5000);
toast('Screenshot saved to your downloads · '+fname+(W?' · '+W+'×'+H:''))}}
catch(e){toast('Screenshot failed','err')}
shot.disabled=false;refocus()};
/*/standalone*/function setFit(fit){stage.classList.toggle('one',!fit);fitB.classList.toggle('sel',fit);oneB.classList.toggle('sel',!fit);fitB.setAttribute('aria-pressed',String(fit));oneB.setAttribute('aria-pressed',String(!fit));refocus()}
fitB.onclick=()=>setFit(true);oneB.onclick=()=>setFit(false);
setInterval(poll,1000);poll();
if(!CONTROL){$('tag').hidden=false}else{
$('cgrp').hidden=false;wrap.tabIndex=0;/*standalone*/mgrp.hidden=false;hbar.hidden=false;loadImages();isoSel.addEventListener('pointerdown',loadImages);umountB.addEventListener('blur',disarm);
mountB.onclick=()=>{if(isoSel.value)media({action:'mount',iso:isoSel.value})};
umountB.onclick=()=>{if(!umountB.classList.contains('arm')){umountB.classList.add('arm');umountB.textContent='Click again to unmount';armT=setTimeout(disarm,4000);return}media({action:'unmount'})};
const pbtns=[...document.querySelectorAll('#pgrp button[data-a]')],hostBtns=[...pbtns,bset,bon,brst,forceB];
const CAN={power_on:['off','sleep','hibernate','unknown'],restart:['on','unknown'],shutdown:['on','unknown'],power_cycle:['on','unknown'],sleep_deep:['on','unknown'],hibernate:['on','unknown'],
hard_reset:['on','sleep','hibernate','unknown'],hard_power_off:['on','sleep','hibernate','unknown'],hard_power_cycle:['on','sleep','hibernate','unknown'],immediate_shutdown:['on','unknown'],immediate_power_cycle:['on','unknown'],nmi:['on','unknown']};
const TIP={power_on:'Power the host on',restart:'Ask the OS to restart (graceful; needs the Intel LMS agent in the OS)',shutdown:'Ask the OS to shut down (graceful)',power_cycle:'Ask the OS to shut down, then power back on (graceful)',sleep_deep:'Suspend to RAM (S3)',hibernate:'Hibernate to disk (S4)',
hard_reset:'Reset the host without asking the OS; unsaved work is lost',hard_power_off:'Cut power without asking the OS',hard_power_cycle:'Cut power, then power back on, without asking the OS',immediate_shutdown:'Shut down now without asking the OS',immediate_power_cycle:'Shut down now and power back on, without asking the OS',nmi:'Non-maskable interrupt; the OS may crash-dump'};
const VERB={power_on:'Powering on…',restart:'Restarting…',shutdown:'Shutting down…',power_cycle:'Power cycling…',sleep_deep:'Sleeping…',hibernate:'Hibernating…',hard_reset:'Resetting…',hard_power_off:'Powering off…',hard_power_cycle:'Power cycling…',immediate_shutdown:'Shutting down…',immediate_power_cycle:'Power cycling…',nmi:'Sending NMI…'};
const DONE={power_on:'Power on sent',restart:'Restart requested from the OS',shutdown:'Shutdown requested from the OS',power_cycle:'Power cycle requested from the OS',sleep_deep:'Sleep requested',hibernate:'Hibernate requested',hard_reset:'Hard reset sent',hard_power_off:'Hard power off sent',hard_power_cycle:'Hard power cycle sent',immediate_shutdown:'Immediate shutdown sent',immediate_power_cycle:'Immediate power cycle sent',nmi:'NMI sent'};
const PNAME={on:'On',sleep:'Sleep',hibernate:'Hibernate',off:'Off',unknown:'Unknown'},PCLS={on:'ok',sleep:'off',hibernate:'off',off:'',unknown:'bad'};
let pstate='unknown',AV=null,pbusy=false,pwrBusy=false,armB=null,armT2=0,lastBoot='',lastBootAt=0,pollT=[];
const norm=s=>{s=String(s||'');return s==='on'?'on':s.indexOf('sleep')===0?'sleep':s==='hibernate'?'hibernate':s.indexOf('off')===0?'off':'unknown'};
const tlabel=()=>{const o=target.options[target.selectedIndex];return o?(o.value==='clear'?'normal boot':o.textContent):''};
function disarmAll(){if(!armB)return;clearTimeout(armT2);armB.classList.remove('arm','arm2');armB.textContent=armB.dataset.l||armB.textContent;armB=null}
function arm(b,label,run){if(armB===b){disarmAll();run();return}disarmAll();armB=b;b.dataset.l=b.textContent;b.classList.add(b.classList.contains('danger')?'arm2':'arm');b.textContent='Click again · '+label;armT2=setTimeout(disarmAll,4000)}
function forceOpen(o){force.hidden=!o;forceB.setAttribute('aria-expanded',String(o));forceB.classList.toggle('sel',o);if(!o)disarmAll()}
function setP(st,p,err){pstate=st;AV=(p&&Array.isArray(p.actions))?p.actions:null;ppill.className='pill '+PCLS[st];ppillt.textContent=PNAME[st];
ppill.title=p?'AMT power state '+(p.power&&p.power.state)+' (code '+(p.power&&p.power.code)+') · read '+when(Date.now()/1000):'Power state unavailable · '+err;
const b=(p&&p.next_boot)||null,yes=v=>v===true||v==='true',known=b&&yes(b.BIOSSetup)?'BIOS setup':b&&yes(b.UseIDER)?'IDE-R media':null;
nb.textContent='next boot · '+(known||(Date.now()-lastBootAt<600000&&lastBoot)||'normal');
nb.title=known?'AMT reports a one-time boot override for the next start':lastBoot&&Date.now()-lastBootAt<600000?'Set from this page; AMT does not report this target back':'No boot override reported by AMT';applyState()}
async function loadPower(){if(pwrBusy)return;pwrBusy=true;try{const r=await fetch('power.json',{cache:'no-store'});if(!r.ok){setP('unknown',null,'power.json '+r.status);return}const p=(await r.json())||{};setP(norm(p.power&&p.power.state),p,'')}catch(e){setP('unknown',null,'unreachable')}finally{pwrBusy=false}}
applyState=()=>{if(pbusy)return;pbtns.forEach(b=>{const ok=CAN[b.dataset.a].includes(pstate)&&(!AV||AV.includes(b.dataset.a));if(!ok&&armB===b)disarmAll();b.disabled=!ok});
const cd=target.value==='cd_ider',need=cd&&!mounted,lab=tlabel();bhint.hidden=!need;
const canOn=CAN.power_on.includes(pstate)&&!need&&(!AV||AV.includes('power_on')),canRst=CAN.hard_reset.includes(pstate)&&!need&&(!AV||AV.includes('hard_reset'));
if(armB!==bon)bon.textContent='Power on → '+lab;if(armB!==brst)brst.textContent='Reset → '+lab;
if(!canOn&&armB===bon)disarmAll();if(!canRst&&armB===brst)disarmAll();
bset.disabled=need;bon.disabled=!canOn;brst.disabled=!canRst;target.disabled=false;
bon.title=need?'Mount an ISO first':pstate==='on'?'The host is already on; use Reset → instead':'Set next boot to '+lab+', then power the host on';
brst.title=need?'Mount an ISO first':canRst?'Set next boot to '+lab+', then HARD reset the host without asking the OS; unsaved work is lost':'The host is off; use Power on → instead'};
async function powerAct(btn,body,route,verb,done){if(pbusy)return;pbusy=true;disarmAll();forceOpen(false);pollT.forEach(clearTimeout);pollT=[];
hostBtns.forEach(x=>x.disabled=true);target.disabled=true;const was=btn.textContent;btn.replaceChildren(el('span','spin'),el('span',null,verb));
try{const r=await fetch(route,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)}),t=await r.text();
if(!r.ok)toast((route==='boot'?'Boot':'Power')+' request refused: '+r.status+' '+t,'err',9000);
else{toast(done+' · AMT applies it in a few seconds; watch the console and the power pill',null,7000);
if(route==='boot'){if(body.then||body.target==='clear'){lastBoot='';lastBootAt=0}else{lastBoot=tlabel();lastBootAt=Date.now()}}}}
catch(e){toast((route==='boot'?'Boot':'Power')+' request failed','err')}
btn.textContent=was;pbusy=false;hostBtns.forEach(x=>x.disabled=false);await loadPower();pollT=[3000,8000,15000].map(ms=>setTimeout(loadPower,ms));refocus()}
pbtns.forEach(b=>{const a=b.dataset.a;b.title=TIP[a];
b.onclick=()=>{const go=()=>powerAct(b,{action:a},'power',VERB[a],DONE[a]);if(a==='power_on')go();else arm(b,b.textContent.toLowerCase(),go)};
b.addEventListener('blur',()=>{if(armB===b)disarmAll()})});
bset.onclick=()=>powerAct(bset,{target:target.value},'boot','Setting…','Next boot set to '+tlabel());
bon.onclick=()=>powerAct(bon,{target:target.value,then:'power_on'},'boot','Powering on…','Next boot set to '+tlabel()+', power on sent');
brst.onclick=()=>arm(brst,'hard reset → '+tlabel(),()=>powerAct(brst,{target:target.value,then:'hard_reset'},'boot','Resetting…','Next boot set to '+tlabel()+', hard reset sent'));
brst.addEventListener('blur',()=>{if(armB===brst)disarmAll()});
target.onchange=()=>{disarmAll();applyState()};
tomedia.onclick=()=>{isoSel.scrollIntoView({block:'center',behavior:'smooth'});isoSel.focus({preventScroll:true})};
forceB.onclick=()=>forceOpen(force.hidden);
document.addEventListener('pointerdown',e=>{if(!force.hidden&&!e.target.closest('.pwrap'))forceOpen(false)});
document.addEventListener('visibilitychange',()=>{if(!document.hidden)loadPower()});
loadPower();setInterval(loadPower,15000);/*/standalone*/
const NAMED={Enter:0xff0d,Backspace:0xff08,Tab:0xff09,Escape:0xff1b,Delete:0xffff,Insert:0xff63,Home:0xff50,End:0xff57,PageUp:0xff55,PageDown:0xff56,ArrowLeft:0xff51,ArrowUp:0xff52,ArrowRight:0xff53,ArrowDown:0xff54,CapsLock:0xffe5,ContextMenu:0xff67,PrintScreen:0xff61,Pause:0xff13,ScrollLock:0xff14,NumLock:0xff7f};
const SIDED={Shift:[0xffe1,0xffe2],Control:[0xffe3,0xffe4],Alt:[0xffe9,0xffea],Meta:[0xffeb,0xffec]};
const tap=k=>[[k,1],[k,0]],CHIPS={cad:[[0xffe3,1],[0xffe9,1],[0xffff,1],[0xffff,0],[0xffe9,0],[0xffe3,0]],esc:tap(0xff1b),del:tap(0xffff),
f2:tap(0xffbf),f7:tap(0xffc4),f10:tap(0xffc7),f11:tap(0xffc8),f12:tap(0xffc9),win:tap(0xffeb)};
const chips=[...document.querySelectorAll('.key')];
function keysym(e){if(SIDED[e.key])return SIDED[e.key][e.location===2?1:0];if(NAMED[e.key])return NAMED[e.key];
const f=/^F([1-9]|1[0-2])$/.exec(e.key);if(f)return 0xffbe+Number(f[1])-1;
if([...e.key].length===1){const c=e.key.codePointAt(0);return c<0x100?c:0x1000000+c}return null}
async function flush(){if(busy||!q.length)return;busy=true;const ev=q.splice(0,500);
try{const r=await fetch('input',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({events:ev})});
if(!r.ok)toast('Input refused: '+r.status+' '+(await r.text()),'err',8000)}catch(e){toast('Input failed: '+e,'err',8000)}
busy=false;if(q.length)flush()}
function releaseKeys(){for(const k of held.values())q.push(['k',k,0]);held.clear();if(btn){btn=0;q.push(['p',lx,ly,0])}flush()}
function stripState(){const live=controlling&&document.activeElement===wrap;
strip.classList.toggle('paused',controlling&&!live);
strip.textContent=live?'CONTROLLING · keys and mouse go to '+DEV+' · Release control to stop':'Paused · click the console to resume';
strip.title='Every key, Escape included, goes to the host. Release with the button or by leaving this window.';
wrap.classList.toggle('live',live);wrap.classList.toggle('paused',controlling&&!live)}
setControl=on=>{controlling=on;if(!on)releaseKeys();ctl.classList.toggle('on',on);ctl.classList.toggle('primary',!on);ctl.textContent=on?'Release control':'Take control';
chips.forEach(c=>c.disabled=!on);if(on)wrap.focus();stripState()};
ctl.onclick=()=>setControl(!controlling);
chips.forEach(c=>c.onclick=()=>{if(!controlling)return;CHIPS[c.dataset.k].forEach(([k,d])=>q.push(['k',k,d]));flush();wrap.focus()});
wrap.addEventListener('focus',stripState);wrap.addEventListener('blur',()=>{releaseKeys();stripState()});
window.addEventListener('blur',()=>{if(controlling)setControl(false)});
wrap.addEventListener('keydown',e=>{if(!controlling)return;e.preventDefault();if(e.repeat)return;const k=keysym(e);if(k==null)return;held.set(e.code||e.key,k);q.push(['k',k,1]);flush()});
wrap.addEventListener('keyup',e=>{if(!controlling)return;e.preventDefault();const id=e.code||e.key,k=held.has(id)?held.get(id):keysym(e);held.delete(id);if(k!=null){q.push(['k',k,0]);flush()}});
function pos(e){const r=view.getBoundingClientRect();lx=Math.max(0,Math.min(W-1,Math.round((e.clientX-r.left)/r.width*W)));ly=Math.max(0,Math.min(H-1,Math.round((e.clientY-r.top)/r.height*H)))}
function ptr(e){if(!controlling||!W)return;e.preventDefault();if(e.type==='mousedown')wrap.focus();pos(e);btn=(e.buttons&1)|(e.buttons&4?2:0)|(e.buttons&2?4:0);
const last=q[q.length-1];if(e.type==='mousemove'&&last&&last[0]==='p'&&last[3]===btn){last[1]=lx;last[2]=ly}else q.push(['p',lx,ly,btn]);flush()}
['mousemove','mousedown','mouseup'].forEach(t=>view.addEventListener(t,ptr));
window.addEventListener('mouseup',e=>{if(controlling&&btn&&e.target!==view){btn=0;q.push(['p',lx,ly,0]);flush()}});
view.addEventListener('contextmenu',e=>{if(controlling)e.preventDefault()});
view.addEventListener('wheel',e=>{if(!controlling||!W)return;e.preventDefault();pos(e);const b=e.deltaY<0?8:16;q.push(['p',lx,ly,btn|b],['p',lx,ly,btn]);flush()},{passive:false})}
</script></body></html>"""


# Markup and script only the standalone page carries (Capture: Record and the Screenshot download,
# Media, Power, Boot) sit between "standalone" markers. The embed page, framed by the management console, drops those
# regions whole, so its source holds no route to them.
_STANDALONE_ONLY = re.compile(r"<!--standalone-->.*?<!--/standalone-->|/\*standalone\*/.*?/\*/standalone\*/", re.S)
_STANDALONE_MARKS = re.compile(r"<!--/?standalone-->|/\*/?standalone\*/")


def render_page(template: str, device: str, control: bool, embed: bool) -> str:
    """A viewer page (this module's or the serial terminal's) for one device. ``embed`` serves
    View and Control only."""
    page = (_STANDALONE_ONLY if embed else _STANDALONE_MARKS).sub("", template)
    return page.replace("__DEVICE__", html.escape(device)).replace("__CONTROL__", "true" if control else "false")


def _frame_ancestors() -> str:
    """The CSP ``frame-ancestors`` value: the console's origin when AMT_CONSOLE_ORIGIN is a plain
    http(s) origin, else 'none' (a malformed value is never copied into a header)."""
    value = os.environ.get(CONSOLE_ORIGIN_ENV, "").strip().rstrip("/")
    return value if re.fullmatch(r"https?://[A-Za-z0-9.\-]+(:[0-9]{1,5})?", value) else "'none'"


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "amt-mirror"

    def log_message(self, *args) -> None:   # never write request logs anywhere
        pass

    def end_headers(self) -> None:
        """Every response, page or not, tells the browser not to leak the token-bearing url in a
        Referer and who may frame it (the management console, if one is configured)."""
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", f"frame-ancestors {_frame_ancestors()}")
        super().end_headers()

    def _embed(self) -> bool:
        """Whether the request carries ``embed=1``: it came from, or is for, an embedded viewer."""
        return urllib.parse.parse_qs(self.path.partition("?")[2]).get("embed") == ["1"]

    def _slashed(self) -> str:
        """This request's path with the trailing slash added, query kept (``?embed=1`` survives)."""
        path, _, query = self.path.partition("?")
        return path + "/" + (f"?{query}" if query else "")

    def _route(self) -> tuple[Mirror | None, bool, str]:
        parts = self.path.split("?", 1)[0].split("/")
        if len(parts) < 3 or parts[1] != "m":
            return None, False, ""
        mirror, control = _by_token(parts[2])
        return mirror, control, "/".join(parts[3:])

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _serial(self, post: bool) -> bool:
        """Route /s/<token>/... to the serial terminal (amt_serial); True when it was handled."""
        parts = self.path.split("?", 1)[0].split("/")
        if len(parts) < 3 or parts[1] != "s":
            return False
        import amt_serial   # imported here: amt_serial imports this module
        term, control = amt_serial.by_token(parts[2])
        if term is None:
            self._send(404, b"not found", "text/plain")
        elif post:
            amt_serial.handle_post(self, term, control, "/".join(parts[3:]))
        else:
            amt_serial.handle_get(self, term, control, "/".join(parts[3:]))
        return True

    def do_GET(self) -> None:  # noqa: N802
        if self._serial(post=False):
            return None
        mirror, control, rest = self._route()
        if mirror is None or rest not in ROUTES:
            return self._send(404, b"not found", "text/plain")
        if rest == "" and not self.path.split("?")[0].endswith("/"):
            self.send_response(301)
            self.send_header("Location", self._slashed())
            self.end_headers()
            return None
        if rest == "":
            page = render_page(PAGE, mirror.device, control, self._embed())
            return self._send(200, page.encode(), "text/html; charset=utf-8")
        if rest in CONTROL_ROUTES and not control:
            return self._send(404, b"not found", "text/plain")
        if rest == "status.json":
            return self._send(200, json.dumps(mirror.info()).encode(), "application/json")
        if rest == "media.json":
            return self._send(200, json.dumps(media_list()).encode(), "application/json")
        if rest == "power.json":
            try:
                body = json.dumps(power_state(mirror.device)).encode()
            except Exception as ex:   # noqa: BLE001 - AMT unreachable; no secret is ever in one
                return self._send(502, f"{type(ex).__name__}: {ex}".encode()[:300], "text/plain")
            return self._send(200, body, "application/json")
        if rest == "frame.jpg":
            if mirror.jpeg is None:
                return self._send(503, b"no frame yet", "text/plain")
            return self._send(200, mirror.jpeg, "image/jpeg")
        if rest == "stream":
            return self._stream(mirror)
        return self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:  # noqa: N802
        if self._serial(post=True):
            return None
        mirror, control, rest = self._route()
        if mirror is None or rest not in POST_ROUTES or (rest in CONTROL_ROUTES and not control):
            return self._send(404, b"not found", "text/plain")
        if rest == "input":
            return self._input(mirror)
        if rest in ACTIONS:
            if self._embed():     # the embedded page has no such controls; a request that says it is embedded gets none
                return self._send(403, b"embed_mode: power, boot and media are not available to an embedded viewer",
                                  "text/plain")
            return self._action(mirror, ACTIONS[rest])
        if self._embed():     # recording is a tool action (record_start needs confirmed): an embedded viewer has no Record
            return self._send(403, b"embed_mode: recording is amt_mirror_link record_start / record_stop, not a viewer route",
                              "text/plain")
        on = "on=1" in self.path.split("?", 1)[-1]
        out = mirror.record_start(recording_dir()) if on else mirror.record_stop()
        return self._send(200, json.dumps(out).encode(), "application/json")

    def _body(self) -> tuple[Any, tuple[int, bytes] | None]:
        """The JSON request body, or the (code, text) refusal."""
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if not 0 < length <= MAX_INPUT_BYTES:
            return None, (413 if length else 411, b"body must be 1-65536 bytes")
        try:
            return json.loads(self.rfile.read(length)), None
        except (ValueError, RecursionError):
            return None, (400, b"bad_body: not JSON")

    def _action(self, mirror: Mirror, run) -> None:
        body, refused = self._body()
        if refused:
            return self._send(*refused, "text/plain")
        try:
            out = run(mirror, body)
        except ValueError as ex:
            return self._send(409, str(ex).encode(), "text/plain")
        except Exception as ex:   # noqa: BLE001 - AMT or TLS failure; the engine never puts a secret in one
            return self._send(502, f"{type(ex).__name__}: {ex}".encode()[:300], "text/plain")
        return self._send(200, json.dumps(out).encode(), "application/json")

    def _input(self, mirror: Mirror) -> None:
        body, refused = self._body()
        if refused:
            return self._send(*refused, "text/plain")
        try:
            events = body["events"]
        except (KeyError, TypeError):
            return self._send(400, b'input_bad_body: expected {"events": [...]}', "text/plain")
        if not mirror.alive():
            return self._send(409, b"mirror_not_live", "text/plain")
        try:
            sent = send_input(mirror, events)
        except ValueError as ex:
            return self._send(400, str(ex).encode(), "text/plain")
        except Exception as ex:   # noqa: BLE001 - a dead socket; the engine never puts a secret in one
            return self._send(502, type(ex).__name__.encode(), "text/plain")
        return self._send(200, json.dumps({"sent": sent}).encode(), "application/json")

    def _stream(self, mirror: Mirror) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Accel-Buffering", "no")   # a buffering reverse proxy would stall frames
        self.end_headers()
        with _LOCK:
            mirror.viewers += 1
        seen = -1
        try:
            while mirror.alive() or mirror.seq != seen:
                with mirror.cond:
                    if mirror.seq == seen:
                        mirror.cond.wait(STREAM_WAIT_SECONDS)
                    jpeg, seq = mirror.jpeg, mirror.seq
                if jpeg is None or seq == seen:
                    if not mirror.alive():
                        break
                    continue
                seen = seq
                self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: "
                                 + str(len(jpeg)).encode() + b"\r\n\r\n" + jpeg + b"\r\n")
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError, OSError):
            pass   # the viewer went away
        finally:
            with _LOCK:
                mirror.viewers -= 1


def _ensure_server(bind: str, port: int) -> tuple[str, int]:
    """The viewer HTTP server for this bind and port, started if none runs. One server carries
    every live mirror and serial terminal, so a different bind or port while any of them is
    live is refused rather than tearing their pages down; with none live the old server is
    replaced, and only after the new one has bound."""
    import amt_serial   # the serial terminal shares this server
    serial_live = amt_serial.live()
    with _LOCK:
        live = _SERVER.get("httpd")
        if live is not None and (_SERVER["bind"], _SERVER["want_port"]) == (bind, port):
            return _SERVER["bind"], _SERVER["port"]
        if live is not None and (_MIRRORS or serial_live):
            raise ValueError(f"viewer_server_in_use: pages are live at {_SERVER['bind']}:{_SERVER['port']}; "
                             "use that bind and port, or stop the live mirrors and terminals first")
        httpd = http.server.ThreadingHTTPServer((bind, port), _Handler)   # bind first: a failure keeps the old one
        httpd.daemon_threads = True
        if live is not None:
            _SERVER.clear()
            live.shutdown()
            live.server_close()
        thread = threading.Thread(target=httpd.serve_forever, name="amt-mirror-http", daemon=True)
        thread.start()
        _SERVER.update(httpd=httpd, thread=thread, bind=bind, want_port=port,
                       port=httpd.server_address[1])
        return bind, _SERVER["port"]


def _stop_server_if_idle() -> None:
    import amt_serial   # the serial terminal shares this server
    serial_live = amt_serial.live()
    with _LOCK:
        if _MIRRORS or serial_live or _SERVER.get("httpd") is None:
            return
        httpd = _SERVER.pop("httpd")
        _SERVER.clear()
    httpd.shutdown()
    httpd.server_close()


VIEWER_BASE_ENV = "AMT_VIEWER_PUBLIC_BASE_URL"   # e.g. https://amt-viewer.example.com, the TLS front


def _viewer_base() -> str | None:
    """The public base URL of the viewer front, or None when unset or not http(s)."""
    value = os.environ.get(VIEWER_BASE_ENV, "").strip().rstrip("/")
    return value if re.fullmatch(r"https?://[^/\s]+", value) else None


def _urls(bind: str, port: int, token: str, device_ip: str, prefix: str = "m") -> list[str]:
    """Viewer URLs, the public front first when AMT_VIEWER_PUBLIC_BASE_URL is set."""
    base = _viewer_base()
    public = [f"{base}/{prefix}/{token}/"] if base and bind in ("0.0.0.0", "::") else []
    return public + _direct_urls(bind, port, token, device_ip, prefix)


def _direct_urls(bind: str, port: int, token: str, device_ip: str, prefix: str) -> list[str]:
    hosts = ["127.0.0.1"] if bind in ("127.0.0.1", "localhost") else []
    if bind not in ("127.0.0.1", "localhost", "0.0.0.0", "::"):
        hosts = [bind]
    if bind in ("0.0.0.0", "::"):
        hosts = ["127.0.0.1"]
        try:   # the address this host uses toward the managed device: the LAN-facing one
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((device_ip, 9))
                hosts.append(s.getsockname()[0])
        except OSError:
            pass
    return [f"http://{h}:{port}/{prefix}/{token}/" for h in hosts]


def recording_dir() -> Path:
    raw = amt_write._load_settings().get("recording_dir")
    return Path(raw) if raw else Path.home() / "amt-recordings"


def set_recording_dir(directory: str) -> Path:
    path = Path(directory).expanduser().resolve()
    path.mkdir(parents=True, exist_ok=True)
    settings = amt_write._load_settings()
    settings["recording_dir"] = str(path)
    amt_write._save_settings(settings)
    return path


# -- actions --------------------------------------------------------------------------------

def start(device: str = amt_tools.DEFAULT_DEVICE, bind: str = DEFAULT_BIND, port: int = DEFAULT_PORT,
          fps: int = DEFAULT_FPS, quality: int = DEFAULT_QUALITY, record: bool = False) -> dict[str, Any]:
    if not 1 <= fps <= 30 or not 10 <= quality <= 95 or not 0 <= port <= 65535:
        raise ValueError("mirror_bad_settings: fps 1-30, quality 10-95, port 0-65535")
    dev = amt_registry.get_device(device)
    with _LOCK:
        existing = _MIRRORS.get(dev.key)
    if existing is not None and existing.alive():
        out = status(dev.key)
        out["note"] = "already live; returning the existing link"
        return out
    amt_wsman.require_pin(dev)
    session = amt_tools._pinned_kvm_session(dev, amt_vault.get_secret(dev.amt_vault_key))
    try:
        session.open()
    except Exception:
        session.close()
        raise
    mirror = Mirror(dev.key, session, fps, quality)
    try:
        bind, port = _ensure_server(bind, port)
    except Exception:
        session.close()
        raise
    mirror.thread = threading.Thread(target=mirror.run, name=f"amt-mirror-{dev.key}", daemon=True)
    with _LOCK:
        _MIRRORS[dev.key] = mirror
    mirror.thread.start()
    if record:
        mirror.record_start(recording_dir())
    return {**status(dev.key), "note": "urls are view only; control_urls add a Take control switch "
                                       "for keyboard and mouse. The agent's console tools share this "
                                       "session, so the viewer sees what the agent does"}


def stop(device: str = amt_tools.DEFAULT_DEVICE) -> dict[str, Any]:
    dev = amt_registry.get_device(device)
    with _LOCK:
        mirror = _MIRRORS.pop(dev.key, None)
    if mirror is None:
        return {"device": dev.key, "stopped": False, "note": "no mirror was live"}
    mirror.stop.set()
    if mirror.thread is not None:
        mirror.thread.join(timeout=15)
    _stop_server_if_idle()
    return {"device": dev.key, "stopped": True, "session_released": not mirror.alive(),
            "frames": mirror.seq, "error": mirror.error, "recording": mirror.last_recording}


def status(device: str | None = None) -> dict[str, Any]:
    with _LOCK:
        mirrors = {k: m for k, m in _MIRRORS.items() if device in (None, k)}
        bind, port = _SERVER.get("bind"), _SERVER.get("port")
    out = []
    for key, m in mirrors.items():
        dev = amt_registry.get_device(key)
        out.append({**m.info(), "urls": _urls(bind, port, m.token, dev.amt_ip) if port else [],
                    "control_urls": _urls(bind, port, m.control_token, dev.amt_ip) if port else []})
    if device is not None:
        return out[0] if out else {"device": device, "live": False}
    return {"mirrors": out, "server": {"bind": bind, "port": port} if port else None,
            "recording_dir": str(recording_dir())}


def record(device: str, on: bool, directory: str | None = None) -> dict[str, Any]:
    dev = amt_registry.get_device(device)
    with _LOCK:
        mirror = _MIRRORS.get(dev.key)
    if mirror is None or not mirror.alive():
        raise ValueError("mirror_not_live: start it with amt_mirror_link action=start")
    if on:
        target = set_recording_dir(directory) if directory else recording_dir()
        return {"device": dev.key, "recording": mirror.record_start(target)}
    return {"device": dev.key, "recording": mirror.record_stop()}


# -- the tool -------------------------------------------------------------------------------

async def amt_mirror_link(
    action: Annotated[MirrorAction, Field(
        description="start opens the device's KVM session and returns viewer URLs; stop ends it; "
                    "status lists live mirrors; record_start / record_stop save the live view to a "
                    "file.")] = "status",
    device: Annotated[str, Field(
        description=f"Registered device key; defaults to {amt_tools.DEFAULT_DEVICE}.")] = amt_tools.DEFAULT_DEVICE,
    bind: Annotated[str, Field(
        description="start: address the viewer page listens on. 127.0.0.1 (default) is this "
                    "machine only; 0.0.0.0 lets other machines on the LAN watch.")] = DEFAULT_BIND,
    port: Annotated[int, Field(
        description="start: viewer port (default 8766; 0 picks a free one).")] = DEFAULT_PORT,
    fps: Annotated[int, Field(description="start: frames per second, 1-30 (default 15).")] = DEFAULT_FPS,
    quality: Annotated[int, Field(description="start: JPEG quality, 10-95 (default 70).")] = DEFAULT_QUALITY,
    record_on_start: Annotated[bool, Field(
        description="start: begin recording at once.")] = False,
    directory: Annotated[str | None, Field(
        description="record_start: folder for recordings (a NAS mount works); kept for later "
                    "recordings. Default ~/amt-recordings.")] = None,
    confirmed: Annotated[StrictBool, Field(
        description="start and record_start need the JSON boolean true; false refuses and starts "
                    "nothing. stop, record_stop and status need none.")] = False,
) -> dict:
    """Live display mirror of a host's console for the operator, MeshCommander's Remote Desktop
    view. start opens the device's KVM session once, grabs the screen at the set rate and serves
    it at http://<bind>:<port>/m/<token>/ (page, MJPEG stream, frame.jpg, status.json, Record
    and Screenshot buttons); the token is the only access key, so share the URL only with viewers. control_urls
    carry a second token whose page adds Take control: the holder's keyboard and mouse then drive
    the host, plus buttons for Ctrl+Alt+Del, Esc, Del, F2, F7, F10, F11, F12 and Win, and an
    ISO picker that mounts (always start=next_boot, never a reset) or unmounts IDE-R media,
    and MeshCommander's Power and Boot actions (graceful ones inline, forced ones in a separate
    tray, each that interrupts the host behind a two-click confirm). Share those only with whoever should drive. A url
    with ?embed=1 serves View and Control only (no Record button: use record_start / record_stop), for the management console's frame. status.json
    carries in_flight: the tool name and start time of an agent call now using the shared session. While a mirror
    is live, amt_screenshot, amt_console_input and amt_remote_logon / logoff reuse its session
    instead of opening their own, so the viewer watches the agent work. IDE-R mounts run alongside
    it. Recordings are encoded to H.264 .mp4 on stop (needs ffmpeg; without it the raw .mjpeg and
    .times are kept and status says why).
    stop releases the session. The mirror sends no input of its own; only a control page does.
    Refuses a device whose TLS leaf is unpinned or does not match its pin."""
    remember_tool_loop()
    if action == "status":
        return await asyncio.to_thread(status, None if device == amt_tools.DEFAULT_DEVICE else device)
    if action == "stop":
        async with amt_tools._session_lock(device):
            return await asyncio.to_thread(stop, device)
    if action == "record_stop":
        return await asyncio.to_thread(record, device, False)
    if action == "record_start":
        amt_tools._require_confirmed(confirmed, "starts recording the live console view to a file on "
                                                "the server")
        return await asyncio.to_thread(record, device, True, directory)
    amt_tools._require_confirmed(confirmed, f"opens {device}'s KVM session and serves its live screen "
                                            f"at http://{bind}:{port}/m/<token>/ to anyone holding the "
                                            "link until stop; the control link also takes keyboard "
                                            "and mouse input")
    async with amt_tools._session_lock(device):
        return await asyncio.to_thread(start, device, bind, port, fps, quality, record_on_start)


MIRROR_TOOL_SPECS = (
    (amt_mirror_link, "amt_mirror_link", "AMT Display Mirror", {"destructiveHint": False}),
)
