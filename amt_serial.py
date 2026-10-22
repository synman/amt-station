"""Live serial terminal: one AMT Serial-over-LAN session per device, fanned out to browser viewers.

``amt_serial_link`` opens the device's SOL session once and keeps it. A reader thread pumps the
session and appends everything the host prints to a bounded scrollback buffer; every viewer of a
small page served by the mirror's HTTP server (``/s/<token>/``) gets that buffer and then the live
stream as server-sent events (``events``). The page renders it with the vendored xterm.js. Each
terminal has two tokens, as the mirror does: the view token serves a watch-only page; the control
token's page adds Take control, whose keystrokes reach the host through ``input``. While a
terminal is live, ``amt_sol`` does not open a second session: ``shared_terminal`` hands it this
one, so the operator watches exactly what the agent types and reads. Every socket operation is
serialized on one lock, because a TLS socket is not safe for concurrent use. Recording writes an
asciinema v2 ``.cast`` file (timed output, replayable with ``asciinema play``) to the mirror's
recording folder.

Viewers need a per-terminal token in the URL; nothing is served without it, and ``input``
answers only the control token. Nothing is ever printed to stdout (in stdio mode stdout is the
MCP channel). The agent never types a credential here (``amt_sol`` forbids it by contract). What
the operator types on the control page, a login password included, crosses the page's plain HTTP,
so bind to 127.0.0.1 or a trusted LAN only.
"""
from __future__ import annotations

import asyncio
import base64
import codecs
import hmac
import json
import re
import secrets
import socket
import threading
import urllib.parse
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, StrictBool

import amt_handoff
import amt_redir
import amt_registry
import amt_tools
import amt_vault
import amt_wsman

SCROLLBACK_BYTES = 256 * 1024      # kept per terminal; a viewer joining later gets this much
PUMP_SECONDS = 0.05                # how long the reader holds the socket lock per read
EVENT_WAIT_SECONDS = 15.0          # an idle event stream sends a comment this often
MAX_INPUT_BYTES = 4096             # one POST input body's data, UTF-8
SEND_TIMEOUT_SECONDS = 10.0        # a send's socket timeout; the reader leaves a 50 ms one behind
DEFAULT_COLS, DEFAULT_ROWS = 120, 36
VENDOR = Path(__file__).resolve().parent / "vendor" / "xterm"
ASSETS = {"xterm.js": ("xterm.js", "text/javascript; charset=utf-8"),
          "xterm.css": ("xterm.css", "text/css; charset=utf-8"),
          "addon-fit.js": ("addon-fit.js", "text/javascript; charset=utf-8")}
ROUTES = ("", "events", "status.json", *ASSETS)    # GET, all under /s/<token>/
POST_ROUTES = ("input", "record")
CONTROL_ROUTES = ("input",)                        # control token only
SerialAction = Literal["start", "stop", "status", "record_start", "record_stop"]


class Terminal:
    def __init__(self, device: str, session):
        self.device, self.session = device, session
        self.token = secrets.token_urlsafe(24)            # watch only
        self.control_token = secrets.token_urlsafe(24)    # watch plus keyboard
        self.io = threading.Lock()                        # every socket call
        self.cond = threading.Condition()                 # buffer changes
        self.stop = threading.Event()
        self.buf = bytearray()
        self.base = 0          # absolute stream offset of buf[0]
        self.total = 0         # absolute offset one past the last byte received
        self.sent = 0          # bytes sent to the host, operator and agent together
        self.started_at = time.time()
        self.last_output: float | None = None
        self.last_input: float | None = None
        self.error: str | None = None
        self.viewers = 0
        self.in_flight = amt_tools.InFlight()    # agent tool calls sharing this session
        self.recording: dict[str, Any] | None = None
        self.last_recording: dict[str, Any] | None = None
        self.rec_lock = threading.Lock()
        self.thread: threading.Thread | None = None

    def alive(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def run(self) -> None:
        try:
            while not self.stop.is_set():
                with self.io:
                    self.session.pump_once(time.time() + PUMP_SECONDS)
                    if time.time() - self.session.last_keepalive >= amt_redir.SOL_KEEPALIVE_SECONDS:
                        self.session.send(bytes([0x2B, 0, 0, 0]) + self.session.seq())
                        self.session.last_keepalive = time.time()
                    data = bytes(self.session.rx)
                    self.session.rx.clear()
                if data:
                    self._append(data)
                else:          # step outside the lock so waiting input gets the socket
                    self.stop.wait(0.002)
        except Exception as ex:   # noqa: BLE001 - reported by status; the engine never puts a secret in one
            self.error = f"{type(ex).__name__}:{ex}"
        finally:
            with self.io:
                self.session.close()
            self.record_stop()
            with self.cond:
                self.cond.notify_all()

    def _append(self, data: bytes) -> None:
        with self.cond:
            self.buf += data
            self.total += len(data)
            self.last_output = time.time()
            extra = len(self.buf) - SCROLLBACK_BYTES
            if extra > 0:
                del self.buf[:extra]
                self.base += extra
            self.cond.notify_all()
        self._record(data)

    def send(self, data: bytes) -> int:
        """Send bytes to the host's serial console under the socket lock."""
        with self.io:
            if not self.alive() or getattr(self.session, "s", True) is None:
                raise ValueError("terminal_not_live")
            sock = getattr(self.session, "s", None)
            if sock is not None:
                sock.settimeout(SEND_TIMEOUT_SECONDS)
            self.session.send_text(data)
        self.sent += len(data)
        self.last_input = time.time()
        return len(data)

    def read_since(self, offset: int, wait: float) -> tuple[bytes, int, bool]:
        """Bytes from absolute ``offset`` on, waiting up to ``wait`` seconds for any. Returns
        ``(data, next_offset, gap)``; ``gap`` is True when scrollback no longer reaches
        ``offset`` (the data then starts at the oldest byte kept)."""
        with self.cond:
            offset = max(0, min(offset, self.total))
            if offset == self.total and wait > 0 and self.alive():
                self.cond.wait(wait)
            gap = offset < self.base
            start = max(offset, self.base)
            data = bytes(self.buf[start - self.base:])
            return data, self.total, gap

    def collect(self, start: int, seconds: float, max_bytes: int) -> tuple[bytes, bool, str | None]:
        """What the host printed from ``start`` on, for ``seconds`` or until ``max_bytes``:
        ``amt_sol``'s read window on a shared terminal. Returns ``(data, truncated, error)``;
        ``truncated`` is also True when scrollback overran the window, and ``error`` names a
        session that ended before the window did."""
        end, offset, out, lost = time.time() + seconds, start, bytearray(), False
        while time.time() < end and len(out) <= max_bytes:
            if not self.alive():
                data, offset, gap = self.read_since(offset, 0)
                out += data
                return bytes(out[:max_bytes]), lost or gap or len(out) > max_bytes, "terminal_ended_during_read"
            data, offset, gap = self.read_since(offset, min(0.25, max(0.0, end - time.time())))
            out += data
            lost = lost or gap
        return bytes(out[:max_bytes]), lost or len(out) > max_bytes, None

    # -- recording ------------------------------------------------------------------------

    def record_start(self, directory: Path) -> dict[str, Any]:
        with self.rec_lock:
            if self.recording is not None:
                return self._rec_info(self.recording)
            directory.mkdir(parents=True, exist_ok=True)
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
            path = directory / f"{self.device}-serial-{stamp}.cast"
            fh = path.open("x", encoding="utf-8")   # never overwrite an earlier recording
            fh.write(json.dumps({"version": 2, "width": DEFAULT_COLS, "height": DEFAULT_ROWS,
                                 "timestamp": int(time.time()), "title": f"{self.device} serial"}) + "\n")
            fh.flush()
            self.recording = {"path": str(path), "fh": fh, "t0": time.time(), "bytes": 0,
                              "decoder": codecs.getincrementaldecoder("utf-8")("replace")}
            return self._rec_info(self.recording)

    def record_stop(self) -> dict[str, Any] | None:
        with self.rec_lock:
            return self._end_recording()

    def _end_recording(self, error: str | None = None) -> dict[str, Any] | None:
        """Close the recording (``rec_lock`` held). A write error ends it and is reported; it
        never reaches the reader, so a full disk or a lost NAS mount keeps the console up."""
        rec, self.recording = self.recording, None
        if rec is None:
            return None
        try:
            tail = rec["decoder"].decode(b"", final=True)
            if tail and error is None:
                rec["fh"].write(json.dumps([round(time.time() - rec["t0"], 6), "o", tail]) + "\n")
        except OSError as ex:
            error = error or f"{type(ex).__name__}: {ex}"
        finally:
            try:
                rec["fh"].close()
            except OSError as ex:
                error = error or f"{type(ex).__name__}: {ex}"
        self.last_recording = {**self._rec_info(rec, ended=True), **({"error": error} if error else {})}
        return self.last_recording

    def _record(self, data: bytes) -> None:
        with self.rec_lock:
            rec = self.recording
            if rec is None:
                return
            try:
                text = rec["decoder"].decode(data)
                if text:
                    rec["fh"].write(json.dumps([round(time.time() - rec["t0"], 6), "o", text]) + "\n")
                    rec["fh"].flush()
                rec["bytes"] += len(data)
            except OSError as ex:
                self._end_recording(f"{type(ex).__name__}: {ex}")

    @staticmethod
    def _rec_info(rec: dict[str, Any], ended: bool = False) -> dict[str, Any]:
        info = {"path": rec["path"], "bytes": rec["bytes"], "seconds": round(time.time() - rec["t0"], 1),
                "format": "asciinema v2 (.cast)", **({"ended": True} if ended else {})}
        if ended:   # the finished cast, offered once over HTTP; a failed offer keeps the path
            try:
                info.update(amt_handoff.offer(rec["path"]))
            except OSError as ex:
                info["url_error"] = f"{type(ex).__name__}: {ex}"[:200]
        return info

    def info(self) -> dict[str, Any]:
        import amt_mirror   # imported here: amt_mirror imports this module lazily too
        now = time.time()
        with self.rec_lock:
            rec = self._rec_info(self.recording) if self.recording else None
        return {"device": self.device, "live": self.alive(), "error": self.error,
                "bytes_received": self.total, "bytes_sent": self.sent, "scrollback_bytes": len(self.buf),
                "viewers": self.viewers, "in_flight": self.in_flight.snapshot(),
                "uptime_s": round(now - self.started_at, 1),
                "last_output_age_s": round(now - self.last_output, 1) if self.last_output else None,
                "last_input_age_s": round(now - self.last_input, 1) if self.last_input else None,
                "recording": rec,
                "recording_dir": str(amt_mirror.recording_dir()), "hostname": socket.gethostname(),
                "last_recording": self.last_recording}


_TERMS: dict[str, Terminal] = {}
_LOCK = threading.Lock()


def live() -> bool:
    """Whether any terminal is live or still starting; the shared HTTP server stays up while
    one is. A terminal whose session died stays listed for status but no longer holds it."""
    with _LOCK:
        return any(t.thread is None or t.alive() for t in _TERMS.values())


def shared_terminal(device_key: str) -> Terminal | None:
    """The live terminal for this device, or None (``amt_sol`` opens its own session)."""
    with _LOCK:
        term = _TERMS.get(device_key)
    return term if term is not None and term.alive() else None


def by_token(token: str) -> tuple[Terminal | None, bool]:
    """The terminal a token opens, and whether it is that terminal's control token."""
    with _LOCK:
        terms = list(_TERMS.values())
    found, control = None, False
    for t in terms:            # compare against every token so timing reveals nothing
        if hmac.compare_digest(t.token.encode(), token.encode()):
            found = t
        if hmac.compare_digest(t.control_token.encode(), token.encode()):
            found, control = t, True
    return found, control


# -- HTTP (served by amt_mirror's server, which routes /s/<token>/... here) ----------------

def handle_get(handler, term: Terminal, control: bool, rest: str) -> None:
    if rest not in ROUTES or (rest in CONTROL_ROUTES and not control):
        return handler._send(404, b"not found", "text/plain")
    if rest == "" and not handler.path.split("?")[0].endswith("/"):
        handler.send_response(301)
        handler.send_header("Location", handler._slashed())
        handler.end_headers()
        return None
    if rest == "":
        import amt_mirror
        page = amt_mirror.render_page(PAGE, term.device, control, handler._embed())
        return handler._send(200, page.encode(), "text/html; charset=utf-8")
    if rest in ASSETS:
        name, ctype = ASSETS[rest]
        return handler._send(200, (VENDOR / name).read_bytes(), ctype)
    if rest == "status.json":
        return handler._send(200, json.dumps(term.info()).encode(), "application/json")
    return _events(handler, term)


def handle_post(handler, term: Terminal, control: bool, rest: str) -> None:
    import amt_mirror
    if rest not in POST_ROUTES or (rest in CONTROL_ROUTES and not control):
        return handler._send(404, b"not found", "text/plain")
    if rest == "record":
        if handler._embed():   # recording is a tool action (record_start needs confirmed): an embedded viewer has no Record
            return handler._send(403, b"embed_mode: recording is amt_serial_link record_start / record_stop, not a viewer route",
                                 "text/plain")
        query = urllib.parse.parse_qs(urllib.parse.urlsplit(handler.path).query)
        on = query.get("on") == ["1"]
        out = term.record_start(amt_mirror.recording_dir()) if on else term.record_stop()
        return handler._send(200, json.dumps(out).encode(), "application/json")
    body, refused = handler._body()
    if refused:
        return handler._send(*refused, "text/plain")
    data = body.get("data") if isinstance(body, dict) else None
    if not isinstance(data, str) or not data:
        return handler._send(400, b'input_bad_body: expected {"data": "<text>"}', "text/plain")
    raw = data.encode("utf-8")
    if len(raw) > MAX_INPUT_BYTES:
        return handler._send(413, b"input_too_long: at most 4096 bytes per request", "text/plain")
    if not term.alive():
        return handler._send(409, b"terminal_not_live", "text/plain")
    try:
        sent = term.send(raw)
    except ValueError as ex:
        return handler._send(409, str(ex).encode(), "text/plain")
    except Exception as ex:   # noqa: BLE001 - a dead socket; the engine never puts a secret in one
        return handler._send(502, type(ex).__name__.encode(), "text/plain")
    return handler._send(200, json.dumps({"sent": sent}).encode(), "application/json")


def _events(handler, term: Terminal) -> None:
    """Server-sent events: the scrollback, then live output. Each ``out`` event carries
    ``{"d": <base64 bytes>, "gap": bool}`` and its ``id`` is the next stream offset, so an
    EventSource reconnect (Last-Event-ID) resumes where it left off."""
    try:
        offset = int(handler.headers.get("Last-Event-ID") or 0)
    except ValueError:
        offset = 0
    handler.send_response(200)
    handler.send_header("Content-Type", "text/event-stream")
    handler.send_header("Cache-Control", "no-store")
    handler.send_header("X-Accel-Buffering", "no")
    handler.end_headers()
    with _LOCK:
        term.viewers += 1
    try:
        handler.wfile.write(b"retry: 2000\n\n")
        handler.wfile.flush()
        while True:
            data, nxt, gap = term.read_since(offset, EVENT_WAIT_SECONDS)
            if data or gap:
                payload = json.dumps({"d": base64.b64encode(data).decode(), "gap": gap})
                handler.wfile.write(f"id: {nxt}\nevent: out\ndata: {payload}\n\n".encode())
                offset = nxt
            elif term.alive():
                handler.wfile.write(b": idle\n\n")
            if not term.alive() and offset >= term.total:
                handler.wfile.write(b"event: end\ndata: {}\n\n")
                handler.wfile.flush()
                break
            handler.wfile.flush()
    except (BrokenPipeError, ConnectionResetError, OSError):
        pass   # the viewer went away
    finally:
        with _LOCK:
            term.viewers -= 1


# -- actions --------------------------------------------------------------------------------

def start(device: str = amt_tools.DEFAULT_DEVICE, bind: str | None = None, port: int | None = None,
          record: bool = False) -> dict[str, Any]:
    import amt_mirror
    bind = amt_mirror.DEFAULT_BIND if bind is None else bind
    port = amt_mirror.DEFAULT_PORT if port is None else port
    if not 0 <= port <= 65535:
        raise ValueError("serial_bad_settings: port 0-65535")
    dev = amt_registry.get_device(device)
    with _LOCK:
        existing = _TERMS.get(dev.key)
    if existing is not None and existing.alive():
        out = status(dev.key)
        out["note"] = "already live; returning the existing link"
        return out
    amt_wsman.require_pin(dev)
    session = amt_redir.pinned(amt_redir.SolSession, dev, amt_vault.get_secret(dev.amt_vault_key))
    try:
        session.open_session()
    except Exception:
        session.close()
        raise
    term = Terminal(dev.key, session)
    with _LOCK:   # registered (starting) first, so a concurrent mirror stop keeps the server up
        _TERMS[dev.key] = term
    try:
        bind, port = amt_mirror._ensure_server(bind, port)
        if record:
            term.record_start(amt_mirror.recording_dir())
    except Exception:
        with _LOCK:
            _TERMS.pop(dev.key, None)
        session.close()
        amt_mirror._stop_server_if_idle()
        raise
    term.thread = threading.Thread(target=term.run, name=f"amt-serial-{dev.key}", daemon=True)
    term.thread.start()
    return {**status(dev.key), "note": "urls are watch only; control_urls add Take control for the "
                                       "keyboard. amt_sol shares this session, so the viewer sees "
                                       "what the agent types and reads"}


def stop(device: str = amt_tools.DEFAULT_DEVICE) -> dict[str, Any]:
    import amt_mirror
    dev = amt_registry.get_device(device)
    with _LOCK:
        term = _TERMS.pop(dev.key, None)
    if term is None:
        return {"device": dev.key, "stopped": False, "note": "no terminal was live"}
    term.stop.set()
    if term.thread is not None:
        term.thread.join(timeout=15)
    amt_mirror._stop_server_if_idle()
    return {"device": dev.key, "stopped": True, "session_released": not term.alive(),
            "bytes_received": term.total, "bytes_sent": term.sent, "error": term.error,
            "recording": term.last_recording}


def status(device: str | None = None) -> dict[str, Any]:
    import amt_mirror
    with _LOCK:
        terms = {k: t for k, t in _TERMS.items() if device in (None, k)}
    with amt_mirror._LOCK:
        bind, port = amt_mirror._SERVER.get("bind"), amt_mirror._SERVER.get("port")
    out = []
    for key, t in terms.items():
        dev = amt_registry.get_device(key)
        out.append({**t.info(),
                    "urls": amt_mirror._urls(bind, port, t.token, dev.amt_ip, "s") if port else [],
                    "control_urls": amt_mirror._urls(bind, port, t.control_token, dev.amt_ip, "s")
                    if port else []})
    if device is not None:
        return out[0] if out else {"device": device, "live": False}
    return {"terminals": out, "server": {"bind": bind, "port": port} if port else None,
            "recording_dir": str(amt_mirror.recording_dir())}


def record(device: str, on: bool, directory: str | None = None) -> dict[str, Any]:
    import amt_mirror
    dev = amt_registry.get_device(device)
    with _LOCK:
        term = _TERMS.get(dev.key)
    if term is None or not term.alive():
        raise ValueError("terminal_not_live: start it with amt_serial_link action=start")
    if on:
        target = amt_mirror.set_recording_dir(directory) if directory else amt_mirror.recording_dir()
        return {"device": dev.key, "recording": term.record_start(target)}
    return {"device": dev.key, "recording": term.record_stop()}


# -- serial console logon / logoff (amt_remote_logon / amt_remote_logoff, console="serial") ----
#
# The serial getty is judged by the same prompt classifier as the KVM text console
# (``amt_tools.console_prompt``), fed the serial output's text lines instead of OCR fragments.
# The credential is read from the server's own vault by the caller and typed here; it is never
# returned, logged or echoed (getty does not echo a password). ONE attempt, as on KVM.

SERIAL_READ_SECONDS = 2.0      # one read window
SERIAL_PROMPT_READS = 3        # windows to wait for getty's Password: (or login:) prompt
SERIAL_SUBMIT_READS = 4        # PAM holds a wrong password ~3 s before Login incorrect
SERIAL_CONTEXT_BYTES = 4096    # how much of a live terminal's scrollback states where it is
SERIAL_MAX_BYTES = 16384
_ESCAPES = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[@-Z\\-_])")


class _SerialConsole:
    """One serial conversation: the live terminal when one runs (its viewer watches it), else a
    pinned SOL session of its own, closed by ``close``. ``text`` is all output read so far."""

    def __init__(self, dev: amt_registry.Device, amt_password: str):
        self.term = shared_terminal(dev.key)
        self.session, self.text = None, ""
        if self.term is not None:
            self.term.in_flight.begin()
            self.offset = max(0, self.term.total - SERIAL_CONTEXT_BYTES)
        else:
            amt_wsman.require_pin(dev)
            self.session = amt_redir.pinned(amt_redir.SolSession, dev, amt_password)
            self.session.open_session()

    def read(self, seconds: float | None = None) -> None:
        seconds = SERIAL_READ_SECONDS if seconds is None else seconds
        if self.term is None:
            data, _truncated = self.session.read_window(seconds, SERIAL_MAX_BYTES)
        else:
            end, chunks = time.time() + seconds, []
            while time.time() < end:
                data, self.offset, _gap = self.term.read_since(self.offset, min(0.25, max(0.0, end - time.time())))
                chunks.append(data)
            data = b"".join(chunks)
        self.text += data.decode("utf-8", errors="replace")

    def send(self, text: str) -> None:
        raw = text.encode("ascii")
        if self.term is not None:
            self.term.send(raw)
        else:
            self.session.send_text(raw)

    def frags(self) -> list:
        lines = _ESCAPES.sub("", self.text).replace("\r", "").split("\n")
        while lines and not lines[-1].strip():
            lines.pop()
        return [amt_tools.Fragment(line, 0.5, float(i)) for i, line in enumerate(lines[-60:]) if line.strip()]

    def prompt(self) -> str | None:
        return amt_tools.console_prompt(self.frags())

    def close(self) -> None:
        if self.term is not None:
            self.term.in_flight.end()
        if self.session is not None:
            self.session.close()


def _where(con: _SerialConsole) -> tuple[str | None, bool]:
    """The prompt the serial console waits at. Reads first, sending nothing; only when nothing
    readable came back is one Enter sent to make getty or the shell print its prompt. A
    ``Password:`` prompt on that first read is never answered. Returns (prompt, enter_sent)."""
    con.read()
    prompt = con.prompt()
    if prompt is not None or con.frags():
        return prompt, False
    con.send("\r")
    con.read()
    return con.prompt(), True


def console_logon(dev: amt_registry.Device, amt_password: str, user: str, password: str) -> dict[str, Any]:
    """Log into the host's serial getty: the account name and Enter at ``login:``, then the
    password and Enter only once ``Password:`` is read. A shell prompt is the no-op success;
    any other last line aborts with no credential sent. One attempt, never retried."""
    con = _SerialConsole(dev, amt_password)
    base = {"device": dev.key, "console": "serial", "shared_terminal": con.term is not None}
    try:
        prompt, enter_sent = _where(con)
        base["enter_sent_to_find_prompt"] = enter_sent
        if prompt == amt_tools.PROMPT_COMMAND:
            return {**base, "aborted": False, "already_logged_in": True, "logged_in": True,
                    "typed_nothing": True, "console_prompt": prompt}
        if prompt != amt_tools.PROMPT_LOGIN:
            return {**base, "aborted": True, "reason": "console_not_at_login_prompt",
                    "typed_nothing": True, "console_prompt": prompt}
        con.send(amt_tools._account_name(user) + "\r")
        for _ in range(SERIAL_PROMPT_READS):
            con.read()
            if con.prompt() == amt_tools.PROMPT_PASSWORD:
                break
        else:
            return {**base, "aborted": True, "reason": "password_prompt_not_identified",
                    "typed_nothing": False, "account_typed": True, "password_typed": False,
                    "console_prompt": con.prompt()}
        con.send(password + "\r")
        password = ""
        for _ in range(SERIAL_SUBMIT_READS):
            con.read()
            frags = con.frags()
            if (amt_tools.console_login_incorrect(frags)
                    or amt_tools.console_prompt(frags) in (amt_tools.PROMPT_COMMAND, amt_tools.PROMPT_LOGIN)):
                break
        frags = con.frags()
        prompt, incorrect = amt_tools.console_prompt(frags), amt_tools.console_login_incorrect(frags)
        logged_in = False if incorrect or prompt == amt_tools.PROMPT_LOGIN else (
            True if prompt == amt_tools.PROMPT_COMMAND else None)
        return {**base, "aborted": False, "console_prompt": prompt, "login_incorrect": incorrect,
                "logged_in": logged_in,
                "logged_in_basis": "classifier: the serial console's last line after the password"}
    finally:
        con.close()


def console_logoff(dev: amt_registry.Device, amt_password: str) -> dict[str, Any]:
    """Log out of the host's serial console from a shell prompt: ``exit`` and Enter, then wait
    for getty's ``login:``. Any other last line aborts with nothing sent."""
    con = _SerialConsole(dev, amt_password)
    base = {"device": dev.key, "console": "serial", "shared_terminal": con.term is not None}
    try:
        prompt, enter_sent = _where(con)
        base["enter_sent_to_find_prompt"] = enter_sent
        if prompt != amt_tools.PROMPT_COMMAND:
            return {**base, "aborted": True, "reason": "console_not_at_shell_prompt",
                    "typed_nothing": True, "console_prompt": prompt}
        con.send("exit\r")
        for _ in range(SERIAL_PROMPT_READS):
            con.read()
            if con.prompt() == amt_tools.PROMPT_LOGIN:
                break
        prompt = con.prompt()
        return {**base, "aborted": False, "logoff_submitted": True, "console_prompt": prompt,
                "logged_off": True if prompt == amt_tools.PROMPT_LOGIN else (
                    False if prompt == amt_tools.PROMPT_COMMAND else None),
                "logged_off_basis": "classifier: the serial console's last line after exit"}
    finally:
        con.close()


# -- the tool -------------------------------------------------------------------------------

async def amt_serial_link(
    action: Annotated[SerialAction, Field(
        description="start opens the device's Serial-over-LAN session and returns viewer URLs; stop "
                    "ends it; status lists live terminals; record_start / record_stop save the "
                    "serial stream to an asciinema .cast file.")] = "status",
    device: Annotated[str, Field(
        description=f"Registered device key; defaults to {amt_tools.DEFAULT_DEVICE}.")] = amt_tools.DEFAULT_DEVICE,
    bind: Annotated[str, Field(
        description="start: address the page listens on, shared with the display mirror. "
                    "127.0.0.1 (default) is this machine only; 0.0.0.0 lets the LAN watch.")] = "127.0.0.1",
    port: Annotated[int, Field(
        description="start: page port, shared with the display mirror (default 8766; 0 picks a "
                    "free one).")] = 8766,
    record_on_start: Annotated[bool, Field(description="start: begin recording at once.")] = False,
    directory: Annotated[str | None, Field(
        description="record_start: folder for recordings (a NAS mount works); kept for later "
                    "recordings. Default ~/amt-recordings, the mirror's folder.")] = None,
    confirmed: Annotated[StrictBool, Field(
        description="start and record_start need the JSON boolean true; false refuses and starts "
                    "nothing. stop, record_stop and status need none.")] = False,
) -> dict:
    """Live serial terminal of a host's Serial-over-LAN console for the operator, MeshCommander's
    Serial-over-LAN terminal. start opens the device's SOL session once and serves a terminal page
    at http://<bind>:<port>/s/<token>/ (xterm.js, the scrollback then the live stream, status, a
    Record button; with ?embed=1, for the management console's frame, no Record button: use
    record_start / record_stop); the token is the only access key, so share the URL only with viewers.
    control_urls carry a second token whose page adds Take control: the holder's keyboard then
    types into the host's serial console. While a terminal is live, amt_sol sends and reads through
    it instead of opening its own session, so the viewer watches the agent work. Recordings are
    asciinema v2 .cast files. stop releases the session. The terminal sends nothing of its own
    except AMT's keep-alive; only a control page or amt_sol types. The host needs a serial getty
    (or GRUB and kernel console) on the AMT SOL port to show anything. Refuses a device whose TLS
    leaf is unpinned or does not match its pin."""
    import amt_mirror   # imported here: amt_mirror imports this module lazily too
    amt_mirror.remember_tool_loop()
    if action == "status":
        return await asyncio.to_thread(status, None if device == amt_tools.DEFAULT_DEVICE else device)
    if action == "stop":
        async with amt_tools._session_lock(device):
            return await asyncio.to_thread(stop, device)
    if action == "record_stop":
        return await asyncio.to_thread(record, device, False)
    if action == "record_start":
        amt_tools._require_confirmed(confirmed, "starts recording the live serial stream to a file on "
                                                "the server")
        return await asyncio.to_thread(record, device, True, directory)
    amt_tools._require_confirmed(confirmed, f"opens {device}'s Serial-over-LAN session and serves its "
                                            f"live serial console at http://{bind}:{port}/s/<token>/ "
                                            "to anyone holding the link until stop; the control link "
                                            "also types into the host")
    async with amt_tools._session_lock(device):
        return await asyncio.to_thread(start, device, bind, port, record_on_start)


SERIAL_TOOL_SPECS = (
    (amt_serial_link, "amt_serial_link", "AMT Serial Terminal", {"destructiveHint": False}),
)


# The page, styled to read as one product with the mirror's (same tokens, pill, toolbar, keycaps,
# REC badge, toasts, footer). A raw string: the JS escapes (\x03, \x1b[A, \r) reach the browser as
# written. The contract it must keep: load xterm.css, xterm.js and addon-fit.js from this folder
# and nothing from the internet; keep the literal `const CONTROL=__CONTROL__;`; read output from
# EventSource('events') (event "out", data {"d": base64, "gap": bool}, decoded to bytes; event
# "end"); poll status.json; when __CONTROL__ is true and Take control is on, POST input
# {"data": "<text>"} for xterm onData, at most 4096 UTF-8 bytes per request; POST record?on=1 or
# record to toggle recording (the standalone page only: an embed=1 request is refused). Server data only ever lands in textContent, never innerHTML.
PAGE = r"""<!doctype html><html lang=en><head><meta charset=utf-8>
<meta name=viewport content="width=device-width,initial-scale=1"><title>AMT serial</title>
<link rel=stylesheet href="xterm.css">
<style>
:root{color-scheme:light dark;--bg:#0b0d12;--fg:#e8eaf0;--mute:#8b93a3;--line:#262c37;--chip:#161a22;--chip2:#1f2531;--rec:#ef4444;--ok:#22c55e;--warn:#f59e0b;--acc:#60a5fa;--stage:#000;--term:#07090d;--recbg:rgba(239,68,68,.12);--warnbg:rgba(245,158,11,.12);--shadow:0 10px 30px rgba(0,0,0,.45)}
@media (prefers-color-scheme:light){:root{--bg:#f4f5f7;--fg:#14171c;--mute:#5b6372;--line:#d8dce3;--chip:#fff;--chip2:#eceff3;--acc:#2563eb;--stage:#15181e;--shadow:0 10px 30px rgba(0,0,0,.25)}}
*{box-sizing:border-box}
[hidden]{display:none!important}
html{height:100%}
html,body{margin:0;background:var(--bg);color:var(--fg)}
body{font:14px/1.45 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;-webkit-font-smoothing:antialiased;height:100vh;height:100dvh;display:flex;flex-direction:column;overflow:auto;overflow-x:hidden}
.mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:12.5px}
.num{font-variant-numeric:tabular-nums}
.mute{color:var(--mute)}
.top,.bar,.msg,.stage,footer{padding-left:16px;padding-right:16px;flex:none}
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
.act{display:inline-flex;align-items:center;gap:6px;font-size:11px;font-weight:700;letter-spacing:.08em;text-transform:uppercase;color:var(--acc)}
.act i{width:7px;height:7px;border-radius:50%;background:currentColor;animation:pulse 1.2s ease-in-out infinite}
.bar{display:flex;flex-wrap:wrap;gap:10px 22px;padding-top:6px;padding-bottom:10px;border-bottom:1px solid var(--line)}
.grp{display:flex;flex-wrap:wrap;gap:6px;align-items:center;min-width:0}
.lbl{font-size:10.5px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;color:var(--mute);margin-right:4px;user-select:none}
button{font:inherit;line-height:1.2;color:var(--fg);background:var(--chip);border:1px solid var(--line);border-radius:7px;padding:6px 12px;cursor:pointer;display:inline-flex;align-items:center;gap:7px;white-space:nowrap}
button:hover:not(:disabled){background:var(--chip2)}
button:focus-visible{outline:2px solid var(--acc);outline-offset:1px}
button:disabled{opacity:.38;cursor:default}
button.primary{border-color:var(--acc);color:var(--acc)}
button.on{background:var(--rec);border-color:var(--rec);color:#fff}
button.on:hover:not(:disabled){background:#dc2626}
button.sm{padding:3px 9px;font-size:12px;border-radius:6px}
button.key{font:600 12px/1 ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;padding:8px 9px;border-bottom-width:2px;border-radius:6px}
button.key:active:not(:disabled){transform:translateY(1px);border-bottom-width:1px}
.fsz{min-width:3.4em;text-align:center;color:var(--mute)}
.cluster{display:inline-flex;gap:6px;flex:none}
.rdot{width:8px;height:8px;border-radius:50%;background:var(--rec);flex:none}
button.on .rdot{background:#fff;animation:pulse 1.2s ease-in-out infinite}
.rdot.live{animation:pulse 1.2s ease-in-out infinite}
.alert{margin:10px 16px 0;padding:8px 12px;border-radius:8px;border:1px solid rgba(239,68,68,.45);background:var(--recbg);overflow-wrap:anywhere;font-size:13px;flex:none}
.alert.warn{border-color:rgba(245,158,11,.45);background:var(--warnbg)}
.msg{display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;padding-top:9px;padding-bottom:9px;min-height:40px;min-width:0;overflow-wrap:anywhere}
.msg strong{font-weight:600}
.path{display:inline-block;max-width:100%;background:var(--chip);border:1px solid var(--line);border-radius:5px;padding:2px 7px;overflow-wrap:anywhere;color:var(--fg)}
.host{font-size:11px;font-weight:600;letter-spacing:.04em;border-radius:999px;padding:1px 8px;background:var(--chip2);color:var(--mute);white-space:nowrap}
.msg input{font:inherit;color:var(--fg);background:var(--chip);border:1px solid var(--line);border-radius:6px;padding:3px 7px;width:min(100%,42em)}
.stage{background:var(--stage);padding-top:14px;padding-bottom:14px;flex:1 1 auto;min-height:260px;display:flex;flex-direction:column;min-width:0}
.note{font-size:12px;color:#aab1bf;background:rgba(255,255,255,.07);border:1px solid rgba(255,255,255,.08);border-bottom:0;border-radius:6px 6px 0 0;padding:5px 10px;flex:none}
.wrap{position:relative;flex:1 1 auto;min-height:0;display:flex;flex-direction:column;background:var(--term);border:1px solid #2a2f38;border-radius:6px;box-shadow:var(--shadow);overflow:hidden;outline:none}
.note+.wrap{border-radius:0 0 6px 6px}
.wrap.live{outline:2px solid var(--rec)}
.wrap.paused{outline:2px dashed var(--mute)}
.wrap.ended{opacity:.78}
.strip{display:none;font-size:12px;font-weight:600;letter-spacing:.04em;padding:6px 10px;color:#fff;background:var(--rec);flex:none}
.strip.paused{background:#1f2531;color:#e8eaf0;font-weight:500}
.wrap.live .strip,.wrap.paused .strip{display:block}
#term{flex:1 1 auto;min-height:0;padding:8px 2px 8px 10px}
.badge{position:absolute;right:22px;bottom:12px;display:inline-flex;align-items:center;gap:6px;background:var(--rec);color:#fff;font:700 11px/1 ui-monospace,SFMono-Regular,Menlo,monospace;letter-spacing:.06em;padding:5px 8px;border-radius:5px;pointer-events:none;box-shadow:0 2px 8px rgba(0,0,0,.4)}
.badge i{width:7px;height:7px;border-radius:50%;background:#fff;animation:pulse 1.2s ease-in-out infinite}
footer{color:var(--mute);font-size:12px;padding-top:10px;padding-bottom:16px;display:flex;flex-wrap:wrap;align-items:center;gap:4px 8px;overflow-wrap:anywhere}
footer .path{font-size:11.5px;padding:1px 6px}
.toast{position:fixed;left:50%;bottom:18px;transform:translate(-50%,8px);max-width:calc(100% - 32px);background:var(--chip2);border:1px solid var(--line);border-radius:8px;padding:8px 12px;font-size:13px;box-shadow:var(--shadow);pointer-events:none;opacity:0;transition:opacity .18s,transform .18s;overflow-wrap:anywhere;z-index:9}
.toast.show{opacity:1;transform:translate(-50%,0)}
.toast.err{border-color:var(--rec)}
@keyframes pulse{50%{opacity:.3}}
@media (prefers-reduced-motion:reduce){*{animation:none!important;transition:none!important}}
@media (max-width:640px){.stage{min-height:52vh;min-height:52dvh}}
@media (max-width:480px){.bar{gap:10px 16px}.right{margin-left:0;width:100%}}
</style></head><body>
<header class=top><span class=pill id=pill><i></i><span id=pillt>Connecting</span></span><h1 id=name>__DEVICE__</h1><span class="meta num" id=meta></span>
<span class=right><span class=act id=act hidden><i></i><span>typing</span></span><span class=tag id=tag hidden>view only</span><span class="mute num" id=vw></span></span></header>
<nav class=bar>
<!--standalone--><div class=grp><span class=lbl>Capture</span><button id=rec title="Start recording"><i class=rdot></i><span id=rect>Record</span></button><button id=dl title="Download what this terminal holds as a text file">Download .txt</button></div><!--/standalone-->
<div class=grp><span class=lbl>View</span><button id=fontm aria-label="Smaller text" title="Smaller text">A−</button><span class="mono num fsz" id=fsz></span><button id=fontp aria-label="Larger text" title="Larger text">A+</button><button id=copy title="Copy the selected text">Copy</button><button id=clr title="Clear this terminal's screen; the host is not touched">Clear</button></div>
<div class=grp id=cgrp hidden><span class=lbl>Control</span><button id=ctl class=primary aria-pressed=false>Take control</button>
<button class=key data-k=cc disabled title="Send Ctrl+C · interrupt">Ctrl+C</button><button class=key data-k=cd disabled title="Send Ctrl+D · end of input, logs a shell out">Ctrl+D</button><button class=key data-k=cz disabled title="Send Ctrl+Z · suspend">Ctrl+Z</button><button class=key data-k=cl disabled title="Send Ctrl+L · redraw the screen">Ctrl+L</button><button class=key data-k=esc disabled title="Send Escape">Esc</button><button class=key data-k=tab disabled title="Send Tab">Tab</button><span class=cluster><button class=key data-k=up disabled aria-label="Arrow up" title="Send arrow up">↑</button><button class=key data-k=down disabled aria-label="Arrow down" title="Send arrow down">↓</button><button class=key data-k=left disabled aria-label="Arrow left" title="Send arrow left">←</button><button class=key data-k=right disabled aria-label="Arrow right" title="Send arrow right">→</button></span></div>
</nav>
<div class=alert id=alert role=status aria-live=polite hidden></div>
<div class=msg id=msg></div>
<section class=stage id=stage><div class=note id=gap hidden>Earlier output was trimmed · the server keeps the last 256 KB of scrollback</div><div class=wrap id=wrap><div class=strip id=strip></div><div id=term role=region aria-label="serial console of __DEVICE__"></div><span class=badge id=badge hidden><i></i><span id=badget>REC</span></span></div></section>
<footer id=foot></footer>
<div class=toast id=toast role=status aria-live=polite></div>
<script src="xterm.js"></script><script src="addon-fit.js"></script>
<script>
const CONTROL=__CONTROL__;
const MAX=4096,KEYS={cc:'\x03',cd:'\x04',cz:'\x1a',cl:'\x0c',esc:'\x1b',tab:'\t',up:'\x1b[A',down:'\x1b[B',left:'\x1b[D',right:'\x1b[C'};
const $=id=>document.getElementById(id);
const pill=$('pill'),pillt=$('pillt'),nameEl=$('name'),meta=$('meta'),vw=$('vw'),act=$('act'),rec=$('rec'),rect=$('rect'),fontm=$('fontm'),fontp=$('fontp'),fsz=$('fsz'),copyB=$('copy'),clr=$('clr');
const alertEl=$('alert'),msg=$('msg'),gapEl=$('gap'),wrap=$('wrap'),strip=$('strip'),termEl=$('term'),badge=$('badge'),badget=$('badget'),foot=$('foot'),toastEl=$('toast'),ctl=$('ctl');
const DEV=nameEl.textContent,chips=[...document.querySelectorAll('.key')];
let S=null,HOST='',stream='connecting',offline=false,misses=0,controlling=false,recNow=null,recBusy=false,toastT=0,msgKey='',footKey='',recMeta=null,q='',busy=false,flushT=0,font=13;
const el=(tag,cls,text)=>{const e=document.createElement(tag);if(cls)e.className=cls;if(text!=null)e.textContent=text;return e};
const mmss=s=>{s=Math.max(0,Math.round(s||0));return String(Math.floor(s/60)).padStart(2,'0')+':'+String(s%60).padStart(2,'0')};
const hms=s=>{s=Math.max(0,Math.round(s||0));return s>=3600?Math.floor(s/3600)+':'+String(Math.floor(s%3600/60)).padStart(2,'0')+':'+String(s%60).padStart(2,'0'):mmss(s)};
const size=b=>b>=1048576?(b/1048576).toFixed(1)+' MB':b>=1024?Math.round(b/1024)+' KB':Math.round(b||0)+' B';
const css=n=>getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const stamp=()=>new Date().toISOString().slice(0,19).replace(/[-:]/g,'')+'Z';
const refocus=()=>{if(CONTROL&&controlling)term.focus()};
function toast(text,kind,ms){toastEl.textContent=text;toastEl.className='toast show'+(kind?' '+kind:'');clearTimeout(toastT);toastT=setTimeout(()=>toastEl.classList.remove('show'),ms||5000)}
function setPill(kind,text){pill.className='pill '+kind;pillt.textContent=text}
function pathNode(p){const c=el('code','mono path',p);c.title=p;return c}
function hostChip(){return el('span','host',HOST||'server')}
function copyBtn(p){if(navigator.clipboard&&window.isSecureContext){const b=el('button','sm','Copy path');
b.onclick=async()=>{try{await navigator.clipboard.writeText(p);b.textContent='Copied';toast('Path copied')}catch(e){b.textContent='Copy failed'}setTimeout(()=>{b.textContent='Copy path';refocus()},1500)};return b}
const i=el('input','mono');i.readOnly=true;i.value=p;i.title='select and copy';i.setAttribute('aria-label','recording path');i.onfocus=()=>i.select();return i}
function setMsg(key,nodes){if(key===msgKey)return;msgKey=key;msg.replaceChildren(...nodes)}
function showIdle(ended){setMsg(ended?'ended':'idle',[el('span','mute',ended?'The session has ended; the terminal keeps what it printed.'/*standalone*/+' Download .txt saves a copy.'/*/standalone*/:CONTROL?'Take control to type into the serial console of '+DEV+'. The agent shares this session, so what it types shows here too.':'View only. This link cannot type into '+DEV+'.')])}
function showRecording(r){const key='rec|'+r.path;if(msgKey!==key){recMeta=el('span','num mute');setMsg(key,[el('i','rdot live'),el('strong',null,'Recording'),recMeta,hostChip(),pathNode(r.path)])}
recMeta.textContent=mmss(r.seconds)+' · '+size(r.bytes)}
function showSaved(l){const key='saved|'+l.path;if(key===msgKey)return;
setMsg(key,[el('strong',null,'Saved'),el('span','num mute',mmss(l.seconds)+' · '+size(l.bytes)),hostChip(),pathNode(l.path),copyBtn(l.path),el('span','mute','replay with asciinema play')])}
function showFooter(s){const key=s.hostname+'|'+s.recording_dir;if(key===footKey)return;footKey=key;
foot.replaceChildren(el('span',null,'Recordings go to'),hostChip(),pathNode(s.recording_dir),el('span',null,'as asciinema .cast · change it with amt_serial_link record_start directory'))}
function render(){const s=S,ended=stream==='ended'||!!(s&&!s.live);
let k='ok',t='Live',a='',ak='';
if(ended){k='bad';t='Ended';a='Serial session ended'+(s&&s.error?' · '+s.error:'')+'. Start it again with amt_serial_link.'}
else if(offline){k='off';t='Offline';a='Lost contact with the serial server. Retrying every 2 seconds.';ak='warn'}
else if(stream==='reconnecting'){k='off';t='Reconnecting';a='Lost the output stream. Reconnecting and resuming where it stopped.';ak='warn'}
else if(stream==='closed'){k='bad';t='Stream closed';a='The output stream closed and the browser will not retry. Reload the page.'}
else if(stream==='connecting'){k='';t='Connecting'}
setPill(k,t);alertEl.hidden=!a;alertEl.className='alert'+(ak?' '+ak:'');if(alertEl.textContent!==a)alertEl.textContent=a;
wrap.classList.toggle('ended',ended);if(ended&&CONTROL&&controlling)setControl(false);if(CONTROL)ctl.disabled=ended;
if(!s)return;
meta.textContent='↓ '+size(s.bytes_received)+' · ↑ '+size(s.bytes_sent)+' · up '+hms(s.uptime_s);
meta.title='received from the host · sent to it by the operator and the agent · scrollback kept '+size(s.scrollback_bytes)+(s.last_output_age_s!=null?' · last output '+s.last_output_age_s+' s ago':' · no output yet');
vw.textContent=s.viewers+(s.viewers===1?' viewer':' viewers');
const typed=s.last_input_age_s;act.hidden=!(s.live&&typed!=null&&typed<=3);act.title='Keys reached the host '+typed+' s ago, from a control page or the agent';
showFooter(s);const r=s.recording,l=s.last_recording;recNow=r;
/*standalone*/rec.classList.toggle('on',!!r);rect.textContent=r?'Stop · '+mmss(r.seconds):'Record';rec.disabled=!r&&ended;
rec.title=r?'Stop recording':'Start recording on '+(HOST||'the server')+' in '+s.recording_dir;/*/standalone*/
badge.hidden=!r;if(r)badget.textContent='REC '+mmss(r.seconds);
document.title=(r?'● REC · ':'')+DEV+' · AMT serial';
if(r)showRecording(r);else if(l)showSaved(l);else showIdle(ended)}
async function poll(){let s;
try{s=await(await fetch('status.json',{cache:'no-store'})).json()}
catch(e){misses++;if(misses>=3){offline=true;render()}return}
misses=0;offline=false;S=s;HOST=s.hostname||'';render()}
try{const v=parseInt(localStorage.getItem('amt-serial-font'),10);if(v>=10&&v<=22)font=v}catch(e){}
const term=new Terminal({scrollback:10000,fontSize:font,fontFamily:'ui-monospace,SFMono-Regular,Menlo,Consolas,monospace',cursorBlink:false,disableStdin:true,convertEol:false,
theme:{background:css('--term'),foreground:'#e8eaf0',cursor:'#e8eaf0',cursorAccent:css('--term'),selectionBackground:'rgba(96,165,250,.38)',selectionInactiveBackground:'rgba(96,165,250,.2)'}});
const fit=new FitAddon.FitAddon();term.loadAddon(fit);term.open(termEl);
function refit(){try{fit.fit()}catch(e){}}
new ResizeObserver(()=>requestAnimationFrame(refit)).observe(termEl);refit();
function setFont(n){font=Math.max(10,Math.min(22,n));term.options.fontSize=font;fsz.textContent=font+' px';fontm.disabled=font<=10;fontp.disabled=font>=22;refit();try{localStorage.setItem('amt-serial-font',String(font))}catch(e){}}
setFont(font);fontm.onclick=()=>{setFont(font-1);refocus()};fontp.onclick=()=>{setFont(font+1);refocus()};
const es=new EventSource('events');
es.addEventListener('out',e=>{const m=JSON.parse(e.data);if(m.gap)gapEl.hidden=false;
const b=atob(m.d),u=new Uint8Array(b.length);for(let i=0;i<b.length;i++)u[i]=b.charCodeAt(i);term.write(u)});
es.addEventListener('end',()=>{stream='ended';es.close();render();poll()});
es.onopen=()=>{if(stream!=='live'){stream='live';render()}};
es.onerror=()=>{if(stream==='ended')return;stream=es.readyState===2?'closed':'reconnecting';render()};
/*standalone*/rec.onclick=async()=>{if(recBusy)return;recBusy=true;rec.disabled=true;
try{const r=await fetch('record'+(recNow?'':'?on=1'),{method:'POST'});if(!r.ok)toast('Record request refused: '+r.status,'err')}
catch(e){toast('Record request failed','err')}
rec.disabled=false;recBusy=false;await poll();refocus()};/*/standalone*/
/*standalone*/const dl=$('dl');
dl.onclick=()=>{try{const b=term.buffer.active,lines=[];for(let i=0;i<b.length;i++){const l=b.getLine(i);lines.push(l?l.translateToString(true):'')}
while(lines.length&&!lines[lines.length-1])lines.pop();
if(!lines.length){toast('Nothing to save yet');return}
const fname='amt-'+DEV+'-serial-'+stamp()+'.txt',url=URL.createObjectURL(new Blob([lines.join('\n')+'\n'],{type:'text/plain;charset=utf-8'})),a=el('a');a.href=url;a.download=fname;document.body.appendChild(a);a.click();a.remove();setTimeout(()=>URL.revokeObjectURL(url),5000);
toast('Saved to your downloads · '+fname+' · '+lines.length+' lines')}catch(e){toast('Download failed','err')}refocus()};
/*/standalone*/copyB.onclick=async()=>{const s=term.getSelection();if(!s){toast('Select some text in the terminal first');refocus();return}
try{if(navigator.clipboard&&window.isSecureContext)await navigator.clipboard.writeText(s);
else{const t=el('textarea');t.value=s;t.setAttribute('aria-hidden','true');t.style.position='fixed';t.style.opacity='0';document.body.appendChild(t);t.select();const ok=document.execCommand('copy');t.remove();if(!ok)throw new Error('copy')}
toast('Copied '+s.length+' characters')}catch(e){toast('Copy failed · select the text and use your keyboard','err')}refocus()};
clr.onclick=()=>{term.clear();toast('Screen cleared on this page only · '+DEV+' is not touched');refocus()};
setInterval(poll,2000);poll();
let setControl=()=>{};
if(!CONTROL){$('tag').hidden=false}else{
$('cgrp').hidden=false;
const blen=c=>c<0x80?1:c<0x800?2:c<0x10000?3:4;
function send(s){if(!s)return;q+=s.replace(/\p{Surrogate}/gu,'');if(!flushT)flushT=setTimeout(flush,10)}
async function flush(){flushT=0;if(busy||!q)return;busy=true;
while(q){let n=0,i=0;for(const ch of q){const b=blen(ch.codePointAt(0));if(n+b>MAX)break;n+=b;i+=ch.length}
const chunk=q.slice(0,i);q=q.slice(i);
try{const r=await fetch('input',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({data:chunk})});
if(!r.ok){const t=await r.text();toast(r.status===409?'The serial session is not live · nothing was sent':'Input refused: '+r.status+' '+t,'err',8000);q='';break}}
catch(e){toast('Input failed: '+e,'err',8000);q='';break}}
busy=false;if(q)flush()}
function stripState(){const live=controlling&&document.activeElement===term.textarea;
strip.classList.toggle('paused',controlling&&!live);
strip.textContent=live?'CONTROLLING · keys go to the serial console of '+DEV+' · Release control to stop':'Paused · click the terminal to resume';
strip.title='Every key, Tab and Escape included, goes to the host. Release with the button or by leaving this window.';
wrap.classList.toggle('live',live);wrap.classList.toggle('paused',controlling&&!live)}
setControl=on=>{if(on===controlling)return;controlling=on;term.options.disableStdin=!on;term.options.cursorBlink=on;
ctl.classList.toggle('on',on);ctl.classList.toggle('primary',!on);ctl.textContent=on?'Release control':'Take control';ctl.setAttribute('aria-pressed',String(on));
chips.forEach(c=>c.disabled=!on);if(on)term.focus();stripState();toast(on?'Control on · your keys go to '+DEV:'Control released',null,2500)};
ctl.onclick=()=>{if(!controlling&&(stream==='ended'||(S&&!S.live))){toast('The serial session is not live','err');return}setControl(!controlling)};
chips.forEach(c=>c.onclick=()=>{if(!controlling)return;send(KEYS[c.dataset.k]);term.focus()});
term.onData(d=>{if(controlling)send(d)});
term.textarea.addEventListener('focus',stripState);term.textarea.addEventListener('blur',stripState);
window.addEventListener('blur',()=>{if(controlling)setControl(false)});
document.addEventListener('visibilitychange',()=>{if(document.hidden&&controlling)setControl(false)})}
</script></body></html>"""
