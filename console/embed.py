"""The embeds' backend (packet C4): amt-mcp's own mirror and serial viewer pages, shown to the operator through the console.

A viewer page is reached by a url that carries a one-time-style token (``/m/<token>/`` for the display mirror, ``/s/<token>/``
for the serial terminal). The token is the viewer's only key, so it must never reach the browser. The console therefore does not
redirect to the viewer: it asks amt-mcp for the session (one server-side ``tools/call`` of ``amt_mirror_link`` or
``amt_serial_link`` with ``action: "status"``), keeps the control url in memory, and relays the viewer's embed-mode page
(``?embed=1``) and the few sub-routes it needs under the console's own ``/embed/<kind>/<server>/`` path. The browser sees only that
path. Nothing of the token is logged, put in a header, a body, an exception or a file.

* The relayed page runs in a sandboxed frame with an opaque origin (no ``allow-same-origin``), so it cannot reach the console page's DOM,
  globals or cookie, and the console's session cookie (SameSite=Strict) cannot ride its requests. The routes under ``/embed/`` are
  therefore authenticated by a per-page-view embed key in the path (``Keys`` below), minted by a session-authed route, held in memory,
  bound to the signed-in session and to one (kind, server), and compared in constant time. The key is in no log line, header, body,
  upstream request or file.
* The route never opens a session. Opening the host's single KVM or SOL session is a write, so it is the Start sheet's confirmed
  ``tools/call``; this route reuses a session that is already live.
* Only a control url on the viewer front (the configured viewer origin) is relayed. A session an agent started with the tool's
  default bind (127.0.0.1) has no such url: the page says it is not reachable from here.
* Only the sub-routes the embed page uses are relayed. Media, power and boot routes of the standalone page, and every other path,
  are answered here with nothing sent upstream. Every upstream request also says ``embed=1``, so amt-mcp refuses those routes too.
* The console's cookie, its bearer and its CSRF token are never sent to the viewer; the viewer's ``Location`` and framing headers
  are never copied back. Text bodies have the session's tokens and any one-time url replaced before they leave.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import queue
import re
import secrets
import select
import socket
import threading
import time
import urllib.parse

import captures
import fleet
import mcp_client

# kind -> (tool, key of the list a default-device status answers with, url prefix)
KINDS = {"mirror": ("amt_mirror_link", "mirrors", "m"), "serial": ("amt_serial_link", "terminals", "s")}
# The sub-routes the embed-mode pages use (amt_mirror.ROUTES / amt_serial.ROUTES and POST_ROUTES, minus the standalone-only ones and record).
GET_ROUTES = {"mirror": {"", "stream", "frame.jpg", "status.json"},
              "serial": {"", "events", "status.json", "xterm.js", "xterm.css", "addon-fit.js"}}
# Only the live keyboard and mouse input is a relayed write (the design's one non-tool path). Record is not: it is
# amt_mirror_link / amt_serial_link record_start and record_stop, a confirmed tools/call from the console's own chrome.
POST_ROUTES = {"mirror": {"input"}, "serial": {"input"}}
STREAM_ROUTES = {"stream", "events"}
TARGET_TTL = 30.0                                    # seconds a resolved session is reused before the next status call
MAX_BODY = 64 * 1024
MAX_PAGE = 16 * 1024 * 1024
UPSTREAM_TIMEOUT = 20.0
RELAY_IDLE = 10.0                                    # seconds of quiet on a stream before the browser's socket is checked
KEY_RECHECK = 2.0                                    # seconds between two checks that an open stream's key is still live (a busy stream is checked too)
KEY_TTL_IDLE = 600.0                                 # seconds an embed key may sit unused (no request with it, no page poll for its server) before it is dead
KEYS_MAX = 256                                       # live keys at most; the oldest unused goes first
KEY_RE = re.compile(r"[A-Za-z0-9_-]{43}")            # secrets.token_urlsafe(32)
TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{16,128}")
HOST_RE = re.compile(r"[A-Za-z0-9.\-]{1,80}")
TYPE_RE = re.compile(r"[\w.+-]+/[\w.+-]+(?:; ?[\w-]+=[\w\"-]+)?")
TEXT_TYPES = ("text/html", "text/plain", "text/css", "text/javascript", "application/json", "application/javascript")


class EmbedError(Exception):
    """A refusal with a fixed code, an HTTP status and (optionally) a few non-secret facts for the page."""

    def __init__(self, code: str, status: int, **extra):
        super().__init__(code)
        self.code, self.status, self.extra = code, status, extra


class Keys:
    """The embed keys: one per page view of an embedded viewer, in memory only, never written anywhere.

    A key is ``secrets.token_urlsafe(32)``. It is bound to the session that minted it (by ``session_ref``, never the cookie), to one
    kind (mirror or serial) and to one server, and it dies when that session signs out or idles out, when the key itself has been unused
    for ``idle`` seconds, or when the process restarts. A stream open under a key asks ``check`` again every ``KEY_RECHECK`` seconds (``Upstream.relay``), so a dead key ends it too and the stream counts as a use. Only a digest is kept, and a presented key is compared against every kept digest
    with ``hmac.compare_digest`` (no early exit), so neither the memory nor the timing of a lookup tells a guesser anything."""

    def __init__(self, session_live, now=time.monotonic, idle: float = KEY_TTL_IDLE):
        self.session_live, self.now, self.idle = session_live, now, idle
        self._lock = threading.Lock()
        self._keys: list[dict] = []

    @staticmethod
    def _digest(key: str) -> bytes:
        return hashlib.sha256(key.encode()).digest()

    def _prune(self) -> None:
        now = self.now()
        live = {ref: self.session_live(ref) for ref in {k["ref"] for k in self._keys}}
        self._keys = [k for k in self._keys if now - k["seen"] <= self.idle and live[k["ref"]]]

    def mint(self, ref: str, kind: str, server: str) -> str:
        key = secrets.token_urlsafe(32)
        with self._lock:
            self._prune()
            self._keys.append({"digest": self._digest(key), "ref": ref, "kind": kind, "server": server, "seen": self.now()})
            if len(self._keys) > KEYS_MAX:
                self._keys.sort(key=lambda k: k["seen"])
                del self._keys[:len(self._keys) - KEYS_MAX]
        return key

    def check(self, key: str, kind: str, server: str) -> bool:
        """Whether ``key`` is live for exactly this (kind, server); a live key is thereby used (its idle clock restarts)."""
        digest = self._digest(key)
        with self._lock:
            self._prune()
            found = None
            for k in self._keys:                           # no early exit: every kept digest is compared
                if hmac.compare_digest(k["digest"], digest):
                    found = k
            if found is None or (found["kind"], found["server"]) != (kind, server):
                return False
            found["seen"] = self.now()
            return True

    def touch(self, ref: str, kind: str, server: str) -> bool:
        """The page that minted keys for (kind, server) is still open and polling: keep them alive. Whether this session holds a live one."""
        with self._lock:
            self._prune()
            mine = [k for k in self._keys if (k["ref"], k["kind"], k["server"]) == (ref, kind, server)]
            for k in mine:
                k["seen"] = self.now()
            return bool(mine)

    def revoke_session(self, ref: str | None) -> None:
        """Sign-out: every key the session minted is gone at once."""
        with self._lock:
            self._keys = [k for k in self._keys if k["ref"] != ref]

    def __len__(self) -> int:
        with self._lock:
            self._prune()
            return len(self._keys)


class Target:
    """A live session's control url, held in memory only. ``tokens`` is every token the session's urls carry (view and control),
    kept to be removed from any text relayed to the browser."""
    __slots__ = ("path", "tokens")

    def __init__(self, path: str, tokens: frozenset):
        self.path, self.tokens = path, tokens

    def __repr__(self) -> str:
        return "Target(<withheld>)"


def mask(data: bytes, tokens, ctype: str) -> bytes:
    """A text body with every session token and every one-time url replaced; other bodies are returned as they are."""
    if not ctype.lower().startswith(TEXT_TYPES):
        return data
    for token in tokens:
        data = data.replace(token.encode(), b"[withheld]")
    try:
        return captures.mask_one_time_urls(data.decode("utf-8")).encode("utf-8")
    except UnicodeDecodeError:
        return data


class Upstream:
    """One relayed response. The caller reads it and closes it."""

    def __init__(self, resp, status: int, ctype: str, tokens, stream: bool):
        self.resp, self.status, self.ctype, self.tokens, self.stream = resp, status, ctype, tokens, stream

    def body(self) -> bytes:
        return mask(self.resp.read(MAX_PAGE), self.tokens, self.ctype)

    def close(self) -> None:
        mcp_client.close_response(self.resp)

    def relay(self, write, client_gone, idle: float | None = None, alive=None, recheck: float | None = None) -> str:
        """Copy a stream (the MJPEG ``stream``, the SSE ``events``) to the browser until either side ends. ``write(chunk)`` raises
        OSError once the browser is gone; ``client_gone()`` is asked whenever the viewer is quiet. ``alive()`` (when given) is asked at
        least every ``recheck`` seconds, quiet or busy, and the stream ends the first time it says no: a key checked once at the
        start would otherwise keep the host's screen or terminal flowing after sign-out. A reader thread owns the blocking read (a
        timed-out read cannot be resumed), and the upstream socket is shut down on the way out so it ends. Returns why it ended:
        ``browser_gone``, ``upstream_ended`` or ``key_dead`` (a write to a gone browser raises OSError instead)."""
        idle = RELAY_IDLE if idle is None else idle
        recheck = KEY_RECHECK if recheck is None else recheck
        wait = min(idle, recheck) if alive else idle
        next_check = time.monotonic() + recheck
        chunks: queue.Queue = queue.Queue(maxsize=8)
        stop = threading.Event()

        def pump() -> None:
            try:
                while not stop.is_set():
                    chunk = self.resp.read1(65536)
                    while not stop.is_set():
                        try:
                            chunks.put(chunk, timeout=1.0)
                            break
                        except queue.Full:
                            continue
                    if not chunk:
                        return
            except (OSError, http.client.HTTPException, ValueError, AttributeError):   # AttributeError: the response was closed under it
                try:
                    chunks.put_nowait(b"")
                except queue.Full:
                    pass

        reader = threading.Thread(target=pump, name="amt-console-embed-relay", daemon=True)
        reader.start()
        try:
            while True:
                try:
                    chunk = chunks.get(timeout=wait)
                except queue.Empty:
                    if client_gone():
                        return "browser_gone"
                    chunk = None
                if chunk is not None:
                    if not chunk:
                        return "upstream_ended"
                    write(chunk)
                if alive and time.monotonic() >= next_check:
                    if not alive():
                        return "key_dead"
                    next_check = time.monotonic() + recheck
        finally:
            stop.set()
            sock = getattr(self.resp, "_sock", None)
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
            reader.join(timeout=2.0)


class Embed:
    def __init__(self, client, viewer_origin: str, now=time.monotonic):
        parts = urllib.parse.urlsplit(viewer_origin)
        self.mcp, self.origin, self.now = client, (parts.scheme, parts.netloc), now
        self.host = parts.hostname or ""
        self._lock = threading.Lock()
        self._targets: dict[tuple[str, str], tuple[Target, float]] = {}

    # -- the session, from amt-mcp's own status -------------------------------------------------------------------------
    def forget(self, device) -> None:
        """A start or stop went through the console: the next request asks amt-mcp again."""
        with self._lock:
            for k in [k for k in self._targets if k[1] == device]:
                del self._targets[k]

    def _target_from(self, prefix: str, urls) -> Target | None:
        tokens = set()
        control = None
        for field, is_control in (("urls", False), ("control_urls", True)):
            for u in urls.get(field) or []:
                if not isinstance(u, str):
                    continue
                parts = urllib.parse.urlsplit(u)
                m = re.fullmatch(rf"/{prefix}/({TOKEN_RE.pattern})/", parts.path)
                if not m:
                    continue
                tokens.add(m.group(1))
                if (is_control and control is None and (parts.scheme, parts.netloc) == self.origin
                        and not parts.query and not parts.fragment):
                    control = parts.path
        return Target(control, frozenset(tokens)) if control else None

    def resolve(self, kind: str, key: str) -> tuple[dict, Target | None, str | None]:
        """(the device's session view, its relay target or None, the bind its direct url names or None). One server-side
        ``status`` call; the view is amt-mcp's own and still holds urls: only ``state`` below may leave this module."""
        tool, list_key, prefix = KINDS[kind]
        try:
            res = self.mcp.call(tool, {"device": key, "action": "status"})
        except mcp_client.VaultError:
            raise EmbedError("console_bearer_unavailable", 503) from None
        except mcp_client.McpError as ex:
            code = str(ex)
            raise EmbedError(code if code.startswith("amt_mcp_") else "amt_mcp_call_refused", 502) from None
        if res.is_error:
            raise EmbedError("status_unreadable", 502, detail=captures.mask_one_time_urls(res.text)[:300])
        view = fleet._pick(fleet.result_object(res), list_key, key)
        if not isinstance(view, dict) or view.get("live") is not True:
            self.forget(key)
            return {"live": False}, None, None
        target = self._target_from(prefix, view)
        bind = None
        if target is None:
            for u in view.get("control_urls") or []:
                host = urllib.parse.urlsplit(u).hostname if isinstance(u, str) else None
                if host and HOST_RE.fullmatch(host):
                    bind = host
                    break
        with self._lock:
            if target is None:
                self._targets.pop((kind, key), None)
            else:
                self._targets[(kind, key)] = (target, self.now() + TARGET_TTL)
        return view, target, bind

    def state(self, kind: str, key: str) -> dict:
        """What the page may know about the session: whether it is live and reachable, the viewer host, the bind of an
        unreachable one, and amt-mcp's own whitelisted view of it (in-flight call, geometry, recording). No url, no token."""
        view, target, bind = self.resolve(kind, key)
        if not view.get("live"):
            return {"live": False, "reachable": False}
        clean = (fleet.clean_mirror if kind == "mirror" else fleet.clean_terminal)(view, key, time.time())
        return {**clean, "live": True, "reachable": target is not None, "viewer_host": self.host, "bind": bind}

    def target(self, kind: str, key: str, fresh: bool = False) -> Target:
        with self._lock:
            held = None if fresh else self._targets.get((kind, key))
        if held is not None and held[1] > self.now():
            return held[0]
        view, target, bind = self.resolve(kind, key)
        if not view.get("live"):
            raise EmbedError("session_not_live", 409)
        if target is None:
            raise EmbedError("viewer_not_reachable", 409, bind=bind)
        return target

    # -- the relay ---------------------------------------------------------------------------------------------------
    def open(self, kind: str, key: str, method: str, rest: str, *, accept: str | None = None,
             body: bytes | None = None, ctype: str | None = None, last_event_id: str | None = None) -> Upstream:
        """Relay one request to the viewer. Raises EmbedError (a refusal made here, nothing sent upstream for a route outside
        the allowlist) after at most one retry against a fresh session lookup."""
        allowed = GET_ROUTES[kind] if method == "GET" else POST_ROUTES[kind]
        if rest not in allowed:
            raise EmbedError("not_found", 404)
        for attempt in (0, 1):
            target = self.target(kind, key, fresh=attempt == 1)
            headers = {"Accept": accept if accept and len(accept) < 200 else "*/*"}
            if method == "POST":
                headers["Content-Type"] = ctype or "application/json"
            if last_event_id and last_event_id.isdigit():
                headers["Last-Event-ID"] = last_event_id
            url = f"{self.origin[0]}://{self.origin[1]}{target.path}{rest}?embed=1"
            try:
                resp = mcp_client.http_request(url, method, headers, body, UPSTREAM_TIMEOUT)
            except mcp_client.McpError:
                self.forget(key)
                raise EmbedError("viewer_unreachable", 502) from None
            if resp.status == 404 and attempt == 0:           # the session was restarted: its tokens changed
                mcp_client.close_response(resp)
                continue
            break
        status = resp.status
        if 300 <= status < 400:
            mcp_client.close_response(resp)
            raise EmbedError("viewer_redirected", 502)
        raw_type = resp.getheader("Content-Type", "") or ""
        ctype_out = raw_type if TYPE_RE.fullmatch(raw_type) else "application/octet-stream"
        return Upstream(resp, status, ctype_out, target.tokens, rest in STREAM_ROUTES and 200 <= status < 300)


def client_closed(sock) -> bool:
    """Whether the browser has gone away: its socket is readable and a peek finds end-of-stream."""
    try:
        readable, _, _ = select.select([sock], [], [], 0)
        return bool(readable) and sock.recv(1, socket.MSG_PEEK) == b""
    except (OSError, ValueError):
        return True
