#!/usr/bin/env python3
"""amt-console: the management console's backend and static client.

Serves the sign-in page, the app shell and the static client, and turns the browser's actions into
``tools/call`` requests to amt-mcp with the console's own bearer (``mcp_client``). It holds no write path
into amt-mcp's state: no vault, devices file or image root of amt-mcp is mounted here; everything goes
through the tools. The browser never calls amt-mcp's MCP endpoint and never holds the bearer.

Security model (design note 2.1): the session cookie is ``Secure; HttpOnly; SameSite=Strict``; every
POST needs a same-origin ``Origin`` (and ``Sec-Fetch-Site`` when sent) and, once signed in, the
per-session CSRF token; every response carries ``Content-Security-Policy: default-src 'self'; frame-src
'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'``, ``X-Frame-Options: DENY`` and ``Referrer-Policy: no-referrer`` (http.server's own error pages go through the same headers; only a
request so malformed it names no HTTP version gets a bare error body, since HTTP/0.9 has no header block). A one-time url in a tool result
(download handoff, mirror or serial viewer, upload, intake) never reaches the browser: handoffs become capture records, the rest are masked.
The mirror and serial viewer pages are relayed under ``/embed/<kind>/<server>/<key>/`` (``embed.py``); only those responses may be framed, and
only by a console page. They run in an OPAQUE origin (the frame's sandbox has no ``allow-same-origin``, and the response's own CSP ``sandbox``
holds the same for a tab), so the relayed script cannot touch the console page's DOM, globals, cookie or ``/api``; the routes under ``/embed/``
are therefore authenticated by a per-page-view embed key in the path (``embed.Keys``: session-minted, in memory, bound to one server, constant-time
compared) instead of the SameSite=Strict cookie, and answer CORS (no credentials) on a valid key only; every other route keeps the exact-Origin,
cookie and CSRF rules above.
"""
from __future__ import annotations

import html
import http
import http.cookies
import json
import logging
import os
import re
import sys
import urllib.parse
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import auth
import captures
import embed
import fleet
import images
import intake
import mcp_client
import power

log = logging.getLogger("amt_console")

HERE = Path(__file__).resolve().parent
STATIC = HERE / "static"
PAGES = HERE / "pages"
COOKIE = "amt_console_session"
MAX_BODY = 64 * 1024
CONTENT_TYPES = {".css": "text/css; charset=utf-8", ".js": "text/javascript; charset=utf-8",
                 ".svg": "image/svg+xml"}
NAV = [("fleet", "Fleet", "/", "i-dns"), ("manage", "Manage", "/manage", "i-key"),
       ("images", "Images", "/images", "i-disc"), ("settings", "Settings", "/settings", "i-settings")]
SERVER_TABS = [("", "Status"), ("power", "Power & boot"), ("console", "KVM"), ("serial", "SOL"), ("media", "Media"),
               ("logs", "Logs"), ("inventory", "Inventory"), ("settings", "AMT settings"), ("wsman", "Advanced")]
TAB_SCRIPTS = {"power", "console", "serial", "media", "logs", "inventory", "settings", "wsman"}  # server tabs with their own static/<tab>.js (console and serial share embed.js)
SPLIT_TABS = {"", "console", "serial"}       # tabs laid out as a main column and a side column
KEY_PATH = r"[a-z0-9][a-z0-9-]{0,62}"
UPLOAD_ROUTE = re.compile(r"/api/images/upload/([A-Za-z0-9_-]{1,64})")   # a bad id is the route's 404, not the router's
INTAKE_ROUTE = re.compile(r"/api/identities/intake/([A-Za-z0-9_-]{1,64})")
ORIGIN_RE = re.compile(r"https?://[A-Za-z0-9.-]+(:\d{1,5})?")
EMBED_ROUTE = re.compile(rf"/embed/(mirror|serial)/({KEY_PATH})/({embed.KEY_RE.pattern})(/[A-Za-z0-9._-]*)?")
EMBED_KEY_IN_PATH = re.compile(r"(/embed/[^/]*/[^/]*/)[A-Za-z0-9_-]{16,}")      # wider than a key, and whatever follows it: a near miss or a key with a stray suffix is masked too
# What the opaque-origin viewer page's fetch, EventSource and POST need from a key-authed /embed/ path. No credentials are ever allowed, so the
# wildcard origin gives a page that has no key nothing, and a page that has one the one thing the key already grants.
EMBED_CORS = {"Access-Control-Allow-Origin": "*"}
EMBED_PREFLIGHT = {**EMBED_CORS, "Access-Control-Allow-Methods": "GET, POST, OPTIONS", "Access-Control-Max-Age": "600",
                   "Access-Control-Allow-Headers": "Content-Type, Accept, Last-Event-ID, Cache-Control, Pragma"}


def embed_headers(origin: str) -> dict:
    """The relayed viewer pages carry their own inline script and style, so they get their own policy instead of the console's:
    they may be framed by a console page only, they run in an opaque origin (``sandbox`` without ``allow-same-origin``, here as well as
    on the frame, so a copy opened in a tab is no more privileged than the framed one), and the page may fetch, load and connect to
    nothing but the relay's own /embed/ paths (the console's API and static files are out of its reach), nor submit a form. The sources
    are the absolute ``<origin>/embed/``: an opaque document has no ``'self'`` to match."""
    own = f"{origin}/embed/"
    return {"Content-Security-Policy": f"default-src 'none'; script-src {own} 'unsafe-inline'; style-src {own} 'unsafe-inline'; img-src {own} data: blob:; "
                                       f"connect-src {own}; font-src {own}; frame-ancestors 'self'; base-uri 'none'; form-action 'none'; object-src 'none'; "
                                       "sandbox allow-scripts allow-forms",
            "X-Frame-Options": "SAMEORIGIN"}


@dataclass
class Config:
    origin: str = "https://amt-console.example.com"
    rp_id: str = "amt-console.example.com"
    data_dir: str = "/console-data"
    mcp_url: str = "https://amt.example.com/mcp"
    viewer_origin: str = "https://amt-viewer.example.com"
    secrets_cli: str | None = None
    bind: str = "0.0.0.0"
    port: int = 8767
    idle_seconds: float = 12 * 3600
    capture_hours: float = 24.0
    mcp_timeout: float = 60.0
    fleet_interval: float = fleet.DEFAULT_INTERVAL
    fleet_poll: bool = True                      # off only in tests, which drive the schedule by hand

    @classmethod
    def from_env(cls, env=os.environ) -> "Config":
        d = cls()
        return cls(origin=env.get("AMT_CONSOLE_ORIGIN", d.origin), rp_id=env.get("AMT_CONSOLE_RP_ID", d.rp_id),
                   data_dir=env.get("AMT_CONSOLE_DATA", d.data_dir), mcp_url=env.get("AMT_CONSOLE_MCP_URL", d.mcp_url),
                   viewer_origin=env.get("AMT_CONSOLE_VIEWER_ORIGIN", d.viewer_origin),
                   secrets_cli=env.get("AMT_CONSOLE_SECRETS_CLI") or None, bind=env.get("AMT_CONSOLE_BIND", d.bind),
                   port=int(env.get("AMT_CONSOLE_PORT", d.port)),
                   idle_seconds=float(env.get("AMT_CONSOLE_IDLE_HOURS", "12")) * 3600,
                   capture_hours=float(env.get("AMT_CONSOLE_CAPTURE_HOURS", "24")),
                   mcp_timeout=float(env.get("AMT_CONSOLE_MCP_TIMEOUT", "60")),
                   fleet_interval=float(env.get("AMT_CONSOLE_FLEET_SECONDS", fleet.DEFAULT_INTERVAL)))


class App:
    """The console's collaborators, built once from a Config."""

    def __init__(self, cfg: Config, client: mcp_client.Client | None = None):
        for name in ("origin", "viewer_origin"):
            if not ORIGIN_RE.fullmatch(getattr(cfg, name)):
                raise ValueError(f"{name} must be scheme://host[:port]")
        self.cfg = cfg
        self.host = urllib.parse.urlsplit(cfg.origin).netloc
        self.auth = auth.Store(cfg.data_dir, cfg.rp_id, cfg.origin, idle_seconds=cfg.idle_seconds)
        self.mcp = client or mcp_client.Client(cfg.mcp_url, mcp_client.Vault(cfg.secrets_cli), cfg.mcp_timeout)
        mcp_parts = urllib.parse.urlsplit(cfg.mcp_url)
        self.captures = captures.CaptureStore(Path(cfg.data_dir) / "captures", f"{mcp_parts.scheme}://{mcp_parts.netloc}",
                                              cfg.capture_hours)
        self.fleet = fleet.Fleet(self.mcp, interval=cfg.fleet_interval, state_path=Path(cfg.data_dir) / "host-sessions.json",
                                 poll=cfg.fleet_poll)
        self.embed = embed.Embed(self.mcp, cfg.viewer_origin)
        self.keys = embed.Keys(self.auth.is_live)
        self.uploads = images.Uploads(f"{mcp_parts.scheme}://{mcp_parts.netloc}")
        self.intakes = intake.Intakes(f"{mcp_parts.scheme}://{mcp_parts.netloc}")
        self.embed_headers = embed_headers(cfg.origin)
        # The only frame the console shows is its own /embed route (the viewer pages are relayed there, never framed from their origin).
        self.csp = ("default-src 'self'; frame-src 'self'; frame-ancestors 'none'; "
                    "base-uri 'none'; form-action 'self'; object-src 'none'")


def loggable(path: str) -> str:
    """A request path as it may be logged: the id of a pending upload or intake is the handle of what is about to be sent, and an embed key
    is the credential of a relayed page, so neither is ever written down."""
    return EMBED_KEY_IN_PATH.sub(r"\1<key>", INTAKE_ROUTE.sub("/api/identities/intake/<id>", UPLOAD_ROUTE.sub("/api/images/upload/<id>", path)))


def strip_one_time_urls(obj, store: captures.CaptureStore):
    """Ingest every download handoff in a tool result and replace its url with the capture record; every other
    one-time url (a viewer, upload or intake url, wherever it sits) is masked in place: no token reaches the
    browser (immutables 11, 12 and 21)."""
    if captures.is_handoff(obj):
        record = store.ingest(obj)
        rest = {k: strip_one_time_urls(v, store) for k, v in obj.items() if k not in ("url", "url_note")}
        return {**rest, "capture": record}
    if isinstance(obj, dict):
        return {k: strip_one_time_urls(v, store) for k, v in obj.items()}
    if isinstance(obj, list):
        return [strip_one_time_urls(v, store) for v in obj]
    if isinstance(obj, str):
        return captures.mask_one_time_urls(obj)
    return obj


def nav_html(current: str, rail: bool) -> str:
    items = []
    for key, label, href, icon in NAV:
        cur = ' aria-current="page"' if key == current else ""
        cls = ' class="ri"' if rail else ""
        items.append(f'<a{cls} href="{href}"{cur}><span class="ind"><svg class="i" aria-hidden="true">'
                     f'<use href="/static/icons.svg#{icon}"/></svg></span>{label}</a>')
    return "".join(items)


def make_handler(app: App):
    class Handler(BaseHTTPRequestHandler):
        server_version = "amt-console"
        sys_version = ""

        # -- plumbing ---------------------------------------------------------------------------------------
        def log_request(self, code="-", size="-"):
            # a request rejected before it was parsed (bad request line, URI too long) has no path or command yet
            path = loggable(urllib.parse.urlsplit(getattr(self, "path", "") or "").path[:200])
            log.info("%s %s %s", getattr(self, "command", None) or "-", path, code)

        def log_message(self, fmt, *args):
            log.warning("%s", fmt % args)

        def _headers(self, status: int, ctype: str, length: int | None, extra: dict | None = None):
            """The response head. ``extra`` adds to the standard set or replaces one of its entries (the relayed viewer pages);
            ``length`` None sends no Content-Length (a stream that ends when the connection does)."""
            head = {"Content-Type": ctype, "Content-Security-Policy": app.csp, "X-Frame-Options": "DENY",
                    "Referrer-Policy": "no-referrer", "X-Content-Type-Options": "nosniff", "Cross-Origin-Opener-Policy": "same-origin",
                    "Cache-Control": "no-store"}
            if length is not None:
                head["Content-Length"] = str(length)
            head.update(extra or {})
            self.send_response(status)
            for k, v in head.items():
                self.send_header(k, v)
            self.end_headers()

        def _send(self, status: int, body: bytes, ctype: str, extra: dict | None = None):
            self._headers(status, ctype, len(body), extra)
            if self.command != "HEAD":
                self.wfile.write(body)

        def send_error(self, code, message=None, explain=None):
            """http.server's own error pages (501 for a method with no handler, 400 and 414 for a request it could
            not parse) leave through _headers like every other response, so they carry the framing headers too."""
            self.close_connection = True
            self._error(code, http.HTTPStatus(code).phrase.lower().replace(" ", "_"))

        def _json(self, status: int, obj, extra: dict | None = None):
            self._send(status, json.dumps(obj).encode(), "application/json", extra)

        def _error(self, status: int, code: str):
            self._json(status, {"error": code})

        def _redirect(self, where: str, extra: dict | None = None):
            self._headers(302, "text/plain", 0, {"Location": where, **(extra or {})})

        def _cookie(self) -> str | None:
            jar = http.cookies.SimpleCookie()
            try:
                jar.load(self.headers.get("Cookie", ""))
            except http.cookies.CookieError:
                return None
            morsel = jar.get(COOKIE)
            return morsel.value if morsel else None

        @staticmethod
        def _set_cookie(value: str, clear: bool = False) -> dict:
            attrs = "Path=/; Secure; HttpOnly; SameSite=Strict" + ("; Max-Age=0" if clear else "")
            return {"Set-Cookie": f"{COOKIE}={value}; {attrs}"}

        def _host_ok(self) -> bool:
            return self.headers.get("Host") == app.host

        def _same_origin(self) -> bool:
            site = self.headers.get("Sec-Fetch-Site")
            return self.headers.get("Origin") == app.cfg.origin and site in (None, "same-origin")

        def _body(self) -> dict | None:
            """The JSON object body of a POST, or None after an error response has been sent."""
            if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/json":
                self._error(415, "json_required")
                return None
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                self._error(411, "length_required")
                return None
            if not 0 <= length <= MAX_BODY:
                self._error(413, "body_too_large")
                return None
            try:
                body = json.loads(self.rfile.read(length) or b"null")
            except ValueError:
                self._error(400, "bad_json")
                return None
            if not isinstance(body, dict):
                self._error(400, "bad_json")
                return None
            return body

        def _session(self) -> tuple[str, dict | None]:
            return app.auth.lookup(self._cookie())

        def _guarded(self, fn):
            """A fault in a handler is a 500 with no detail; the type goes to the log, never the message."""
            try:
                fn()
            except (BrokenPipeError, ConnectionResetError):
                pass
            except Exception as ex:  # noqa: BLE001 - fail closed on anything unforeseen
                log.error("handler fault %s on %s", type(ex).__name__, loggable(urllib.parse.urlsplit(self.path).path))
                try:
                    self._error(500, "internal")
                except OSError:
                    pass

        def do_GET(self):
            self._guarded(self._get)

        def do_POST(self):
            self._guarded(self._post)

        def do_OPTIONS(self):
            """Only the CORS preflight of a key-authed /embed/ path is answered; every other path is a method with no handler."""
            path = urllib.parse.urlsplit(self.path).path
            if not path.startswith("/embed/"):
                return self.send_error(501)
            self._guarded(lambda: self._embed("OPTIONS", path) if self._host_ok() else self._error(421, "host_not_allowed"))

        # -- GET --------------------------------------------------------------------------------------------
        def _get(self):
            if not self._host_ok():
                return self._error(421, "host_not_allowed")
            path = urllib.parse.urlsplit(self.path).path
            if path.startswith("/embed/"):
                return self._embed("GET", path)
            if path.startswith("/static/"):
                return self._static(path[len("/static/"):])
            if path == "/signin":
                return self._page("signin.html", {"ORIGIN": html.escape(app.cfg.origin),
                                                  "IDLE": f"{app.cfg.idle_seconds / 3600:g}"})
            section = {"/": "fleet", "/manage": "manage", "/images": "images", "/settings": "settings"}.get(path)
            if section:
                return self._shell(section)
            if path == "/manage/identities":                     # the Manage section's second page: the credential entries by name
                return self._shell("manage", title="Identities", content=(PAGES / "content-manage-identities.html").read_text(),
                                   appbar=(PAGES / "appbar-manage-identities.html").read_text(), scripts=("status", "identities"), split=True)
            m = re.fullmatch(rf"/server/({KEY_PATH})(?:/([a-z]+))?", path)
            if m and m.group(2) in {slug for slug, _ in SERVER_TABS} | {None}:
                return self._server_page(m.group(1), m.group(2) or "")
            status, session = self._session()
            if status != "ok":
                return self._error(401, "not_signed_in")
            if path == "/api/session":
                return self._json(200, {"csrf": session["csrf"], "idle_seconds": app.cfg.idle_seconds})
            if path == "/api/passkeys":
                return self._json(200, {"passkeys": app.auth.passkeys()})
            if path == "/api/captures":
                return self._json(200, {"captures": app.captures.list()})
            if path == "/api/fleet":
                app.fleet.touch()
                return self._json(200, app.fleet.snapshot())
            m = re.fullmatch(rf"/api/embed/(mirror|serial)/({KEY_PATH})", path)
            if m:
                return self._embed_state(m.group(1), m.group(2))
            m = re.fullmatch(rf"/api/server/({KEY_PATH})(/captures|/power)?", path)
            if m:
                return self._server_api(m.group(1), m.group(2))
            m = re.fullmatch(r"/captures/([A-Za-z0-9_-]+)", path)
            if m:
                return self._capture(m.group(1))
            self._error(404, "not_found")

        # -- the relayed viewer pages (embed.py) ----------------------------------------------------------------
        def _known_server(self, key: str) -> bool:
            if app.fleet.devices_at is None:
                app.fleet.refresh_devices()
            return key in app.fleet.devices

        def _embed_state(self, kind: str, key: str):
            """What the page may know about the session (live, reachable, in-flight call, geometry): never a url or a token."""
            if not self._known_server(key):
                return self._error(404, "unknown_server")
            try:
                state = app.embed.state(kind, key)
            except embed.EmbedError as ex:
                return self._json(ex.status, {"error": ex.code, **ex.extra})
            # the page that minted this server's embed keys is open and polling, which keeps them alive; false tells it the frame's key is gone
            # (an idle limit, a console restart) so it mounts a fresh one. A boolean: the key itself is never in this reply.
            self._json(200, {**state, "key_live": app.keys.touch(app.auth.session_ref(self._cookie()), kind, key)})

        def _embed(self, method: str, path: str):
            """GET, POST or OPTIONS under /embed/<kind>/<server>/<key>/: the viewer's embed-mode page and its few sub-routes, relayed.
            The relayed page runs in an opaque origin, so it carries no console cookie (SameSite=Strict) and no CSRF token: the embed key in the
            path is its credential. A key that is wrong, expired, revoked or for another server or kind is a 404 with nothing sent upstream and no
            CORS header; the key is checked before anything else is. A POST here is the viewer page's own live input (the design's named
            exception, not a tool call); its Origin must be `null` (the opaque frame) or the console's own. Only `input` is relayed: Record is a
            confirmed tools/call, not a route."""
            m = EMBED_ROUTE.fullmatch(path)
            if not m:
                return self._error(404, "not_found")
            kind, key, ekey, tail = m.groups()
            if tail is None or not app.keys.check(ekey, kind, key):          # a missing slash is not redirected: the redirect would repeat the key
                return self._error(404, "not_found")
            rest = tail[1:]
            if method == "OPTIONS":
                if rest not in embed.GET_ROUTES[kind] | embed.POST_ROUTES[kind]:
                    return self._error(404, "not_found")
                return self._headers(204, "text/plain", None, EMBED_PREFLIGHT)
            if method == "POST" and self.headers.get("Origin") not in ("null", app.cfg.origin):
                log.warning("cross-site POST refused path=%s", loggable(urllib.parse.urlsplit(self.path).path))
                return self._json(403, {"error": "cross_site_refused"}, EMBED_CORS)
            if not self._known_server(key):
                return self._json(404, {"error": "unknown_server"}, EMBED_CORS)
            args = {}
            if method == "POST":
                length = self.headers.get("Content-Length")
                try:
                    size = int(length) if length is not None else 0
                except ValueError:
                    return self._json(411, {"error": "length_required"}, EMBED_CORS)
                ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
                if not 0 <= size <= embed.MAX_BODY:
                    return self._json(413, {"error": "body_too_large"}, EMBED_CORS)
                if ctype not in ("", "application/json"):
                    return self._json(415, {"error": "json_required"}, EMBED_CORS)
                args = {"body": self.rfile.read(size), "ctype": ctype or None}
            else:
                args = {"accept": self.headers.get("Accept"), "last_event_id": self.headers.get("Last-Event-ID")}
            try:
                up = app.embed.open(kind, key, method, rest, **args)
            except embed.EmbedError as ex:
                return self._json(ex.status, {"error": ex.code, **ex.extra}, EMBED_CORS)
            try:
                if up.stream:
                    self._headers(up.status, up.ctype, None, {**app.embed_headers, **EMBED_CORS, "X-Accel-Buffering": "no"})
                    self.close_connection = True

                    def write(chunk):
                        self.wfile.write(chunk)
                        self.wfile.flush()
                    try:
                        why = up.relay(write, lambda: embed.client_closed(self.connection),
                                       alive=lambda: app.keys.check(ekey, kind, key))   # sign-out, session expiry and a restart end an open stream too
                    except OSError as ex:
                        why = f"write_failed:{type(ex).__name__}"
                    log.info("embed stream ended %s path=%s", why, loggable(path))
                    return
                data = up.body()
                status = up.status if up.status < 500 else 502
                self._send(status, data if status < 300 else data[:2000], up.ctype, {**app.embed_headers, **EMBED_CORS})
            finally:
                up.close()

        def _static(self, name: str):
            file = STATIC / name
            if not re.fullmatch(r"[a-z0-9][a-z0-9._-]*", name) or not file.is_file() or file.suffix not in CONTENT_TYPES:
                return self._error(404, "not_found")
            self._send(200, file.read_bytes(), CONTENT_TYPES[file.suffix], {"Cache-Control": "no-cache"})

        def _page(self, name: str, fields: dict):
            text = (PAGES / name).read_text()
            for key, value in fields.items():
                text = text.replace(f"@@{key}@@", value)
            self._send(200, text.encode(), "text/html; charset=utf-8")

        def _shell(self, section: str, title: str | None = None, content: str | None = None, appbar: str | None = None,
                   scripts: tuple[str, ...] = (), split: bool = False):
            status, _ = self._session()
            if status != "ok":
                return self._redirect("/signin?expired=1" if status == "expired" else "/signin",
                                      self._set_cookie("", clear=True) if status != "none" else None)
            label = next(n[1] for n in NAV if n[0] == section)
            if content is None and section == "images":                  # the Images section is the Media page with a server picker
                content = (PAGES / "content-server-media.html").read_text().replace("@@KEY@@", "").replace("@@PICK@@", "")
            if content is None:
                page = PAGES / f"content-{section}.html"
                content = (page if page.is_file() else PAGES / "content-unbuilt.html").read_text()
            if appbar is None:
                bar = PAGES / f"appbar-{section}.html"
                appbar = bar.read_text() if bar.is_file() else '<header class="appbar"><h1>@@TITLE@@</h1></header>'
            title = html.escape(title or label)
            scripts = scripts or {"fleet": ("status", "fleet"), "images": ("status", "media"), "manage": ("status", "servers")}.get(section, ())
            self._page("shell.html", {"TITLE": title, "RAIL": nav_html(section, True), "BOTTOM": nav_html(section, False),
                                      "APPBAR": appbar.replace("@@TITLE@@", title), "SPLIT": " split" if split else "",
                                      "PAGESCRIPTS": "".join(f'<script src="/static/{s}.js"></script>' for s in scripts),
                                      "CONTENT": content.replace("@@LABEL@@", html.escape(label))})

        def _server_page(self, key: str, tab: str):
            label = next(name for slug, name in SERVER_TABS if slug == tab)
            tabs = "".join(f'<a href="/server/{key}{"/" + slug if slug else ""}"{" aria-current=page" if slug == tab else ""}>{html.escape(name)}</a>'
                           for slug, name in SERVER_TABS)
            chips = "".join(f'<a class="chip{" selected" if slug == tab else ""}" href="/server/{key}{"/" + slug if slug else ""}"'
                            f'{" aria-current=page" if slug == tab else ""}>{html.escape(name)}</a>' for slug, name in SERVER_TABS)
            bar = (PAGES / "appbar-server.html").read_text().replace("@@KEY@@", key).replace("@@TABS@@", tabs).replace("@@CHIPS@@", chips)
            built = PAGES / f"content-server-{tab}.html"                 # a tab whose page exists; the rest say they are not built
            content = (PAGES / "content-server.html" if not tab else built if built.is_file() else PAGES / "content-unbuilt.html").read_text()
            self._shell("fleet", title=key, content=content.replace("@@KEY@@", key).replace("@@PICK@@", "hidden").replace("@@LABEL@@", html.escape(label)), appbar=bar,
                        scripts=("status", "server") + ("embed",) * (tab in ("console", "serial")) + (tab,) * (tab in TAB_SCRIPTS),
                        split=tab in SPLIT_TABS)

        def _server_api(self, key: str, sub: str | None):
            app.fleet.touch()
            if app.fleet.devices_at is None:
                app.fleet.refresh_devices()
            entry = app.fleet.public(key)
            if entry is None:
                return self._error(404, "unknown_server")
            if sub == "/power":                                  # one read of what AMT offers; only when the page asks
                return self._json(200, power.read_offered(app.mcp, app.fleet, key))
            if sub is None:
                return self._json(200, {"now": app.fleet.now(), "interval": app.fleet.interval, "server": entry})
            try:
                self._json(200, fleet.past_captures(app.mcp, app.captures, key))
            except mcp_client.McpError as ex:
                code = str(ex)
                self._json(502 if code.startswith("amt_mcp_") else 503, {"error": code})

        def _capture(self, cid: str):
            found = app.captures.get(cid)
            if not found:
                return self._error(404, "not_found")
            meta, path = found
            name = urllib.parse.quote(meta["name"])
            data = path.read_bytes()
            self._send(200, data, app.captures.content_type(meta["name"]),
                       {"Content-Disposition": f"attachment; filename*=UTF-8''{name}"})

        # -- POST -------------------------------------------------------------------------------------------
        def _post(self):
            if not self._host_ok():
                return self._error(421, "host_not_allowed")
            path = urllib.parse.urlsplit(self.path).path
            if path.startswith("/embed/"):                       # authenticated by its embed key, with its own Origin rule (the opaque frame sends `null`)
                return self._embed("POST", path)
            if not self._same_origin():
                log.warning("cross-site POST refused path=%s", loggable(path))
                return self._error(403, "cross_site_refused")
            public = {"/auth/enroll/options": self._enroll_options, "/auth/enroll/verify": self._enroll_verify,
                      "/auth/signin/options": self._signin_options, "/auth/signin/verify": self._signin_verify}
            signed_in = {"/auth/signout": self._signout, "/api/passkeys/options": self._passkey_options,
                         "/api/passkeys/verify": self._passkey_verify, "/api/call": self._call, "/api/embed/key": self._embed_key,
                         "/api/fleet/refresh": self._fleet_refresh, "/api/sequence": self._sequence}
            handler = public.get(path)
            if handler is None and path in signed_in:
                if not self._authorized():
                    return
                handler = signed_in[path]
            upload, intake_id = UPLOAD_ROUTE.fullmatch(path), INTAKE_ROUTE.fullmatch(path)
            if handler is None and upload:                       # a file, not JSON: the body is streamed on, never read whole
                if self._authorized():
                    self._image_upload(upload.group(1))
                return
            if handler is None and intake_id:                    # a value, not JSON: relayed once to the one-time url, never kept
                if self._authorized():
                    self._identity_intake(intake_id.group(1))
                return
            if handler is None:
                return self._error(404, "not_found")
            body = self._body()
            if body is not None:
                try:
                    handler(body)
                except auth.AuthError as ex:
                    self._auth_refused(ex)

        def _authorized(self) -> bool:
            """A signed-in session carrying its CSRF token; otherwise the refusal has been sent."""
            status, session = self._session()
            if status != "ok":
                self._error(401, "not_signed_in")
                return False
            if not app.auth.csrf_ok(session, self.headers.get("X-CSRF-Token")):
                self._error(403, "csrf_token_invalid")
                return False
            return True

        def _image_upload(self, upload_id: str):
            """The browser's file, streamed on to the one-time url the console kept when it minted the upload (images.py). A refusal made
            here leaves the request body unread, so the connection is closed after it; amt-mcp's own answer is returned verbatim."""
            def refuse(status: int, code: str):
                self.close_connection = True
                self._error(status, code)
            if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "application/octet-stream":
                return refuse(415, "octet_stream_required")
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return refuse(411, "length_required")
            if length <= 0:
                return refuse(411, "length_required")
            try:
                reply = app.uploads.stream(upload_id, length, self.rfile.read)
            except images.UploadError as ex:
                return refuse(ex.status, ex.code)
            log.info("upload streamed ok=%s", reply.get("ok"))
            if reply.get("ok") is not True:
                self.close_connection = True                     # the body may not have been read to its end
            self._json(200, reply)

        def _identity_intake(self, intake_id: str):
            """The value of a vault entry, relayed once to the one-time url the console kept when it minted the intake (intake.py). The body is
            the value as plain text; a refusal made here leaves the request body unread, so the connection is closed after it. amt-mcp's own
            answer is returned (a one-time url masked); neither the value nor the id is logged."""
            def refuse(status: int, code: str):
                self.close_connection = True
                self._error(status, code)
            if (self.headers.get("Content-Type") or "").split(";")[0].strip().lower() != "text/plain":
                return refuse(415, "text_plain_required")
            try:
                length = int(self.headers.get("Content-Length", ""))
            except ValueError:
                return refuse(411, "length_required")
            try:
                reply = app.intakes.send(intake_id, length, self.rfile.read)
            except images.UploadError as ex:
                return refuse(ex.status, ex.code)
            log.info("intake relayed ok=%s", reply.get("ok"))
            if reply.get("ok"):
                app.fleet.refresh_devices()                      # a replaced identity resumes a server that was paused on its refused credential
            self._json(200, reply)

        def _auth_refused(self, ex: auth.AuthError):
            code = ex.code.split(":")[0]
            status = {"passkey_not_enrolled": 403, "enroll_locked": 429, "too_many_pending": 429}.get(code, 400)
            self._error(status, ex.code)                         # a fixed vocabulary: never a request value

        def _start_session(self, extra: dict):
            cookie, session = app.auth.new_session()
            self._json(200, {"ok": True, "csrf": session["csrf"], **extra}, self._set_cookie(cookie))

        def _enroll_options(self, body):
            self._json(200, app.auth.enroll_begin(body.get("code"), body.get("name")))

        def _enroll_verify(self, body):
            passkey = app.auth.enroll_finish(body)
            self._start_session({"passkey": passkey})

        def _signin_options(self, body):
            self._json(200, app.auth.signin_begin())

        def _signin_verify(self, body):
            cookie, session = app.auth.signin_finish(body)
            self._json(200, {"ok": True, "csrf": session["csrf"]}, self._set_cookie(cookie))

        def _signout(self, body):
            app.keys.revoke_session(app.auth.session_ref(self._cookie()))      # the embeds of this session stop at once (open streams within KEY_RECHECK)
            app.auth.destroy(self._cookie())
            self._json(200, {"ok": True}, self._set_cookie("", clear=True))

        def _passkey_options(self, body):
            self._json(200, app.auth.add_begin(body.get("name")))

        def _passkey_verify(self, body):
            self._json(200, {"ok": True, "passkey": app.auth.add_finish(body)})

        def _embed_key(self, body):
            """The key for one page view of an embedded viewer: the page puts it in the frame's path, /embed/<kind>/<server>/<key>/. It is the
            only reply that carries one, and it is bound to this session and to this one (kind, server)."""
            kind, key = body.get("kind"), body.get("device")
            if kind not in embed.KINDS or not isinstance(key, str) or not re.fullmatch(KEY_PATH, key):
                return self._error(400, "bad_embed_request")
            if not self._known_server(key):
                return self._error(404, "unknown_server")
            self._json(200, {"key": app.keys.mint(app.auth.session_ref(self._cookie()), kind, key)})

        def _fleet_refresh(self, body):
            """Retry now / Retry once for one server (one read, even of a paused one), or refresh all (the schedule's own
            order, a read a second, paused servers left alone)."""
            key = body.get("device")
            app.fleet.touch()
            if key is None:
                app.fleet.mark_all_due()
                return self._json(200, {"ok": True})
            if not isinstance(key, str) or not re.fullmatch(KEY_PATH, key) or app.fleet.public(key) is None:
                return self._error(404, "unknown_server")
            ran = app.fleet.retry(key)
            self._json(200, {"ok": True, "ran": ran, "server": app.fleet.public(key)})

        def _tool_call(self, tool, arguments) -> dict:
            """One tools/call for the browser: the reply it gets (one-time urls ingested or masked). Raises McpError when the
            call was not made or amt-mcp could not be reached (a missing bearer is the fixed code below, never the entry)."""
            try:
                result = app.mcp.call(tool, arguments)
            except mcp_client.VaultError as ex:
                log.error("call not made: %s", ex)
                raise mcp_client.McpError("console_bearer_unavailable") from None
            app.fleet.observe(tool, arguments, result.is_error, result.text)
            if tool in ("amt_mirror_link", "amt_serial_link") and arguments.get("action") in ("start", "stop"):
                app.embed.forget(arguments.get("device"))              # the session's tokens changed
                if not result.is_error:
                    app.fleet.refresh_sessions(arguments["device"])    # so the page sees who holds it now
            if tool == "amt_ider" and arguments.get("action") in ("mount", "unmount", "status") and not result.is_error:
                app.fleet.refresh_sessions(arguments["device"])        # the header's IDE-R chip follows a mount or an unmount at once
            if tool == "amt_device_manage" and not result.is_error:
                app.fleet.refresh_devices()                            # an added, edited, re-pinned or removed server is in the fleet at once
            structured = strip_one_time_urls(result.structured, app.captures)
            if tool == "amt_images" and arguments.get("action") == "upload" and not result.is_error and isinstance(structured, dict):
                structured.update(app.uploads.register(result.structured))   # the url stays here; the browser gets an id for the stream route
            if tool == "amt_identity_manage" and arguments.get("action") == "intake" and not result.is_error and isinstance(structured, dict):
                structured.update(app.intakes.register(result.structured))   # likewise the intake url: the browser gets an id for the intake route
            return {"isError": result.is_error, "text": captures.mask_one_time_urls(result.text), "structured": structured}

        def _call(self, body):
            try:
                reply = self._tool_call(body.get("tool"), body.get("arguments"))
            except mcp_client.McpError as ex:
                code = str(ex)
                log.warning("call not made: %s", code)
                return self._error(503 if code == "console_bearer_unavailable" else 502 if code.startswith("amt_mcp_") else 400, code)
            self._json(200, reply)

        def _sequence(self, body):
            """A combined boot entry: amt_set_next_boot, then amt_power only if the boot step was accepted."""
            try:
                steps = power.check_sequence(body.get("steps"))
            except power.BadSequence as ex:
                return self._error(400, str(ex))
            self._json(200, power.run_sequence(steps, self._tool_call))

    return Handler


def serve(app: App) -> ThreadingHTTPServer:
    httpd = ThreadingHTTPServer((app.cfg.bind, app.cfg.port), make_handler(app))
    httpd.daemon_threads = True
    return httpd


def main() -> int:
    logging.basicConfig(level=logging.INFO, stream=sys.stderr, format="%(asctime)s %(name)s %(message)s")
    app = App(Config.from_env())
    if not app.auth.has_passkeys():
        log.warning("no passkey is enrolled: mint a code with deploy/amt_admin.py console enroll-code")
    httpd = serve(app)
    log.info("amt-console on %s:%d for %s", app.cfg.bind, app.cfg.port, app.cfg.origin)
    httpd.serve_forever()
    return 0


if __name__ == "__main__":
    sys.exit(main())
