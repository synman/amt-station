"""Test doubles for the console: a software passkey authenticator, a fake amt-mcp (the /mcp endpoint and the
one-time /handoffs route), a fake vault CLI, and a running console. Every secret here is a throwaway sentinel."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

import webauthn_min as wa

BEARER = "c0nsole-bearer-SENTINEL-not-a-real-secret"


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# -- CBOR encoder (just enough to build an attestationObject) -----------------------------------------------------

def cbor(v) -> bytes:
    def head(major, n):
        if n < 24: return bytes([major << 5 | n])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if n < 1 << (8 * size): return bytes([major << 5 | info]) + n.to_bytes(size, "big")
    if isinstance(v, bool): return b"\xf5" if v else b"\xf4"
    if isinstance(v, int): return head(0, v) if v >= 0 else head(1, -1 - v)
    if isinstance(v, bytes): return head(2, len(v)) + v
    if isinstance(v, str): return head(3, len(v.encode())) + v.encode()
    if isinstance(v, list): return head(4, len(v)) + b"".join(cbor(x) for x in v)
    if isinstance(v, dict): return head(5, len(v)) + b"".join(cbor(k) + cbor(x) for k, x in v.items())
    raise TypeError(type(v))


class Authenticator:
    """A software passkey: ES256, user verifying, counter that advances."""

    def __init__(self, rp_id: str, origin: str):
        self.rp_id, self.origin = rp_id, origin
        self.key = ec.generate_private_key(ec.SECP256R1())
        self.cred_id = os.urandom(32)
        self.count = 0

    def _xy(self):
        n = self.key.public_key().public_numbers()
        return n.x.to_bytes(32, "big"), n.y.to_bytes(32, "big")

    def _client(self, typ: str, challenge: str, origin: str | None = None) -> bytes:
        return json.dumps({"type": typ, "challenge": challenge, "origin": origin or self.origin, "crossOrigin": False}).encode()

    def register(self, options: dict, *, origin=None, rp_id=None, flags=0x45, fmt="none", alg=-7) -> dict:
        x, y = self._xy()
        cose = {1: 2, 3: alg, -1: 1, -2: x, -3: y}
        auth = (hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + struct.pack(">I", 0)
                + b"\x00" * 16 + struct.pack(">H", len(self.cred_id)) + self.cred_id + cbor(cose))
        client = self._client("webauthn.create", options["publicKey"]["challenge"], origin)
        return {"id": wa.b64u_encode(self.cred_id), "clientDataJSON": wa.b64u_encode(client),
                "attestationObject": wa.b64u_encode(cbor({"fmt": fmt, "attStmt": {}, "authData": auth}))}

    def assert_(self, options: dict, *, origin=None, rp_id=None, flags=0x05, count=None, cred_id=None, typ="webauthn.get") -> dict:
        self.count = self.count + 1 if count is None else count
        auth = hashlib.sha256((rp_id or self.rp_id).encode()).digest() + bytes([flags]) + struct.pack(">I", self.count)
        client = self._client(typ, options["publicKey"]["challenge"], origin)
        sig = self.key.sign(auth + hashlib.sha256(client).digest(), ec.ECDSA(hashes.SHA256()))
        return {"id": wa.b64u_encode(cred_id or self.cred_id), "clientDataJSON": wa.b64u_encode(client),
                "authenticatorData": wa.b64u_encode(auth), "signature": wa.b64u_encode(sig)}


# -- fake amt-mcp -------------------------------------------------------------------------------------------------

class FakeAmt:
    """POST /mcp (JSON-RPC tools/call), GET /handoffs/<token> and PUT /uploads/<token>. `results` maps a tool name to a function
    (arguments -> result dict); `calls` records (tool, arguments, Authorization header). A PUT is answered by `put_handler(path,
    headers, body) -> (status, bytes, content type)` (404 when none is set); the body is whatever arrived before the sender
    stopped, so a short one is visible. `puts` records (path, declared length, bytes received)."""

    def __init__(self, sse: bool = False):
        self.calls: list[tuple[str, dict, str | None]] = []
        self.results: dict = {}
        self.handoffs: dict[str, bytes] = {}
        self.fetches: dict[str, int] = {}
        self.sse = sse
        self.requests: list[tuple[str, str, dict]] = []
        self.puts: list[tuple[str, int, int]] = []
        self.put_handler = None
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def do_PUT(self):
                declared = int(self.headers.get("Content-Length") or 0)
                body = self.rfile.read(declared)                      # fewer bytes than declared when the sender stopped early
                outer.requests.append(("PUT", self.path, dict(self.headers)))
                outer.puts.append((self.path, declared, len(body)))
                status, data, ctype = outer.put_handler(self.path, dict(self.headers), body) if outer.put_handler else (404, b"not found", "text/plain")
                try:
                    self.send_response(status); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data))); self.end_headers()
                    self.wfile.write(data)
                except OSError:
                    pass

            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.requests.append(("POST", self.path, dict(self.headers)))
                p = body["params"]
                outer.calls.append((p["name"], p["arguments"], self.headers.get("Authorization")))
                if self.headers.get("Authorization") != f"Bearer {BEARER}":
                    result = {"content": [{"type": "text", "text": "this call requires the mcp-admin-token bearer header; refused"}], "isError": True}
                else:
                    fn = outer.results.get(p["name"], lambda a: {"ok": True})
                    out = fn(p["arguments"])
                    # what amt-mcp itself sends: its tools declare no output schema, so a dict is JSON text and there is no structuredContent
                    # (test_the_fake_answers_in_the_real_server_s_shape pins this against amt_server's own tool list)
                    result = out if "content" in out else {"content": [{"type": "text", "text": json.dumps(out)}], "isError": False}
                msg = json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result})
                if outer.sse:
                    data, ctype = f"event: message\ndata: {msg}\n\n".encode(), "text/event-stream"
                else:
                    data, ctype = msg.encode(), "application/json"
                self.send_response(200); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(data))); self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                outer.requests.append(("GET", self.path, dict(self.headers)))
                token = self.path.rsplit("/", 1)[-1]
                outer.fetches[token] = outer.fetches.get(token, 0) + 1
                data = outer.handoffs.pop(token, None)             # one fetch, then gone
                if data is None:
                    self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
                self.send_response(200); self.send_header("Content-Length", str(len(data))); self.end_headers(); self.wfile.write(data)

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.port = self.httpd.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()

    def offer(self, data: bytes, name: str = "shot.png", token: str | None = None) -> dict:
        """A handoff the way amt_handoff.offer shapes it."""
        token = token or ("T" + hashlib.sha256(data + name.encode()).hexdigest())[:43].ljust(43, "x")
        self.handoffs[token] = data
        return {"path": f"/data/state/shots/{name}", "url": f"{self.base}/handoffs/{token}",
                "sha256": hashlib.sha256(data).hexdigest(), "expires_in_s": 900}

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()


def write_vault_cli(folder: Path, bearer: str = BEARER) -> Path:
    """A stand-in for node-vault-mcp's secrets.py: `get amt-console-token` prints the sentinel."""
    cli = folder / "fake_secrets.py"
    cli.write_text("import sys\n"
                   f"if sys.argv[1:] == ['get', 'amt-console-token']:\n    print({bearer!r})\n    raise SystemExit(0)\n"
                   "raise SystemExit(1)\n")
    return cli


# -- fake viewer front -------------------------------------------------------------------------------------------------

class FakeViewer:
    """A stand-in for amt-mcp's viewer front: it serves amt-mcp's REAL viewer pages (amt_mirror.PAGE and amt_serial.PAGE through
    render_page, so the embed-mode toolbar a test sees is the real one) at /m/<token>/ and /s/<token>/, with the sub-routes the pages
    call. Every request is recorded. `stream` and `events` send a few parts and then hold open until `hold` is set (or the other end goes
    away, which sets `upstream_closed`), so a test sees a stream pass through while it is still open. Tokens are sentinels."""
    CONTROL = {"m": "VWRctrlM-Sentinel-0123456789abcdefghij", "s": "VWRctrlS-Sentinel-0123456789abcdefghij"}
    VIEW = {"m": "VWRviewM-Sentinel-0123456789abcdefghij", "s": "VWRviewS-Sentinel-0123456789abcdefghij"}

    def __init__(self):
        import base64
        import io
        import select
        import urllib.parse as urllib_parse
        from PIL import Image
        import amt_mirror
        import amt_serial
        self.amt_mirror, self.amt_serial = amt_mirror, amt_serial
        buf = io.BytesIO()
        Image.new("RGB", (64, 40), (40, 80, 120)).save(buf, "JPEG")
        self.jpeg = buf.getvalue()
        self.requests: list[tuple[str, str, dict, bytes]] = []
        self.control, self.view = dict(self.CONTROL), dict(self.VIEW)
        self.status = {"m": {"device": "my-server-1", "live": True, "error": None, "fps": 15, "frames": 400, "viewers": 1, "in_flight": None,
                             "last_frame_age_s": 0.1, "uptime_s": 14.0, "width": 640, "height": 400, "recording": None, "recording_dir": "/data/recordings",
                             "hostname": "nas", "ider": {"mounted": False}, "last_recording": None},
                       "s": {"device": "my-server-1", "live": True, "error": None, "viewers": 1, "in_flight": None, "uptime_s": 9.0, "total": 40,
                             "recording": None, "recording_dir": "/data/recordings", "hostname": "nas", "last_recording": None}}
        self.force: tuple[int, bytes] | None = None       # answer every routed request with this (status, body)
        self.hold, self.upstream_closed = threading.Event(), threading.Event()
        self.chatter = False                                # True: an open stream keeps sending (a busy screen), so it is never quiet
        self.sse_first = base64.b64encode(b"Debian GNU/Linux 13 my-server-1 ttyS0\r\n\r\nmy-server-1 login: ").decode()
        outer = self

        class H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass

            def _route(self):
                path, _, query = self.path.partition("?")
                parts = path.split("/")
                prefix = parts[1] if len(parts) > 2 else ""
                token = parts[2] if len(parts) > 2 else ""
                control = token == outer.control.get(prefix)
                if prefix not in ("m", "s") or not (control or token == outer.view.get(prefix)):
                    return None
                return prefix, control, "/".join(parts[3:]), urllib_parse.parse_qs(query), path

            def _reply(self, code, body: bytes, ctype="text/plain"):
                self.send_response(code); self.send_header("Content-Type", ctype); self.send_header("Content-Length", str(len(body)))
                self.send_header("Content-Security-Policy", "frame-ancestors 'self'"); self.end_headers(); self.wfile.write(body)

            def do_GET(self):
                outer.requests.append(("GET", self.path, dict(self.headers), b""))
                found = self._route()
                if found is None:
                    return self._reply(404, b"not found")
                if outer.force:
                    return self._reply(*outer.force)
                prefix, control, rest, query, path = found
                if rest == "" and not path.endswith("/"):
                    self.send_response(301); self.send_header("Location", self.path.replace(path, path + "/")); self.end_headers(); return
                if rest == "":
                    page = outer.amt_mirror.PAGE if prefix == "m" else outer.amt_serial.PAGE
                    return self._reply(200, outer.amt_mirror.render_page(page, "my-server-1", control, query.get("embed") == ["1"]).encode(), "text/html; charset=utf-8")
                if rest == "status.json":
                    return self._reply(200, json.dumps(outer.status[prefix]).encode(), "application/json")
                if rest == "frame.jpg":
                    return self._reply(200, outer.jpeg, "image/jpeg")
                if prefix == "s" and rest in outer.amt_serial.ASSETS:
                    name, ctype = outer.amt_serial.ASSETS[rest]
                    return self._reply(200, (outer.amt_serial.VENDOR / name).read_bytes(), ctype)
                if rest in ("media.json", "power.json"):
                    return self._reply(200, b"{}", "application/json")
                if rest in ("stream", "events"):
                    return self._stream(rest)
                self._reply(404, b"not found")

            def _stream(self, rest):
                self.send_response(200)
                self.send_header("Content-Type", "multipart/x-mixed-replace; boundary=frame" if rest == "stream" else "text/event-stream")
                self.send_header("Cache-Control", "no-store"); self.end_headers()
                try:
                    if rest == "stream":
                        for _ in range(3):
                            self.wfile.write(b"--frame\r\nContent-Type: image/jpeg\r\nContent-Length: " + str(len(outer.jpeg)).encode() + b"\r\n\r\n" + outer.jpeg + b"\r\n")
                            self.wfile.flush()
                    else:
                        self.wfile.write(b"retry: 2000\n\n"); self.wfile.flush()
                        self.wfile.write(f'id: 40\nevent: out\ndata: {json.dumps({"d": outer.sse_first, "gap": False})}\n\n'.encode()); self.wfile.flush()
                    while not outer.hold.is_set():
                        if outer.chatter:
                            self.wfile.write(b": busy\n\n"); self.wfile.flush()
                        readable, _, _ = select.select([self.connection], [], [], 0.05)
                        if readable and self.connection.recv(1, socket.MSG_PEEK) == b"":
                            outer.upstream_closed.set()
                            return
                except OSError:
                    outer.upstream_closed.set()

            def do_POST(self):
                body = self.rfile.read(int(self.headers.get("Content-Length") or 0))
                outer.requests.append(("POST", self.path, dict(self.headers), body))
                found = self._route()
                if found is None:
                    return self._reply(404, b"not found")
                if outer.force:
                    return self._reply(*outer.force)
                prefix, control, rest, query, path = found
                if rest in ("ider", "power", "boot") and query.get("embed") == ["1"]:
                    return self._reply(403, b"embed_mode: power, boot and media are not available to an embedded viewer")
                if rest == "input" and control:
                    return self._reply(200, json.dumps({"sent": len(body)}).encode(), "application/json")
                if rest == "record":
                    return self._reply(200, json.dumps({"recording": None}).encode(), "application/json")
                self._reply(404, b"not found")

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.httpd.daemon_threads = True
        self.base = f"http://127.0.0.1:{self.httpd.server_address[1]}"
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()

    def url(self, prefix: str, control: bool = True) -> str:
        return f"{self.base}/{prefix}/{(self.control if control else self.view)[prefix]}/"

    def rotate(self, prefix: str) -> None:
        """The session was restarted: its tokens change."""
        self.control[prefix] = self.control[prefix].replace("Sentinel", "Rotated")
        self.view[prefix] = self.view[prefix].replace("Sentinel", "Rotated")

    def seen(self, method: str | None = None) -> list[str]:
        return [path for m, path, _, _ in self.requests if method in (None, m)]

    def close(self):
        self.hold.set()
        self.httpd.shutdown(); self.httpd.server_close()


# -- a running console ----------------------------------------------------------------------------------------------

class Console:
    def __init__(self, tmp: Path, fake: FakeAmt, host: str = "127.0.0.1", **cfg):
        import server
        self.port = free_port()
        self.host = host                                   # "localhost" lets a real browser use WebAuthn (an IP is no RP id)
        self.origin = f"http://{host}:{self.port}"
        self.data = tmp / "console-data"
        values = dict(origin=self.origin, rp_id=host, data_dir=str(self.data), mcp_url=f"{fake.base}/mcp",
                      viewer_origin="https://amt-viewer.example.test", secrets_cli=str(write_vault_cli(tmp)),
                      bind="127.0.0.1", port=self.port, fleet_poll=False)    # no background poller: a test reads the fleet by hand
        values.update(cfg)
        self.app = server.App(server.Config(**values))
        self.httpd = server.serve(self.app)
        threading.Thread(target=self.httpd.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
        self.cookie: str | None = None
        self.csrf: str | None = None
        self.minted_keys: list[str] = []                   # every embed key this console minted for the test (the secrets scans look for them)

    def close(self):
        self.httpd.shutdown(); self.httpd.server_close()

    def mint_embed_key(self, kind: str, device: str = "my-server-1") -> str:
        """A fresh embed key for one page view of the mirror or terminal of `device`, as the page asks for it (session cookie and CSRF token)."""
        r = self.post("/api/embed/key", {"kind": kind, "device": device})
        assert r.status == 200, r.text
        self.minted_keys.append(r.json()["key"])
        return r.json()["key"]

    def embed(self, kind: str, device: str = "my-server-1") -> str:
        """The keyed path prefix of the relayed viewer page, /embed/<kind>/<device>/<key> (no trailing slash), minted once per (kind, device)."""
        cache = self.__dict__.setdefault("_embed_keys", {})
        if (kind, device) not in cache:
            cache[(kind, device)] = self.mint_embed_key(kind, device)
        return f"/embed/{kind}/{device}/{cache[(kind, device)]}"

    def request(self, method: str, path: str, body=None, *, headers: dict | None = None, cookie=True, origin=True, csrf=True, raw: bytes | None = None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=15)
        h = {"Host": f"{self.host}:{self.port}"}
        if body is not None or raw is not None:
            h["Content-Type"] = "application/json"
        if method == "POST" and origin:
            h["Origin"] = self.origin
        if cookie and self.cookie:
            h["Cookie"] = f"amt_console_session={self.cookie}"
        if csrf and self.csrf and method == "POST":
            h["X-CSRF-Token"] = self.csrf
        h.update(headers or {})
        payload = raw if raw is not None else (json.dumps(body) if body is not None else None)
        conn.request(method, path, body=payload, headers=h)
        resp = conn.getresponse()
        data = resp.read()
        out = Reply(resp.status, dict(resp.getheaders()), data)
        conn.close()
        return out

    def get(self, path, **kw): return self.request("GET", path, **kw)
    def post(self, path, body=None, **kw): return self.request("POST", path, {} if body is None else body, **kw)

    def adopt(self, reply: "Reply") -> None:
        """Take the session cookie and CSRF token from a sign-in / enrollment reply."""
        sc = reply.headers.get("Set-Cookie", "")
        if sc.startswith("amt_console_session="):
            self.cookie = sc.split(";", 1)[0].split("=", 1)[1]
        self.csrf = reply.json().get("csrf", self.csrf)


class Reply:
    def __init__(self, status, headers, data):
        self.status, self.headers, self.data = status, headers, data

    def json(self):
        return json.loads(self.data or b"{}")

    @property
    def text(self):
        return self.data.decode("utf-8", "replace")


def enroll_first_passkey(c: Console, auth: Authenticator, code: str = "ABCD-EFGH-JKMN", name: str = "Test key") -> Reply:
    """Write enroll.json for `code`, run the two enrollment calls, adopt the session."""
    plain = code.replace("-", "")
    (c.data).mkdir(parents=True, exist_ok=True)
    (c.data / "enroll.json").write_text(json.dumps({"sha256": hashlib.sha256(plain.encode()).hexdigest(), "expires": int(time.time()) + 600}))
    opts = c.post("/auth/enroll/options", {"code": code, "name": name})
    assert opts.status == 200, opts.text
    done = c.post("/auth/enroll/verify", auth.register(opts.json()))
    assert done.status == 200, done.text
    c.adopt(done)
    return done


_CM = []


def check_mockups():
    """design/check_mockups.py as a module: its force matrix, confirm and hold-contrast drivers run against the built client."""
    if not _CM:
        import importlib.util
        spec = importlib.util.spec_from_file_location("check_mockups", Path(__file__).resolve().parents[2] / "design" / "check_mockups.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules["check_mockups"] = mod
        spec.loader.exec_module(mod)
        _CM.append(mod)
    return _CM[0]
