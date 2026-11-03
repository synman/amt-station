"""Upload handoffs: one image file sent to the image root over HTTP, never through MCP.

``amt_images action=upload`` validates a name, a declared size and an optional SHA-256, then
mints a single-use url: ``PUT`` (or ``POST``) ``<base>/uploads/<token>`` with the raw file as the
body. The token (``secrets.token_urlsafe(32)``) is the only key, as with a download handoff: it
is minted only into a bearer-gated tool result, is claimed by the first request that presents
it, and expires unused after ``TTL_SECONDS``. The route sits outside the bearer gate on purpose,
so ``curl -T`` works.

The body streams to a hidden ``.<name>.upload`` file beside the destination. It must be exactly
the declared size, and match the SHA-256 when one was given; anything else deletes the part file
and answers 400. A good upload is moved into place with ``os.replace``, after the owner's
``check`` (mounted, downloading) passes once more. Offers live in memory: a restart drops them.

The same pattern carries an identity value: ``amt_identity_manage action=intake`` mints
``PUT <base>/intake/<token>`` for ONE named vault entry. The body is the secret (UTF-8, at most
``INTAKE_MAX_BYTES``); it is handed to the vault CLI on stdin and nowhere else, and no log line,
response or exception carries it. Both routes answer a CORS preflight and add
``Access-Control-Allow-Origin`` for the console's origin only (``AMT_CONSOLE_ORIGIN``).
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import re
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response

import amt_handoff
import amt_vault

ROUTE = "/uploads/{token}"
INTAKE_ROUTE = "/intake/{token}"
INTAKE_MAX_BYTES = 4096
INTAKE_EXPIRES = "2035-01-01"           # the vault wants an expiry; the same far date amt_admin uses
SOURCE_NOTE = "source: console"         # the marker amt_identity reads back as source=console
TTL_SECONDS = 900
MAX_BYTES_ENV = "AMT_UPLOAD_MAX_BYTES"
DEFAULT_MAX_BYTES = 16 << 30
FREE_MARGIN_BYTES = 1 << 30          # leave this much free on the image volume
RESULTS_KEPT = 20
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_NO_STORE = {"Cache-Control": "no-store"}


class _Offer:
    def __init__(self, dest: Path, size: int, sha256: str | None, check: Callable[[], str | None]):
        self.dest, self.size, self.want, self.check = dest, size, sha256, check
        self.expires = time.time() + TTL_SECONDS
        self.state, self.got = "waiting", 0

    def snapshot(self) -> dict[str, Any]:
        return {"name": self.dest.name, "state": self.state, "bytes": self.got,
                "size_bytes": self.size, "sha256_expected": self.want}


_OFFERS: dict[str, _Offer] = {}
_RESULTS: list[dict[str, Any]] = []
_LOCK = threading.Lock()


def max_bytes() -> int:
    raw = os.environ.get(MAX_BYTES_ENV, "")
    return int(raw) if raw.isdigit() and int(raw) > 0 else DEFAULT_MAX_BYTES


def _reap(now: float) -> None:
    for token in [t for t, o in _OFFERS.items() if o.state == "waiting" and o.expires < now]:
        del _OFFERS[token]


def pending_for(dest: Path) -> bool:
    """True while an offer for ``dest`` is waiting or receiving."""
    with _LOCK:
        _reap(time.time())
        return any(o.dest == dest for o in _OFFERS.values())


def snapshot() -> dict[str, Any]:
    """Offers still open and the last finished uploads, for amt_images list. Never a token."""
    with _LOCK:
        _reap(time.time())
        return {"open": [o.snapshot() for o in _OFFERS.values()], "finished": list(_RESULTS),
                "max_bytes": max_bytes()}


def offer(dest: Path, size: int, sha256: str | None, check: Callable[[], str | None]) -> dict[str, Any]:
    """Register one upload to ``dest`` and return its url. Refuses when no public base url is
    set, the size passes the cap, or the volume lacks room."""
    base = amt_handoff.base_url()
    if base is None:
        raise ValueError(f"ider_upload_needs_{amt_handoff.BASE_URL_ENV}: uploads arrive over HTTP")
    if size > max_bytes():
        raise ValueError(f"ider_upload_too_large:{size}>{max_bytes()} ({MAX_BYTES_ENV})")
    free = os.statvfs(dest.parent)
    if size + FREE_MARGIN_BYTES > free.f_bavail * free.f_frsize:
        raise ValueError("ider_upload_no_room_on_the_image_volume")
    token = secrets.token_urlsafe(32)
    with _LOCK:
        _reap(time.time())
        if any(o.dest == dest for o in _OFFERS.values()):
            raise ValueError(f"ider_upload_already_open:{dest.name}")
        _OFFERS[token] = _Offer(dest, size, sha256, check)
    return {"name": dest.name, "size_bytes": size, "sha256_expected": sha256,
            "url": f"{base}/uploads/{token}", "method": "PUT", "expires_in_s": TTL_SECONDS,
            "url_note": "send the raw file once as the body (curl -T <file> <url>); the token in the "
                        "url is its only key; poll amt_images list for the result"}


def _finish(o: _Offer, state: str, error: str | None, sha: str | None) -> None:
    o.state = state
    with _LOCK:
        _RESULTS.insert(0, {"name": o.dest.name, "state": state, "bytes": o.got, "sha256": sha,
                            "error": error, "at": int(time.time())})
        del _RESULTS[RESULTS_KEPT:]


async def receive(request: Request) -> Response:
    """PUT/POST /uploads/<token>: the body becomes the image. Unknown or expired token: 404."""
    token = request.path_params.get("token", "")
    missing = PlainTextResponse("not found", status_code=404, headers=_NO_STORE)
    if not _TOKEN_RE.fullmatch(token):
        return missing
    with _LOCK:
        _reap(time.time())
        o = _OFFERS.get(token)
        if o is None or o.state != "waiting":
            return missing
        o.state = "receiving"                 # claimed: a second request finds it taken
    length = request.headers.get("content-length")
    if length is not None and (not length.isdigit() or int(length) != o.size):
        return _fail(token, o, f"content_length_not_declared_size:{length}!={o.size}")
    part = o.dest.with_name(f".{o.dest.name}.upload")
    h = hashlib.sha256()
    try:
        with open(part, "wb") as out:
            async for chunk in request.stream():
                o.got += len(chunk)
                if o.got > o.size:
                    raise ValueError(f"body_larger_than_declared_size:{o.size}")
                out.write(chunk)
                h.update(chunk)
        if o.got != o.size:
            raise ValueError(f"body_shorter_than_declared_size:{o.got}!={o.size}")
        got = h.hexdigest()
        if o.want and got != o.want:
            raise ValueError(f"sha256_mismatch:got {got}")
        busy = o.check()
        if busy and busy != "being_uploaded":
            raise ValueError(f"destination_busy:{busy}")
        os.replace(part, o.dest)
    except Exception as ex:   # noqa: BLE001 - reported in the response and by list
        part.unlink(missing_ok=True)
        return _fail(token, o, f"{type(ex).__name__}:{ex}")
    with _LOCK:
        _OFFERS.pop(token, None)
    _finish(o, "done", None, got)
    return JSONResponse({"name": o.dest.name, "bytes": o.got, "sha256": got}, status_code=201,
                        headers=_NO_STORE)


def _fail(token: str, o: _Offer, error: str) -> Response:
    with _LOCK:
        _OFFERS.pop(token, None)
    _finish(o, "failed", error, None)
    return PlainTextResponse(error, status_code=400, headers=_NO_STORE)


# --- identity intake --------------------------------------------------------------------------

class _Intake:
    def __init__(self, name: str):
        self.name = name
        self.expires = time.time() + TTL_SECONDS
        self.state = "waiting"


_INTAKES: dict[str, _Intake] = {}


def intake_offer(name: str) -> dict[str, Any]:
    """Register one single-use intake for the vault entry ``name`` and return its url. Nothing is
    stored yet. Refuses when no public base url is set."""
    base = amt_handoff.base_url()
    if base is None:
        raise ValueError(f"identity_intake_needs_{amt_handoff.BASE_URL_ENV}: the value arrives over HTTP")
    token = secrets.token_urlsafe(32)
    with _LOCK:
        for t in [t for t, o in _INTAKES.items() if o.state == "waiting" and o.expires < time.time()]:
            del _INTAKES[t]
        _INTAKES[token] = _Intake(name)
    return {"name": name, "url": f"{base}/intake/{token}", "method": "PUT", "expires_in_s": TTL_SECONDS,
            "max_bytes": INTAKE_MAX_BYTES,
            "url_note": "send the value once as the raw body (UTF-8, no line break); the token in the "
                        "url is its only key and the url dies with the first request"}


def _intake_answer(status: int, text: str) -> Response:
    return PlainTextResponse(text, status_code=status, headers=_NO_STORE)


async def receive_intake(request: Request) -> Response:
    """PUT/POST /intake/<token>: the body is the secret value of the offer's entry. Unknown or
    expired token: 404. Every later refusal consumes the offer; a vault that cannot be written
    answers 503 before the body is read and leaves the offer open."""
    token = request.path_params.get("token", "")
    if not _TOKEN_RE.fullmatch(token):
        return _intake_answer(404, "not found")
    with _LOCK:
        o = _INTAKES.get(token)
        if o is not None and o.expires < time.time():
            del _INTAKES[token]
            o = None
        if o is None or o.state != "waiting":
            return _intake_answer(404, "not found")
        o.state = "receiving"                 # claimed: a second request finds it taken
    if not amt_vault.vault_writable():
        o.state = "waiting"
        return _intake_answer(503, "vault_not_writable: nothing was stored")
    try:
        body = bytearray()                    # read in chunks, stopping at the cap: a long Content-Length costs nothing
        async for chunk in request.stream():
            body += chunk
            if len(body) > INTAKE_MAX_BYTES:
                return _intake_answer(413, f"value_larger_than_{INTAKE_MAX_BYTES}_bytes")
        if not body:
            return _intake_answer(400, "value_empty")
        try:
            value = bytes(body).decode("utf-8")
        except UnicodeDecodeError:
            return _intake_answer(400, "value_not_utf8")
        if any(c in value for c in "\r\n\x00"):
            return _intake_answer(400, "value_has_a_line_break_or_nul")
        try:
            await asyncio.to_thread(amt_vault.set_secret, o.name, value, _intake_notes(), INTAKE_EXPIRES)
        except amt_vault.VaultError:
            return _intake_answer(503, f"vault_write_failed:{o.name}: nothing was stored")
        except Exception as ex:   # noqa: BLE001 - the type only: its text could carry the value
            return _intake_answer(500, f"intake_failed:{type(ex).__name__}")
        return JSONResponse({"name": o.name, "stored": True}, status_code=201, headers=_NO_STORE)
    finally:                                  # consumed before any outcome is judged: one request only
        body = bytearray()
        value = ""
        with _LOCK:
            _INTAKES.pop(token, None)


def _intake_notes() -> str:
    return f"{SOURCE_NOTE}; updated: {datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')}"


# --- CORS for the console's browser -----------------------------------------------------------

def _allowed_origin(request: Request) -> str | None:
    """The request's Origin when it is exactly the console's (``AMT_CONSOLE_ORIGIN``, validated as the
    frame-ancestors value is), else None. Imported late: amt_mirror reaches this module through
    amt_write."""
    import amt_mirror
    allowed = amt_mirror._frame_ancestors()
    origin = request.headers.get("origin")
    return origin if allowed != "'none'" and origin == allowed else None


def with_cors(handler: Callable) -> Callable:
    """Wrap a route: answer its preflight and add Access-Control-Allow-Origin for the console's
    origin only. No credentials are ever allowed and any other origin gets no CORS header."""
    async def wrapped(request: Request) -> Response:
        origin = _allowed_origin(request)
        if request.method == "OPTIONS":
            response: Response = Response(status_code=204, headers=_NO_STORE)
            if origin:
                response.headers["Access-Control-Allow-Methods"] = "PUT, POST, OPTIONS"
                response.headers["Access-Control-Allow-Headers"] = "Content-Type"
                response.headers["Access-Control-Max-Age"] = "600"
        else:
            response = await handler(request)
        if origin:
            response.headers["Access-Control-Allow-Origin"] = origin
        response.headers["Vary"] = "Origin"
        return response
    return wrapped


def register(server) -> None:
    """Mount the upload and intake routes on ``server`` (served only by the HTTP app)."""
    server.custom_route(ROUTE, methods=["PUT", "POST", "OPTIONS"])(with_cors(receive))
    server.custom_route(INTAKE_ROUTE, methods=["PUT", "POST", "OPTIONS"])(with_cors(receive_intake))
