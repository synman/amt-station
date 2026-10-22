"""The image upload's backend (packet C5): a file goes from the operator's browser to amt-mcp's one-time ``PUT /uploads/<token>``
url THROUGH the console, and the url never reaches the browser.

``amt_images`` with ``action: "upload"`` mints the url. The console makes that ``tools/call`` itself (``server._tool_call``) and hands the
result to ``Uploads.register``, which keeps the url in memory and gives the browser an opaque ``upload_id`` instead. The browser then
posts the file to ``/api/images/upload/<upload_id>``; ``Uploads.stream`` copies the request body to the url in chunks, never holding
the file (nothing is written here, and the console has no image root). The url, its token and the file name are never logged, put in a
response, an exception or a file: what the browser gets back is amt-mcp's own answer text with any one-time url masked.

amt-mcp checks the exact size and the optional SHA-256 itself and, on any mismatch, deletes its part file and answers 400 with the reason;
that reason is returned verbatim. A browser that stops sending early leaves amt-mcp with a short body, which it refuses the same way.
"""
from __future__ import annotations

import http.client
import json
import re
import secrets
import threading
import time
import urllib.parse

import captures

UPLOAD_PATH = re.compile(r"/uploads/[A-Za-z0-9_-]{43}")
CHUNK = 1 << 20
UPSTREAM_TIMEOUT = 60.0                  # per socket operation, not for the whole file
MAX_OFFERS = 16
DEFAULT_TTL = 900.0                      # amt_upload.TTL_SECONDS: an offer unused for this long is gone upstream
ANSWER_BYTES = 4096


class UploadError(Exception):
    """A refusal made here, before any byte of the file was sent upstream. ``code`` is fixed; it never carries a value."""

    def __init__(self, code: str, status: int):
        super().__init__(code)
        self.code, self.status = code, status


class Uploads:
    def __init__(self, amt_origin: str, now=time.time):
        parts = urllib.parse.urlsplit(amt_origin)
        self.origin = (parts.scheme, parts.netloc)
        self.now = now
        self._offers: dict[str, dict] = {}
        self._lock = threading.Lock()

    # -- minting ---------------------------------------------------------------------------------------------------
    def register(self, structured) -> dict:
        """What the browser may know about a successful ``upload`` result: ``{"upload_id", "name", "size_bytes", "expires_in_s"}``, or
        ``{"upload_refused": code}`` when the result carries no usable url. The url is kept here and nowhere else."""
        s = structured if isinstance(structured, dict) else {}
        url, size, name = s.get("url"), s.get("size_bytes"), s.get("name")
        if not isinstance(url, str) or isinstance(size, bool) or not isinstance(size, int) or size <= 0 or not isinstance(name, str):
            return {"upload_refused": "upload_result_unreadable"}
        parts = urllib.parse.urlsplit(url)
        if ((parts.scheme, parts.netloc) != self.origin or parts.query or parts.fragment       # netloc carries any userinfo: compared whole
                or not UPLOAD_PATH.fullmatch(parts.path)):
            return {"upload_refused": "upload_url_not_from_amt_mcp"}                            # nothing will ever be sent to it
        ttl = s.get("expires_in_s")
        ttl = float(ttl) if isinstance(ttl, (int, float)) and not isinstance(ttl, bool) and 0 < ttl <= DEFAULT_TTL else DEFAULT_TTL
        uid = secrets.token_urlsafe(16)
        with self._lock:
            self._prune()
            while len(self._offers) >= MAX_OFFERS:
                del self._offers[min(self._offers, key=lambda k: self._offers[k]["expires"])]
            self._offers[uid] = {"url": url, "size": size, "expires": self.now() + ttl}
        return {"upload_id": uid, "name": name[:200], "size_bytes": size, "expires_in_s": int(ttl)}

    def _prune(self) -> None:
        now = self.now()
        for k in [k for k, o in self._offers.items() if o["expires"] <= now]:
            del self._offers[k]

    # -- sending ---------------------------------------------------------------------------------------------------
    def stream(self, uid: str, length: int, read) -> dict:
        """Copy ``length`` bytes from ``read(n)`` to the offer's url. Raises UploadError before anything is sent (unknown or expired id, a
        length that is not the declared size, amt-mcp unreachable); the id then stays usable. Otherwise returns the reply for the browser:
        ``{"ok": True, "name", "bytes", "sha256"}`` for amt-mcp's 201, ``{"ok": False, "status", "text"}`` for its refusal (verbatim), or
        ``{"ok": False, "code": "browser_stream_ended_early", "sent"}`` when the browser stopped before the whole file arrived. The id is
        used up the moment the first byte goes."""
        with self._lock:
            self._prune()
            offer = self._offers.get(uid)
        if offer is None:
            raise UploadError("unknown_upload", 404)
        if length != offer["size"]:
            raise UploadError("size_not_the_declared_size", 400)
        parts = urllib.parse.urlsplit(offer["url"])
        cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        conn = cls(parts.hostname, parts.port, timeout=UPSTREAM_TIMEOUT)
        try:
            try:
                conn.connect()
            except OSError as ex:
                raise UploadError(f"amt_mcp_unreachable:{type(ex).__name__}", 502) from None
            with self._lock:
                if self._offers.pop(uid, None) is None:           # a second stream for the same id lost the race
                    raise UploadError("unknown_upload", 404)
            return self._send(conn, parts.path, length, read)
        finally:
            conn.close()

    @staticmethod
    def _send(conn, path: str, length: int, read) -> dict:
        try:
            conn.putrequest("PUT", path, skip_accept_encoding=True)
            conn.putheader("Content-Length", str(length))
            conn.putheader("Content-Type", "application/octet-stream")
            conn.endheaders()
            sent = 0
            while sent < length:
                chunk = read(min(CHUNK, length - sent))
                if not chunk:
                    return {"ok": False, "code": "browser_stream_ended_early", "sent": sent, "size_bytes": length}
                conn.send(chunk)
                sent += len(chunk)
            resp = conn.getresponse()
            status, ctype, body = resp.status, resp.getheader("Content-Type", ""), resp.read(ANSWER_BYTES)
        except (OSError, http.client.HTTPException) as ex:
            return {"ok": False, "code": f"amt_mcp_unreachable:{type(ex).__name__}", "sent": None, "size_bytes": length}
        text = captures.mask_one_time_urls(body.decode("utf-8", "replace"))
        if status == 201:
            try:
                got = json.loads(text) if ctype.startswith("application/json") else {}
            except ValueError:
                got = {}
            if isinstance(got, dict) and isinstance(got.get("sha256"), str):
                return {"ok": True, "name": str(got.get("name", ""))[:200], "bytes": got.get("bytes"), "sha256": got["sha256"]}
        return {"ok": False, "status": status, "text": text[:600]}
