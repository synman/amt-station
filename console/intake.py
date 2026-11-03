"""The identity intake's backend (packet C7): an entry's new value goes from the operator's browser to amt-mcp's one-time
``PUT /intake/<token>`` url THROUGH the console, and neither the url nor the value is kept, logged or returned.

``amt_identity_manage`` with ``action: "intake"`` mints the url. The console makes that ``tools/call`` itself (``server._tool_call``) and
hands the result to ``Intakes.register``, which keeps the url in memory and gives the browser an opaque ``intake_id`` instead. The browser
then posts the value to ``/api/identities/intake/<intake_id>``; ``Intakes.send`` checks it is one line of UTF-8 within the offer's size,
PUTs it to the url once and returns amt-mcp's answer. The value exists in this process for the length of that request only: nothing is
written, no log line or exception carries it, and an answer that happens to contain it is withheld.

The id is used up the moment the PUT starts (amt-mcp's url dies with its first request too); a refusal made here, before anything is sent,
keeps it. An id lives as long as amt-mcp says the url does (at most 15 minutes).
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
from images import UploadError

INTAKE_PATH = re.compile(r"/intake/[A-Za-z0-9_-]{43}")
UPSTREAM_TIMEOUT = 30.0
MAX_OFFERS = 16
DEFAULT_TTL = 900.0                      # amt_upload.TTL_SECONDS: an offer unused for this long is gone upstream
DEFAULT_MAX_BYTES = 4096                 # amt_upload.INTAKE_MAX_BYTES
ANSWER_BYTES = 4096


class Intakes:
    def __init__(self, amt_origin: str, now=time.time):
        parts = urllib.parse.urlsplit(amt_origin)
        self.origin = (parts.scheme, parts.netloc)
        self.now = now
        self._offers: dict[str, dict] = {}
        self._lock = threading.Lock()

    # -- minting ---------------------------------------------------------------------------------------------------
    def register(self, structured) -> dict:
        """What the browser may know about a successful ``intake`` result: ``{"intake_id", "name", "max_bytes", "expires_in_s"}``, or
        ``{"intake_refused": code}`` when the result carries no usable url. The url is kept here and nowhere else."""
        s = structured if isinstance(structured, dict) else {}
        url, name = s.get("url"), s.get("name")
        if not isinstance(url, str) or not isinstance(name, str):
            return {"intake_refused": "intake_result_unreadable"}
        parts = urllib.parse.urlsplit(url)
        if ((parts.scheme, parts.netloc) != self.origin or parts.query or parts.fragment       # netloc carries any userinfo: compared whole
                or not INTAKE_PATH.fullmatch(parts.path)):
            return {"intake_refused": "intake_url_not_from_amt_mcp"}                            # nothing will ever be sent to it
        ttl, cap = s.get("expires_in_s"), s.get("max_bytes")
        ttl = float(ttl) if isinstance(ttl, (int, float)) and not isinstance(ttl, bool) and 0 < ttl <= DEFAULT_TTL else DEFAULT_TTL
        cap = cap if isinstance(cap, int) and not isinstance(cap, bool) and 0 < cap <= DEFAULT_MAX_BYTES else DEFAULT_MAX_BYTES
        iid = secrets.token_urlsafe(16)
        with self._lock:
            self._prune()
            while len(self._offers) >= MAX_OFFERS:
                del self._offers[min(self._offers, key=lambda k: self._offers[k]["expires"])]
            self._offers[iid] = {"url": url, "cap": cap, "expires": self.now() + ttl}
        return {"intake_id": iid, "name": name[:200], "max_bytes": cap, "expires_in_s": int(ttl)}

    def _prune(self) -> None:
        now = self.now()
        for k in [k for k, o in self._offers.items() if o["expires"] <= now]:
            del self._offers[k]

    # -- sending ---------------------------------------------------------------------------------------------------
    def send(self, iid: str, length: int, read) -> dict:
        """Read ``length`` bytes with ``read(n)`` and PUT them to the offer's url once. Raises UploadError before anything is sent (unknown or
        expired id, a value that is empty, too long, short, not UTF-8 or not one line, amt-mcp unreachable); the id then stays usable.
        Otherwise returns the reply for the browser: ``{"ok": True, "name"}`` for amt-mcp's 201, ``{"ok": False, "status", "text"}`` for its
        refusal, or ``{"ok": False, "code"}`` when amt-mcp stopped answering mid-request (whether it stored the value is then unknown)."""
        with self._lock:
            self._prune()
            offer = self._offers.get(iid)
        if offer is None:
            raise UploadError("unknown_intake", 404)
        if not 0 < length <= offer["cap"]:
            raise UploadError("value_size_out_of_range", 400)
        raw = read(length)
        if not isinstance(raw, bytes) or len(raw) != length:
            raise UploadError("value_incomplete", 400)
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise UploadError("value_not_utf8", 400) from None
        if any(c in text for c in "\r\n\x00"):
            raise UploadError("value_has_a_line_break_or_nul", 400)
        parts = urllib.parse.urlsplit(offer["url"])
        cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
        conn = cls(parts.hostname, parts.port, timeout=UPSTREAM_TIMEOUT)
        try:
            try:
                conn.connect()
            except OSError as ex:
                raise UploadError(f"amt_mcp_unreachable:{type(ex).__name__}", 502) from None
            with self._lock:
                if self._offers.pop(iid, None) is None:           # a second send for the same id lost the race
                    raise UploadError("unknown_intake", 404)
            return self._put(conn, parts.path, raw, text)
        finally:
            conn.close()

    @staticmethod
    def _put(conn, path: str, raw: bytes, value: str) -> dict:
        try:
            conn.request("PUT", path, body=raw, headers={"Content-Type": "application/octet-stream"})
            resp = conn.getresponse()
            status, body = resp.status, resp.read(ANSWER_BYTES)
        except (OSError, http.client.HTTPException) as ex:
            return {"ok": False, "code": f"amt_mcp_unreachable:{type(ex).__name__}"}
        text = captures.mask_one_time_urls(body.decode("utf-8", "replace"))
        if status == 201:                                          # a stored reply is read before the echo check: a short value is a substring of {"stored": true, ...}
            try:
                got = json.loads(text)
            except ValueError:
                got = {}
            if isinstance(got, dict) and got.get("stored") is True:
                return {"ok": True, "name": str(got.get("name", ""))[:200]}      # only the name goes back, never the body
        if value in text:
            text = "[answer withheld: it contained the value]"
        return {"ok": False, "status": status, "text": text[:600]}
