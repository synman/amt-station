"""The capture store: files amt-mcp's tools wrote, fetched ONCE through their one-time handoff url.

A tool result that carries a handoff (``url`` + ``sha256``) is ingested here by the console backend:
the url is fetched exactly once, immediately, the body's SHA-256 is compared with the tool's, and only
a matching body is kept. The browser never sees the url or its token (the caller strips it); it sees the
capture record and downloads the file from the console's own authenticated route. A link that is gone by
the time it is fetched is recorded as ``expired``, never silently missing.

Files and records live under ``<AMT_CONSOLE_DATA>/captures`` (0600 in a 0700 folder) and are deleted
after ``retention_hours`` (24 by default). The url is never stored or logged: only its SHA-256, so the
same url is not fetched twice.
"""
from __future__ import annotations

import hashlib
import http.client
import json
import logging
import os
import re
import secrets
import threading
import time
import urllib.parse
from pathlib import Path

import mcp_client

log = logging.getLogger("amt_console.captures")

HANDOFF_PATH = re.compile(r"/handoffs/[A-Za-z0-9_-]{43}")
# Every url whose last path segment is a one-time token: a download handoff (43 characters), an upload or an
# intake url (43), a mirror or serial viewer url (``/m/`` and ``/s/``, 32). The scheme and host are optional so a
# bare path is masked too; a masked path that was not a token url costs nothing, an unmasked token costs the lot.
ONE_TIME_URL = re.compile(r"(?:https?://[^\s\"'<>]*)?/(?:handoffs|uploads|intake|m|s)/[A-Za-z0-9_-]{32,}/?")
MAX_BYTES = 1 << 30
FETCH_TIMEOUT = 60.0
_CONTENT_TYPES = {".png": "image/png", ".jpg": "image/jpeg", ".mp4": "video/mp4"}


def is_handoff(result: object) -> bool:
    """A result dict that offers a one-time download: a string ``url`` on a handoff path and a ``sha256``."""
    return (isinstance(result, dict) and isinstance(result.get("url"), str) and isinstance(result.get("sha256"), str)
            and bool(HANDOFF_PATH.search(urllib.parse.urlsplit(result["url"]).path)))


def mask_one_time_urls(text: str) -> str:
    return ONE_TIME_URL.sub("[one-time url withheld]", text)


def _safe_name(name: object) -> str:
    base = os.path.basename(str(name or "")).strip()
    base = re.sub(r"[^\w.\- ]", "_", base)[:120]
    return base or "capture"


class CaptureStore:
    def __init__(self, folder: str | Path, handoff_origin: str, retention_hours: float = 24.0, now=time.time):
        self.dir = Path(folder)
        parts = urllib.parse.urlsplit(handoff_origin)
        self.origin = (parts.scheme, parts.netloc)
        self.retention = retention_hours * 3600
        self.now = now
        self._lock = threading.Lock()
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)

    # -- records --------------------------------------------------------------------------------------------
    def _meta_path(self, cid: str) -> Path:
        return self.dir / f"{cid}.json"

    def _write_meta(self, meta: dict) -> None:
        tmp = self.dir / f".{meta['id']}.{secrets.token_hex(4)}.tmp"
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(meta, fh)
        os.replace(tmp, self._meta_path(meta["id"]))

    def _records(self) -> list[dict]:
        out = []
        for path in self.dir.glob("*.json"):
            try:
                out.append(json.loads(path.read_text()))
            except (OSError, ValueError):
                continue
        return out

    def sweep(self) -> None:
        """Delete every record and file older than the retention."""
        cutoff = self.now() - self.retention
        for meta in self._records():
            if meta.get("taken_at", 0) < cutoff:
                self._meta_path(meta["id"]).unlink(missing_ok=True)
                (self.dir / f"{meta['id']}.bin").unlink(missing_ok=True)

    def list(self) -> list[dict]:
        """Public records, newest first; never the url hash."""
        with self._lock:
            self.sweep()
            recs = sorted(self._records(), key=lambda m: m["taken_at"], reverse=True)
        return [self._public(m) for m in recs]

    @staticmethod
    def _public(meta: dict) -> dict:
        return {k: meta[k] for k in ("id", "name", "status", "reason", "sha256", "bytes", "taken_at", "expires_at") if k in meta}

    def get(self, cid: str) -> tuple[dict, Path] | None:
        """(record, file) for a stored, verified capture; None for anything else (including a malformed id)."""
        if not re.fullmatch(r"[A-Za-z0-9_-]{22}", cid or ""):
            return None
        with self._lock:
            self.sweep()
            try:
                meta = json.loads(self._meta_path(cid).read_text())
            except (OSError, ValueError):
                return None
            path = self.dir / f"{cid}.bin"
            if meta.get("status") != "ready" or not path.is_file():
                return None
            return meta, path

    @staticmethod
    def content_type(name: str) -> str:
        return _CONTENT_TYPES.get(os.path.splitext(name)[1].lower(), "application/octet-stream")

    # -- ingest ---------------------------------------------------------------------------------------------
    def ingest(self, result: dict) -> dict:
        """Fetch the result's handoff once and keep it; returns the public record (status ready/expired/failed)."""
        url, want = result["url"], result["sha256"].lower()
        urlhash = hashlib.sha256(url.encode()).hexdigest()
        name = _safe_name(result.get("name") or result.get("path"))
        with self._lock:
            self.sweep()
            for meta in self._records():
                if meta.get("urlhash") == urlhash:            # the same one-time link is never fetched twice
                    return self._public(meta)
            meta = {"id": secrets.token_urlsafe(16), "name": name, "sha256": want, "taken_at": int(self.now()),
                    "expires_at": int(self.now() + self.retention), "urlhash": urlhash}
            self._fetch(url, want, meta)
            self._write_meta(meta)
            return self._public(meta)

    def _fetch(self, url: str, want: str, meta: dict) -> None:
        parts = urllib.parse.urlsplit(url)
        if ((parts.scheme, parts.netloc) != self.origin or parts.query or parts.fragment
                or not HANDOFF_PATH.fullmatch(parts.path)):       # netloc carries any userinfo, so it is compared whole
            meta.update(status="failed", reason="handoff_url_not_from_amt_mcp")   # nothing is fetched
            return
        if not re.fullmatch(r"[0-9a-f]{64}", want):
            meta.update(status="failed", reason="result_sha256_malformed")
            return
        target = self.dir / f"{meta['id']}.bin"
        try:
            resp = mcp_client.http_request(url, "GET", {"Accept": "*/*"}, None, FETCH_TIMEOUT)
        except mcp_client.McpError as ex:
            meta.update(status="failed", reason=str(ex))
            return
        try:
            if resp.status in (404, 410):
                meta.update(status="expired", reason="not fetched within 15 minutes")
                return
            if resp.status != 200:
                meta.update(status="failed", reason=f"fetch_status_{resp.status}")
                return
            got, size = self._save(resp, target)
        except (OSError, http.client.HTTPException) as ex:
            target.unlink(missing_ok=True)
            meta.update(status="failed", reason="too_large" if str(ex) == "too_large" else f"fetch_failed:{type(ex).__name__}")
            return
        finally:
            mcp_client.close_response(resp)
        if got != want:
            target.unlink(missing_ok=True)
            meta.update(status="failed", reason="sha256_mismatch")
            return
        meta.update(status="ready", bytes=size)

    @staticmethod
    def _save(resp, target: Path) -> tuple[str, int]:
        """Stream the body into ``target`` (created exclusively, 0600); returns (sha256 hex, size)."""
        digest, size = hashlib.sha256(), 0
        with os.fdopen(os.open(target, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600), "wb") as fh:
            while chunk := resp.read(1 << 20):
                size += len(chunk)
                if size > MAX_BYTES:
                    raise OSError("too_large")
                digest.update(chunk)
                fh.write(chunk)
        return digest.hexdigest(), size
