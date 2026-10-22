"""Download handoffs: a file a tool wrote on the server, fetched once over HTTP.

Over HTTP the server's disk is not the caller's, so a returned path is useless to the caller.
When ``AMT_PUBLIC_BASE_URL`` is set (``scheme://host[:port]``, the address clients reach this
server at), a tool that writes a file also returns a one-time ``url``:
``GET <base>/handoffs/<token>`` returns the file once, then the token is dead.

The token (``secrets.token_urlsafe(32)``) is the only credential, like a pre-signed URL. It is
minted only into a bearer-gated tool result, works once, and expires after ``TTL_SECONDS``. The
route sits outside the bearer gate and the Host/Origin allowlist on purpose, so a plain GET (a
script, an extractor) can fetch it. The handoff is a hard link to the tool's file (a copy when
linking fails), so a fetch deletes the handoff and never the original.

Without a base URL (stdio, or HTTP left unconfigured) nothing is offered and the path stands.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import time
from pathlib import Path
from typing import Any

from starlette.background import BackgroundTask
from starlette.requests import Request
from starlette.responses import FileResponse, PlainTextResponse, Response

BASE_URL_ENV = "AMT_PUBLIC_BASE_URL"
STATE_DIR_ENV = "AMT_STATE_DIR"     # same variable amt_write reads; default ~/.amt-mcp
ROUTE = "/handoffs/{token}"
TTL_SECONDS = 900
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]{43}")
_NO_STORE = {"Cache-Control": "no-store"}


def base_url() -> str | None:
    """The configured public base URL without a trailing slash, or None when unset or not
    http(s)."""
    value = os.environ.get(BASE_URL_ENV, "").strip().rstrip("/")
    return value if re.fullmatch(r"https?://[^/\s]+", value) else None


def _dir() -> Path:
    """The handoff directory, created 0700; refuses a symlink, a non-directory or another
    owner's directory, as the screenshot directory does."""
    d = Path(os.environ.get(STATE_DIR_ENV) or Path.home() / ".amt-mcp") / "handoffs"
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        d.parent.mkdir(parents=True, exist_ok=True)
        os.mkdir(d, 0o700)
        st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid():
        raise PermissionError("handoff_dir_unsafe")
    return d


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _reap(d: Path, now: float) -> None:
    """Delete handoffs past their expiry that nobody fetched."""
    for meta in d.glob("*.json"):
        try:
            expired = json.loads(meta.read_text())["expires"] < now
        except (OSError, ValueError, KeyError, TypeError):
            expired = True
        if expired:
            (d / meta.stem).unlink(missing_ok=True)
            meta.unlink(missing_ok=True)


def offer(path: str | Path) -> dict[str, Any]:
    """Register ``path`` for one fetch and return ``url``, ``sha256`` and ``expires_in_s``; an
    empty dict when no base URL is configured."""
    base = base_url()
    if base is None:
        return {}
    src = Path(path)
    d = _dir()
    now = time.time()
    _reap(d, now)
    token = secrets.token_urlsafe(32)
    target = d / token
    try:
        os.link(src, target)
    except OSError:
        shutil.copyfile(src, target)
    os.chmod(target, 0o600)   # through a link this tightens the tool's file too, never loosens it
    digest = _sha256(target)
    meta = {"name": src.name, "sha256": digest, "bytes": target.stat().st_size,
            "expires": now + TTL_SECONDS}
    fd = os.open(d / f"{token}.json", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(meta, fh)
    return {"url": f"{base}/handoffs/{token}", "sha256": digest, "expires_in_s": TTL_SECONDS,
            "url_note": "fetch once with a plain GET; the token in the url is its only key"}


def describe(path: str | Path) -> dict[str, Any]:
    """The retrieval fields for a file a tool wrote: a one-time url when offered, else a note."""
    return offer(path) or {
        "path_note": f"path on the server's disk; set {BASE_URL_ENV} to also get a one-time url"}


async def download(request: Request) -> Response:
    """GET /handoffs/<token>: the file once, then 404. Unknown, malformed or expired: 404."""
    token = request.path_params.get("token", "")
    missing = PlainTextResponse("not found", status_code=404, headers=_NO_STORE)
    if not _TOKEN_RE.fullmatch(token):
        return missing
    d = _dir()
    claimed = d / f".{token}.claimed"
    meta_path = d / f"{token}.json"
    try:
        os.rename(d / token, claimed)   # atomic claim: a second or concurrent fetch finds nothing
    except FileNotFoundError:
        return missing
    try:
        meta = json.loads(meta_path.read_text())
        live = meta["expires"] >= time.time()
    except (OSError, ValueError, KeyError, TypeError):
        meta, live = {}, False
    meta_path.unlink(missing_ok=True)
    if not live:
        claimed.unlink(missing_ok=True)
        return missing
    return FileResponse(claimed, filename=meta.get("name") or token, headers=_NO_STORE,
                        background=BackgroundTask(claimed.unlink, missing_ok=True))


def register(server) -> None:
    """Mount the download route on ``server`` (served only by the HTTP app)."""
    server.custom_route(ROUTE, methods=["GET"])(download)
