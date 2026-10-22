"""The files the tools have written: screenshots, finished mirror recordings, finished serial casts.

``amt_captures`` lists them (newest first, paged) and hands one back as a fresh one-time download
url through ``amt_handoff``, the same route a tool result already uses. It reads two folders only:
the screenshot directory (``AMT_SHOT_DIR``, via ``amt_tools``) and the recording directory
(``amt_mirror.recording_dir``). A file is listed only when its NAME has the shape a tool gives its
own output and it is a regular file, never a symlink, so a fetch can never name a path outside
those folders: the caller sends a bare name, and that name is looked up in the listing, never
joined onto a path. An unfinished file (a recording still being written, an MP4 still being
encoded) is not listed.
"""
from __future__ import annotations

import asyncio
import os
import re
import stat
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field

import amt_handoff
import amt_mirror
import amt_serial
import amt_tools

_DEV = r"(?P<device>[a-z0-9][a-z0-9-]*)"
# Name shapes, one per writer: amt_tools._create_private_png, amt_mirror.Mirror.record_start (after
# the encode renames .mjpeg to .mp4) and amt_serial.Terminal.record_start.
PATTERNS = (
    ("screenshot", re.compile(rf"amt-{_DEV}-\d{{8}}T\d{{12}}Z-[0-9a-f]{{16}}\.png")),
    ("recording", re.compile(rf"amt-{_DEV}-\d{{8}}T\d{{6}}Z\.mp4")),
    ("serial_cast", re.compile(rf"{_DEV}-serial-\d{{8}}T\d{{6}}\.\d{{6}}Z\.cast")),
)
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,200}")
DEFAULT_LIMIT = 50
MAX_LIMIT = 200


def _plain_dir(path: Path, follow: bool) -> bool:
    try:
        st = os.stat(path) if follow else os.lstat(path)
    except OSError:
        return False
    return stat.S_ISDIR(st.st_mode)


def _live_casts() -> set[str]:
    """Paths of serial casts a live terminal is still writing."""
    out: set[str] = set()
    with amt_serial._LOCK:
        terms = list(amt_serial._TERMS.values())
    for term in terms:
        rec = term.recording
        if rec is not None:
            out.add(str(rec["path"]))
    return out


def _scan(directory: Path, kinds: tuple[str, ...], busy: set[str]) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    shapes = [(k, rx) for k, rx in PATTERNS if k in kinds]
    with os.scandir(directory) as it:
        for entry in it:
            for kind, rx in shapes:
                m = rx.fullmatch(entry.name)
                if m is None:
                    continue
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    break
                if not stat.S_ISREG(st.st_mode) or entry.path in busy:
                    break
                if kind == "recording" and os.path.lexists(entry.path[:-4] + ".mjpeg"):
                    break                      # still being encoded: the raw pair is deleted last
                found.append({"name": entry.name, "kind": kind, "device": m.group("device"),
                              "bytes": st.st_size, "mtime": st.st_mtime, "path": Path(entry.path)})
                break
    return found


def _index() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Every listed file (newest first) and the folders that were searched."""
    shots, recs = amt_tools._shot_dir(), amt_mirror.recording_dir()
    items: list[dict[str, Any]] = []
    searched: list[dict[str, Any]] = []
    busy = _live_casts()
    for directory, follow, kinds in ((shots, False, ("screenshot",)),
                                     (recs, True, ("recording", "serial_cast"))):
        ok = _plain_dir(directory, follow)
        searched.append({"dir": str(directory), "kinds": list(kinds), "found": ok})
        if ok:
            items += _scan(directory, kinds, busy)
    items.sort(key=lambda i: (-i["mtime"], i["name"]))
    return items, searched


def _public(item: dict[str, Any]) -> dict[str, Any]:
    return {"name": item["name"], "kind": item["kind"], "device": item["device"], "bytes": item["bytes"],
            "modified": datetime.fromtimestamp(item["mtime"], timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}


def captures(action: str, name: str | None, offset: int, limit: int) -> dict[str, Any]:
    items, searched = _index()
    if action == "list":
        page = items[offset:offset + limit]
        end = offset + len(page)
        return {"total": len(items), "offset": offset, "captures": [_public(i) for i in page],
                "next_offset": end if end < len(items) else None, "searched": searched}
    if action != "fetch":
        raise ValueError(f"unknown_captures_action:{action!r}")
    if not name:
        raise ValueError("capture_name_required: fetch takes one name from the list")
    if not _NAME.fullmatch(name):
        raise ValueError("capture_name_invalid: a bare file name from the list, no path")
    item = next((i for i in items if i["name"] == name), None)
    if item is None:
        raise ValueError(f"capture_not_found:{name}: not in the list; list shows what can be fetched")
    return {**_public(item), "path": str(item["path"]), **amt_handoff.describe(item["path"])}


async def amt_captures(
    action: Annotated[Literal["list", "fetch"], Field(
        description="list: the files the tools have written, newest first. fetch: a fresh one-time "
                    "download url for one of them.")] = "list",
    name: Annotated[str | None, Field(
        description="fetch: one file name exactly as list shows it (a bare name, never a path).")] = None,
    offset: Annotated[int, Field(ge=0, description="list: how many of the newest to skip.")] = 0,
    limit: Annotated[int, Field(
        ge=1, le=MAX_LIMIT, description=f"list: page size, at most {MAX_LIMIT}.")] = DEFAULT_LIMIT,
) -> dict:
    """Lists the screenshots, finished mirror recordings (.mp4) and finished serial casts (.cast)
    the tools have written, or fetches one. Read-only; touches no host. list returns name, kind,
    device, bytes and modified time, newest first, in pages (next_offset is null on the last), plus
    the folders it searched. fetch takes one name from that list and returns a fresh one-time download
    url with its sha256 (the url works once, 15 minutes); each fetch mints another, so it is not
    idempotent. A file still being written or encoded is not listed; a name outside the list is
    refused."""
    return await asyncio.to_thread(captures, action, name, offset, limit)


READ_TOOL_SPECS = (
    (amt_captures, "amt_captures", "AMT Captures"),
)
