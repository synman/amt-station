"""The fleet's status, read for the browser: one cached entry per server, refreshed on a schedule the console owns.

Each server is read with ``amt_status`` plus the three session views (``amt_mirror_link``, ``amt_serial_link`` and
``amt_ider`` with ``action: "status"``), every one a ``tools/call`` through ``mcp_client`` (read-only, device named).
The reads are staggered across the interval (n servers are n reads spread over ``interval`` seconds, never a burst)
and run only while a page is looking: the poller stops two intervals after the last request for the fleet and starts
again on the next one, so a closed browser costs the host nothing.

A refused credential or a changed TLS leaf pauses the server (design note 2.2, review M9): ``wsman_auth_failed_401``
is one Digest attempt that failed, and a second would count toward an account lockout, so a paused server is never
read automatically again. It resumes when its pin is replaced (``amt_devices``), its identity is replaced
(``amt_identities`` ``updated_at`` moves) or the operator retries once and that read succeeds.

Only whitelisted fields of a tool result reach the browser: a viewer url or token in a session view is never copied.
"""
from __future__ import annotations

import json
import logging
import os
import re
import secrets
import threading
import time
from pathlib import Path

import captures
import mcp_client

log = logging.getLogger("amt_console.fleet")

DEFAULT_INTERVAL = 30.0
HELD_OTHER_TTL = 300.0                       # seconds a refused KVM open keeps the "another client" chip
ALREADY_LIVE = "already live; returning the existing link"   # a mirror or terminal start that found a session already running
PAUSE_MARKERS = (("wsman_auth_failed_401", "credential refused"), ("tls_leaf_pin_mismatch", "pin differs"))
UNPINNED_MARKER = "tls_leaf_unpinned_refused"
# A busy host as amt-mcp really reports it is the redirection start reply's non-zero status ("redir_start_status_N", amt_kvm.py and
# amt_redir.py); "another session is open" is the tool docstrings' and the design note's wording of that refusal. Which N a busy
# host answers has not been read live, so any non-zero start status on a KVM-opening call counts as a refused open.
HELD_OTHER_RE = re.compile(r"another (?:redirection )?session (?:is )?open|redir_start_status_[1-9]\d*", re.I)
POWER_KINDS = {"on": "on", "sleep_light": "sleep", "sleep_deep": "sleep", "hibernate": "sleep",
               "off_hard": "off", "off_soft": "off"}
POWER_LABELS = {"on": "On", "sleep_light": "Sleep", "sleep_deep": "Deep sleep", "hibernate": "Hibernate",
                "off_hard": "Off", "off_soft": "Off"}
KEY_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")


# -- reading a tool result -------------------------------------------------------------------------------------------

def result_object(result: mcp_client.Result):
    """The result's structured value (mcp_client parses a text-only result), else None."""
    return result.structured if isinstance(result.structured, (dict, list)) else None


def _str(v, limit=300):
    """A tool's string as the browser may see it: one-time urls withheld, then cut (``clip``). Every string the readers below
    keep goes through here or ``_scalars``, so a session view's ``error`` or a ``next_boot`` field is masked like the status errors."""
    return clip(v, limit) if isinstance(v, str) else None


def _scalars(d, limit=60) -> dict:
    """The JSON scalars of a dict (nested values dropped), bounded; strings masked, then cut."""
    if not isinstance(d, dict):
        return {}
    out = {}
    for k, v in list(d.items())[:limit]:
        if isinstance(k, str) and (v is None or isinstance(v, (bool, int, float)) or isinstance(v, str)):
            out[k[:80]] = _str(v) if isinstance(v, str) else v
    return out


def _masked(v):
    """A tool's error text as the browser may see it: any one-time url (a handoff, upload, intake or viewer path) withheld,
    the tool's other words kept. Two places apply it: ``clip`` masks, then cuts, the text as it is stored (``classify_error``
    still reads its markers, which the mask leaves), and ``Fleet.public`` and ``Fleet.snapshot`` mask again on the way out, so
    a text stored by any path that forgot ``clip`` is still withheld from the browser."""
    return captures.mask_one_time_urls(v) if isinstance(v, str) else v


def clip(text, limit: int) -> str:
    """A tool's words cut to ``limit`` characters AFTER any one-time url is withheld: cut first and a token the cut lands in the
    middle of is too short to match, and its first characters reach the browser."""
    return _masked(text)[:limit]


def _names(v) -> list:
    return [x[:120] for x in v[:50] if isinstance(x, str)] if isinstance(v, list) else []


SECTION_KEYS = {
    "power": ("state", "code"), "amt": ("version", "build_number", "sku"),
    "provisioning": ("mode", "mode_code", "state", "state_code", "control_mode", "control_mode_code", "zero_touch_enabled"),
    "redirection": ("listener_enabled", "enabled_state_code", "sol_enabled", "ider_enabled"),
    "kvm": ("state", "state_code", "enabled", "port_5900_enabled", "session_timeout"),
    "user_consent": ("required_for", "required_code", "state", "state_code", "can_modify_policy")}


def _keys(d, section: str) -> dict:
    """The named keys of one section of a status result, as scalars; any other key is dropped."""
    return {k: v for k, v in _scalars(d).items() if k in SECTION_KEYS[section]}


def clean_status(obj) -> dict | None:
    """The fields of an ``amt_status`` result the status page shows. Anything else is dropped; ``next_boot`` is the
    device's own boot-settings object, so its scalar fields (whatever they are) are kept."""
    if not isinstance(obj, dict) or not isinstance(obj.get("power"), dict):
        return None
    redirection = obj.get("redirection") if isinstance(obj.get("redirection"), dict) else {}
    reasons = obj.get("unavailable_reasons") if isinstance(obj.get("unavailable_reasons"), dict) else {}
    return {"power": _keys(obj["power"], "power"), "amt": _keys(obj.get("amt"), "amt"), "provisioning": _keys(obj.get("provisioning"), "provisioning"),
            "redirection": {**_keys(redirection, "redirection"), "kvm": _keys(redirection.get("kvm"), "kvm")},
            "user_consent": _keys(obj.get("user_consent"), "user_consent"), "next_boot": _scalars(obj.get("next_boot")),
            "unavailable": _names(obj.get("unavailable")), "truncated": _names(obj.get("truncated")),
            "unavailable_reasons": {k[:120]: v[:200] for k, v in reasons.items() if isinstance(k, str) and isinstance(v, str)}}


def _pick(obj, list_key: str, device: str):
    """One device's view from a session status result. The tool answers with the device's own dict for a named
    non-default device and with a list of every live view for its default, so both shapes are read."""
    if not isinstance(obj, dict):
        return None
    if list_key in obj:
        for m in obj[list_key] or []:
            if isinstance(m, dict) and m.get("device") == device:
                return m
        return {"device": device, "live": False}
    return obj


def _recording(rec) -> dict | None:
    if not isinstance(rec, dict):
        return None
    return {k: rec[k] for k in ("frames", "bytes", "seconds", "started") if isinstance(rec.get(k), (int, float))}


def _in_flight(v) -> dict | None:
    if not isinstance(v, dict):
        return None
    return {"tool": _str(v.get("tool"), 80), "started_at": v.get("started_at") if isinstance(v.get("started_at"), (int, float)) else None}


def clean_mirror(obj, device: str, now: float) -> dict:
    m = _pick(obj, "mirrors", device)
    if not isinstance(m, dict) or m.get("live") is not True:
        return {"live": False}
    up = m.get("uptime_s") if isinstance(m.get("uptime_s"), (int, float)) else None
    return {"live": True, "since": now - up if up is not None else None, "fps": m.get("fps"), "viewers": m.get("viewers"),
            "width": m.get("width"), "height": m.get("height"), "last_frame_age_s": m.get("last_frame_age_s"),
            "in_flight": _in_flight(m.get("in_flight")), "recording": _recording(m.get("recording")),
            "recording_dir": _str(m.get("recording_dir")), "error": _str(m.get("error"))}


def clean_terminal(obj, device: str, now: float) -> dict:
    t = _pick(obj, "terminals", device)
    if not isinstance(t, dict) or t.get("live") is not True:
        return {"live": False}
    up = t.get("uptime_s") if isinstance(t.get("uptime_s"), (int, float)) else None
    return {"live": True, "since": now - up if up is not None else None, "viewers": t.get("viewers"),
            "in_flight": _in_flight(t.get("in_flight")), "recording": _recording(t.get("recording")),
            "recording_dir": _str(t.get("recording_dir")), "error": _str(t.get("error"))}


def clean_ider(obj) -> dict:
    if not isinstance(obj, dict) or obj.get("mounted") is not True:
        return {"mounted": False}
    images = obj.get("images") if isinstance(obj.get("images"), dict) else {}
    return {"mounted": True, "images": {k: v for k, v in images.items() if k in ("iso", "floppy") and isinstance(v, str)},
            "error": _str(obj.get("error"))}


def classify_error(text: str) -> tuple[str, str | None]:
    """('paused', reason) for a refused credential or a changed leaf, ('unpinned', None), else ('error', None)."""
    for marker, reason in PAUSE_MARKERS:
        if marker in text:
            return "paused", reason
    if UNPINNED_MARKER in text:
        return "unpinned", None
    return "error", None


# -- the fleet -------------------------------------------------------------------------------------------------------

class Fleet:
    def __init__(self, client, *, interval: float = DEFAULT_INTERVAL, state_path: str | Path | None = None,
                 now=time.time, poll: bool = True, sleep=time.sleep):
        self.mcp, self.interval, self.now, self.poll, self._sleep = client, interval, now, poll, sleep
        self._lock = threading.RLock()
        self._busy: dict[str, threading.Lock] = {}
        self.devices: dict[str, dict] = {}
        self.order: list[str] = []
        self.entries: dict[str, dict] = {}
        self.devices_error: str | None = None
        self.devices_at: float | None = None                   # the last successful list
        self.devices_tried_at: float | None = None             # the last attempt, good or bad (a failing list is not retried every second)
        self.seen_at: float | None = None
        self._thread: threading.Thread | None = None
        self._stop = False
        self.refused: dict[str, dict] = {}
        self.state_path = Path(state_path) if state_path else None
        self.started: dict[str, float] = self._load_started()
        self.ider_start: dict[str, str] = {}                   # device -> the start mode of the mount this console made (memory only)

    # -- sessions this console started ---------------------------------------------------------------------------
    def _load_started(self) -> dict[str, float]:
        if not self.state_path:
            return {}
        try:
            data = json.loads(self.state_path.read_text())
        except (OSError, ValueError):
            return {}
        return {k: v for k, v in data.items() if isinstance(k, str) and isinstance(v, (int, float))} if isinstance(data, dict) else {}

    def _save_started(self) -> None:
        if not self.state_path:
            return
        tmp = self.state_path.with_name(f".{self.state_path.name}.{secrets.token_hex(4)}.tmp")
        try:
            fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            with os.fdopen(fd, "w") as fh:
                json.dump(self.started, fh)
            os.replace(tmp, self.state_path)
        except OSError as ex:
            log.warning("sessions record not saved: %s", type(ex).__name__)
            tmp.unlink(missing_ok=True)

    def observe(self, tool: str, arguments: dict, is_error: bool, text: str) -> None:
        """A call made through this console: remember a mirror or terminal it started (the holder is "you" while that
        session lives) and a KVM-opening call that another client's session refused (the holder is "another client")."""
        device = arguments.get("device") if isinstance(arguments, dict) else None
        if not isinstance(device, str):
            return
        action = arguments.get("action")
        kind = {"amt_mirror_link": "mirror", "amt_serial_link": "terminal"}.get(tool)
        refused = is_error and "wsman_auth_failed_401" in (text or "")
        identity = self._identity_stamp(device) if refused and device in self.entries else None
        with self._lock:
            if refused and device in self.entries and self.entries[device]["state"] != "paused":
                self._pause(device, "credential refused", clip(text or "", 600), self.now(), identity)   # any call's 401 stops the automatic reads
            if kind and action in ("start", "stop") and not is_error:
                key = f"{kind}:{device}"
                if action == "start":
                    if ALREADY_LIVE not in (text or ""):                 # else the call returned a session already running: not ours
                        self.started[key] = self.now()
                else:
                    self.started.pop(key, None)
                self._save_started()
            if tool == "amt_ider" and action == "mount" and not is_error:
                self.started[f"ider:{device}"] = self.now()          # the mount's since; its start mode is kept beside it in memory
                self.ider_start[device] = arguments.get("start") if arguments.get("start") in ("next_boot", "graceful", "now") else "next_boot"
                self._save_started()                                 # a mount that has ended is dropped by the next session read
            if is_error and HELD_OTHER_RE.search(text or "") and (
                    tool == "amt_screenshot" or (tool == "amt_mirror_link" and action == "start")):
                self.refused[device] = {"at": self.now()}
            elif not is_error and (tool == "amt_screenshot" or (tool == "amt_mirror_link" and action == "start")):
                self.refused.pop(device, None)

    # -- the device list -----------------------------------------------------------------------------------------
    def refresh_devices(self) -> None:
        """Re-read the server list (amt_devices) and resume any paused server whose pin or identity was replaced."""
        with self._lock:
            self.devices_tried_at = self.now()
        try:
            res = self.mcp.call("amt_devices", {"action": "list"})
            obj = result_object(res)
            if res.is_error or not isinstance(obj, dict) or not isinstance(obj.get("devices"), list):
                raise mcp_client.McpError(clip(res.text or "amt_devices_failed", 300) if res.is_error else "amt_devices_bad_result")
        except mcp_client.McpError as ex:
            with self._lock:
                self.devices_error = clip(str(ex), 600)
            return
        listed = {}
        for d in obj["devices"]:
            if isinstance(d, dict) and isinstance(d.get("key"), str) and KEY_RE.fullmatch(d["key"]):
                listed[d["key"]] = {"key": d["key"], "address": _str(d.get("amt_ip"), 64), "pinned": d.get("pinned") is True,
                                    "leaf": _str(d.get("tls_leaf_sha256"), 64), "prefix": _str(d.get("tls_leaf_observed_prefix"), 32),
                                    "amt_vault_key": _str(d.get("amt_vault_key"), 80)}
        with self._lock:
            self.devices_error, self.devices_at = None, self.now()
            self.devices = listed
            self.order = list(listed)
            for gone in [k for k in self.entries if k not in listed]:
                del self.entries[gone]
            n = max(len(listed), 1)
            for i, key in enumerate(self.order):
                if key not in self.entries:
                    self.entries[key] = {"state": "loading", "read_at": None, "tried_at": None, "error": None, "paused": None,
                                         "pin": "unchecked", "status": None, "sessions": None, "sessions_error": None,
                                         "next_due": self.now() + i * self.interval / n}
        for key in list(listed):
            self._resume_if_replaced(key)

    def _pause(self, key: str, reason: str, err: str, now: float, identity) -> None:
        """Stop reading ``key`` automatically. A refused credential was refused over a TLS session whose leaf matched the pin; a
        changed leaf never got that far. Caller holds the lock."""
        entry = self.entries[key]
        entry.update(state="paused", error=err, pin="differs" if reason == "pin differs" else "matches",
                     paused={"reason": reason, "at": now, "leaf": self.devices.get(key, {}).get("leaf"), "identity": identity})

    def _identity_stamp(self, key: str):
        """The updated-at of the server's AMT identity (None when unknown or unreadable)."""
        name = self.devices.get(key, {}).get("amt_vault_key")
        try:
            res = self.mcp.call("amt_identities", {"device": key})
        except mcp_client.McpError:
            return None
        obj = result_object(res)
        if res.is_error or not isinstance(obj, dict):
            return None
        for row in obj.get("identities") or []:
            if isinstance(row, dict) and row.get("name") == name:
                return _str(row.get("updated_at"), 64)
        return None

    def _resume_if_replaced(self, key: str) -> None:
        with self._lock:
            entry = self.entries.get(key)
            paused = entry.get("paused") if entry else None
            if not paused:
                return
            leaf = self.devices[key]["leaf"]
        replaced = leaf != paused.get("leaf")
        if not replaced:
            stamp = self._identity_stamp(key)
            was = paused.get("identity")
            replaced = stamp is not None and was is not None and stamp != was     # no stamp at pause time: nothing to compare, no resume
        if replaced:
            with self._lock:
                entry["paused"], entry["state"], entry["next_due"] = None, "loading", self.now()

    # -- one server's read ---------------------------------------------------------------------------------------
    def _call(self, tool: str, arguments: dict):
        """(result object, error text, McpError?) of one read call."""
        try:
            res = self.mcp.call(tool, arguments)
        except mcp_client.McpError as ex:
            return None, clip(str(ex), 600), True
        if res.is_error:
            return None, clip(res.text or "tool error", 600), False
        return result_object(res), None, False

    def refresh(self, key: str) -> bool:
        """Read one server now (the schedule, or the operator's Retry). False when it was already being read."""
        with self._lock:
            if key not in self.entries:
                return False
            lock = self._busy.setdefault(key, threading.Lock())
        if not lock.acquire(blocking=False):
            return False
        try:
            self._read(key)
        finally:
            lock.release()
        return True

    def _read(self, key: str) -> None:
        now = self.now()
        obj, err, transport = self._call("amt_status", {"device": key})
        status = clean_status(obj) if err is None else None
        if err is None and status is None:
            err, transport = "amt_status returned no readable power section", False
        kind, reason = classify_error(err) if err is not None else ("ok", None)
        identity = self._identity_stamp(key) if kind == "paused" else None
        with self._lock:
            entry = self.entries.get(key)
            if entry is None:                                         # the server was removed while it was being read
                return
            entry["tried_at"], entry["next_due"] = now, now + self.interval
            if kind == "ok":
                entry.update(state="live", read_at=now, error=None, paused=None, pin="matches", status=status)
            elif kind == "paused":
                self._pause(key, reason, err, now, identity)
            else:
                entry["error"] = err
                entry["state"] = "unreachable"
                if kind == "unpinned":
                    entry["pin"] = "unpinned"
                elif entry["pin"] == "matches":
                    entry["pin"] = "unchecked"
            state = entry["state"]
        if state == "paused":
            return                                                    # no further reads of a refused server
        if transport:
            with self._lock:
                entry["sessions"], entry["sessions_error"] = None, err
            return
        self._read_sessions(key, now)

    def _read_sessions(self, key: str, now: float) -> None:
        mirror, e1, _ = self._call("amt_mirror_link", {"device": key, "action": "status"})
        term, e2, _ = self._call("amt_serial_link", {"device": key, "action": "status"})
        ider, e3, _ = self._call("amt_ider", {"device": key, "action": "status"})
        with self._lock:
            entry = self.entries.get(key)
            if entry is None:
                return
            for kind, view, failed in (("mirror", mirror, e1), ("terminal", term, e2)):
                live = isinstance(view, dict) and (_pick(view, "mirrors" if kind == "mirror" else "terminals", key) or {}).get("live") is True
                if not failed and not live and self.started.pop(f"{kind}:{key}", None) is not None:
                    self._save_started()                              # a session that ended on its own is no longer ours
            if not e3 and not (isinstance(ider, dict) and ider.get("mounted") is True):
                self.ider_start.pop(key, None)                        # a mount that ended is no longer ours
                if self.started.pop(f"ider:{key}", None) is not None:
                    self._save_started()
            errs = [e for e in (e1, e2, e3) if e]
            entry["sessions_error"] = "; ".join(errs)[:600] if errs else None
            entry["sessions"] = {
                "kvm": clean_mirror(mirror, key, now) if not e1 else None,
                "sol": clean_terminal(term, key, now) if not e2 else None,
                "ider": clean_ider(ider) if not e3 else None}

    def refresh_sessions(self, key: str) -> None:
        """Re-read one server's mirror, terminal and IDE-R views now: a start or stop went through the console, and the holder
        must not read "free" until the next scheduled pass. These are amt-mcp's own state, not a WS-MAN call, so a paused
        server's credential is not touched."""
        with self._lock:
            known = key in self.entries
        if known:
            self._read_sessions(key, self.now())

    def retry(self, key: str) -> bool:
        """The operator's Retry now / Retry once: one read, even of a paused server."""
        return self.refresh(key)

    # -- the schedule --------------------------------------------------------------------------------------------
    def _due(self) -> list:
        now = self.now()
        return [(e["next_due"], k) for k, e in self.entries.items() if e["state"] != "paused" and e["next_due"] <= now]

    def step(self) -> str | None:
        """Read the one server that is most overdue (never a paused one); returns its key, or None when none is due."""
        with self._lock:
            refresh = self.devices_tried_at is None or self.now() - self.devices_tried_at >= self.interval
        if refresh:
            self.refresh_devices()
        with self._lock:
            due = self._due()
        if not due:
            return None
        key = min(due)[1]
        self.refresh(key)
        return key

    def mark_all_due(self) -> None:
        """Refresh all: every server that is not paused becomes due now; the poller reads them in turn."""
        with self._lock:
            for e in self.entries.values():
                if e["state"] != "paused":
                    e["next_due"] = self.now()

    def touch(self) -> None:
        """A page asked for the fleet: keep the poller running."""
        with self._lock:
            self.seen_at = self.now()
            if self.poll and (self._thread is None or not self._thread.is_alive()):
                self._stop = False
                self._thread = threading.Thread(target=self._run, name="amt-console-fleet", daemon=True)
                self._thread.start()

    def _run(self) -> None:
        while not self._stop:
            with self._lock:
                idle = self.now() - (self.seen_at or 0) > 2 * self.interval
            if idle:
                return
            try:
                self.step()
            except Exception as ex:  # noqa: BLE001 - a fault in one pass must not end the poller
                log.error("fleet pass fault %s", type(ex).__name__)
            self._sleep(min(1.0, self.interval / 4))

    def stop(self) -> None:
        self._stop = True
        t = self._thread
        if t is not None and t is not threading.current_thread():
            t.join(timeout=5)

    # -- what the browser gets -----------------------------------------------------------------------------------
    def _holder(self, kind: str, device: str, view: dict | None, now: float) -> dict:
        if view is None:
            return {"holder": "unknown"}
        if view.get("live"):
            who = "console" if f"{kind}:{device}" in self.started else "agent"
            return {"holder": who, **{k: v for k, v in view.items() if k != "live"}}
        if kind == "mirror":
            seen = self.refused.get(device)
            if seen and now - seen["at"] <= HELD_OTHER_TTL:
                return {"holder": "other", "refused_at": seen["at"]}
        return {"holder": "free"}

    def _ider(self, key: str, view: dict | None) -> dict:
        """The mount view; while one is held, when this console made it (``since``) and with which start mode, if it did."""
        if view is None:
            return {"mounted": None}
        if view.get("mounted") is not True:
            return view
        out = dict(view)
        if f"ider:{key}" in self.started:
            out["since"] = self.started[f"ider:{key}"]
        if key in self.ider_start:
            out["start"] = self.ider_start[key]
        return out

    def public(self, key: str) -> dict | None:
        with self._lock:
            entry, dev = self.entries.get(key), self.devices.get(key)
            if entry is None or dev is None:
                return None
            now = self.now()
            st = entry["status"]
            code = (st or {}).get("power", {}).get("state")
            if entry["state"] == "unreachable":
                power = {"kind": "unreachable", "label": "Unreachable"}
            elif entry["state"] in ("paused", "loading") or st is None:
                power = {"kind": "unknown", "label": "Reading" if entry["state"] == "loading" else "Unknown"}
            else:
                power = {"kind": POWER_KINDS.get(code, "unknown"), "label": POWER_LABELS.get(code, "Unknown"),
                         "state": code, "code": st["power"].get("code")}
            sess = entry["sessions"]
            sessions = None
            if sess is not None:
                sessions = {"kvm": self._holder("mirror", key, sess["kvm"], now), "sol": self._holder("terminal", key, sess["sol"], now),
                            "ider": self._ider(key, sess["ider"])}
                for view in (sessions["kvm"], sessions["sol"]):
                    if isinstance(view.get("since"), (int, float)):
                        view["elapsed_s"] = max(0.0, now - view["since"])
                    if isinstance(view.get("refused_at"), (int, float)):
                        view["refused_age_s"] = max(0.0, now - view["refused_at"])
            return {"key": key, "address": dev["address"], "pinned": dev["pinned"], "leaf": dev["leaf"], "prefix": dev["prefix"],
                    "state": entry["state"], "power": power, "pin": "unpinned" if not dev["pinned"] else entry["pin"],
                    "read_at": entry["read_at"], "tried_at": entry["tried_at"], "error": _masked(entry["error"]),
                    "age_s": max(0.0, now - entry["read_at"]) if entry["read_at"] else None,
                    "next_in_s": max(0.0, entry["next_due"] - now) if entry["state"] != "paused" else None,
                    "paused": {"reason": entry["paused"]["reason"], "at": entry["paused"]["at"]} if entry["paused"] else None,
                    "status": st, "version": ((st or {}).get("amt") or {}).get("version"), "sessions": sessions,
                    "sessions_error": _masked(entry["sessions_error"])}

    def snapshot(self) -> dict:
        with self._lock:
            keys = list(self.order)
            now = self.now()
            err = self.devices_error
        return {"now": now, "interval": self.interval, "servers": [p for p in (self.public(k) for k in keys) if p],
                "devices_error": _masked(err), "loaded": self.devices_at is not None}


# -- past captures of one server --------------------------------------------------------------------------------------

PAGE = 200
MAX_PAGES = 10


def past_captures(client, store, key: str) -> dict:
    """The screenshots, recordings and casts amt-mcp lists for ``key`` (the tool has no device filter, so every page is
    read and filtered here), each joined to the capture store's record of the same name. Names the surface it covered."""
    items, searched, offset, listed, complete = [], [], 0, 0, False
    for _ in range(MAX_PAGES):
        res = client.call("amt_captures", {"action": "list", "offset": offset, "limit": PAGE})
        obj = result_object(res)
        if res.is_error or not isinstance(obj, dict) or not isinstance(obj.get("captures"), list):
            raise mcp_client.McpError(clip(res.text or "amt_captures_failed", 300) if res.is_error else "amt_captures_bad_result")
        for c in obj["captures"]:
            if isinstance(c, dict) and c.get("device") == key and isinstance(c.get("name"), str):
                items.append({"name": c["name"][:200], "kind": _str(c.get("kind"), 40), "bytes": c.get("bytes"),
                              "modified": _str(c.get("modified"), 40)})
        listed += len(obj["captures"])
        searched = [{"kinds": _names(s.get("kinds")), "found": s.get("found") is True} for s in obj.get("searched") or [] if isinstance(s, dict)]
        offset = obj.get("next_offset")
        if not isinstance(offset, int):
            complete = True
            break
    stored = {}
    for rec in store.list():                                      # newest first: keep the newest record per name
        stored.setdefault(rec["name"], rec)
    for item in items:
        rec = stored.get(item["name"])
        item["capture"] = {k: rec[k] for k in ("id", "status", "reason", "sha256", "bytes") if k in rec} if rec else None
    return {"captures": items, "listed": listed, "complete": complete, "searched": searched}
