"""Tools for amt-mcp: the six read tools (status, screenshot, inventory, logs, settings,
WS-MAN get) and the two composite WRITE tools (remote logon, remote logoff).

Every read tool here is read-only (``readOnlyHint: True``) and carries no ``confirmed`` guard
(``amt_screenshot`` additionally opens the host's single AMT redirection session; see its
description). The composite tools (``amt_remote_logon``, ``amt_remote_logoff``) are the
exception: ``readOnlyHint: False`` and a ``confirmed`` guard (see the section near the end).
Implementations are plain sync functions (``status``, ``screenshot``, ...) so tests can drive
them with a mocked transport; the ``amt_*`` coroutines are the registered tool surface and
push the blocking network work onto a thread so one slow AMT call never stalls the server.

Errors raise (FastMCP turns them into ``isError`` results); no tool returns a success that
carries an error field. The one structured exception is a composite tool's precondition abort
(``{"aborted": true, "reason": ...}``): the console was not the screen it may type into, so it
typed nothing, which is a refusal to act rather than a failure. Every AMT class name below that is not marked "proven" is the
documented AMT/CIM/IPS class chosen from the schema and is confirmed by a later live
read-verify, tagged ``TODO verify-live``.
"""
from __future__ import annotations

import asyncio
import base64
import hmac
import io
import json
import os
import re
import secrets
import shutil
import stat
import struct
import subprocess
import tempfile
import threading
import time
import weakref
from datetime import datetime, timezone
from pathlib import Path
from typing import Annotated, Any, Literal, NamedTuple

from pydantic import Field, StrictBool

import amt_gate
import amt_handoff
import amt_kvm
import amt_logdecode
import amt_registry
import amt_vault
import amt_wsman

DEFAULT_DEVICE = amt_wsman.DEFAULT_DEVICE
# Every tool takes the target host the same way: one optional ``device``, defaulting to AMT_DEFAULT_DEVICE.
DeviceParam = Annotated[str, Field(
    description=f"Registered device key; defaults to {DEFAULT_DEVICE}. The device must have a TLS pin.")]
SHOT_DIR_ENV = "AMT_SHOT_DIR"

# --- typed coercion ---------------------------------------------------------------------

# Fields that look numeric but are identifiers/labels: keep them as strings.
_KEEP_STR = re.compile(
    r"(Serial|PartNumber|Version|Tag$|InstanceID|DeviceID|Name$|Label|Caption|Description|"
    r"Address$|Identifier|Key$|String$|Manufacturer|Model|Domain|MAC|ID$)", re.I)
_INT = re.compile(r"-?(0|[1-9]\d{0,17})")


def typed(value: Any, key: str = "") -> Any:
    """Coerce WS-MAN text to bool/int where the field is a flag or a count; recurse."""
    if isinstance(value, dict):
        return {k: typed(v, k) for k, v in value.items()}
    if isinstance(value, list):
        return [typed(v, key) for v in value]
    if isinstance(value, str) and not _KEEP_STR.search(key):
        low = value.lower()
        if low in ("true", "false"):
            return low == "true"
        if _INT.fullmatch(value):
            return int(value)
    return value


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _label(mapping: dict[int, str], code: Any) -> str | None:
    if code is None:
        return None
    return mapping.get(code, f"unknown({code})")


def _password(device: str) -> str:
    """Resolve the AMT password ONCE per tool call (pin gate first); in-process only."""
    dev = amt_registry.get_device(device)
    return amt_wsman.resolve_password(dev, None)


class _Reads:
    """WS-MAN reads for one tool call: one resolved password, and a record of coverage.

    A SOAP Fault means the device does not expose THAT class: the class is listed in
    ``unavailable`` and the tool carries on. Auth, TLS-pin, unreachable and protocol errors
    are not class-specific and always propagate (swallowing them would hide a lockout or a
    man-in-the-middle behind an apparently normal partial result).
    """

    def __init__(self, device: str, password: str | None = None, *, tolerant: bool = True):
        self.device = device
        self.password = password if password is not None else _password(device)
        self.tolerant = tolerant
        self.unavailable: list[str] = []
        self.reasons: dict[str, str] = {}
        self.truncated: list[str] = []

    def _fault(self, cls: str, ex: amt_wsman.WsmanFault) -> None:
        if not self.tolerant:
            raise ex
        if cls not in self.unavailable:
            self.unavailable.append(cls)
        self.reasons[cls] = str(ex)[:200]

    def get(self, cls: str) -> dict[str, Any]:
        try:
            return typed(amt_wsman.get(cls, device=self.device, password=self.password))
        except amt_wsman.WsmanFault as ex:
            self._fault(cls, ex)
            return {}

    def enum(self, cls: str) -> list[dict[str, Any]]:
        try:
            items, truncated = amt_wsman.enumerate_(cls, device=self.device, password=self.password)
        except amt_wsman.WsmanFault as ex:
            self._fault(cls, ex)
            return []
        if truncated and cls not in self.truncated:
            self.truncated.append(cls)
        return [typed(i) for i in items]

    def coverage(self) -> dict[str, Any]:
        out: dict[str, Any] = {"unavailable": self.unavailable, "truncated": self.truncated}
        if self.reasons:
            out["unavailable_reasons"] = self.reasons
        return out


# --- amt_status -------------------------------------------------------------------------

POWER_STATES = {2: "on", 3: "sleep_light", 4: "sleep_deep", 6: "off_hard", 7: "hibernate", 8: "off_soft"}
PROVISIONING_MODES = {1: "enterprise", 4: "client"}
PROVISIONING_STATES = {0: "pre_provisioning", 1: "in_provisioning", 2: "post_provisioning"}
CONTROL_MODES = {0: "not_provisioned", 1: "client_control_mode", 2: "admin_control_mode"}
KVM_STATES = {2: "enabled", 3: "disabled", 6: "enabled_offline"}
OPT_IN_REQUIRED = {0: "none", 1: "kvm", 4294967295: "all"}
OPT_IN_STATES = {0: "not_started", 1: "requested", 2: "displayed", 3: "received", 4: "in_session"}
# AMT_RedirectionService.EnabledState: (ider, sol)
REDIRECTION_STATES = {32768: (False, False), 32769: (True, False), 32770: (False, True), 32771: (True, True)}


def status(device: str = DEFAULT_DEVICE) -> dict[str, Any]:
    # TODO verify-live: CIM_AssociatedPowerManagementService, CIM_SoftwareIdentity,
    # AMT_SetupAndConfigurationService, IPS_HostBasedSetupService, AMT_RedirectionService,
    # CIM_KVMRedirectionSAP, IPS_OptInService. Proven in the spike: AMT_BootSettingData,
    # IPS_KVMRedirectionSettingData.
    r = _Reads(device)
    power = r.get("CIM_AssociatedPowerManagementService")
    identities = r.enum("CIM_SoftwareIdentity")
    setup = r.get("AMT_SetupAndConfigurationService")
    host_setup = r.get("IPS_HostBasedSetupService")
    redirection = r.get("AMT_RedirectionService")
    kvm_sap = r.get("CIM_KVMRedirectionSAP")
    kvm_settings = r.get("IPS_KVMRedirectionSettingData")
    opt_in = r.get("IPS_OptInService")
    boot = r.get("AMT_BootSettingData")

    firmware = {str(i.get("InstanceID")): i.get("VersionString") for i in identities if i.get("InstanceID")}
    power_code = power.get("PowerState")
    mode_code = setup.get("ProvisioningMode")
    state_code = setup.get("ProvisioningState")
    control_code = host_setup.get("CurrentControlMode")
    ider, sol = REDIRECTION_STATES.get(redirection.get("EnabledState"), (None, None))
    kvm_code = kvm_sap.get("EnabledState")
    required = opt_in.get("OptInRequired")
    opt_state = opt_in.get("OptInState")
    return {
        "device": device,
        "power": {"state": _label(POWER_STATES, power_code), "code": power_code},
        "amt": {
            "version": firmware.get("AMT"),
            "build_number": firmware.get("Build Number"),
            "sku": firmware.get("Sku"),
            "firmware": firmware,
        },
        "provisioning": {
            "mode": _label(PROVISIONING_MODES, mode_code), "mode_code": mode_code,
            "state": _label(PROVISIONING_STATES, state_code), "state_code": state_code,
            "control_mode": _label(CONTROL_MODES, control_code), "control_mode_code": control_code,
            "zero_touch_enabled": setup.get("ZeroTouchConfigurationEnabled"),
        },
        "redirection": {
            "listener_enabled": redirection.get("ListenerEnabled"),
            "enabled_state_code": redirection.get("EnabledState"),
            "sol_enabled": sol,
            "ider_enabled": ider,
            "kvm": {
                "state": _label(KVM_STATES, kvm_code), "state_code": kvm_code,
                "enabled": None if kvm_code is None else kvm_code in (2, 6),
                "port_5900_enabled": kvm_settings.get("Is5900PortEnabled"),
                "session_timeout": kvm_settings.get("SessionTimeout"),
            },
        },
        "user_consent": {
            "required_for": _label(OPT_IN_REQUIRED, required), "required_code": required,
            "state": _label(OPT_IN_STATES, opt_state), "state_code": opt_state,
            "can_modify_policy": opt_in.get("CanModifyOptInPolicy"),
        },
        "next_boot": boot,
        **r.coverage(),
    }


# --- amt_screenshot ---------------------------------------------------------------------

def _shot_dir() -> Path:
    return Path(os.environ.get(SHOT_DIR_ENV) or Path(tempfile.gettempdir()) / "amt-mcp-shots")


def _private_shot_dir() -> Path:
    """The screenshot directory, created 0700. Refuses a symlink, a non-directory, or a
    directory owned by someone else (a planted path would let another user read or redirect
    console captures). The default directory is tightened to 0700 if it was made looser."""
    d = _shot_dir()
    try:
        st = os.lstat(d)
    except FileNotFoundError:
        d.parent.mkdir(parents=True, exist_ok=True)
        os.mkdir(d, 0o700)
        st = os.lstat(d)
    if not stat.S_ISDIR(st.st_mode):     # lstat: a symlink to a directory is not S_ISDIR
        raise PermissionError("shot_dir_unsafe:not_a_plain_directory")
    if st.st_uid != os.getuid():
        raise PermissionError("shot_dir_unsafe:not_owned_by_this_user")
    if not os.environ.get(SHOT_DIR_ENV) and st.st_mode & 0o077:
        os.chmod(d, 0o700)
    return d


def _create_private_png(out_dir: Path, device_key: str) -> Path:
    """Create the (empty, 0600, unguessably named) PNG; the engine then truncates it in place,
    so the inode keeps 0600. O_EXCL|O_NOFOLLOW: never reuse or follow an existing path."""
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    path = out_dir / f"amt-{device_key}-{stamp}-{secrets.token_hex(8)}.png"
    os.close(os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0), 0o600))
    return path


def _pinned_kvm_session(dev: amt_registry.Device, password: str):
    """A KvmSession whose ``connect`` verifies the TLS leaf against the registry pin.

    ``KvmSession.open`` calls ``connect`` itself and only afterwards sends the KVMR start and
    answers the Digest challenge, so checking inside ``connect`` rejects a wrong certificate
    before any byte (or the password digest) is sent, without touching the engine. The base
    class is resolved at call time.
    """
    pin = dev.tls_leaf_sha256

    class Pinned(amt_kvm.KvmSession):
        def connect(self):
            super().connect()
            fingerprint = getattr(self, "cert_fp", None) or ""
            if not hmac.compare_digest(fingerprint, pin):
                self.close()
                raise amt_kvm.AmtError("tls_leaf_pin_mismatch")

    return Pinned(dev.amt_ip, dev.kvm_port, pw=password)


class InFlight:
    """The tool calls now using a viewer's shared session (the display mirror's KVM session, the
    serial terminal's SOL session), for the viewer's ``status.json``. A call is its tool name and
    start time only, never its arguments. Keyed by the calling thread: each tool call runs on one
    worker thread, from the session's open to its close."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._calls: dict[int, dict[str, Any]] = {}

    def begin(self) -> None:
        with self._lock:
            self._calls.setdefault(threading.get_ident(), {
                "tool": amt_gate.current_tool() or "unknown", "started_at": round(time.time(), 3)})

    def end(self) -> None:
        with self._lock:
            self._calls.pop(threading.get_ident(), None)

    def snapshot(self) -> dict[str, Any] | None:
        """The longest-running call, or None when no call is using the session."""
        with self._lock:
            return dict(min(self._calls.values(), key=lambda c: c["started_at"])) if self._calls else None


def _kvm_session(dev: amt_registry.Device, password: str):
    """The live display mirror's shared session when one is running for this device (its
    open/close are no-ops and every call is serialized with the mirror's frame grabs), otherwise
    a fresh pinned session the caller opens and closes."""
    import amt_mirror   # imported here: amt_mirror imports this module
    return amt_mirror.shared_session(dev.key) or _pinned_kvm_session(dev, password)


def screenshot(device: str = DEFAULT_DEVICE) -> dict[str, Any]:
    dev = amt_registry.get_device(device)
    amt_wsman.require_pin(dev)           # unpinned: refuse before the vault, the disk or the wire
    out_dir = _private_shot_dir()        # unsafe directory: refuse before opening the session
    password = amt_vault.get_secret(dev.amt_vault_key)
    session = _kvm_session(dev, password)
    try:  # AMT allows ONE redirection session: always close, success or not.
        session.open()
        width, height, iterations, stable, delta = session.grab_stable()
        path = Path(session.write_png(_create_private_png(out_dir, dev.key)))
        return {
            "device": dev.key,
            "path": str(path),
            **amt_handoff.describe(path),
            "width": width,
            "height": height,
            "bytes": path.stat().st_size,
            "iterations": iterations,
            "stable": stable,
            "delta_bits": delta,
            "tls_leaf_sha256": getattr(session, "cert_fp", None),
        }
    finally:
        session.close()


# --- amt_inventory ----------------------------------------------------------------------

INVENTORY_CLASSES = {  # TODO verify-live: all seven are documented CIM_* inventory classes
    "chassis": "CIM_Chassis",
    "baseboard": "CIM_Card",
    "bios": "CIM_BIOSElement",
    "processors": "CIM_Processor",
    "memory": "CIM_PhysicalMemory",
    "storage_media": "CIM_MediaAccessDevice",
    "physical_media": "CIM_PhysicalMedia",
}
InventorySection = Literal["chassis", "baseboard", "bios", "processors", "memory",
                           "storage_media", "physical_media"]


def inventory(sections: list[str] | None = None, device: str = DEFAULT_DEVICE) -> dict[str, Any]:
    chosen = list(sections) if sections else list(INVENTORY_CLASSES)
    unknown = [s for s in chosen if s not in INVENTORY_CLASSES]
    if unknown:
        raise ValueError(f"unknown_inventory_section:{','.join(unknown)}")
    r = _Reads(device)
    resolved: dict[str, list[dict[str, Any]]] = {}
    for section in chosen:
        cls = INVENTORY_CLASSES[section]
        items = r.enum(cls)
        if cls not in r.unavailable:
            resolved[section] = items
    return {
        "device": device,
        "sections": resolved,
        "classes": {s: INVENTORY_CLASSES[s] for s in resolved},
        **r.coverage(),
    }


# --- amt_logs ---------------------------------------------------------------------------

MAX_LOG_CALLS = 50
# Live-verified: the event log is the AMT-schema singleton AMT_MessageLog (its CIM_MessageLog
# enumerate returns that concrete class). GetRecords on it takes no selector and IterationIdentifier 1;
# the CIM_MessageLog URI answers DestinationUnreachable.


def _iso(epoch: int | None) -> str | None:
    if not epoch:
        return None  # 0 = the AMT clock was not set when the record was written
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def decode_event_record(b64: str) -> dict[str, Any]:
    """AMT_MessageLog record: u32 LE time, then device/sensor/event bytes, 8 data bytes.
    Layout verified live on my-server-1 2026-10-18; readable fields come from amt_logdecode."""
    raw = base64.b64decode(b64)
    if len(raw) < 13:
        raise ValueError("event_record_too_short")
    epoch = struct.unpack_from("<I", raw, 0)[0]
    return {
        "epoch": epoch or None, "timestamp": _iso(epoch),
        **amt_logdecode.describe_event(raw[5], raw[7], raw[9], raw[11], raw[13:21]),
        "device_address": raw[4], "sensor_type": raw[5], "event_type": raw[6],
        "event_offset": raw[7], "source_type": raw[8], "severity_code": raw[9],
        "sensor_number": raw[10], "entity": raw[11], "entity_instance": raw[12],
        "event_data_hex": raw[13:21].hex(), "raw_hex": raw.hex(), "decoded": True,
    }


def decode_audit_record(b64: str) -> dict[str, Any]:
    """AMT_AuditLog record: app id, event id, initiator, time, location, address, extra.
    Fields are BIG-endian (network byte order) — verified live on my-server-1
    2026-10-18: a record's time 0x6AD46AFF decodes to 2026-10, not the 2105 that
    a little-endian read produced."""
    raw = base64.b64decode(b64)
    app_id, event_id = struct.unpack_from(">HH", raw, 0)
    initiator_type = raw[4]
    ptr = 5
    if initiator_type == 0:  # HTTP digest: length-prefixed user name
        n = raw[ptr]
        initiator = raw[ptr + 1:ptr + 1 + n].decode("latin-1")
        ptr += 1 + n
    elif initiator_type == 1:  # Kerberos: u32 user-in-domain, then SID length and SID
        n = raw[ptr + 4]
        initiator = amt_logdecode.sid_string(raw[ptr + 5:ptr + 5 + n])
        ptr += 5 + n
    elif initiator_type in (2, 3):  # local, or the KVM default port: no initiator payload
        initiator = ("Local", "KVM Default Port")[initiator_type - 2]
    else:  # an unknown layout: fail visibly rather than misread the time that follows
        raise ValueError(f"unknown_audit_initiator_type:{initiator_type}")
    epoch = struct.unpack_from(">I", raw, ptr)[0]
    ptr += 4
    location = raw[ptr]
    n = raw[ptr + 1]
    address = raw[ptr + 2:ptr + 2 + n].decode("latin-1")
    ptr += 2 + n
    ex = raw[ptr + 1:ptr + 1 + raw[ptr]] if ptr < len(raw) else b""
    return {
        "epoch": epoch or None, "timestamp": _iso(epoch),
        **amt_logdecode.describe_audit(app_id, event_id, initiator_type, ex),
        "app_id": app_id, "event_id": event_id, "initiator_type": initiator_type,
        "initiator": initiator, "mc_location_type": location, "net_address": address,
        "raw_hex": raw.hex(), "decoded": True,
    }


def _safe_hex(b64: Any) -> str | None:
    try:
        return base64.b64decode(b64).hex()
    except Exception:
        return None


def _fetch_event_records(device: str, password: str | None = None) -> tuple[list[str], bool]:
    """Returns ``(records, complete)``; complete only when the device said NoMoreRecords."""
    records: list[str] = []
    iteration = 1
    for _ in range(MAX_LOG_CALLS):
        out = amt_wsman.invoke_read(
            "AMT_MessageLog", "GetRecords", {"IterationIdentifier": iteration, "MaxReadRecords": 390},
            device=device, password=password)
        records += _as_list(out.get("RecordArray"))
        if str(out.get("NoMoreRecords", "")).lower() == "true":
            return records, True
        nxt = out.get("IterationIdentifier")
        if nxt is None or not str(nxt).isdigit() or int(nxt) <= iteration:
            return records, False   # more may remain but the device gave no way forward
        iteration = int(nxt)
    return records, False


def _fetch_audit_records(device: str, password: str | None = None) -> tuple[list[str], bool]:
    """Returns ``(records, complete)``; complete only when TotalRecordCount is reached."""
    records: list[str] = []
    for _ in range(MAX_LOG_CALLS):
        out = amt_wsman.invoke_read(
            "AMT_AuditLog", "ReadRecords", {"StartIndex": len(records) + 1},
            device=device, password=password)
        got = _as_list(out.get("EventRecords"))
        records += got
        total = typed(out.get("TotalRecordCount"), "TotalRecordCount")
        if isinstance(total, int) and len(records) >= total:
            return records, True
        if not got:
            return records, False   # an empty page that did not reach the total is not "done"
    return records, False


def _parse_time(label: str, text: str | None) -> int | None:
    if text is None or not text.strip():
        return None
    try:
        dt = datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        raise ValueError(f"invalid_{label}:expected ISO-8601 like 2026-10-17T00:00:00Z") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp())


def logs(kind: str = "event", since: str | None = None, until: str | None = None,
         offset: int = 0, limit: int = 50, device: str = DEFAULT_DEVICE) -> dict[str, Any]:
    if kind not in ("event", "audit"):
        raise ValueError(f"unknown_log_kind:{kind}")
    if offset < 0 or not 1 <= limit <= 500:
        raise ValueError("invalid_paging:offset>=0 and 1<=limit<=500")
    lo, hi = _parse_time("since", since), _parse_time("until", until)
    fetch, decode = ((_fetch_event_records, decode_event_record) if kind == "event"
                     else (_fetch_audit_records, decode_audit_record))
    raw_records, complete = fetch(device, _password(device))

    rows: list[dict[str, Any]] = []
    for index, b64 in enumerate(raw_records):
        try:
            row = decode(b64)
        except Exception:  # one bad record must not hide the rest; it is reported, not dropped
            row = {"epoch": None, "timestamp": None, "decoded": False, "raw_hex": _safe_hex(b64)}
        row["index"] = index
        rows.append(row)

    undecodable = sum(1 for r in rows if not r["decoded"])
    undated = sum(1 for r in rows if r["epoch"] is None)
    if lo is not None or hi is not None:
        rows = [r for r in rows if r["epoch"] is not None
                and (lo is None or r["epoch"] >= lo) and (hi is None or r["epoch"] <= hi)]
    rows.sort(key=lambda r: (r["epoch"] or 0, r["index"]), reverse=True)  # newest first
    page = rows[offset:offset + limit]
    return {
        "device": device, "kind": kind,
        "fetched": len(raw_records), "fetch_complete": complete,
        "undecodable": undecodable, "undated": undated,
        "matched": len(rows), "offset": offset, "limit": limit,
        "returned": len(page), "records": page,
    }


# --- amt_settings -----------------------------------------------------------------------

# (section name, class, "get" | "enum").  TODO verify-live: every class below; the spike
# proved IPS_KVMRedirectionSettingData only.
SETTINGS_AREAS: dict[str, list[tuple[str, str, str]]] = {
    "network": [
        ("ethernet_ports", "AMT_EthernetPortSettings", "enum"),
        ("general", "AMT_GeneralSettings", "get"),
    ],
    "internet": [
        ("mps_servers", "AMT_ManagementPresenceRemoteSAP", "enum"),
        ("remote_access_policy_rules", "AMT_RemoteAccessPolicyRule", "enum"),
        ("environment_detection", "AMT_EnvironmentDetectionSettingData", "get"),
    ],
    "security": [
        ("tls", "AMT_TLSSettingData", "enum"),
        ("certificates", "AMT_PublicKeyCertificate", "enum"),
        ("authorization", "AMT_AuthorizationService", "get"),
    ],
    "agent_presence": [
        ("watchdogs", "AMT_AgentPresenceWatchdog", "enum"),
        ("capabilities", "AMT_AgentPresenceCapabilities", "get"),
    ],
    "system_defense": [
        ("policies", "AMT_SystemDefensePolicy", "enum"),
        ("service", "AMT_SystemDefenseService", "get"),
    ],
    "subscriptions": [
        ("filter_subscriptions", "CIM_FilterCollectionSubscription", "enum"),
        ("indication_filters", "CIM_IndicationFilter", "enum"),
    ],
    "wake_alarms": [
        ("service", "AMT_AlarmClockService", "get"),
        ("occurrences", "IPS_AlarmClockOccurrence", "enum"),
    ],
    "kvm": [
        ("redirection_sap", "CIM_KVMRedirectionSAP", "get"),
        ("settings", "IPS_KVMRedirectionSettingData", "get"),
        ("opt_in", "IPS_OptInService", "get"),
    ],
    "features": [
        ("redirection_service", "AMT_RedirectionService", "get"),
        ("kvm_sap", "CIM_KVMRedirectionSAP", "get"),
        ("opt_in", "IPS_OptInService", "get"),
        ("setup", "AMT_SetupAndConfigurationService", "get"),
    ],
}
SETTINGS_AREA_NAMES = tuple(SETTINGS_AREAS) + ("users",)
SettingsArea = Literal["network", "internet", "security", "agent_presence", "system_defense",
                       "users", "subscriptions", "wake_alarms", "kvm", "features"]
_BLOB_FIELDS = ("X509Certificate", "DERKey")  # large public blobs: report their size only


def _strip_blobs(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: (f"<{len(v)} chars omitted>" if k in _BLOB_FIELDS and isinstance(v, str)
                    else _strip_blobs(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [_strip_blobs(v) for v in value]
    return value


def _users(device: str, password: str) -> list[dict[str, Any]]:
    handles: list[Any] = []
    total = None
    for _ in range(MAX_LOG_CALLS):
        out = amt_wsman.invoke_read("AMT_AuthorizationService", "EnumerateUserAclEntries",
                                    {"StartIndex": len(handles) + 1}, device=device, password=password)
        got = _as_list(out.get("Handles"))
        handles += got
        total = typed(out.get("TotalCount"), "TotalCount")
        if not got or (isinstance(total, int) and len(handles) >= total):
            break
    return [typed(amt_wsman.invoke_read("AMT_AuthorizationService", "GetUserAclEntryEx",
                                        {"Handle": h}, device=device, password=password)) for h in handles]


def settings(area: str, device: str = DEFAULT_DEVICE) -> dict[str, Any]:
    if area not in SETTINGS_AREA_NAMES:
        raise ValueError(f"unknown_settings_area:{area}")
    r = _Reads(device, tolerant=False)
    if area == "users":
        return {"device": device, "area": area, "sections": {"users": _users(device, r.password)},
                "classes": {"users": "AMT_AuthorizationService"}, **r.coverage()}
    sections: dict[str, Any] = {}
    classes: dict[str, str] = {}
    for name, cls, mode in SETTINGS_AREAS[area]:
        sections[name] = _strip_blobs(r.enum(cls) if mode == "enum" else r.get(cls))
        classes[name] = cls
    return {"device": device, "area": area, "sections": sections, "classes": classes, **r.coverage()}


# --- amt_wsman_get ----------------------------------------------------------------------

def wsman_get(class_name: str, operation: str = "get", selectors: dict[str, str] | None = None,
              max_items: int = 200, device: str = DEFAULT_DEVICE) -> dict[str, Any]:
    amt_wsman.resource_uri(class_name)   # validate before any vault read or network call
    if operation == "get":
        return {"device": device, "class": class_name, "operation": "get",
                "instance": amt_wsman.get(class_name, selectors=selectors, device=device,
                                          password=_password(device))}
    if operation == "enumerate":
        if selectors:
            raise ValueError("selectors_not_supported_for_enumerate")
        items, truncated = amt_wsman.enumerate_(class_name, max_items=max_items, device=device,
                                                password=_password(device))
        return {"device": device, "class": class_name, "operation": "enumerate",
                "count": len(items), "truncated": truncated, "instances": items}
    raise ValueError(f"unknown_operation:{operation}")


# --- registered tool surface ------------------------------------------------------------

async def amt_status(device: DeviceParam = DEFAULT_DEVICE) -> dict:
    """Read the AMT host's live state: power (on/sleep/off), AMT firmware version, provisioning
    mode and state, KVM/SOL/IDE-R redirection state, user-consent policy and state, and the
    next-boot settings. Read-only; makes several WS-MAN requests to the device. Values are
    typed (ints/bools) with a readable label beside each enumerated code. A class the device
    does not expose is listed in `unavailable` (its section is empty) instead of failing the
    call; `truncated` lists classes cut at the item cap. Fails if the device is unreachable,
    rejects the credentials, fails the TLS pin, or the vault entry is missing."""
    return await asyncio.to_thread(status, device)


# One redirection session per host: serialize the in-process callers per (event loop, device).
_SESSION_LOCKS: "weakref.WeakKeyDictionary[asyncio.AbstractEventLoop, dict[str, asyncio.Lock]]" = (
    weakref.WeakKeyDictionary())


def _session_lock(device: str) -> asyncio.Lock:
    """The lock for one REGISTERED device. The key is validated first (``KeyError:
    unknown_device``), so a caller-supplied string can never add an entry to the lock table.

    Residual, disclosed: cancelling a tool call (a client disconnect) releases this lock while
    the worker thread is still running the KVM sequence, so a second call can start before the
    first one closed its session. AMT's own single-redirection-session refusal is the backstop:
    the second ``open`` fails with nothing sent."""
    amt_registry.get_device(device)
    locks = _SESSION_LOCKS.setdefault(asyncio.get_running_loop(), {})
    return locks.setdefault(device, asyncio.Lock())


async def amt_screenshot(device: DeviceParam = DEFAULT_DEVICE) -> dict:
    """Opens the host's single AMT redirection (KVM) session to capture the console as a PNG,
    then closes it: while open it blocks every other KVM/SOL/IDE-R user, and where user opt-in
    is required it may trigger a consent prompt on the host. It fails if another session is
    open or consent is pending. Returns the PNG's server-side path (mode 0600, unguessable
    name), over HTTP with a public base URL a one-time download url with its sha256, width,
    height, bytes, frames grabbed, whether the screen settled (stable) and the final frame delta. Works for Windows and BIOS screens.
    Refuses a device whose TLS leaf is unpinned or does not match its pin. Read-only for the
    host's state: it sends no input."""
    async with _session_lock(device):
        return await asyncio.to_thread(screenshot, device)


async def amt_inventory(
    sections: Annotated[list[InventorySection] | None, Field(
        description="Inventory sections to read; omit for all. Choices: chassis, baseboard, "
                    "bios, processors, memory, storage_media, physical_media.")] = None,
    device: DeviceParam = DEFAULT_DEVICE,
) -> dict:
    """Read hardware inventory from the AMT host over WS-MAN: chassis, baseboard, BIOS,
    processors, memory modules and the storage media table (media access devices plus physical
    media). Returns one list of typed instance dicts per section. Read-only. Choose `sections`
    to read a subset, or omit it for everything. A class the device does not expose is left
    out of `sections` and named in `unavailable`; `truncated` names classes cut at the item cap."""
    return await asyncio.to_thread(inventory, sections, device)


async def amt_logs(
    kind: Annotated[Literal["event", "audit"], Field(
        description="Which log to read: 'event' (AMT event log) or 'audit' (AMT audit log).")] = "event",
    since: Annotated[str | None, Field(
        description="Only records at or after this ISO-8601 time, e.g. 2026-10-17T00:00:00Z "
                    "(no zone means UTC). Omit for no lower bound.")] = None,
    until: Annotated[str | None, Field(
        description="Only records at or before this ISO-8601 time (no zone means UTC). "
                    "Omit for no upper bound.")] = None,
    offset: Annotated[int, Field(ge=0, description="Records to skip, newest first, for paging.")] = 0,
    limit: Annotated[int, Field(ge=1, le=500, description="Maximum records to return (1-500).")] = 50,
    device: DeviceParam = DEFAULT_DEVICE,
) -> dict:
    """Read the AMT event log or audit log, newest first, with a time filter and paging.
    Each event record carries a readable description, source, severity and level (info,
    warning, critical); each audit record carries the app and event names, the initiator and
    decoded extended data. Raw codes and hex stay alongside. Returns matched count, the page,
    and how many records were fetched, undated or undecodable, so an empty page can be told from
    an empty log. Read-only. A time filter drops records written before the AMT clock was set."""
    return await asyncio.to_thread(logs, kind, since, until, offset, limit, device)


async def amt_settings(
    area: Annotated[SettingsArea, Field(
        description="One settings area: network, internet, security, agent_presence, "
                    "system_defense, users, subscriptions, wake_alarms, kvm or features.")],
    device: DeviceParam = DEFAULT_DEVICE,
) -> dict:
    """Read ONE AMT settings area (network, internet, security, agent_presence, system_defense,
    users, subscriptions, wake_alarms, kvm, features) and return its sections as typed dicts
    and lists, plus the AMT class behind each section. Read-only. Credentials are never
    returned: any field named like a password, passphrase, secret, PSK or private key is
    redacted and certificate blobs are reduced to a size note. `truncated` names classes cut
    at the item cap."""
    return await asyncio.to_thread(settings, area, device)


async def amt_wsman_get(
    class_name: Annotated[str, Field(
        description="AMT, CIM or IPS class name, e.g. AMT_BootSettingData or "
                    "CIM_SoftwareIdentity. Must start with AMT_, CIM_ or IPS_.")],
    operation: Annotated[Literal["get", "enumerate"], Field(
        description="'get' reads one instance (singleton classes, or with selectors); "
                    "'enumerate' lists every instance of the class.")] = "get",
    selectors: Annotated[dict[str, str] | None, Field(
        description="Selector name/value pairs that pick one instance for 'get', e.g. "
                    "{\"InstanceID\": \"Intel(r) AMT: Boot Configuration 0\"}. Not valid with 'enumerate'.")] = None,
    max_items: Annotated[int, Field(
        ge=1, le=1000, description="Maximum instances returned by 'enumerate' (1-1000).")] = 200,
    device: DeviceParam = DEFAULT_DEVICE,
) -> dict:
    """General read primitive: WS-MAN Get or Enumerate of any AMT_, CIM_ or IPS_ class on the
    host. Returns the raw instance fields as strings (nested structures stay nested, repeated
    elements become lists); password/secret-named fields are redacted. Read-only: no Put, no method
    invocation. A wrong class name or missing selector raises with the device's fault text."""
    return await asyncio.to_thread(wsman_get, class_name, operation, selectors, max_items, device)


# --- composite write tools: remote logon / logoff ---------------------------------------
#
# Both drive the host's console over the pin-enforced KVM session, so they carry a
# ``confirmed`` guard, take the same per-device session lock as ``amt_screenshot`` and raise
# on failure. Positions are ratios of the console geometry (proven live on 1280x800).

LOGON_WAKE = (0.5, 0.5)        # click point that wakes the lock screen
LOGON_FIELD = (0.5, 0.575)     # password field centre on the sign-in screen
WAKE_SETTLE_SECONDS = 2.5      # a single Enter does not dismiss the lock screen; Esc does
SUBMIT_SETTLE_SECONDS = 3.0    # one wait for the "Welcome" transition before a result check
# A first logon after a cold boot outlasted both waits live (2026-10-19 02:12Z): the lock screen
# was still up when the post-wake frame was judged, and the sign-in was still up 3 s after Enter
# though the desktop arrived later. So the tool re-reads, sending nothing, before judging.
WAKE_RECHECKS = 3              # extra post-wake reads while the frame is still the lock screen
WAKE_RECHECK_SECONDS = 2.0
SUBMIT_CHECKS = 6              # result reads, SUBMIT_SETTLE_SECONDS apart, until the box is gone
RUN_DIALOG_SETTLE_SECONDS = 1.5
LOGOFF_SETTLE_SECONDS = 2.0
SIGNIN_REGION = (0.3, 0.3, 0.7, 0.85)       # avatar, name and password box live here
SIGNIN_GONE_FRACTION = 0.35                 # >= this much of the region changed: box is gone
RUN_DIALOG_REGION = (0.0, 0.55, 0.45, 0.95)  # the Win+R dialog opens bottom-left
RUN_DIALOG_MIN_FRACTION = 0.05
_PIXEL_DELTA = 48              # summed |dR|+|dG|+|dB| for two pixels to count as different
_SAMPLE_GRID = 48              # samples per axis, so the compare cost is bounded

# Screen-context preconditions. Keys are only sent into a screen that is positively the
# expected one; every doubt aborts with nothing typed (see ``_aborted``).
POWER_ON = 2                   # CIM_AssociatedPowerManagementService.PowerState "on"
# BIOS/POST frames are 640x480-class, where Delete/Esc/Enter change firmware settings.
MIN_WINDOWS_WIDTH = 1024
MIN_WINDOWS_HEIGHT = 720
# Windows taskbar: a horizontal edge spanning the screen in the bottom band, over a strip whose
# body is mostly one colour (the icons and tray cover a minority). Calibrated on real 1280x800
# frames (see tests/test_screen_context_real_frames.py): taskbar edges span 94-100% of the
# sampled columns, a sign-in or lock wallpaper at most 3%.
TASKBAR_BAND = (0.88, 0.99)    # rows (as ratios of the height) searched for the top edge
TASKBAR_EDGE_ROWS = 3          # an edge is a change against the row this many above
TASKBAR_EDGE_DELTA = 60        # summed |dR|+|dG|+|dB| for a column to count as an edge
TASKBAR_EDGE_COLUMNS = 0.85    # fraction of sampled columns that must show the edge
TASKBAR_BODY_TOLERANCE = 60    # distance from the strip's median colour for a pixel to match it
TASKBAR_BODY_FRACTION = 0.60   # fraction of the strip body that must match its median colour
_TASKBAR_COLUMNS = 96
_TASKBAR_BODY_ROWS = 8
# A console that has not painted yet (slow wake) is one colour; no sign-in screen is.
BLANK_TOLERANCE = 24
BLANK_FRACTION = 0.99
# Positive screen identification by OCR (see ``_ocr_gate``). The Windows interactive sign-in
# screen centres the user tile and the "Password" field, one above the other; a text console
# prints its prompt at the left margin. Measured on real 1280x800 sign-in frames: tile centre
# x 0.50, field-placeholder centre x 0.41, field 0.07 of the height below the tile.
SIGNIN_BAND = (0.25, 0.75)     # centre-x range (ratio of the width) of the tile and the field
SIGNIN_MAX_GAP = 0.25          # the field lies below the tile by at most this much of the height
# Words that only a non-Windows screen (text console, boot loader, firmware, installer) prints.
# A match aborts whatever else the frame shows: a console whose user already typed the account
# name ("<host> login: jdoe" / "Password:") carries both tokens the sign-in match looks for.
# Split in two so the classifier labels only what it can ground: console words make a
# ``linux-console``; boot-loader/firmware words veto the Windows tools but are not given a
# label of their own yet (``unknown``). ``FOREIGN_MARKERS`` is their union, the veto.
CONSOLE_MARKERS = re.compile(r"\blogin\b|\bkernel\b|\btty\d|\blinux\b|\bubuntu\b|\bdebian\b", re.I)
BOOT_MARKERS = re.compile(r"\bgrub\b|\buefi\b|\bbios\b", re.I)
FOREIGN_MARKERS = re.compile(CONSOLE_MARKERS.pattern + "|" + BOOT_MARKERS.pattern, re.I)
SIGNIN_OPTIONS = re.compile(r"sign[\s-]*in\s+options", re.I)   # logoff veto: a sign-in screen
# Lock screen: a large clock and a long date, away from the taskbar tray in the bottom-right
# corner (a desktop's tray also shows a clock and a numeric date, so the corner is excluded).
# Measured on real lock frames: clock centre (0.50, 0.23), date (0.50, 0.33); tray clock/date
# (0.97, 0.96)/(0.96, 0.98).
LOCK_TRAY_MIN_Y = 0.85         # fragments at or below this height are the tray, not the lock clock
CLOCK_TEXT = re.compile(r"^\d{1,2}:\d{2}(\s?[ap]m)?$", re.I)
DATE_TEXT = re.compile(r"\b(mon|tues?|wed(nes)?|thu(rs)?|fri|sat(ur)?|sun)[a-z]*\b.*\b\d{1,2}\b|"
                       r"\b(jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)[a-z]*\b.*\b\d{1,2}\b", re.I)
TESSERACT_TIMEOUT = 30         # seconds for one recognition run
TESSERACT_BRIGHT = 150         # luma above this is text: the sign-in screen is light on dark
TESSERACT_UPSCALE = 2
TESSERACT_MIN_CONFIDENCE = 20
# Share of near-black (luma < 16) pixels from which a frame is a text console. Real frames: Debian
# ttys 0.991-0.998, every GRUB/MOK/installer/BIOS/Windows frame 0.635 or less.
TESSERACT_CONSOLE_BLACK_SHARE = 0.95
# Linux text console (getty, then a shell). Read from the LAST text line only, the one the cursor
# is on. Grounded on the real Debian 13 tty1 frame: ocrmac read the hostname's "0" as "ø" and the
# cursor as "-", so a prompt is matched on how it ENDS, never on the hostname. "Last login:" (the
# motd after a login) is not a login prompt, and a line that starts like a shell prompt is never a
# getty prompt, whatever it ends with (a typed "echo login:" must not read as one).
CONSOLE_LINE_TOLERANCE = 0.012  # fragment centres this close in height share one text line
_CURSOR = r"\s*[-_|]?\s*$"
CONSOLE_LOGIN = re.compile(r"\blogin:" + _CURSOR, re.I)
CONSOLE_LAST_LOGIN = re.compile(r"\blast\s+login\b", re.I)
CONSOLE_PASSWORD = re.compile(r"\bpassword:" + _CURSOR, re.I)
CONSOLE_SHELL = re.compile(r"\S@\S+:\S*[$#]")       # user@host:~$ (or #), anywhere on the line
CONSOLE_INCORRECT = re.compile(r"\blogin\s+incorrect\b", re.I)
PROMPT_LOGIN, PROMPT_PASSWORD, PROMPT_COMMAND = "login_prompt", "password_prompt", "command_prompt"
CONSOLE_SETTLE_SECONDS = 2.0   # between reads while waiting for getty's Password: prompt
CONSOLE_PROMPT_CHECKS = 3
CONSOLE_SUBMIT_SECONDS = 2.0   # a wrong password costs PAM's ~3 s delay before "Login incorrect"
CONSOLE_SUBMIT_CHECKS = 8

LOGON_CONSEQUENCE = ("types the vaulted host credential (the Windows password, or the Linux account "
                     "name and password) into the console and logs into the host")
LOGOFF_CONSEQUENCE = ("signs the current user out of the host (Windows, or a Linux console's shell), "
                      "closing their session")


class ConfirmationRequired(ValueError):
    """A write tool was called without ``confirmed=True``; nothing was run."""


def _require_confirmed(confirmed: Any, consequence: str) -> None:
    if confirmed is not True:
        raise ConfirmationRequired(
            f"confirmation_required: this {consequence}. Nothing was done. "
            "Re-call with confirmed=true only on the operator's explicit approval.")


def _pause(seconds: float) -> None:
    """Every wait in the composite sequences; tests replace this so none really sleeps."""
    time.sleep(seconds)


def _at(width: int, height: int, ratio: tuple[float, float]) -> tuple[int, int]:
    """A ratio (0 first pixel .. 1 last pixel) as a pixel: x=1.0 is width-1, never off-screen."""
    return (min(max(round(width * ratio[0]), 0), max(width - 1, 0)),
            min(max(round(height * ratio[1]), 0), max(height - 1, 0)))


def _snapshot(session) -> bytes | None:
    fb = getattr(session, "fb", None)
    return bytes(fb) if fb else None


def _changed_fraction(before: bytes | None, after: bytes | None, width: int, height: int,
                      region: tuple[float, float, float, float]) -> float | None:
    """Fraction of a bounded sample grid inside ``region`` (ratios x0,y0,x1,y1) whose RGB pixel
    differs between two frames; None when either frame is missing or does not match the
    geometry (unknown must not read as 'unchanged')."""
    need = width * height * 3
    if not before or not after or len(before) < need or len(after) < need:
        return None
    x0, y0, x1, y1 = int(width * region[0]), int(height * region[1]), \
        int(width * region[2]), int(height * region[3])
    xs = [x0 + (x1 - x0) * i // _SAMPLE_GRID for i in range(_SAMPLE_GRID)]
    ys = [y0 + (y1 - y0) * i // _SAMPLE_GRID for i in range(_SAMPLE_GRID)]
    diff = 0
    for y in ys:
        for x in xs:
            o = (y * width + x) * 3
            if (abs(before[o] - after[o]) + abs(before[o + 1] - after[o + 1])
                    + abs(before[o + 2] - after[o + 2])) > _PIXEL_DELTA:
                diff += 1
    return diff / (len(xs) * len(ys))


def windows_geometry(width: int, height: int) -> bool:
    """True for a Windows-class console; False for a BIOS/POST-class frame (640x480)."""
    return width >= MIN_WINDOWS_WIDTH and height >= MIN_WINDOWS_HEIGHT


def _readable(fb: bytes | None, width: int, height: int) -> bool:
    return bool(fb) and width > 0 and height > 0 and len(fb) >= width * height * 3


def taskbar_present(fb: bytes | None, width: int, height: int) -> bool | None:
    """Whether the frame shows the Windows desktop taskbar; None when the frame is unreadable
    (unknown must not read as 'no taskbar').

    The taskbar is a bar across the very bottom: a sharp horizontal edge over almost every
    sampled column, above a strip that is mostly one colour. A sign-in or lock screen is a
    smooth wallpaper there and has neither."""
    if not _readable(fb, width, height):
        return None
    xs = [width * (2 * i + 1) // (2 * _TASKBAR_COLUMNS) for i in range(_TASKBAR_COLUMNS)]

    def px(x: int, y: int) -> tuple[int, int, int]:
        o = (y * width + x) * 3
        return fb[o], fb[o + 1], fb[o + 2]

    need = TASKBAR_EDGE_COLUMNS * len(xs)
    for y in range(max(int(height * TASKBAR_BAND[0]), TASKBAR_EDGE_ROWS), int(height * TASKBAR_BAND[1])):
        edge = 0
        for x in xs:
            a, b = px(x, y), px(x, y - TASKBAR_EDGE_ROWS)
            if abs(a[0] - b[0]) + abs(a[1] - b[1]) + abs(a[2] - b[2]) > TASKBAR_EDGE_DELTA:
                edge += 1
        if edge < need:
            continue
        top = y + TASKBAR_EDGE_ROWS
        if top >= height:
            continue
        rows = sorted({top + (height - 1 - top) * i // (_TASKBAR_BODY_ROWS - 1)
                       for i in range(_TASKBAR_BODY_ROWS)})
        body = [px(x, r) for r in rows for x in xs]
        median = tuple(sorted(p[c] for p in body)[len(body) // 2] for c in range(3))
        near = sum(1 for p in body
                   if abs(p[0] - median[0]) + abs(p[1] - median[1]) + abs(p[2] - median[2])
                   <= TASKBAR_BODY_TOLERANCE)
        if near >= TASKBAR_BODY_FRACTION * len(body):
            return True
    return False


def frame_is_blank(fb: bytes | None, width: int, height: int) -> bool | None:
    """Whether the frame is (almost) one colour, as a console that has not painted yet is;
    None when the frame is unreadable."""
    if not _readable(fb, width, height):
        return None
    pts = []
    for j in range(_SAMPLE_GRID):
        y = (height - 1) * j // (_SAMPLE_GRID - 1)
        for i in range(_SAMPLE_GRID):
            o = (y * width + (width - 1) * i // (_SAMPLE_GRID - 1)) * 3
            pts.append((fb[o], fb[o + 1], fb[o + 2]))
    median = tuple(sorted(p[c] for p in pts)[len(pts) // 2] for c in range(3))
    near = sum(1 for p in pts
               if abs(p[0] - median[0]) + abs(p[1] - median[1]) + abs(p[2] - median[2]) <= BLANK_TOLERANCE)
    return near >= BLANK_FRACTION * len(pts)


# --- screen-text recognition: the positive gate -----------------------------------------
#
# The structural detectors above can say what a screen is NOT (a BIOS, a desktop). They cannot
# say it IS the Windows sign-in: a Linux text console, a boot loader or an installer is also
# "no taskbar, not blank". Keys that carry a credential are therefore sent only when OCR of the
# frame positively reads the Windows sign-in prompt, and every other outcome (no OCR backend,
# a recognizer error, no text, a foreign marker, no sign-in signature) aborts.

class OcrError(RuntimeError):
    """The frame could not be read as text."""


class OcrUnavailable(OcrError):
    """No OCR backend is usable on this node (a module, Pillow or the tesseract binary is absent)."""


class Fragment(NamedTuple):
    """One recognized piece of text and the centre of its box, as ratios of the frame
    (origin top-left)."""
    text: str
    cx: float
    cy: float


def _frame_image(fb: bytes, width: int, height: int):
    try:
        from PIL import Image
    except ImportError:
        raise OcrUnavailable("pillow_missing") from None
    return Image.frombytes("RGB", (width, height), bytes(fb[:width * height * 3]))


def _ocr_ocrmac(fb: bytes, width: int, height: int) -> list[Fragment]:
    """Apple Vision through ``ocrmac`` (macOS dev nodes)."""
    try:
        from ocrmac import ocrmac
    except ImportError:
        raise OcrUnavailable("ocrmac_missing") from None
    image = _frame_image(fb, width, height)
    # Vision boxes are normalized (x, y, w, h) with the origin at the bottom-left.
    return [Fragment(text, x + w / 2, 1 - (y + h / 2))
            for text, _conf, (x, y, w, h) in ocrmac.OCR(image, recognition_level="accurate").recognize()]


def _ocr_tesseract(fb: bytes, width: int, height: int) -> list[Fragment]:
    """The ``tesseract`` binary (Linux / the container), driven directly. Raw tesseract misses
    the sign-in text on its photographic wallpaper, so the frame is first reduced to black text
    on white (bright pixels are text) and doubled in size; measured on real sign-in frames. A
    black text console is read as one uniform block (--psm 6): sparse mode (--psm 11) dropped the
    colon of getty's ``login:`` on a live frame, so the prompt went unrecognised."""
    exe = shutil.which("tesseract")
    if not exe:
        raise OcrUnavailable("tesseract_missing")
    image = _frame_image(fb, width, height)
    from PIL import Image
    luma = image.convert("L")
    hist = luma.histogram()
    console = sum(hist[:16]) >= TESSERACT_CONSOLE_BLACK_SHARE * width * height
    grey = luma.point(lambda v: 0 if v > TESSERACT_BRIGHT else 255)
    w2, h2 = width * TESSERACT_UPSCALE, height * TESSERACT_UPSCALE
    buf = io.BytesIO()
    grey.resize((w2, h2), Image.LANCZOS).save(buf, "PNG")
    proc = subprocess.run([exe, "stdin", "stdout", "--psm", "6" if console else "11", "tsv"],
                          input=buf.getvalue(),
                          capture_output=True, timeout=TESSERACT_TIMEOUT, check=False)
    if proc.returncode != 0:
        raise OcrError("tesseract_failed")
    out = []
    for line in proc.stdout.decode("utf-8", "replace").splitlines()[1:]:
        f = line.split("\t")
        if len(f) != 12 or not f[11].strip():
            continue
        try:
            left, top, bw, bh, conf = (float(v) for v in f[6:11])
        except ValueError:
            continue
        if conf >= TESSERACT_MIN_CONFIDENCE:
            out.append(Fragment(f[11].strip(), (left + bw / 2) / w2, (top + bh / 2) / h2))
    return out


# In order of preference. A backend that is not installed is skipped; one that is installed and
# fails raises (no silent fall-through to a second opinion).
OCR_BACKENDS = (("ocrmac", _ocr_ocrmac), ("tesseract", _ocr_tesseract))


def ocr_fragments(fb: bytes | None, width: int, height: int) -> tuple[str, list[Fragment]]:
    """``(backend name, text fragments)`` for a frame. Raises ``OcrUnavailable`` when no backend
    is usable and ``OcrError`` for an unreadable frame; the gate treats both as a refusal."""
    if not _readable(fb, width, height):
        raise OcrError("screen_unreadable")
    for name, run in OCR_BACKENDS:
        try:
            return name, run(fb, width, height)
        except OcrUnavailable:
            continue
    raise OcrUnavailable("no_ocr_backend")


def _account_name(user: str) -> str:
    """The account name as the sign-in tile spells it: no DOMAIN\\ prefix, lower case."""
    return user.rsplit("\\", 1)[-1].strip().lower()


def _words(text: str) -> list[str]:
    return [w for w in (t.strip(" \t:;,.|[]()<>'\"") for t in text.lower().split()) if w]


def foreign_marker_found(frags: list[Fragment]) -> bool:
    """Whether any fragment carries a word only a non-Windows screen prints (``login``, GRUB...)."""
    return any(FOREIGN_MARKERS.search(f.text) for f in frags)


def _centred(f: Fragment) -> bool:
    return SIGNIN_BAND[0] <= f.cx <= SIGNIN_BAND[1]


def signin_signals(frags: list[Fragment], user: str) -> tuple[bool, bool, bool]:
    """``(user tile found, password field found, positioned as a sign-in)`` for the account
    ``user``. The tile is a centred fragment holding the account name as a whole word. The field
    is a centred fragment that is exactly the word ``Password`` and does not end in a colon (a
    console prompt does). They count as the sign-in only with the field below the tile."""
    name = _account_name(user)
    tiles = [f for f in frags if name and _centred(f) and name in _words(f.text)]
    fields = [f for f in frags if _centred(f) and _words(f.text) == ["password"]
              and not f.text.rstrip().endswith(":")]
    return (bool(tiles), bool(fields),
            any(0 < p.cy - t.cy <= SIGNIN_MAX_GAP for t in tiles for p in fields))


def _console_lines(frags: list[Fragment]) -> list[str]:
    """The frame's text lines, top to bottom: fragments grouped by height, joined left to right."""
    rows: list[list[Fragment]] = []
    for f in sorted(frags, key=lambda f: f.cy):
        if rows and f.cy - rows[-1][0].cy <= CONSOLE_LINE_TOLERANCE:
            rows[-1].append(f)
        else:
            rows.append([f])
    return [" ".join(f.text for f in sorted(row, key=lambda f: f.cx)).strip() for row in rows]


def console_prompt(frags: list[Fragment]) -> str | None:
    """What the console's LAST text line is waiting for: ``login_prompt`` (getty's ``<host>
    login:``), ``password_prompt`` (``Password:``), ``command_prompt`` (``user@host:~$``), or None."""
    lines = _console_lines(frags)
    if not lines:
        return None
    last = lines[-1]
    if CONSOLE_SHELL.search(last):
        return PROMPT_COMMAND if re.search(r"[$#]" + _CURSOR, last) else None
    if CONSOLE_LOGIN.search(last) and not CONSOLE_LAST_LOGIN.search(last):
        return PROMPT_LOGIN
    if CONSOLE_PASSWORD.search(last):
        return PROMPT_PASSWORD
    return None


def console_login_incorrect(frags: list[Fragment]) -> bool:
    """Whether ``Login incorrect`` follows the last ``Password:`` line, so an older failure
    still on screen above the prompt being judged never counts (a getty run with --noclear keeps
    it; a Debian 13 tty1 was seen clearing on logout, 2026-10-19)."""
    lines = _console_lines(frags)
    asked = [i for i, line in enumerate(lines) if re.search(r"\bpassword:", line, re.I)]
    return bool(asked) and any(CONSOLE_INCORRECT.search(line) for line in lines[asked[-1] + 1:])


def signin_screen_marker(frags: list[Fragment]) -> bool:
    """Whether the frame shows sign-in furniture (a centred ``Password`` field or the
    "Sign-in options" link), which no logged-in desktop shows."""
    return any(SIGNIN_OPTIONS.search(f.text) or (_centred(f) and _words(f.text) == ["password"])
               for f in frags)


# --- screen-context classifier: the single source of truth for what the console shows ------
#
# ``classify_screen`` names the context from the signals above (geometry, taskbar edge-coverage,
# OCR text). The logon/logoff gates DERIVE their decisions from its label and markers; they hold
# no screen logic of their own. Only labels the signals ground are produced:
#
#   windows-signin  the vaulted account's centred tile with a ``Password`` field below it
#   desktop         taskbar at Windows geometry, readable text, no foreign marker, no sign-in furniture
#   lock            no taskbar, no sign-in furniture, a clock AND a long date away from the tray
#   grub            GRUB's own menu text (``GNU GRUB`` title, its key-help lines, the installer
#                   media's ``GRUB Command line`` hint), read by OCR at any geometry
#   text-installer  the Debian text installer's dialogs (``[!!]``/``[!]`` title, ``<Go Back>``/
#                   ``<Continue>`` buttons, the ``<Tab> moves`` help line), read by OCR
#   mok-manager     the shim MOK manager (``Shim UEFI key management``, ``Perform MOK management``,
#                   ``Enroll MOK``), read by OCR
#   bios-setup      sub-Windows geometry (640x480 BIOS/POST, 800x600) that none of the three
#                   boot labels above claims: the geometry fallback, never positive evidence
#   linux-console   a console marker (login/tty/kernel/Linux/Ubuntu/Debian), no taskbar
#   unknown         everything else, fail closed: no OCR backend, a recognizer error, no text,
#                   an unreadable frame, a frame matching two boot signatures at once, and
#                   firmware boot-device menus (no real capture of one exists: every "boot menu"
#                   frame on file is a BIOS setup page, so it has no label of its own). Boot-loader
#                   words still trip the foreign-marker veto, so the Windows tools abort on every
#                   one of these exactly as before.
#
# Each boot label is a text signature calibrated on real 800x600 frames from the my-server-1
# (tests/real_frames/, both recognizers) and is claimed only when exactly ONE of the three
# matches: a frame that reads as two is no label. The signatures are phrases the boot software
# prints, never a lone word, because "Installing GRUB boot loader" is an installer progress bar,
# not GRUB.

LABEL_SIGNIN, LABEL_DESKTOP, LABEL_LOCK = "windows-signin", "desktop", "lock"
LABEL_BIOS, LABEL_CONSOLE, LABEL_UNKNOWN = "bios-setup", "linux-console", "unknown"
LABEL_GRUB, LABEL_INSTALLER, LABEL_MOK = "grub", "text-installer", "mok-manager"
SCREEN_LABELS = (LABEL_SIGNIN, LABEL_DESKTOP, LABEL_LOCK, LABEL_BIOS, LABEL_CONSOLE,
                 LABEL_GRUB, LABEL_INSTALLER, LABEL_MOK, LABEL_UNKNOWN)
# Screens that read the first keys typed and never take a credential from an agent: a secret step
# beside any of them is refused (``amt_write.console_input`` ``expect``).
BOOT_FIRMWARE_LABELS = frozenset({LABEL_BIOS, LABEL_GRUB, LABEL_INSTALLER, LABEL_MOK})
BOOT_SIGNATURES: tuple[tuple[str, re.Pattern], ...] = (
    (LABEL_GRUB, re.compile(r"\bgnu\s+grub\b|\bgrub\s+command[\s-]*line\b|\bentry\s+is\s+highlighted\b", re.I)),
    (LABEL_INSTALLER, re.compile(r"\[\s*!{1,2}\s*\]|<\s*go\s*back\s*>|<\s*continue\s*>|<\s*tab\s*>\s*moves", re.I)),
    (LABEL_MOK, re.compile(r"\bmok\s+management\b|\benroll\s+mok\b|\bshim\s+uefi\s+key", re.I)),
)


def boot_screen(frags: list[Fragment]) -> str | None:
    """``grub`` / ``text-installer`` / ``mok-manager`` when exactly one boot signature matches the
    frame's text (fragments joined in recognizer order), else None."""
    text = " ".join(f.text for f in frags)
    hits = [label for label, pat in BOOT_SIGNATURES if pat.search(text)]
    return hits[0] if len(hits) == 1 else None


def _frame_parts(frame: Any) -> tuple[bytes | None, int, int] | None:
    """``(framebuffer, width, height)`` from a PNG (bytes), a ``(fb, width, height)`` tuple or an
    object carrying ``fb``/``width``/``height``; None when it is none of those or a PNG that
    cannot be decoded."""
    if isinstance(frame, (bytes, bytearray)) and bytes(frame[:8]) == b"\x89PNG\r\n\x1a\n":
        try:
            from PIL import Image
            with Image.open(io.BytesIO(bytes(frame))) as im:
                rgb = im.convert("RGB")
                return rgb.tobytes(), rgb.width, rgb.height
        except Exception:  # unreadable PNG or no Pillow: the frame is unidentified
            return None
    if all(hasattr(frame, a) for a in ("fb", "width", "height")):   # before the tuple: a NamedTuple has both
        return frame.fb, int(frame.width), int(frame.height)
    if isinstance(frame, tuple) and len(frame) == 3:
        return frame[0], int(frame[1]), int(frame[2])
    return None


def _fragment_markers(frags: list[Fragment], user: str) -> dict[str, Any]:
    """The yes/no findings OCR text supports. Booleans only: no recognized text leaves here."""
    tile, field, positioned = signin_signals(frags, user)
    away = [f for f in frags if f.cy < LOCK_TRAY_MIN_Y]
    return {
        "foreign_markers": foreign_marker_found(frags),
        "boot_screen": boot_screen(frags),
        "console_marker": any(CONSOLE_MARKERS.search(f.text) for f in frags),
        "console_prompt": console_prompt(frags),
        "login_incorrect": console_login_incorrect(frags),
        "signin_furniture": signin_screen_marker(frags),
        "user_tile": tile, "password_field": field, "signin_positioned": positioned,
        "lock_clock": any(CLOCK_TEXT.match(f.text.strip()) for f in away),
        # Joined: tesseract returns "Sunday," "October" "18" as three fragments, ocrmac as one.
        "lock_date": bool(DATE_TEXT.search(" ".join(f.text for f in away))),
    }


def _ocr_markers(fb: bytes | None, width: int, height: int, user: str) -> dict[str, Any]:
    """``ocr_backend`` and ``ocr_problem`` (None, or why the frame could not be read as text:
    ``ocr_unavailable`` / ``ocr_failed`` / ``ocr_no_text``), plus the fragment findings when it
    could. Any recognizer failure leaves the screen unidentified."""
    out: dict[str, Any] = {"ocr_backend": None, "ocr_problem": None}
    try:
        backend, frags = ocr_fragments(fb, width, height)
    except OcrUnavailable:
        return {**out, "ocr_problem": "ocr_unavailable"}
    except Exception:
        return {**out, "ocr_problem": "ocr_failed"}
    out["ocr_backend"] = backend
    if not frags:
        return {**out, "ocr_problem": "ocr_no_text"}
    return {**out, **_fragment_markers(frags, user)}


def _label_for(m: dict[str, Any]) -> str:
    """The context label for a marker set; pure, ordered most-specific first, fail closed."""
    if m["windows_geometry"] is False:
        return m.get("boot_screen") or LABEL_BIOS     # OCR (when it ran) may name the boot software
    if not m["readable"] or m.get("ocr_problem") or "foreign_markers" not in m:
        return LABEL_UNKNOWN              # unreadable, or OCR not run/failed/empty
    if m["boot_screen"] and not m["taskbar"]:
        return m["boot_screen"]           # a boot word in a taskbar window's text is not a boot screen
    shell = m["console_prompt"] == PROMPT_COMMAND
    if m["foreign_markers"] or shell:
        # A console word on a taskbar desktop may just be a window's text: ambiguous, not a console.
        # A cleared shell (``user@host:~$`` alone) carries no marker word; its prompt is the marker.
        # A bare ``Password:`` is not: nothing ties it to a console.
        return LABEL_CONSOLE if (m["console_marker"] or shell) and not m["taskbar"] else LABEL_UNKNOWN
    if m["taskbar"]:
        return LABEL_UNKNOWN if m["signin_furniture"] else LABEL_DESKTOP
    if m["signin_positioned"]:
        return LABEL_SIGNIN
    if m["lock_clock"] and m["lock_date"] and not m["signin_furniture"]:
        return LABEL_LOCK
    return LABEL_UNKNOWN


def classify_screen(frame: Any, user: str = "", *, ocr: bool = True) -> dict[str, Any]:
    """``{"label": <one of SCREEN_LABELS>, "markers": {...}}`` for a console frame: a PNG
    (bytes), a ``(framebuffer, width, height)`` tuple, or an object with ``fb``/``width``/
    ``height``. ``user`` is the vaulted account the sign-in tile must show.

    ``markers`` carries yes/no findings only (geometry, ``taskbar``, ``blank``, the OCR backend
    name and what the text showed): never recognized text. ``ocr=False`` is the cheap structural
    pass the gates run first; it never invokes a recognizer, so every OCR-dependent label comes
    back ``unknown`` (``bios-setup``, the sub-Windows geometry fallback, survives). Fail closed: an
    unreadable frame, no OCR backend, a recognizer error or no text is ``unknown`` at Windows
    geometry; a sub-Windows frame then keeps ``bios-setup`` with ``ocr_problem`` set, which is
    geometry only and never proof of a screen (``amt_write``'s ``expect`` refuses it)."""
    parts = _frame_parts(frame)
    if parts is None:
        return {"label": LABEL_UNKNOWN, "markers": {"readable": False, "windows_geometry": None,
                                                    "width": None, "height": None, "taskbar": None,
                                                    "blank": None, "ocr_backend": None,
                                                    "ocr_problem": None}}
    fb, width, height = parts
    m: dict[str, Any] = {"width": width, "height": height, "readable": _readable(fb, width, height),
                         "windows_geometry": windows_geometry(width, height),
                         "taskbar": taskbar_present(fb, width, height),
                         "blank": frame_is_blank(fb, width, height),
                         "ocr_backend": None, "ocr_problem": None}
    if ocr and m["readable"]:     # sub-Windows frames are read too: GRUB, the installer and MOK are 800x600
        m.update(_ocr_markers(fb, width, height, user))
    return {"label": _label_for(m), "markers": m}


def _structural_reason(m: dict[str, Any], *, desktop: bool, check_blank: bool) -> str | None:
    """The reason the console is not the screen a tool may send keys into, from the structural
    markers alone (no OCR), or None.

    ``desktop=False`` (logon) wants a sign-in/lock screen, i.e. NO taskbar: a taskbar means the
    host is already logged in, and typing the password there would put it into whatever app has
    focus. ``desktop=True`` (logoff) wants the opposite. Anything unreadable is a problem."""
    if not m["windows_geometry"]:
        return "not_windows_resolution"
    if m["taskbar"] is None:
        return "screen_unreadable"
    if desktop and not m["taskbar"]:
        return "no_desktop_taskbar"
    if not desktop and m["taskbar"]:
        return "host_already_logged_in"
    if check_blank and m["blank"]:
        return "screen_blank"
    return None


def _context_problem(fb: bytes | None, width: int, height: int, *, desktop: bool,
                     check_blank: bool = False) -> str | None:
    """The structural pre-filter, derived from ``classify_screen(ocr=False)``."""
    markers = classify_screen((fb, width, height), ocr=False)["markers"]
    return _structural_reason(markers, desktop=desktop, check_blank=check_blank)


def _findings(label: str, m: dict[str, Any], *, desktop: bool) -> dict[str, Any]:
    """The yes/no OCR findings an abort or success carries: the label, the backend name and the
    booleans the check reached, never recognized text (the sign-in tile holds the account name)."""
    out: dict[str, Any] = {"screen_label": label, "ocr_backend": m["ocr_backend"]}
    if m["ocr_problem"]:
        return out
    out["foreign_markers"] = m["foreign_markers"]
    if m["foreign_markers"]:
        return out
    if desktop:
        out["signin_furniture"] = m["signin_furniture"]
    else:
        out.update(user_tile=m["user_tile"], password_field=m["password_field"])
    return out


def _label_reason(label: str, m: dict[str, Any], *, desktop: bool) -> str | None:
    """Why ``label`` is not the screen the tool needs (logon: ``windows-signin``; logoff:
    ``desktop``), or None when it is."""
    if m["ocr_problem"]:
        return m["ocr_problem"]
    if m["foreign_markers"]:
        return "foreign_console_detected"
    if not desktop:
        return None if label == LABEL_SIGNIN else "signin_not_identified"
    if label == LABEL_DESKTOP:
        return None
    return "signin_screen_detected" if m["signin_furniture"] else "desktop_not_identified"


def _screen_problem(fb: bytes | None, width: int, height: int, *, desktop: bool, user: str = "",
                    check_blank: bool = False) -> tuple[str | None, dict[str, Any]]:
    """``(reason, detail)`` unless ``classify_screen`` passes the frame: first its structural
    pass (``_context_problem``'s rules), then the full classification, whose label must be the
    one the tool needs. ``(None, detail)`` means keys may be sent. The structural pass runs
    first so a BIOS, a missing-taskbar or a blank frame never pays for recognition."""
    problem = _context_problem(fb, width, height, desktop=desktop, check_blank=check_blank)
    if problem:
        return problem, {}
    cls = classify_screen((fb, width, height), user)
    label, m = cls["label"], cls["markers"]
    return _label_reason(label, m, desktop=desktop), _findings(label, m, desktop=desktop)


def _desktop_findings(problem: str | None, fb: bytes | None, width: int, height: int,
                      user: str) -> dict[str, Any] | None:
    """The findings when a logon's ``host_already_logged_in`` stop is a desktop the classifier
    positively labels ``desktop`` (the logon goal, a usable session, is already met); None for
    any other problem or any other label, which stay aborts."""
    if problem != "host_already_logged_in":
        return None
    cls = classify_screen((fb, width, height), user)
    if cls["label"] != LABEL_DESKTOP:
        return None
    return _findings(cls["label"], cls["markers"], desktop=True)


def key_combo(session, modifiers: tuple[str, ...], key: str) -> None:
    """Hold ``modifiers``, tap ``key``, release the modifiers in reverse (engine key names or a
    single ASCII character). Modifiers are released in a ``finally`` so a failure mid-chord
    never leaves e.g. the Win key stuck down on the host."""
    ksyms = []
    for name in modifiers:
        ks = amt_kvm.KEYSYM.get(name.lower())
        if ks is None:
            raise amt_kvm.AmtError(f"unknown_key_{name}")
        ksyms.append(ks)
    tap = amt_kvm.KEYSYM.get(key.lower()) if len(key) > 1 else ord(key)
    if tap is None:
        raise amt_kvm.AmtError(f"unknown_key_{key}")
    held = []
    try:
        for ks in ksyms:
            session._key(ks, True)
            held.append(ks)
        session.tap(tap)
    finally:
        for ks in reversed(held):
            session._key(ks, False)


def _host_credential(dev: amt_registry.Device) -> tuple[str, str]:
    """``(user, password)`` from the vaulted ``{"user":...,"password":...}`` entry. The user is
    the account the sign-in tile must show (``user`` is matched as the tile spells it, without
    any ``DOMAIN\\`` prefix). Failures name the vault KEY only: the parse error is dropped
    (``from None``) so no fragment of the value can reach an exception message."""
    if not dev.host_vault_key:
        raise amt_vault.VaultError(f"no_host_credential:{dev.key}")
    raw = amt_vault.get_secret(dev.host_vault_key)
    try:
        entry = json.loads(raw)
        user, password = entry.get("user"), entry.get("password")
    except (ValueError, AttributeError):
        raise amt_vault.VaultError(f"vault_bad_credential_shape:{dev.host_vault_key}") from None
    if (not isinstance(password, str) or not password
            or not isinstance(user, str) or not _account_name(user)):
        raise amt_vault.VaultError(f"vault_bad_credential_shape:{dev.host_vault_key}")
    return user, password


def _result_frame(session, dev: amt_registry.Device, out_dir: Path) -> dict[str, Any]:
    width, height, iterations, stable, delta = session.grab_stable()
    path = Path(session.write_png(_create_private_png(out_dir, dev.key)))
    return {
        "device": dev.key,
        "path": str(path),
        **amt_handoff.describe(path),
        "width": width,
        "height": height,
        "bytes": path.stat().st_size,
        "iterations": iterations,
        "stable": stable,
        "delta_bits": delta,
        "tls_leaf_sha256": getattr(session, "cert_fp", None),
    }


def _power_state(device: str, amt_password: str) -> int | None:
    """The host's AMT power state code (2 = on) from one WS-MAN Get; None when the class
    faults or carries no state (unknown must not read as 'on')."""
    try:
        got = typed(amt_wsman.get("CIM_AssociatedPowerManagementService", device=device,
                                  password=amt_password))
    except amt_wsman.WsmanFault:
        return None
    code = got.get("PowerState")
    return code if isinstance(code, int) else None


# What the caller should know about an abort whose reason is not self-explanatory.
ABORT_NOTES = {
    "ocr_unavailable": "no OCR backend is usable on this node (ocrmac, or tesseract plus Pillow); "
                       "the screen cannot be identified, so nothing was typed (fail closed)",
    "ocr_failed": "the OCR backend failed on this frame; the screen was not identified",
    "ocr_no_text": "OCR read no text from this frame; the screen was not identified",
    "foreign_console_detected": "the frame carries a non-Windows marker (login prompt, boot "
                                "loader, firmware, Linux console) where the Windows sign-in was "
                                "expected; a Linux console is handled only when the FIRST frame "
                                "already shows it",
    "console_not_at_login_prompt": "the Linux console's last line is not a fresh getty login "
                                   "prompt (a Password: prompt someone else started, or "
                                   "unrecognised text); nothing was typed",
    "password_prompt_not_identified": "the account name was typed at the login prompt, but no "
                                      "Password: prompt followed; the password was NOT typed",
    "console_not_at_shell_prompt": "the Linux console's last line is not a shell prompt (a "
                                   "login or Password: prompt, or program output); exit would "
                                   "land there, so nothing was typed",
    "signin_not_identified": "the frame is not the Windows interactive sign-in for the vaulted "
                             "account (account tile with a Password field below it)",
    "signin_screen_detected": "the frame shows sign-in furniture; logoff needs a logged-in desktop",
    "desktop_not_identified": "the frame was not positively identified as the Windows desktop; "
                              "logoff needs a logged-in desktop",
}


def _attach_screenshot(out: dict[str, Any], session, dev: amt_registry.Device, out_dir: Path) -> dict[str, Any]:
    """``out["screenshot"]`` = the console as it is NOW (None before the session opened, or if
    the capture itself failed, in which case ``screenshot_error`` names the exception type)."""
    out["screenshot"] = None
    if session is not None:
        try:
            out["screenshot"] = _result_frame(session, dev, out_dir)
        except Exception as ex:  # the result stands even if the evidence frame cannot be taken
            out["screenshot_error"] = type(ex).__name__
    return out


def _aborted(session, dev: amt_registry.Device, out_dir: Path, reason: str,
             **detail: Any) -> dict[str, Any]:
    """The structured result of a precondition abort: nothing was typed. ``screenshot`` is the
    console as it is NOW, so the caller can see what the tool refused to type into. Carries no
    secret: the Windows password is never placed here."""
    out: dict[str, Any] = {"aborted": True, "reason": reason, "device": dev.key,
                           "typed_nothing": True, **detail}
    if reason in ABORT_NOTES:
        out["note"] = ABORT_NOTES[reason]
    return _attach_screenshot(out, session, dev, out_dir)


DESKTOP_BASIS = ("classifier: the console shows the Windows desktop (taskbar present, readable "
                 "text, no sign-in or foreign-console marker)")
COMMAND_PROMPT_BASIS = "classifier: the Linux console's last line is a shell prompt (user@host:...$)"


def _already_logged_in(session, dev: amt_registry.Device, out_dir: Path, found: dict[str, Any],
                       basis: str = DESKTOP_BASIS) -> dict[str, Any]:
    """The no-op SUCCESS of a logon that finds the console already logged in (the Windows desktop,
    or a Linux shell prompt): the goal (a usable session) is met, so nothing is typed or cleared."""
    out: dict[str, Any] = {
        "aborted": False, "already_logged_in": True, "logged_in": True, "typed_nothing": True,
        "device": dev.key, **found, "logged_in_basis": basis}
    return _attach_screenshot(out, session, dev, out_dir)


def _console_findings(cls: dict[str, Any]) -> dict[str, Any]:
    """The yes/no findings a Linux-console result carries: the label, the backend and the KIND of
    prompt on the last line, never its text (the prompt line can hold the account name)."""
    m = cls["markers"]
    return {"screen_label": cls["label"], "ocr_backend": m["ocr_backend"],
            "console_prompt": m.get("console_prompt")}


def _read_console(session, user: str) -> dict[str, Any]:
    width, height = session.grab_stable()[:2]
    return classify_screen((_snapshot(session), width, height), user)


def _console_logon(session, dev: amt_registry.Device, out_dir: Path, cls: dict[str, Any],
                   user: str, password: str) -> dict[str, Any]:
    """Log into a Linux text console the first frame showed: Ctrl+U, the account name, Enter;
    then, only once getty's ``Password:`` prompt is positively read, the password and Enter.

    ONE attempt: ``Login incorrect`` (or getty's login prompt coming back) is reported as
    ``logged_in: False``, never retried. A shell prompt on the first frame is the no-op success.
    The blank check does not apply: a real tty is a few lines of text on black, which the
    structural detector reads as blank. Ctrl+U, not Ctrl+A/Delete, is the clear: in a canonical
    tty Ctrl+A is a literal character and Ctrl+U kills the line."""
    prompt = cls["markers"].get("console_prompt")
    if prompt == PROMPT_COMMAND:
        return _already_logged_in(session, dev, out_dir, _console_findings(cls), COMMAND_PROMPT_BASIS)
    if prompt != PROMPT_LOGIN:
        return _aborted(session, dev, out_dir, "console_not_at_login_prompt", **_console_findings(cls))
    key_combo(session, ("ctrl",), "u")
    try:
        session.type_text(_account_name(user))
    except amt_kvm.AmtError:
        raise amt_kvm.AmtError("logon_type_failed") from None   # the engine would name a character
    session.named_key("enter")
    for _ in range(CONSOLE_PROMPT_CHECKS):
        _pause(CONSOLE_SETTLE_SECONDS)
        cls = _read_console(session, user)
        if cls["label"] == LABEL_CONSOLE and cls["markers"].get("console_prompt") == PROMPT_PASSWORD:
            break
    else:
        return _aborted(session, dev, out_dir, "password_prompt_not_identified", typed_nothing=False,
                        account_typed=True, password_typed=False, **_console_findings(cls))
    try:
        session.type_text(password)
    except amt_kvm.AmtError:
        raise amt_kvm.AmtError("logon_type_failed") from None
    password = ""
    session.named_key("enter")
    for _ in range(CONSOLE_SUBMIT_CHECKS):   # judge once a prompt is back or a failure is printed
        _pause(CONSOLE_SUBMIT_SECONDS)
        cls = _read_console(session, user)
        m = cls["markers"]
        if m.get("login_incorrect") or m.get("console_prompt") in (PROMPT_COMMAND, PROMPT_LOGIN):
            break
    m = cls["markers"]
    out = _result_frame(session, dev, out_dir)
    out.update(aborted=False, **_console_findings(cls), login_incorrect=bool(m.get("login_incorrect")))
    if m.get("login_incorrect") or m.get("console_prompt") == PROMPT_LOGIN:
        out["logged_in"] = False
    else:
        out["logged_in"] = True if m.get("console_prompt") == PROMPT_COMMAND else None
    out["logged_in_basis"] = ("classifier: the Linux console's last line after the password "
                              "(a shell prompt, or Login incorrect / a new login prompt)")
    return out


def remote_logon(device: str = DEFAULT_DEVICE, confirmed: bool = False,
                 console: str = "kvm") -> dict[str, Any]:
    """Wake the lock screen, focus and clear the password field, type the vaulted Windows
    password once and press Enter. ONE attempt: a wrong-password screen is reported, never
    retried (Windows accounts lock out). The password is read here from the vault; it is never
    an argument, a return value, a log line or exception text, and neither is its length.

    A Linux text console is handled too, when the FIRST frame (read before any input) is
    labelled ``linux-console``: on getty's ``<host> login:`` prompt it sends Ctrl+U, the vaulted
    account name and Enter, and types the password only once a ``Password:`` prompt is read
    (``_console_logon``). A shell prompt there is the ``already_logged_in`` no-op; any other last
    line aborts with nothing typed. ``Login incorrect`` is reported as ``logged_in: False``, never
    retried. Everything below describes the Windows path.

    Positive match or abort: the password is typed ONLY into a screen OCR positively reads as
    the Windows interactive sign-in (the vaulted account's tile with a ``Password`` field below
    it, no foreign marker such as ``login:``); a Linux console, boot loader, installer, desktop,
    lock screen, dialog or blank frame is not that, and an absent OCR backend aborts too.
    Before the first input: host power is on, the console is Windows-class (not 640x480
    BIOS/POST), and no desktop taskbar is showing. The first frame is NOT OCR-gated, because
    the usual start is the lock screen, which only a wake turns into the sign-in; the wake sends
    one click and Esc, never a character. After the wake, and again on the frame right before
    the password is typed, the structural checks (plus blank) AND the OCR match must pass; the
    clear (Ctrl+A, Delete) follows the first of those. Any failure returns
    ``{"aborted": True, "reason": ...}`` with nothing typed; the result carries yes/no OCR
    findings and the backend name, never recognized text. The password-field clear is Ctrl+A
    then Delete only (no backspace sweep).

    Every screen decision is ``classify_screen``'s label. A console it labels ``desktop`` (on the
    first frame, or on the frame after the wake) is not an abort: the logon goal, a usable
    session, is already met, so the tool returns ``{"aborted": False, "already_logged_in": True,
    "logged_in": True, "typed_nothing": True, "screenshot": ...}`` having typed nothing and cleared
    nothing. The frame right before typing is not given that exit (the field clear has already
    gone out by then), so a desktop there still aborts ``host_already_logged_in``."""
    _require_confirmed(confirmed, LOGON_CONSEQUENCE)
    dev = amt_registry.get_device(device)
    amt_wsman.require_pin(dev)           # unpinned: refuse before the vault, the disk or the wire
    out_dir = _private_shot_dir()
    amt_password = amt_vault.get_secret(dev.amt_vault_key)
    host_user, host_password = _host_credential(dev)  # before the session opens: a vault miss costs nothing
    power = _power_state(device, amt_password)
    if power != POWER_ON:
        return _aborted(None, dev, out_dir, "host_not_powered_on",
                        power_state=_label(POWER_STATES, power))
    if console == "serial":
        import amt_serial   # imported here: amt_serial imports this module
        return amt_serial.console_logon(dev, amt_password, host_user, host_password)
    session = _kvm_session(dev, amt_password)
    try:  # AMT allows ONE redirection session: always close, success or not.
        session.open()
        width, height = session.grab_stable()[:2]
        first = _snapshot(session)
        problem = _context_problem(first, width, height, desktop=False)
        if problem:
            seen = _desktop_findings(problem, first, width, height, host_user)
            if seen is not None:
                return _already_logged_in(session, dev, out_dir, seen)
            return _aborted(session, dev, out_dir, problem)
        # Read the first frame BEFORE the wake: its click and Esc are for Windows, and on a getty
        # the Esc would land in the login line. Only the linux-console label changes the path.
        first_cls = classify_screen((first, width, height), host_user)
        if first_cls["label"] == LABEL_CONSOLE:
            return _console_logon(session, dev, out_dir, first_cls, host_user, host_password)
        session.click(*_at(width, height, LOGON_WAKE))
        session.named_key("escape")
        _pause(WAKE_SETTLE_SECONDS)
        for recheck in range(WAKE_RECHECKS + 1):     # re-read only while it is still the lock screen
            width, height = session.grab_stable()[:2]
            woken = _snapshot(session)
            problem, found = _screen_problem(woken, width, height, desktop=False,
                                             user=host_user, check_blank=True)
            if found.get("screen_label") != LABEL_LOCK or recheck == WAKE_RECHECKS:
                break
            _pause(WAKE_RECHECK_SECONDS)
        if problem:
            seen = _desktop_findings(problem, woken, width, height, host_user)
            if seen is not None:
                return _already_logged_in(session, dev, out_dir, seen)
            return _aborted(session, dev, out_dir, problem, **found)
        session.click(*_at(width, height, LOGON_FIELD))
        key_combo(session, ("ctrl",), "a")   # minimal clear: select-all, delete
        session.named_key("delete")
        width, height = session.grab_stable()[:2]
        before = _snapshot(session)          # the frame the password is about to be typed into
        problem, found = _screen_problem(before, width, height, desktop=False, user=host_user,
                                         check_blank=True)
        if problem:
            return _aborted(session, dev, out_dir, problem, **found)
        try:
            session.type_text(host_password)
        except amt_kvm.AmtError:
            # The engine names the offending character's code point: that is password content.
            raise amt_kvm.AmtError("logon_type_failed") from None
        host_password = ""               # drop our reference; the vault holds the value
        session.named_key("enter")
        for _ in range(SUBMIT_CHECKS):       # judge only once the box is gone, or time is up
            _pause(SUBMIT_SETTLE_SECONDS)
            width, height = session.grab_stable()[:2]
            changed = _changed_fraction(before, _snapshot(session), width, height, SIGNIN_REGION)
            if changed is None or changed >= SIGNIN_GONE_FRACTION:
                break
        out = _result_frame(session, dev, out_dir)
        changed = _changed_fraction(before, _snapshot(session), out["width"], out["height"],
                                    SIGNIN_REGION)
        out["aborted"] = False
        out["logged_in"] = None if changed is None else changed >= SIGNIN_GONE_FRACTION
        out["logged_in_basis"] = "heuristic: the sign-in region of the console changed"
        out["signin_region_changed"] = None if changed is None else round(changed, 3)
        return out
    finally:
        session.close()


def _console_logoff(session, dev: amt_registry.Device, out_dir: Path,
                    cls: dict[str, Any]) -> dict[str, Any]:
    """Log out of a Linux text console whose last line is a shell prompt: Ctrl+U (kill whatever
    is half-typed), ``exit``, Enter, then re-read until getty's login prompt is back. Any other
    last line (a login or Password: prompt, program output) aborts with nothing sent: ``exit``
    typed there would be an account name or a password attempt. One ``exit`` only, so a nested
    shell (``sudo -i``) is left one level up and reported as not logged off."""
    if cls["markers"].get("console_prompt") != PROMPT_COMMAND:
        return _aborted(session, dev, out_dir, "console_not_at_shell_prompt", **_console_findings(cls))
    key_combo(session, ("ctrl",), "u")
    session.type_text("exit")
    session.named_key("enter")
    for _ in range(CONSOLE_PROMPT_CHECKS):
        _pause(CONSOLE_SETTLE_SECONDS)
        cls = _read_console(session, "")
        if cls["markers"].get("console_prompt") == PROMPT_LOGIN:
            break
    prompt = cls["markers"].get("console_prompt")
    out = _result_frame(session, dev, out_dir)
    out.update(aborted=False, logoff_submitted=True, **_console_findings(cls))
    out["logged_off"] = True if prompt == PROMPT_LOGIN else (False if prompt == PROMPT_COMMAND else None)
    out["logged_off_basis"] = "classifier: the Linux console's last line after exit (a login prompt)"
    return out


def remote_logoff(device: str = DEFAULT_DEVICE, confirmed: bool = False,
                  console: str = "kvm") -> dict[str, Any]:
    """Win+R, type ``logoff``, Enter, from an already logged-in desktop. Keyboard only.

    Positive match or abort: before any key, host power is on, the console is Windows-class, a
    desktop taskbar IS showing, and OCR works and reads the frame as a desktop (no foreign
    marker such as ``login:``, no sign-in furniture). Logging off only makes sense from a
    logged-in desktop; on a sign-in or lock screen the text would land in a password box and a
    wrong-password attempt counts toward lockout, and on a text console it would be typed into
    a login prompt. A frame OCR cannot read, or an absent OCR backend, aborts.
    After Win+R the Run dialog must have appeared (bottom-left region changed). Any failure
    returns ``{"aborted": True, "reason": ...}`` with nothing typed; after Win+R it also sends
    Esc to dismiss whatever opened. The Win key is always released."""
    _require_confirmed(confirmed, LOGOFF_CONSEQUENCE)
    dev = amt_registry.get_device(device)
    amt_wsman.require_pin(dev)
    out_dir = _private_shot_dir()
    amt_password = amt_vault.get_secret(dev.amt_vault_key)
    power = _power_state(device, amt_password)
    if power != POWER_ON:
        return _aborted(None, dev, out_dir, "host_not_powered_on",
                        power_state=_label(POWER_STATES, power))
    if console == "serial":
        import amt_serial   # imported here: amt_serial imports this module
        return amt_serial.console_logoff(dev, amt_password)
    session = _kvm_session(dev, amt_password)
    try:
        session.open()
        width, height = session.grab_stable()[:2]
        before = _snapshot(session)
        problem, found = _screen_problem(before, width, height, desktop=True)
        if problem == "no_desktop_taskbar":   # no taskbar: a Linux console is the one other case
            cls = classify_screen((before, width, height))
            if cls["label"] == LABEL_CONSOLE:
                return _console_logoff(session, dev, out_dir, cls)
        if problem:
            return _aborted(session, dev, out_dir, problem, **found)
        key_combo(session, ("win",), "r")
        _pause(RUN_DIALOG_SETTLE_SECONDS)
        session.grab_stable()
        shown = _changed_fraction(before, _snapshot(session), width, height, RUN_DIALOG_REGION)
        if shown is None or shown < RUN_DIALOG_MIN_FRACTION:
            session.named_key("escape")      # dismiss whatever Win+R did open (e.g. Start)
            return _aborted(session, dev, out_dir, "run_dialog_not_detected")
        session.type_text("logoff")
        session.named_key("enter")
        _pause(LOGOFF_SETTLE_SECONDS)
        out = _result_frame(session, dev, out_dir)
        out["aborted"] = False
        out["logoff_submitted"] = True
        return out
    finally:
        session.close()


async def amt_remote_logon(
    device: Annotated[str, Field(
        description=f"Registered device key whose console to log on to; defaults to {DEFAULT_DEVICE}. "
                    "The device must have a TLS pin and a vaulted host credential.")] = DEFAULT_DEVICE,
    confirmed: Annotated[StrictBool, Field(
        description="Must be the JSON boolean true to proceed (\"true\" or 1 is rejected). It authorizes typing the vaulted host credential "
                    "into the console and logging into the host; false refuses and does nothing.")] = False,
    console: Annotated[Literal["kvm", "serial"], Field(
        description="Which console: kvm (default) is the screen, read by OCR and shared with a live "
                    "mirror; serial is the Linux serial getty over Serial-over-LAN, read as text and "
                    "shared with a live serial terminal.")] = "kvm",
) -> dict:
    """Logs into the host's console with the vaulted credential: the Windows interactive
    sign-in, or a Linux text console (getty). Needs confirmed=true. It first checks the host is
    powered on, the console is not a 640x480 BIOS and no desktop taskbar shows, then reads the
    first frame BEFORE any input. A Linux console at getty's login: prompt gets Ctrl+U, the
    vaulted account name and Enter, and the password only after a Password: prompt is read; a
    shell prompt there means already logged in. Otherwise it is the Windows path: wake the lock
    screen, clear the password field (Ctrl+A, Delete), type the password, Enter, and only when OCR
    POSITIVELY identifies the Windows sign-in (the vaulted account's tile with a Password field
    below it). Anything it cannot identify (a console line someone else started, boot loader,
    lock screen that did not wake, dialog, blank screen, or a node with no OCR backend) ABORTS,
    typing nothing, with aborted=true, a reason, a note and the screenshot. A console already on
    the Windows desktop or a shell prompt is the goal met: aborted=false, already_logged_in=true,
    logged_in=true, typed_nothing=true. Exactly one attempt; a wrong password (Login incorrect)
    is reported as logged_in=false, never retried. Returns the result screenshot's server-side
    path, geometry and logged_in (the Linux path judges the prompt after the password; the
    Windows path is a heuristic on the sign-in box). The password, its length and the vault value
    are never returned. console=serial does the same Linux login on the serial getty (no
    screenshot; it reads first and sends one Enter only if nothing readable came back, never at a
    Password: prompt). Refuses a device whose TLS leaf is unpinned or does not match its pin,
    and fails if another redirection session is open."""
    _require_confirmed(confirmed, LOGON_CONSEQUENCE)
    async with _session_lock(device):
        return await asyncio.to_thread(remote_logon, device, confirmed, console)


async def amt_remote_logoff(
    device: Annotated[str, Field(
        description=f"Registered device key whose console to log off; defaults to {DEFAULT_DEVICE}. "
                    "The device must have a TLS pin.")] = DEFAULT_DEVICE,
    confirmed: Annotated[StrictBool, Field(
        description="Must be the JSON boolean true to proceed (\"true\" or 1 is rejected). It authorizes signing the current Windows user "
                    "out of the host; false refuses and does nothing.")] = False,
    console: Annotated[Literal["kvm", "serial"], Field(
        description="Which console: kvm (default) is the screen, read by OCR and shared with a live "
                    "mirror; serial is the Linux serial getty over Serial-over-LAN, read as text and "
                    "shared with a live serial terminal.")] = "kvm",
) -> dict:
    """Signs the current user out of the host: on Windows Win+R, logoff, Enter; on a Linux
    console (kvm, or console=serial for the serial getty) exit and Enter, only at a shell
    prompt, then checks the login prompt is back. Needs confirmed=true. On Windows run it from a
    logged-in Windows desktop only: it first checks the host is powered on, the console is
    Windows-sized, a desktop taskbar shows and OCR reads the frame as a desktop (no login
    prompt, no sign-in screen; a node with no OCR backend aborts), then that the Run dialog
    appeared; on any doubt (a sign-in screen, a Linux console) it ABORTS, typing nothing, and
    returns aborted=true with a reason and the screenshot. Unsaved work in the session can be lost. Returns the result
    screenshot's server-side path and geometry. Refuses a device whose TLS leaf is unpinned or
    does not match its pin, and fails if another redirection session is open."""
    _require_confirmed(confirmed, LOGOFF_CONSEQUENCE)
    async with _session_lock(device):
        return await asyncio.to_thread(remote_logoff, device, confirmed, console)


# Per-tool annotation overrides on top of the read-tool defaults the server applies.
TOOL_ANNOTATION_OVERRIDES = {
    # Purpose is a read, but it takes the host's one redirection session: not idempotent.
    "amt_screenshot": {"idempotentHint": False},
    # list is a pure read; fetch mints a fresh one-time download url each call.
    "amt_captures": {"idempotentHint": False},
}

TOOL_SPECS = (
    (amt_status, "amt_status", "AMT Host Status"),
    (amt_screenshot, "amt_screenshot", "AMT Console Screenshot"),
    (amt_inventory, "amt_inventory", "AMT Hardware Inventory"),
    (amt_logs, "amt_logs", "AMT Event and Audit Logs"),
    (amt_settings, "amt_settings", "AMT Settings Area"),
    (amt_wsman_get, "amt_wsman_get", "AMT WS-MAN Get or Enumerate"),
)

# The composite WRITE tools: (function, name, title, annotation hints). The server applies
# readOnlyHint False to these; neither is idempotent (each repeats a console action) and both
# are destructive (logon issues Delete to clear the field; logoff closes the user's session).
COMPOSITE_TOOL_SPECS = (
    (amt_remote_logon, "amt_remote_logon", "AMT Remote Windows Logon", {"destructiveHint": True}),
    (amt_remote_logoff, "amt_remote_logoff", "AMT Remote Windows Logoff", {"destructiveHint": True}),
)
