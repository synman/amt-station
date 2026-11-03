"""Readable meaning for AMT event-log and audit-log records.

Pure decoding, no I/O. The tables and the description logic are ported from MeshCommander's
``default.htm`` (``_GetEventDetailStr``, ``_AmtAuditStringTable``, ``GetAuditLogExtendedDataStr``,
``GetSidString``), the same reference the parity manifest is built from. Two deliberate
departures, both where MeshCommander's own code is wrong:

* The packet-filter handle (sensor type 36) is read as an unsigned 32-bit value. MeshCommander
  adds ``byte << 24``, which JavaScript makes signed, so its named-filter checks never match.
* Every lookup that would give ``undefined`` in MeshCommander returns a labelled fallback, so a
  record always carries a description string.

Severity names are the IPMI Platform Event Trap event-severity values. ``level`` follows
MeshCommander's event-log icons: below 8 is info, 8 to 15 is warning, 16 and up is critical.
"""
from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Any

SEVERITY = {0: "Unspecified", 1: "Monitor", 2: "Information", 4: "OK", 8: "Non-critical condition",
            16: "Critical condition", 32: "Non-recoverable condition"}

FIRMWARE_ERROR = (
    "Unspecified.|No system memory is physically installed in the system.|No usable system memory, "
    "all installed memory has experienced an unrecoverable failure.|Unrecoverable hard-disk/ATAPI/IDE "
    "device failure.|Unrecoverable system-board failure.|Unrecoverable diskette subsystem failure.|"
    "Unrecoverable hard-disk controller failure.|Unrecoverable PS/2 or USB keyboard failure.|Removable "
    "boot media not found.|Unrecoverable video controller failure.|No video device detected.|Firmware "
    "(BIOS) ROM corruption detected.|CPU voltage mismatch (processors that share same supply have "
    "mismatched voltage requirements)|CPU speed matching failure").split("|")
FIRMWARE_PROGRESS = (
    "Unspecified.|Memory initialization.|Starting hard-disk initialization and test|Secondary "
    "processor(s) initialization|User authentication|Entering BIOS setup|USB resource configuration|PCI "
    "resource configuration|Option ROM initialization|Video initialization|Cache initialization|SM Bus "
    "initialization|Keyboard controller initialization|Embedded controller/management controller "
    "initialization|Docking station attachment|Enabling docking station|Docking station ejection|"
    "Disabling docking station|Calling operating system wake-up vector|Starting operating system boot "
    "process|Baseboard or motherboard initialization|reserved|Floppy initialization|Keyboard test|"
    "Pointing device test|Primary processor initialization").split("|")
ENTITY = (
    "Unspecified|Other|Unknown|Processor|Disk|Peripheral|System management module|System board|Memory "
    "module|Processor module|Power supply|Add in card|Front panel board|Back panel board|Power system "
    "board|Drive backplane|System internal expansion board|Other system board|Processor board|Power "
    "unit|Power module|Power management board|Chassis back panel board|System chassis|Sub chassis|Other "
    "chassis board|Disk drive bay|Peripheral bay|Device bay|Fan cooling|Cooling unit|Cable interconnect|"
    "Memory device|System management software|BIOS|Intel(r) ME|System bus|Group|Intel(r) ME|External "
    "environment|Battery|Processing blade|Connectivity switch|Processor/memory module|I/O module|"
    "Processor I/O module|Management controller firmware|IPMI channel|PCI bus|PCI express bus|SCSI bus|"
    "SATA/SAS bus|Processor front side bus").split("|")
REALMS = ("||Redirection||Hardware Asset|Remote Control|Storage|Event Manager|Storage Admin|Agent "
          "Presence Local|Agent Presence Remote|Circuit Breaker|Network Time|General Information|"
          "Firmware Update|EIT|LocalUN|Endpoint Access Control|Endpoint Access Control Admin|Event Log "
          "Reader|Audit Log|ACL Realm|||Local System").split("|")
WATCHDOG_STATES = {1: "Not Started", 2: "Stopped", 4: "Running", 8: "Expired", 16: "Suspended"}
OCR_PROGRESS = ["Boot parameters received from CSME", "CSME Boot Option % added successfully",
                "HTTPS URI name resolved", "HTTPS connected successfully", "HTTPSBoot download is completed",
                "Attempt to boot", "Exit boot services"]
OCR_ERROR = ["", "No network connection available", "Name resolution of URI failed", "Connect to URI failed",
             "OEM app not found at local URI", "HTTPS TLS Auth failed", "HTTPS Digest Auth failed",
             "Verified boot failed (bad image)", "HTTPS Boot File not found"]
OCR_SOURCE = {1: "", 2: "HTTPS", 4: "Local PBA", 8: "WinRE"}

AUDIT_NAMES: dict[int, str] = {
    16: "Security Admin", 17: "RCO", 18: "Redirection Manager", 19: "Firmware Update Manager",
    20: "Security Audit Log", 21: "Network Time", 22: "Network Administration", 23: "Storage Administration",
    24: "Event Manager", 25: "Circuit Breaker Manager", 26: "Agent Presence Manager",
    27: "Wireless Configuration", 28: "EAC", 29: "KVM", 30: "User Opt-In Events", 32: "Screen Blanking",
    33: "Watchdog Events",
    1600: "Provisioning Started", 1601: "Provisioning Completed", 1602: "ACL Entry Added",
    1603: "ACL Entry Modified", 1604: "ACL Entry Removed", 1605: "ACL Access with Invalid Credentials",
    1606: "ACL Entry State", 1607: "TLS State Changed", 1608: "TLS Server Certificate Set",
    1609: "TLS Server Certificate Remove", 1610: "TLS Trusted Root Certificate Added",
    1611: "TLS Trusted Root Certificate Removed", 1612: "TLS Preshared Key Set",
    1613: "Kerberos Settings Modified", 1614: "Kerberos Main Key Modified",
    1615: "Flash Wear out Counters Reset", 1616: "Power Package Modified", 1617: "Set Realm Authentication Mode",
    1618: "Upgrade Client to Admin Control Mode", 1619: "Unprovisioning Started",
    1700: "Performed Power Up", 1701: "Performed Power Down", 1702: "Performed Power Cycle",
    1703: "Performed Reset", 1704: "Set Boot Options", 1705: "Remote graceful power down initiated",
    1706: "Remote graceful reset initiated", 1707: "Remote Standby initiated", 1708: "Remote Hibernate initiated",
    1709: "Remote NMI initiated",
    1800: "IDER Session Opened", 1801: "IDER Session Closed", 1802: "IDER Enabled", 1803: "IDER Disabled",
    1804: "SoL Session Opened", 1805: "SoL Session Closed", 1806: "SoL Enabled", 1807: "SoL Disabled",
    1808: "KVM Session Started", 1809: "KVM Session Ended", 1810: "KVM Enabled", 1811: "KVM Disabled",
    1812: "VNC Password Failed 3 Times",
    1900: "Firmware Updated", 1901: "Firmware Update Failed",
    2000: "Security Audit Log Cleared", 2001: "Security Audit Policy Modified", 2002: "Security Audit Log Disabled",
    2003: "Security Audit Log Enabled", 2004: "Security Audit Log Exported", 2005: "Security Audit Log Recovered",
    2100: "Intel(r) ME Time Set",
    2200: "TCPIP Parameters Set", 2201: "Host Name Set", 2202: "Domain Name Set", 2203: "VLAN Parameters Set",
    2204: "Link Policy Set", 2205: "IPv6 Parameters Set",
    2300: "Global Storage Attributes Set", 2301: "Storage EACL Modified", 2302: "Storage FPACL Modified",
    2303: "Storage Write Operation",
    2400: "Alert Subscribed", 2401: "Alert Unsubscribed", 2402: "Event Log Cleared", 2403: "Event Log Frozen",
    2500: "CB Filter Added", 2501: "CB Filter Removed", 2502: "CB Policy Added", 2503: "CB Policy Removed",
    2504: "CB Default Policy Set", 2505: "CB Heuristics Option Set", 2506: "CB Heuristics State Cleared",
    2600: "Agent Watchdog Added", 2601: "Agent Watchdog Removed", 2602: "Agent Watchdog Action Set",
    2700: "Wireless Profile Added", 2701: "Wireless Profile Removed", 2702: "Wireless Profile Updated",
    2703: "An existing profile sync was modified", 2704: "An existing profile link preference was changed",
    2705: "Wireless profile share with UEFI enabled setting was changed",
    2800: "EAC Posture Signer SET", 2801: "EAC Enabled", 2802: "EAC Disabled", 2803: "EAC Posture State",
    2804: "EAC Set Options",
    2900: "KVM Opt-in Enabled", 2901: "KVM Opt-in Disabled", 2902: "KVM Password Changed",
    2903: "KVM Consent Succeeded", 2904: "KVM Consent Failed",
    3000: "Opt-In Policy Change", 3001: "Send Consent Code Event", 3002: "Start Opt-In Blocked Event",
    3301: "A user has modified the Watchdog Action settings",
    3302: "A user has modified a Watchdog to add, remove, or alter the Watchdog Action connected to it",
}
INITIATOR_KINDS = {0: "digest", 1: "kerberos", 2: "local", 3: "kvm_default_port"}


def _pick(table: list[str], i: int, what: str) -> str:
    return table[i] if 0 <= i < len(table) else f"Unknown {what} code {i}"


def _hex(*values: int) -> str:
    return "".join(f"{v:02X}" for v in values)


def severity(code: int) -> tuple[str, str]:
    """(name, level) for an event severity byte."""
    level = "critical" if code >= 16 else "warning" if code >= 8 else "info"
    return SEVERITY.get(code, f"Unknown severity {code}"), level


def entity_name(code: int) -> str:
    return ENTITY[code] if 0 <= code < len(ENTITY) else "Unknown"


def _firmware(offset: int, d: list[int]) -> str:
    if d[0] == 235:
        return "Invalid Data"
    if offset == 0:
        return _pick(FIRMWARE_ERROR, d[1], "firmware error")
    if offset == 3:
        if d[0] == 170 and d[1] == 48:
            return f"AMT One Click Recovery: {_pick(OCR_ERROR, d[2], 'recovery error')}"
        if d[0] == 170 and d[1] == 64:
            return {1: "Got an error erasing Device SSD", 2: "Erasing Device TPM is not supported",
                    3: "Reached Max Counter"}.get(d[2], f"Platform erase error code {d[2]}")
        return "OEM Specific Firmware Error event"
    if offset == 5:
        if d[0] == 170 and d[1] == 48:
            if d[2] == 1:
                return (f"AMT One Click Recovery: CSME Boot Option {d[3]}:{OCR_SOURCE.get(d[3], '')} "
                        "added successfully")
            if d[2] < 7:
                return f"AMT One Click Recovery: {OCR_PROGRESS[d[2]]}"
            return f"AMT One Click Recovery: Unknown progress event {d[2]}"
        if d[0] == 170 and d[1] == 64:
            target = {2: "SSD", 3: "TPM", 5: "BIOS Reload of Golden Config"}.get(d[3])
            if d[2] == 1 and target:
                return f"Started erasing Device {target}"
            if d[2] == 2 and target:
                return f"Erasing Device {target} ended successfully"
            return {3: "Beginning Platform Erase", 4: "Clear Reserved Parameters",
                    5: "All setting decremented"}.get(d[2], f"Platform erase progress code {d[2]}")
        return "OEM Specific Firmware Progress event"
    return _pick(FIRMWARE_PROGRESS, d[1], "firmware progress")


def event_description(sensor_type: int, offset: int, d: list[int]) -> str:
    """MeshCommander's ``_GetEventDetailStr``: one readable line for an event record."""
    if sensor_type == 15:
        return _firmware(offset, d)
    if sensor_type == 18 and d[0] == 170:
        state = WATCHDOG_STATES.get(d[7], f"state {d[7]}")
        return f"Agent watchdog {_hex(d[4], d[3], d[2], d[1])}-{_hex(d[6], d[5])}-... changed to {state}"
    if sensor_type == 5 and offset == 0:
        return "Case intrusion"
    if sensor_type == 192 and offset == 0 and d[0] == 170 and d[1] == 48 and d[2] in (0, 1, 2, 3):
        return ("A remote Serial Over LAN session was established.",
                "Remote Serial Over LAN session finished. User control was restored.",
                "A remote IDE-Redirection session was established.",
                "Remote IDE-Redirection session finished. User control was restored.")[d[2]]
    if sensor_type == 36:
        handle = int.from_bytes(bytes(d[1:5]), "big")   # unsigned, unlike MeshCommander's signed shift
        nic = "wired" if d[0] == 0xAA else f"#{d[0]}"
        named = {0xFFFFFFFD: "All received packet filter", 0xFFFFFFFC: "All outbound packet filter",
                 0xFFFFFFFA: "Spoofed packet filter"}
        return f"{named.get(handle, f'Filter {handle}')} was matched on {nic} interface."
    if sensor_type == 192:
        return {0: "Security policy invoked. Some or all network traffic (TX) was stopped.",
                2: "Security policy invoked. Some or all network traffic (RX) was stopped."}.get(
                    d[2], "Security policy invoked.")
    if sensor_type == 193 and d[0] == 0xAA:
        key = (d[1], d[2], d[3])
        known = {(0x30, 0x00, 0x00): "User request for remote connection.",
                 (0x20, 0x03, 0x01): "EAC error: attempt to get posture while NAC in Intel(r) AMT is disabled.",
                 (0x20, 0x04, 0x00): "HWA Error: general error"}
        if key in known:
            return known[key]
    if sensor_type == 6:
        return f"Authentication failed {d[1] + (d[2] << 8)} times. The system may be under attack."
    if sensor_type == 30:
        return "No bootable media"
    if sensor_type == 32:
        return "Operating system lockup or power interrupt"
    if sensor_type == 35:
        return "BIOS POST (Power On Self-Test) Watchdog Timeout." if d[0] == 64 else "System boot failure"
    if sensor_type == 37:
        return "System firmware started (at least one CPU is properly executing)."
    return f"Unknown Sensor Type #{sensor_type}"


def describe_event(sensor_type: int, offset: int, severity_code: int, entity: int,
                   data: bytes) -> dict[str, Any]:
    """The readable fields added to a decoded event record."""
    d = list(data[:8]) + [0] * (8 - len(data[:8]))
    name, level = severity(severity_code)
    return {"description": event_description(sensor_type, offset, d), "source": entity_name(entity),
            "severity": name, "level": level, "event_data": d}


def sid_string(sid: bytes) -> str:
    """Windows SID bytes as ``S-<rev>-<authority>-<sub>...``."""
    if len(sid) < 8:
        return sid.hex()
    count = min(sid[1], (len(sid) - 8) // 4)
    subs = struct.unpack_from(f"<{count}I", sid, 8)
    return "-".join(["S", str(sid[0]), str(int.from_bytes(sid[2:8], "big")), *map(str, subs)])


def _iso(epoch: int) -> str:
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def audit_extended(event_key: int, ex: bytes) -> str | None:
    """MeshCommander's ``GetAuditLogExtendedDataStr``; ``None`` where it has no reading."""
    def text(a: int, b: int | None = None) -> str:
        return ex[a:b].decode("latin-1")
    try:
        if event_key in (1602, 1604) and ex[0] == 0:
            return text(2, 2 + ex[1])
        if event_key == 1603:
            return text(3) if ex[1] == 0 else None
        if event_key == 1605:
            return ("Invalid ME access", "Invalid MEBx access")[ex[0]]
        if event_key == 1606:
            state = ("Disabled", "Enabled")[ex[0]]
            return f"{state}, {text(3)}" if ex[1] == 0 else state
        if event_key == 1607:
            modes = ("NoAuth", "ServerAuth", "MutualAuth")
            return f"Remote {modes[ex[0]]}, Local {modes[ex[1]]}"
        if event_key == 1617:
            realm = struct.unpack_from(">I", ex, 0)[0]
            return f"{_pick(REALMS, realm, 'realm')}, {('NoAuth', 'Auth', 'Disabled')[ex[4]]}"
        if event_key == 1619:
            return ("BIOS", "MEBx", "Local MEI", "Local WSMAN", "Remote WSMAN")[ex[0]]
        if event_key == 1900:
            v = struct.unpack_from(">8H", ex, 0)
            return f"From {'.'.join(map(str, v[:4]))} to {'.'.join(map(str, v[4:]))}"
        if event_key == 2100:
            return _iso(struct.unpack_from(">I", ex, 0)[0])
        if event_key == 3000:
            policies = ("None", "KVM", "All")
            return f"From {policies[ex[0]]} to {policies[ex[1]]}"
        if event_key == 3001:
            return ("Success", "Failed 3 times")[ex[0]]
    except (IndexError, struct.error):
        return None   # too short or out of range for its layout: the raw hex is still returned
    return None


def describe_audit(app_id: int, event_id: int, initiator_type: int, ex: bytes) -> dict[str, Any]:
    """The readable fields added to a decoded audit record."""
    key = app_id * 100 + event_id
    return {"app": AUDIT_NAMES.get(app_id, f"Unknown app {app_id}"),
            "event": AUDIT_NAMES.get(key, f"#{event_id}"),
            "initiator_kind": INITIATOR_KINDS.get(initiator_type, f"unknown ({initiator_type})"),
            "extended_data": audit_extended(key, ex), "extended_data_hex": ex.hex()}
