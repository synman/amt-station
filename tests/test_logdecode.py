"""Readable event/audit records. Vectors marked LIVE are raw records read from my-server-1
2026-10-18 with amt_logs; the expected text is what MeshCommander's default.htm decoders give."""
import base64
import struct

import pytest

import amt_logdecode as ld
import amt_tools


def _b64(hexstr: str) -> str:
    return base64.b64encode(bytes.fromhex(hexstr)).decode()


def test_live_event_firmware_progress_from_the_me():
    # LIVE: sensor 15 (firmware progress), offset 2, severity 1, entity 38, data 40 0d.
    rec = amt_tools.decode_event_record(_b64("2b6ed46aff0f6f026801ff2600400d000000000000"))
    assert rec["description"] == "Embedded controller/management controller initialization"
    assert rec["source"] == "Intel(r) ME"
    assert (rec["severity"], rec["level"]) == ("Monitor", "info")
    assert rec["timestamp"] == "2026-10-18T06:58:51Z"
    assert rec["raw_hex"].startswith("2b6ed46a")          # raw stays alongside


def test_live_event_os_boot_from_the_bios_is_a_warning_level():
    # LIVE: severity 8, entity 34 (BIOS), data 40 13 -> progress code 19.
    rec = amt_tools.decode_event_record(_b64("2b6ed46aff0f6f026808ff22004013000000000000"))
    assert rec["description"] == "Starting operating system boot process"
    assert rec["source"] == "BIOS"
    assert (rec["severity"], rec["level"]) == ("Non-critical condition", "warning")
    assert rec["event_data"] == [0x40, 0x13, 0, 0, 0, 0, 0, 0]


def test_live_audit_kvm_session_started_by_admin():
    rec = amt_tools.decode_audit_record(_b64("00120008000561646d696e6ad51d1e000d3139382e35312e3130302e313700"))
    assert (rec["app"], rec["event"]) == ("Redirection Manager", "KVM Session Started")
    assert (rec["initiator_kind"], rec["initiator"]) == ("digest", "admin")
    assert rec["net_address"] == "198.51.100.17" and rec["timestamp"] == "2026-10-18T19:25:18Z"
    assert rec["extended_data"] is None and rec["extended_data_hex"] == ""


def test_live_audit_local_initiator_is_named():
    rec = amt_tools.decode_audit_record(_b64("00120005026ad50a7f000d3139382e35312e3130302e313700"))
    assert rec["event"] == "SoL Session Closed"
    assert (rec["initiator_kind"], rec["initiator"]) == ("local", "Local")
    assert rec["timestamp"] == "2026-10-18T18:05:51Z"


def _audit(app, event, initiator: bytes, ex: bytes = b"", epoch=0x6AD46AFF, addr=b"10.0.0.1"):
    raw = struct.pack(">HH", app, event) + initiator + struct.pack(">I", epoch) + bytes([0, len(addr)]) + addr
    return base64.b64encode(raw + bytes([len(ex)]) + ex).decode()


def test_kerberos_initiator_skips_the_domain_field_and_renders_the_sid():
    sid = bytes([1, 2]) + (5).to_bytes(6, "big") + struct.pack("<II", 21, 1001)
    initiator = bytes([1]) + struct.pack(">I", 1) + bytes([len(sid)]) + sid
    rec = amt_tools.decode_audit_record(_audit(16, 2, initiator))
    assert rec["initiator"] == "S-1-5-21-1001"
    assert rec["timestamp"].startswith("2026-")          # the time after the SID is read in place
    assert rec["net_address"] == "10.0.0.1"


def test_unknown_initiator_type_is_undecodable_not_misread():
    with pytest.raises(ValueError, match="unknown_audit_initiator_type:9"):
        amt_tools.decode_audit_record(_audit(16, 2, bytes([9])))


@pytest.mark.parametrize("key,ex,want", [
    (1607, bytes([1, 2]), "Remote ServerAuth, Local MutualAuth"),
    (3000, bytes([0, 2]), "From None to All"),
    (3001, bytes([1]), "Failed 3 times"),
    (1602, bytes([0, 4]) + b"bob1", "bob1"),
    (1617, struct.pack(">I", 2) + bytes([1]), "Redirection, Auth"),
    (1900, struct.pack(">8H", 19, 0, 5, 1992, 19, 0, 6, 2001), "From 19.0.5.1992 to 19.0.6.2001"),
    (2100, struct.pack(">I", 0x6AD46AFF), "2026-10-18T06:45:19Z"),   # 0x6AD46AFF = 1792305919
    (1607, b"", None),                                  # too short: no reading, no crash
    (1808, b"", None),                                  # no reading defined
])
def test_audit_extended_data(key, ex, want):
    assert ld.audit_extended(key, ex) == want


def test_unknown_audit_ids_keep_meshcommanders_fallback():
    out = ld.describe_audit(99, 7, 0, b"")
    assert (out["app"], out["event"]) == ("Unknown app 99", "#7")


@pytest.mark.parametrize("handle,want", [
    (0xFFFFFFFD, "All received packet filter was matched on wired interface."),
    (0xFFFFFFFA, "Spoofed packet filter was matched on wired interface."),
    (77, "Filter 77 was matched on wired interface."),
])
def test_packet_filter_handle_is_unsigned(handle, want):
    # MeshCommander's signed shift never matches the named handles; this decoder does.
    d = [0xAA, *handle.to_bytes(4, "big"), 0, 0, 0]
    assert ld.event_description(36, 0, d) == want


@pytest.mark.parametrize("sensor,offset,d,want", [
    (15, 0, [0, 8, 0, 0, 0, 0, 0, 0], "Removable boot media not found."),
    (15, 2, [0, 5, 0, 0, 0, 0, 0, 0], "Entering BIOS setup"),
    (15, 2, [0, 200, 0, 0, 0, 0, 0, 0], "Unknown firmware progress code 200"),
    (15, 2, [235, 0, 0, 0, 0, 0, 0, 0], "Invalid Data"),
    (15, 5, [170, 48, 1, 2, 0, 0, 0, 0], "AMT One Click Recovery: CSME Boot Option 2:HTTPS added successfully"),
    (192, 0, [170, 48, 2, 0, 0, 0, 0, 0], "A remote IDE-Redirection session was established."),
    (192, 1, [0, 0, 2, 0, 0, 0, 0, 0], "Security policy invoked. Some or all network traffic (RX) was stopped."),
    (6, 0, [0, 3, 1, 0, 0, 0, 0, 0], "Authentication failed 259 times. The system may be under attack."),
    (18, 0, [170, 1, 2, 3, 4, 5, 6, 4], "Agent watchdog 04030201-0605-... changed to Running"),
    (35, 0, [64, 0, 0, 0, 0, 0, 0, 0], "BIOS POST (Power On Self-Test) Watchdog Timeout."),
    (99, 0, [0] * 8, "Unknown Sensor Type #99"),
])
def test_event_descriptions(sensor, offset, d, want):
    assert ld.event_description(sensor, offset, d) == want


@pytest.mark.parametrize("code,level", [(1, "info"), (4, "info"), (8, "warning"), (16, "critical"), (32, "critical")])
def test_severity_level_follows_meshcommanders_icons(code, level):
    assert ld.severity(code)[1] == level


def test_entity_out_of_range_is_unknown():
    assert ld.entity_name(200) == "Unknown"
