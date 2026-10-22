"""Read-tool tests with MOCKED AMT. No test opens a socket, reads the real vault or calls AMT.

``amt_wsman.transport`` (the only network function) is replaced by ``FakeAmt``, which serves
canned SOAP bodies and records every request so the suite can assert that nothing but
Get / Enumerate / Pull / allowlisted reader methods is ever sent. ``amt_kvm.KvmSession`` is
replaced so no KVM socket opens. Canned XML is the documented AMT response shape; whether
the real device answers these class names this way is the later live read-verify.
"""
import asyncio
import base64
import json
import re
import struct
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import amt_gate  # noqa: E402
import amt_parity  # noqa: E402
import amt_server  # noqa: E402
import amt_tools  # noqa: E402
import amt_vault  # noqa: E402
import amt_wsman  # noqa: E402
from test_skeleton import TOKEN, TOKEN_HASH, _call, _client  # noqa: E402

AMT = "http://intel.com/wbem/wscim/1/amt-schema/1/"
IPS = "http://intel.com/wbem/wscim/1/ips-schema/1/"
CIM = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
VAULT_SENTINEL = "PW-SENTINEL-not-a-real-secret"


def soap(body: str) -> str:
    return ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:x="http://www.w3.org/2001/XMLSchema-instance"><s:Header/>'
            f"<s:Body>{body}</s:Body></s:Envelope>")


def inst(cls: str, **fields) -> str:
    inner = "".join(f"<g:{k}>{v}</g:{k}>" for k, v in fields.items())
    return f'<g:{cls} xmlns:g="urn:test">{inner}</g:{cls}>'


FAULT = soap("<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code>"
             "<s:Reason><s:Text>No such class</s:Text></s:Reason></s:Fault>")


class FakeAmt:
    """Canned WS-MAN endpoint. ``singles[cls]`` answers Get; ``lists[cls]`` answers
    Enumerate+Pull (a list of pages, each a list of instance bodies); ``methods[(cls, m)]``
    is a list of responses served in order."""

    def __init__(self):
        self.singles, self.lists, self.methods = {}, {}, {}
        self.calls = []          # (action_leaf, class_name, raw_xml)
        self.passwords = []      # the password argument of every transport call
        self._pages = {}

    def __call__(self, device, xml, password=None):
        self.passwords.append(password)
        action = re.search(r"<a:Action>([^<]+)</a:Action>", xml).group(1)
        cls = re.search(r"<w:ResourceURI>[^<]*/([A-Za-z0-9_]+)</w:ResourceURI>", xml).group(1)
        leaf = action.rsplit("/", 1)[-1]
        self.calls.append((leaf, cls, xml))
        if leaf == "Get":
            return soap(self.singles[cls]) if cls in self.singles else FAULT
        if leaf == "Enumerate":
            if cls not in self.lists:
                return FAULT
            self._pages[cls] = list(self.lists[cls])
            return soap("<n:EnumerateResponse xmlns:n='http://schemas.xmlsoap.org/ws/2004/09/enumeration'>"
                        "<n:EnumerationContext>ctx-1</n:EnumerationContext></n:EnumerateResponse>")
        if leaf == "Pull":
            page = self._pages[cls].pop(0)
            end = "<n:EndOfSequence/>" if not self._pages[cls] else \
                "<n:EnumerationContext>ctx-2</n:EnumerationContext>"
            return soap("<n:PullResponse xmlns:n='http://schemas.xmlsoap.org/ws/2004/09/enumeration'>"
                        f"<n:Items>{''.join(page)}</n:Items>{end}</n:PullResponse>")
        if (cls, leaf) in self.methods:
            return soap(self.methods[(cls, leaf)].pop(0))
        return FAULT

    @property
    def actions(self):
        return {leaf for leaf, _, _ in self.calls}


def standard_amt() -> FakeAmt:
    f = FakeAmt()
    f.singles.update({
        "CIM_AssociatedPowerManagementService": inst("CIM_AssociatedPowerManagementService", PowerState=2),
        "AMT_SetupAndConfigurationService": inst(
            "AMT_SetupAndConfigurationService", ProvisioningMode=4, ProvisioningState=2,
            ZeroTouchConfigurationEnabled="true"),
        "IPS_HostBasedSetupService": inst("IPS_HostBasedSetupService", CurrentControlMode=1),
        "AMT_RedirectionService": inst("AMT_RedirectionService", ListenerEnabled="true", EnabledState=32771),
        "CIM_KVMRedirectionSAP": inst("CIM_KVMRedirectionSAP", EnabledState=6),
        "IPS_KVMRedirectionSettingData": inst(
            "IPS_KVMRedirectionSettingData", Is5900PortEnabled="false", SessionTimeout=0,
            RFBPassword="rfb-secret-must-not-leak"),
        "IPS_OptInService": inst("IPS_OptInService", OptInRequired=4294967295, OptInState=0,
                                 CanModifyOptInPolicy="true"),
        "AMT_BootSettingData": inst("AMT_BootSettingData", BIOSSetup="false", UseSOL="false",
                                    BootMediaIndex=0, OwningEntity=32768),
    })
    f.lists["CIM_SoftwareIdentity"] = [[
        inst("CIM_SoftwareIdentity", InstanceID="AMT", VersionString="16.1.25"),
        inst("CIM_SoftwareIdentity", InstanceID="Build Number", VersionString="2539"),
        inst("CIM_SoftwareIdentity", InstanceID="Sku", VersionString="16392"),
    ]]
    return f


@pytest.fixture(autouse=True)
def _env(monkeypatch):
    monkeypatch.setenv(amt_gate.HASH_ENV, TOKEN_HASH)
    monkeypatch.delenv(amt_gate.TRANSPORT_ENV, raising=False)
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: VAULT_SENTINEL)


@pytest.fixture
def amt(monkeypatch):
    fake = standard_amt()
    monkeypatch.setattr(amt_wsman, "transport", fake)
    return fake


# --- amt_status -----------------------------------------------------------------------------

def test_status_parses_into_typed_fields(amt):
    s = amt_tools.status()
    assert s["power"] == {"state": "on", "code": 2}
    assert s["amt"]["version"] == "16.1.25" and s["amt"]["build_number"] == "2539"
    assert s["amt"]["sku"] == "16392" and s["amt"]["firmware"]["AMT"] == "16.1.25"
    p = s["provisioning"]
    assert (p["mode"], p["state"], p["control_mode"]) == ("client", "post_provisioning", "client_control_mode")
    assert p["zero_touch_enabled"] is True
    r = s["redirection"]
    assert r["listener_enabled"] is True and r["sol_enabled"] is True and r["ider_enabled"] is True
    assert r["kvm"]["state"] == "enabled_offline" and r["kvm"]["enabled"] is True
    assert r["kvm"]["port_5900_enabled"] is False and r["kvm"]["session_timeout"] == 0
    c = s["user_consent"]
    assert c["required_for"] == "all" and c["state"] == "not_started" and c["can_modify_policy"] is True
    assert s["next_boot"]["BIOSSetup"] is False and s["next_boot"]["BootMediaIndex"] == 0


def test_status_never_carries_a_secret_or_an_error_field(amt):
    dumped = json.dumps(amt_tools.status())
    assert VAULT_SENTINEL not in dumped and "rfb-secret-must-not-leak" not in dumped
    assert "error" not in amt_tools.status()


def test_status_degrades_per_class_and_discloses_what_is_missing(amt):
    del amt.singles["IPS_OptInService"]
    s = amt_tools.status()
    assert s["unavailable"] == ["IPS_OptInService"] and s["truncated"] == []
    assert "No such class" in s["unavailable_reasons"]["IPS_OptInService"]
    assert s["user_consent"]["required_for"] is None and s["user_consent"]["state"] is None
    assert s["power"]["state"] == "on" and s["amt"]["version"] == "16.1.25"      # the rest survives


def test_status_reports_no_unavailable_classes_when_all_resolve(amt):
    s = amt_tools.status()
    assert s["unavailable"] == [] and s["truncated"] == [] and "unavailable_reasons" not in s


@pytest.mark.parametrize("err", ["wsman_auth_failed_401", "tls_leaf_pin_mismatch",
                                 "wsman_unreachable:ConnectionRefusedError", "wsman_bad_status_line"])
def test_non_fault_errors_are_never_degraded_to_unavailable(amt, monkeypatch, err):
    def broken(device, xml, password=None):
        raise amt_wsman.WsmanError(err)

    monkeypatch.setattr(amt_wsman, "transport", broken)
    for call in (amt_tools.status, amt_tools.inventory, lambda: amt_tools.settings("kvm"),
                 lambda: amt_tools.wsman_get("AMT_X")):
        with pytest.raises(amt_wsman.WsmanError) as ex:
            call()
        assert str(ex.value) == err


def test_password_is_resolved_once_per_tool_call(amt, monkeypatch):
    calls = []
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: calls.append(key) or VAULT_SENTINEL)
    amt_tools.status()
    assert calls == ["my-server-1-amt"] and len(amt.calls) > 8
    assert set(amt.passwords) == {VAULT_SENTINEL}, "every request must reuse the one resolved password"
    calls.clear()
    amt.lists["CIM_Chassis"] = [[inst("CIM_Chassis", Tag="1")]]
    amt_tools.inventory(["chassis"])
    assert calls == ["my-server-1-amt"]
    calls.clear()
    amt.methods[("AMT_AuditLog", "ReadRecords")] = [
        "<g:O xmlns:g='u'><g:TotalRecordCount>0</g:TotalRecordCount></g:O>"]
    amt_tools.logs("audit")
    assert calls == ["my-server-1-amt"]
    calls.clear()
    amt_tools.settings("kvm"); amt_tools.wsman_get("AMT_BootSettingData")
    assert calls == ["my-server-1-amt", "my-server-1-amt"]


# --- amt_screenshot -------------------------------------------------------------------------

PIN = amt_wsman.amt_registry.get_device("my-server-1").tls_leaf_sha256


class FakeKvm:
    instances = []
    fail_open = False
    presented_fp = PIN
    hold = None          # a threading.Event: open() blocks until it is set

    def __init__(self, host, port=16995, pw=None, key_delay=0.02):
        self.host, self.port, self.pw = host, port, pw
        self.closed = False
        self.past_connect = False
        self.cert_fp = None
        FakeKvm.instances.append(self)

    def connect(self):
        self.cert_fp = FakeKvm.presented_fp

    def open(self, deadline=None):
        self.connect()                 # the real engine's open() dials via self.connect()
        self.past_connect = True       # i.e. KVMR start / digest answer would go out from here
        if FakeKvm.hold is not None:
            FakeKvm.hold.wait(5)
        if FakeKvm.fail_open:
            raise amt_tools.amt_kvm.AmtError("auth_rejected_no_retry")
        return 1920, 1080

    def grab_stable(self, **kw):
        return 1920, 1080, 3, True, 1234

    def write_png(self, path):
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\nfake")
        return path

    def close(self):
        self.closed = True


@pytest.fixture
def kvm(monkeypatch, tmp_path):
    FakeKvm.instances, FakeKvm.fail_open = [], False
    FakeKvm.presented_fp, FakeKvm.hold = PIN, None
    monkeypatch.setattr(amt_tools.amt_kvm, "KvmSession", FakeKvm)
    monkeypatch.setenv(amt_tools.SHOT_DIR_ENV, str(tmp_path / "shots"))
    return FakeKvm


def test_screenshot_returns_expected_shape_and_closes(kvm, tmp_path):
    out = amt_tools.screenshot()
    assert out["device"] == "my-server-1" and (out["width"], out["height"]) == (1920, 1080)
    assert out["stable"] is True and out["iterations"] == 3 and out["delta_bits"] == 1234
    assert out["tls_leaf_sha256"] == PIN
    png = Path(out["path"])
    assert png.parent == tmp_path / "shots" and png.suffix == ".png" and out["bytes"] == png.stat().st_size
    assert "AMT_PUBLIC_BASE_URL" in out["path_note"] and "url" not in out
    (s,) = kvm.instances
    assert (s.host, s.port) == ("198.51.100.26", 16995)
    assert s.pw == VAULT_SENTINEL, "password must come from amt_vault, not the engine's own reader"
    assert s.closed is True
    assert VAULT_SENTINEL not in json.dumps(out)


def test_screenshot_closes_the_single_amt_session_on_failure(kvm):
    kvm.fail_open = True
    with pytest.raises(amt_tools.amt_kvm.AmtError):
        amt_tools.screenshot()
    assert kvm.instances[0].closed is True


# --- amt_inventory --------------------------------------------------------------------------

def test_inventory_sections_are_typed_and_identifiers_stay_strings(amt):
    amt.lists["CIM_PhysicalMemory"] = [[
        inst("CIM_PhysicalMemory", BankLabel="BANK 0", Capacity=17179869184, Speed=5600,
             SerialNumber="00012345", PartNumber="M425R2GA3BB0"),
        inst("CIM_PhysicalMemory", BankLabel="BANK 1", Capacity=17179869184, Speed=5600,
             SerialNumber="67890", PartNumber="X"),
    ]]
    amt.lists["CIM_MediaAccessDevice"] = [[inst("CIM_MediaAccessDevice", DeviceID="Media 0", MaxMediaSize=1000204886016)]]
    out = amt_tools.inventory(["memory", "storage_media"])
    assert set(out["sections"]) == {"memory", "storage_media"}
    mem = out["sections"]["memory"]
    assert [m["Capacity"] for m in mem] == [17179869184, 17179869184] and mem[0]["Speed"] == 5600
    assert mem[0]["SerialNumber"] == "00012345" and mem[1]["SerialNumber"] == "67890"
    assert out["sections"]["storage_media"][0] == {"DeviceID": "Media 0", "MaxMediaSize": 1000204886016}
    assert out["classes"]["memory"] == "CIM_PhysicalMemory"


def test_inventory_default_reads_every_section_and_rejects_unknown(amt):
    for cls in amt_tools.INVENTORY_CLASSES.values():
        amt.lists[cls] = [[inst(cls, InstanceID="1")]]
    full = amt_tools.inventory()
    assert set(full["sections"]) == set(amt_tools.INVENTORY_CLASSES)
    assert full["unavailable"] == [] and full["truncated"] == []
    with pytest.raises(ValueError, match="unknown_inventory_section:disks"):
        amt_tools.inventory(["disks"])


def test_inventory_degrades_when_a_class_is_not_exposed(amt):
    """The live AMT answers a fault for CIM_PhysicalMedia: data for the rest, class disclosed."""
    for cls in amt_tools.INVENTORY_CLASSES.values():
        if cls != "CIM_PhysicalMedia":
            amt.lists[cls] = [[inst(cls, InstanceID="1")]]
    out = amt_tools.inventory()
    assert out["unavailable"] == ["CIM_PhysicalMedia"]
    assert "physical_media" not in out["sections"] and "physical_media" not in out["classes"]
    assert set(out["sections"]) == set(amt_tools.INVENTORY_CLASSES) - {"physical_media"}
    assert "No such class" in out["unavailable_reasons"]["CIM_PhysicalMedia"]


def test_truncation_is_propagated_not_discarded(amt):
    amt.lists["CIM_Processor"] = [[inst("CIM_Processor", DeviceID=str(i)) for i in range(501)]]
    out = amt_tools.inventory(["processors"])
    assert out["truncated"] == ["CIM_Processor"] and len(out["sections"]["processors"]) == 500
    amt.lists["CIM_Processor"] = [[inst("CIM_Processor", DeviceID=str(i)) for i in range(500)]]
    assert amt_tools.inventory(["processors"])["truncated"] == []
    amt.lists["AMT_TLSSettingData"] = [[inst("AMT_TLSSettingData", InstanceID=str(i)) for i in range(501)]]
    amt.lists["AMT_PublicKeyCertificate"] = [[inst("AMT_PublicKeyCertificate", InstanceID="1")]]
    amt.singles["AMT_AuthorizationService"] = inst("AMT_AuthorizationService", EnabledState=5)
    assert amt_tools.settings("security")["truncated"] == ["AMT_TLSSettingData"]


# --- amt_logs -------------------------------------------------------------------------------

def event_rec(epoch, sensor=1, severity=4):
    raw = struct.pack("<I", epoch) + bytes([0x20, sensor, 0x6F, 3, 0x6F, severity, 9, 0x23, 0]) + bytes(range(8))
    return base64.b64encode(raw).decode()


def audit_rec(epoch, user="admin", addr="10.0.0.9", app=16, event=3):
    # AMT audit records are BIG-endian (verified live on my-server-1 2026-10-18).
    raw = (struct.pack(">HH", app, event) + bytes([0, len(user)]) + user.encode()
           + struct.pack(">I", epoch) + bytes([1, len(addr)]) + addr.encode() + bytes([2]) + b"hi")
    return base64.b64encode(raw).decode()


T0 = 1_760_000_000   # 2025-10-09T08:53:20Z
DAY = 86_400


def test_event_log_orders_newest_first_pages_and_filters(amt):
    recs = [event_rec(T0 + i * DAY, sensor=i) for i in range(5)]
    recs.insert(2, base64.b64encode(b"\x01\x02").decode())      # undecodable
    recs.append(event_rec(0))                                    # AMT clock not set
    ra = "".join(f"<g:RecordArray>{r}</g:RecordArray>" for r in recs)
    amt.methods[("AMT_MessageLog", "GetRecords")] = [
        f"<g:GetRecords_OUTPUT xmlns:g='u'>{ra}<g:NoMoreRecords>true</g:NoMoreRecords>"
        "<g:ReturnValue>0</g:ReturnValue></g:GetRecords_OUTPUT>"]
    out = amt_tools.logs("event", limit=3)
    assert (out["fetched"], out["fetch_complete"], out["undecodable"], out["undated"]) == (7, True, 1, 2)
    assert out["matched"] == 7 and out["returned"] == 3
    assert [r["sensor_type"] for r in out["records"] if r["decoded"]] == [4, 3, 2]
    assert out["records"][0]["timestamp"] == amt_tools._iso(T0 + 4 * DAY)
    assert out["records"][0]["event_data_hex"] == "0001020304050607"

    amt.methods[("AMT_MessageLog", "GetRecords")] = [
        f"<g:GetRecords_OUTPUT xmlns:g='u'>{ra}<g:NoMoreRecords>true</g:NoMoreRecords></g:GetRecords_OUTPUT>"]
    since = amt_tools._iso(T0 + 1 * DAY)
    until = amt_tools._iso(T0 + 3 * DAY)
    filt = amt_tools.logs("event", since=since, until=until)
    assert [r["sensor_type"] for r in filt["records"]] == [3, 2, 1]   # undated/undecodable excluded
    assert filt["matched"] == 3

    amt.methods[("AMT_MessageLog", "GetRecords")] = [
        f"<g:GetRecords_OUTPUT xmlns:g='u'>{ra}<g:NoMoreRecords>true</g:NoMoreRecords></g:GetRecords_OUTPUT>"]
    page2 = amt_tools.logs("event", offset=3, limit=2)
    assert [r["sensor_type"] for r in page2["records"] if r["decoded"]] == [1, 0]


def test_event_log_invokes_the_amt_singleton_with_no_selector(amt):
    """Live: GetRecords is addressed to AMT_MessageLog (amt-schema URI), with no SelectorSet."""
    amt.methods[("AMT_MessageLog", "GetRecords")] = [_out("<g:NoMoreRecords>true</g:NoMoreRecords>")]
    amt_tools.logs("event")
    (leaf, cls, xml), = amt.calls
    assert (leaf, cls) == ("GetRecords", "AMT_MessageLog")
    assert f"<w:ResourceURI>{AMT}AMT_MessageLog</w:ResourceURI>" in xml
    assert f'<h:GetRecords_INPUT xmlns:h="{AMT}AMT_MessageLog">' in xml
    assert "SelectorSet" not in xml and "CIM_MessageLog" not in xml


def test_event_log_follows_iteration_until_no_more(amt):
    first = ("<g:GetRecords_OUTPUT xmlns:g='u'>"
             f"<g:RecordArray>{event_rec(T0)}</g:RecordArray><g:IterationIdentifier>2</g:IterationIdentifier>"
             "<g:NoMoreRecords>false</g:NoMoreRecords></g:GetRecords_OUTPUT>")
    second = ("<g:GetRecords_OUTPUT xmlns:g='u'>"
              f"<g:RecordArray>{event_rec(T0 + 1)}</g:RecordArray>"
              "<g:NoMoreRecords>true</g:NoMoreRecords></g:GetRecords_OUTPUT>")
    amt.methods[("AMT_MessageLog", "GetRecords")] = [first, second]
    out = amt_tools.logs("event")
    assert out["fetched"] == 2 and out["fetch_complete"] is True
    sent = [x for leaf, c, x in amt.calls if leaf == "GetRecords"]
    assert "<h:IterationIdentifier>1</h:IterationIdentifier>" in sent[0]
    assert "<h:IterationIdentifier>2</h:IterationIdentifier>" in sent[1]


def test_audit_log_decodes_initiator_time_and_address(amt):
    ra = "".join(f"<g:EventRecords>{audit_rec(T0 + i, user=f'u{i}')}</g:EventRecords>" for i in range(3))
    amt.methods[("AMT_AuditLog", "ReadRecords")] = [
        f"<g:ReadRecords_OUTPUT xmlns:g='u'><g:TotalRecordCount>3</g:TotalRecordCount>"
        f"<g:RecordsReturned>3</g:RecordsReturned>{ra}<g:ReturnValue>0</g:ReturnValue></g:ReadRecords_OUTPUT>"]
    out = amt_tools.logs("audit", limit=10)
    assert out["fetched"] == 3 and out["fetch_complete"] is True and out["undecodable"] == 0
    newest = out["records"][0]
    assert newest["initiator"] == "u2" and newest["net_address"] == "10.0.0.9" and newest["extended_data_hex"] == b"hi".hex()
    assert (newest["app_id"], newest["event_id"]) == (16, 3) and newest["epoch"] == T0 + 2


def test_logs_rejects_bad_arguments_and_nonzero_return(amt):
    with pytest.raises(ValueError, match="unknown_log_kind"):
        amt_tools.logs("syslog")
    with pytest.raises(ValueError, match="invalid_since"):
        amt_tools.logs("event", since="yesterday")
    with pytest.raises(ValueError, match="invalid_paging"):
        amt_tools.logs("event", limit=0)
    amt.methods[("AMT_MessageLog", "GetRecords")] = [
        "<g:GetRecords_OUTPUT xmlns:g='u'><g:ReturnValue>2</g:ReturnValue></g:GetRecords_OUTPUT>"]
    with pytest.raises(amt_wsman.WsmanError, match="wsman_return_value:AMT_MessageLog.GetRecords:2"):
        amt_tools.logs("event")


# --- amt_settings ---------------------------------------------------------------------------

def test_every_settings_area_is_wired_and_matches_the_tool_schema():
    assert set(amt_tools.SETTINGS_AREA_NAMES) == {
        "network", "internet", "security", "agent_presence", "system_defense", "users",
        "subscriptions", "wake_alarms", "kvm", "features"}
    schema = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}["amt_settings"].inputSchema
    assert set(schema["properties"]["area"]["enum"]) == set(amt_tools.SETTINGS_AREA_NAMES)


def test_settings_security_strips_blobs_and_secrets(amt):
    amt.lists["AMT_TLSSettingData"] = [[inst("AMT_TLSSettingData", InstanceID="Intel(r) AMT 802.3 TLS Settings",
                                             Enabled="true", MutualAuthentication="false")]]
    amt.lists["AMT_PublicKeyCertificate"] = [[inst(
        "AMT_PublicKeyCertificate", InstanceID="Intel(r) AMT Certificate: Handle: 0",
        X509Certificate="A" * 900, Subject="CN=amt", TrustedRootCertficate="false", CertPassword="x-leak")]]
    amt.singles["AMT_AuthorizationService"] = inst("AMT_AuthorizationService", EnabledState=5)
    out = amt_tools.settings("security")
    assert out["area"] == "security" and out["sections"]["tls"][0]["Enabled"] is True
    cert = out["sections"]["certificates"][0]
    assert cert["X509Certificate"] == "<900 chars omitted>" and cert["Subject"] == "CN=amt"
    assert cert["TrustedRootCertficate"] is False and cert["CertPassword"] == "<redacted>"
    assert out["classes"]["tls"] == "AMT_TLSSettingData"


def test_settings_kvm_area_redacts_rfb_password(amt):
    amt.singles["CIM_KVMRedirectionSAP"] = inst("CIM_KVMRedirectionSAP", EnabledState=2)
    out = amt_tools.settings("kvm")
    assert out["sections"]["settings"]["RFBPassword"] == "<redacted>"
    assert "rfb-secret-must-not-leak" not in json.dumps(out)


def test_settings_users_walks_acl_handles(amt):
    amt.methods[("AMT_AuthorizationService", "EnumerateUserAclEntries")] = [
        "<g:EnumerateUserAclEntries_OUTPUT xmlns:g='u'><g:TotalCount>2</g:TotalCount>"
        "<g:Handles>1</g:Handles><g:Handles>2</g:Handles><g:ReturnValue>0</g:ReturnValue>"
        "</g:EnumerateUserAclEntries_OUTPUT>"]
    amt.methods[("AMT_AuthorizationService", "GetUserAclEntryEx")] = [
        "<g:GetUserAclEntryEx_OUTPUT xmlns:g='u'><g:DigestUsername>admin</g:DigestUsername>"
        "<g:AccessPermission>2</g:AccessPermission><g:ReturnValue>0</g:ReturnValue></g:GetUserAclEntryEx_OUTPUT>",
        "<g:GetUserAclEntryEx_OUTPUT xmlns:g='u'><g:DigestUsername>ops</g:DigestUsername>"
        "<g:AccessPermission>0</g:AccessPermission><g:ReturnValue>0</g:ReturnValue></g:GetUserAclEntryEx_OUTPUT>"]
    users = amt_tools.settings("users")["sections"]["users"]
    assert [u["DigestUsername"] for u in users] == ["admin", "ops"]
    assert users[0]["AccessPermission"] == 2


def test_settings_unknown_area_raises(amt):
    with pytest.raises(ValueError, match="unknown_settings_area:wifi"):
        amt_tools.settings("wifi")


# --- amt_wsman_get --------------------------------------------------------------------------

def test_wsman_get_sends_selectors_and_returns_raw_strings(amt):
    amt.singles["CIM_BootConfigSetting"] = inst("CIM_BootConfigSetting", InstanceID="Intel(r) AMT: Boot Configuration 0",
                                                ElementName="Boot", Priority="0")
    out = amt_tools.wsman_get("CIM_BootConfigSetting", "get",
                              {"InstanceID": "Intel(r) AMT: Boot Configuration 0"})
    assert out["instance"] == {"InstanceID": "Intel(r) AMT: Boot Configuration 0", "ElementName": "Boot",
                               "Priority": "0"}
    (leaf, cls, xml), = amt.calls
    assert (leaf, cls) == ("Get", "CIM_BootConfigSetting")
    assert 'Selector Name="InstanceID">Intel(r) AMT: Boot Configuration 0<' in xml
    assert f"<w:ResourceURI>{CIM}CIM_BootConfigSetting</w:ResourceURI>" in xml


def test_wsman_enumerate_pages_and_reports_truncation(amt):
    pages = [[inst("AMT_X", N=i) for i in range(p * 3, p * 3 + 3)] for p in range(3)]
    amt.lists["AMT_EthernetPortSettings"] = [list(p) for p in pages]
    out = amt_tools.wsman_get("AMT_EthernetPortSettings", "enumerate", max_items=200)
    assert out["count"] == 9 and out["truncated"] is False and out["instances"][8] == {"N": "8"}
    assert [c for c in amt.calls if c[0] == "Pull"].__len__() == 3

    amt.calls.clear()
    amt.lists["AMT_EthernetPortSettings"] = [list(p) for p in pages]
    capped = amt_tools.wsman_get("AMT_EthernetPortSettings", "enumerate", max_items=4)
    assert capped["count"] == 4 and capped["truncated"] is True


def test_wsman_get_validates_input_and_redacts_passwords(amt):
    for bad in ("Win32_Process", "AMT_", "AMT_Bad Name", "amt_lower", "AMT_X/../y", ""):
        with pytest.raises(ValueError, match="invalid_class_name"):
            amt_tools.wsman_get(bad)
    with pytest.raises(ValueError, match="selectors_not_supported"):
        amt_tools.wsman_get("AMT_X", "enumerate", {"a": "b"})
    with pytest.raises(ValueError, match="unknown_operation"):
        amt_tools.wsman_get("AMT_X", "put")
    amt.singles["IPS_KVMRedirectionSettingData"] = inst("IPS_KVMRedirectionSettingData", RFBPassword="rfb-secret-must-not-leak")
    assert amt_tools.wsman_get("IPS_KVMRedirectionSettingData")["instance"]["RFBPassword"] == "<redacted>"
    assert amt.calls and all(leaf == "Get" for leaf, _, _ in amt.calls)


def test_fault_text_surfaces_from_wsman_get(amt):
    with pytest.raises(amt_wsman.WsmanError, match="No such class"):
        amt_tools.wsman_get("AMT_DoesNotExist")


# --- nothing but reads ever goes out --------------------------------------------------------

def test_no_tool_ever_sends_a_write(amt, kvm):
    amt.lists.update({c: [[inst(c, InstanceID="1")]] for c in amt_tools.INVENTORY_CLASSES.values()})
    for areas in amt_tools.SETTINGS_AREAS.values():
        for _, cls, mode in areas:
            (amt.lists if mode == "enum" else amt.singles).setdefault(
                cls, [[inst(cls, InstanceID="1")]] if mode == "enum" else inst(cls, InstanceID="1"))
    amt.methods[("AMT_MessageLog", "GetRecords")] = [
        "<g:O xmlns:g='u'><g:NoMoreRecords>true</g:NoMoreRecords></g:O>"] * 2
    amt.methods[("AMT_AuditLog", "ReadRecords")] = ["<g:O xmlns:g='u'/>"]
    amt.methods[("AMT_AuthorizationService", "EnumerateUserAclEntries")] = ["<g:O xmlns:g='u'/>"]
    amt_tools.status(); amt_tools.inventory(); amt_tools.logs("event"); amt_tools.logs("audit")
    for area in amt_tools.SETTINGS_AREA_NAMES:
        amt_tools.settings(area)
    amt_tools.wsman_get("AMT_BootSettingData")
    amt_tools.screenshot()
    assert amt.actions <= {"Get", "Enumerate", "Pull", "GetRecords", "ReadRecords",
                           "EnumerateUserAclEntries", "GetUserAclEntryEx"}
    assert not {"Put", "Create", "Delete"} & amt.actions


def test_invoke_read_refuses_any_method_off_the_allowlist(amt):
    for cls, method in (("CIM_BootService", "SetBootConfigRole"), ("CIM_PowerManagementService", "RequestPowerStateChange"),
                        ("AMT_MessageLog", "ClearLog")):
        with pytest.raises(ValueError, match="method_not_allowed"):
            amt_wsman.invoke_read(cls, method, {})
    assert amt.calls == []


def test_typed_coercion_rules():
    t = amt_tools.typed({"A": "true", "EnabledState": "32771", "SerialNumber": "00012", "Port": "16993",
                         "VersionString": "2539", "L": ["1", "x"], "N": {"Flag": "false"}})
    assert t == {"A": True, "EnabledState": 32771, "SerialNumber": "00012", "Port": 16993,
                 "VersionString": "2539", "L": [1, "x"], "N": {"Flag": False}}


# --- the gate covers the new tools over real ASGI HTTP --------------------------------------

def _tools_server():
    return amt_server.register_tools(amt_server.build_server())


def test_read_tool_is_refused_anonymously_and_allowed_with_bearer(amt):
    with _client(_tools_server()) as c:
        for token in (None, "wrong-token"):
            res = _call(c, "amt_status", token)
            assert res["isError"] is True and "mcp-admin-token" in res["content"][0]["text"]
        assert amt.calls == [], "no WS-MAN request may be made for a refused call"

        res = _call(c, "amt_status", TOKEN)
        assert not res.get("isError")
        body = res.get("structuredContent") or json.loads(res["content"][0]["text"])
        assert body["power"]["state"] == "on" and body["amt"]["version"] == "16.1.25"
        assert amt.calls, "tripwire: the gated branch let the correct token through"


def test_every_tool_is_gated_anonymously(amt, kvm):
    names = [t.name for t in asyncio.run(amt_server.mcp.list_tools())]
    assert len(names) == 23
    with _client(_tools_server()) as c:
        for name in names:
            res = _call(c, name)
            assert res["isError"] is True and "mcp-admin-token" in res["content"][0]["text"], name
    assert amt.calls == [] and kvm.instances == []


def test_tool_error_is_isError_not_a_success_field(amt, monkeypatch):
    def denied(device, xml, password=None):
        raise amt_wsman.WsmanError("wsman_auth_failed_401")

    monkeypatch.setattr(amt_wsman, "transport", denied)
    with _client(_tools_server()) as c:
        res = _call(c, "amt_status", TOKEN)
    assert res["isError"] is True
    assert "wsman_auth_failed_401" in res["content"][0]["text"] and VAULT_SENTINEL not in res["content"][0]["text"]


# --- hardening: screenshot pin, private files, concurrency, annotations ---------------------

def test_screenshot_pin_match_connects_and_mismatch_is_refused_before_use(kvm):
    amt_tools.screenshot()
    assert kvm.instances[0].past_connect is True
    kvm.instances.clear()
    kvm.presented_fp = "0" * 64
    with pytest.raises(amt_tools.amt_kvm.AmtError, match="tls_leaf_pin_mismatch"):
        amt_tools.screenshot()
    (s,) = kvm.instances
    assert s.past_connect is False, "nothing may be sent on a connection whose leaf failed the pin"
    assert s.closed is True


def test_screenshot_refuses_an_unpinned_device_before_vault_disk_or_wire(kvm, monkeypatch, tmp_path):
    unpinned = amt_wsman.amt_registry.Device(key="u", amt_ip="192.0.2.1", wsman_port=1, kvm_port=2,
                                             amt_vault_key="k", tls_leaf_sha256=None)
    monkeypatch.setitem(amt_wsman.amt_registry.DEVICES, "u", unpinned)
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: pytest.fail("vault read for unpinned device"))
    with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
        amt_tools.screenshot("u")
    assert kvm.instances == [] and not (tmp_path / "shots").exists()


def test_screenshot_files_are_private_and_unguessable(kvm, tmp_path):
    import os
    import stat
    a, b = amt_tools.screenshot(), amt_tools.screenshot()
    d = tmp_path / "shots"
    assert stat.S_IMODE(os.stat(d).st_mode) == 0o700
    for out in (a, b):
        assert stat.S_IMODE(os.stat(out["path"]).st_mode) == 0o600
        assert re.fullmatch(r"amt-my-server-1-\d{8}T\d{12}Z-[0-9a-f]{16}\.png", Path(out["path"]).name)
    assert a["path"] != b["path"]


def test_screenshot_refuses_symlinked_or_foreign_shot_dir(kvm, tmp_path, monkeypatch):
    import os
    target = tmp_path / "elsewhere"
    target.mkdir()
    (tmp_path / "shots").symlink_to(target)
    with pytest.raises(PermissionError, match="shot_dir_unsafe"):
        amt_tools.screenshot()
    assert kvm.instances == [] and list(target.iterdir()) == []
    (tmp_path / "shots").unlink()
    (tmp_path / "shots").mkdir()
    me = os.getuid()
    monkeypatch.setattr(amt_tools.os, "getuid", lambda: me + 1)
    with pytest.raises(PermissionError, match="not_owned_by_this_user"):
        amt_tools.screenshot()
    assert kvm.instances == []


def test_screenshot_never_reuses_an_existing_path(kvm, tmp_path, monkeypatch):
    out_dir = amt_tools._private_shot_dir()
    monkeypatch.setattr(amt_tools.secrets, "token_hex", lambda n: "0" * 16)
    stamp = amt_tools.datetime.now(amt_tools.timezone.utc)

    class Frozen(amt_tools.datetime):
        @classmethod
        def now(cls, tz=None):
            return stamp

    monkeypatch.setattr(amt_tools, "datetime", Frozen)
    existing = amt_tools._create_private_png(out_dir, "my-server-1")
    existing.write_bytes(b"precious")
    with pytest.raises(FileExistsError):
        amt_tools.screenshot()
    assert existing.read_bytes() == b"precious"
    assert kvm.instances[0].closed is True


def test_screenshot_annotations_and_description_state_the_side_effects():
    tools = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}
    shot = tools["amt_screenshot"]
    assert shot.annotations.readOnlyHint is True
    assert shot.annotations.idempotentHint is False and shot.annotations.openWorldHint is True
    lead = shot.description.split(".")[0].lower()
    assert "single" in lead and "redirection" in lead
    assert "consent" in shot.description and "one-time download url" in shot.description
    read_names = {r["name"] for r in amt_parity.TOOLS if r["kind"] == "read"}
    assert read_names <= set(tools)
    for name in read_names - {"amt_screenshot", "amt_captures"}:   # captures: fetch mints a url each call
        assert tools[name].annotations.idempotentHint is True, name
    assert tools["amt_captures"].annotations.idempotentHint is False


def test_concurrent_screenshots_serialize_on_the_single_redirection_session(kvm):
    import threading
    kvm.hold = threading.Event()

    async def run():
        first = asyncio.create_task(amt_tools.amt_screenshot())
        for _ in range(100):
            await asyncio.sleep(0.01)
            if kvm.instances:
                break
        assert len(kvm.instances) == 1
        second = asyncio.create_task(amt_tools.amt_screenshot())
        await asyncio.sleep(0.2)
        assert len(kvm.instances) == 1, "second session must not exist while the first is open"
        kvm.hold.set()
        await asyncio.gather(first, second)
        assert len(kvm.instances) == 2 and all(s.closed for s in kvm.instances)

    asyncio.run(run())
    kvm.instances.clear()
    kvm.hold = None

    async def again():   # a second event loop reuses nothing from the first (locks are per loop)
        await asyncio.gather(amt_tools.amt_screenshot(), amt_tools.amt_screenshot())

    asyncio.run(again())
    assert len(kvm.instances) == 2


# --- hardening: log completeness ------------------------------------------------------------------

def _out(body):
    return f"<g:GetRecords_OUTPUT xmlns:g='u'>{body}</g:GetRecords_OUTPUT>"


def test_event_log_is_not_complete_on_an_empty_page_that_is_not_the_end(amt):
    amt.methods[("AMT_MessageLog", "GetRecords")] = [
        _out("<g:IterationIdentifier>2</g:IterationIdentifier><g:NoMoreRecords>false</g:NoMoreRecords>"),
        _out("<g:NoMoreRecords>false</g:NoMoreRecords>")]
    out = amt_tools.logs("event")
    assert out["fetched"] == 0 and out["fetch_complete"] is False


def test_event_log_is_not_complete_when_the_device_gives_no_way_forward(amt):
    amt.methods[("AMT_MessageLog", "GetRecords")] = [
        _out(f"<g:RecordArray>{event_rec(T0)}</g:RecordArray><g:NoMoreRecords>false</g:NoMoreRecords>")]
    assert amt_tools.logs("event")["fetch_complete"] is False
    amt.methods[("AMT_MessageLog", "GetRecords")] = [   # a non-advancing iteration id cannot loop
        _out(f"<g:RecordArray>{event_rec(T0)}</g:RecordArray><g:IterationIdentifier>1</g:IterationIdentifier>")]
    assert amt_tools.logs("event")["fetch_complete"] is False


def test_event_log_empty_but_declared_done_is_complete(amt):
    amt.methods[("AMT_MessageLog", "GetRecords")] = [_out("<g:NoMoreRecords>true</g:NoMoreRecords>")]
    out = amt_tools.logs("event")
    assert out["fetched"] == 0 and out["fetch_complete"] is True


def test_event_log_call_cap_is_reported_as_incomplete(amt):
    page = _out(f"<g:RecordArray>{event_rec(T0)}</g:RecordArray>"
                "<g:IterationIdentifier>{n}</g:IterationIdentifier><g:NoMoreRecords>false</g:NoMoreRecords>")
    amt.methods[("AMT_MessageLog", "GetRecords")] = [page.replace("{n}", str(i + 2))
                                                     for i in range(amt_tools.MAX_LOG_CALLS)]
    out = amt_tools.logs("event")
    assert out["fetched"] == amt_tools.MAX_LOG_CALLS and out["fetch_complete"] is False


def test_audit_log_is_complete_only_when_the_total_is_reached(amt):
    one = f"<g:EventRecords>{audit_rec(T0)}</g:EventRecords>"
    amt.methods[("AMT_AuditLog", "ReadRecords")] = [
        f"<g:O xmlns:g='u'><g:TotalRecordCount>5</g:TotalRecordCount>{one}</g:O>",
        "<g:O xmlns:g='u'><g:TotalRecordCount>5</g:TotalRecordCount></g:O>"]   # stalls at 1 of 5
    out = amt_tools.logs("audit")
    assert out["fetched"] == 1 and out["fetch_complete"] is False
    amt.methods[("AMT_AuditLog", "ReadRecords")] = [f"<g:O xmlns:g='u'>{one}</g:O>",
                                                    "<g:O xmlns:g='u'/>"]       # no total reported at all
    assert amt_tools.logs("audit")["fetch_complete"] is False
    amt.methods[("AMT_AuditLog", "ReadRecords")] = [
        "<g:O xmlns:g='u'><g:TotalRecordCount>0</g:TotalRecordCount></g:O>"]
    empty = amt_tools.logs("audit")
    assert empty["fetched"] == 0 and empty["fetch_complete"] is True


def test_empty_soap_body_from_a_log_invoke_is_an_error_not_an_empty_log(amt):
    amt.methods[("AMT_MessageLog", "GetRecords")] = [""]
    with pytest.raises(amt_wsman.WsmanError, match="wsman_empty_body:AMT_MessageLog.GetRecords"):
        amt_tools.logs("event")


# --- hardening: redaction on both paths --------------------------------------------------------------

def test_secret_named_fields_are_redacted_in_settings_and_wsman_get(amt):
    fields = dict(PSKPassPhrase="psk-clear", SharedSecret="shared-clear", Name="keep")
    amt.singles["IPS_KVMRedirectionSettingData"] = inst("IPS_KVMRedirectionSettingData", **fields)
    amt.singles["CIM_KVMRedirectionSAP"] = inst("CIM_KVMRedirectionSAP", EnabledState=2)
    for out in (amt_tools.settings("kvm")["sections"]["settings"],
                amt_tools.wsman_get("IPS_KVMRedirectionSettingData")["instance"]):
        assert out["PSKPassPhrase"] == "<redacted>" and out["SharedSecret"] == "<redacted>"
        assert out["Name"] == "keep"
    amt.lists["AMT_TLSSettingData"] = [[inst("AMT_TLSSettingData", **fields)]]
    got = amt_tools.wsman_get("AMT_TLSSettingData", "enumerate")["instances"][0]
    assert got["PSKPassPhrase"] == "<redacted>" and got["SharedSecret"] == "<redacted>"


def test_wsman_get_validates_the_class_before_any_vault_read_or_request(amt, monkeypatch):
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: pytest.fail("vault read before validation"))
    with pytest.raises(ValueError, match="invalid_class_name"):
        amt_tools.wsman_get("Win32_Process")
    assert amt.calls == []


@pytest.mark.parametrize("err", ["wsman_auth_failed_401", "tls_leaf_pin_mismatch", "wsman_incomplete_read"])
def test_reads_get_and_enum_each_propagate_non_fault_errors(amt, monkeypatch, err):
    """status() mixes get and enum, so the swallowing of either alone is only caught here."""
    def broken(device, xml, password=None):
        raise amt_wsman.WsmanError(err)

    monkeypatch.setattr(amt_wsman, "transport", broken)
    r = amt_tools._Reads("my-server-1")
    for call in (lambda: r.get("AMT_X"), lambda: r.enum("AMT_X")):
        with pytest.raises(amt_wsman.WsmanError) as ex:
            call()
        assert str(ex.value) == err
    assert r.unavailable == [] and r.truncated == []


def test_audit_log_call_cap_is_reported_as_incomplete(amt):
    page = (f"<g:O xmlns:g='u'><g:TotalRecordCount>9999</g:TotalRecordCount>"
            f"<g:EventRecords>{audit_rec(T0)}</g:EventRecords></g:O>")
    amt.methods[("AMT_AuditLog", "ReadRecords")] = [page] * amt_tools.MAX_LOG_CALLS
    out = amt_tools.logs("audit")
    assert out["fetched"] == amt_tools.MAX_LOG_CALLS and out["fetch_complete"] is False


def test_audit_record_is_big_endian_against_a_real_vector():
    # Real my-server-1 audit shape: app 0x0012, event 0x0009, initiator "admin",
    # time 0x6AD46AFF. Big-endian => 2026; a little-endian read gives 2105. This
    # vector is anchored to the live device, not to the fixture's own encoding.
    raw = (bytes.fromhex("00120009") + bytes([0, 5]) + b"admin"
           + bytes.fromhex("6AD46AFF") + bytes([1, 0, 0]))
    rec = amt_tools.decode_audit_record(base64.b64encode(raw).decode())
    assert (rec["app_id"], rec["event_id"]) == (0x12, 0x09)
    assert rec["epoch"] == 0x6AD46AFF
    assert rec["initiator"] == "admin"
    assert rec["timestamp"].startswith("2026-")  # not 2105-


def test_screenshot_over_http_with_a_base_url_returns_a_one_time_url(kvm, monkeypatch):
    import hashlib
    from starlette.testclient import TestClient
    import amt_handoff
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, "https://nas.example.com:8443")
    monkeypatch.setenv(amt_server.TRANSPORT_ENV, "http")
    out = amt_tools.screenshot()
    assert "path_note" not in out and out["url"].startswith("https://nas.example.com:8443/handoffs/")
    png = Path(out["path"]).read_bytes()
    assert out["sha256"] == hashlib.sha256(png).hexdigest()
    client = TestClient(amt_server.build_http_app(amt_server.mcp))
    path = out["url"].split(":8443", 1)[1]
    r = client.get(path)
    assert r.status_code == 200 and r.content == png
    assert client.get(path).status_code == 404
