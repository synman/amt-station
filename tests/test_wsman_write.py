"""The WS-MAN write primitive (``amt_wsman_write``): exact SOAP actions, secret handling, the
separation from the read client, one-attempt auth and the pin. The transport is replaced by
``wire.Wire`` (or, for the auth test, ``_open_connection``); no socket, host or real vault is used."""
import ast
import dataclasses
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import amt_registry  # noqa: E402
import amt_vault  # noqa: E402
import amt_wsman  # noqa: E402
import amt_wsman_write as ww  # noqa: E402
import wire as wirelib  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
PW = "AMT-SENTINEL-primitive-not-real"
RFB = "RFB-SENTINEL-primitive-not-real"
VAULT = {"my-server-1-amt": PW, "my-server-1-amt-rfb": RFB}
URI = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"
VAULT_READS: list = []


@pytest.fixture
def wire(monkeypatch):
    w = wirelib.Wire()
    VAULT_READS.clear()

    def get_secret(key):
        VAULT_READS.append(key)
        return VAULT[key]

    monkeypatch.setattr(amt_wsman, "transport", w.transport)
    monkeypatch.setattr(amt_vault, "get_secret", get_secret)
    return w


# --- exact actions -----------------------------------------------------------------------

def test_put_emits_the_put_action_with_fields_in_order(wire):
    wire.instances["AMT_BootSettingData"] = {}
    ww.put("AMT_BootSettingData", {"ZField": "1", "AField": True, "MField": "x<y"},
           selectors={"InstanceID": "i"})
    call, = wire.calls
    assert call.action == "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put" == ww.A_PUT
    assert call.cls == "AMT_BootSettingData" and call.selectors == {"InstanceID": "i"}
    assert call.order == ["ZField", "AField", "MField"], "element order is preserved (AMT is order sensitive)"
    assert call.fields == {"ZField": "1", "AField": "true", "MField": "x<y"}


def test_invoke_emits_the_method_action_and_input_element(wire):
    out = ww.invoke("CIM_BootService", "SetBootConfigRole", {"Role": 1})
    call, = wire.calls
    assert call.action == URI + "CIM_BootService/SetBootConfigRole"
    assert "<h:SetBootConfigRole_INPUT" in call.xml and call.fields == {"Role": "1"}
    assert out["ReturnValue"] == "0"


def test_reference_parameters_are_rendered_with_selectors(wire):
    ww.invoke("CIM_BootService", "SetBootConfigRole",
              {"BootConfigSetting": ww.epr("CIM_BootConfigSetting", {"InstanceID": "Intel(r) AMT: Boot Configuration 0"})})
    ref = wire.calls[0].fields["BootConfigSetting"]
    assert ref == {"epr": {"class": "CIM_BootConfigSetting",
                           "selectors": {"InstanceID": "Intel(r) AMT: Boot Configuration 0"}}}
    assert "role/anonymous" in wire.calls[0].xml


def test_create_and_delete_emit_their_actions(wire):
    ww.create("AMT_Foo", {"ElementName": "n"})
    ww.delete("AMT_Foo", selectors={"InstanceID": "x"})
    assert wire.calls[0].action == ww.A_CREATE and wire.calls[1].action == ww.A_DELETE
    assert wire.calls[1].selectors == {"InstanceID": "x"}


def test_delete_without_selectors_is_refused_and_sends_nothing(wire):
    with pytest.raises(ValueError, match="delete_requires_selectors"):
        ww.delete("AMT_Foo", selectors={})
    assert wire.calls == [] and VAULT_READS == []


def test_nonzero_return_value_fault_and_empty_reply_raise(wire):
    wire.return_values[("CIM_BootService", "SetBootConfigRole")] = "5"
    with pytest.raises(amt_wsman.WsmanError, match="wsman_return_value:CIM_BootService.SetBootConfigRole:5"):
        ww.invoke("CIM_BootService", "SetBootConfigRole", {"Role": 1})
    wire.faults[("invoke", "CIM_BootService", "SetBootConfigRole")] = "denied by device"
    with pytest.raises(amt_wsman.WsmanFault, match="denied by device"):
        ww.invoke("CIM_BootService", "SetBootConfigRole", {"Role": 1})
    wire.faults[("put", "AMT_Foo")] = "bad put"
    with pytest.raises(amt_wsman.WsmanFault, match="bad put"):
        ww.put("AMT_Foo", {"A": "1"})


@pytest.mark.parametrize("bad", ["bad name", "1x", "a;b", "", "x" * 70])
def test_invalid_method_and_field_names_are_refused_before_any_io(wire, bad):
    with pytest.raises(ValueError):
        ww.invoke("CIM_BootService", bad, {})
    with pytest.raises(ValueError):
        ww.put("AMT_Foo", {bad: "1"})
    assert wire.calls == [] and VAULT_READS == []


# --- secrets -----------------------------------------------------------------------------

@pytest.mark.parametrize("name", ["Password", "RFBPassword", "DigestPassword", "passphrase", "MySecret",
                                  "PSK", "PrivateKey"])
def test_a_credential_named_field_is_never_accepted_from_a_caller(wire, name):
    with pytest.raises(ValueError, match=f"secret_field_refused:{name}"):
        ww.put("AMT_Foo", {name: "x"})
    with pytest.raises(ValueError, match="secret_field_refused"):
        ww.create("AMT_Foo", {name: "x"})
    with pytest.raises(ValueError, match="secret_field_refused"):
        ww.invoke("AMT_Foo", "Do", {name: "x"})
    assert wire.calls == [] and VAULT_READS == []


def test_vault_secret_is_inserted_in_slot_order_and_never_returned(wire):
    wire.instances["IPS_KVMRedirectionSettingData"] = {}
    out = ww.put("IPS_KVMRedirectionSettingData",
                 {"ElementName": "e", "OptInPolicy": "true", "RFBPassword": ww.SECRET_SLOT, "SessionTimeout": "0"},
                 secret_fields={"RFBPassword": "my-server-1-amt-rfb"})
    call, = wire.calls
    assert call.order == ["ElementName", "OptInPolicy", "RFBPassword", "SessionTimeout"]
    assert call.fields["RFBPassword"] == RFB, "the vaulted value reaches the device"
    assert "my-server-1-amt-rfb" in VAULT_READS
    assert RFB not in repr(out) and out["RFBPassword"] == "<redacted>"


def test_an_unslotted_vault_secret_is_appended_and_a_slot_without_a_key_is_refused(wire):
    ww.put("AMT_Foo", {"A": "1"}, secret_fields={"RFBPassword": "my-server-1-amt-rfb"})
    assert wire.calls[0].order == ["A", "RFBPassword"]
    wire.calls.clear()
    with pytest.raises(ValueError, match="secret_slot_without_vault_key"):
        ww.put("AMT_Foo", {"RFBPassword": ww.SECRET_SLOT})
    assert wire.calls == []


def test_the_bypass_flag_is_not_redacted_but_real_credential_names_still_are(wire):
    wire.instances["AMT_BootSettingData"] = {"UserPasswordBypass": "true", "RSEPassword": "x", "AdminPassword": "y",
                                             "Passphrase": "z", "PreSharedPSK": "w"}
    got = amt_wsman.get("AMT_BootSettingData")
    assert got["UserPasswordBypass"] == "true"
    assert all(got[k] == "<redacted>" for k in ("RSEPassword", "AdminPassword", "Passphrase", "PreSharedPSK"))
    ww.put("AMT_BootSettingData", {"UserPasswordBypass": True})     # a flag, not a credential: accepted
    assert wire.calls[-1].fields["UserPasswordBypass"] == "true"


def test_a_device_echo_of_a_secret_under_an_innocent_name_is_scrubbed(wire):
    wire.echo_extra["AMT_Foo"] = {"Comment": f"saved {RFB} ok"}
    out = ww.put("AMT_Foo", {"A": "1"}, secret_fields={"RFBPassword": "my-server-1-amt-rfb"})
    assert RFB not in repr(out) and "<redacted>" in out["Comment"]


def test_secret_params_are_the_only_credential_path_for_invoke(wire):
    ww.invoke("AMT_AuthorizationService", "AddUserAclEntryEx", {"DigestUsername": "bob"},
              secret_params={"DigestPassword": "digest-value"})
    assert wire.calls[0].fields["DigestPassword"] == "digest-value"
    with pytest.raises(ValueError, match="secret_field_refused"):
        ww.invoke("AMT_AuthorizationService", "AddUserAclEntryEx", {"DigestPassword": "x"})


# --- broadened secret matching: names, nesting, replies and fault text ----------------------

CREDENTIAL_NAMES = ["Passwd", "Pwd", "Pass", "Credential", "Token", "SharedKey", "ApiKey", "Hash", "MasterKey",
                    "PPS", "PID", "NetAdminPassEncrypted", "NetAdminPass", "DigestPassword", "ProvisioningPID",
                    "AccessToken", "CertHash", "PASSWD", "apikey", "sharedkey"]


@pytest.mark.parametrize("name", CREDENTIAL_NAMES)
def test_every_credential_pattern_is_redacted_on_read_and_refused_on_write(wire, name):
    assert amt_wsman.is_secret_name(name)
    wire.instances["AMT_Foo"] = {name: "device-secret", "Visible": "ok"}
    got = amt_wsman.get("AMT_Foo")
    assert got[name] == "<redacted>" and got["Visible"] == "ok"
    for call in (lambda: ww.put("AMT_Foo", {name: "x"}), lambda: ww.create("AMT_Foo", {name: "x"}),
                 lambda: ww.invoke("AMT_Foo", "Do", {name: "x"})):
        with pytest.raises(ValueError, match="secret_field_refused"):
            call()
    assert [c.op for c in wire.calls] == ["get"]


@pytest.mark.parametrize("name", ["UserPasswordBypass", "Bypass", "Rapid", "Passthrough", "HostName", "Is5900PortEnabled",
                                  "IDERBootDevice", "DDNSPeriodicUpdateInterval", "Tokenizer", "Mapping"])
def test_ordinary_names_that_merely_contain_a_marker_are_not_credentials(name):
    assert not amt_wsman.is_secret_name(name)


@pytest.mark.parametrize("bad", [5, "hunter2", "", None, ["true"], {"a": "1"}, 7, "yes please"])
def test_the_bypass_exemption_is_type_checked_to_a_boolean_ish_value(wire, bad):
    with pytest.raises(ValueError, match="secret_field_refused:UserPasswordBypass"):
        ww.put("AMT_BootSettingData", {"UserPasswordBypass": bad})
    assert wire.calls == []


@pytest.mark.parametrize("ok", [True, False, "true", "False", "0", "1", 0, 1])
def test_the_bypass_exemption_accepts_boolean_ish_values(wire, ok):
    ww.put("AMT_BootSettingData", {"UserPasswordBypass": ok})
    assert len(wire.calls) == 1


def test_a_non_boolean_bypass_value_in_a_reply_is_redacted(wire):
    wire.instances["AMT_BootSettingData"] = {"UserPasswordBypass": "not-a-flag-hunter2"}
    assert amt_wsman.get("AMT_BootSettingData")["UserPasswordBypass"] == "<redacted>"


def test_a_credential_named_selector_inside_a_reference_parameter_is_refused(wire):
    ref = ww.epr("CIM_BootConfigSetting", {"InstanceID": "ok", "Password": "hunter2"})
    with pytest.raises(ValueError, match="secret_field_refused:Password"):
        ww.invoke("CIM_BootService", "SetBootConfigRole", {"BootConfigSetting": ref})
    with pytest.raises(ValueError, match="secret_field_refused:PID"):
        ww.put("AMT_Foo", {"List": [ww.epr("CIM_X", {"PID": "1"})]})
    assert wire.calls == []


def test_a_credential_named_top_level_selector_is_refused_on_every_write_verb(wire):
    sel = {"Token": "abc"}
    for call in (lambda: ww.put("AMT_Foo", {"A": "1"}, selectors=sel), lambda: ww.create("AMT_Foo", {}, selectors=sel),
                 lambda: ww.delete("AMT_Foo", selectors=sel), lambda: ww.invoke("AMT_Foo", "Do", {}, selectors=sel)):
        with pytest.raises(ValueError, match="secret_field_refused:Token"):
            call()
    assert wire.calls == []


def test_the_general_tool_refuses_a_credential_nested_in_an_epr_field(wire):
    import amt_write
    fields = {"BootConfigSetting": {"epr": {"class": "CIM_BootConfigSetting", "selectors": {"SharedKey": "k"}}}}
    with pytest.raises(ValueError, match="secret_field_refused:SharedKey"):
        amt_write.wsman_invoke("invoke", "CIM_BootService", method="SetBootConfigRole", fields=fields, confirmed=True)
    with pytest.raises(ValueError, match="secret_field_refused:Hash"):
        amt_write.wsman_invoke("delete", "AMT_Foo", selectors={"Hash": "h"}, confirmed=True)
    # refused by the TOOL before the confirmation guard (the primitive refuses it again; both are pinned)
    with pytest.raises(ValueError, match="secret_field_refused:Hash"):
        amt_write.wsman_invoke("delete", "AMT_Foo", selectors={"Hash": "h"})
    with pytest.raises(ValueError, match="secret_field_refused:SharedKey"):
        amt_write.wsman_invoke("invoke", "CIM_BootService", method="SetBootConfigRole", fields=fields)
    assert wire.calls == []


def test_a_reply_nested_credential_is_redacted_in_a_success_reply(wire):
    wire.echo_extra["AMT_Foo"] = {"ApiKey": DEVICE, "PID": DEVICE, "Visible": "ok"}
    out = ww.put("AMT_Foo", {"A": "1"})
    assert out["ApiKey"] == out["PID"] == "<redacted>" and out["Visible"] == "ok" and DEVICE not in repr(out)


DEVICE = "DEVICE-ECHOED-SECRET-hunter2"


def test_fault_text_has_credential_assignments_redacted(wire):
    wire.faults[("put", "AMT_Foo")] = f"bad value Password={DEVICE} and Token: '{DEVICE} two' PID \"{DEVICE}\" ok"
    with pytest.raises(amt_wsman.WsmanFault) as ex:
        ww.put("AMT_Foo", {"A": "1"})
    assert DEVICE not in str(ex.value) and "ok" in str(ex.value) and "bad value" in str(ex.value)
    wire.faults[("invoke", "AMT_Foo", "Do")] = f"x:Password={DEVICE}"
    with pytest.raises(amt_wsman.WsmanFault) as ex:
        ww.invoke("AMT_Foo", "Do", {})
    assert DEVICE not in str(ex.value) and "Password=<redacted>" in str(ex.value)


def test_fault_text_redacts_the_read_clients_faults_too(wire):
    wire.instances.pop("AMT_Foo", None)
    wire.faults[("put", "AMT_Foo")] = f"Credential={DEVICE}"
    # the read client's own parse (Get of a missing class) is the same code path
    text = wirelib.fault_xml(f"Passwd: {DEVICE} rejected")
    with pytest.raises(amt_wsman.WsmanFault) as ex:
        amt_wsman.parse(text)
    assert DEVICE not in str(ex.value) and "rejected" in str(ex.value)


def test_fault_text_has_known_vault_values_and_the_amt_password_removed(wire):
    wire.faults[("put", "AMT_Foo")] = f"device said {RFB} and also {PW} verbatim"
    with pytest.raises(amt_wsman.WsmanFault) as ex:
        ww.put("AMT_Foo", {"A": "1"}, secret_fields={"RFBPassword": "my-server-1-amt-rfb"})
    assert RFB not in str(ex.value) and PW not in str(ex.value) and "device said <redacted>" in str(ex.value)


# --- _scrub is pinned at every call site (removing any one must fail a test) ------------------

def test_put_scrubs_a_vaulted_value_a_device_echoes_under_an_innocent_name(wire):
    wire.echo_extra["AMT_Foo"] = {"Comment": f"saved {RFB} ok"}
    out = ww.put("AMT_Foo", {"A": "1"}, secret_fields={"RFBPassword": "my-server-1-amt-rfb"})
    assert RFB not in repr(out) and out["Comment"] == "saved <redacted> ok"


def test_invoke_scrubs_a_secret_param_a_device_echoes_under_an_innocent_name(wire):
    wire.handlers[("AMT_AuthorizationService", "AddUserAclEntryEx")] = lambda c: {"Note": f"digest {c.fields['DigestPassword']}"}
    out = ww.invoke("AMT_AuthorizationService", "AddUserAclEntryEx", {"DigestUsername": "bob"},
                    secret_params={"DigestPassword": "digest-value-xyz"})
    assert "digest-value-xyz" not in repr(out) and out["Note"] == "digest <redacted>"


@pytest.mark.parametrize("verb", ["put", "create", "delete", "invoke"])
def test_every_write_verb_scrubs_the_amt_password_from_a_reply(wire, monkeypatch, verb):
    reply = wirelib.soap(f'<h:Reply xmlns:h="{URI}"><h:Comment>pw {PW}</h:Comment><h:ReturnValue>0</h:ReturnValue></h:Reply>')
    assert PW in reply, "positive control: the reply does carry the password"
    monkeypatch.setattr(amt_wsman, "transport", lambda device, xml, password=None: reply)
    calls = {"put": lambda: ww.put("AMT_Foo", {"A": "1"}), "create": lambda: ww.create("AMT_Foo", {"A": "1"}),
             "delete": lambda: ww.delete("AMT_Foo", selectors={"InstanceID": "x"}),
             "invoke": lambda: ww.invoke("AMT_Foo", "Do", {})}
    out = calls[verb]()
    assert PW not in repr(out) and out["Comment"] == "pw <redacted>"


# --- the write path is separate from the read client ------------------------------------------

def test_the_read_client_has_no_write_operation_and_its_allowlist_is_unchanged():
    for name in ("put", "create", "delete", "invoke"):
        assert not hasattr(amt_wsman, name), name
    assert amt_wsman.READ_METHODS == frozenset({
        ("AMT_MessageLog", "GetRecords"), ("AMT_AuditLog", "ReadRecords"),
        ("AMT_AuthorizationService", "EnumerateUserAclEntries"),
        ("AMT_AuthorizationService", "GetUserAclEntryEx")})


@pytest.mark.parametrize("cls,method", [
    ("CIM_PowerManagementService", "RequestPowerStateChange"),
    ("CIM_BootService", "SetBootConfigRole"), ("CIM_BootConfigSetting", "ChangeBootOrder"),
    ("AMT_AuthorizationService", "AddUserAclEntryEx"), ("AMT_AuthorizationService", "RemoveUserAclEntry"),
    ("AMT_SetupAndConfigurationService", "Unprovision")])
def test_the_read_client_refuses_every_write_method(wire, cls, method):
    with pytest.raises(ValueError, match="method_not_allowed"):
        amt_wsman.invoke_read(cls, method, {})
    assert wire.calls == []


def _imports(path: Path) -> set[str]:
    names = set()
    for node in ast.walk(ast.parse(path.read_text())):
        if isinstance(node, ast.Import):
            names |= {a.name for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module:
            names.add(node.module)
    return names


def test_no_read_module_imports_a_write_module():
    # amt_wsman_get must stay unable to reach Put/Invoke, structurally, not by convention.
    for name in ("amt_wsman.py", "amt_tools.py", "amt_gate.py", "amt_registry.py", "amt_vault.py", "amt_kvm.py"):
        found = _imports(ROOT / name) & {"amt_wsman_write", "amt_write", "amt_redir"}
        assert not found, (name, found)
    assert "amt_wsman_write" in _imports(ROOT / "amt_write.py")


def test_the_read_tool_cannot_perform_a_write_operation(wire):
    import amt_tools
    with pytest.raises(ValueError, match="unknown_operation"):
        amt_tools.wsman_get("AMT_BootSettingData", operation="put")
    with pytest.raises(ValueError):
        amt_tools.wsman_get("AMT_BootSettingData", operation="invoke")
    assert wire.calls == []


# --- pin and one-attempt auth ---------------------------------------------------------------

def test_an_unpinned_device_is_refused_before_the_vault_and_the_wire(wire, monkeypatch):
    dev = amt_registry.get_device("my-server-1")
    monkeypatch.setitem(amt_registry.DEVICES, "my-server-1", dataclasses.replace(dev, tls_leaf_sha256=None))
    for call in (lambda: ww.put("AMT_Foo", {"A": "1"}), lambda: ww.invoke("AMT_Foo", "Do", {}),
                 lambda: ww.create("AMT_Foo", {}), lambda: ww.delete("AMT_Foo", selectors={"I": "x"})):
        with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
            call()
    assert wire.calls == [] and VAULT_READS == []


def test_a_write_makes_one_authenticated_attempt_and_never_retries_a_401(monkeypatch):
    from test_wsman_transport import CHALLENGE, FakeConn, FakeResp
    log = []
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: PW)
    monkeypatch.setattr(amt_wsman, "_open_connection",
                        lambda dev: FakeConn(lambda h, n: FakeResp(401, "denied", [("WWW-Authenticate", CHALLENGE)]), log))
    with pytest.raises(amt_wsman.WsmanError, match="wsman_auth_failed_401") as ex:
        ww.invoke("CIM_PowerManagementService", "RequestPowerStateChange", {"PowerState": 14})
    assert PW not in str(ex.value)
    assert len(log) == 2 and sum("Authorization" in r[3] for r in log) == 1
