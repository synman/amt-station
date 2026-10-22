"""The seven WRITE tools with MOCKED transports. No test opens a socket, reads the real vault,
touches a host or runs any tool live: WS-MAN is ``wire.Wire`` (replacing ``amt_wsman.transport``),
the KVM engine is ``FakeKvm``, SOL/IDE-R are ``FakeSol``/``FakeIder``, and the vault is a dict.

Every tool is checked for: the ``confirmed=False`` refusal sends NOTHING (no vault read, no wire,
no session); the exact SOAP action / power state / boot sequence on confirm; the TLS pin; and that
no secret reaches a result, an argument or an exception text.
"""
import asyncio
import base64
import hashlib
import inspect
import json
import os
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
sys.path.insert(0, str(Path(__file__).resolve().parent))
import amt_gate  # noqa: E402
import amt_kvm  # noqa: E402
import amt_redir  # noqa: E402
import amt_registry  # noqa: E402
import amt_server  # noqa: E402
import amt_tools  # noqa: E402
import amt_vault  # noqa: E402
import amt_write  # noqa: E402
import amt_wsman  # noqa: E402
import wire as wirelib  # noqa: E402
from test_skeleton import TOKEN, TOKEN_HASH, _client, _rpc  # noqa: E402

def _any_real_ocr() -> bool:
    for _name, run in amt_tools.OCR_BACKENDS:
        try:
            run(bytes(64 * 64 * 3), 64, 64)
            return True
        except amt_tools.OcrUnavailable:
            continue
    return False


needs_any_real_ocr = pytest.mark.skipif(not _any_real_ocr(), reason="no OCR backend usable on this node")

DEV = amt_registry.get_device("my-server-1")
PIN = DEV.tls_leaf_sha256
AMT_PW = "AMT-SENTINEL-write-not-real"
RFB_PW = "RFB-SENTINEL-write-not-real"
USER_PW = "USER-SENTINEL-write-not-real"
DEVICE_SECRET = "DEVICE-SIDE-SECRET-SENTINEL"
VAULT = {"my-server-1-amt": AMT_PW, "my-server-1-amt-rfb": RFB_PW, "my-server-1-amt-user-bob": USER_PW}
SENTINELS = (AMT_PW, RFB_PW, USER_PW)
VAULT_READS: list = []
LOG: list = []
PM = "CIM_PowerManagementService"
BOOT_SET = "AMT_BootSettingData"
CIM = "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/"


def fresh_boot_instance():
    return {
        "ElementName": "Intel(r) AMT Boot Configuration Settings", "InstanceID": "Intel(r) AMT:BootSettingData 0",
        "BIOSPause": "false", "BIOSSetup": "false", "BootMediaIndex": "0", "ConfigurationDataReset": "false",
        "FirmwareVerbosity": "0", "ForcedProgressEvents": "false", "IDERBootDevice": "0",
        "LockKeyboard": "false", "LockPowerButton": "false", "LockResetButton": "false",
        "LockSleepButton": "false", "ReflashBIOS": "false", "UseIDER": "false", "UseSOL": "false",
        "UseSafeMode": "false", "UserPasswordBypass": "true",
        # read-only / secret fields a Get returns and a Put must never echo back
        "BIOSLastStatus": ["2", "0"], "BootguardStatus": "0", "UEFIBootNumberOfParams": "0",
        "UEFIBootParametersArray": None, "RPEEnabled": "false", "SecureEraseEnabled": "false",
        "WinREBootEnabled": "false", "UEFILocalPBABootEnabled": "false", "UEFIHTTPSBootEnabled": "false",
        "PlatformErase": "false", "SecureBootControlEnabled": "false", "OptionsCleared": "true",
        "RSEPassword": DEVICE_SECRET,
    }


READ_ONLY_FIELDS = ("BIOSLastStatus", "BootguardStatus", "UEFIBootNumberOfParams", "UEFIBootParametersArray",
                    "RPEEnabled", "SecureEraseEnabled", "WinREBootEnabled", "UEFILocalPBABootEnabled",
                    "UEFIHTTPSBootEnabled", "PlatformErase", "SecureBootControlEnabled", "OptionsCleared",
                    "RSEPassword")


@pytest.fixture
def wire(monkeypatch):
    w = wirelib.Wire()
    VAULT_READS.clear()

    def get_secret(key):
        VAULT_READS.append(key)
        return VAULT[key]

    w.instances[BOOT_SET] = fresh_boot_instance()
    w.instances["CIM_AssociatedPowerManagementService"] = {"PowerState": "2"}
    monkeypatch.setattr(amt_wsman, "transport", w.transport)
    monkeypatch.setattr(amt_vault, "get_secret", get_secret)
    return w


def assert_clean(*things):
    """No vault secret and no device-side secret in anything a caller can see."""
    blob = " ".join(json.dumps(t, default=str) if not isinstance(t, str) else t for t in things)
    for s in (*SENTINELS, DEVICE_SECRET):
        assert s not in blob, f"secret {s[:10]}... leaked"


def assert_nothing_sent(w=None):
    assert VAULT_READS == [], f"vault read before the guard allowed it: {VAULT_READS}"
    if w is not None:
        assert w.calls == [], "a WS-MAN request was sent"
    assert FakeKvm.instances == [] and FakeSol.instances == [] and FakeIder.instances == []


# --- fake engines -----------------------------------------------------------------------

class FakeKvm:
    instances = []
    presented_fp = PIN
    size = (1280, 800)
    tap_error = None
    type_error = None

    def __init__(self, host, port=16995, pw=None, key_delay=0.02):
        self.host, self.port, self.pw = host, port, pw
        self.closed = False
        self.past_connect = False
        self.cert_fp = None
        self.fb = None
        self.typed = []
        FakeKvm.instances.append(self)

    def connect(self):
        self.cert_fp = FakeKvm.presented_fp

    def open(self, deadline=None):
        self.connect()
        self.past_connect = True
        LOG.append(("open",))
        return FakeKvm.size

    def grab_stable(self, **kw):
        LOG.append(("grab_stable",))
        return (*FakeKvm.size, 2, True, 100)

    def click(self, x, y, button="left"):
        LOG.append(("click", x, y, button))

    def _key(self, keysym, down):
        LOG.append(("key", keysym, down))

    def tap(self, keysym):
        LOG.append(("tap", keysym))
        if FakeKvm.tap_error:
            raise FakeKvm.tap_error

    def type_char(self, c):
        LOG.append(("type_char",))
        self.typed.append(c)

    def type_text(self, text):
        LOG.append(("type_text",))         # the text itself is not logged
        self.typed.append(text)
        if FakeKvm.type_error:
            raise FakeKvm.type_error
        return len(text)

    def cad(self):
        LOG.append(("cad",))

    def write_png(self, path):
        Path(path).write_bytes(b"\x89PNG\r\n\x1a\nfake")
        return path

    def close(self):
        self.closed = True


class FakeSol:
    instances = []
    presented_fp = PIN
    output = b"login: "
    truncated = False

    def __init__(self, host, port=16995, pw=None):
        self.host, self.port, self.pw = host, port, pw
        self.sent = []
        self.closed = False
        self.past_connect = False
        self.cert_fp = None
        FakeSol.instances.append(self)

    def connect(self):
        self.cert_fp = FakeSol.presented_fp

    def open_session(self, timeout=20):
        self.connect()
        self.past_connect = True
        LOG.append(("sol_open",))

    def send_text(self, data):
        self.sent.append(data)
        LOG.append(("sol_send",))

    def read_window(self, seconds, max_bytes):
        LOG.append(("sol_read", seconds, max_bytes))
        return FakeSol.output[:max_bytes], FakeSol.truncated

    def close(self):
        self.closed = True


class FakeIder:
    instances = []
    presented_fp = PIN
    fail_open = None

    def __init__(self, host, port=16995, pw=None):
        self.host, self.port, self.pw = host, port, pw
        self.cdrom = self.floppy = None
        self.start_mode = None
        self.bytes_to_amt = 4321
        self.closed = False
        self.cert_fp = None
        FakeIder.instances.append(self)

    def connect(self):
        self.cert_fp = FakeIder.presented_fp

    def open_session(self, timeout=20):
        self.connect()
        if FakeIder.fail_open:
            raise FakeIder.fail_open

    def serve(self, stop, poll=0.5):
        stop.wait()

    def close(self):
        self.closed = True


@pytest.fixture(autouse=True)
def env(monkeypatch, tmp_path):
    LOG.clear()
    FakeKvm.instances, FakeKvm.presented_fp, FakeKvm.tap_error, FakeKvm.type_error = [], PIN, None, None
    FakeSol.instances, FakeSol.presented_fp, FakeSol.output, FakeSol.truncated = [], PIN, b"login: ", False
    FakeIder.instances, FakeIder.presented_fp, FakeIder.fail_open = [], PIN, None
    monkeypatch.setenv(amt_gate.HASH_ENV, TOKEN_HASH)
    monkeypatch.delenv(amt_gate.TRANSPORT_ENV, raising=False)
    monkeypatch.setenv(amt_tools.SHOT_DIR_ENV, str(tmp_path / "shots"))
    monkeypatch.delenv(amt_write.IMAGE_ROOT_ENV, raising=False)
    monkeypatch.setattr(amt_tools.amt_kvm, "KvmSession", FakeKvm)
    monkeypatch.setattr(amt_redir, "SolSession", FakeSol)
    monkeypatch.setattr(amt_redir, "IderSession", FakeIder)
    monkeypatch.setattr(amt_write, "_pause", lambda s: LOG.append(("pause", s)))
    yield
    for mount in list(amt_write._MOUNTS.values()):      # never leave a serving thread behind
        mount.stop.set()
        if mount.thread:
            mount.thread.join(timeout=5)
    amt_write._MOUNTS.clear()


def unpin(monkeypatch):
    monkeypatch.setitem(amt_registry.DEVICES, "my-server-1", __import__("dataclasses").replace(DEV, tls_leaf_sha256=None))


# --- the confirmed guard, every tool ----------------------------------------------------

SYNC_CALLS = {
    "amt_power": lambda **kw: amt_write.power(**kw),
    "amt_set_next_boot": lambda **kw: amt_write.set_next_boot("bios_setup", **kw),
    "amt_console_input": lambda **kw: amt_write.console_input([{"kind": "key", "key": "enter"}], **kw),
    "amt_sol": lambda **kw: amt_write.sol("ls\r", **kw),
    "amt_ider": lambda **kw: amt_write.ider("mount", iso_path="x.iso", **kw),
    "amt_configure": lambda **kw: amt_write.configure("network", {"HostName": "box"}, **kw),
    "amt_wsman_invoke": lambda **kw: amt_write.wsman_invoke("invoke", "CIM_PowerManagementService",
                                                            method="RequestPowerStateChange",
                                                            fields={"PowerState": 12}, **kw),
}
CONSEQUENCE_WORDS = {
    "amt_power": "unsaved work", "amt_set_next_boot": "NEXT boot", "amt_console_input": "console",
    "amt_sol": "Serial-over-LAN", "amt_ider": "IDE-R", "amt_configure": "reads the whole instance",
    "amt_wsman_invoke": "WS-MAN invoke",
}


@pytest.mark.parametrize("tool", sorted(SYNC_CALLS))
@pytest.mark.parametrize("kwargs", [{}, {"confirmed": False}, {"confirmed": "true"}, {"confirmed": 1}])
def test_the_sync_guard_refuses_anything_but_the_literal_true_naming_the_consequence(wire, tool, kwargs):
    """SYNC layer only (what a Python caller reaches). It does NOT show what an HTTP client meets:
    that is the schema's StrictBool, pinned by test_over_http_* below."""
    with pytest.raises(amt_write.ConfirmationRequired) as ex:
        SYNC_CALLS[tool](**kwargs)
    assert "confirmation_required" in str(ex.value) and "Nothing was done" in str(ex.value)
    assert CONSEQUENCE_WORDS[tool] in str(ex.value), "the refusal must name the consequence"
    assert_nothing_sent(wire)


@pytest.mark.parametrize("tool", sorted(SYNC_CALLS))
def test_the_async_tool_refuses_before_taking_a_lock_or_thread(wire, monkeypatch, tool):
    sync_name = {"amt_power": "power", "amt_set_next_boot": "set_next_boot", "amt_console_input": "console_input",
                 "amt_sol": "sol", "amt_ider": "ider", "amt_configure": "configure",
                 "amt_wsman_invoke": "wsman_invoke"}[tool]
    # If the async layer let the call through, it would hand the worker thread the sync function.
    monkeypatch.setattr(amt_write, sync_name, lambda *a, **k: pytest.fail("the call reached the worker thread"))
    fn = getattr(amt_write, tool)
    args = {"amt_set_next_boot": {"target": "pxe"},
            "amt_console_input": {"actions": [{"kind": "key", "key": "enter"}]},
            "amt_ider": {"action": "mount", "iso_path": "x.iso"},
            "amt_configure": {"area": "network", "changes": {"HostName": "box"}},
            "amt_wsman_invoke": {"operation": "invoke", "class_name": "CIM_PowerManagementService",
                                 "method": "RequestPowerStateChange", "fields": {"PowerState": 12}}}.get(tool, {})
    with pytest.raises(amt_write.ConfirmationRequired):
        asyncio.run(fn(**args))
    assert_nothing_sent(wire)


def test_every_write_tool_has_a_confirmed_guard_that_defaults_to_refusing():
    for tool in SYNC_CALLS:
        params = inspect.signature(getattr(amt_write, tool)).parameters
        assert params["confirmed"].default is False, tool
    for sync in (amt_write.power, amt_write.set_next_boot, amt_write.console_input, amt_write.sol,
                 amt_write.ider, amt_write.configure, amt_write.wsman_invoke):
        assert inspect.signature(sync).parameters["confirmed"].default is False


# --- amt_power --------------------------------------------------------------------------

STATES = {"restart": 14, "shutdown": 12, "power_cycle": 15, "shutdown_hard_graceful": 13,
          "power_cycle_hard_graceful": 16, "power_on": 2, "sleep_light": 3, "sleep_deep": 4, "hibernate": 7,
          "immediate_power_cycle": 5, "immediate_shutdown": 8, "hard_power_off": 6, "hard_power_cycle": 9,
          "hard_reset": 10, "nmi": 11}


def power_calls(w):
    return [c for c in w.calls if c.op == "invoke"]


def test_power_defaults_to_the_graceful_os_aware_restart_never_the_hard_reset(wire):
    default = inspect.signature(amt_write.power).parameters["action"].default
    assert default == "restart" == amt_write.DEFAULT_POWER_ACTION
    assert amt_write.POWER_ACTIONS[default][0] == 14
    amt_write.power(confirmed=True)
    call, = power_calls(wire)
    assert call.action == CIM + "CIM_PowerManagementService/RequestPowerStateChange"
    assert call.fields["PowerState"] == "14" and call.fields["PowerState"] != "10"


def test_the_async_tool_default_is_also_the_graceful_restart(wire):
    asyncio.run(amt_write.amt_power(confirmed=True))
    assert [c.fields["PowerState"] for c in power_calls(wire)] == ["14"]


@pytest.mark.parametrize("action,state", sorted(STATES.items()))
def test_each_named_action_emits_exactly_its_dmtf_power_state(wire, action, state):
    out = amt_write.power(action, confirmed=True)
    assert [c.fields["PowerState"] for c in power_calls(wire)] == [str(state)]
    assert out["power_state_requested"] == state and out["graceful"] is (state in (12, 13, 14, 15, 16, 2, 3, 4, 7))


def test_the_vocabulary_is_exactly_the_documented_set_and_only_one_name_sends_state_10():
    assert {k: v[0] for k, v in amt_write.POWER_ACTIONS.items()} == STATES
    assert [k for k, v in amt_write.POWER_ACTIONS.items() if v[0] == 10] == ["hard_reset"]
    assert amt_write.UNGRACEFUL_STATES == {5, 6, 8, 9, 10, 11}


def test_a_hard_reset_is_sent_only_when_explicitly_named_and_says_so(wire):
    with pytest.raises(amt_write.ConfirmationRequired, match="WITHOUT asking the host OS"):
        amt_write.power("hard_reset")
    out = amt_write.power("hard_reset", confirmed=True)
    assert power_calls(wire)[0].fields["PowerState"] == "10" and out["graceful"] is False


def test_a_refused_graceful_request_is_not_silently_downgraded(wire):
    wire.return_values[(PM, "RequestPowerStateChange")] = "1"
    with pytest.raises(amt_wsman.WsmanError, match="wsman_return_value"):
        amt_write.power(confirmed=True)
    assert [c.fields["PowerState"] for c in power_calls(wire)] == ["14"], "no second, harder request"


def test_power_names_the_managed_system_in_its_reference_and_reads_back(wire):
    out = amt_write.power("power_on", confirmed=True)
    call, = power_calls(wire)
    assert call.fields["ManagedElement"] == {"epr": {"class": "CIM_ComputerSystem", "selectors": {
        "CreationClassName": "CIM_ComputerSystem", "Name": "ManagedSystem"}}}
    assert call.order == ["PowerState", "ManagedElement"]
    assert out["power_state_after"] == "on" and wire.ops()[-1] == ("get", "CIM_AssociatedPowerManagementService", None)
    assert_clean(out)


def test_unknown_power_actions_are_refused_before_the_guard(wire):
    for bad in ("reset", "hard-reset", "", "10", "RESTART", "restart; hard_reset"):
        with pytest.raises(ValueError, match="unknown_power_action"):
            amt_write.power(bad, confirmed=True)
    assert_nothing_sent(wire)


# --- amt_set_next_boot ------------------------------------------------------------------

def boot_steps(w):
    return [(c.op, c.cls, c.method) for c in w.calls]


def put_of(w):
    return next(c for c in w.calls if c.op == "put")


# MeshCommander's order (default.htm powerAction*): clear the boot order, Put, activate the role,
# then set the boot order with a source (PXE / disk / diagnostic only).
GET = ("get", "AMT_BootSettingData", None)
CLEAR = ("invoke", "CIM_BootConfigSetting", "ChangeBootOrder")
PUT = ("put", "AMT_BootSettingData", None)
ROLE = ("invoke", "CIM_BootService", "SetBootConfigRole")
SOURCES = {"pxe": "Intel(r) AMT: Force PXE Boot", "hard_disk": "Intel(r) AMT: Force Hard-drive Boot",
           "diagnostic": "Intel(r) AMT: Force Diagnostic Boot"}


@pytest.mark.parametrize("target", ["bios_setup", "pxe", "hard_disk", "cd_ider", "floppy_ider", "diagnostic"])
def test_the_sequence_follows_meshcommanders_order_for_every_target(wire, target):
    out = amt_write.set_next_boot(target, confirmed=True)
    sourced = target in SOURCES
    assert boot_steps(wire) == [GET, CLEAR, PUT, ROLE, *([CLEAR] if sourced else []), GET]
    assert out["steps"] == ["clear_boot_order", "put", "set_boot_config_role",
                            *(["change_boot_order"] if sourced else [])]
    clear, role = wire.calls[1], wire.calls[3]
    assert clear.action == CIM + "CIM_BootConfigSetting/ChangeBootOrder" and clear.fields == {}
    assert clear.selectors == {"InstanceID": "Intel(r) AMT: Boot Configuration 0"}
    assert role.action == CIM + "CIM_BootService/SetBootConfigRole"
    assert role.fields["Role"] == "1"
    assert role.fields["BootConfigSetting"] == {"epr": {"class": "CIM_BootConfigSetting", "selectors": {
        "InstanceID": "Intel(r) AMT: Boot Configuration 0"}}}
    assert wire.calls[2].action == "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
    if sourced:
        assert wire.calls[4].fields == {"Source": {"epr": {"class": "CIM_BootSourceSetting",
                                                           "selectors": {"InstanceID": SOURCES[target]}}}}


def test_an_ider_boot_names_no_boot_source():
    # Live 2026-10-18: naming "Force CD/DVD Boot" (a LOCAL drive) for an IDE-R boot made
    # SetBootConfigRole answer 5. IDE-R boots are picked by the UseIDER flags alone.
    assert "cd_ider" not in amt_write.BOOT_SOURCES and "floppy_ider" not in amt_write.BOOT_SOURCES


def test_the_put_never_echoes_a_read_only_or_secret_field(wire):
    amt_write.set_next_boot("bios_setup", confirmed=True)
    put = put_of(wire)
    for name in READ_ONLY_FIELDS:
        assert name not in put.fields, name
    assert DEVICE_SECRET not in put.xml and "&lt;redacted&gt;" not in put.xml and "<redacted>" not in put.xml
    assert put.fields["BIOSSetup"] == "true"
    # the writable remainder of the Get is preserved (not a minimal rewrite), in the device's order
    assert put.fields["ElementName"].startswith("Intel(r) AMT") and put.fields["UseSafeMode"] == "false"
    # UserPasswordBypass is a plain flag whose NAME contains "password": it is NOT a credential, so it is
    # sent as a real boolean (never a redacted marker). The Get shows "true" from an earlier request; the
    # clean baseline forces it back to false, because nothing from an earlier call may ride along.
    assert put.fields["UserPasswordBypass"] == "false"
    expected_order = [k for k in fresh_boot_instance() if k not in READ_ONLY_FIELDS]
    assert put.order == expected_order


def test_a_future_credential_named_field_in_the_get_is_dropped_too(wire):
    # BOOT_READ_ONLY already lists the known RSEPassword; this pins the NAME-based filter on its own,
    # so an unlisted credential-looking field can never be echoed back as a redacted marker.
    wire.instances[BOOT_SET]["NewRemoteAdminPassword"] = "device-side-value"
    wire.instances[BOOT_SET]["SomeSecretKey"] = "device-side-value-2"
    amt_write.set_next_boot("pxe", confirmed=True)
    put = put_of(wire)
    assert "NewRemoteAdminPassword" not in put.fields and "SomeSecretKey" not in put.fields
    assert "device-side-value" not in put.xml


def test_a_non_scalar_field_in_the_get_is_dropped_not_flattened(wire):
    wire.instances[BOOT_SET]["SomeList"] = ["a", "b"]
    amt_write.set_next_boot("pxe", confirmed=True)
    assert "SomeList" not in put_of(wire).fields


def test_each_next_boot_starts_from_clean_flags(wire):
    wire.instances[BOOT_SET].update({"UseSOL": "true", "UseSafeMode": "true", "BIOSSetup": "true", "UseIDER": "true"})
    amt_write.set_next_boot("pxe", confirmed=True)
    f = put_of(wire).fields
    assert (f["UseSOL"], f["UseSafeMode"], f["BIOSSetup"], f["UseIDER"]) == ("false",) * 4


def test_ider_targets_set_the_ider_flags(wire):
    amt_write.set_next_boot("cd_ider", confirmed=True)
    assert (put_of(wire).fields["UseIDER"], put_of(wire).fields["IDERBootDevice"]) == ("true", "1")
    wire.calls.clear()
    amt_write.set_next_boot("floppy_ider", confirmed=True)
    assert (put_of(wire).fields["UseIDER"], put_of(wire).fields["IDERBootDevice"]) == ("true", "0")


def test_clear_resets_the_flags_and_does_not_activate(wire):
    wire.instances[BOOT_SET]["BIOSSetup"] = "true"
    out = amt_write.set_next_boot("clear", confirmed=True)
    assert [c.method for c in wire.calls if c.op == "invoke"] == ["ChangeBootOrder"]
    assert put_of(wire).fields["BIOSSetup"] == "false" and out["steps"] == ["clear_boot_order", "put"]


@pytest.mark.parametrize("bad", ["usb", "USB", "", "bios", "pxe ", "Intel(r) AMT: Force USB Boot",
                                 "pxe; usb", "../etc", "cd", None])
def test_a_target_outside_the_allowlist_is_refused_and_nothing_is_sent(wire, bad):
    with pytest.raises(ValueError, match="boot_target_not_allowed"):
        amt_write.set_next_boot(bad, confirmed=True)
    assert_nothing_sent(wire)


def test_the_only_boot_sources_ever_sent_are_the_three_fixed_names():
    assert set(amt_write.BOOT_SOURCES.values()) == set(SOURCES.values())
    assert set(amt_write.BOOT_TARGETS) == {"bios_setup", "pxe", "hard_disk", "cd_ider", "floppy_ider",
                                           "diagnostic", "clear"}


def test_advanced_options_are_sixteen_validated_and_applied_over_the_target(wire):
    assert len(amt_write.BOOT_OPTIONS) == 16 and len({f for f, _ in amt_write.BOOT_OPTIONS.values()}) == 16
    out = amt_write.set_next_boot("pxe", {"lock_keyboard": True, "firmware_verbosity": 2, "use_sol": True},
                                  confirmed=True)
    f = put_of(wire).fields
    assert (f["LockKeyboard"], f["FirmwareVerbosity"], f["UseSOL"]) == ("true", "2", "true")
    assert out["options"] == ["firmware_verbosity", "lock_keyboard", "use_sol"]


@pytest.mark.parametrize("opts", [{"nope": True}, {"lock_keyboard": 1}, {"firmware_verbosity": 4},
                                  {"firmware_verbosity": True}, {"boot_media_index": 256}, {"use_sol": "true"}])
def test_bad_advanced_options_are_refused_before_the_guard(wire, opts):
    with pytest.raises(ValueError):
        amt_write.set_next_boot("pxe", opts, confirmed=True)
    assert_nothing_sent(wire)


def test_the_bypass_flag_is_settable_and_verified_on_readback(wire):
    wire.instances[BOOT_SET]["UserPasswordBypass"] = "false"
    out = amt_write.set_next_boot("pxe", {"user_password_bypass": True}, confirmed=True)
    assert put_of(wire).fields["UserPasswordBypass"] == "true"
    assert out["readback"]["UserPasswordBypass"] is True
    wire.ignore_put.add(BOOT_SET)
    wire.instances[BOOT_SET]["UserPasswordBypass"] = "false"
    with pytest.raises(amt_wsman.WsmanError, match="boot_readback_mismatch:.*UserPasswordBypass"):
        amt_write.set_next_boot("pxe", {"user_password_bypass": True}, confirmed=True)


def test_destructive_options_are_named_in_the_consequence(wire):
    with pytest.raises(amt_write.ConfirmationRequired, match="secure_erase"):
        amt_write.set_next_boot("pxe", {"secure_erase": True})


def test_a_put_fault_short_circuits_the_rest_of_the_sequence(wire):
    wire.faults[("put", BOOT_SET)] = "rejected"
    with pytest.raises(amt_wsman.WsmanError, match="boot_sequence_failed:completed=clear_boot_order:"):
        amt_write.set_next_boot("pxe", confirmed=True)
    assert boot_steps(wire) == [GET, CLEAR, PUT]


def test_a_failure_after_the_put_names_what_already_happened(wire):
    wire.faults[("invoke", "CIM_BootService", "SetBootConfigRole")] = "no role"
    with pytest.raises(amt_wsman.WsmanError, match="completed=clear_boot_order,put:"):
        amt_write.set_next_boot("pxe", confirmed=True)


def test_a_readback_that_disagrees_raises_instead_of_claiming_success(wire):
    wire.ignore_put.add(BOOT_SET)
    with pytest.raises(amt_wsman.WsmanError, match="boot_readback_mismatch:BIOSSetup"):
        amt_write.set_next_boot("bios_setup", confirmed=True)


def test_boot_result_carries_the_readback_and_no_secret(wire):
    out = amt_write.set_next_boot("bios_setup", confirmed=True)
    assert out["readback"]["BIOSSetup"] is True and out["target"] == "bios_setup"
    assert_clean(out)


# --- amt_console_input ------------------------------------------------------------------

def kvm_log():
    return [e for e in LOG if e[0] not in ("pause",)]


def test_console_steps_run_in_order_paced_and_return_a_screenshot(wire):
    out = amt_write.console_input([
        {"kind": "click", "x": 0.5, "y": 0.25},
        {"kind": "text", "text": "hello"},
        {"kind": "key", "key": "enter"},
        {"kind": "key", "key": "c", "modifiers": ["ctrl"]},
        {"kind": "macro", "macro": "alt_tab"},
        {"kind": "macro", "macro": "ctrl_alt_del"},
        {"kind": "wait", "seconds": 2},
    ], confirmed=True)
    ks = amt_kvm.KEYSYM
    assert kvm_log() == [
        ("open",), ("grab_stable",),
        ("click", 640, 200, "left"),
        ("type_text",),
        ("tap", ks["enter"]),
        ("key", ks["ctrl"], True), ("tap", ord("c")), ("key", ks["ctrl"], False),
        ("key", ks["alt"], True), ("tap", ks["tab"]), ("key", ks["alt"], False),
        ("cad",),
        ("grab_stable",),
    ]
    assert [e for e in LOG if e[0] == "pause"].count(("pause", amt_write.INPUT_PAUSE_SECONDS)) == 7
    assert ("pause", 2) in LOG
    assert out["steps_run"] == 7 and out["kinds"] == ["click", "text", "key", "key", "macro", "macro", "wait"]
    assert out["screenshot"]["path"].endswith(".png") and Path(out["screenshot"]["path"]).exists()
    assert FakeKvm.instances[0].closed is True


def test_typed_text_reaches_the_engine_but_never_the_result(wire):
    out = amt_write.console_input([{"kind": "text", "text": "needle-text-123"}], confirmed=True)
    assert FakeKvm.instances[0].typed == ["needle-text-123"]
    assert "needle-text-123" not in json.dumps(out, default=str)


def test_a_secret_step_types_the_vaulted_host_credential_but_never_returns_it(wire, monkeypatch):
    host_user, host_pw = "operator-host-user", "host-pw-needle-77"
    monkeypatch.setitem(VAULT, "my-server-1-os", json.dumps({"user": host_user, "password": host_pw}))
    out = amt_write.console_input([{"kind": "secret", "secret": "host_user"}, {"kind": "key", "key": "tab"},
                                   {"kind": "secret", "secret": "host_password"}], confirmed=True)
    assert FakeKvm.instances[0].typed == [host_user, host_pw]
    assert out["kinds"] == ["secret", "key", "secret"]
    blob = json.dumps(out, default=str)
    assert host_pw not in blob and host_user not in blob
    assert "my-server-1-os" in VAULT_READS


def test_a_secret_step_with_no_usable_credential_sends_nothing(wire, monkeypatch):
    monkeypatch.setitem(VAULT, "my-server-1-os", "not json host-pw-needle-77")
    with pytest.raises(amt_vault.VaultError) as ex:
        amt_write.console_input([{"kind": "secret", "secret": "host_password"}], confirmed=True)
    assert "needle" not in str(ex.value)
    assert not FakeKvm.instances


def test_modifiers_are_released_when_a_key_fails_and_the_session_closes(wire):
    FakeKvm.tap_error = amt_kvm.AmtError("boom-with-detail")
    with pytest.raises(amt_kvm.AmtError) as ex:
        amt_write.console_input([{"kind": "key", "key": "f4", "modifiers": ["alt", "ctrl"]}], confirmed=True)
    assert str(ex.value) == "console_input_failed:step_0:key" and "boom" not in str(ex.value)
    ks = amt_kvm.KEYSYM
    downs = [e for e in LOG if e[0] == "key" and e[2]]
    ups = [e for e in LOG if e[0] == "key" and not e[2]]
    assert [e[1] for e in downs] == [ks["alt"], ks["ctrl"]] and [e[1] for e in ups] == [ks["ctrl"], ks["alt"]]
    assert FakeKvm.instances[0].closed is True


def test_an_engine_text_error_never_echoes_the_typed_character(wire):
    FakeKvm.type_error = amt_kvm.AmtError("non_ascii_char_0xe9")
    with pytest.raises(amt_kvm.AmtError) as ex:
        amt_write.console_input([{"kind": "text", "text": "abc"}], confirmed=True)
    assert "0xe9" not in str(ex.value) and str(ex.value) == "console_input_failed:step_0:text"


@pytest.mark.parametrize("actions", [
    [], [{"kind": "click"}], [{"kind": "click", "x": 2, "y": 0.5}], [{"kind": "text"}],
    [{"kind": "text", "text": "café"}], [{"kind": "text", "text": "a" * 501}],
    [{"kind": "text", "text": "tab\there"}], [{"kind": "key"}], [{"kind": "key", "key": "nokey"}],
    [{"kind": "key", "key": "é"}], [{"kind": "macro"}], [{"kind": "macro", "macro": "format_c"}],
    [{"kind": "wait"}], [{"kind": "wait", "seconds": 11}], [{"kind": "bogus"}],
    [{"kind": "secret"}], [{"kind": "secret", "secret": "amt_password"}],
    [{"kind": "key", "key": "a", "extra": 1}],
    [{"kind": "key", "key": "enter"}] * 51,
    [{"kind": "wait", "seconds": 10}] * 4,
])
def test_a_malformed_step_list_is_refused_before_any_session_opens(wire, actions):
    with pytest.raises(ValueError):          # a pydantic ValidationError is a ValueError subclass
        amt_write.console_input(actions, confirmed=True)
    assert_nothing_sent(wire)


def test_console_pin_mismatch_is_refused_before_any_input(wire):
    FakeKvm.presented_fp = "0" * 64
    with pytest.raises(amt_kvm.AmtError, match="tls_leaf_pin_mismatch"):
        amt_write.console_input([{"kind": "text", "text": "x"}], confirmed=True)
    assert not any(e[0] in ("click", "type_text", "tap", "key", "cad") for e in LOG)
    assert FakeKvm.instances[0].past_connect is False


def test_console_unpinned_device_is_refused_before_the_vault_and_the_wire(wire, monkeypatch):
    unpin(monkeypatch)
    with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
        amt_write.console_input([{"kind": "key", "key": "enter"}], confirmed=True)
    assert_nothing_sent(wire)


def test_key_macros_are_the_census_25_and_every_one_resolves():
    import amt_parity
    assert len(amt_write.KEY_MACROS) == 25 == amt_parity.COVERAGE["key_macros"]["total"]
    for name in amt_write.KEY_MACROS:
        assert amt_write._compile_actions([{"kind": "macro", "macro": name}])
    assert amt_write.EXTRA_KEYSYM["f2"] == 0xFFBF and amt_write.EXTRA_KEYSYM["f12"] == 0xFFC9


def test_ctrl_alt_del_uses_the_engine_cad_and_a_single_char_without_modifiers_is_typed(wire):
    amt_write.console_input([{"kind": "macro", "macro": "ctrl_alt_del"}, {"kind": "key", "key": "A"}], confirmed=True)
    assert ("cad",) in LOG and ("type_char",) in LOG


# --- amt_console_input: the optional ``expect`` screen guard --------------------------------

INPUT_EVENTS = ("click", "type_text", "type_char", "tap", "key", "cad")
HOST_CRED = json.dumps({"user": "operator-host-user", "password": "host-pw-needle-77"})


def sent_input():
    """Every event that put a key, click or text on the host (opening and grabbing do not)."""
    return [e for e in LOG if e[0] in INPUT_EVENTS]


def fake_screen(monkeypatch, label, problem=None):
    """Replace the classifier the guard calls; returns the list of ``user`` values it was given."""
    users = []

    def classify(frame, user="", *, ocr=True):
        users.append(user)
        return {"label": label, "markers": {"ocr_problem": problem}}

    monkeypatch.setattr(amt_tools, "classify_screen", classify)
    return users


def test_a_screen_that_is_not_expected_aborts_naming_the_label_and_sends_nothing(wire, monkeypatch):
    fake_screen(monkeypatch, "bios-setup")
    with pytest.raises(amt_kvm.AmtError) as ex:
        amt_write.console_input([{"kind": "key", "key": "enter"}, {"kind": "text", "text": "x"},
                                 {"kind": "click", "x": 0.5, "y": 0.5}], confirmed=True, expect=["grub", "mok-manager"])
    assert str(ex.value) == "screen_not_expected:saw=bios-setup:expected=grub,mok-manager"
    assert sent_input() == [] and FakeKvm.instances[0].typed == []
    assert FakeKvm.instances[0].closed is True, "the session is closed even when the guard aborts"


def test_a_screen_that_is_expected_runs_the_steps_and_reports_its_label(wire, monkeypatch):
    fake_screen(monkeypatch, "grub")
    out = amt_write.console_input([{"kind": "key", "key": "down"}, {"kind": "key", "key": "enter"}],
                                  confirmed=True, expect=["bios-setup", "grub"])
    assert [e[0] for e in sent_input()] == ["tap", "tap"]
    assert out["steps_run"] == 2 and out["screen_label"] == "grub"
    assert out["screenshot"]["path"].endswith(".png")


def test_the_guard_classifies_the_first_frame_before_the_first_step(wire, monkeypatch):
    fake_screen(monkeypatch, "grub")
    amt_write.console_input([{"kind": "key", "key": "enter"}], confirmed=True, expect=["grub"])
    names = [e[0] for e in LOG if e[0] != "pause"]
    assert names[:2] == ["open", "grab_stable"] and names.index("tap") > 1


@pytest.mark.parametrize("problem", ["ocr_unavailable", "ocr_failed", "ocr_no_text"])
def test_a_frame_the_recognizer_could_not_read_aborts_even_with_a_geometry_label(wire, monkeypatch, problem):
    """A sub-Windows frame keeps ``bios-setup`` without OCR; that is geometry, never proof."""
    fake_screen(monkeypatch, "bios-setup", problem)
    with pytest.raises(amt_kvm.AmtError) as ex:
        amt_write.console_input([{"kind": "key", "key": "f2"}], confirmed=True, expect=["bios-setup"])
    assert str(ex.value) == f"screen_not_identified:{problem}:expected=bios-setup"
    assert sent_input() == []


@pytest.mark.parametrize("label", sorted(amt_tools.BOOT_FIRMWARE_LABELS))
def test_a_secret_step_beside_a_boot_or_firmware_label_is_refused_before_the_session_opens(wire, label):
    with pytest.raises(ValueError, match=f"secret_step_refused_for_boot_screen:{label}"):
        amt_write.console_input([{"kind": "secret", "secret": "host_password"}], confirmed=True,
                                expect=["linux-console", label])
    assert_nothing_sent(wire)       # no vault read, no session, no input


def test_the_secret_refusal_comes_before_the_confirmation_and_the_async_layer_takes_no_thread(wire, monkeypatch):
    monkeypatch.setattr(amt_write, "console_input", lambda *a, **k: pytest.fail("reached the worker thread"))
    with pytest.raises(ValueError, match="secret_step_refused_for_boot_screen:grub"):
        asyncio.run(amt_write.amt_console_input([{"kind": "secret", "secret": "host_user"}], expect=["grub"],
                                                confirmed=False))
    assert_nothing_sent(wire)


def test_a_secret_beside_a_non_boot_label_is_allowed_and_typed_only_after_the_screen_matches(wire, monkeypatch):
    monkeypatch.setitem(VAULT, "my-server-1-os", HOST_CRED)
    fake_screen(monkeypatch, "linux-console")
    amt_write.console_input([{"kind": "secret", "secret": "host_user"}], confirmed=True, expect=["linux-console"])
    assert FakeKvm.instances[0].typed == ["operator-host-user"]
    LOG.clear()
    fake_screen(monkeypatch, "grub")
    FakeKvm.instances.clear()
    with pytest.raises(amt_kvm.AmtError, match="screen_not_expected:saw=grub"):
        amt_write.console_input([{"kind": "secret", "secret": "host_password"}], confirmed=True,
                                expect=["linux-console"])
    assert FakeKvm.instances[0].typed == [] and sent_input() == [], "no credential reached a mismatched screen"


def test_without_expect_the_tool_behaves_exactly_as_before(wire, monkeypatch):
    monkeypatch.setattr(amt_tools, "classify_screen", lambda *a, **k: pytest.fail("classified without expect"))
    out = amt_write.console_input([{"kind": "key", "key": "enter"}], confirmed=True)
    assert set(out) == {"device", "steps_run", "kinds", "screenshot"} and "screen_label" not in out
    assert [e[0] for e in LOG if e[0] != "pause"] == ["open", "grab_stable", "tap", "grab_stable"]
    assert amt_write.console_input([{"kind": "key", "key": "enter"}], confirmed=True, expect=None)["steps_run"] == 1


@pytest.mark.parametrize("expect", [[], "grub", ["nonsense"], ["unknown"], ["grub", "boot-menu"], [None], 5])
def test_a_malformed_expect_is_refused_before_any_session_opens(wire, expect):
    with pytest.raises(ValueError):
        amt_write.console_input([{"kind": "key", "key": "enter"}], confirmed=True, expect=expect)
    assert_nothing_sent(wire)


def test_a_windows_signin_expectation_matches_the_tile_against_the_vaulted_user_only(wire, monkeypatch):
    monkeypatch.setitem(VAULT, "my-server-1-os", HOST_CRED)
    users = fake_screen(monkeypatch, "windows-signin")
    out = amt_write.console_input([{"kind": "key", "key": "tab"}], confirmed=True, expect=["windows-signin"])
    assert users == ["operator-host-user"] and out["screen_label"] == "windows-signin"
    assert "host-pw-needle-77" not in json.dumps(out, default=str)
    users = fake_screen(monkeypatch, "grub")
    VAULT_READS.clear()
    amt_write.console_input([{"kind": "key", "key": "tab"}], confirmed=True, expect=["grub"])
    assert users == [""] and "my-server-1-os" not in VAULT_READS, "the host credential is read only when needed"


def test_expect_is_a_documented_optional_schema_parameter_of_the_registered_tool():
    tool = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}["amt_console_input"]
    prop = tool.inputSchema["properties"]["expect"]
    assert "expect" not in tool.inputSchema.get("required", [])
    assert prop["description"].strip() and prop["default"] is None
    enum = prop["anyOf"][0]["items"]["enum"]
    assert enum == list(amt_write.EXPECT_LABELS) and "unknown" not in enum
    assert {"grub", "text-installer", "mok-manager", "bios-setup", "linux-console"} <= set(enum)
    assert "no credential is ever typed" in prop["description"]


@needs_any_real_ocr
@pytest.mark.parametrize("name,real_label", [("grub-installed-menu.png", "grub"),
                                             ("text-installer-keyboard-list.png", "text-installer"),
                                             ("mok-perform-continue-boot.png", "mok-manager")])
def test_the_guard_on_a_real_boot_frame_end_to_end(wire, monkeypatch, name, real_label):
    """Real frame, real recognizer, mocked session: the matching expectation runs, any other aborts."""
    from frames import decode_png
    path = Path(__file__).resolve().parent / "real_frames" / name
    if not path.exists():
        pytest.skip(f"real frame missing, not replaced: {path}")
    shot = decode_png(path)

    def grab(self, **kw):
        LOG.append(("grab_stable",))
        self.fb = shot.fb
        return (shot.width, shot.height, 2, True, 100)

    monkeypatch.setattr(FakeKvm, "grab_stable", grab)
    out = amt_write.console_input([{"kind": "key", "key": "enter"}], confirmed=True, expect=[real_label])
    assert out["screen_label"] == real_label and [e[0] for e in sent_input()] == ["tap"]
    LOG.clear()
    other = next(l for l in ("grub", "text-installer", "mok-manager") if l != real_label)
    with pytest.raises(amt_kvm.AmtError, match=f"screen_not_expected:saw={real_label}:expected={other}"):
        amt_write.console_input([{"kind": "key", "key": "enter"}], confirmed=True, expect=[other])
    assert sent_input() == []


# --- amt_sol ----------------------------------------------------------------------------

def test_sol_sends_the_text_reads_a_bounded_window_and_closes(wire):
    out = amt_write.sol("root\r", read_seconds=2, max_bytes=100, confirmed=True)
    s = FakeSol.instances[0]
    assert s.sent == [b"root\r"] and s.closed is True
    assert [e for e in LOG if e[0].startswith("sol")] == [("sol_open",), ("sol_send",), ("sol_read", 2, 100)]
    assert out["output"] == "login: " and out["bytes"] == 7 and out["truncated"] is False
    assert out["sent_chars"] == 5 and "root" not in json.dumps(out)
    assert_clean(out)


def test_sol_with_no_text_only_reads(wire):
    out = amt_write.sol(confirmed=True)
    assert FakeSol.instances[0].sent == [] and out["bytes"] == 7


@pytest.mark.parametrize("kwargs", [{"text": "x" * 1025}, {"text": "café"}, {"read_seconds": 0},
                                    {"read_seconds": 16}, {"max_bytes": 0}, {"max_bytes": 16385}])
def test_sol_arguments_are_bounded_before_any_session(wire, kwargs):
    with pytest.raises(ValueError):
        amt_write.sol(confirmed=True, **kwargs)
    assert_nothing_sent(wire)


def test_sol_pin_mismatch_and_unpinned_device_are_refused(wire, monkeypatch):
    FakeSol.presented_fp = "f" * 64
    with pytest.raises(amt_kvm.AmtError, match="tls_leaf_pin_mismatch"):
        amt_write.sol("x", confirmed=True)
    assert FakeSol.instances[0].sent == [] and FakeSol.instances[0].closed is True
    FakeSol.instances.clear()
    unpin(monkeypatch)
    VAULT_READS.clear()
    with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
        amt_write.sol("x", confirmed=True)
    assert VAULT_READS == [] and FakeSol.instances == []


# --- amt_ider ---------------------------------------------------------------------------

def make_image(root, name, size=4096):
    p = root / name
    p.write_bytes(b"\x00" * size)
    return p


@pytest.fixture
def images(tmp_path, monkeypatch):
    root = tmp_path / "nas"
    root.mkdir()
    monkeypatch.setenv(amt_write.IMAGE_ROOT_ENV, str(root))
    return root


def test_mount_without_an_image_root_is_refused_before_the_vault_or_a_session(wire):
    with pytest.raises(ValueError, match="ider_image_root_unset"):
        amt_write.ider("mount", iso_path="a.iso", confirmed=True)
    assert_nothing_sent(wire)


def test_mount_serves_the_image_until_unmount_and_reports_status(wire, images):
    make_image(images, "boot.iso", 4096)
    make_image(images, "tools.img", 1024)
    out = amt_write.ider("mount", iso_path="boot.iso", floppy_path="tools.img", start="graceful", confirmed=True)
    assert out["mounted"] is True and out["images"] == {"iso": "boot.iso", "floppy": "tools.img"}
    s = FakeIder.instances[0]
    assert s.cdrom.size == 4096 and s.floppy.size == 1024 and s.start_mode == "graceful"
    st = amt_write.ider("status")
    assert st["mounted"] is True and st["images"]["iso"] == "boot.iso" and st["bytes_to_host"] == 4321
    with pytest.raises(ValueError, match="ider_already_mounted"):
        amt_write.ider("mount", iso_path="boot.iso", confirmed=True)
    assert len(FakeIder.instances) == 1
    fds = [m.fd for m in (s.cdrom, s.floppy)]
    done = amt_write.ider("unmount", confirmed=True)
    assert done["mounted"] is False and done["ended_with_error"] is None and s.closed is True
    for fd in fds:
        with pytest.raises(OSError):
            os.fstat(fd)
    assert amt_write.ider("status") == {"device": "my-server-1", "mounted": False}
    with pytest.raises(ValueError, match="ider_not_mounted"):
        amt_write.ider("unmount", confirmed=True)


@pytest.mark.parametrize("path", ["../escape.iso", "sub/../../escape.iso", "/etc/passwd.iso", "missing.iso",
                                  "notiso.txt", "odd.iso", "empty.iso", "dir.iso"])
def test_unsafe_or_invalid_images_are_refused_and_no_session_opens(wire, images, tmp_path, path):
    make_image(images, "odd.iso", 1000)
    make_image(images, "empty.iso", 0)
    make_image(images, "notiso.txt", 512)
    (images / "dir.iso").mkdir()
    make_image(tmp_path, "escape.iso", 512)
    with pytest.raises(ValueError):
        amt_write.ider("mount", iso_path=path, confirmed=True)
    assert FakeIder.instances == [] and VAULT_READS == []


@pytest.mark.parametrize("path", ["../escape.iso", "sub/../../escape.iso", "a/../b.iso"])
def test_a_parent_directory_segment_is_refused_by_name_before_the_filesystem_is_consulted(wire, images, path):
    # Redundant with the resolve+containment check for a real escape, so pin the specific refusal.
    with pytest.raises(ValueError, match="ider_image_path_traversal"):
        amt_write.ider("mount", iso_path=path, confirmed=True)
    assert FakeIder.instances == []


def test_a_symlink_out_of_the_image_root_is_refused(wire, images, tmp_path):
    outside = make_image(tmp_path, "outside.iso", 512)
    (images / "link.iso").symlink_to(outside)
    with pytest.raises(ValueError, match="ider_image_outside_image_root"):
        amt_write.ider("mount", iso_path="link.iso", confirmed=True)
    assert FakeIder.instances == []


def test_an_iso_must_be_iso_and_a_floppy_img_and_one_image_is_required(wire, images):
    make_image(images, "a.img", 512)
    make_image(images, "a.iso", 512)
    with pytest.raises(ValueError, match="needs_extension_.iso"):
        amt_write.ider("mount", iso_path="a.img", confirmed=True)
    with pytest.raises(ValueError, match="needs_extension_.img"):
        amt_write.ider("mount", floppy_path="a.iso", confirmed=True)
    with pytest.raises(ValueError, match="ider_mount_needs_an_image"):
        amt_write.ider("mount", confirmed=True)


def test_ider_pin_mismatch_closes_the_images_and_leaves_nothing_mounted(wire, images):
    make_image(images, "boot.iso", 512)
    FakeIder.presented_fp = "a" * 64
    with pytest.raises(amt_kvm.AmtError, match="tls_leaf_pin_mismatch"):
        amt_write.ider("mount", iso_path="boot.iso", confirmed=True)
    assert amt_write.ider("status")["mounted"] is False


def test_ider_unpinned_device_is_refused_before_the_vault(wire, images, monkeypatch):
    make_image(images, "boot.iso", 512)
    unpin(monkeypatch)
    with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
        amt_write.ider("mount", iso_path="boot.iso", confirmed=True)
    assert VAULT_READS == [] and FakeIder.instances == []


def test_a_failed_session_open_closes_the_images(wire, images):
    make_image(images, "boot.iso", 512)
    FakeIder.fail_open = amt_kvm.AmtError("ider_start_refused")
    with pytest.raises(amt_kvm.AmtError, match="ider_start_refused"):
        amt_write.ider("mount", iso_path="boot.iso", confirmed=True)
    assert FakeIder.instances[0].closed is True and amt_write.ider("status")["mounted"] is False


def test_status_needs_no_confirmation_but_unmount_and_mount_do(wire, images):
    assert amt_write.ider("status")["mounted"] is False
    for action in ("mount", "unmount"):
        with pytest.raises(amt_write.ConfirmationRequired):
            amt_write.ider(action, iso_path="x.iso")


# --- amt_configure ----------------------------------------------------------------------

def general_instance():
    return {"ElementName": "Intel(r) AMT: General Settings", "InstanceID": "Intel(r) AMT: General Settings",
            "HostName": "old-host", "DomainName": "lan", "DigestRealm": "Digest:ABC123",
            "AMTNetworkEnabled": "1", "NetworkInterfaceEnabled": "true", "SharedFQDN": "true",
            "PingResponseEnabled": "true", "IdleWakeTimeout": "1"}


def kvm_instance():
    return {"ElementName": "Intel(r) KVM Redirection Settings", "InstanceID": "Intel(r) KVM Redirection Settings",
            "Is5900PortEnabled": "false", "OptInPolicy": "true", "RFBPassword": "must-not-be-echoed",
            "SessionTimeout": "0", "EnabledByMEBx": "true"}


def test_configure_network_puts_the_whole_instance_with_only_the_change_applied_and_reads_it_all_back(wire):
    wire.instances["AMT_GeneralSettings"] = general_instance()
    out = amt_write.configure("network", {"HostName": "new-host", "PingResponseEnabled": False}, confirmed=True)
    assert [(c.op, c.cls) for c in wire.calls] == [("get", "AMT_GeneralSettings"), ("put", "AMT_GeneralSettings"),
                                                  ("get", "AMT_GeneralSettings")]
    put = wire.calls[1]
    assert put.fields["HostName"] == "new-host" and put.fields["PingResponseEnabled"] == "false"
    # every OTHER writable field is echoed unchanged (a whole-replace Put must not reset it) ...
    assert put.fields["DomainName"] == "lan" and put.fields["AMTNetworkEnabled"] == "1"
    assert put.fields["NetworkInterfaceEnabled"] == "true" and put.fields["SharedFQDN"] == "true"
    # ... and the device-owned read-only field is not
    assert "DigestRealm" not in put.fields
    assert put.order == ["ElementName", "InstanceID", "HostName", "DomainName", "AMTNetworkEnabled",
                         "NetworkInterfaceEnabled", "SharedFQDN", "PingResponseEnabled", "IdleWakeTimeout"], \
        "the device's own order"
    assert out["previous"] == {"HostName": "old-host", "PingResponseEnabled": True}
    assert out["readback"] == {"HostName": "new-host", "PingResponseEnabled": False}
    assert out["verified_unchanged"] == ["AMTNetworkEnabled", "DomainName", "ElementName", "IdleWakeTimeout",
                                         "InstanceID", "NetworkInterfaceEnabled", "SharedFQDN"]
    assert "previous" in out["revert"]
    assert_clean(out)


def test_configure_reports_a_collateral_reset_the_device_made_to_a_field_it_was_not_asked_to_change(wire):
    wire.instances["AMT_GeneralSettings"] = general_instance()
    wire.on_put["AMT_GeneralSettings"] = lambda c: wire.instances["AMT_GeneralSettings"].update({"DomainName": ""})
    with pytest.raises(amt_wsman.WsmanError, match=r"configure_collateral_change:network:DomainName:was=.*lan"):
        amt_write.configure("network", {"HostName": "new-host"}, confirmed=True)


def test_configure_refuses_before_any_put_an_instance_it_cannot_echo_faithfully(wire, monkeypatch):
    """A whole-replace Put would silently reset a field this tool cannot echo, so the area is refused."""
    nested = {**general_instance(), "Nested": {"a": "1"}}
    monkeypatch.setattr(amt_wsman, "get", lambda *a, **k: nested)
    with pytest.raises(amt_wsman.WsmanError, match="configure_instance_not_round_trippable:network:Nested"):
        amt_write.configure("network", {"HostName": "new-host"}, confirmed=True)
    assert wire.calls == [], "nothing was written"


def test_configure_refuses_before_any_put_an_instance_holding_an_unechoable_credential(wire):
    wire.instances["AMT_GeneralSettings"] = {**general_instance(), "AdminPassword": DEVICE_SECRET}
    with pytest.raises(amt_wsman.WsmanError, match="configure_instance_not_round_trippable:network:AdminPassword"):
        amt_write.configure("network", {"HostName": "new-host"}, confirmed=True)
    assert [c.op for c in wire.calls] == ["get"], "nothing was written"


def test_configure_a_readback_that_disagrees_raises_with_the_previous_values(wire):
    wire.instances["AMT_GeneralSettings"] = general_instance()
    wire.ignore_put.add("AMT_GeneralSettings")
    with pytest.raises(amt_wsman.WsmanError, match=r"configure_readback_mismatch:network:HostName:previous=.*old-host"):
        amt_write.configure("network", {"HostName": "new-host"}, confirmed=True)


def test_configure_security_names_its_instance_selector(wire):
    wire.instances["AMT_TLSSettingData"] = {"ElementName": "TLS", "InstanceID": "Intel(r) AMT 802.3 TLS Settings",
                                            "AcceptNonSecureConnections": "true", "MutualAuthentication": "false"}
    amt_write.configure("security", {"AcceptNonSecureConnections": False}, confirmed=True)
    assert all(c.selectors == {"InstanceID": "Intel(r) AMT 802.3 TLS Settings"} for c in wire.calls)
    # the field that was not asked to change is echoed, not dropped, and verified on readback
    assert wire.calls[1].fields["MutualAuthentication"] == "false" and wire.calls[1].fields["AcceptNonSecureConnections"] == "false"


def test_configure_kvm_takes_the_rfb_password_from_the_vault_in_the_devices_position(wire):
    wire.instances["IPS_KVMRedirectionSettingData"] = kvm_instance()
    out = amt_write.configure("kvm", {"Is5900PortEnabled": True}, confirmed=True)
    put = wire.calls[1]
    assert put.order == ["ElementName", "InstanceID", "Is5900PortEnabled", "OptInPolicy", "RFBPassword", "SessionTimeout"]
    assert put.fields["RFBPassword"] == RFB_PW and "must-not-be-echoed" not in put.xml
    assert "EnabledByMEBx" not in put.fields
    assert "my-server-1-amt-rfb" in VAULT_READS
    assert_clean(out)
    assert RFB_PW not in json.dumps(out)


def test_configure_kvm_failures_never_carry_the_rfb_password(wire):
    wire.instances["IPS_KVMRedirectionSettingData"] = kvm_instance()
    wire.ignore_put.add("IPS_KVMRedirectionSettingData")
    with pytest.raises(amt_wsman.WsmanError) as ex:
        amt_write.configure("kvm", {"Is5900PortEnabled": True}, confirmed=True)
    assert_clean(str(ex.value))


@pytest.mark.parametrize("area,changes,why", [
    ("network", {"RFBPassword": "x"}, "secret_field_refused"),
    ("network", {"AdminPassword": "x"}, "secret_field_refused"),
    ("kvm", {"RFBPassword": "x"}, "secret_field_refused"),
    ("network", {"NetworkInterfaceEnabled": False}, "unknown_field:network"),
    ("network", {"DigestRealm": "x"}, "unknown_field:network"),
    ("security", {"MutualAuthentication": True}, "unknown_field:security"),
    ("network", {"HostName": 5}, "invalid_value"),
    ("network", {"PingResponseEnabled": "yes"}, "invalid_value"),
    ("network", {"DDNSTTL": True}, "invalid_value"),
    ("network", {"HostName": ""}, "invalid_value"),
    ("internet", {"DetectionStrings": "one"}, "invalid_value"),
    ("network", {}, "changes_must_be_a_nonempty_object"),
    ("features", {"listener_enabled": True}, "unknown_field:features"),
    ("agent_presence", {"x": 1}, "area_not_writable_by_this_tool"),
    ("system_defense", {"x": 1}, "area_not_writable_by_this_tool"),
    ("subscriptions", {"x": 1}, "area_not_writable_by_this_tool"),
    ("wake_alarms", {"x": 1}, "area_not_writable_by_this_tool"),
    ("bogus", {"x": 1}, "unknown_settings_area"),
])
def test_configure_refuses_unlisted_secret_and_malformed_changes_before_any_io(wire, area, changes, why):
    with pytest.raises(ValueError, match=why):
        amt_write.configure(area, changes, confirmed=True)
    assert_nothing_sent(wire)


def test_configure_internet_writes_a_list_field(wire):
    wire.instances["AMT_EnvironmentDetectionSettingData"] = {
        "ElementName": "e", "InstanceID": "i", "DetectionAlgorithm": "0", "DetectionStrings": ["a.lan", "b.lan"]}
    out = amt_write.configure("internet", {"DetectionStrings": ["corp.example", "lan.example"]}, confirmed=True)
    assert wire.calls[1].fields["DetectionStrings"] == ["corp.example", "lan.example"]
    assert out["previous"]["DetectionStrings"] == ["a.lan", "b.lan"]


def redirection_world(w, ider=False, sol=False, kvm=3):
    w.instances["AMT_RedirectionService"] = {"EnabledState": {(False, False): "32768", (True, False): "32769",
                                                              (False, True): "32770", (True, True): "32771"}[(ider, sol)]}
    w.instances["CIM_KVMRedirectionSAP"] = {"EnabledState": str(kvm)}
    w.handlers[("AMT_RedirectionService", "RequestStateChange")] = lambda c: (
        w.instances["AMT_RedirectionService"].update({"EnabledState": c.fields["RequestedState"]}) or {})
    w.handlers[("CIM_KVMRedirectionSAP", "RequestStateChange")] = lambda c: (
        w.instances["CIM_KVMRedirectionSAP"].update({"EnabledState": c.fields["RequestedState"]}) or {})


@pytest.mark.parametrize("start,change,code", [
    ((False, False), {"ider_enabled": True}, "32769"), ((False, False), {"sol_enabled": True}, "32770"),
    ((False, False), {"ider_enabled": True, "sol_enabled": True}, "32771"),
    ((True, True), {"sol_enabled": False}, "32769"), ((True, True), {"ider_enabled": False, "sol_enabled": False}, "32768")])
def test_configure_features_requests_the_matching_redirection_state(wire, start, change, code):
    redirection_world(wire, *start)
    out = amt_write.configure("features", change, confirmed=True)
    rsc = [c for c in wire.calls if c.method == "RequestStateChange"]
    assert [c.fields["RequestedState"] for c in rsc] == [code]
    assert rsc[0].action == "http://intel.com/wbem/wscim/1/amt-schema/1/AMT_RedirectionService/RequestStateChange"
    assert out["readback"] == change and set(out["previous"]) == set(change)


def test_configure_features_kvm_uses_the_kvm_sap_and_a_no_op_sends_nothing(wire):
    redirection_world(wire, kvm=3)
    out = amt_write.configure("features", {"kvm_enabled": True}, confirmed=True)
    kvm = [c for c in wire.calls if c.cls == "CIM_KVMRedirectionSAP" and c.method]
    assert [c.fields["RequestedState"] for c in kvm] == ["2"] and out["readback"] == {"kvm_enabled": True}
    wire.calls.clear()
    amt_write.configure("features", {"kvm_enabled": True}, confirmed=True)
    assert not [c for c in wire.calls if c.op == "invoke"], "already in the requested state: no write"


def test_configure_features_readback_mismatch_raises(wire):
    redirection_world(wire)
    wire.handlers[("AMT_RedirectionService", "RequestStateChange")] = lambda c: {}   # device ignores it
    with pytest.raises(amt_wsman.WsmanError, match="configure_readback_mismatch:features:ider_enabled"):
        amt_write.configure("features", {"ider_enabled": True}, confirmed=True)


def users_world(w, users):
    """``users``: {username: handle}; the device enumerates, reads and mutates this table."""
    w.instances["AMT_GeneralSettings"] = general_instance()
    w.handlers[("AMT_AuthorizationService", "EnumerateUserAclEntries")] = lambda c: {
        "TotalCount": str(len(users)), "Handles": list(users.values())}
    w.handlers[("AMT_AuthorizationService", "GetUserAclEntryEx")] = lambda c: {
        "DigestUsername": next(n for n, h in users.items() if str(h) == c.fields["Handle"])}
    w.handlers[("AMT_AuthorizationService", "AddUserAclEntryEx")] = lambda c: (
        users.update({c.fields["DigestUsername"]: 7}) or {"Handle": "7"})
    w.handlers[("AMT_AuthorizationService", "RemoveUserAclEntry")] = lambda c: (
        users.pop(next(n for n, h in users.items() if str(h) == c.fields["Handle"])) and {})
    return users


def test_configure_users_add_reads_the_password_from_the_vault_and_sends_only_its_digest(wire):
    users = users_world(wire, {"admin": 1})
    out = amt_write.configure("users", {"action": "add", "username": "bob", "access_permission": 2, "realms": [3, 4]},
                              confirmed=True)
    add = next(c for c in wire.calls if c.method == "AddUserAclEntryEx")
    expected = base64.b64encode(hashlib.md5(f"bob:Digest:ABC123:{USER_PW}".encode()).digest()).decode()
    assert add.fields == {"DigestUsername": "bob", "AccessPermission": "2", "Realms": ["3", "4"], "DigestPassword": expected}
    assert "my-server-1-amt-user-bob" in VAULT_READS and "bob" in users
    assert USER_PW not in wire.all_xml()
    assert out["readback"] == {"present": True}
    assert_clean(out)


def test_configure_users_remove_looks_up_the_handle_then_verifies_absence(wire):
    users = users_world(wire, {"admin": 1, "bob": 7})
    out = amt_write.configure("users", {"action": "remove", "username": "bob"}, confirmed=True)
    rm = next(c for c in wire.calls if c.method == "RemoveUserAclEntry")
    assert rm.fields == {"Handle": "7"} and "bob" not in users and out["readback"] == {"present": False}


@pytest.mark.parametrize("username", ["admin", "Admin", "ADMIN", "", "a b", "x" * 17, "bob;rm", 5])
def test_configure_users_never_touches_admin_or_an_invalid_name(wire, username):
    users_world(wire, {"admin": 1})
    with pytest.raises(ValueError):
        amt_write.configure("users", {"action": "remove", "username": username}, confirmed=True)
    assert_nothing_sent(wire)


@pytest.mark.parametrize("changes", [
    {"action": "add", "username": "bob"},
    {"action": "add", "username": "bob", "access_permission": 3, "realms": [1]},
    {"action": "add", "username": "bob", "access_permission": 1, "realms": []},
    {"action": "add", "username": "bob", "access_permission": 1, "realms": [99]},
    {"action": "add", "username": "bob", "access_permission": 1, "realms": [1], "password": "x"},
    {"action": "add", "username": "bob", "access_permission": 1, "realms": [1], "DigestPassword": "x"},
    {"action": "drop", "username": "bob"}])
def test_configure_users_validates_before_any_io_and_accepts_no_password(wire, changes):
    with pytest.raises(ValueError):
        amt_write.configure("users", changes, confirmed=True)
    assert_nothing_sent(wire)


def test_configure_users_add_for_an_existing_name_and_remove_for_a_missing_one_raise(wire):
    users_world(wire, {"admin": 1, "bob": 7})
    with pytest.raises(ValueError, match="users_user_exists"):
        amt_write.configure("users", {"action": "add", "username": "bob", "access_permission": 2, "realms": [3]},
                            confirmed=True)
    with pytest.raises(ValueError, match="users_no_such_user"):
        amt_write.configure("users", {"action": "remove", "username": "carol"}, confirmed=True)


def test_configure_unpinned_device_is_refused_before_the_vault(wire, monkeypatch):
    unpin(monkeypatch)
    with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
        amt_write.configure("network", {"HostName": "x"}, confirmed=True)
    assert_nothing_sent(wire)


# --- amt_wsman_invoke -------------------------------------------------------------------

def test_each_operation_emits_its_exact_action(wire):
    amt_write.wsman_invoke("put", "AMT_Foo", fields={"A": "1"}, selectors={"InstanceID": "i"}, confirmed=True)
    amt_write.wsman_invoke("create", "AMT_Foo", fields={"A": "1"}, confirmed=True)
    amt_write.wsman_invoke("delete", "AMT_Foo", selectors={"InstanceID": "i"}, confirmed=True)
    out = amt_write.wsman_invoke("invoke", "CIM_PowerManagementService", method="RequestPowerStateChange",
                                 fields={"PowerState": 12}, confirmed=True)
    assert [c.action for c in wire.calls] == [
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put", "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
        "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete", CIM + "CIM_PowerManagementService/RequestPowerStateChange"]
    assert wire.calls[3].fields == {"PowerState": "12"} and out["result"]["ReturnValue"] == "0"
    assert out["operation"] == "invoke" and out["method"] == "RequestPowerStateChange"


def test_a_reference_parameter_can_be_supplied(wire):
    amt_write.wsman_invoke("invoke", "CIM_BootService", method="SetBootConfigRole", confirmed=True, fields={
        "BootConfigSetting": {"epr": {"class": "CIM_BootConfigSetting", "selectors": {"InstanceID": "x"}}}, "Role": 1})
    assert wire.calls[0].fields["BootConfigSetting"]["epr"]["selectors"] == {"InstanceID": "x"}


@pytest.mark.parametrize("name", ["Password", "RFBPassword", "DigestPassword", "passphrase", "Secret", "PSK", "PrivateKey"])
def test_credential_named_fields_are_refused_by_the_general_primitive(wire, name):
    for op in ("put", "create", "invoke"):
        with pytest.raises(ValueError, match="secret_field_refused"):
            amt_write.wsman_invoke(op, "AMT_Foo", method="Do" if op == "invoke" else None,
                                   fields={name: "x"}, confirmed=True)
    assert_nothing_sent(wire)


@pytest.mark.parametrize("kwargs,why", [
    (dict(operation="drop", class_name="AMT_Foo"), "unknown_operation"),
    (dict(operation="put", class_name="Foo"), "invalid_class_name"),
    (dict(operation="put", class_name="AMT_Foo/../x"), "invalid_class_name"),
    (dict(operation="invoke", class_name="AMT_Foo"), "invoke_needs_method"),
    (dict(operation="put", class_name="AMT_Foo", method="Do"), "method_only_valid_for_invoke"),
    (dict(operation="delete", class_name="AMT_Foo"), "delete_takes_selectors_only"),
    (dict(operation="delete", class_name="AMT_Foo", selectors={"I": "x"}, fields={"A": "1"}), "delete_takes_selectors_only"),
    (dict(operation="put", class_name="AMT_Foo", fields={"A": {"nested": 1}}), "unsupported_nested_field"),
    (dict(operation="put", class_name="AMT_Foo", fields={"A": {"epr": {"class": "CIM_X"}}}), "unsupported_nested_field"),
    (dict(operation="put", class_name="AMT_Foo", fields={"bad name": "1"}), "invalid_field_name"),
])
def test_malformed_requests_are_refused_before_any_io(wire, kwargs, why):
    with pytest.raises(ValueError, match=why):
        amt_write.wsman_invoke(confirmed=True, **kwargs)
    assert_nothing_sent(wire)


def test_a_device_fault_and_a_nonzero_return_value_raise(wire):
    wire.return_values[("CIM_PowerManagementService", "RequestPowerStateChange")] = "2"
    with pytest.raises(amt_wsman.WsmanError, match="wsman_return_value"):
        amt_write.wsman_invoke("invoke", "CIM_PowerManagementService", method="RequestPowerStateChange", confirmed=True)
    wire.faults[("put", "AMT_Foo")] = "nope"
    with pytest.raises(amt_wsman.WsmanFault):
        amt_write.wsman_invoke("put", "AMT_Foo", fields={"A": "1"}, confirmed=True)


def test_the_reply_is_returned_with_password_like_fields_redacted(wire):
    wire.echo_extra["AMT_Foo"] = {"AdminPassword": DEVICE_SECRET, "Visible": "ok"}
    out = amt_write.wsman_invoke("put", "AMT_Foo", fields={"A": "1"}, confirmed=True)
    assert out["result"]["AdminPassword"] == "<redacted>" and out["result"]["Visible"] == "ok"
    assert_clean(out)


def test_wsman_invoke_unpinned_device_is_refused(wire, monkeypatch):
    unpin(monkeypatch)
    with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
        amt_write.wsman_invoke("put", "AMT_Foo", fields={"A": "1"}, confirmed=True)
    assert_nothing_sent(wire)


# --- cross-cutting ----------------------------------------------------------------------

def test_the_registered_schema_matches_the_vocabularies():
    tools = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}
    props = lambda n: tools[n].inputSchema["properties"]   # noqa: E731
    assert props("amt_power")["action"]["enum"] == list(amt_write.POWER_ACTIONS)
    assert props("amt_power")["action"]["default"] == "restart"
    assert props("amt_set_next_boot")["target"]["enum"] == list(amt_write.BOOT_TARGETS)
    assert set(props("amt_set_next_boot")["options"]["anyOf"][0]["propertyNames"]["enum"]) == set(amt_write.BOOT_OPTIONS)
    assert tools["amt_console_input"].inputSchema["$defs"]["ConsoleAction"]["properties"]["macro"]["anyOf"][0]["enum"] \
        == list(amt_write.KEY_MACROS)
    assert props("amt_configure")["area"]["enum"] == ["network", "internet", "security", "users", "kvm", "features"]
    assert set(props("amt_wsman_invoke")["operation"]["enum"]) == {"put", "create", "delete", "invoke"}
    for name in SYNC_CALLS:
        t = tools[name]
        assert t.annotations.readOnlyHint is False and "confirmed" in t.inputSchema["properties"]


def test_every_write_tool_description_states_the_guard_and_the_pin():
    tools = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}
    for name in SYNC_CALLS:
        d = tools[name].description
        assert "confirmed=true" in d and "TLS leaf" in d and len(d) <= 2048, name


def test_the_write_tools_are_gated_over_http_and_refuse_unconfirmed_with_a_tool_error(wire):
    with _client(amt_server.register_tools(amt_server.build_server())) as c:
        status, msg = _rpc(c, "tools/call", {"name": "amt_power", "arguments": {}}, None)
        assert status == 200 and msg["result"]["isError"] is True
        assert "mcp-admin-token" in msg["result"]["content"][0]["text"]
        status, msg = _rpc(c, "tools/call", {"name": "amt_power", "arguments": {"action": "hard_reset"}}, TOKEN)
        res = msg["result"]
        assert res["isError"] is True and "confirmation_required" in res["content"][0]["text"]
        assert "WITHOUT asking the host OS" in res["content"][0]["text"]
        status, msg = _rpc(c, "tools/call", {"name": "amt_power", "arguments": {"action": "reset_the_world", "confirmed": True}}, TOKEN)
        assert msg["result"]["isError"] is True
    assert wire.calls == [] and VAULT_READS == []


def test_no_secret_reaches_any_result_argument_or_error_across_the_tools(wire, images):
    make_image(images, "boot.iso", 512)
    wire.instances["AMT_GeneralSettings"] = general_instance()
    wire.instances["IPS_KVMRedirectionSettingData"] = kvm_instance()
    outputs = [
        amt_write.power(confirmed=True),
        amt_write.set_next_boot("bios_setup", confirmed=True),
        amt_write.console_input([{"kind": "text", "text": "abc"}], confirmed=True),
        amt_write.sol("x", confirmed=True),
        amt_write.ider("mount", iso_path="boot.iso", confirmed=True),
        amt_write.ider("status"),
        amt_write.configure("network", {"HostName": "h"}, confirmed=True),
        amt_write.configure("kvm", {"Is5900PortEnabled": True}, confirmed=True),
        amt_write.wsman_invoke("put", "AMT_Foo", fields={"A": "1"}, confirmed=True),
        amt_write.ider("unmount", confirmed=True),
    ]
    assert_clean(*outputs)
    errors = []
    for fn in (lambda: amt_write.configure("kvm", {"RFBPassword": "x"}, confirmed=True),
               lambda: amt_write.wsman_invoke("put", "AMT_Foo", fields={"Password": "x"}, confirmed=True),
               lambda: amt_write.set_next_boot("usb", confirmed=True),
               lambda: amt_write.power("hard_reset")):
        with pytest.raises(Exception) as ex:
            fn()
        errors.append(repr(ex.value))
    assert_clean(*errors)
    # the AMT admin password never travels in a request BODY (it is only a Digest input in the transport)
    assert AMT_PW not in wire.all_xml() and USER_PW not in wire.all_xml()
    assert RFB_PW in wire.all_xml(), "positive control: the vaulted RFB value does reach the device in the kvm Put"


# --- review fixes: clean boot baseline, power after-the-fact, strict confirmed, ider, configure --

DIRTY_BOOT = {   # every option an earlier request could have left armed, as the device's Get shows it
    "SecureErase": "true", "EnforceSecureBoot": "true", "LockPowerButton": "true", "LockResetButton": "true",
    "LockSleepButton": "true", "LockKeyboard": "true", "UserPasswordBypass": "true", "FirmwareVerbosity": "3",
    "BootMediaIndex": "7", "ForcedProgressEvents": "true", "ReflashBIOS": "true", "ConfigurationDataReset": "true",
    "BIOSPause": "true", "UseSafeMode": "true", "UseSOL": "true", "UseIDER": "true", "BIOSSetup": "true",
    "IDERBootDevice": "1"}
SAFE_BOOT = {name: ("0" if name in ("FirmwareVerbosity", "BootMediaIndex", "IDERBootDevice") else "false")
             for name in DIRTY_BOOT}


@pytest.mark.parametrize("target", ["pxe", "hard_disk", "diagnostic", "clear"])
def test_every_put_starts_from_the_safe_baseline_whatever_the_device_still_shows(wire, target):
    wire.instances[BOOT_SET].update(DIRTY_BOOT)
    out = amt_write.set_next_boot(target, confirmed=True)
    assert {k: put_of(wire).fields[k] for k in SAFE_BOOT} == SAFE_BOOT, "no earlier option rides along"
    assert {k: out["readback"][k] for k in SAFE_BOOT} == {k: (False if v == "false" else int(v))
                                                           for k, v in SAFE_BOOT.items()}


@pytest.mark.parametrize("target,flags", [("bios_setup", {"BIOSSetup": "true"}),
                                          ("cd_ider", {"UseIDER": "true", "IDERBootDevice": "1"}),
                                          ("floppy_ider", {"UseIDER": "true", "IDERBootDevice": "0"})])
def test_only_the_targets_own_flags_differ_from_the_baseline(wire, target, flags):
    wire.instances[BOOT_SET].update(DIRTY_BOOT)
    amt_write.set_next_boot(target, confirmed=True)
    assert {k: put_of(wire).fields[k] for k in SAFE_BOOT} == {**SAFE_BOOT, **flags}


def test_a_secure_erase_set_by_one_call_is_gone_after_clear_and_a_later_pxe_does_not_rearm_it(wire):
    amt_write.set_next_boot("pxe", {"secure_erase": True, "lock_power_button": True}, confirmed=True)
    puts = lambda: [c for c in wire.calls if c.op == "put"]   # noqa: E731
    assert puts()[-1].fields["SecureErase"] == "true" and wire.instances[BOOT_SET]["SecureErase"] == "true"
    out = amt_write.set_next_boot("clear", confirmed=True)
    assert puts()[-1].fields["SecureErase"] == "false" and puts()[-1].fields["LockPowerButton"] == "false"
    assert wire.instances[BOOT_SET]["SecureErase"] == "false", "the device state after clear is disarmed"
    assert out["readback"]["SecureErase"] is False and out["readback"]["LockPowerButton"] is False
    amt_write.set_next_boot("pxe", confirmed=True)
    assert puts()[-1].fields["SecureErase"] == "false" and puts()[-1].fields["LockPowerButton"] == "false"


def test_clear_neutralises_the_request_and_never_sends_the_arming_role(wire):
    wire.instances[BOOT_SET].update(DIRTY_BOOT)
    out = amt_write.set_next_boot("clear", confirmed=True)
    invokes = [c for c in wire.calls if c.op == "invoke"]
    assert [c.method for c in invokes] == ["ChangeBootOrder"] and invokes[0].fields == {}, "no boot source"
    assert not [c for c in wire.calls if c.method == "SetBootConfigRole"], "clear must never arm Role=1"
    assert out["steps"] == ["clear_boot_order", "put"] and "neutralised" in out["note"]


def test_options_do_not_carry_over_from_one_call_to_the_next(wire):
    amt_write.set_next_boot("pxe", {"lock_keyboard": True, "firmware_verbosity": 2}, confirmed=True)
    assert wire.instances[BOOT_SET]["LockKeyboard"] == "true"
    amt_write.set_next_boot("pxe", {"use_sol": True}, confirmed=True)
    f = [c for c in wire.calls if c.op == "put"][-1].fields
    assert (f["UseSOL"], f["LockKeyboard"], f["FirmwareVerbosity"]) == ("true", "false", "0")


def test_a_baseline_field_the_device_does_not_reset_fails_the_readback(wire):
    wire.instances[BOOT_SET].update({"SecureErase": "true"})
    wire.ignore_put.add(BOOT_SET)
    with pytest.raises(amt_wsman.WsmanError, match="boot_readback_mismatch:.*SecureErase"):
        amt_write.set_next_boot("clear", confirmed=True)


def test_the_lock_buttons_are_destructive_options_named_in_the_confirmation(wire):
    assert {"lock_power_button", "lock_reset_button"} <= amt_write.DESTRUCTIVE_BOOT_OPTIONS
    for opt in ("lock_power_button", "lock_reset_button"):
        with pytest.raises(amt_write.ConfirmationRequired, match=opt):
            amt_write.set_next_boot("pxe", {opt: True})
    with pytest.raises(amt_write.ConfirmationRequired) as ex:
        amt_write.set_next_boot("pxe", {"lock_power_button": False})
    assert "lock_power_button" not in str(ex.value), "a false flag requests nothing"


def test_clear_names_that_it_resets_every_option(wire):
    with pytest.raises(amt_write.ConfirmationRequired, match="safe default"):
        amt_write.set_next_boot("clear")


# -- amt_power: a readback problem after an accepted request is not a failed tool --

def test_power_an_invoke_level_fault_is_a_failure_and_reads_nothing_back(wire):
    wire.faults[("invoke", PM, "RequestPowerStateChange")] = "denied"
    with pytest.raises(amt_wsman.WsmanFault, match="denied"):
        amt_write.power(confirmed=True)
    assert [c.op for c in wire.calls] == ["get", "invoke"], "the availability read, then nothing back"


def test_power_an_invoke_level_transport_error_is_a_failure(wire, monkeypatch):
    def boom(device, xml, password=None):
        raise amt_wsman.WsmanError("wsman_unreachable:TimeoutError")
    monkeypatch.setattr(amt_wsman, "transport", boom)
    with pytest.raises(amt_wsman.WsmanError, match="wsman_unreachable"):
        amt_write.power(confirmed=True)


@pytest.mark.parametrize("failure", [amt_wsman.WsmanError("wsman_unreachable:TimeoutError"),
                                     amt_wsman.WsmanFault("wsman_fault:no such class")])
def test_power_a_readback_that_fails_after_the_accepted_request_is_not_an_error(wire, monkeypatch, failure):
    real = wire.transport

    def transport(device, xml, password=None):
        if wirelib.parse_request(xml).op == "get":
            raise failure
        return real(device, xml, password)
    monkeypatch.setattr(amt_wsman, "transport", transport)
    out = amt_write.power(confirmed=True)                    # must not raise: a retry would reboot twice
    assert out["applied"] is True and out["requested_state"] == 14 and out["return_value"] == 0
    assert out["readback"] == "unavailable" and out["readback_error"] == type(failure).__name__
    assert "power_state_after" not in out
    assert str(failure) not in json.dumps(out), "the error TYPE only"
    assert len(power_calls(wire)) == 1, "the request went exactly once"


def test_power_a_good_readback_is_marked_ok(wire):
    out = amt_write.power("power_on", confirmed=True)
    assert out["applied"] is True and out["readback"] == "ok" and out["power_state_after"] == "on"


def test_power_a_reply_without_a_return_value_is_unknown_not_success(wire):
    wire.return_values[(PM, "RequestPowerStateChange")] = None      # rendered as xsi:nil
    out = amt_write.power(confirmed=True)
    assert out["applied"] == "unknown" and out["return_value"] == "unknown" and "unknown" in out["note"]
    assert len(power_calls(wire)) == 1


def test_a_boot_step_with_no_return_value_fails_the_sequence_instead_of_assuming_success(wire):
    wire.return_values[("CIM_BootService", "SetBootConfigRole")] = None
    with pytest.raises(amt_wsman.WsmanError, match="boot_sequence_failed:completed=clear_boot_order,put:.*"
                                                    "wsman_return_value_missing"):
        amt_write.set_next_boot("pxe", confirmed=True)


def test_wsman_invoke_reports_a_missing_return_value_as_unknown(wire):
    wire.return_values[(PM, "RequestPowerStateChange")] = None
    out = amt_write.wsman_invoke("invoke", PM, method="RequestPowerStateChange", fields={"PowerState": 14},
                                 confirmed=True)
    assert out["return_value"] == "unknown" and "unknown" in out["note"]
    del wire.return_values[(PM, "RequestPowerStateChange")]
    ok = amt_write.wsman_invoke("invoke", PM, method="RequestPowerStateChange", fields={"PowerState": 14},
                                confirmed=True)
    assert "return_value" not in ok and ok["result"]["ReturnValue"] == "0"


# -- confirmed is a STRICT boolean over HTTP --

HTTP_ARGS = {
    "amt_power": {}, "amt_set_next_boot": {"target": "pxe"},
    "amt_console_input": {"actions": [{"kind": "key", "key": "enter"}]}, "amt_sol": {"text": "x"},
    "amt_ider": {"action": "mount", "iso_path": "x.iso"},
    "amt_configure": {"area": "network", "changes": {"HostName": "box"}},
    "amt_wsman_invoke": {"operation": "invoke", "class_name": PM, "method": "RequestPowerStateChange",
                         "fields": {"PowerState": 12}},
    "amt_remote_logon": {}, "amt_remote_logoff": {},
}


def http_call(name, arguments):
    with _client(amt_server.register_tools(amt_server.build_server())) as c:
        status, msg = _rpc(c, "tools/call", {"name": name, "arguments": arguments}, TOKEN)
    assert status == 200
    return msg["result"]


@pytest.mark.parametrize("confirmed", ["true", "True", "yes", "1", 1, "false", 0])
@pytest.mark.parametrize("name", sorted(HTTP_ARGS))
def test_over_http_a_non_boolean_confirmed_is_rejected_for_every_destructive_tool(wire, name, confirmed):
    res = http_call(name, {**HTTP_ARGS[name], "confirmed": confirmed})
    text = res["content"][0]["text"]
    assert res["isError"] is True and "confirmed" in text
    assert "confirmation_required" not in text, "the schema rejects it; the guard never has to"
    assert_nothing_sent(wire)


@pytest.mark.parametrize("name", sorted(HTTP_ARGS))
@pytest.mark.parametrize("arguments", [{}, {"confirmed": False}])
def test_over_http_omitted_or_false_confirmed_refuses_naming_the_consequence(wire, name, arguments):
    res = http_call(name, {**HTTP_ARGS[name], **arguments})
    assert res["isError"] is True and "confirmation_required" in res["content"][0]["text"]
    assert_nothing_sent(wire)


def test_over_http_the_json_boolean_true_proceeds(wire):
    res = http_call("amt_power", {"action": "power_on", "confirmed": True})
    assert not res.get("isError"), res
    body = json.loads(res["content"][0]["text"])
    assert body["applied"] is True and body["requested_state"] == 2
    assert [c.fields["PowerState"] for c in power_calls(wire)] == ["2"]


def test_the_confirmed_schema_is_a_boolean_that_defaults_to_false_on_every_destructive_tool():
    tools = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}
    for name in HTTP_ARGS:
        prop = tools[name].inputSchema["properties"]["confirmed"]
        assert prop["type"] == "boolean" and prop["default"] is False, name


# -- destructive hints and descriptions --

def test_every_write_tool_is_marked_destructive():
    tools = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}
    for name in HTTP_ARGS:
        assert tools[name].annotations.destructiveHint is True, name
        assert tools[name].annotations.readOnlyHint is False, name


def test_descriptions_carry_the_warnings_the_review_asked_for():
    d = {t.name: t.description for t in asyncio.run(amt_server.mcp.list_tools())}
    assert "RESETS the host" in d["amt_ider"] and "no time limit" in d["amt_ider"]
    assert "Unprovision" in d["amt_wsman_invoke"] and "FULL instance" in d["amt_wsman_invoke"]
    for phrase in ("disables user consent", "5900", "non-TLS"):
        assert phrase in d["amt_configure"], phrase
    assert "safe default" in d["amt_set_next_boot"] and "lock_power_button" in d["amt_set_next_boot"]


@pytest.mark.parametrize("area,changes,phrase", [
    ("kvm", {"OptInPolicy": False}, "OFF user consent"), ("kvm", {"Is5900PortEnabled": True}, "port 5900"),
    ("security", {"AcceptNonSecureConnections": True}, "non-TLS")])
def test_configure_names_a_risky_change_in_the_confirmation(wire, area, changes, phrase):
    with pytest.raises(amt_write.ConfirmationRequired, match=phrase):
        amt_write.configure(area, changes)
    with pytest.raises(amt_write.ConfirmationRequired) as ex:
        amt_write.configure("kvm", {"SessionTimeout": 5})
    assert "THIS REQUEST" not in str(ex.value)


# -- amt_ider: ider unmount race --

def test_unmount_while_the_session_thread_is_still_live_reports_it_held_not_unmounted(wire, images, monkeypatch):
    make_image(images, "boot.iso", 512)
    release = threading.Event()
    monkeypatch.setattr(FakeIder, "serve", lambda self, stop, poll=0.5: release.wait(10))   # ignores stop
    monkeypatch.setattr(amt_write, "IDER_UNMOUNT_JOIN_SECONDS", 0.05)
    amt_write.ider("mount", iso_path="boot.iso", confirmed=True)
    with pytest.raises(amt_kvm.AmtError, match="ider_unmount_timeout.*STILL HELD"):
        amt_write.ider("unmount", confirmed=True)
    st = amt_write.ider("status")
    assert st["mounted"] is True, "status must not say unmounted while the thread holds the session"
    with pytest.raises(ValueError, match="ider_already_mounted"):
        amt_write.ider("mount", iso_path="boot.iso", confirmed=True)
    assert len(FakeIder.instances) == 1, "no second session while the first is held"
    release.set()
    done = amt_write.ider("unmount", confirmed=True)       # now it stops; the record was never lost
    assert done["mounted"] is False and amt_write.ider("status")["mounted"] is False


def test_a_graceful_or_now_mount_says_it_resets_the_host_and_next_boot_does_not():
    for start in ("graceful", "now"):
        with pytest.raises(amt_write.ConfirmationRequired, match="RESETS the host immediately"):
            amt_write.ider("mount", iso_path="x.iso", start=start)
    with pytest.raises(amt_write.ConfirmationRequired) as ex:
        amt_write.ider("mount", iso_path="x.iso", start="next_boot")
    assert "RESETS" not in str(ex.value) and "no time limit" in str(ex.value) and "KVM keeps working alongside it" in str(ex.value)


# -- console pointer clamp --

def test_a_click_at_the_far_edge_lands_on_the_last_pixel_not_off_screen(wire):
    amt_write.console_input([{"kind": "click", "x": 1.0, "y": 1.0}, {"kind": "click", "x": 0.0, "y": 0.0}],
                            confirmed=True)
    clicks = [e for e in LOG if e[0] == "click"]
    assert clicks == [("click", 1279, 799, "left"), ("click", 0, 0, "left")]
    assert amt_tools._at(1280, 800, (1.0, 1.0)) == (1279, 799)


# --- AMT's own list of the power states it accepts now ------------------------------------

def test_power_refuses_by_name_a_state_amt_does_not_offer_and_sends_nothing(wire):
    # Live 2026-10-19 at the Debian GRUB menu: AMT offered only 10 and 11, and refused 12 and 6
    # with a bare ReturnValue 2.
    wire.instances["CIM_AssociatedPowerManagementService"] = {
        "PowerState": "2", "AvailableRequestedPowerStates": ["10", "11"]}
    with pytest.raises(ValueError, match="power_state_not_available.*offers hard_reset, nmi.*Nothing was sent"):
        amt_write.power("shutdown", confirmed=True)
    assert power_calls(wire) == []


def test_power_sends_a_state_amt_offers(wire):
    wire.instances["CIM_AssociatedPowerManagementService"] = {
        "PowerState": "2", "AvailableRequestedPowerStates": ["10", "8", "5", "11", "4", "7", "14", "12"]}
    amt_write.power("shutdown", confirmed=True)
    assert [c.fields["PowerState"] for c in power_calls(wire)] == ["12"]


def test_offered_actions_accept_one_value_or_a_list_and_none_means_unknown():
    assert amt_write.offered_power_actions("2") == ["power_on"]
    assert amt_write.offered_power_actions(["10", "11"]) == ["hard_reset", "nmi"]
    assert amt_write.offered_power_actions(None) is None
