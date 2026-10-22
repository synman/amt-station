"""The fleet and server status backend (packet C2): the schedule and its stagger, the stop-on-401 rule, the session views,
the holder of a session, the coverage a read reports, past captures and the routes. Every amt-mcp answer is scripted
(console_fakes.FakeAmt); the clock is a hand-turned fake, so nothing here waits for an interval."""
import json
import re
import stat
import time

import pytest

import fleet
import mcp_client
from console_fakes import BEARER, Authenticator, Console, enroll_first_passkey

KEY = "my-server-1"
LEAF = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"


class Clock:
    def __init__(self):
        self.t = 1_760_000_000.0

    def __call__(self):
        return self.t

    def advance(self, seconds):
        self.t += seconds


def tool_error(text):
    return {"content": [{"type": "text", "text": text}], "isError": True}


def device(key=KEY, leaf=LEAF, pinned=True, ip="10.0.0.26"):
    return {"key": key, "amt_ip": ip, "wsman_port": 16993, "kvm_port": 16995, "amt_vault_key": f"{key}-amt", "host_vault_key": None,
            "tls_leaf_sha256": leaf if pinned else None, "tls_leaf_observed_prefix": leaf[:16] if pinned else None, "pinned": pinned}


STATUS = {"device": KEY, "power": {"state": "on", "code": 2},
          "amt": {"version": "19.0.5", "build_number": "1234", "sku": "16392", "firmware": {"AMT": "19.0.5"}},
          "provisioning": {"mode": "client", "mode_code": 4, "state": "post_provisioning", "state_code": 2,
                           "control_mode": "admin_control_mode", "control_mode_code": 2, "zero_touch_enabled": False},
          "redirection": {"listener_enabled": True, "enabled_state_code": 32771, "sol_enabled": True, "ider_enabled": True,
                          "kvm": {"state": "enabled", "state_code": 2, "enabled": True, "port_5900_enabled": False, "session_timeout": 3}},
          "user_consent": {"required_for": "none", "required_code": 0, "state": "not_started", "state_code": 0, "can_modify_policy": True},
          "next_boot": {"BIOSSetup": False, "BootMediaIndex": 0}, "unavailable": [], "truncated": []}


@pytest.fixture()
def fc(tmp_path, fake_amt):
    """A console whose fleet is driven by hand: no poller thread, a fake clock, one registered server, all views idle."""
    console = Console(tmp_path, fake_amt, fleet_poll=False)
    clock = Clock()
    console.app.fleet.now = clock
    console.clock = clock
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device()]}
    fake_amt.results["amt_status"] = lambda a: STATUS
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_serial_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
    fake_amt.results["amt_identities"] = lambda a: {"vault_entries": 1, "identities": [
        {"name": f"{a['device']}-amt", "status": "present", "used_by": [], "source": "main", "updated_at": "2026-10-01"}]}
    yield console
    console.close()


@pytest.fixture()
def me(fc):
    enroll_first_passkey(fc, Authenticator(fc.app.cfg.rp_id, fc.origin))
    return fc


def calls(fake, tool, key=None):
    return [a for t, a, _ in fake.calls if t == tool and (key is None or a.get("device") == key)]


def settle(fc, n=1):
    """Run the schedule until every due server has been read (n servers, one per step)."""
    got = []
    for _ in range(n):
        got.append(fc.app.fleet.step())
    return got


# -- one read: the status and the three session views, every call naming its device -------------------------------------

def test_one_read_is_the_status_and_the_three_session_views(fc, fake_amt):
    assert settle(fc) == [KEY]
    assert [(t, a) for t, a, _ in fake_amt.calls] == [
        ("amt_devices", {"action": "list"}), ("amt_status", {"device": KEY}), ("amt_mirror_link", {"device": KEY, "action": "status"}),
        ("amt_serial_link", {"device": KEY, "action": "status"}), ("amt_ider", {"device": KEY, "action": "status"})]
    assert all(auth == f"Bearer {BEARER}" for _, _, auth in fake_amt.calls)       # the console's own bearer, nothing else
    e = fc.app.fleet.public(KEY)
    assert (e["state"], e["power"]["kind"], e["power"]["code"], e["version"], e["pin"]) == ("live", "on", 2, "19.0.5", "matches")
    assert e["sessions"]["kvm"] == {"holder": "free"} and e["sessions"]["ider"] == {"mounted": False}


@pytest.mark.parametrize("state,kind", [("on", "on"), ("sleep_light", "sleep"), ("sleep_deep", "sleep"), ("hibernate", "sleep"),
                                        ("off_hard", "off"), ("off_soft", "off"), ("something_new", "unknown")])
def test_power_states_map_to_the_pill_kinds(fc, fake_amt, state, kind):
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "power": {"state": state, "code": 9}}
    settle(fc)
    assert fc.app.fleet.public(KEY)["power"]["kind"] == kind


def test_an_unreadable_status_is_an_error_not_a_blank_card(fc, fake_amt):
    fake_amt.results["amt_status"] = lambda a: {"surprise": True}
    settle(fc)
    e = fc.app.fleet.public(KEY)
    assert e["state"] == "unreachable" and "no readable power section" in e["error"]


def test_coverage_reaches_the_browser_as_the_tool_reported_it(me, fake_amt):
    """Immutable 19, backend half: unavailable classes, their reasons and truncated classes pass through; a read that
    reported none says none."""
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "unavailable": ["CIM_PhysicalMedia"], "truncated": ["CIM_Processor"],
                                                "unavailable_reasons": {"CIM_PhysicalMedia": "Unsupported (not exposed)"}}
    settle(me)
    st = me.get(f"/api/server/{KEY}").json()["server"]["status"]
    assert st["unavailable"] == ["CIM_PhysicalMedia"] and st["truncated"] == ["CIM_Processor"]
    assert st["unavailable_reasons"] == {"CIM_PhysicalMedia": "Unsupported (not exposed)"}
    fake_amt.results["amt_status"] = lambda a: STATUS
    me.clock.advance(31)
    settle(me)
    st = me.get(f"/api/server/{KEY}").json()["server"]["status"]
    assert st["unavailable"] == [] and st["truncated"] == []


def test_only_whitelisted_status_fields_are_passed_on(me, fake_amt):
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "surprise": "SURPRISE-VALUE", "amt": {**STATUS["amt"], "serial": "SERIAL-VALUE"},
                                                "next_boot": {"BIOSSetup": True, "nested": {"x": 1}}}
    settle(me)
    body = me.get(f"/api/server/{KEY}").text
    assert "SURPRISE-VALUE" not in body and "SERIAL-VALUE" not in body and '"nested"' not in body
    assert json.loads(body)["server"]["status"]["next_boot"] == {"BIOSSetup": True}


# -- the stagger ------------------------------------------------------------------------------------------------------

def test_n_servers_are_n_reads_spread_across_the_interval_never_a_burst(fc, fake_amt):
    keys = ["alpha", "bravo", "charlie"]
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device(k) for k in keys]}
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"]}
    assert fc.app.fleet.step() == "alpha" and fc.app.fleet.step() is None           # only the first is due at t0
    fc.clock.advance(10)
    assert fc.app.fleet.step() == "bravo" and fc.app.fleet.step() is None
    fc.clock.advance(10)
    assert fc.app.fleet.step() == "charlie" and fc.app.fleet.step() is None
    assert [a["device"] for a in calls(fake_amt, "amt_status")] == keys
    fc.clock.advance(10)                                                            # a full interval after the first read
    assert fc.app.fleet.step() == "alpha"
    assert len(calls(fake_amt, "amt_status")) == 4


def test_a_server_is_not_read_again_before_its_interval(fc, fake_amt):
    settle(fc)
    fc.clock.advance(29)
    assert fc.app.fleet.step() is None and len(calls(fake_amt, "amt_status")) == 1
    fc.clock.advance(2)
    assert fc.app.fleet.step() == KEY and len(calls(fake_amt, "amt_status")) == 2


# -- a transport error is not a refused credential ------------------------------------------------------------------

def test_a_transport_error_is_shown_verbatim_and_the_next_read_stays_scheduled(me, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("amt_status failed: connect timed out (10 s)")
    settle(me)
    e = me.get(f"/api/server/{KEY}").json()["server"]
    assert (e["state"], e["power"]["kind"], e["pin"]) == ("unreachable", "unreachable", "unchecked")
    assert "connect timed out (10 s)" in e["error"] and e["paused"] is None and e["next_in_s"] == 30
    assert e["sessions"] is not None                                               # amt-mcp itself answered: its session views are real
    me.clock.advance(31)
    assert me.app.fleet.step() == KEY and len(calls(fake_amt, "amt_status")) == 2  # still read on schedule


def test_a_failed_read_after_a_good_one_no_longer_vouches_for_the_pin(fc, fake_amt):
    settle(fc)
    assert fc.app.fleet.public(KEY)["pin"] == "matches"
    fake_amt.results["amt_status"] = lambda a: tool_error("amt_status failed: connect timed out (10 s)")
    fc.clock.advance(31)
    settle(fc)
    e = fc.app.fleet.public(KEY)
    assert e["state"] == "unreachable" and e["pin"] == "unchecked"


def test_amt_mcp_itself_unreachable_is_unreachable_with_no_session_views(fc, fake_amt):
    fake_amt.close()                                                               # nothing listens any more
    fc.app.fleet.refresh_devices()
    assert "amt_mcp_unreachable" in (fc.app.fleet.devices_error or "")
    # the list is unknown, so the earlier (empty) state stands and nothing was invented
    assert fc.app.fleet.snapshot()["servers"] == [] and fc.app.fleet.snapshot()["loaded"] is False


def test_amt_mcp_going_away_after_a_read_marks_the_server_unreachable(fc, fake_amt):
    settle(fc)
    real = fc.app.mcp.call

    def down(tool, arguments):
        raise mcp_client.McpError("amt_mcp_unreachable:ConnectionRefusedError")
    fc.app.mcp.call = down
    fc.clock.advance(31)
    fc.app.fleet.step()
    e = fc.app.fleet.public(KEY)
    assert e["state"] == "unreachable" and e["error"] == "amt_mcp_unreachable:ConnectionRefusedError"
    assert e["sessions"] is None and e["sessions_error"] == e["error"]
    assert e["status"] is not None                                                 # the last good values are kept, to be marked stale
    fc.app.mcp.call = real


# -- immutable 7: a refused credential pauses the server -------------------------------------------------------------

def test_a_401_pauses_the_server_and_no_further_status_call_is_made(fc, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("Error executing tool amt_status: wsman_auth_failed_401")
    settle(fc)
    e = fc.app.fleet.public(KEY)
    assert e["state"] == "paused" and e["paused"]["reason"] == "credential refused" and e["power"]["kind"] == "unknown"
    assert e["pin"] == "matches"                                                   # the 401 came over a TLS session whose leaf matched
    assert "wsman_auth_failed_401" in e["error"]
    assert not [c for c in fake_amt.calls if c[0] in ("amt_mirror_link", "amt_serial_link", "amt_ider")]   # the refused read itself went no further
    before = len(fake_amt.calls)
    for _ in range(3):                                                             # the next three refresh periods
        fc.clock.advance(31)
        assert fc.app.fleet.step() is None
    assert len(calls(fake_amt, "amt_status")) == 1
    assert not [c for c in fake_amt.calls[before:] if c[0] in ("amt_status", "amt_mirror_link", "amt_serial_link", "amt_ider")]


def test_a_401_seen_on_any_call_pauses_the_automatic_reads_too(me, fake_amt):
    """The account is the thing a second failed attempt endangers, whichever call made the first: a refused credential in
    an operator's own call stops the schedule's reads of that server as well."""
    settle(me)
    fake_amt.results["amt_screenshot"] = lambda a: tool_error("Error executing tool amt_screenshot: wsman_auth_failed_401")
    r = me.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": KEY}}).json()
    assert r["isError"] and "wsman_auth_failed_401" in r["text"]
    e = me.app.fleet.public(KEY)
    assert e["state"] == "paused" and e["paused"]["reason"] == "credential refused"
    for _ in range(3):
        me.clock.advance(31)
        assert me.app.fleet.step() is None
    assert len(calls(fake_amt, "amt_status")) == 1


def test_a_failing_device_list_is_not_retried_on_every_step(fc, fake_amt):
    fake_amt.results["amt_devices"] = lambda a: tool_error("devices file malformed")
    for _ in range(5):
        fc.app.fleet.step()
    assert len(calls(fake_amt, "amt_devices")) == 1
    fc.clock.advance(31)
    fc.app.fleet.step()
    assert len(calls(fake_amt, "amt_devices")) == 2


def test_a_server_removed_while_it_is_being_read_is_dropped_without_a_fault(fc, fake_amt):
    settle(fc)

    def gone(a):
        fake_amt.results["amt_devices"] = lambda b: {"source": "file", "devices": [device("other")]}
        fc.app.fleet.refresh_devices()                                           # the list changes under the read
        return STATUS
    fake_amt.results["amt_status"] = gone
    fc.clock.advance(31)
    fc.app.fleet.refresh(KEY)
    assert fc.app.fleet.public(KEY) is None and fc.app.fleet.public("other") is not None


def test_a_paused_server_does_not_stop_the_others_from_being_read(fc, fake_amt):
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device("alpha"), device("bravo")]}
    fake_amt.results["amt_status"] = lambda a: tool_error("wsman_auth_failed_401") if a["device"] == "alpha" else {**STATUS, "device": "bravo"}
    fc.app.fleet.step()
    fc.clock.advance(16)
    fc.app.fleet.step()
    for _ in range(3):
        fc.clock.advance(31)
        fc.app.fleet.step()
    assert len(calls(fake_amt, "amt_status", "alpha")) == 1 and len(calls(fake_amt, "amt_status", "bravo")) == 4


def test_refresh_all_leaves_a_paused_server_alone(me, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("wsman_auth_failed_401")
    settle(me)
    due_before = me.app.fleet.entries[KEY]["next_due"]
    me.clock.advance(5)
    assert me.post("/api/fleet/refresh", {}).json() == {"ok": True}
    assert me.app.fleet.entries[KEY]["next_due"] == due_before                      # not marked due: refresh-all skips it
    assert me.app.fleet.step() is None and len(calls(fake_amt, "amt_status")) == 1
    other = me.app.fleet
    other.entries[KEY]["state"], other.entries[KEY]["paused"] = "live", None         # control: a server that is not paused IS marked due
    assert me.post("/api/fleet/refresh", {}).json() == {"ok": True}
    assert me.app.fleet.entries[KEY]["next_due"] == me.clock()


def test_retry_once_is_one_attempt_and_stays_paused_when_refused_again(me, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("wsman_auth_failed_401")
    settle(me)
    r = me.post("/api/fleet/refresh", {"device": KEY}).json()
    assert r["ran"] is True and r["server"]["state"] == "paused"
    assert len(calls(fake_amt, "amt_status")) == 2                                 # exactly one more, not a loop
    me.clock.advance(120)
    assert me.app.fleet.step() is None and len(calls(fake_amt, "amt_status")) == 2


def test_retry_once_that_succeeds_resumes_the_schedule(me, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("wsman_auth_failed_401")
    settle(me)
    fake_amt.results["amt_status"] = lambda a: STATUS
    r = me.post("/api/fleet/refresh", {"device": KEY}).json()["server"]
    assert r["state"] == "live" and r["paused"] is None
    me.clock.advance(31)
    assert me.app.fleet.step() == KEY                                              # polling is back


def test_a_pin_mismatch_pauses_too_and_says_the_pin_differs(fc, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("tls_leaf_pin_mismatch")
    settle(fc)
    e = fc.app.fleet.public(KEY)
    assert (e["state"], e["pin"], e["paused"]["reason"]) == ("paused", "differs", "pin differs")
    fc.clock.advance(31)
    assert fc.app.fleet.step() is None and len(calls(fake_amt, "amt_status")) == 1


def test_a_re_pin_resumes_a_paused_server(fc, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("tls_leaf_pin_mismatch")
    settle(fc)
    assert fc.app.fleet.public(KEY)["state"] == "paused"
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device(leaf="b" * 64)]}
    fake_amt.results["amt_status"] = lambda a: STATUS
    fc.clock.advance(31)
    assert fc.app.fleet.step() == KEY
    assert fc.app.fleet.public(KEY)["state"] == "live"


def test_a_replaced_identity_resumes_a_paused_server(fc, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("wsman_auth_failed_401")
    settle(fc)
    fc.clock.advance(31)
    assert fc.app.fleet.step() is None and fc.app.fleet.public(KEY)["state"] == "paused"      # nothing changed: still paused
    fake_amt.results["amt_identities"] = lambda a: {"identities": [{"name": f"{KEY}-amt", "status": "present", "updated_at": "2026-10-21"}]}
    fake_amt.results["amt_status"] = lambda a: STATUS
    fc.clock.advance(31)
    assert fc.app.fleet.step() == KEY and fc.app.fleet.public(KEY)["state"] == "live"


def test_a_pause_with_no_identity_stamp_to_compare_never_resumes_on_a_later_one(fc, fake_amt):
    """The identity could not be read when the 401 came, so a stamp read later has nothing to differ from: the unchanged
    credential must not get a second automatic Digest attempt."""
    fake_amt.results["amt_status"] = lambda a: tool_error("Error executing tool amt_status: wsman_auth_failed_401")
    fake_amt.results["amt_identities"] = lambda a: tool_error("identities unavailable")
    settle(fc)
    assert fc.app.fleet.public(KEY)["state"] == "paused"
    fake_amt.results["amt_identities"] = lambda a: {"identities": [{"name": f"{KEY}-amt", "status": "present", "updated_at": "2026-10-01"}]}
    for _ in range(3):
        fc.clock.advance(31)
        assert fc.app.fleet.step() is None
    assert fc.app.fleet.public(KEY)["state"] == "paused" and len(calls(fake_amt, "amt_status")) == 1


def test_an_unpinned_server_is_an_error_that_is_not_a_pause(fc, fake_amt):
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device(pinned=False)]}
    fake_amt.results["amt_status"] = lambda a: tool_error("tls_leaf_unpinned_refused")
    settle(fc)
    e = fc.app.fleet.public(KEY)
    assert (e["state"], e["pin"], e["paused"]) == ("unreachable", "unpinned", None)


# -- the holder of a session (immutable 8) ----------------------------------------------------------------------------

MIRROR = {"device": KEY, "live": True, "error": None, "fps": 15, "frames": 400, "viewers": 2, "uptime_s": 14.0, "width": 1280, "height": 800,
          "in_flight": None, "recording": None, "recording_dir": "/data/recordings", "last_frame_age_s": 0.2,
          "urls": ["http://nas:8766/m/MIRRORVIEWTOKENMIRRORVIEWTOKEN12/"], "control_urls": ["http://nas:8766/m/MIRRORCTRLTOKENMIRRORCTRLTOKEN123/"]}


def start_mirror(me, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": KEY, "live": a["action"] == "start" or a["action"] == "status", "urls": []}
    return me.post("/api/call", {"tool": "amt_mirror_link", "arguments": {"device": KEY, "action": "start", "bind": "0.0.0.0", "port": 8766, "confirmed": True}})


def test_a_mirror_the_console_started_is_held_by_you_and_one_it_did_not_is_an_agents(me, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: {"mirrors": [MIRROR], "server": {"bind": "0.0.0.0", "port": 8766}, "recording_dir": "/r"}
    settle(me)
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "agent"
    start_mirror(me, fake_amt)
    fake_amt.results["amt_mirror_link"] = lambda a: {"mirrors": [MIRROR]}
    me.clock.advance(31)
    settle(me)
    kvm = me.app.fleet.public(KEY)["sessions"]["kvm"]
    assert kvm["holder"] == "console" and kvm["elapsed_s"] == 14.0 and kvm["fps"] == 15 and kvm["viewers"] == 2


def test_both_status_shapes_are_read_the_list_for_the_default_device_and_the_dict_for_a_named_one(me, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: MIRROR                           # the dict shape (a named, non-default device)
    settle(me)
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "agent"
    fake_amt.results["amt_mirror_link"] = lambda a: {"mirrors": [], "server": None, "recording_dir": "/r"}     # the list shape, no live mirror
    me.clock.advance(31)
    settle(me)
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "free"
    fake_amt.results["amt_mirror_link"] = lambda a: {"mirrors": [{**MIRROR, "device": "someone-else"}]}      # a mirror of another server
    me.clock.advance(31)
    settle(me)
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "free"


def test_a_mirror_that_ended_is_no_longer_the_consoles(me, fake_amt):
    start_mirror(me, fake_amt)
    assert f"mirror:{KEY}" in me.app.fleet.started
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": KEY, "live": False}
    me.clock.advance(31)
    settle(me)
    assert f"mirror:{KEY}" not in me.app.fleet.started
    fake_amt.results["amt_mirror_link"] = lambda a: MIRROR                           # an agent's mirror later is the agent's, not ours
    me.clock.advance(31)
    settle(me)
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "agent"


def test_stopping_a_mirror_through_the_console_forgets_it(me, fake_amt):
    start_mirror(me, fake_amt)
    me.post("/api/call", {"tool": "amt_mirror_link", "arguments": {"device": KEY, "action": "stop"}})
    assert f"mirror:{KEY}" not in me.app.fleet.started


def test_a_refused_start_does_not_make_the_console_the_holder(me, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: tool_error("another session is open")
    me.post("/api/call", {"tool": "amt_mirror_link", "arguments": {"device": KEY, "action": "start", "confirmed": True}})
    assert f"mirror:{KEY}" not in me.app.fleet.started


def test_a_start_that_returned_a_session_already_running_is_not_the_consoles(me, fake_amt):
    """amt_mirror_link start answers with the existing mirror's status when one is live: that mirror is an agent's."""
    fake_amt.results["amt_mirror_link"] = lambda a: {**MIRROR, "note": "already live; returning the existing link"} if a["action"] == "start" \
        else {"mirrors": [MIRROR]}
    me.post("/api/call", {"tool": "amt_mirror_link", "arguments": {"device": KEY, "action": "start", "confirmed": True}})
    assert f"mirror:{KEY}" not in me.app.fleet.started
    settle(me)
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "agent"


def test_a_repeated_start_keeps_the_record_of_the_session_the_console_started(me, fake_amt):
    start_mirror(me, fake_amt)
    at = me.app.fleet.started[f"mirror:{KEY}"]
    me.clock.advance(60)
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": KEY, "live": True, "note": "already live; returning the existing link"}
    me.post("/api/call", {"tool": "amt_mirror_link", "arguments": {"device": KEY, "action": "start", "confirmed": True}})
    assert me.app.fleet.started[f"mirror:{KEY}"] == at


def test_what_the_console_started_survives_a_restart_in_a_private_file(me, fake_amt):
    start_mirror(me, fake_amt)
    path = me.data / "host-sessions.json"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    again = fleet.Fleet(me.app.mcp, state_path=path)
    assert f"mirror:{KEY}" in again.started


def test_another_clients_session_is_what_amt_mcp_could_not_open(me, fake_amt):
    """A scripted `another session is open` refusal of a KVM-opening call makes the holder another client, for a while."""
    settle(me)
    fake_amt.results["amt_screenshot"] = lambda a: tool_error("another session is open")
    r = me.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": KEY}}).json()
    assert r["isError"] and "another session is open" in r["text"]                   # rendered verbatim by the page
    kvm = me.app.fleet.public(KEY)["sessions"]["kvm"]
    assert kvm["holder"] == "other" and kvm["refused_age_s"] == 0
    me.clock.advance(fleet.HELD_OTHER_TTL - 1)
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "other"
    me.clock.advance(2)
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "free"           # an old refusal does not stand for ever


@pytest.mark.parametrize("tool, arguments", [("amt_screenshot", {}), ("amt_mirror_link", {"action": "start", "confirmed": True})])
def test_the_start_status_amt_mcp_really_answers_a_busy_host_is_another_client_too(me, fake_amt, tool, arguments):
    """amt_kvm and amt_redir fail a refused start with `redir_start_status_N`, never the words "another session is open"."""
    settle(me)
    fake_amt.results[tool] = lambda a: tool_error(f"Error executing tool {tool}: redir_start_status_3")
    me.post("/api/call", {"tool": tool, "arguments": {"device": KEY, **arguments}})
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "other"


def test_a_zero_start_status_is_not_a_refusal(me, fake_amt):
    settle(me)
    fake_amt.results["amt_screenshot"] = lambda a: tool_error("Error executing tool amt_screenshot: redir_start_status_0")
    me.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": KEY}})
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "free"


def test_a_later_successful_open_clears_the_other_client(me, fake_amt):
    settle(me)
    fake_amt.results["amt_screenshot"] = lambda a: tool_error("another session is open")
    me.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": KEY}})
    fake_amt.results["amt_screenshot"] = lambda a: {"device": KEY, "width": 1, "height": 1, "bytes": 1}
    me.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": KEY}})
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "free"


def test_an_unrelated_refusal_is_not_another_client(me, fake_amt):
    settle(me)
    for text in ("tls_leaf_pin_mismatch", "connect timed out"):
        fake_amt.results["amt_screenshot"] = lambda a, t=text: tool_error(t)
        me.post("/api/call", {"tool": "amt_screenshot", "arguments": {"device": KEY}})
    fake_amt.results["amt_sol"] = lambda a: tool_error("another session is open")      # not a KVM-opening call
    me.post("/api/call", {"tool": "amt_sol", "arguments": {"device": KEY, "text": "x", "confirmed": True}})
    assert me.app.fleet.public(KEY)["sessions"]["kvm"]["holder"] == "free"


def test_an_agent_call_in_flight_is_reported_without_arguments(me, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: {**MIRROR, "in_flight": {"tool": "amt_console_input", "started_at": 1_759_999_990.0, "arguments": {"text": "SECRET-ARG"}}}
    settle(me)
    kvm = me.app.fleet.public(KEY)["sessions"]["kvm"]
    assert kvm["in_flight"] == {"tool": "amt_console_input", "started_at": 1_759_999_990.0}
    assert "SECRET-ARG" not in json.dumps(me.app.fleet.snapshot())


def test_no_viewer_url_or_token_reaches_the_browser(me, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: MIRROR
    fake_amt.results["amt_serial_link"] = lambda a: {"device": KEY, "live": True, "uptime_s": 5.0, "viewers": 0, "urls": ["http://nas:8766/s/SERIALVIEWTOKENSERIALVIEWTOKEN12/"],
                                                     "control_urls": ["http://nas:8766/s/SERIALCTRLTOKENSERIALCTRLTOKEN123/"], "recording": None}
    settle(me)
    for path in ("/api/fleet", f"/api/server/{KEY}"):
        text = me.get(path).text
        assert "TOKEN" not in text and "/m/" not in text and "/s/" not in text and "urls" not in text, path
        assert BEARER not in text


def test_ide_r_reports_the_image_names_only(me, fake_amt):
    fake_amt.results["amt_ider"] = lambda a: {"device": KEY, "mounted": True, "images": {"iso": "debian-13.3-netinst.iso"}, "bytes_to_host": 4096, "error": None}
    settle(me)
    assert me.app.fleet.public(KEY)["sessions"]["ider"] == {"mounted": True, "images": {"iso": "debian-13.3-netinst.iso"}, "error": None}


def test_a_session_view_that_failed_is_unknown_not_free(me, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: tool_error("mirror status failed")
    settle(me)
    e = me.app.fleet.public(KEY)
    assert e["sessions"]["kvm"] == {"holder": "unknown"} and "mirror status failed" in e["sessions_error"]
    assert e["sessions"]["sol"]["holder"] == "free"


# -- past captures ------------------------------------------------------------------------------------------------------

def listing(items, nxt=None, found=True):
    return {"total": len(items), "offset": 0, "captures": items, "next_offset": nxt,
            "searched": [{"dir": "/data/shots", "kinds": ["screenshot"], "found": True}, {"dir": "/data/rec", "kinds": ["recording", "serial_cast"], "found": found}]}


def cap(name, device=KEY, kind="screenshot", size=10):
    return {"name": name, "kind": kind, "device": device, "bytes": size, "modified": "2026-10-20T14:24:31Z"}


def test_past_captures_are_this_servers_own_and_name_what_was_searched(me, fake_amt):
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device(), device("other")]}
    fake_amt.results["amt_captures"] = lambda a: listing([cap("amt-my-server-1-1.png"), cap("amt-other-1.png", device="other"), cap("amt-my-server-1-2.mp4", kind="recording", size=48)], found=False)
    got = me.get(f"/api/server/{KEY}/captures").json()
    assert [c["name"] for c in got["captures"]] == ["amt-my-server-1-1.png", "amt-my-server-1-2.mp4"]
    assert got["listed"] == 3 and got["complete"] is True
    assert [s["found"] for s in got["searched"]] == [True, False]                    # a folder amt-mcp could not read is disclosed
    assert all(c["capture"] is None for c in got["captures"])


def test_past_captures_page_through_everything_amt_mcp_lists(me, fake_amt):
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device()]}
    pages = {0: listing([cap(f"amt-my-server-1-{i}.png") for i in range(200)], nxt=200), 200: listing([cap("amt-my-server-1-last.png")])}
    fake_amt.results["amt_captures"] = lambda a: pages[a["offset"]]
    got = me.get(f"/api/server/{KEY}/captures").json()
    assert len(got["captures"]) == 201 and got["listed"] == 201 and got["complete"] is True
    assert [a["offset"] for a in calls(fake_amt, "amt_captures")] == [0, 200]


def test_a_cut_list_says_it_was_cut(me, fake_amt):
    fake_amt.results["amt_captures"] = lambda a: listing([cap("amt-my-server-1-1.png")], nxt=a["offset"] + 1)
    got = me.get(f"/api/server/{KEY}/captures").json()
    assert got["complete"] is False and got["listed"] == fleet.MAX_PAGES


def test_a_fetched_capture_is_joined_to_the_store_record_of_the_same_name(me, fake_amt):
    fake_amt.results["amt_captures"] = lambda a: listing([cap("amt-my-server-1-1.png")]) if a["action"] == "list" else fake_amt.offer(b"png-bytes", a["name"])
    r = me.post("/api/call", {"tool": "amt_captures", "arguments": {"action": "fetch", "name": "amt-my-server-1-1.png"}}).json()
    rec = r["structured"]["capture"]
    assert rec["status"] == "ready" and "handoffs" not in json.dumps(r) and "http" not in json.dumps(r["structured"])
    row = me.get(f"/api/server/{KEY}/captures").json()["captures"][0]
    assert row["capture"]["id"] == rec["id"] and row["capture"]["status"] == "ready" and row["capture"]["sha256"] == rec["sha256"]
    assert me.get("/captures/" + rec["id"]).data == b"png-bytes"
    assert len(fake_amt.fetches) == 1 and set(fake_amt.fetches.values()) == {1}      # fetched once, from amt-mcp's own origin


def test_an_expired_past_capture_is_expired_never_missing(me, fake_amt):
    def fetch(a):
        out = fake_amt.offer(b"x", a["name"])
        fake_amt.handoffs.clear()                                                    # the link is gone by the time it is fetched
        return out
    fake_amt.results["amt_captures"] = lambda a: listing([cap("amt-my-server-1-1.png")]) if a["action"] == "list" else fetch(a)
    r = me.post("/api/call", {"tool": "amt_captures", "arguments": {"action": "fetch", "name": "amt-my-server-1-1.png"}}).json()
    assert r["structured"]["capture"]["status"] == "expired"
    row = me.get(f"/api/server/{KEY}/captures").json()["captures"][0]
    assert row["capture"]["status"] == "expired"


def test_a_capture_list_that_failed_is_an_error_not_an_empty_list(me, fake_amt):
    fake_amt.results["amt_captures"] = lambda a: tool_error("captures folder unreadable")
    r = me.get(f"/api/server/{KEY}/captures")
    assert r.status == 503 and "captures folder unreadable" in r.json()["error"]


# -- the routes -------------------------------------------------------------------------------------------------------

def test_the_status_routes_need_a_signed_in_session(fc):
    for path in ("/api/fleet", f"/api/server/{KEY}", f"/api/server/{KEY}/captures"):
        assert fc.get(path).status == 401, path
    assert fc.post("/api/fleet/refresh", {}, cookie=False).status == 401


def test_refresh_needs_the_csrf_token_and_the_origin(me):
    assert me.post("/api/fleet/refresh", {}, csrf=False).status == 403
    assert me.post("/api/fleet/refresh", {}, origin=False).status == 403
    assert me.post("/api/fleet/refresh", {}, headers={"Origin": "https://evil.example"}).status == 403


def test_refresh_names_a_known_server_only(me, fake_amt):
    settle(me)
    assert me.post("/api/fleet/refresh", {"device": "nope"}).status == 404
    assert me.post("/api/fleet/refresh", {"device": "../x"}).status == 404
    assert me.post("/api/fleet/refresh", {"device": ["a"]}).status == 404
    assert me.get("/api/server/nope").status == 404


def test_the_fleet_snapshot_before_any_read_is_loading_not_empty(me):
    snap = me.get("/api/fleet").json()
    assert snap["servers"] == [] and snap["loaded"] is False
    settle(me)
    snap = me.get("/api/fleet").json()
    assert snap["loaded"] is True and [s["key"] for s in snap["servers"]] == [KEY]


def test_a_server_added_is_listed_and_one_removed_disappears(me, fake_amt):
    settle(me)
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device(), device("newcomer")]}
    me.clock.advance(31)
    me.app.fleet.refresh_devices()
    keys = [s["key"] for s in me.get("/api/fleet").json()["servers"]]
    assert keys == [KEY, "newcomer"] and me.app.fleet.public("newcomer")["state"] == "loading"
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device("newcomer")]}
    me.app.fleet.refresh_devices()
    assert [s["key"] for s in me.get("/api/fleet").json()["servers"]] == ["newcomer"]


def test_a_failed_device_list_keeps_the_last_good_one_and_says_so(me, fake_amt):
    settle(me)
    fake_amt.results["amt_devices"] = lambda a: tool_error("devices file malformed")
    me.app.fleet.refresh_devices()
    snap = me.get("/api/fleet").json()
    assert [s["key"] for s in snap["servers"]] == [KEY] and "devices file malformed" in snap["devices_error"]


def test_the_server_page_renders_its_header_and_all_nine_tabs(me):
    r = me.get(f"/server/{KEY}")
    assert r.status == 200
    tabs = re.findall(r'<nav class="tabs"[^>]*>(.*?)</nav>', r.text, re.S)[0]
    labels = re.findall(r">([^<]+)</a>", tabs)
    assert labels == ["Status", "Power &amp; boot", "KVM", "SOL", "Media", "Logs", "Inventory", "AMT settings", "Advanced"]
    assert tabs.count("aria-current=page") == 1 and f'href="/server/{KEY}" aria-current=page' in tabs
    assert f'data-server="{KEY}"' in r.text and 'src="/static/server.js"' in r.text and 'src="/static/fleet.js"' not in r.text
    other = me.get(f"/server/{KEY}/wsman").text
    assert 'href="/server/my-server-1/wsman" aria-current=page' in other and 'id="wsman-page"' in other and "built in a later step" not in other and 'id="status-cards"' not in other


def test_a_server_tab_that_does_not_exist_is_a_404_and_no_key_is_echoed_unescaped(me):
    assert me.get(f"/server/{KEY}/nope").status == 404
    assert me.get("/server/Bad_Key").status == 404
    assert me.get('/server/"><script>').status == 404
    assert me.get("/server/x/").status == 404


def test_the_fleet_page_loads_its_scripts_and_the_server_page_is_a_fleet_section(me):
    r = me.get("/")
    assert 'src="/static/status.js"' in r.text and 'src="/static/fleet.js"' in r.text and 'id="fleet-grid"' in r.text
    assert 'href="/" aria-current="page"' in me.get(f"/server/{KEY}").text           # a server belongs to the Fleet section of the navigation


def test_status_pages_redirect_when_signed_out(fc):
    assert fc.get("/").status == 302 and fc.get(f"/server/{KEY}").status == 302


# -- the poller -------------------------------------------------------------------------------------------------------

class CountingClient:
    def __init__(self):
        self.n = 0

    def call(self, tool, arguments):
        self.n += 1 if tool == "amt_status" else 0
        if tool == "amt_devices":
            return mcp_client.Result(False, "", {"devices": [device()]})
        if tool == "amt_status":
            return mcp_client.Result(False, "", STATUS)
        return mcp_client.Result(False, "", {"live": False, "mounted": False, "identities": []})


def wait_for(pred, seconds=6):
    end = time.time() + seconds
    while time.time() < end:
        if pred():
            return True
        time.sleep(0.02)
    return False


def test_the_poller_runs_only_while_a_page_is_looking():
    client = CountingClient()
    fl = fleet.Fleet(client, interval=0.2)
    time.sleep(0.5)
    assert client.n == 0 and fl._thread is None                                      # nobody asked: nothing is read
    fl.touch()
    assert wait_for(lambda: client.n >= 1), "the poller never read the server"
    assert wait_for(lambda: fl._thread is not None and not fl._thread.is_alive()), "the poller did not stop after the page went away"
    read = client.n
    time.sleep(0.5)
    assert client.n == read                                                          # and it stays stopped
    fl.touch()
    assert wait_for(lambda: client.n > read), "a new request did not restart the poller"
    fl.stop()


def test_the_poller_survives_a_fault_in_one_pass():
    class Flaky(CountingClient):
        def call(self, tool, arguments):
            if tool == "amt_status" and self.n == 0:
                self.n += 1
                raise RuntimeError("boom")
            return super().call(tool, arguments)
    client = Flaky()
    fl = fleet.Fleet(client, interval=0.2)
    fl.touch()
    assert wait_for(lambda: client.n >= 2), "one faulting pass ended the poller"
    fl.stop()


def test_nothing_secret_is_in_the_status_routes_or_the_sessions_file(me, fake_amt):
    settle(me)
    start_mirror(me, fake_amt)
    for path in ("/", "/api/fleet", f"/api/server/{KEY}", f"/server/{KEY}", f"/api/server/{KEY}/captures", "/static/fleet.js", "/static/server.js", "/static/status.js"):
        assert BEARER not in me.get(path).text, path
    assert BEARER not in (me.data / "host-sessions.json").read_text()


# -- invariant 2 on the status routes: a one-time url in a tool's error text never reaches the browser (sprint review M2) ---

HANDOFF_TOKEN = "Hq" + "7" * 41                    # 43 url-safe characters, the shape of a handoff, upload or intake token
VIEWER_TOKEN = "Vw" + "9" * 30                     # 32, the shape of a viewer token (token_urlsafe(24))
LEAK = (f"Error executing tool amt_status: wsman_auth_failed_401 https://amt.example.test/handoffs/{HANDOFF_TOKEN} "
        f"and https://amt-viewer.example.test/m/{VIEWER_TOKEN}/")


def assert_masked(text):
    assert HANDOFF_TOKEN not in text and VIEWER_TOKEN not in text and "/handoffs/" not in text and "/m/" not in text
    assert "one-time url withheld" in text


def test_the_status_error_is_masked_on_both_routes(me, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error(LEAK)
    settle(me)
    for path in (f"/api/server/{KEY}", "/api/fleet"):
        r = me.get(path)
        assert "wsman_auth_failed_401" in r.text                                   # the tool's words stay
        assert_masked(r.text)
    assert me.get(f"/api/server/{KEY}").json()["server"]["paused"]["reason"] == "credential refused"   # the stored text still classifies


def test_the_sessions_error_is_masked_on_both_routes(me, fake_amt):
    fake_amt.results["amt_mirror_link"] = lambda a: tool_error(LEAK.replace("amt_status", "amt_mirror_link"))
    settle(me)
    assert me.get(f"/api/server/{KEY}").json()["server"]["sessions_error"]
    for path in (f"/api/server/{KEY}", "/api/fleet"):
        assert_masked(me.get(path).text)


def test_the_device_list_error_is_masked_on_both_routes(me, fake_amt):
    settle(me)
    fake_amt.results["amt_devices"] = lambda a: tool_error(LEAK.replace("amt_status", "amt_devices"))
    me.app.fleet.refresh_devices()
    snap = me.get("/api/fleet").json()
    assert snap["devices_error"] and "wsman_auth_failed_401" in snap["devices_error"]
    assert_masked(me.get("/api/fleet").text)


def test_a_token_the_cut_lands_inside_is_masked_before_the_cut(me, fake_amt):
    """The stored text is cut to 600 characters. Cut first and a viewer token that straddles the cut is too short to match, so its
    first characters would reach the browser; the text is masked, then cut."""
    pad = "x" * (600 - len("https://amt-viewer.example.test/m/") - 20 - 5)
    text = f"{pad} https://amt-viewer.example.test/m/{VIEWER_TOKEN}/"
    assert 600 - 25 < len(text) - len(VIEWER_TOKEN) < 600                     # the cut falls inside the token
    fake_amt.results["amt_status"] = lambda a: tool_error(text)
    settle(me)
    stored = me.app.fleet.entries[KEY]["error"]
    assert VIEWER_TOKEN[:12] not in stored and VIEWER_TOKEN[:12] not in me.get("/api/fleet").text


def test_the_past_captures_error_is_masked(me, fake_amt):
    fake_amt.results["amt_captures"] = lambda a: tool_error(LEAK.replace("amt_status", "amt_captures"))
    r = me.get(f"/api/server/{KEY}/captures")
    assert r.status >= 500 and "wsman_auth_failed_401" in r.text
    assert_masked(r.text)


def test_the_next_boot_fields_are_masked_on_both_routes(me, fake_amt):
    """``next_boot`` keeps the device's own scalar fields, whatever they are, so its strings are masked like the errors (final review, finding 1)."""
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"], "next_boot": {"note": LEAK}}
    settle(me)
    assert me.get(f"/api/server/{KEY}").json()["server"]["status"]["next_boot"]["note"]
    for path in (f"/api/server/{KEY}", "/api/fleet"):
        assert_masked(me.get(path).text)


def test_public_masks_a_text_stored_unmasked(me, fake_amt):
    """The route-level guard stands on its own: a store that forgot to mask still does not reach the browser."""
    settle(me)
    me.app.fleet.entries[KEY].update(error=LEAK, sessions_error=LEAK)
    me.app.fleet.devices_error = LEAK
    for path in (f"/api/server/{KEY}", "/api/fleet"):
        assert_masked(me.get(path).text)
