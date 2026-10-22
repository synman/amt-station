"""The AMT settings tab (packet C6, the settings half): the ten settings areas through amt_settings, the six that amt_configure writes with an
old / new preview, the write sheet and Revert, the AMT accounts with vaulted passwords, and the four read-only areas that point at Advanced.

Every amt-mcp answer is scripted (console_fakes.FakeAmt, and a small fake host here that answers like amt_settings and amt_configure over a state it
keeps, validating through amt_write's own rules); no test reaches a host, and a write is only ever sent to the fake. Immutables 4 and 5 (no write on a
bare click, one activation one call, focus; no area is destructive by argument), 7 (a refusal in its own card, a refused credential pauses the server),
19 (coverage from the result), plus 13, 14 and 1 on the built page."""
import asyncio
import copy
import json
import re
import time
from pathlib import Path

import pytest

import amt_tools
import amt_write
import mcp_client
from console_fakes import Authenticator, Console, check_mockups, enroll_first_passkey
from test_console_fleet import KEY, STATUS, device, tool_error, fc, me, settle, calls  # noqa: F401 - fixtures
from test_console_fleet_browser import open_page, text

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed: the browser immutables are NOT checked")

CONSOLE = Path(__file__).resolve().parent.parent
WIDTHS = [360, 600, 1024, 1440]
TLS_ID = amt_write.PUT_AREAS["security"].selectors["InstanceID"]
WRITE_TOOLS = {name for name, (_, read_only) in mcp_client.TOOLS.items() if not read_only}


def wait_for(fn, what, seconds=8):
    end = time.time() + seconds
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


# ============================== a fake host: amt_settings and amt_configure over a state it keeps ===============================================

def fresh_state():
    return {
        "general": {"HostName": "my-server-1", "DomainName": "lan.example.test", "SharedFQDN": True, "PingResponseEnabled": True,
                    "RmcpPingResponseEnabled": False, "DDNSUpdateEnabled": False, "DDNSPeriodicUpdateInterval": 24, "DDNSTTL": 900,
                    "IdleWakeTimeout": 1, "DigestRealm": "Digest:A1B2C3", "ElementName": "Intel(r) AMT: General Settings"},
        "ethernet_ports": [{"InstanceID": "Intel(r) AMT Ethernet Port Settings 0", "MACAddress": "58:47:ca:00:00:01", "DHCPEnabled": True},
                           {"InstanceID": "Intel(r) AMT Ethernet Port Settings 1", "MACAddress": "58:47:ca:00:00:02", "DHCPEnabled": False}],
        "environment_detection": {"InstanceID": "Intel(r) AMT Environment Detection Settings", "DetectionAlgorithm": 0, "DetectionStrings": ["lan.example.test", "corp.example.test"]},
        "tls": [{"InstanceID": "Intel(r) AMT 802.11 TLS Settings", "AcceptNonSecureConnections": True},
                {"InstanceID": TLS_ID, "AcceptNonSecureConnections": False, "Enabled": True}],
        "settings": {"InstanceID": "Intel(r) KVM Redirection Settings", "Is5900PortEnabled": False, "OptInPolicy": True, "SessionTimeout": 3,
                     "RFBPassword": "<redacted>", "EnabledByMEBx": True},
        "redirection_sap": {"EnabledState": 2}, "opt_in": {"OptInRequired": 1},
        "redirection_service": {"EnabledState": 32769}, "kvm_sap": {"EnabledState": 3},
        "watchdogs": [{"DeviceID": "wd0", "TimeoutLow": 120}], "capabilities": {"MaxWatchdogs": 4},
        "users": [{"DigestUsername": "admin", "AccessPermission": 2, "Realms": [3, 4, 5]}, {"DigestUsername": "ops", "AccessPermission": 1, "Realms": [3]}],
    }


class Host:
    """Answers like amt_settings and amt_configure: sections from amt_tools.SETTINGS_AREAS over `state`, a write validated by amt_write.validate_configure
    (so a refusal is the tool's own text), a readback of the state it changed. `refuse` (a text) answers the next configure with that refusal."""

    def __init__(self):
        self.state = fresh_state()
        self.refuse = None
        self.unavailable, self.truncated, self.reasons = [], [], {}
        self.reads, self.writes = [], []

    def read(self, a):
        self.reads.append(a)
        area = a["area"]
        if area == "users":
            return {"device": a["device"], "area": area, "sections": {"users": copy.deepcopy(self.state["users"])}, "classes": {"users": "AMT_AuthorizationService"},
                    "unavailable": [], "truncated": []}
        sections, classes = {}, {}
        for name, cls, mode in amt_tools.SETTINGS_AREAS[area]:
            sections[name] = copy.deepcopy(self.state.get(name, [] if mode == "enum" else {}))
            classes[name] = cls
        out = {"device": a["device"], "area": area, "sections": sections, "classes": classes, "unavailable": list(self.unavailable), "truncated": list(self.truncated)}
        if self.reasons:
            out["unavailable_reasons"] = dict(self.reasons)
        return out

    def instance(self, area):
        spec = amt_write.PUT_AREAS[area]
        sec = self.state[{"network": "general", "internet": "environment_detection", "kvm": "settings", "security": "tls"}[area]]
        return next(i for i in sec if i["InstanceID"] == spec.selectors["InstanceID"]) if isinstance(sec, list) else sec

    def configure(self, a):
        self.writes.append(a)
        area = a["area"]
        try:
            changes = amt_write.validate_configure(area, a["changes"])
        except ValueError as ex:
            return tool_error(f"Error executing tool amt_configure: {ex}")
        if self.refuse:
            text, self.refuse = self.refuse, None
            return tool_error(text)
        if area in amt_write.PUT_AREAS:
            inst = self.instance(area)
            previous = {n: inst[n] for n in changes}
            inst.update(changes)
            return {"device": a["device"], "area": area, "class": amt_write.PUT_AREAS[area].cls, "previous": previous, "readback": dict(changes),
                    "verified_unchanged": sorted(n for n in inst if n not in changes and n not in ("RFBPassword",)),
                    "revert": "call amt_configure again with the 'previous' values"}
        if area == "features":
            rs = amt_tools.REDIRECTION_STATES[self.state["redirection_service"]["EnabledState"]]
            before = {"ider_enabled": rs[0], "sol_enabled": rs[1], "kvm_enabled": self.state["kvm_sap"]["EnabledState"] in (2, 6)}
            want = (changes.get("ider_enabled", rs[0]), changes.get("sol_enabled", rs[1]))
            self.state["redirection_service"]["EnabledState"] = next(c for c, pair in amt_tools.REDIRECTION_STATES.items() if pair == want)
            if "kvm_enabled" in changes:
                self.state["kvm_sap"]["EnabledState"] = 2 if changes["kvm_enabled"] else 3
            return {"device": a["device"], "area": area, "class": "AMT_RedirectionService,CIM_KVMRedirectionSAP", "previous": {n: before[n] for n in changes},
                    "readback": dict(changes), "revert": "call amt_configure again with the 'previous' values"}
        name = changes["username"]
        present = [u for u in self.state["users"] if u["DigestUsername"] == name]
        if changes["action"] == "remove":
            if not present:
                return tool_error(f"Error executing tool amt_configure: users_no_such_user:{name}")
            self.state["users"].remove(present[0])
            return {"device": a["device"], "area": area, "class": "AMT_AuthorizationService", "previous": {"present": True}, "readback": {"present": False},
                    "revert": "call amt_configure with the opposite action"}
        if present:
            return tool_error(f"Error executing tool amt_configure: users_user_exists:{name}")
        self.state["users"].append({"DigestUsername": name, "AccessPermission": changes["access_permission"], "Realms": changes["realms"]})
        return {"device": a["device"], "area": area, "class": "AMT_AuthorizationService", "previous": {"present": False}, "readback": {"present": True},
                "revert": "call amt_configure with the opposite action"}


def identities(*names):
    return lambda a: {"vault_entries": len(names), "identities": [{"name": n, "status": "present", "used_by": [{"device": KEY, "field": "amt_configure_users"}],
                                                                     "source": "console", "updated_at": "2026-10-21T01:00:00Z"} for n in names]}


# ============================== the built page and what it sends (no browser) ===================================================================

def live_tools():
    import amt_server
    return {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}


def test_the_settings_tab_is_built_with_its_own_script_and_no_inline_style(me):
    page = me.get(f"/server/{KEY}/settings").text
    assert 'id="settings-page"' in page and f'data-server="{KEY}"' in page and "/static/settings.js" in page and "built in a later step" not in page and "@@" not in page
    assert page.count('<script src="/static/') == page.count("<script src=") and "/static/status.js" in page
    assert "style=" not in page.split('id="settings-page"')[1].split("</main>")[0], "the console's CSP forbids inline styles"
    assert f'href="/server/{KEY}/settings" aria-current=page' in page
    assert "logs.js" not in page and "inventory.js" not in page and "wsman.js" not in page, "a tab loads only its own script"


def test_the_areas_the_page_offers_are_the_tools_own_ten_and_the_dashed_four_are_the_ones_amt_configure_cannot_write():
    live = live_tools()
    enums = []

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("enum"), list) and "agent_presence" in node["enum"]:
                enums.append(node["enum"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(live["amt_settings"].inputSchema)
    assert enums
    page = (CONSOLE / "pages" / "content-server-settings.html").read_text()
    chips = re.findall(r'<button type="button" class="chip( dashed| selected)?" aria-pressed="\w+" data-area="(\w+)"', page)
    assert sorted(a for _, a in chips) == sorted(enums[0]) and len(chips) == 10
    assert sorted(a for k, a in chips if k.strip() == "dashed") == sorted(amt_write.UNSUPPORTED_AREAS)
    configure_enum = live["amt_configure"].inputSchema["properties"]["area"]["enum"]
    assert sorted(a for k, a in chips if k.strip() != "dashed") == sorted(set(configure_enum) | {"users"}) and "users" in configure_enum


def js_table():
    src = (CONSOLE / "static" / "settings.js").read_text()
    body = re.search(r"var AREAS = \{\n(.*?)\n  \};", src, re.S).group(1)
    areas = {}
    for chunk in re.split(r"(?m)^    (?=\w+: \{)", body)[1:]:
        areas[chunk.split(":")[0]] = re.findall(r"\{ n: '(\w+)', t: '(\w+)' \}", chunk)
    return src, areas


def test_the_writable_fields_and_their_kinds_are_the_tools_own_table():
    src, areas = js_table()
    for area, spec in amt_write.PUT_AREAS.items():
        assert dict(areas[area]) == spec.fields, area
    assert dict(areas["features"]) == amt_write.FEATURE_FIELDS
    assert sorted(areas) == sorted(list(amt_write.PUT_AREAS) + ["features"])
    assert re.search(r"pick: '([^']+)'", src).group(1) == amt_write.PUT_AREAS["security"].selectors["InstanceID"]
    block = re.search(r"var SECTIONS = \{(.*?)\n  \};", src, re.S).group(1)
    sections = {k: re.findall(r"'(\w+)'", v) for k, v in re.findall(r"(\w+): \[([^\]]*)\]", block)}
    for area, rows in amt_tools.SETTINGS_AREAS.items():
        assert sections[area] == [n for n, _, _ in rows], area
    assert sections["users"] == ["users"] and len(sections) == 10
    for area, section in (("network", "general"), ("internet", "environment_detection"), ("security", "tls"), ("kvm", "settings")):
        assert re.search(rf"    {area}: \{{ section: '{section}'", src), area                       # where the area's fields sit in the read
        cls = next(c for n, c, _ in amt_tools.SETTINGS_AREAS[area] if n == section)
        assert cls == amt_write.PUT_AREAS[area].cls, area                                           # and that section is the class the tool writes


def test_the_redirection_table_and_the_risky_changes_are_the_tools_own():
    src, _ = js_table()
    pairs = {int(k): (a == "true", b == "true") for k, a, b in re.findall(r"(\d+): \[(true|false), (true|false)\]", re.search(r"var REDIRECTION = \{(.*?)\};", src).group(1))}
    assert pairs == amt_tools.REDIRECTION_STATES
    assert re.search(r"var KVM_ENABLED = \[(.*?)\];", src).group(1).replace(" ", "") == "2,6"
    risky = {(a, f, v == "true"): t for a, f, v, t in re.findall(r"\['(\w+)', '(\w+)', (true|false), '([^']+)'\]", re.search(r"var RISKY = \[(.*?)\];", src, re.S).group(1))}
    assert risky == amt_write.RISKY_CONFIGURE
    assert re.search(r"var USER_NAME = /\^(.*?)\$/;", src).group(1) == amt_write.USER_NAME.pattern


def test_the_page_sends_only_what_the_live_tool_schemas_take():
    live = live_tools()
    assert mcp_client.TOOLS["amt_settings"] == (True, True) and mcp_client.TOOLS["amt_configure"] == (True, False)    # a device is named; a write carries confirmed
    assert set(live["amt_settings"].inputSchema["properties"]) == {"area", "device"} and "confirmed" not in live["amt_settings"].inputSchema["properties"]
    assert {"area", "changes", "device", "confirmed"} == set(live["amt_configure"].inputSchema["properties"])
    assert mcp_client.TOOLS["amt_identities"] == (False, True)


def test_a_credential_named_field_is_refused_by_the_tool_before_anything_else():
    """What the scripted refusal below quotes is the tool's real text, not an invention."""
    with pytest.raises(ValueError, match=r"^secret_field_refused:AdminPassword$"):
        amt_write.validate_configure("network", {"AdminPassword": "x"})


@pytest.mark.parametrize("name", ["settings.js"])
def test_what_a_tool_or_a_host_says_is_never_set_as_markup(name):
    src = (CONSOLE / "static" / name).read_text()
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert banned not in src, (name, banned)


def test_a_configure_without_a_named_device_or_without_confirmed_is_refused_before_it_is_sent(me, fake_amt):
    for args in ({"area": "kvm", "changes": {"SessionTimeout": 5}, "confirmed": True}, {"device": KEY, "area": "kvm", "changes": {"SessionTimeout": 5}}):
        reply = me.post("/api/call", {"tool": "amt_configure", "arguments": args})
        assert reply.status == 400 and reply.json()["error"] in ("device_not_named", "confirmed_not_true")
    assert calls(fake_amt, "amt_configure") == []


def test_a_401_in_a_settings_read_pauses_the_server_and_it_is_not_read_again(me, fake_amt):
    fake_amt.results["amt_settings"] = lambda a: tool_error("Error executing tool amt_settings: wsman_auth_failed_401")
    settle(me)
    r = me.post("/api/call", {"tool": "amt_settings", "arguments": {"device": KEY, "area": "kvm"}}).json()
    assert r["isError"] and "wsman_auth_failed_401" in r["text"]
    assert me.app.fleet.public(KEY)["state"] == "paused"


# ============================== the page, in a real browser (headless Chromium) ================================================================

@pytest.fixture(scope="module")
def browser():
    with sync_api.sync_playwright() as p:
        try:
            b = p.chromium.launch()
        except Exception as ex:  # noqa: BLE001
            pytest.skip(f"headless Chromium is not installed ({type(ex).__name__}): the browser immutables are NOT checked")
        yield b
        b.close()


@pytest.fixture()
def sb(tmp_path, fake_amt):
    """A signed-in console, the server read once, a fake host answering amt_settings and amt_configure, two identities in the vault."""
    console = Console(tmp_path, fake_amt)
    enroll_first_passkey(console, Authenticator(console.app.cfg.rp_id, console.origin))
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device()]}
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"]}
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_serial_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
    fake_amt.results["amt_identities"] = identities(f"{KEY}-amt", f"{KEY}-amt-user-viewer")
    fake_amt.host = Host()
    fake_amt.results["amt_settings"] = fake_amt.host.read
    fake_amt.results["amt_configure"] = fake_amt.host.configure
    console.app.fleet.refresh_devices()
    console.app.fleet.refresh(KEY)
    yield console
    console.close()


READY = "#set-cards .card, #set-state .result"


def idle(pg):
    pg.wait_for_function("() => !document.getElementById('set-reread').hasAttribute('aria-disabled')")


def open_tab(browser, sb, area="kvm", width=1024, scheme="light", ready=True, **kw):
    ctx, pg = open_page(browser, sb, f"/server/{KEY}/settings", width=width, scheme=scheme, **kw)
    pg.set_default_timeout(8000)
    if ready:
        pg.wait_for_selector(READY)
        idle(pg)
        if area != "kvm":
            choose(pg, area)
    return ctx, pg


def choose(pg, area):
    pg.click(f'[data-area="{area}"]')
    pg.wait_for_function("a => !!(document.querySelector('#set-card[data-area=\"' + a + '\"]') || (a === 'users' && document.getElementById('users-card')) || document.querySelector('#set-state .result'))", arg=area)
    idle(pg)


def reads(fake):
    return calls(fake, "amt_settings")


def writes(fake):
    return calls(fake, "amt_configure")


def press(pg, sel, fake, n):
    before = len(reads(fake))
    pg.click(sel)
    wait_for(lambda: len(reads(fake)) == before + 1, f"read {before + 1}")
    idle(pg)
    assert len(reads(fake)) == n


def diff(pg):
    cells = pg.eval_on_selector_all("#set-card .diff > span", "es => es.map(e => e.textContent.trim())")
    return [cells[i:i + 3] for i in range(3, len(cells), 3)]


def sheet(pg):
    return pg.evaluate("() => { const s = Array.from(document.querySelectorAll('.sheet.open')).pop(); return s ? { force: s.hasAttribute('data-force-sheet'), plain: s.hasAttribute('data-confirm-sheet'), "
                       "call: s.querySelector('.call').textContent, title: s.querySelector('h2').textContent, say: s.querySelector('.consequence').textContent } : null; }")


def confirm_plain(pg):
    pg.click(".sheet.open [data-confirm]")


def set_text(pg, field, value):
    pg.fill(f'[data-field="{field}"]', value)


def toggle(pg, field):
    pg.click(f'[data-field="{field}"]')


# -- reading ----------------------------------------------------------------------------------------------------------------------------

def test_the_kvm_area_is_read_on_open_with_the_device_named_and_each_field_beside_the_tools_value(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb)
    try:
        assert reads(fake_amt) == [{"device": KEY, "area": "kvm"}]
        assert diff(pg) == [["Is5900PortEnabled", "false", "false (unchanged)"], ["OptInPolicy", "true", "true (unchanged)"], ["SessionTimeout", "3", "3 (unchanged)"]]
        assert pg.get_attribute('[data-field="Is5900PortEnabled"]', "aria-checked") == "false" and pg.get_attribute('[data-field="OptInPolicy"]', "aria-checked") == "true"
        assert pg.input_value('[data-field="SessionTimeout"]') == "3"
        assert "weakens access when true: opens the unencrypted VNC port 5900" in text(pg, '[data-field="Is5900PortEnabled"]')
        assert text(pg, "#set-note").startswith("amt_settings · read ") and text(pg, "#set-call").startswith('tools/call amt_settings {device: "my-server-1", area: "kvm"} · read-only')
        assert pg.get_attribute('[data-area="kvm"]', "aria-pressed") == "true" and pg.errors == []
        assert pg.get_attribute("#set-write", "aria-disabled") == "true" and text(pg, "#set-write ~ .reason") == "nothing changed"
        assert text(pg, "#set-card h2") == "kvm" and "IPS_KVMRedirectionSettingData" in text(pg, "#set-card")
        # every section the read returned is on the page, as the tool returned it; the redacted field is the tool's own marker
        sec = text(pg, "#sections-card")
        assert "redirection_sap" in sec and "opt_in" in sec and "RFBPassword <redacted>" in sec.replace("\n", " ")
    finally:
        ctx.close()


def test_a_bool_field_the_tool_did_not_report_is_not_offered_and_says_why(browser, sb, fake_amt):
    del fake_amt.host.state["settings"]["OptInPolicy"]
    ctx, pg = open_tab(browser, sb)
    try:
        assert pg.get_attribute('[data-field="OptInPolicy"]', "aria-disabled") == "true" and "not reported by AMT, so it is not offered" in text(pg, '[data-field="OptInPolicy"]')
        assert diff(pg)[1] == ["OptInPolicy", "not reported", "not offered"]
        pg.click('[data-field="OptInPolicy"]', force=True)
        assert pg.get_attribute('[data-field="OptInPolicy"]', "aria-checked") == "false" and pg.get_attribute("#set-write", "aria-disabled") == "true"
    finally:
        ctx.close()


# -- the write: old / new preview, one sheet, the exact call ------------------------------------------------------------------------------

def test_a_changed_field_is_previewed_and_written_through_one_sheet_with_the_exact_call(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb)
    try:
        set_text(pg, "SessionTimeout", "5")
        assert diff(pg)[2] == ["SessionTimeout", "3", "5"] and "new" in pg.get_attribute("#set-card .diff > span:last-child", "class").split()
        assert pg.get_attribute("#set-write", "aria-disabled") is None and pg.get_attribute("#set-discard", "aria-disabled") is None
        pg.click("#set-write")
        got = sheet(pg)
        assert got["plain"] and not got["force"] and got["title"] == "Write kvm settings of my-server-1"
        assert got["say"].startswith("SessionTimeout changes from 3 to 5. The whole instance is read, merged, written and read back; if anything else changed, the call raises and the previous values are kept for revert. No password is sent from this form.")
        assert got["call"] == 'tools/call amt_configure {device: "my-server-1", area: "kvm", changes: {SessionTimeout: 5}, confirmed: true}'
        assert writes(fake_amt) == []                                                       # nothing is sent by opening the sheet
        confirm_plain(pg)
        wait_for(lambda: len(writes(fake_amt)) == 1, "the write")
        assert writes(fake_amt) == [{"device": KEY, "area": "kvm", "changes": {"SessionTimeout": 5}, "confirmed": True}]
        row = "#set-card [data-results=kvm] .result.ok"
        pg.wait_for_selector(row)
        assert "written and read back: {SessionTimeout: 5} · previous values kept for revert: {SessionTimeout: 3}" in text(pg, row)
        assert "other field(s) verified unchanged" in text(pg, row)
        wait_for(lambda: len(reads(fake_amt)) == 2, "the re-read after the write")
        idle(pg)
        assert diff(pg)[2] == ["SessionTimeout", "5", "5 (unchanged)"] and pg.input_value('[data-field="SessionTimeout"]') == "5"
        assert pg.query_selector(".sheet.open") is None and pg.errors == []
    finally:
        ctx.close()


def test_revert_writes_the_previous_values_back_through_its_own_sheet(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb)
    try:
        set_text(pg, "SessionTimeout", "9")
        pg.click("#set-write"); confirm_plain(pg)
        pg.wait_for_selector("[data-revert=kvm]")
        wait_for(lambda: len(reads(fake_amt)) == 2, "the re-read"); idle(pg)
        assert fake_amt.host.state["settings"]["SessionTimeout"] == 9
        pg.click("[data-revert=kvm]")
        got = sheet(pg)
        assert got["plain"] and got["title"] == "Revert kvm settings of my-server-1" and "Writes the previous values back: {SessionTimeout: 3}" in got["say"]
        assert got["call"] == 'tools/call amt_configure {device: "my-server-1", area: "kvm", changes: {SessionTimeout: 3}, confirmed: true}'
        confirm_plain(pg)
        wait_for(lambda: len(writes(fake_amt)) == 2, "the revert")
        assert writes(fake_amt)[1] == {"device": KEY, "area": "kvm", "changes": {"SessionTimeout": 3}, "confirmed": True} and fake_amt.host.state["settings"]["SessionTimeout"] == 3
        wait_for(lambda: len(reads(fake_amt)) == 3, "the re-read after the revert"); idle(pg)
        assert pg.input_value('[data-field="SessionTimeout"]') == "3"
        assert pg.get_attribute("[data-revert=kvm]", "aria-disabled") == "true" and "already reverted" in text(pg, "[data-results=kvm]")
    finally:
        ctx.close()


def test_a_change_that_weakens_access_names_what_it_does_on_the_sheet_and_stays_a_plain_confirm(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb)
    try:
        toggle(pg, "Is5900PortEnabled")
        pg.click("#set-write")
        got = sheet(pg)
        assert got["plain"] and not got["force"] and "THIS REQUEST opens the unencrypted VNC port 5900." in got["say"] and got["say"].startswith("Is5900PortEnabled changes from false to true.")
        assert got["call"] == 'tools/call amt_configure {device: "my-server-1", area: "kvm", changes: {Is5900PortEnabled: true}, confirmed: true}'
        pg.evaluate("() => window.__closeSheets()")
        toggle(pg, "OptInPolicy")
        pg.click("#set-write")
        got = sheet(pg)
        assert got["say"].count("THIS REQUEST") == 2 and "THIS REQUEST opens the unencrypted VNC port 5900." in got["say"] and "THIS REQUEST turns OFF user consent for remote KVM sessions." in got["say"]
        assert got["call"].endswith("changes: {Is5900PortEnabled: true, OptInPolicy: false}, confirmed: true}")
        pg.evaluate("() => window.__closeSheets()")
        toggle(pg, "Is5900PortEnabled"); toggle(pg, "OptInPolicy")                         # back to what AMT holds
        assert pg.get_attribute("#set-write", "aria-disabled") == "true" and text(pg, "#set-write ~ .reason") == "nothing changed"
        assert writes(fake_amt) == []
    finally:
        ctx.close()


@pytest.mark.parametrize("bad", ["abc", "-1", "3.5", "4294967296", "", " "])
def test_an_input_the_tool_would_refuse_never_opens_a_sheet_and_says_why(browser, sb, fake_amt, bad):
    ctx, pg = open_tab(browser, sb)
    try:
        set_text(pg, "SessionTimeout", bad)
        assert pg.get_attribute("#set-write", "aria-disabled") == "true" and text(pg, "#set-write ~ .reason") == "SessionTimeout must be a whole number from 0 to 4294967295"
        assert "err" in pg.get_attribute("#set-field-SessionTimeout", "class").split() and diff(pg)[2][2] == "invalid"
        pg.click("#set-write", force=True)
        assert pg.query_selector(".sheet.open") is None and writes(fake_amt) == [] and pg.evaluate("() => window.__callCount()") == 0
    finally:
        ctx.close()


def test_discard_returns_every_field_to_what_amt_holds_and_a_value_set_back_is_not_a_change(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb)
    try:
        assert pg.get_attribute("#set-discard", "aria-disabled") == "true" and text(pg, "#set-discard ~ .reason") == "nothing to discard"
        set_text(pg, "SessionTimeout", "7"); toggle(pg, "Is5900PortEnabled")
        pg.click("#set-discard")
        assert pg.input_value('[data-field="SessionTimeout"]') == "3" and pg.get_attribute('[data-field="Is5900PortEnabled"]', "aria-checked") == "false"
        set_text(pg, "SessionTimeout", "3")                                                 # typed, but the same as AMT holds
        assert pg.get_attribute("#set-write", "aria-disabled") == "true" and text(pg, "#set-write ~ .reason") == "nothing changed" and diff(pg)[2] == ["SessionTimeout", "3", "3 (unchanged)"]
        assert len(reads(fake_amt)) == 1 and writes(fake_amt) == []                           # Discard is local: no read, no write
    finally:
        ctx.close()


# -- the other writable areas: their fields, kinds and where their values sit in the read -------------------------------------------------

def test_network_carries_text_numbers_and_switches_and_sends_only_what_changed_in_the_tools_kinds(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb, area="network")
    try:
        assert reads(fake_amt)[-1] == {"device": KEY, "area": "network"}
        assert [r[0] for r in diff(pg)] == [n for n in amt_write.PUT_AREAS["network"].fields]
        assert pg.input_value('[data-field="HostName"]') == "my-server-1" and pg.input_value('[data-field="DDNSTTL"]') == "900"
        assert pg.get_attribute('[data-field="SharedFQDN"]', "aria-checked") == "true" and pg.get_attribute('[data-field="DDNSUpdateEnabled"]', "aria-checked") == "false"
        set_text(pg, "DDNSTTL", "1200"); set_text(pg, "HostName", "host-renamed"); toggle(pg, "DDNSUpdateEnabled")
        pg.click("#set-write")
        assert sheet(pg)["call"] == ('tools/call amt_configure {device: "my-server-1", area: "network", changes: {HostName: "host-renamed", DDNSUpdateEnabled: true, DDNSTTL: 1200}, confirmed: true}')
        confirm_plain(pg)
        wait_for(lambda: len(writes(fake_amt)) == 1, "the write")
        assert writes(fake_amt)[0]["changes"] == {"HostName": "host-renamed", "DDNSUpdateEnabled": True, "DDNSTTL": 1200}      # a string stays a string, a number a number, a flag a flag
        assert "DigestRealm" not in json.dumps(writes(fake_amt))                                # a device-owned field is never sent from here
        assert "ethernet_ports" in text(pg, "#sections-card") and "58:47:ca:00:00:01" in text(pg, "#sections-card")
    finally:
        ctx.close()


def test_a_host_name_the_tool_would_refuse_is_stopped_before_the_sheet(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb, area="network")
    try:
        set_text(pg, "HostName", "")
        assert text(pg, "#set-write ~ .reason") == "HostName must be 1 to 256 printable characters"
        set_text(pg, "HostName", "x" * 257)
        assert text(pg, "#set-write ~ .reason") == "HostName must be 1 to 256 printable characters"
        set_text(pg, "HostName", "fine"); set_text(pg, "DDNSTTL", "1.5")
        assert text(pg, "#set-write ~ .reason") == "DDNSTTL must be a whole number from 0 to 4294967295"
    finally:
        ctx.close()


def test_a_field_nobody_touched_is_not_judged_even_when_the_tools_value_is_empty(browser, sb, fake_amt):
    fake_amt.host.state["general"]["DomainName"] = ""
    ctx, pg = open_tab(browser, sb, area="network")
    try:
        set_text(pg, "DDNSTTL", "901")
        assert pg.get_attribute("#set-write", "aria-disabled") is None and diff(pg)[1] == ["DomainName", "empty", "empty (unchanged)"]
        pg.click("#set-write")
        assert sheet(pg)["call"].endswith("changes: {DDNSTTL: 901}, confirmed: true}")
    finally:
        ctx.close()


def test_internet_sends_a_list_of_lines_as_a_list(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb, area="internet")
    try:
        assert pg.input_value('[data-field="DetectionStrings"]') == "lan.example.test\ncorp.example.test" and pg.input_value('[data-field="DetectionAlgorithm"]') == "0"
        set_text(pg, "DetectionStrings", "lan.example.test\n\nnew.example.test\n")
        assert diff(pg)[1] == ["DetectionStrings", "lan.example.test, corp.example.test", "lan.example.test, new.example.test"]
        pg.click("#set-write")
        assert sheet(pg)["call"] == 'tools/call amt_configure {device: "my-server-1", area: "internet", changes: {DetectionStrings: ["lan.example.test", "new.example.test"]}, confirmed: true}'
        confirm_plain(pg)
        wait_for(lambda: len(writes(fake_amt)) == 1, "the write")
        assert writes(fake_amt)[0]["changes"] == {"DetectionStrings": ["lan.example.test", "new.example.test"]}
        wait_for(lambda: len(reads(fake_amt)) == 3, "the re-read"); idle(pg)
        set_text(pg, "DetectionStrings", "")
        assert text(pg, "#set-write ~ .reason") == "DetectionStrings must be 1 to 16 lines, each 1 to 256 printable characters"
    finally:
        ctx.close()


def test_security_uses_the_one_tls_instance_the_tool_writes_and_names_the_plaintext_risk(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb, area="security")
    try:
        assert pg.get_attribute('[data-field="AcceptNonSecureConnections"]', "aria-checked") == "false"      # the other TLS instance says true: it is not this one
        toggle(pg, "AcceptNonSecureConnections")
        pg.click("#set-write")
        assert "THIS REQUEST accepts non-TLS (plaintext) connections to AMT." in sheet(pg)["say"]
        confirm_plain(pg)
        wait_for(lambda: len(writes(fake_amt)) == 1, "the write")
        assert writes(fake_amt)[0] == {"device": KEY, "area": "security", "changes": {"AcceptNonSecureConnections": True}, "confirmed": True}
    finally:
        ctx.close()
    fake_amt.host.state["tls"] = [fake_amt.host.state["tls"][0]]                            # this AMT reports no such instance: nothing is offered
    ctx, pg = open_tab(browser, sb, area="security")
    try:
        assert pg.get_attribute('[data-field="AcceptNonSecureConnections"]', "aria-disabled") == "true" and diff(pg) == [["AcceptNonSecureConnections", "not reported", "not offered"]]
    finally:
        ctx.close()


def test_features_derive_their_state_from_the_two_redirection_reads_and_revert_by_previous(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb, area="features")
    try:
        assert [pg.get_attribute(f'[data-field="{n}"]', "aria-checked") for n in ("ider_enabled", "sol_enabled", "kvm_enabled")] == ["true", "false", "false"]
        toggle(pg, "sol_enabled")
        pg.click("#set-write")
        got = sheet(pg)
        assert "THIS REQUEST enables Serial-over-LAN." in got["say"] and "the states are read back" in got["say"] and "No password is sent from this form." in got["say"]
        assert got["call"] == 'tools/call amt_configure {device: "my-server-1", area: "features", changes: {sol_enabled: true}, confirmed: true}'
        confirm_plain(pg)
        pg.wait_for_selector("[data-revert=features]")
        assert "previous values kept for revert: {sol_enabled: false}" in text(pg, "[data-results=features]")
        wait_for(lambda: len(reads(fake_amt)) == 3, "the re-read"); idle(pg)         # 1 kvm on open, 1 features, 1 after the write
        assert pg.get_attribute('[data-field="sol_enabled"]', "aria-checked") == "true"
    finally:
        ctx.close()
    fake_amt.host.state["redirection_service"]["EnabledState"] = 99999                   # a state the tool's table does not know: ider and sol are not guessed
    ctx, pg = open_tab(browser, sb, area="features")
    try:
        assert [pg.get_attribute(f'[data-field="{n}"]', "aria-disabled") for n in ("ider_enabled", "sol_enabled", "kvm_enabled")] == ["true", "true", None]
    finally:
        ctx.close()


# -- immutable 7: a refusal in its own card, verbatim; the secret_field_refused text -----------------------------------------------------

def write_session_timeout(pg, fake, n=1, value="5"):
    set_text(pg, "SessionTimeout", value)
    pg.click("#set-write"); confirm_plain(pg)
    wait_for(lambda: len(writes(fake)) == n, f"write {n}")


def test_a_credential_named_field_the_tool_refuses_is_shown_verbatim_with_nothing_sent_and_the_identities_pointer(browser, sb, fake_amt):
    refusal = "Error executing tool amt_configure: secret_field_refused:AdminPassword"
    fake_amt.host.refuse = refusal
    ctx, pg = open_tab(browser, sb, area="network")
    try:
        set_text(pg, "HostName", "other")
        pg.click("#set-write"); confirm_plain(pg)
        row = "#set-card [data-results=network] .result.error"
        pg.wait_for_selector(row)
        note = text(pg, row)
        assert f"refused: {refusal} · nothing sent" in note and "Passwords come from Identities, never from a form here." in note
        pg.wait_for_timeout(300)
        assert len(reads(fake_amt)) == 2                                                        # the two area reads (kvm on open, network); a clear refusal re-reads nothing
        assert pg.query_selector("#set-card .result.ok") is None
    finally:
        ctx.close()


def test_the_real_tool_text_for_a_credential_field_is_what_the_page_pointer_matches(sb):
    with pytest.raises(ValueError) as ex:
        amt_write.validate_configure("kvm", {"RFBPassword": "x"})
    assert "secret_field_refused:RFBPassword" in str(ex.value)


@pytest.mark.parametrize("text_,sent,reread", [
    ("Error executing tool amt_configure: unknown_field:kvm:Bogus; writable: Is5900PortEnabled", "nothing sent", False),
    ("Error executing tool amt_configure: invalid_value:kvm.SessionTimeout:needs int", "nothing sent", False),
    ("Error executing tool amt_configure: users_user_exists:ops", "nothing sent", False),
    ("Error executing tool amt_configure: configure_readback_mismatch:kvm:SessionTimeout:previous={'SessionTimeout': 3}", "the write was sent and AMT's readback did not match", True),
    ("Error executing tool amt_configure: configure_collateral_change:kvm:OptInPolicy:was={'OptInPolicy': True}:the requested fields were applied", "the write was sent and AMT's readback did not match", True),
    ("Error executing tool amt_configure: wsman_fault:The server was unable to process the request", "the text does not say whether the host changed", True),
])
def test_a_refusal_says_only_what_its_text_lets_the_page_say_about_the_host(browser, sb, fake_amt, text_, sent, reread):
    fake_amt.host.refuse = text_
    ctx, pg = open_tab(browser, sb)
    try:
        write_session_timeout(pg, fake_amt)
        row = "#set-card [data-results=kvm] .result.error"
        pg.wait_for_selector(row)
        note = text(pg, row)
        assert f"refused: {text_}" in note and sent in note
        assert ("nothing sent" in note) == (not reread)                                          # "nothing sent" is only ever said when the text proves it
        pg.wait_for_timeout(600)
        assert len(reads(fake_amt)) == (2 if reread else 1)
    finally:
        ctx.close()


def test_a_tool_text_is_rendered_as_text_never_as_markup(browser, sb, fake_amt):
    nasty = '<img src=x onerror="window.__pwned=1"><b>x</b>'
    fake_amt.host.refuse = f"Error executing tool amt_configure: configure_readback_mismatch:kvm:{nasty}"
    fake_amt.host.state["settings"]["ElementName"] = nasty
    fake_amt.host.state["redirection_sap"] = {nasty: nasty}
    ctx, pg = open_tab(browser, sb)
    try:
        write_session_timeout(pg, fake_amt)
        pg.wait_for_selector("#set-card .result.error")
        assert nasty in text(pg, "#set-card .result.error") and pg.query_selector("#set-card .result.error b, #set-card .result.error img") is None
        wait_for(lambda: len(reads(fake_amt)) == 2, "the re-read"); idle(pg)
        assert nasty in text(pg, "#sections-card") and pg.query_selector("#sections-card img, #sections-card b") is None and pg.evaluate("() => window.__pwned === undefined")
    finally:
        ctx.close()


def open_routed(browser, console, path, handler, width=1024):
    ctx = browser.new_context(viewport={"width": width, "height": 900})
    ctx.add_cookies([{"name": "amt_console_session", "value": console.cookie, "domain": console.host, "path": "/", "httpOnly": True, "secure": True, "sameSite": "Strict"}])
    ctx.route(f"{console.origin}/api/call", handler)
    pg = ctx.new_page()
    pg.set_default_timeout(8000)
    pg.goto(f"{console.origin}{path}")
    return ctx, pg


def only(tool, status, code):
    """Answer a call to `tool` with a console-side failure and let every other call through."""
    def handler(route):
        body = route.request.post_data_json or {}
        if body.get("tool") == tool:
            route.fulfill(status=status, content_type="application/json", body=json.dumps({"error": code}))
        else:
            route.continue_()
    return handler


@pytest.mark.parametrize("status,code,says,unsure", [(502, "amt_mcp_unreachable:TimeoutError", "amt-mcp did not answer (amt_mcp_unreachable:TimeoutError) · it is not known whether the request was sent", True),
                                                      (503, "console_bearer_unavailable", "refused: console_bearer_unavailable · nothing sent", False),
                                                      (400, "device_not_named", "refused: device_not_named · nothing sent", False)])
def test_a_write_the_console_could_not_make_is_not_reported_as_a_refusal_by_the_tool(browser, sb, fake_amt, status, code, says, unsure):
    ctx, pg = open_routed(browser, sb, f"/server/{KEY}/settings", only("amt_configure", status, code))
    try:
        pg.wait_for_selector("#set-card"); idle(pg)
        set_text(pg, "SessionTimeout", "5")
        pg.click("#set-write"); confirm_plain(pg)
        pg.wait_for_selector("#set-card .result")
        note = text(pg, "#set-card .result")
        assert says in note and ("did not answer" in note) == unsure
        pg.wait_for_timeout(500)
        assert writes(fake_amt) == [] and len(reads(fake_amt)) == (2 if unsure else 1)          # amt-mcp saw no write; an unsure one re-reads
    finally:
        ctx.close()


# -- immutable 19: coverage from the result; a result the page cannot read offers nothing -------------------------------------------------

def test_the_coverage_banner_is_made_of_the_results_own_lists(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb)
    try:
        assert text(pg, "#set-banner") == "Coverage: All 3 sections of this area were read. Nothing was truncated." and pg.get_attribute("#set-banner", "class") == "banner"
    finally:
        ctx.close()
    fake_amt.host.truncated = ["CIM_KVMRedirectionSAP"]
    fake_amt.host.unavailable, fake_amt.host.reasons = ["IPS_OptInService"], {"IPS_OptInService": "No such class"}
    ctx, pg = open_tab(browser, sb)
    try:
        assert text(pg, "#set-banner") == ("Coverage: IPS_OptInService is unavailable: No such class, so its section is empty. "
                                           "CIM_KVMRedirectionSAP was cut at the item cap: more exist than were read.")
        assert "live" in pg.get_attribute("#set-banner", "class").split()
    finally:
        ctx.close()
    fake_amt.host.reasons = {}
    ctx, pg = open_tab(browser, sb)
    try:
        assert "IPS_OptInService is unavailable: the tool gave no reason, so its section is empty." in text(pg, "#set-banner")
    finally:
        ctx.close()


@pytest.mark.parametrize("drop,needle", [("unavailable", "unavailable"), ("truncated", "truncated"), ("sections", "sections"), ("classes", "classes"), ("area", "area")])
def test_a_result_missing_its_coverage_or_its_area_is_unreadable_and_offers_nothing_to_write(browser, sb, fake_amt, drop, needle):
    base = fake_amt.host.read
    fake_amt.results["amt_settings"] = lambda a: {k: v for k, v in base(a).items() if k != drop}
    ctx, pg = open_tab(browser, sb)
    try:
        note = text(pg, "#set-state .result.error")
        assert "cannot read" in note and needle in note and "nothing is offered to write" in note
        assert pg.is_hidden("#set-banner") and pg.query_selector("#set-card, #users-card") is None and pg.query_selector("#set-write") is None
    finally:
        ctx.close()


def test_a_result_for_another_area_or_with_a_section_missing_is_unreadable(browser, sb, fake_amt):
    base = fake_amt.host.read
    fake_amt.results["amt_settings"] = lambda a: dict(base(a), area="network")
    ctx, pg = open_tab(browser, sb)
    try:
        assert "missing or wrong: area" in text(pg, "#set-state .result.error") and pg.query_selector("#set-write") is None
    finally:
        ctx.close()
    fake_amt.results["amt_settings"] = lambda a: dict(base(a), sections={k: v for k, v in base(a)["sections"].items() if k != "settings"})
    ctx, pg = open_tab(browser, sb)
    try:
        assert "sections not returned: settings" in text(pg, "#set-state .result.error") and pg.query_selector("#set-write") is None
    finally:
        ctx.close()


def test_the_settings_tool_refusal_is_verbatim_text_in_its_own_card(browser, sb, fake_amt):
    fake_amt.results["amt_settings"] = lambda a: tool_error("Error executing tool amt_settings: wsman_fault:Not Found <i>x</i>")
    ctx, pg = open_tab(browser, sb)
    try:
        note = text(pg, "#set-state .result.error")
        assert "refused: Error executing tool amt_settings: wsman_fault:Not Found <i>x</i>" in note and "read-only" in note
        assert pg.query_selector("#set-state .result.error i") is None and pg.is_hidden("#set-banner") and pg.query_selector("#set-write") is None
    finally:
        ctx.close()


# -- the AMT accounts ------------------------------------------------------------------------------------------------------------------

def test_the_accounts_are_listed_as_read_and_the_admin_account_has_no_remove(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb, area="users")
    try:
        assert reads(fake_amt)[-1] == {"device": KEY, "area": "users"} and calls(fake_amt, "amt_identities")[-1] == {"device": KEY}
        assert text(pg, '[data-user="admin"]').startswith("admin") and "access 2 · realms 3, 4, 5 · the admin account is never changed here" in text(pg, '[data-user="admin"]')
        assert pg.query_selector('[data-user="admin"] button') is None
        assert "access 1 · realms 3" in text(pg, '[data-user="ops"]') and pg.get_attribute('[data-remove="ops"]', "aria-label") == "Remove ops"
        assert "sections-card" not in pg.content().split('id="users-card"')[0] and text(pg, "#set-banner") == "Coverage: The 1 section of this area was read. Nothing was truncated."
    finally:
        ctx.close()


def test_removing_an_account_is_a_sheet_with_the_exact_call_and_the_account_is_gone_after(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb, area="users")
    try:
        pg.click('[data-remove="ops"]')
        got = sheet(pg)
        assert got["plain"] and not got["force"] and got["title"] == "Remove the AMT user ops from my-server-1"
        assert got["say"] == f"The account is deleted from AMT. Anything authenticating as ops is refused from now on. The vault entry {KEY}-amt-user-ops stays until deleted in Identities."
        assert got["call"] == 'tools/call amt_configure {device: "my-server-1", area: "users", changes: {action: "remove", username: "ops"}, confirmed: true}'
        assert writes(fake_amt) == []
        confirm_plain(pg)
        wait_for(lambda: len(writes(fake_amt)) == 1, "the remove")
        assert writes(fake_amt) == [{"device": KEY, "area": "users", "changes": {"action": "remove", "username": "ops"}, "confirmed": True}]
        pg.wait_for_selector("[data-results=users] .result.ok")
        assert "revert: call amt_configure with the opposite action" in text(pg, "[data-results=users]") and pg.query_selector("[data-revert]") is None
        wait_for(lambda: len(reads(fake_amt)) == 3, "the re-read"); idle(pg)
        assert pg.query_selector('[data-user="ops"]') is None and pg.query_selector('[data-user="admin"]') is not None
    finally:
        ctx.close()


def type_user(pg, name, realms="3, 4", perm="2"):
    pg.fill("#user-name", name); pg.fill("#user-realms", realms); pg.select_option("#user-perm", perm)


def test_adding_an_account_needs_its_vaulted_identity_and_says_which_one_is_missing(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb, area="users")
    try:
        assert pg.get_attribute("#user-add", "aria-disabled") == "true" and text(pg, "#user-add ~ .reason") == "enter a user name"
        type_user(pg, "ghost")
        assert text(pg, "#user-entry") == f"{KEY}-amt-user-ghost" and text(pg, "#user-add ~ .reason") == f"identity {KEY}-amt-user-ghost is missing"
        assert pg.get_attribute("#users-card a.btn", "href") == "/manage" and "Create it" in text(pg, "#users-card a.btn")
        pg.click("#user-add", force=True)
        assert pg.query_selector(".sheet.open") is None and writes(fake_amt) == []
        type_user(pg, "viewer")
        assert pg.get_attribute("#user-add", "aria-disabled") is None and pg.query_selector("#user-add ~ .reason") is None
        assert "which must exist first" in text(pg, "#users-card .result")
    finally:
        ctx.close()


def test_adding_an_account_sends_the_name_the_access_and_the_realms_and_never_a_password(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb, area="users")
    try:
        type_user(pg, "viewer", realms="3, 4", perm="1")
        pg.click("#user-add")
        got = sheet(pg)
        assert got["plain"] and got["title"] == "Add the AMT user viewer to my-server-1"
        assert got["call"] == ('tools/call amt_configure {device: "my-server-1", area: "users", changes: {action: "add", username: "viewer", access_permission: 1, realms: [3, 4]}, confirmed: true}')
        assert f"vaulted identity {KEY}-amt-user-viewer: only the digest is sent to AMT, and no password is typed here" in got["say"]
        confirm_plain(pg)
        wait_for(lambda: len(writes(fake_amt)) == 1, "the add")
        assert writes(fake_amt)[0]["changes"] == {"action": "add", "username": "viewer", "access_permission": 1, "realms": [3, 4]}
        assert "password" not in json.dumps(writes(fake_amt)).lower()
        pg.wait_for_selector("[data-results=users] .result.ok")
        wait_for(lambda: len(reads(fake_amt)) == 3, "the re-read"); idle(pg)
        assert "access 1 · realms 3, 4" in text(pg, '[data-user="viewer"]')
        assert pg.query_selector("input[type=password], [autocomplete=new-password]") is None
    finally:
        ctx.close()


@pytest.mark.parametrize("name,realms,reason", [
    ("", "3", "enter a user name"), ("a" * 17, "3", "user name must be 1 to 16 of A-Z a-z 0-9 _ . @ -"), ("bad name", "3", "user name must be 1 to 16 of A-Z a-z 0-9 _ . @ -"),
    ("admin", "3", "the admin account is never changed here"), ("Admin", "3", "the admin account is never changed here"),
    ("viewer", "", "realms are numbers 0 to 31"), ("viewer", "32", "realms are numbers 0 to 31"), ("viewer", "x", "realms are numbers 0 to 31"), ("viewer", "3,,x", "realms are numbers 0 to 31")])
def test_an_account_the_tool_would_refuse_is_stopped_before_the_sheet(browser, sb, fake_amt, name, realms, reason):
    ctx, pg = open_tab(browser, sb, area="users")
    try:
        type_user(pg, name, realms)
        assert pg.get_attribute("#user-add", "aria-disabled") == "true" and text(pg, "#user-add ~ .reason") == reason
        pg.click("#user-add", force=True)
        assert pg.query_selector(".sheet.open") is None and writes(fake_amt) == []
    finally:
        ctx.close()


def test_an_unreadable_identity_list_leaves_add_disabled_and_says_so(browser, sb, fake_amt):
    fake_amt.results["amt_identities"] = lambda a: tool_error("Error executing tool amt_identities: vault_unavailable")
    ctx, pg = open_tab(browser, sb, area="users")
    try:
        type_user(pg, "viewer")
        assert text(pg, "#user-add ~ .reason").startswith("identities could not be read (Error executing tool amt_identities: vault_unavailable)")
        assert pg.query_selector('[data-remove="ops"]') is not None                                 # removing needs no identity
    finally:
        ctx.close()


def test_an_account_refusal_by_the_tool_is_verbatim_and_a_duplicate_says_nothing_was_sent(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb, area="users")
    try:
        type_user(pg, "viewer")
        fake_amt.host.state["users"].append({"DigestUsername": "viewer", "AccessPermission": 2, "Realms": [3]})   # it appeared since the page read
        pg.click("#user-add"); confirm_plain(pg)
        pg.wait_for_selector("[data-results=users] .result.error")
        assert f"refused: Error executing tool amt_configure: users_user_exists:viewer · nothing sent" in text(pg, "[data-results=users] .result.error")
    finally:
        ctx.close()


# -- the four read-only areas ----------------------------------------------------------------------------------------------------------

@pytest.mark.parametrize("area,section", [("agent_presence", "watchdogs"), ("system_defense", "policies"), ("subscriptions", "filter_subscriptions"), ("wake_alarms", "occurrences")])
def test_a_read_only_area_is_read_shown_as_returned_and_points_at_the_advanced_templates(browser, sb, fake_amt, area, section):
    ctx, pg = open_tab(browser, sb)
    try:
        assert "dashed" in pg.get_attribute(f'[data-area="{area}"]', "class").split()
        choose(pg, area)
        assert reads(fake_amt)[-1] == {"device": KEY, "area": area}
        assert text(pg, "#set-card h2") == f"{area} · read-only here" and section in text(pg, "#set-card")
        assert pg.get_attribute("#set-card a", "href") == f"/server/{KEY}/wsman" and f"amt_configure has no {area} area" in text(pg, "#set-card")
        assert pg.query_selector("#set-write, #set-card [role=switch], #set-card input, #set-card textarea") is None
        assert pg.evaluate("() => window.__callCount()") == 0 and writes(fake_amt) == []
    finally:
        ctx.close()


def test_switching_areas_reads_the_chosen_area_and_a_slow_read_of_the_old_one_is_dropped(browser, sb, fake_amt):
    import threading
    gates = {"kvm": threading.Event(), "network": threading.Event()}
    base = fake_amt.host.read
    fake_amt.results["amt_settings"] = lambda a: (gates[a["area"]].wait(10), base(a))[1] if a["area"] in gates else base(a)
    ctx, pg = open_page(browser, sb, f"/server/{KEY}/settings")
    pg.set_default_timeout(8000)
    try:
        wait_for(lambda: len(reads(fake_amt)) == 1, "the open-read")
        pg.click('[data-area="network"]')                                            # the operator moves on while kvm is still out
        gates["kvm"].set()
        wait_for(lambda: len(reads(fake_amt)) == 2, "the read of the chosen area")
        pg.wait_for_timeout(300)                                                      # kvm's answer has arrived; network's has not
        assert pg.query_selector("#set-card") is None and pg.query_selector("#set-state .progress") is not None, "the dropped answer was drawn"
        gates["network"].set()
        pg.wait_for_selector('#set-card[data-area="network"]')
        idle(pg)
        assert [r["area"] for r in reads(fake_amt)] == ["kvm", "network"] and pg.get_attribute('[data-area="network"]', "aria-pressed") == "true"
    finally:
        for g in gates.values():
            g.set()
        ctx.close()


# -- immutable 7: a refused credential pauses the server and the page reads no more -------------------------------------------------------

def test_a_refused_credential_in_a_write_pauses_the_server_and_the_page_offers_and_reads_no_more(browser, sb, fake_amt):
    fake_amt.host.refuse = "Error executing tool amt_configure: wsman_auth_failed_401"
    ctx, pg = open_tab(browser, sb)
    try:
        write_session_timeout(pg, fake_amt)
        pg.wait_for_selector("#set-paused:not([hidden])")
        assert "Reading is paused for this server (credential refused)" in text(pg, "#set-paused") and pg.get_attribute("#set-paused a", "href") == f"/server/{KEY}"
        assert sb.app.fleet.public(KEY)["state"] == "paused"
        note = text(pg, "#set-card .result.error")
        assert "refused: Error executing tool amt_configure: wsman_auth_failed_401" in note
        assert pg.get_attribute("#set-reread", "aria-disabled") == "true" and text(pg, "#set-reread ~ .reason") == "paused · credential refused"
        assert pg.get_attribute("#set-write", "aria-disabled") == "true" and text(pg, "#set-write ~ .reason") == "paused · credential refused"
        pg.wait_for_timeout(500)
        assert len(reads(fake_amt)) == 1
        status_before = len(calls(fake_amt, "amt_status"))
        bump = [0]
        sb.app.fleet.now = lambda: time.time() + bump[0]
        for _ in range(3):
            bump[0] += 31
            assert sb.app.fleet.step() is None
        assert len(calls(fake_amt, "amt_status")) == status_before
    finally:
        ctx.close()


def test_a_page_opened_on_a_paused_server_reads_nothing_and_offers_no_write(browser, sb, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("Error executing tool amt_status: wsman_auth_failed_401")
    sb.app.fleet.refresh(KEY)
    assert sb.app.fleet.public(KEY)["state"] == "paused"
    ctx, pg = open_tab(browser, sb, ready=False)
    try:
        pg.wait_for_selector("#set-paused:not([hidden])")
        pg.wait_for_timeout(400)
        assert reads(fake_amt) == [] and pg.get_attribute("#set-reread", "aria-disabled") == "true" and text(pg, "#set-reread ~ .reason") == "paused · credential refused"
        pg.click('[data-area="users"]'); pg.wait_for_timeout(300)
        assert reads(fake_amt) == [] and "Retry once from the Status tab" in text(pg, "#set-paused")
    finally:
        ctx.close()


def test_a_page_is_read_when_it_opens_and_when_asked_never_on_a_timer(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb)
    try:
        assert len(reads(fake_amt)) == 1
        pg.wait_for_timeout(5600)                                                       # past the page's own 5 s refresh of the cached state
        assert len(reads(fake_amt)) == 1
        press(pg, "#set-reread", fake_amt, 2)
    finally:
        ctx.close()


def test_one_activation_is_one_read_and_the_control_says_why_it_waits(browser, sb, fake_amt):
    import threading
    gate = threading.Event()
    base = fake_amt.host.read
    fake_amt.results["amt_settings"] = lambda a: (gate.wait(10), base(a))[1]
    ctx, pg = open_page(browser, sb, f"/server/{KEY}/settings")
    pg.set_default_timeout(8000)
    try:
        wait_for(lambda: len(reads(fake_amt)) == 1, "the open-read")
        assert pg.get_attribute("#set-reread", "aria-disabled") == "true" and text(pg, "#set-reread ~ .reason") == "waiting for amt-mcp"
        for _ in range(3):
            pg.click("#set-reread", force=True)
        pg.wait_for_timeout(200)
        assert len(reads(fake_amt)) == 1
        gate.set()
        pg.wait_for_selector(READY); idle(pg)
        assert len(reads(fake_amt)) == 1
    finally:
        gate.set()
        ctx.close()


@pytest.mark.parametrize("status,code,says", [(502, "amt_mcp_unreachable:TimeoutError", "amt-mcp did not answer (amt_mcp_unreachable:TimeoutError)"),
                                              (503, "console_bearer_unavailable", "refused: console_bearer_unavailable · nothing sent"),
                                              (400, "device_not_named", "refused: device_not_named · nothing sent")])
def test_a_read_the_console_could_not_make_is_not_reported_as_a_refusal_by_the_tool(browser, sb, fake_amt, status, code, says):
    ctx, pg = open_routed(browser, sb, f"/server/{KEY}/settings", only("amt_settings", status, code))
    try:
        pg.wait_for_selector("#set-state .result")
        note = text(pg, "#set-state .result")
        assert says in note and ("did not answer" in note) == (status == 502)
        assert pg.query_selector("#set-card") is None and pg.query_selector("#set-write") is None
    finally:
        ctx.close()
    assert reads(fake_amt) == []


# ============================== immutables 4, 5 and 9 on this page ====================================================================

SWEEP = """() => {
  const ctrls = () => Array.from(document.querySelectorAll('#set-cards button, #set-cards [role=switch], #set-cards a[href], #set-cards select, #set-state button, [data-results] button'))
    .filter(el => !el.closest('.sheet'));
  document.addEventListener('click', e => { const a = e.target.closest('a[href]'); if (a) e.preventDefault(); }, true);
  const n = ctrls().length;
  for (let i = 0; i < n; i++) { const el = ctrls()[i]; if (el) el.click(); window.__closeSheets(); }
  return n;
}"""


@pytest.mark.parametrize("area", ["kvm", "network", "internet", "security", "features", "users", "agent_presence"])
def test_a_bare_click_on_any_control_of_any_area_sends_no_write_and_opens_no_hold(browser, sb, fake_amt, area):
    """Immutable 4 for this page: every control outside a sheet, clicked, sends no write and fires no force control; a control that opens a sheet is a
    plain confirmation. The reads the chips and Re-read make are not writes."""
    ctx, pg = open_tab(browser, sb, area=area)
    try:
        n = pg.evaluate(SWEEP)
        assert n >= (1 if area == "agent_presence" else 2), f"the sweep saw {n} controls: it would pass on an empty page"
        pg.wait_for_timeout(300)
        assert pg.evaluate("() => window.__callCount()") == 0 and pg.evaluate("() => window.__forceFireCount()") == 0 and pg.query_selector(".sheet.open") is None
        assert pg.query_selector(".sheet[data-force-sheet], .force-control") is None
    finally:
        ctx.close()
    assert writes(fake_amt) == []
    assert [t for t, a, _ in fake_amt.calls if t in WRITE_TOOLS and a.get("action") not in ("status", "list")] == []


def build_every_sheet(pg, fake):
    """A write sheet (kvm), a revert sheet (after a real write to the fake), a remove sheet and an add sheet: all four in the document."""
    set_text(pg, "SessionTimeout", "5")
    pg.click("#set-write"); confirm_plain(pg)
    pg.wait_for_selector("[data-revert=kvm]")
    wait_for(lambda: len(reads(fake)) == 2, "the re-read"); idle(pg)
    pg.click("[data-revert=kvm]"); pg.evaluate("() => window.__closeSheets()")
    set_text(pg, "SessionTimeout", "6")
    pg.click("#set-write"); pg.evaluate("() => window.__closeSheets()")
    choose(pg, "users")
    pg.click('[data-remove="ops"]'); pg.evaluate("() => window.__closeSheets()")
    type_user(pg, "viewer")
    pg.click("#user-add"); pg.evaluate("() => window.__closeSheets()")
    assert pg.eval_on_selector_all(".sheet[data-confirm-sheet]", "ss => ss.map(s => s.id).sort()") == ["set-revert-sheet", "set-user-add", "set-user-remove", "set-write-sheet"]


def test_every_plain_confirm_sheet_of_the_page_sends_one_call_and_manages_focus(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb)
    try:
        build_every_sheet(pg, fake_amt)
        before = len(writes(fake_amt))
        checks = check_mockups().confirm_checks(pg)
        assert len(checks) == 4, checks
        for c in checks:
            assert c["click"] == 1 and c["enter_held"] == 1, c                    # one activation, one request
            assert c["focus_key"] == {"inSheet": True, "isCancel": True} and c["focus_ptr"] and c["trapped"], c
        wait_for(lambda: len(writes(fake_amt)) == before + 8, "the eight confirmed calls reach the fake")
    finally:
        ctx.close()


def test_no_call_this_page_sends_satisfies_the_destructive_predicate_and_the_predicates_controls_hold(browser, sb, fake_amt):
    """Immutable 5: the destructive set is decided by the call's arguments. Nothing amt_configure can send is in it, so every sheet here is plain and no
    sent call was preceded by a force fire; the controls show the predicate itself still bites on the calls it exists for."""
    ctx, pg = open_tab(browser, sb)
    try:
        build_every_sheet(pg, fake_amt)
        spy = pg.evaluate("() => window.__calls().map(c => ({ forced: c.forced, destructive: window.__destructiveCall({ tool: c.tool, arguments: c.arguments, then: c.then }, c.ctx), tool: c.tool }))")
        assert len(spy) == 1 and spy[0] == {"forced": False, "destructive": False, "tool": "amt_configure"}
        assert pg.evaluate("() => window.__forceFireCount()") == 0
        controls = pg.evaluate("""() => [
          window.__destructiveCall({ tool: 'amt_configure', arguments: { area: 'kvm', changes: { OptInPolicy: false, Is5900PortEnabled: true } } }),
          window.__destructiveCall({ tool: 'amt_configure', arguments: { area: 'users', changes: { action: 'remove', username: 'ops' } } }),
          window.__destructiveCall({ tool: 'amt_wsman_invoke', arguments: { operation: 'invoke', class_name: 'AMT_SetupAndConfigurationService', method: 'Unprovision' } }),
          window.__destructiveCall({ tool: 'amt_wsman_invoke', arguments: { operation: 'invoke', class_name: 'IPS_OptInService', method: 'StartOptIn' } })]""")
        assert controls == [False, False, True, False]
    finally:
        ctx.close()


def test_no_password_is_a_field_or_an_argument_on_this_page(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb)
    try:
        build_every_sheet(pg, fake_amt)
        for area in ("kvm", "users", "network"):
            choose(pg, area)
            body = pg.content()
            assert 'type="password"' not in body and "new-password" not in body and pg.query_selector("input[type=password], [autocomplete=new-password]") is None
        assert "password" not in json.dumps(writes(fake_amt)).lower()
        sent = pg.evaluate("() => window.__calls().map(c => JSON.stringify(c.arguments))")
        assert sent and not [s for s in sent if "assword" in s]
    finally:
        ctx.close()


# ============================== layout, contrast and the outside world ================================================================

def stage_results(pg, fake):
    """A written-and-read-back row with its Revert, and a refused row, so the walk sees both states."""
    set_text(pg, "SessionTimeout", "5")
    pg.click("#set-write"); confirm_plain(pg)
    pg.wait_for_selector("[data-results=kvm] .result.ok")
    wait_for(lambda: len(reads(fake)) == 2, "the re-read"); idle(pg)
    fake.host.refuse = "Error executing tool amt_configure: secret_field_refused:AdminPassword"
    set_text(pg, "SessionTimeout", "6")
    pg.click("#set-write"); confirm_plain(pg)
    pg.wait_for_selector("[data-results=kvm] .result.error")


@pytest.mark.parametrize("area", ["kvm", "users"])
@pytest.mark.parametrize("width", WIDTHS)
def test_the_page_fits_every_width_with_hit_areas_and_a_16_px_gutter(browser, sb, fake_amt, area, width):
    cm = check_mockups()
    ctx, pg = open_tab(browser, sb, width=width)
    try:
        if area == "kvm":
            stage_results(pg, fake_amt)
        else:
            choose(pg, "users")
            type_user(pg, "viewer")
        pg.wait_for_timeout(300)
        r = pg.evaluate(cm.JS_WALK)
        bottom, anim = pg.evaluate(cm.JS_BOTTOM), pg.evaluate(cm.JS_ANIMATED)
        bad = []
        if r["scrollWidth"] > r["inner"]: bad.append(("overflow", r["scrollWidth"], r["inner"]))
        if r["gutter"] is not None and r["gutter"] != 16: bad.append(("gutter", r["gutter"]))
        if r["currentTab"] and not r["currentTab"]["ok"]: bad.append(("current-tab", r["currentTab"]))
        bad += [("letter-wrapped", x) for x in r["narrow"]]
        if width < 600: bad += [("control-offscreen", x) for x in r["offscreen"]]
        bad += [("fixed-over-control", x) for x in r["fixedOverlap"]] + [("under-bottom-bar", x) for x in bottom]
        bad += [("animated-without-data-motion", x) for x in anim["missing"]]
        if width in cm.PHONE_HEIGHT_CEILING and r["docHeight"] > cm.PHONE_HEIGHT_CEILING[width]: bad.append(("page-height", r["docHeight"]))
        for t in r["targets"]:
            if not ((t["w"] >= 48 and t["h"] >= 48) or (t["chip"] and t["w"] >= 24 and t["h"] >= 24)): bad.append(("target", t))
        assert bad == [], bad
        assert len(r["targets"]) >= 12 and r["text"], "the walk saw nothing: it would pass on an empty page"
        assert pg.errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("area", ["kvm", "users"])
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_every_text_and_ring_on_the_page_clears_the_contrast_floors(browser, sb, fake_amt, area, scheme):
    cm = check_mockups()
    ctx, pg = open_tab(browser, sb, scheme=scheme)
    try:
        if area == "kvm":
            stage_results(pg, fake_amt)
            toggle(pg, "Is5900PortEnabled")                                                # the warning line in the error colour, and a changed row in the preview
        else:
            choose(pg, "users")
            type_user(pg, "ghost")
        pg.wait_for_timeout(250)
        r = pg.evaluate(cm.JS_WALK)
        low = [(t["snippet"], t["ratio"], t["ex"]) for t in r["text"] if t["ratio"] < (3.0 if t["large"] else 4.5)]
        rings = [(x["ex"], x["ratio"]) for x in r["rings"] if x["ratio"] < 3.0 and x["ex"].split(".")[0] in ("button", "a", "input", "select", "textarea")]
        assert low == [], low
        assert rings == [], rings
        assert len(r["text"]) > 40, "the walk saw too little text: it would pass on an empty page"
        assert pg.errors == []
    finally:
        ctx.close()


def test_the_page_loads_nothing_from_outside_the_console_and_never_touches_amt_mcp(browser, sb, fake_amt):
    ctx, pg = open_tab(browser, sb)
    try:
        origins = {u.split("/")[0] + "//" + u.split("/")[2] for u in pg.requests if u.startswith("http")}
        assert origins == {sb.origin}, origins
        assert not [u for u in pg.requests if fake_amt.base in u or u.endswith("/mcp")]
        body = pg.content()
        assert "type=\"password\"" not in body and "handoffs/" not in body
    finally:
        ctx.close()


# -- smaller guards, each pinned by a test that was shown to fail with its branch broken -------------------------------------------------

def test_a_previous_value_the_tool_did_not_report_leaves_the_result_without_a_revert(browser, sb, fake_amt):
    base = fake_amt.host.configure
    fake_amt.results["amt_configure"] = lambda a: dict(base(a), previous={"SessionTimeout": None})
    ctx, pg = open_tab(browser, sb)
    try:
        write_session_timeout(pg, fake_amt)
        pg.wait_for_selector("[data-results=kvm] .result.ok")
        assert "previous values kept for revert: {SessionTimeout: null}" in text(pg, "[data-results=kvm]")
        assert pg.query_selector("[data-revert]") is None
    finally:
        ctx.close()


def test_while_a_write_is_out_nothing_else_is_sent_and_every_control_says_why(browser, sb, fake_amt):
    import threading
    gate = threading.Event()
    base = fake_amt.host.configure
    fake_amt.results["amt_configure"] = lambda a: (gate.wait(10), base(a))[1]
    ctx, pg = open_tab(browser, sb)
    try:
        set_text(pg, "SessionTimeout", "5")
        pg.click("#set-write"); confirm_plain(pg)
        wait_for(lambda: len(writes(fake_amt)) == 1, "the write")
        assert pg.get_attribute("#set-write", "aria-disabled") == "true" and text(pg, "#set-write ~ .reason") == "waiting for amt-mcp"
        assert pg.get_attribute("#set-reread", "aria-disabled") == "true" and text(pg, "#set-reread ~ .reason") == "waiting for amt-mcp"
        pg.click("#set-write", force=True); pg.click("#set-reread", force=True); pg.wait_for_timeout(200)
        assert pg.query_selector(".sheet.open") is None and len(writes(fake_amt)) == 1 and len(reads(fake_amt)) == 1
        gate.set()
        pg.wait_for_selector("[data-results=kvm] .result.ok")
        wait_for(lambda: len(reads(fake_amt)) == 2, "the re-read")
    finally:
        gate.set()
        ctx.close()


def test_a_single_detection_string_arrives_as_a_bare_string_and_is_one_line(browser, sb, fake_amt):
    fake_amt.host.state["environment_detection"]["DetectionStrings"] = "only.example.test"      # one repeated element comes back as a bare string
    ctx, pg = open_tab(browser, sb, area="internet")
    try:
        assert pg.input_value('[data-field="DetectionStrings"]') == "only.example.test" and diff(pg)[1] == ["DetectionStrings", "only.example.test", "only.example.test (unchanged)"]
        set_text(pg, "DetectionStrings", "only.example.test\nsecond.example.test")
        pg.click("#set-write")
        assert sheet(pg)["call"].endswith('changes: {DetectionStrings: ["only.example.test", "second.example.test"]}, confirmed: true}')
    finally:
        ctx.close()


def test_a_users_result_that_is_not_a_list_is_unreadable(browser, sb, fake_amt):
    base = fake_amt.host.read
    fake_amt.results["amt_settings"] = lambda a: dict(base(a), sections={"users": {"DigestUsername": "ops"}}) if a["area"] == "users" else base(a)
    ctx, pg = open_tab(browser, sb, area="users")
    try:
        assert "users is not a list" in text(pg, "#set-state .result.error") and pg.query_selector("#users-card") is None
    finally:
        ctx.close()


# -- review fixes (C6b): a held-back read, the risk lines, the revert guard, the tool's own idea of printable ------------------------------------

def test_an_area_chosen_while_a_write_is_out_is_read_when_the_write_ends_in_a_refusal_that_needs_no_re_read(browser, sb, fake_amt):
    import threading
    gate = threading.Event()
    base = fake_amt.host.configure
    fake_amt.results["amt_configure"] = lambda a: (gate.wait(10), base(a))[1]
    fake_amt.host.refuse = "Error executing tool amt_configure: invalid_value:kvm.SessionTimeout:needs int"
    ctx, pg = open_tab(browser, sb)
    try:
        write_session_timeout_no_wait(pg)
        wait_for(lambda: len(writes(fake_amt)) == 1, "the write")
        pg.click('[data-area="network"]')
        pg.wait_for_timeout(200)
        assert len(reads(fake_amt)) == 1                                                       # nothing is sent while the write is out
        gate.set()
        pg.wait_for_selector('#set-card[data-area="network"]')
        assert len(reads(fake_amt)) == 2 and reads(fake_amt)[1]["area"] == "network"           # one read of the area chosen, no second one
        pg.wait_for_timeout(400)
        assert len(reads(fake_amt)) == 2
    finally:
        gate.set()
        ctx.close()


def test_an_area_chosen_while_a_write_is_out_is_read_once_when_the_write_succeeds(browser, sb, fake_amt):
    import threading
    gate = threading.Event()
    base = fake_amt.host.configure
    fake_amt.results["amt_configure"] = lambda a: (gate.wait(10), base(a))[1]
    ctx, pg = open_tab(browser, sb)
    try:
        write_session_timeout_no_wait(pg)
        wait_for(lambda: len(writes(fake_amt)) == 1, "the write")
        pg.click('[data-area="network"]')
        gate.set()
        pg.wait_for_selector('#set-card[data-area="network"]')
        pg.wait_for_timeout(600)
        assert [r["area"] for r in reads(fake_amt)] == ["kvm", "network"]                        # the write's own re-read is the read of the area chosen: not a second one
    finally:
        gate.set()
        ctx.close()


def write_session_timeout_no_wait(pg, value="5"):
    set_text(pg, "SessionTimeout", value)
    pg.click("#set-write"); confirm_plain(pg)


def test_a_change_in_the_safe_direction_carries_no_risk_line(browser, sb, fake_amt):
    state = fake_amt.host.state
    state["settings"]["OptInPolicy"], state["settings"]["Is5900PortEnabled"] = False, True    # both currently the risky way round
    state["tls"][1]["AcceptNonSecureConnections"] = True
    for area, fields in (("kvm", ("OptInPolicy", "Is5900PortEnabled")), ("security", ("AcceptNonSecureConnections",)), ("features", ("ider_enabled",))):
        ctx, pg = open_tab(browser, sb, area=area)
        try:
            for f in fields:
                toggle(pg, f)
            pg.click("#set-write")
            got = sheet(pg)
            assert got["plain"] and "THIS REQUEST" not in got["say"], (area, got["say"])
        finally:
            ctx.close()


def test_a_previous_value_object_with_nothing_in_it_leaves_the_result_without_a_revert(browser, sb, fake_amt):
    base = fake_amt.host.configure
    fake_amt.results["amt_configure"] = lambda a: dict(base(a), previous={})
    ctx, pg = open_tab(browser, sb)
    try:
        write_session_timeout(pg, fake_amt)
        pg.wait_for_selector("[data-results=kvm] .result.ok")
        assert pg.query_selector("[data-revert]") is None
    finally:
        ctx.close()


@pytest.mark.parametrize("value", ["a b", "a b", "a b", "a​b", "a­b", "ab", "a͸b", "a\tb", "a\x7fb", "a b", "café", "á", "\U0001f600" * 256, "\U0001f600" * 257, " ", " "])
def test_the_page_judges_a_text_as_the_tool_does(browser, sb, fake_amt, value):
    try:
        amt_write._check_value("network", "HostName", "str", value)
        expected = True
    except ValueError:
        expected = False
    ctx, pg = open_tab(browser, sb, area="network")
    try:
        set_text(pg, "HostName", value)
        refused = "err" in pg.get_attribute("#set-field-HostName", "class").split()
        assert (pg.get_attribute("#set-write", "aria-disabled") == "true") == refused
        assert refused == (not expected), repr(value)
    finally:
        ctx.close()
