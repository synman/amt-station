"""The Logs and Inventory tabs (packet C6, the logs and inventory half): the event and audit logs through amt_logs with a time window, a
severity filter, the tool's own counts and paging; the hardware inventory through amt_inventory with its coverage banner and an export.

Every amt-mcp answer is scripted (console_fakes.FakeAmt); no test reaches a host. The scripted log answers like the tool (window, newest first,
offset and limit, the counts), so paging is real. Immutables 4 (these pages write nothing), 7 (a refusal in its own card, a refused credential
pauses the server and is not read again), 19 (coverage from the result; an empty page is not an empty log), plus 13, 14 and 1 on the built pages."""
import asyncio
import json
import re
import time
from datetime import datetime, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

import pytest

import amt_tools
import mcp_client
from console_fakes import Authenticator, Console, check_mockups, enroll_first_passkey
from test_console_fleet import KEY, STATUS, device, tool_error, fc, me, settle, calls  # noqa: F401 - fixtures
from test_console_fleet_browser import open_page, text

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed: the browser immutables are NOT checked")

CONSOLE = Path(__file__).resolve().parent.parent
BASE = 1_792_000_000                                        # a fixed "now" for the scripted logs (2026-10)
WIDTHS = [360, 600, 1024, 1440]
WRITE_TOOLS = {name for name, (_, read_only) in mcp_client.TOOLS.items() if not read_only}


def iso(epoch):
    return datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if epoch else None


def eastern(epoch):
    t = datetime.fromtimestamp(epoch, ZoneInfo("America/New_York"))
    return t.strftime("%Y-%m-%d %H:%M:%S ") + t.tzname()


# -- a scripted log that answers like amt_tools.logs --------------------------------------------------------------------------------

SEVERITY = {"info": ("Information", 0), "warning": ("Non-critical", 8), "critical": ("Critical", 16)}


def event(i, level="info", epoch="auto", **over):
    epoch = BASE - i * 600 if epoch == "auto" else epoch
    name, code = SEVERITY[level]
    rec = {"epoch": epoch, "timestamp": iso(epoch), "description": f"Event {i}: thermal reading", "source": "Processor", "severity": name, "level": level,
           "event_data": [0, 1, 0, 0, 0, 0, 0, 0], "device_address": 32, "sensor_type": 7, "event_type": 2, "event_offset": 0, "source_type": 3,
           "severity_code": code, "sensor_number": 1, "entity": 3, "entity_instance": 0, "event_data_hex": "0001000000000000",
           "raw_hex": "00" * 21, "decoded": True}
    rec.update(over)
    return rec


def audit(i, epoch="auto", **over):
    epoch = BASE - i * 600 if epoch == "auto" else epoch
    rec = {"epoch": epoch, "timestamp": iso(epoch), "app": "Redirection manager", "event": f"KVM session started #{i}", "initiator_kind": "digest",
           "initiator": "admin", "extended_data": "ip 10.0.0.24", "extended_data_hex": "0a973318", "app_id": 16, "event_id": 3, "initiator_type": 0,
           "mc_location_type": 1, "net_address": "10.0.0.24", "raw_hex": "00" * 30, "decoded": True}
    rec.update(over)
    return rec


def level_of(i):
    return "critical" if i % 10 == 0 else "warning" if i % 5 == 0 else "info"


def mixed_events(n=209, undated=3):
    return [event(i, level_of(i)) for i in range(n)] + [event(1000 + k, epoch=None, timestamp=None) for k in range(undated)]


class Log:
    """amt_tools.logs over a fixed list of decoded records: the window drops the undated, newest first, then offset and limit."""

    def __init__(self, records, kind="event", complete=True):
        self.records, self.kind, self.complete = records, kind, complete
        self.asked = []

    @staticmethod
    def when(label, value):
        if value is None or not value.strip():
            return None
        try:
            dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
        except ValueError:
            raise ValueError(f"invalid_{label}:expected ISO-8601 like 2026-10-17T00:00:00Z") from None
        return int((dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)).timestamp())

    def __call__(self, a):
        self.asked.append(a)
        try:
            lo, hi = self.when("since", a.get("since")), self.when("until", a.get("until"))
        except ValueError as ex:
            return tool_error(f"Error executing tool amt_logs: {ex}")
        rows = [dict(r, index=i) for i, r in enumerate(self.records)]
        undecodable = sum(1 for r in rows if not r["decoded"])
        undated = sum(1 for r in rows if r["epoch"] is None)
        if lo is not None or hi is not None:
            rows = [r for r in rows if r["epoch"] is not None and (lo is None or r["epoch"] >= lo) and (hi is None or r["epoch"] <= hi)]
        rows.sort(key=lambda r: (r["epoch"] or 0, r["index"]), reverse=True)
        page = rows[a.get("offset", 0):a.get("offset", 0) + a.get("limit", 50)]
        return {"device": a["device"], "kind": a["kind"], "fetched": len(self.records), "fetch_complete": self.complete, "undecodable": undecodable,
                "undated": undated, "matched": len(rows), "offset": a.get("offset", 0), "limit": a.get("limit", 50), "returned": len(page), "records": page}


def inventory_result(**over):
    out = {"device": KEY, "sections": {
        "chassis": [{"Manufacturer": "Minisforum", "Model": "MS-02 Ultra", "SerialNumber": "MSU2-0421-7788", "ChassisPackageType": 35}],
        "baseboard": [{"Product": "MS-02-U", "Version": "1.0", "SerialNumber": "BB-7781-2201"}],
        "bios": [{"Manufacturer": "American Megatrends", "Version": "1.08", "ReleaseDate": "2026-06-12", "PrimaryBIOS": True}],
        "processors": [{"DeviceID": "CPU 0", "MaxClockSpeed": 5400, "CurrentClockSpeed": 2800, "Family": 198}],
        "memory": [{"BankLabel": "BANK 0", "Capacity": 51539607552, "Speed": 5600, "SerialNumber": "00012345"},
                   {"BankLabel": "BANK 1", "Capacity": 51539607552, "Speed": 5600, "SerialNumber": "00067890"}],
        "storage_media": [{"DeviceID": "Media 0", "MaxMediaSize": 2000398934016}, {"DeviceID": "Media 1", "MaxMediaSize": 4000787030016}]},
        "classes": {"chassis": "CIM_Chassis", "baseboard": "CIM_Card", "bios": "CIM_BIOSElement", "processors": "CIM_Processor", "memory": "CIM_PhysicalMemory",
                    "storage_media": "CIM_MediaAccessDevice"},
        "unavailable": ["CIM_PhysicalMedia"], "truncated": [], "unavailable_reasons": {"CIM_PhysicalMedia": "No such class"}}
    out.update(over)
    return out


def inventory_tool(result=None):
    """Answers like amt_inventory: only the sections asked for, a class this AMT lacks is unavailable."""
    full = result or inventory_result()

    def answer(a):
        want = a.get("sections") or list(amt_tools.INVENTORY_CLASSES)
        sections = {n: full["sections"][n] for n in want if n in full["sections"]}
        unavailable = [c for n, c in amt_tools.INVENTORY_CLASSES.items() if n in want and c in full["unavailable"]]
        return dict(full, sections=sections, classes={n: amt_tools.INVENTORY_CLASSES[n] for n in sections}, unavailable=unavailable)
    return answer


def wait_for(fn, what, seconds=8):
    end = time.time() + seconds
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


# ============================== the built pages and what they send (no browser) ===========================================================

def live_tools():
    import amt_server
    return {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}


def test_the_logs_and_inventory_tabs_are_built_each_with_its_own_script(me):
    for tab, root, script in (("logs", 'id="logs-page"', "/static/logs.js"), ("inventory", 'id="inventory-page"', "/static/inventory.js")):
        page = me.get(f"/server/{KEY}/{tab}").text
        assert root in page and f'data-server="{KEY}"' in page and script in page and "built in a later step" not in page and "@@" not in page, tab
        assert page.count('<script src="/static/') == page.count("<script src=") and "/static/status.js" in page
        assert "style=" not in page.split(root)[1].split("</main>")[0], "the console's CSP forbids inline styles"
        assert f'href="/server/{KEY}/{tab}" aria-current=page' in page
        others = {"logs.js", "inventory.js"} - {script.rsplit("/", 1)[1]}
        assert not [o for o in others if o in page], "a tab loads only its own script"
    assert "built in a later step" not in me.get(f"/server/{KEY}/wsman").text          # every server tab is built now


def test_the_pages_send_only_what_the_live_tool_schemas_take():
    live = live_tools()
    logs, inv = live["amt_logs"].inputSchema["properties"], live["amt_inventory"].inputSchema["properties"]
    assert {"device", "kind", "since", "until", "offset", "limit"} <= set(logs) and logs["kind"]["enum"] == ["event", "audit"]
    assert 1 <= 50 <= logs["limit"]["maximum"] and logs["limit"]["minimum"] == 1
    js = (CONSOLE / "static" / "logs.js").read_text()
    assert "? 20 : 50" in js and "kind: st.kind" in js and "limit: LIMIT" in js and logs["limit"]["maximum"] >= 50
    assert mcp_client.TOOLS["amt_logs"] == (True, True) and mcp_client.TOOLS["amt_inventory"] == (True, True)   # a device is named, nothing is confirmed
    assert "confirmed" not in logs and "confirmed" not in inv


def test_the_inventory_page_keeps_the_tools_own_section_table():
    src = (CONSOLE / "static" / "inventory.js").read_text()
    body = re.search(r"var CLASSES = \{(.*?)\};", src, re.S).group(1)
    table = dict(re.findall(r"(\w+): '(\w+)'", body))
    assert table == amt_tools.INVENTORY_CLASSES
    enums = []

    def walk(node):
        if isinstance(node, dict):
            if isinstance(node.get("enum"), list) and "chassis" in node["enum"]:
                enums.append(node["enum"])
            for v in node.values():
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)
    walk(live_tools()["amt_inventory"].inputSchema)
    assert enums and all(e == list(table) for e in enums)
    page = (CONSOLE / "pages" / "content-server-inventory.html").read_text()
    assert "data-section" not in page and "inv-chips" not in page             # designer ruling 2026-10-21: no section picker; every read names all seven
    assert "sections: SECTIONS.slice()" in src


@pytest.mark.parametrize("name", ["logs.js", "inventory.js", "status.js"])
def test_what_a_tool_or_a_host_says_is_never_set_as_markup(name):
    """A record's text comes from the host and a refusal's text from the tool: both are data, set as text nodes only."""
    src = (CONSOLE / "static" / name).read_text()
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert banned not in src, (name, banned)


def test_a_401_in_a_log_read_pauses_the_server_and_it_is_not_read_again(me, fake_amt):
    fake_amt.results["amt_logs"] = lambda a: tool_error("Error executing tool amt_logs: wsman_auth_failed_401")
    settle(me)
    r = me.post("/api/call", {"tool": "amt_logs", "arguments": {"device": KEY, "kind": "event", "offset": 0, "limit": 50}}).json()
    assert r["isError"] and "wsman_auth_failed_401" in r["text"]
    assert me.app.fleet.public(KEY)["state"] == "paused"
    assert me.get(f"/api/server/{KEY}").json()["server"]["paused"]["reason"] == "credential refused"


def test_a_log_read_without_a_named_device_is_refused_before_it_is_sent(me, fake_amt):
    for tool, args in (("amt_logs", {"kind": "event"}), ("amt_inventory", {"sections": ["bios"]})):
        reply = me.post("/api/call", {"tool": tool, "arguments": args})
        assert reply.status == 400 and reply.json() == {"error": "device_not_named"}
    assert calls(fake_amt, "amt_logs") == [] and calls(fake_amt, "amt_inventory") == []


# ============================== the pages, in a real browser (headless Chromium) ====================================================

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
def lb(tmp_path, fake_amt):
    """A signed-in console, the server read once, a scripted event log of 212 records (209 dated, 3 undated) and a scripted inventory."""
    console = Console(tmp_path, fake_amt)
    enroll_first_passkey(console, Authenticator(console.app.cfg.rp_id, console.origin))
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device()]}
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"]}
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_serial_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
    fake_amt.results["amt_identities"] = lambda a: {"identities": []}
    fake_amt.log = Log(mixed_events())
    fake_amt.results["amt_logs"] = fake_amt.log
    fake_amt.results["amt_inventory"] = inventory_tool()
    console.app.fleet.refresh_devices()
    console.app.fleet.refresh(KEY)
    yield console
    console.close()


READY = {"logs": "#log-counts:not(:empty), #log-state .result", "inventory": "#inv-cards .card, #inv-state .result"}
TOOL = {"logs": "amt_logs", "inventory": "amt_inventory"}
BUTTON = {"logs": "#log-read", "inventory": "#inv-reread"}
SLOT = {"logs": "#log-state", "inventory": "#inv-state"}
PAUSED = {"logs": "#logs-paused", "inventory": "#inv-paused"}


def open_tab(browser, lb, tab, width=1024, scheme="light", ready=True, **kw):
    ctx, pg = open_page(browser, lb, f"/server/{KEY}/{tab}", width=width, scheme=scheme, **kw)
    pg.set_default_timeout(8000)
    if ready:
        pg.wait_for_selector(READY[tab])
        idle(pg, tab)    # the open-read is over
    return ctx, pg


def idle(pg, tab):
    """The tab's read control is enabled again: no read of the page is out."""
    pg.wait_for_function("sel => !document.querySelector(sel).hasAttribute('aria-disabled')", arg=BUTTON[tab])


def reads(fake, tab):
    return calls(fake, TOOL[tab])


def rows(pg):
    return pg.eval_on_selector_all("#log-table tbody tr", "rs => rs.map(r => Array.from(r.cells).map(c => c.innerText.replace(/\\s+/g, ' ').trim()))")


def counts(pg):
    return text(pg, "#log-counts")


def press(pg, sel, fake, tab, n):
    """One activation, then wait for the n-th read of the tab's tool to have arrived and been drawn."""
    before = len(reads(fake, tab))
    pg.click(sel)
    wait_for(lambda: len(reads(fake, tab)) == before + 1, f"read {before + 1}")
    idle(pg, tab)
    assert len(reads(fake, tab)) == n


# -- the event log: read on open, the result's own counts ---------------------------------------------------------------------

def test_the_event_log_is_read_on_open_with_the_device_named_and_shows_the_results_own_counts(browser, lb, fake_amt):
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        assert reads(fake_amt, "logs") == [{"device": KEY, "kind": "event", "offset": 0, "limit": 50}]
        assert counts(pg) == ("matched 212 of 212 fetched · fetch complete · 3 undated (no AMT clock time on the record: listed last) · "
                              "0 undecodable · showing 1–50 newest first")
        got = rows(pg)
        assert len(got) == 50 and pg.eval_on_selector_all("#log-table thead th", "hs => hs.map(h => h.textContent)") == ["Level", "Time", "Source", "Description", "Raw sensor / type / data"]
        level, when, source, desc, raw = got[0]
        assert level.startswith("critical") and when == f"{iso(BASE)[:10]} {iso(BASE)[11:19]} UTC {eastern(BASE)}"
        assert (source, desc, raw) == ("Processor", "Event 0: thermal reading", "0x07 / 0x02 / 0x0001000000000000")
        assert got[1][0].startswith("info") and got[5][0].startswith("warning") and "Non-critical" in got[5][0]
        assert text(pg, "#log-call").startswith('tools/call amt_logs {device: "my-server-1", kind: "event", offset: 0, limit: 50} · read-only · read ')
        assert text(pg, "#log-title") == "Event log" and pg.is_visible("#sev-seg") and pg.errors == []
    finally:
        ctx.close()


def test_nothing_on_these_pages_writes_a_bare_click_sends_no_write_and_opens_no_sheet(browser, lb, fake_amt):
    """Immutable 4 for two read pages: every control outside a sheet, clicked, sends a read at most; there is no sheet, no force fire."""
    for tab, buttons in (("logs", ["#log-audit", "#log-event", "[data-sev=critical]", "[data-sev=all]", "#log-read", "#log-older", "#log-newer"]),
                         ("inventory", ["#inv-reread", "#inv-export"])):
        ctx, pg = open_tab(browser, lb, tab)
        try:
            for sel in buttons:
                pg.click(sel, force=True)
                idle(pg, tab)
            assert pg.query_selector(".sheet.open") is None and pg.query_selector(".sheet") is None
            assert pg.evaluate("() => window.__callCount()") == 0 and pg.evaluate("() => window.__forceFireCount()") == 0
        finally:
            ctx.close()
    written = [(t, a) for t, a, _ in fake_amt.calls if t in WRITE_TOOLS and a.get("action") not in ("status", "list")]   # the fleet's own status views are reads of write-tools
    assert written == [] and not [a for _, a, _ in fake_amt.calls if "confirmed" in a]
    assert all(a.get("device") == KEY for t, a, _ in fake_amt.calls if t in ("amt_logs", "amt_inventory"))


def test_the_window_filters_the_read_and_the_counts_say_what_it_dropped(browser, lb, fake_amt):
    since = iso(BASE - 100 * 600)
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        pg.fill("#since", since)
        press(pg, "#log-read", fake_amt, "logs", 2)
        assert reads(fake_amt, "logs")[-1] == {"device": KEY, "kind": "event", "since": since, "offset": 0, "limit": 50}
        assert counts(pg) == ("matched 101 of 212 fetched · fetch complete · 3 undated (no AMT clock time on the record: dropped by the time filter) · "
                              "0 undecodable · showing 1–50 newest first")
        pg.fill("#until", iso(BASE - 90 * 600))
        pg.press("#until", "Enter")                                                  # Enter in a field reads, once
        wait_for(lambda: len(reads(fake_amt, "logs")) == 3, "the third read")
        idle(pg, "logs")                                                             # the request arrives before the page redraws: wait for the draw, then read the counts
        assert reads(fake_amt, "logs")[-1]["until"] == iso(BASE - 90 * 600) and counts(pg).startswith("matched 11 of 212 fetched")
        pg.fill("#since", ""); pg.fill("#until", "")
        press(pg, "#log-read", fake_amt, "logs", 4)
        assert set(reads(fake_amt, "logs")[-1]) == {"device", "kind", "offset", "limit"}      # a cleared field is no bound at all, not an empty string
    finally:
        ctx.close()


def test_paging_keeps_the_window_of_the_result_on_the_page_not_the_one_typed_since(browser, lb, fake_amt):
    """Newer / Older step through the displayed result: an edited Since or Until reaches the tool only through Read."""
    since, edited = iso(BASE - 100 * 600), iso(BASE - 20 * 600)
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        pg.fill("#since", since)
        press(pg, "#log-read", fake_amt, "logs", 2)
        assert counts(pg).startswith("matched 101 of 212 fetched")
        pg.fill("#since", edited); pg.fill("#until", iso(BASE - 10 * 600))              # typed, not read
        press(pg, "#log-older", fake_amt, "logs", 3)
        assert reads(fake_amt, "logs")[-1] == {"device": KEY, "kind": "event", "since": since, "offset": 50, "limit": 50}
        assert counts(pg).startswith("matched 101 of 212 fetched") and counts(pg).endswith("showing 51–100 newest first")
        press(pg, "#log-newer", fake_amt, "logs", 4)
        assert reads(fake_amt, "logs")[-1] == {"device": KEY, "kind": "event", "since": since, "offset": 0, "limit": 50}
        press(pg, "#log-read", fake_amt, "logs", 5)                                    # Read is where the typed window is sent, from the first page
        assert reads(fake_amt, "logs")[-1] == {"device": KEY, "kind": "event", "since": edited, "until": iso(BASE - 10 * 600), "offset": 0, "limit": 50}
    finally:
        ctx.close()


def test_paging_steps_fifty_at_a_time_and_each_press_is_one_read(browser, lb, fake_amt):
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        assert pg.get_attribute("#log-newer", "aria-disabled") == "true" and text(pg, "#log-newer-wrap .reason") == "newest page"
        press(pg, "#log-older", fake_amt, "logs", 2)
        assert reads(fake_amt, "logs")[-1]["offset"] == 50 and counts(pg).endswith("showing 51–100 newest first") and rows(pg)[0][3] == "Event 50: thermal reading"
        press(pg, "#log-older", fake_amt, "logs", 3)
        assert reads(fake_amt, "logs")[-1]["offset"] == 100 and counts(pg).endswith("showing 101–150 newest first")
        press(pg, "#log-older", fake_amt, "logs", 4)
        assert counts(pg).endswith("showing 151–200 newest first")
        press(pg, "#log-older", fake_amt, "logs", 5)
        assert counts(pg).endswith("showing 201–212 newest first") and len(rows(pg)) == 12
        assert pg.get_attribute("#log-older", "aria-disabled") == "true" and text(pg, "#log-older-wrap .reason") == "oldest page"
        before = len(reads(fake_amt, "logs"))
        pg.click("#log-older", force=True)
        pg.wait_for_timeout(300)
        assert len(reads(fake_amt, "logs")) == before                                   # a disabled control ignores activation
        assert pg.get_attribute("#log-newer", "aria-disabled") is None
        press(pg, "#log-newer", fake_amt, "logs", 6)
        assert reads(fake_amt, "logs")[-1]["offset"] == 150 and counts(pg).endswith("showing 151–200 newest first")
    finally:
        ctx.close()


def test_a_phone_reads_twenty_a_page_so_the_card_per_row_page_stays_under_the_height_ceiling(browser, lb, fake_amt):
    ctx, pg = open_tab(browser, lb, "logs", width=360)
    try:
        assert reads(fake_amt, "logs") == [{"device": KEY, "kind": "event", "offset": 0, "limit": 20}]
        assert counts(pg).endswith("showing 1–20 newest first") and len(rows(pg)) == 20
        press(pg, "#log-older", fake_amt, "logs", 2)
        assert reads(fake_amt, "logs")[-1]["offset"] == 20 and counts(pg).endswith("showing 21–40 newest first")
    finally:
        ctx.close()


def test_a_switch_of_log_is_a_read_of_that_log_and_the_audit_rows_carry_their_own_columns(browser, lb, fake_amt):
    fake_amt.results["amt_logs"] = lambda a: Log([audit(0, initiator_kind="local", initiator="Local", extended_data=None, extended_data_hex="", net_address=""),
                                                  audit(1), audit(2, initiator_kind="kerberos", initiator="S-1-5-21-1", extended_data="tls on", extended_data_hex="01"),
                                                  audit(3, decoded=False, epoch=None, timestamp=None, raw_hex="deadbeef")], kind="audit")(a)
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        pg.click("#log-audit")
        wait_for(lambda: len(reads(fake_amt, "logs")) == 2, "the audit read")
        pg.wait_for_selector("#log-table tbody tr")
        assert reads(fake_amt, "logs")[-1] == {"device": KEY, "kind": "audit", "offset": 0, "limit": 50}
        assert pg.eval_on_selector_all("#log-table thead th", "hs => hs.map(h => h.textContent)") == ["Time", "App", "Event", "Initiator", "Extended data"]
        assert text(pg, "#log-title") == "Audit log" and pg.is_hidden("#sev-seg") and pg.get_attribute("#log-audit", "aria-pressed") == "true"
        got = rows(pg)
        assert got[1][1:] == ["Redirection manager", "KVM session started #1", "digest · admin", "address 10.0.0.24 · ip 10.0.0.24 · hex 0a97 3318"]
        assert got[2][3] == "kerberos · S-1-5-21-1" and got[2][4] == "address 10.0.0.24 · tls on · hex 01"
        assert got[0][3] == "local" and got[0][4] == "—"                                    # a local initiator is not "local · Local"; no data is a dash
        assert got[3] == ["no time", "unknown", "could not be decoded", "unknown", "raw hex deadbeef"]
        assert counts(pg).startswith("matched 4 of 4 fetched · fetch complete · 1 undated") and "1 undecodable (shown with their raw hex)" in counts(pg)
        pg.click("#log-event")
        wait_for(lambda: len(reads(fake_amt, "logs")) == 3, "the event read again")
        assert reads(fake_amt, "logs")[-1]["kind"] == "event"
    finally:
        ctx.close()


# -- the severity filter lives on the page: no new read, the counts stay the result's ------------------------------------------------

def test_the_severity_filter_hides_rows_on_the_page_without_a_read_and_leaves_the_counts_alone(browser, lb, fake_amt):
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        before = counts(pg)
        pg.click("[data-sev=warning]")
        shown = [r[0].split(" ")[0] for r in rows(pg)]
        assert shown and set(shown) == {"critical", "warning"} and len(shown) == 10      # of Events 0-49: 5 critical and 5 warning
        assert "Severity filter warning+: 10 of the 50 records on this page shown, 40 hidden." in text(pg, "#log-sevnote") and "before the filter" in text(pg, "#log-sevnote")
        pg.click("[data-sev=critical]")
        assert {r[0].split(" ")[0] for r in rows(pg)} == {"critical"} and len(rows(pg)) == 5
        assert counts(pg) == before and len(reads(fake_amt, "logs")) == 1                # the counts are the tool's; nothing was re-read
        pg.click("[data-sev=all]")
        assert len(rows(pg)) == 50 and pg.is_hidden("#log-sevnote")
    finally:
        ctx.close()


def test_a_page_whose_records_are_all_below_the_filter_says_so_and_is_not_an_empty_log(browser, lb, fake_amt):
    fake_amt.results["amt_logs"] = Log([event(i) for i in range(8)])
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        pg.click("[data-sev=critical]")
        assert pg.query_selector("#log-table table") is None
        note = text(pg, '#log-state [data-state="sevhidden"]')
        assert note == "All 8 records on this page are below the severity filter. Other pages may hold more."
        assert pg.query_selector('#log-state [data-state="emptylog"]') is None and pg.query_selector('#log-state [data-state="emptypage"]') is None
        assert counts(pg).startswith("matched 8 of 8 fetched")
    finally:
        ctx.close()


def test_an_undecodable_or_levelless_record_is_never_hidden_by_the_filter(browser, lb, fake_amt):
    odd = [event(1), event(2, decoded=False, epoch=None, timestamp=None, raw_hex="0102"), dict(event(3), level=None)]
    fake_amt.results["amt_logs"] = Log(odd)
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        pg.click("[data-sev=critical]")
        got = rows(pg)
        assert len(got) == 2 and got[0][0].startswith("level not reported") and got[0][3] == "Event 3: thermal reading"     # no level: not known to be below the filter
        assert got[1][3:] == ["could not be decoded", "raw hex 0102"]                                              # undecodable: kept too; Event 1 (info) is gone
    finally:
        ctx.close()


# -- immutable 19: coverage from the result; an empty page is not an empty log --------------------------------------------------

def test_an_empty_window_and_an_empty_log_are_different_sentences(browser, lb, fake_amt):
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        late = iso(BASE + 86400)
        pg.fill("#since", late)
        press(pg, "#log-read", fake_amt, "logs", 2)
        window = text(pg, '#log-state [data-state="emptypage"]')
        assert window == (f"No records in this window: 212 were fetched and none is at or after {late}. The event log itself is not empty (it holds 212). Widen the window.")
        assert counts(pg) == ("matched 0 of 212 fetched · fetch complete · 3 undated (no AMT clock time on the record: dropped by the time filter) · "
                              "0 undecodable · showing none")
        assert pg.query_selector("#log-table table") is None and pg.get_attribute("#log-older", "aria-disabled") == "true"
        fake_amt.results["amt_logs"] = Log([])
        pg.fill("#since", "")
        press(pg, "#log-read", fake_amt, "logs", 3)
        empty = text(pg, '#log-state [data-state="emptylog"]')
        assert empty == ("The event log is empty: 0 fetched, 0 undated, 0 undecodable. A cleared or never-written log looks like this; a filter that matched nothing does not.")
        assert window != empty and "not empty" not in empty and "is empty" not in window
        assert pg.query_selector('#log-state [data-state="emptypage"]') is None
        assert counts(pg) == "matched 0 of 0 fetched · fetch complete · 0 undated · 0 undecodable · showing none"
    finally:
        ctx.close()


def test_a_read_that_did_not_finish_is_not_reported_as_an_empty_log(browser, lb, fake_amt):
    fake_amt.results["amt_logs"] = Log([], complete=False)
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        assert pg.query_selector('#log-state [data-state="emptylog"]') is None
        assert "it is not known whether the event log is empty" in text(pg, '#log-state [data-state="unread"]')
        assert "fetch incomplete: more records may exist than were read" in counts(pg) and "fetch complete" not in counts(pg)
        assert "The fetch did not complete" in text(pg, '#log-state [data-state="incomplete"]')
    finally:
        ctx.close()
    fake_amt.results["amt_logs"] = Log(mixed_events(60, 0), complete=False)
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        assert "matched 60 of 60 fetched · fetch incomplete" in counts(pg)
        assert "counts cover the 60 records read, and older records may exist" in text(pg, '#log-state [data-state="incomplete"]') and len(rows(pg)) == 50
    finally:
        ctx.close()


def test_a_page_past_the_end_says_so_and_newer_steps_back_to_the_last_page_with_records(browser, lb, fake_amt):
    log = Log(mixed_events(230, 0))
    fake_amt.results["amt_logs"] = log
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        press(pg, "#log-older", fake_amt, "logs", 2)
        press(pg, "#log-older", fake_amt, "logs", 3)
        assert reads(fake_amt, "logs")[-1]["offset"] == 100
        log.records = mixed_events(70, 0)                                              # the log shrank while the page was open
        press(pg, "#log-older", fake_amt, "logs", 4)
        assert reads(fake_amt, "logs")[-1]["offset"] == 150 and pg.query_selector("#log-table table") is None
        assert text(pg, '#log-state [data-state="pastend"]') == "This page is past the end: 70 records match and offset 150 is beyond them. Press Newer."
        assert pg.query_selector('#log-state [data-state="emptylog"]') is None and pg.query_selector('#log-state [data-state="emptypage"]') is None
        assert counts(pg).startswith("matched 70 of 70 fetched") and counts(pg).endswith("showing none")
        press(pg, "#log-newer", fake_amt, "logs", 5)
        assert reads(fake_amt, "logs")[-1]["offset"] == 50 and len(rows(pg)) == 20      # the last page that holds records, not one step back
    finally:
        ctx.close()


def test_the_footer_names_an_undecodable_record_and_shows_its_raw_hex(browser, lb, fake_amt):
    fake_amt.results["amt_logs"] = Log([event(0), event(1, decoded=False, epoch=None, timestamp=None, raw_hex="aabbcc"), event(2)])
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        assert counts(pg) == ("matched 3 of 3 fetched · fetch complete · 1 undated (no AMT clock time on the record: listed last) · "
                              "1 undecodable (shown with their raw hex) · showing 1–3 newest first")
        assert rows(pg)[-1] == ["undecodable", "no time", "unknown", "could not be decoded", "raw hex aabbcc"]
        fake_amt.results["amt_logs"] = Log([event(0, epoch=None, timestamp=None)])           # a record with no time that DID decode
        press(pg, "#log-read", fake_amt, "logs", 2)
        assert rows(pg)[0][1] == "no time" and "0 undecodable · showing 1–1" in counts(pg)
    finally:
        ctx.close()


def test_a_result_missing_a_count_is_unreadable_not_a_zero(browser, lb, fake_amt):
    good = Log(mixed_events(10, 0))
    for missing in ("matched", "fetched", "undated", "undecodable", "fetch_complete", "records"):
        fake_amt.results["amt_logs"] = lambda a, m=missing: {k: v for k, v in good(a).items() if k != m}
        ctx, pg = open_tab(browser, lb, "logs")
        try:
            note = text(pg, "#log-state .result.error")
            assert "cannot read" in note and missing in note and "no count is shown" in note, (missing, note)
            assert counts(pg) == "" and pg.query_selector("#log-table table") is None
            assert pg.get_attribute("#log-older", "aria-disabled") == "true" and text(pg, "#log-older-wrap .reason") == "read first"
        finally:
            ctx.close()
    fake_amt.results["amt_logs"] = lambda a: dict(good(a), returned=3)               # records and returned disagree
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        assert "records_vs_returned" in text(pg, "#log-state .result.error") and counts(pg) == ""
    finally:
        ctx.close()
    fake_amt.results["amt_logs"] = lambda a: dict(good(a), kind="audit")             # the other log's answer to an event read
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        assert "kind" in text(pg, "#log-state .result.error") and counts(pg) == "" and pg.query_selector("#log-table table") is None
    finally:
        ctx.close()
    fake_amt.results["amt_logs"] = lambda a: dict(good(a), matched=-1)               # a count that is not a count
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        assert "matched" in text(pg, "#log-state .result.error") and counts(pg) == ""
    finally:
        ctx.close()


# -- immutable 7: a refusal in its own card, a refused credential pauses the server -------------------------------------------------------

REFUSAL = "Error executing tool amt_logs: invalid_since:expected ISO-8601 like 2026-10-17T00:00:00Z <b>x</b>"


def test_a_tool_refusal_is_shown_verbatim_in_the_logs_card_as_text_and_the_old_table_is_gone(browser, lb, fake_amt):
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        assert len(rows(pg)) == 50
        pg.fill("#since", "last tuesday")
        press(pg, "#log-read", fake_amt, "logs", 2)
        note = text(pg, "#log-card .result.error")
        assert "refused: Error executing tool amt_logs: invalid_since:expected ISO-8601 like 2026-10-17T00:00:00Z" in note and "read-only: nothing on the host was changed" in note
        assert pg.query_selector("#log-table table") is None and counts(pg) == ""             # a refusal leaves no stale table under it
        assert reads(fake_amt, "logs")[-1]["since"] == "last tuesday"                          # what was typed is sent as typed; the tool judges it
        fake_amt.results["amt_logs"] = lambda a: tool_error(REFUSAL)
        press(pg, "#log-read", fake_amt, "logs", 3)
        assert "<b>x</b>" in text(pg, "#log-card .result.error") and pg.query_selector("#log-card .result.error b") is None     # text, never markup
    finally:
        ctx.close()


def open_routed(browser, console, path, handler):
    """open_page, with the console's /api/call answered by `handler` from the first request on."""
    ctx = browser.new_context(viewport={"width": 1024, "height": 900})
    ctx.add_cookies([{"name": "amt_console_session", "value": console.cookie, "domain": console.host, "path": "/", "httpOnly": True, "secure": True, "sameSite": "Strict"}])
    ctx.route(f"{console.origin}/api/call", handler)
    pg = ctx.new_page()
    pg.set_default_timeout(8000)
    pg.goto(f"{console.origin}{path}")
    return ctx, pg


@pytest.mark.parametrize("status,code,says", [(502, "amt_mcp_unreachable:TimeoutError", "amt-mcp did not answer (amt_mcp_unreachable:TimeoutError)"),
                                              (503, "console_bearer_unavailable", "refused: console_bearer_unavailable · nothing sent"),
                                              (400, "device_not_named", "refused: device_not_named · nothing sent")])
@pytest.mark.parametrize("tab", ["logs", "inventory"])
def test_a_call_the_console_could_not_make_is_not_reported_as_a_refusal_by_the_tool(browser, lb, fake_amt, tab, status, code, says):
    ctx, pg = open_routed(browser, lb, f"/server/{KEY}/{tab}", lambda route: route.fulfill(status=status, content_type="application/json", body=json.dumps({"error": code})))
    try:
        pg.wait_for_selector(f"{SLOT[tab]} .result")
        note = text(pg, f"{SLOT[tab]} .result")
        assert says in note
        assert ("did not answer" in note) == (status == 502) and ("the read may or may not have reached the host" in note) == (status == 502)
        assert pg.query_selector("#log-table table, #inv-cards .card") is None
    finally:
        ctx.close()
    assert reads(fake_amt, tab) == []                                                   # the route answered; amt-mcp saw nothing


@pytest.mark.parametrize("tab", ["logs", "inventory"])
def test_a_refused_credential_is_shown_verbatim_pauses_the_server_and_the_page_reads_no_more(browser, lb, fake_amt, tab):
    text401 = f"Error executing tool {TOOL[tab]}: wsman_auth_failed_401"
    fake_amt.results[TOOL[tab]] = lambda a: tool_error(text401)
    ctx, pg = open_tab(browser, lb, tab, ready=False)
    try:
        pg.wait_for_selector(f"{PAUSED[tab]}:not([hidden])")
        assert text401 in text(pg, f"{SLOT[tab]} .result.error") and "read-only" in text(pg, f"{SLOT[tab]} .result.error")
        banner = text(pg, PAUSED[tab])
        assert "Reading is paused for this server (credential refused)" in banner and "Retry once from the Status tab" in banner
        assert pg.get_attribute(f"{PAUSED[tab]} a", "href") == f"/server/{KEY}"
        assert lb.app.fleet.public(KEY)["state"] == "paused"
        assert pg.get_attribute(BUTTON[tab], "aria-disabled") == "true" and text(pg, f"{BUTTON[tab]} ~ .reason") == "paused · credential refused"
        one = len(reads(fake_amt, tab))
        assert one == 1
        pg.click(BUTTON[tab], force=True)                                               # a click on the disabled control sends nothing
        if tab == "logs":
            for sel in ("#log-older", "#log-newer", "#log-audit", "#log-event"):
                pg.click(sel, force=True)
        pg.wait_for_timeout(300)
        assert len(reads(fake_amt, tab)) == one
        status_before = len(calls(fake_amt, "amt_status"))
        bump = [0]
        lb.app.fleet.now = lambda: time.time() + bump[0]
        for _ in range(3):                                                              # the next three refresh periods
            bump[0] += 31
            assert lb.app.fleet.step() is None
        assert len(calls(fake_amt, "amt_status")) == status_before
    finally:
        ctx.close()


@pytest.mark.parametrize("tab", ["logs", "inventory"])
def test_a_page_opened_on_a_paused_server_reads_nothing_and_says_why(browser, lb, fake_amt, tab):
    fake_amt.results["amt_status"] = lambda a: tool_error("Error executing tool amt_status: wsman_auth_failed_401")
    lb.app.fleet.refresh(KEY)
    assert lb.app.fleet.public(KEY)["state"] == "paused"
    ctx, pg = open_tab(browser, lb, tab, ready=False)
    try:
        pg.wait_for_selector(f"{PAUSED[tab]}:not([hidden])")
        pg.wait_for_timeout(400)
        assert reads(fake_amt, tab) == []
        assert pg.get_attribute(BUTTON[tab], "aria-disabled") == "true" and text(pg, f"{BUTTON[tab]} ~ .reason") == "paused · credential refused"
        assert "Retry once from the Status tab" in text(pg, PAUSED[tab])
        if tab == "inventory":
            assert pg.get_attribute("#inv-export", "aria-disabled") == "true" and text(pg, "#inv-export-wrap .reason") == "read first"
    finally:
        ctx.close()


@pytest.mark.parametrize("tab", ["logs", "inventory"])
def test_a_page_is_read_when_it_opens_and_when_asked_never_on_a_timer(browser, lb, fake_amt, tab):
    ctx, pg = open_tab(browser, lb, tab)
    try:
        assert len(reads(fake_amt, tab)) == 1
        pg.wait_for_timeout(5600)                                                       # past the page's own 5 s refresh of the cached state
        assert len(reads(fake_amt, tab)) == 1
        press(pg, BUTTON[tab], fake_amt, tab, 2)
    finally:
        ctx.close()


@pytest.mark.parametrize("tab", ["logs", "inventory"])
def test_one_activation_is_one_read_and_the_control_says_why_it_waits(browser, lb, fake_amt, tab):
    import threading
    gate = threading.Event()
    real = fake_amt.results[TOOL[tab]]
    fake_amt.results[TOOL[tab]] = lambda a: (gate.wait(10), real(a))[1]
    ctx, pg = open_page(browser, lb, f"/server/{KEY}/{tab}")
    pg.set_default_timeout(8000)
    try:
        wait_for(lambda: len(reads(fake_amt, tab)) == 1, "the open-read")
        assert pg.get_attribute(BUTTON[tab], "aria-disabled") == "true" and text(pg, f"{BUTTON[tab]} ~ .reason") == "waiting for amt-mcp"
        for _ in range(3):
            pg.click(BUTTON[tab], force=True)
        pg.wait_for_timeout(200)
        assert len(reads(fake_amt, tab)) == 1
        gate.set()
        pg.wait_for_selector(READY[tab])
        idle(pg, tab)
        assert len(reads(fake_amt, tab)) == 1
    finally:
        gate.set()
        ctx.close()


def test_a_records_text_is_shown_as_text_never_as_markup(browser, lb, fake_amt):
    nasty = '<img src=x onerror="window.__pwned=1"><script>window.__pwned=1</script>'
    fake_amt.results["amt_logs"] = Log([event(0, description=nasty, source=nasty), event(1, raw_hex=nasty, decoded=False, epoch=None, timestamp=None)])
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        assert rows(pg)[0][2] == nasty and rows(pg)[0][3] == nasty
        assert pg.query_selector("#log-table img, #log-table script") is None and pg.evaluate("() => window.__pwned === undefined")
        assert pg.errors == []
    finally:
        ctx.close()
    fake_amt.results["amt_logs"] = Log([audit(0, app=nasty, event=nasty, extended_data=nasty, initiator=nasty)], kind="audit")
    ctx, pg = open_tab(browser, lb, "logs")
    try:
        pg.click("#log-audit"); pg.wait_for_selector("#log-table table[data-kind=audit]")
        assert nasty in rows(pg)[0][1] and pg.query_selector("#log-table img, #log-table script") is None and pg.evaluate("() => window.__pwned === undefined")
    finally:
        ctx.close()


# ============================== the inventory ==============================================================================================

def cards(pg):
    return pg.eval_on_selector_all("#inv-cards .card", "cs => cs.map(c => [c.getAttribute('data-card'), c.querySelector('h2').textContent.trim(), c.innerText.replace(/\\s+/g, ' ').trim()])")


def test_the_inventory_is_read_on_open_with_every_section_named_and_one_card_each(browser, lb, fake_amt):
    ctx, pg = open_tab(browser, lb, "inventory")
    try:
        assert reads(fake_amt, "inventory") == [{"device": KEY, "sections": list(amt_tools.INVENTORY_CLASSES)}]
        got = cards(pg)
        assert [c[0] for c in got] == ["chassis", "baseboard", "bios", "processors", "memory", "storage"]
        assert [c[1] for c in got] == ["Chassis (1)", "Baseboard (1)", "BIOS (1)", "Processors (1)", "Memory (2)", "Storage media (2)"]
        chassis = dict(zip(*[iter(pg.eval_on_selector_all('[data-card=chassis] dl.kv > *', "es => es.map(e => e.textContent.trim())"))] * 2))
        assert chassis == {"Manufacturer": "Minisforum", "Model": "MS-02 Ultra", "SerialNumber": "MSU2-0421-7788", "ChassisPackageType": "35"}   # the tool's own names and values
        assert "PrimaryBIOS true" in got[2][2] and "BANK 1" in got[4][2] and "1 of 2" in got[4][2] and "2 of 2" in got[4][2]
        assert text(pg, "#inv-note").startswith("amt_inventory · read ") and text(pg, "#inv-call").startswith('tools/call amt_inventory {device: "my-server-1", sections: ["chassis", ')
        assert pg.errors == []
    finally:
        ctx.close()


def test_the_coverage_banner_and_the_unavailable_part_come_from_the_result(browser, lb, fake_amt):
    ctx, pg = open_tab(browser, lb, "inventory")
    try:
        assert text(pg, "#inv-banner") == "Coverage: physical_media is unavailable: No such class, so that section is empty and the rest was read. Nothing was truncated."
        assert pg.get_attribute("#inv-banner", "class") == "banner"
        assert pg.query_selector("#inv-bar .chip, [data-section]") is None                          # no section picker to press
        assert "unavailable on this AMT" in text(pg, '[data-card=storage] [data-part=physical_media]')
        assert pg.query_selector("[data-card=storage] [data-part=storage_media]") is None      # its two instances are there; the chip is only for the missing part
    finally:
        ctx.close()


@pytest.mark.parametrize("result,banner,live", [
    (inventory_result(unavailable=[], unavailable_reasons={}, sections=dict(inventory_result()["sections"], physical_media=[{"Tag": "x"}])),
     "Coverage: All 7 sections were read. Nothing was truncated.", False),
    (inventory_result(truncated=["CIM_Processor"]),
     "Coverage: physical_media is unavailable: No such class, so that section is empty and the rest was read. processors was cut at the item cap: more exist than were read.", True),
    (inventory_result(unavailable_reasons={}),
     "Coverage: physical_media is unavailable: the tool gave no reason, so that section is empty and the rest was read. Nothing was truncated.", False),
    (inventory_result(unavailable=["CIM_PhysicalMedia", "CIM_Chassis"], unavailable_reasons={"CIM_PhysicalMedia": "No such class"}, sections={
        n: v for n, v in inventory_result()["sections"].items() if n != "chassis"}),
     "Coverage: chassis is unavailable: the tool gave no reason, so that section is empty and the rest was read. "
     "physical_media is unavailable: No such class, so that section is empty and the rest was read. Nothing was truncated.", False),
])
def test_each_coverage_field_the_tool_reports_changes_the_banner(browser, lb, fake_amt, result, banner, live):
    fake_amt.results["amt_inventory"] = inventory_tool(result)
    ctx, pg = open_tab(browser, lb, "inventory")
    try:
        assert text(pg, "#inv-banner") == banner
        assert ("live" in pg.get_attribute("#inv-banner", "class").split()) == live
    finally:
        ctx.close()


@pytest.mark.parametrize("width", [360, 880, 1120, 1440])
def test_a_long_cim_name_wraps_in_its_column_and_never_lies_over_its_value(browser, lb, fake_amt, width):
    """Real CIM names have no space to wrap at (operator report 2026-10-21: names lay over values at some widths)."""
    long_keys = {"SystemCreationClassName": "CIM_ComputerSystem", "ConfiguredMemoryClockSpeed": 4800, "ExternalBusClockSpeed": 100,
                 "OtherFamilyDescription": "", "TargetOperatingSystem": 66, "SoftwareElementState": 2}
    res = inventory_result()
    res["sections"] = dict(res["sections"], processors=[long_keys], bios=[long_keys], memory=[long_keys])
    fake_amt.results["amt_inventory"] = inventory_tool(res)
    ctx, pg = open_tab(browser, lb, "inventory", width=width)
    try:
        bad = pg.evaluate("""() => [...document.querySelectorAll('#inv-cards .kv dt')].filter(dt => {
            const dd = dt.nextElementSibling, a = dt.getBoundingClientRect(), b = dd.getBoundingClientRect();
            return dt.scrollWidth > dt.clientWidth + 1 || (a.right > b.left + 1 && a.top < b.bottom - 1 && b.top < a.bottom - 1); }).map(dt => dt.textContent)""")
        assert bad == []
        assert "SystemCreationClassName" in pg.eval_on_selector_all("#inv-cards .kv dt", "es => es.map(e => e.textContent)")   # the name is unchanged, only breakable
    finally:
        ctx.close()


def test_a_section_with_no_instance_is_none_reported_not_unavailable(browser, lb, fake_amt):
    res = inventory_result()
    res["sections"] = dict(res["sections"], memory=[])
    fake_amt.results["amt_inventory"] = inventory_tool(res)
    ctx, pg = open_tab(browser, lb, "inventory")
    try:
        mem = dict((c[0], c) for c in cards(pg))["memory"]
        assert mem[1] == "Memory (0)" and "none reported" in mem[2] and "unavailable" not in mem[2]
        assert "memory" not in text(pg, "#inv-banner")
    finally:
        ctx.close()


def test_re_read_reads_every_section_again_including_one_found_unavailable(browser, lb, fake_amt):
    ctx, pg = open_tab(browser, lb, "inventory")
    try:
        assert pg.get_attribute("#inv-reread", "aria-disabled") is None
        press(pg, "#inv-reread", fake_amt, "inventory", 2)
        assert reads(fake_amt, "inventory") == [{"device": KEY, "sections": list(amt_tools.INVENTORY_CLASSES)}] * 2   # an unavailable section is re-probed every read
        assert [c[0] for c in cards(pg)] == ["chassis", "baseboard", "bios", "processors", "memory", "storage"]
        assert text(pg, "#inv-banner").startswith("Coverage: physical_media is unavailable")
    finally:
        ctx.close()


def test_export_json_is_the_result_as_the_tool_returned_it_and_sends_nothing(browser, lb, fake_amt, tmp_path):
    ctx, pg = open_tab(browser, lb, "inventory", accept_downloads=True)
    try:
        before = list(fake_amt.calls)
        with pg.expect_download() as dl:
            pg.click("#inv-export")
        got = dl.value
        assert got.suggested_filename == f"{KEY}-inventory.json"
        saved = tmp_path / "export.json"
        got.save_as(str(saved))
        want = inventory_tool()({"device": KEY, "sections": list(amt_tools.INVENTORY_CLASSES)})
        assert json.loads(saved.read_text()) == want
        assert fake_amt.calls == before and pg.evaluate("() => window.__callCount()") == 0           # nothing was read or sent for it
    finally:
        ctx.close()


def test_export_waits_for_a_read(browser, lb, fake_amt):
    import threading
    gate = threading.Event()
    real = fake_amt.results["amt_inventory"]
    fake_amt.results["amt_inventory"] = lambda a: (gate.wait(10), real(a))[1]
    ctx, pg = open_page(browser, lb, f"/server/{KEY}/inventory", accept_downloads=True)
    pg.set_default_timeout(8000)
    try:
        wait_for(lambda: len(reads(fake_amt, "inventory")) == 1, "the open-read")
        assert pg.get_attribute("#inv-export", "aria-disabled") == "true" and text(pg, "#inv-export-wrap .reason") == "waiting for amt-mcp"
        pg.click("#inv-export", force=True); pg.wait_for_timeout(200)
        gate.set()
        pg.wait_for_selector("#inv-cards .card")
        pg.wait_for_function("() => !document.getElementById('inv-export').hasAttribute('aria-disabled')")
    finally:
        gate.set()
        ctx.close()


def test_an_inventory_missing_its_coverage_lists_is_unreadable_not_clean(browser, lb, fake_amt):
    base = inventory_tool()
    for drop, needle in (("unavailable", "unavailable"), ("truncated", "truncated"), ("sections", "sections")):
        fake_amt.results["amt_inventory"] = lambda a, d=drop: {k: v for k, v in base(a).items() if k != d}
        ctx, pg = open_tab(browser, lb, "inventory")
        try:
            note = text(pg, "#inv-state .result.error")
            assert "cannot read" in note and needle in note and "no coverage is claimed" in note, (drop, note)
            assert pg.is_hidden("#inv-banner") and pg.query_selector("#inv-cards .card") is None
            assert pg.get_attribute("#inv-export", "aria-disabled") == "true"
        finally:
            ctx.close()


def test_a_section_asked_for_that_comes_back_neither_read_nor_unavailable_is_unreadable(browser, lb, fake_amt):
    base = inventory_tool()
    fake_amt.results["amt_inventory"] = lambda a: dict(base(a), sections={k: v for k, v in base(a)["sections"].items() if k != "bios"})
    ctx, pg = open_tab(browser, lb, "inventory")
    try:
        assert "neither returned nor reported unavailable: bios" in text(pg, "#inv-state .result.error") and pg.is_hidden("#inv-banner")
        assert pg.query_selector("#inv-cards .card") is None
    finally:
        ctx.close()
    fake_amt.results["amt_inventory"] = lambda a: dict(base(a), sections=dict(base(a)["sections"], bios={"Version": "1"}))
    ctx, pg = open_tab(browser, lb, "inventory")
    try:
        assert "bios" in text(pg, "#inv-state .result.error")
    finally:
        ctx.close()


def test_the_inventory_tool_refusal_is_verbatim_text_in_its_own_card(browser, lb, fake_amt):
    fake_amt.results["amt_inventory"] = lambda a: tool_error("Error executing tool amt_inventory: unknown_inventory_section:disks <i>x</i>")
    ctx, pg = open_tab(browser, lb, "inventory")
    try:
        note = text(pg, "#inv-state .result.error")
        assert "refused: Error executing tool amt_inventory: unknown_inventory_section:disks <i>x</i>" in note and "read-only" in note
        assert pg.query_selector("#inv-state .result.error i") is None and pg.is_hidden("#inv-banner")
    finally:
        ctx.close()


def test_a_hosts_inventory_text_is_shown_as_text_never_as_markup(browser, lb, fake_amt):
    nasty = '<img src=x onerror="window.__pwned=1">'
    res = inventory_result()
    res["sections"] = dict(res["sections"], chassis=[{"Manufacturer": nasty, nasty: "v", "List": [nasty, {"a": nasty}], "Nothing": None, "Empty": ""}])
    fake_amt.results["amt_inventory"] = inventory_tool(res)
    ctx, pg = open_tab(browser, lb, "inventory")
    try:
        body = text(pg, "[data-card=chassis]")
        assert nasty in body and "not reported" in body and "empty" in body
        assert pg.query_selector("#inv-cards img") is None and pg.evaluate("() => window.__pwned === undefined")
    finally:
        ctx.close()


# ============================== layout, contrast and the outside world ======================================================================

@pytest.mark.parametrize("tab", ["logs", "inventory"])
@pytest.mark.parametrize("width", WIDTHS)
def test_the_page_fits_every_width_with_hit_areas_and_a_16_px_gutter(browser, lb, fake_amt, tab, width):
    cm = check_mockups()
    ctx, pg = open_tab(browser, lb, tab, width=width)
    try:
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


@pytest.mark.parametrize("tab", ["logs", "inventory"])
def test_the_phone_layout_is_card_per_row_with_the_column_name_before_each_value(browser, lb, fake_amt, tab):
    ctx, pg = open_tab(browser, lb, tab, width=360)
    try:
        if tab == "logs":
            assert pg.evaluate("() => getComputedStyle(document.querySelector('#log-table thead')).display") == "none"
            labels = pg.eval_on_selector_all("#log-table tbody tr:first-child td", "cs => cs.map(c => getComputedStyle(c, '::before').content)")
            assert labels == ['"Level: "', '"Time: "', '"Source: "', '"Description: "', '"Raw sensor / type / data: "']
            assert pg.evaluate("() => document.querySelector('#log-table tbody tr').getBoundingClientRect().width") <= 360 - 32 + 1
            pg.click("#log-audit"); pg.wait_for_selector("#log-table table[data-kind=audit]")
            labels = pg.eval_on_selector_all("#log-table tbody tr:first-child td", "cs => cs.map(c => getComputedStyle(c, '::before').content)")
            assert labels == ['"Time: "', '"App: "', '"Event: "', '"Initiator: "', '"Extended data: "']
        else:
            assert pg.evaluate("() => document.documentElement.scrollWidth") <= 360
            assert pg.evaluate("() => Array.from(document.querySelectorAll('#inv-cards .card')).every(c => c.getBoundingClientRect().right <= 360 - 15)")
    finally:
        ctx.close()


@pytest.mark.parametrize("tab", ["logs", "inventory"])
@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_every_text_and_ring_on_the_page_clears_the_contrast_floors(browser, lb, fake_amt, tab, scheme):
    cm = check_mockups()
    ctx, pg = open_tab(browser, lb, tab, scheme=scheme)
    try:
        if tab == "logs":
            pg.click("[data-sev=warning]")                                               # critical, warning and info glyphs on one page: a mix of the states
            pg.click("[data-sev=all]")
        pg.wait_for_timeout(250)
        r = pg.evaluate(cm.JS_WALK)
        low = [(t["snippet"], t["ratio"], t["ex"]) for t in r["text"] if t["ratio"] < (3.0 if t["large"] else 4.5)]
        rings = [(x["ex"], x["ratio"]) for x in r["rings"] if x["ratio"] < 3.0 and x["ex"].split(".")[0] in ("button", "a", "input", "select", "textarea")]
        assert low == [], low
        assert rings == [], rings                                                       # the borders of controls; a divider rule between rows is not a control
        assert len(r["text"]) > 40, "the walk saw too little text: it would pass on an empty page"
        assert pg.errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("tab", ["logs", "inventory"])
def test_the_page_loads_nothing_from_outside_the_console_and_never_touches_amt_mcp(browser, lb, fake_amt, tab):
    ctx, pg = open_tab(browser, lb, tab)
    try:
        origins = {u.split("/")[0] + "//" + u.split("/")[2] for u in pg.requests if u.startswith("http")}
        assert origins == {lb.origin}, origins
        assert not [u for u in pg.requests if fake_amt.base in u or u.endswith("/mcp")]
        body = pg.content()
        assert "type=\"password\"" not in body and "handoffs/" not in body
    finally:
        ctx.close()
