"""The Advanced tab (packet C6, the Advanced half): the WS-MAN browser through amt_wsman_get with Copy as JSON and Edit and Put (Get-merge-Put, the
redacted fields stripped and named), the script editor through amt_wsman_invoke with its client-side credential-name check, the guarded templates
(Unprovision behind the hold, Platform Erase shown unavailable).

Every amt-mcp answer is scripted (console_fakes.FakeAmt and a small fake WS-MAN host here that validates through amt_write's and amt_wsman_write's own
functions); no test reaches a host, and a write is only ever sent to the fake. The templates' round trip against a live enumerate is the coordinator's
receipt, not a test here: what these tests pin is that every template is a call the tool would accept and that each names the class a live check must
find. Immutables 4 and 5 (Unprovision is the hold; nothing else here is), 7 (a refusal verbatim in its own card; a refused credential pauses the server),
19 (coverage from the result), 9 (no password field or argument), plus 13, 14 and 1 on the built page."""
import asyncio
import json
import re
import time
from pathlib import Path

import pytest

import amt_wsman
import amt_wsman_write as ww
import amt_write
import mcp_client
from console_fakes import Authenticator, Console, check_mockups, enroll_first_passkey
from test_console_fleet import KEY, STATUS, device, tool_error, fc, me, settle, calls  # noqa: F401 - fixtures
from test_console_fleet_browser import open_page, text

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed: the browser immutables are NOT checked")

CONSOLE = Path(__file__).resolve().parent.parent
WIDTHS = [360, 600, 1024, 1440]
WRITE_TOOLS = {name for name, (_, read_only) in mcp_client.TOOLS.items() if not read_only}


def wait_for(fn, what, seconds=8):
    end = time.time() + seconds
    while time.time() < end:
        got = fn()
        if got:
            return got
        time.sleep(0.02)
    raise AssertionError(f"timed out waiting for {what}")


# ============================== a fake WS-MAN host: amt_wsman_get and amt_wsman_invoke ==========================================================

BOOT = {"InstanceID": "Intel(r) AMT: Boot Configuration 0", "BIOSSetup": "false", "UseIDER": "true", "UseSOL": "false", "PlatformErase": "false",
        "RSEPassword": "<redacted>", "BootMediaIndex": "0"}
PORTS = [{"InstanceID": "Intel(r) AMT Ethernet Port Settings 0", "MACAddress": "58:47:ca:00:00:01", "DHCPEnabled": "true"},
         {"InstanceID": "Intel(r) AMT Ethernet Port Settings 1", "MACAddress": "58:47:ca:00:00:02", "DHCPEnabled": "false"}]


class Wsman:
    """Answers like amt_wsman_get (get / enumerate over `instances`, the tool's own refusals for a bad class or selectors on an enumerate) and like
    amt_wsman_invoke: the same pre-I/O validation in the same order (amt_write._field_values, amt_wsman_write.refuse_secret_names, fields_xml), then a
    scripted answer. `answer` (a function of the arguments) replaces the default success."""

    def __init__(self):
        self.instances = {"AMT_BootSettingData": dict(BOOT), "AMT_EthernetPortSettings": [dict(p) for p in PORTS]}
        self.answer = None
        self.max = 200

    def get(self, a):
        try:
            amt_wsman.resource_uri(a["class_name"])
        except ValueError as ex:
            return tool_error(f"Error executing tool amt_wsman_get: {ex}")
        have = self.instances.get(a["class_name"])
        if have is None:
            return tool_error(f"Error executing tool amt_wsman_get: wsman_fault:No such class {a['class_name']}")
        if a.get("operation", "get") == "enumerate":
            if a.get("selectors"):
                return tool_error("Error executing tool amt_wsman_get: selectors_not_supported_for_enumerate")
            items = have if isinstance(have, list) else [have]
            return {"device": a["device"], "class": a["class_name"], "operation": "enumerate", "count": len(items[:self.max]), "truncated": len(items) > self.max,
                    "instances": items[:self.max]}
        return {"device": a["device"], "class": a["class_name"], "operation": "get", "instance": have[0] if isinstance(have, list) else have}

    def invoke(self, a):
        try:
            wire = amt_write._field_values(a.get("fields"))
            ww.refuse_secret_names(wire)
            ww.refuse_secret_names(a.get("selectors"))
            amt_wsman.resource_uri(a["class_name"])
            ww.fields_xml(wire)
        except ValueError as ex:
            return tool_error(f"Error executing tool amt_wsman_invoke: {ex}")
        if self.answer:
            return self.answer(a)
        base = {"device": a["device"], "operation": a["operation"], "class": a["class_name"], "method": a.get("method")}
        if a["operation"] == "invoke":
            return {**base, "result": {"ReturnValue": "0"}}
        return {**base, "result": {"InstanceID": "x"}}


# ============================== the built page and what it pins (no browser) ====================================================================

def live_tools():
    import amt_server
    return {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}


GET_SCHEMA = live_tools()["amt_wsman_get"].inputSchema      # read at import: a running browser loop forbids asyncio.run later


def test_the_advanced_tab_is_built_with_its_own_script_and_no_inline_style(me):
    page = me.get(f"/server/{KEY}/wsman").text
    assert 'id="wsman-page"' in page and f'data-server="{KEY}"' in page and "/static/wsman.js" in page and "built in a later step" not in page and "@@" not in page
    assert page.count('<script src="/static/') == page.count("<script src=") and "/static/status.js" in page
    assert "style=" not in page.split('id="wsman-page"')[1].split("</main>")[0], "the console's CSP forbids inline styles"
    assert f'href="/server/{KEY}/wsman" aria-current=page' in page
    assert not [s for s in ("logs.js", "inventory.js", "settings.js", "power.js") if s in page], "a tab loads only its own script"


def test_the_page_sends_only_what_the_live_tool_schemas_take():
    live = live_tools()
    get, inv = live["amt_wsman_get"].inputSchema["properties"], live["amt_wsman_invoke"].inputSchema["properties"]
    assert {"device", "class_name", "operation", "selectors", "max_items"} == set(get) and get["operation"]["enum"] == ["get", "enumerate"]
    assert {"device", "operation", "class_name", "method", "fields", "selectors", "confirmed"} == set(inv) and inv["operation"]["enum"] == ["put", "create", "delete", "invoke"]
    assert mcp_client.TOOLS["amt_wsman_get"] == (True, True) and mcp_client.TOOLS["amt_wsman_invoke"] == (True, False)       # a device is named; a write carries confirmed
    src = (CONSOLE / "static" / "wsman.js").read_text()
    assert re.search(r"CLASS_NAME = /\^\(AMT\|CIM\|IPS\)_\[A-Za-z0-9_\]\{1,80\}\$/", src) and amt_wsman.CLASS_NAME.pattern == r"(AMT|CIM|IPS)_[A-Za-z0-9_]{1,80}"
    assert amt_wsman.SELECTOR_NAME.pattern == "[A-Za-z0-9_.-]{1,64}" and "SELECTOR_NAME = /^[A-Za-z0-9_.-]{1,64}$/" in src
    assert ww.FIELD_NAME.pattern == r"[A-Za-z][A-Za-z0-9_]{0,63}" and "FIELD_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/" in src
    assert ww.METHOD_NAME.pattern == r"[A-Za-z][A-Za-z0-9_]{0,63}" and "METHOD_NAME = /^[A-Za-z][A-Za-z0-9_]{0,63}$/" in src


@pytest.mark.parametrize("name", ["wsman.js"])
def test_what_a_tool_or_a_host_says_is_never_set_as_markup(name):
    src = (CONSOLE / "static" / name).read_text()
    for banned in ("innerHTML", "outerHTML", "insertAdjacentHTML", "document.write", "eval(", "new Function"):
        assert banned not in src, (name, banned)


def test_the_credential_name_rule_in_the_page_is_the_tools_rule():
    src = (CONSOLE / "static" / "wsman.js").read_text()
    assert re.search(r"var SECRET_FIELD = /(.*?)/i;", src).group(1) == amt_wsman.SECRET_FIELD.pattern
    assert set(re.findall(r"'(\w+)'", re.search(r"var SECRET_WORDS = \[(.*?)\];", src).group(1))) == set(amt_wsman.SECRET_WORDS)
    assert re.search(r"var WORD = /(.*?)/g;", src).group(1) == amt_wsman._WORD.pattern
    assert set(re.findall(r"'(\w+)'", re.search(r"var NOT_CREDENTIAL = \[(.*?)\];", src).group(1))) == set(amt_wsman.NOT_CREDENTIAL_NAMES)


def test_a_wsman_write_without_a_named_device_or_without_confirmed_is_refused_before_it_is_sent(me, fake_amt):
    for args in ({"operation": "invoke", "class_name": "IPS_OptInService", "method": "CancelOptIn", "confirmed": True},
                 {"device": KEY, "operation": "invoke", "class_name": "IPS_OptInService", "method": "CancelOptIn"}):
        reply = me.post("/api/call", {"tool": "amt_wsman_invoke", "arguments": args})
        assert reply.status == 400 and reply.json()["error"] in ("device_not_named", "confirmed_not_true")
    assert calls(fake_amt, "amt_wsman_invoke") == []
    reply = me.post("/api/call", {"tool": "amt_wsman_get", "arguments": {"class_name": "AMT_BootSettingData"}})
    assert reply.status == 400 and reply.json() == {"error": "device_not_named"}


def test_a_401_in_a_wsman_read_pauses_the_server_and_it_is_not_read_again(me, fake_amt):
    fake_amt.results["amt_wsman_get"] = lambda a: tool_error("Error executing tool amt_wsman_get: wsman_auth_failed_401")
    settle(me)
    r = me.post("/api/call", {"tool": "amt_wsman_get", "arguments": {"device": KEY, "class_name": "AMT_BootSettingData", "operation": "get"}}).json()
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
def wb(tmp_path, fake_amt):
    """A signed-in console, the server read once, a fake WS-MAN host answering amt_wsman_get and amt_wsman_invoke."""
    console = Console(tmp_path, fake_amt)
    enroll_first_passkey(console, Authenticator(console.app.cfg.rp_id, console.origin))
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [device()]}
    fake_amt.results["amt_status"] = lambda a: {**STATUS, "device": a["device"]}
    fake_amt.results["amt_mirror_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_serial_link"] = lambda a: {"device": a["device"], "live": False}
    fake_amt.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
    fake_amt.results["amt_identities"] = lambda a: {"identities": []}
    fake_amt.host = Wsman()
    fake_amt.results["amt_wsman_get"] = fake_amt.host.get
    fake_amt.results["amt_wsman_invoke"] = fake_amt.host.invoke
    console.app.fleet.refresh_devices()
    console.app.fleet.refresh(KEY)
    yield console
    console.close()


def open_ws(browser, wb, width=1024, scheme="light", **kw):
    ctx, pg = open_page(browser, wb, f"/server/{KEY}/wsman", width=width, scheme=scheme, **kw)
    pg.set_default_timeout(8000)
    pg.wait_for_selector("#ws-templates li")
    pg.wait_for_function("() => window.amtc && window.amtc.csrf")
    return ctx, pg


def gets(fake):
    return calls(fake, "amt_wsman_get")


def invokes(fake):
    return calls(fake, "amt_wsman_invoke")


def read(pg, fake, cls=None, op=None, selectors=None):
    """Fill the browser, press Read, and wait for the one read it makes to have been drawn."""
    if cls is not None:
        pg.fill("#ws-class", cls)
    if op is not None:
        pg.click(f'#ws-op [data-op="{op}"]')
    if selectors is not None:
        pg.fill("#ws-selectors", selectors)
    before = len(gets(fake))
    pg.click("#ws-read")
    wait_for(lambda: len(gets(fake)) == before + 1, "the read")
    pg.wait_for_function("() => !document.querySelector('#ws-state .progress') && !document.getElementById('ws-read').hasAttribute('aria-disabled')")


def tree(pg):
    return pg.inner_text("#ws-tree")


def sheet(pg):
    return pg.evaluate("() => { const s = Array.from(document.querySelectorAll('.sheet.open')).pop(); return s ? { force: s.hasAttribute('data-force-sheet'), plain: s.hasAttribute('data-confirm-sheet'), "
                       "call: s.querySelector('.call').textContent, title: s.querySelector('h2').textContent, say: s.querySelector('.consequence').textContent } : null; }")


def confirm_plain(pg):
    pg.click(".sheet.open [data-confirm]")


def hold_force(pg):
    pg.wait_for_timeout(400)
    k = pg.query_selector(".sheet.open .force-control[data-hold]")
    b = k.bounding_box()
    pg.mouse.move(b["x"] + b["width"] / 2, b["y"] + b["height"] / 2)
    pg.mouse.down(); pg.wait_for_timeout(1400); pg.mouse.up(); pg.wait_for_timeout(150)


def editor(pg):
    return {"op": pg.evaluate("() => document.querySelector('#ed-op [aria-pressed=true]').getAttribute('data-op')"), "class": pg.input_value("#ed-class"), "method": pg.input_value("#ed-method"),
            "selectors": pg.input_value("#ed-selectors"), "fields": pg.input_value("#ed-fields")}


def fill_editor(pg, op, cls, method="", selectors="", fields=""):
    pg.click(f'#ed-op [data-op="{op}"]')
    pg.fill("#ed-class", cls)
    if op == "invoke":
        pg.fill("#ed-method", method)
    pg.fill("#ed-selectors", selectors)
    pg.fill("#ed-fields", fields)


def run_why(pg):
    return pg.inner_text("#ed-run ~ .reason") if pg.get_attribute("#ed-run", "aria-disabled") == "true" else None


# -- the browser: read on request, the instance as returned, redacted fields marked ---------------------------------------------------

def test_nothing_is_read_until_asked_and_a_get_shows_the_instance_with_the_redacted_field_marked(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        pg.wait_for_timeout(300)
        assert gets(fake_amt) == [] and "Nothing read yet" in tree(pg) and pg.is_hidden("#ws-cov")
        assert pg.get_attribute("#ws-copy", "aria-disabled") == "true" and text(pg, "#ws-copy ~ .reason") == "read first"
        assert pg.get_attribute("#ws-edit", "aria-disabled") == "true" and text(pg, "#ws-edit ~ .reason") == "read an instance first"
        read(pg, fake_amt)
        assert gets(fake_amt) == [{"device": KEY, "class_name": "AMT_BootSettingData", "operation": "get"}]
        lines = tree(pg).split("\n")
        assert lines[0] == "AMT_BootSettingData" and re.fullmatch(r"  RSEPassword\s+\[redacted\]   \(credential-named\)", next(l for l in lines if "RSEPassword" in l))
        assert re.fullmatch(r"  UseIDER\s+true", next(l for l in lines if "UseIDER" in l)) and re.fullmatch(r"  InstanceID\s+Intel\(r\) AMT: Boot Configuration 0", lines[1])
        assert text(pg, "#ws-cov") == "Coverage: One instance, as the device returned it." and pg.get_attribute("#ws-cov", "class") == "banner"
        assert text(pg, "#ws-call") == ('tools/call amt_wsman_get {device: "my-server-1", class_name: "AMT_BootSettingData", operation: "get"} · read-only · redacted fields are marked as the tool returned them')
        assert pg.get_attribute("#ws-copy", "aria-disabled") is None and pg.get_attribute("#ws-edit", "aria-disabled") is None and pg.errors == []
        assert pg.get_attribute("#ws-tree", "tabindex") == "0"
    finally:
        ctx.close()


def test_a_get_carries_the_selectors_as_typed_and_an_enumerate_carries_none(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, selectors='{"InstanceID": "Intel(r) AMT: Boot Configuration 0"}')
        assert gets(fake_amt)[-1] == {"device": KEY, "class_name": "AMT_BootSettingData", "operation": "get", "selectors": {"InstanceID": "Intel(r) AMT: Boot Configuration 0"}}
        pg.click('#ws-op [data-op="enumerate"]')
        assert pg.get_attribute("#ws-selectors", "aria-disabled") == "true" and "not valid with enumerate" in text(pg, "#ws-selectors-help")
        read(pg, fake_amt, cls="AMT_EthernetPortSettings")
        assert gets(fake_amt)[-1] == {"device": KEY, "class_name": "AMT_EthernetPortSettings", "operation": "enumerate"}      # the typed selectors are not sent
        assert "AMT_EthernetPortSettings [1 of 2]" in tree(pg) and "AMT_EthernetPortSettings [2 of 2]" in tree(pg)
        assert text(pg, "#ws-cov") == "Coverage: 2 instance(s) read. Nothing was truncated."
        assert pg.get_attribute("#ws-edit", "aria-disabled") == "true" and text(pg, "#ws-edit ~ .reason") == "get one instance to edit it: enumerate carries no selectors for a Put"
    finally:
        ctx.close()


def test_the_class_list_and_its_keys_are_the_live_measured_table():
    """Designer ruling 2026-10-21: a suggestion list of every class amt-mcp's code names, with the get keys measured live (read-only) on my-server-1."""
    src = (CONSOLE / "static" / "wsman.js").read_text()
    body = re.search(r"var CLASS_KEYS = \{(.*?)\n  \};", src, re.S).group(1)
    table = {c: (json.loads(k) if k != "null" else None) for c, k in re.findall(r"(\w+): (null|\[[^\]]*\])", body)}
    measured = json.loads((CONSOLE / "tests" / "data" / "wsman_class_keys.json").read_text())["keys"]
    assert table == measured and len(table) >= 40
    assert all(amt_wsman.CLASS_NAME.fullmatch(c) for c in table)
    page = (CONSOLE / "pages" / "content-server-wsman.html").read_text()
    assert 'list="ws-classes"' in page and '<datalist id="ws-classes">' in page


def test_picking_a_class_never_reads_and_shows_its_keys_as_a_placeholder(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        assert pg.eval_on_selector_all("#ws-classes option", "os => os.length") >= 40
        pg.fill("#ws-class", "CIM_SoftwareIdentity")
        assert pg.get_attribute("#ws-selectors", "placeholder") == '{"InstanceID":"…"}' and pg.input_value("#ws-selectors") == ""
        assert text(pg, "#ws-selectors-help") == "keys: InstanceID · empty = bare get (one-instance class) · or enumerate and pick"
        pg.fill("#ws-class", "CIM_Processor")
        assert pg.get_attribute("#ws-selectors", "placeholder") == '{"CreationClassName":"…","DeviceID":"…","SystemCreationClassName":"…","SystemName":"…"}'
        pg.fill("#ws-class", "AMT_NotOnTheList")
        assert text(pg, "#ws-selectors-help") == "JSON text values · empty = bare get (one-instance class)"
        pg.wait_for_timeout(200)
        assert gets(fake_amt) == []                                                                   # a pick is not a read
    finally:
        ctx.close()


def test_an_enumerate_offers_its_instances_and_a_pick_fills_a_get_without_reading(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        assert pg.is_hidden("#ws-instances")
        read(pg, fake_amt, cls="AMT_EthernetPortSettings", op="enumerate")
        chips = pg.eval_on_selector_all("#ws-instances button", "bs => bs.map(b => b.textContent)")
        assert chips == [p["InstanceID"] for p in PORTS] and pg.is_visible("#ws-instances")
        n = len(gets(fake_amt))
        pg.click("#ws-instances button >> nth=1")
        assert pg.get_attribute('#ws-op [data-op="get"]', "aria-pressed") == "true" and pg.get_attribute("#ws-selectors", "aria-disabled") is None
        assert json.loads(pg.input_value("#ws-selectors")) == {"InstanceID": PORTS[1]["InstanceID"]}
        pg.wait_for_timeout(200)
        assert len(gets(fake_amt)) == n                                                               # filled, not read
        read(pg, fake_amt)
        assert gets(fake_amt)[-1] == {"device": KEY, "class_name": "AMT_EthernetPortSettings", "operation": "get", "selectors": {"InstanceID": PORTS[1]["InstanceID"]}}
        assert pg.is_hidden("#ws-instances")                                                          # a get offers no instance row
    finally:
        ctx.close()


@pytest.mark.parametrize("cls,selectors,reason", [
    ("", "", "enter a class"), ("Win32_Foo", "", "class must be AMT_, CIM_ or IPS_ and a name"), ("AMT_", "", "class must be AMT_, CIM_ or IPS_ and a name"),
    ("AMT_BootSettingData", "{nope", "selectors is not valid JSON"), ("AMT_BootSettingData", "[1]", "selectors must be a JSON object"),
    ("AMT_BootSettingData", '{"a": 1}', "selectors are names and text values"), ("AMT_BootSettingData", '{"bad name": "x"}', "selectors are names and text values")])
def test_an_input_the_tool_would_refuse_never_reads_and_says_why(browser, wb, fake_amt, cls, selectors, reason):
    ctx, pg = open_ws(browser, wb)
    try:
        pg.fill("#ws-class", cls); pg.fill("#ws-selectors", selectors)
        assert pg.get_attribute("#ws-read", "aria-disabled") == "true" and text(pg, "#ws-read ~ .reason") == reason
        pg.click("#ws-read", force=True); pg.press("#ws-class", "Enter"); pg.wait_for_timeout(200)
        assert gets(fake_amt) == []
    finally:
        ctx.close()


def test_enter_in_the_class_field_reads_once(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        pg.press("#ws-class", "Enter")
        wait_for(lambda: len(gets(fake_amt)) == 1, "the read")
        pg.wait_for_timeout(300)
        assert len(gets(fake_amt)) == 1
    finally:
        ctx.close()


def test_a_truncated_enumerate_says_more_exist_and_a_result_missing_its_coverage_is_unreadable(browser, wb, fake_amt):
    wb_host = fake_amt.host
    wb_host.max = 1
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, cls="AMT_EthernetPortSettings", op="enumerate")
        assert text(pg, "#ws-cov") == "Coverage: 1 instance(s) read. The list was cut at the item cap: more exist than were read." and "live" in pg.get_attribute("#ws-cov", "class").split()
    finally:
        ctx.close()
    wb_host.max = 200
    base = wb_host.get
    for drop in ("truncated", "count", "instances", "class", "operation"):
        fake_amt.results["amt_wsman_get"] = lambda a, d=drop: {k: v for k, v in base(a).items() if k != d}
        ctx, pg = open_ws(browser, wb)
        try:
            read(pg, fake_amt, cls="AMT_EthernetPortSettings", op="enumerate")
            note = text(pg, "#ws-state .result.error")
            assert "cannot read" in note and drop in note and "nothing is shown and no Put is offered" in note, (drop, note)
            assert pg.is_hidden("#ws-cov") and "Nothing read yet" in tree(pg)
        finally:
            ctx.close()
    fake_amt.results["amt_wsman_get"] = lambda a: dict(base(a), count=5)                       # a count that is not the list's
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, cls="AMT_EthernetPortSettings", op="enumerate")
        assert "count" in text(pg, "#ws-state .result.error") and pg.is_hidden("#ws-cov")
    finally:
        ctx.close()
    fake_amt.results["amt_wsman_get"] = lambda a: {k: v for k, v in base(a).items() if k != "instance"} if a["operation"] == "get" else base(a)
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt)
        assert "instance" in text(pg, "#ws-state .result.error") and pg.get_attribute("#ws-edit", "aria-disabled") == "true"
    finally:
        ctx.close()


def test_the_tools_refusal_of_a_read_is_verbatim_text_in_its_own_card(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, cls="AMT_NoSuchThing")
        note = text(pg, "#ws-state .result.error")
        assert "refused: Error executing tool amt_wsman_get: wsman_fault:No such class AMT_NoSuchThing" in note and "read-only: nothing on the host was changed" in note
        fake_amt.results["amt_wsman_get"] = lambda a: tool_error("Error executing tool amt_wsman_get: wsman_fault:<i>x</i>")
        read(pg, fake_amt)
        assert "<i>x</i>" in text(pg, "#ws-state .result.error") and pg.query_selector("#ws-state .result.error i") is None
    finally:
        ctx.close()


def test_copy_as_json_puts_the_instance_as_returned_on_the_clipboard(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb, permissions=["clipboard-read", "clipboard-write"])
    try:
        read(pg, fake_amt)
        before = list(fake_amt.calls)
        pg.click("#ws-copy")
        pg.wait_for_function("() => document.getElementById('ws-copy').textContent.trim() === 'Copied'")
        assert json.loads(pg.evaluate("() => navigator.clipboard.readText()")) == BOOT                  # RSEPassword is still the tool's <redacted>
        assert fake_amt.calls == before and pg.evaluate("() => window.__callCount()") == 0
        read(pg, fake_amt, cls="AMT_EthernetPortSettings", op="enumerate")
        pg.click("#ws-copy")
        pg.wait_for_function("() => document.getElementById('ws-copy').textContent.trim() === 'Copied'")
        assert json.loads(pg.evaluate("() => navigator.clipboard.readText()")) == PORTS
    finally:
        ctx.close()


# -- Edit and Put: the full instance, the redacted fields stripped and named --------------------------------------------------------------

SEL = '{"InstanceID": "Intel(r) AMT: Boot Configuration 0"}'
BOOT_KEPT = {k: v for k, v in BOOT.items() if k != "RSEPassword"}


def test_edit_and_put_loads_the_full_instance_without_its_redacted_fields_and_the_sheet_names_them(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, selectors=SEL)
        pg.click("#ws-edit")
        ed = editor(pg)
        assert ed["op"] == "put" and ed["class"] == "AMT_BootSettingData" and ed["method"] == "" and json.loads(ed["selectors"]) == json.loads(SEL)
        assert json.loads(ed["fields"]) == BOOT_KEPT and "RSEPassword" not in ed["fields"]
        note = text(pg, "#ed-loaded-text")
        assert "Stripped from the Put because they were redacted in the read: RSEPassword." in note and "AMT may reset such a field when the whole instance is replaced" in note
        pg.click("#ed-run")
        got = sheet(pg)
        assert got["plain"] and not got["force"] and got["title"] == "Put AMT_BootSettingData on my-server-1 (Get-merge-Put)"
        assert "RSEPassword was redacted in the read and is stripped from this Put: AMT may reset it when the instance is replaced." in got["say"]
        assert "This tool does not read the instance back: read it in the browser afterwards." in got["say"] and "a Put may reset any field you omit" in got["say"]
        assert got["call"] == ('tools/call amt_wsman_invoke {device: "my-server-1", operation: "put", class_name: "AMT_BootSettingData", selectors: {InstanceID: "Intel(r) AMT: Boot Configuration 0"}, '
                               'fields: {InstanceID: "Intel(r) AMT: Boot Configuration 0", BIOSSetup: "false", UseIDER: "true", UseSOL: "false", PlatformErase: "false", BootMediaIndex: "0"}, confirmed: true}')
        assert invokes(fake_amt) == []
        confirm_plain(pg)
        wait_for(lambda: len(invokes(fake_amt)) == 1, "the put")
        assert invokes(fake_amt)[0] == {"device": KEY, "operation": "put", "class_name": "AMT_BootSettingData", "selectors": json.loads(SEL), "fields": BOOT_KEPT, "confirmed": True}
        assert "RSEPassword" not in json.dumps(invokes(fake_amt))
        row = "#ed-results .result.ok"
        pg.wait_for_selector(row)
        assert "put AMT_BootSettingData · accepted by AMT (no fault); this tool does not read the instance back: read it in the browser to confirm" in text(pg, row)
    finally:
        ctx.close()


def test_a_field_named_like_a_credential_is_stripped_even_when_the_tool_did_not_redact_it(browser, wb, fake_amt):
    fake_amt.host.instances["AMT_BootSettingData"]["PasswordHint"] = "visible"
    fake_amt.host.instances["AMT_BootSettingData"]["Nested"] = {"Token": "t", "Keep": "k"}
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, selectors=SEL)
        pg.click("#ws-edit")
        fields = json.loads(editor(pg)["fields"])
        assert "PasswordHint" not in fields and fields["Nested"] == {"Keep": "k"} and "RSEPassword" not in fields
        assert "RSEPassword, PasswordHint, Token" in text(pg, "#ed-loaded-text")
        assert run_why(pg) == "unsupported_nested_field:Nested"                              # a nested value the tool cannot send is left for the operator, not flattened
        fields.pop("Nested")
        pg.fill("#ed-fields", json.dumps(fields))
        pg.click("#ed-run")
        assert "RSEPassword, PasswordHint, Token were redacted in the read and are stripped from this Put: AMT may reset them" in sheet(pg)["say"]
    finally:
        ctx.close()


def test_a_credential_named_field_inside_a_list_of_objects_is_stripped_and_named_like_one_anywhere_else(browser, wb, fake_amt):
    fake_amt.host.instances["AMT_BootSettingData"]["Outer"] = [{"RFBPassword": "<redacted>", "Keep": "k"}, [{"Token": "t", "Also": "a"}]]
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, selectors=SEL)
        pg.click("#ws-edit")
        fields = json.loads(editor(pg)["fields"])
        assert fields["Outer"] == [{"Keep": "k"}, [{"Also": "a"}]]
        note = text(pg, "#ed-loaded-text")
        assert "RFBPassword" in note and "Token" in note
    finally:
        ctx.close()


def test_a_field_whose_value_is_the_redaction_marker_is_stripped_whatever_its_name(browser, wb, fake_amt):
    fake_amt.host.instances["AMT_BootSettingData"]["Banner"] = "<redacted>"                  # a device echo the tool scrubbed under a name that is not credential-like
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, selectors=SEL)
        pg.click("#ws-edit")
        assert "Banner" not in json.loads(editor(pg)["fields"]) and "RSEPassword, Banner" in text(pg, "#ed-loaded-text")
        assert re.search(r"Banner\s+\[redacted\]", tree(pg))
    finally:
        ctx.close()


def test_an_instance_with_nothing_redacted_says_so_and_the_sheet_strips_nothing(browser, wb, fake_amt):
    fake_amt.host.instances["AMT_BootSettingData"].pop("RSEPassword")
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, selectors=SEL)
        pg.click("#ws-edit")
        assert "No field was redacted." in text(pg, "#ed-loaded-text")
        pg.click("#ed-run")
        assert "stripped" not in sheet(pg)["say"] and sheet(pg)["title"].endswith("(Get-merge-Put)")
    finally:
        ctx.close()


def test_changing_the_class_or_the_selectors_after_loading_ends_the_get_merge_put_claim(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, selectors=SEL)
        pg.click("#ws-edit")
        pg.fill("#ed-selectors", '{"InstanceID": "another"}')
        pg.click("#ed-run")
        got = sheet(pg)
        assert "Get-merge-Put" not in got["title"] and "stripped" not in got["say"] and "RSEPassword" not in got["say"]
        pg.evaluate("() => window.__closeSheets()")
        pg.fill("#ed-selectors", SEL); pg.fill("#ed-class", "AMT_Other")
        pg.click("#ed-run")
        assert "Get-merge-Put" not in sheet(pg)["title"]
    finally:
        ctx.close()


# -- the editor: the client-side credential-name check, and the rest of what the tool would refuse ---------------------------------------

CASES = [
    ("invoke", "", "", "", "", "enter a class"),
    ("invoke", "IPS_OptInService", "", "", "", "invoke_needs_method"),
    ("invoke", "Foo", "CancelOptIn", "", "", 'invalid_class_name:"Foo"'),
    ("invoke", "IPS_OptInService", "Cancel Opt", "", "", 'invalid_method_name:"Cancel Opt"'),
    ("put", "AMT_BootSettingData", "", "", '{"AdminPassword": "x"}', "secret_field_refused:AdminPassword"),
    ("put", "AMT_BootSettingData", "", "", '{"Fine": 1, "UserPasswordBypass": "abc"}', "secret_field_refused:UserPasswordBypass"),
    ("create", "AMT_IPHeadersFilter", "", "", '{"Outer": [{"RFBPassword": "x"}]}', "secret_field_refused:RFBPassword"),
    ("invoke", "IPS_PowerManagementService", "RequestOSPowerSavingStateChange", "",
     '{"ManagedElement": {"epr": {"class": "CIM_ComputerSystem", "selectors": {"Passwd": "x"}}}}', "secret_field_refused:Passwd"),
    ("put", "AMT_BootSettingData", "", '{"RSEPassword": "x"}', '{"Fine": 1}', "secret_field_refused:RSEPassword"),
    ("create", "AMT_IPHeadersFilter", "", "", '{"Nested": {"a": 1}}', "unsupported_nested_field:Nested"),
    ("create", "AMT_IPHeadersFilter", "", "", '{"bad name": 1}', 'invalid_field_name:"bad name"'),
    ("delete", "AMT_EventSubscriber", "", "", "", "delete_takes_selectors_only"),
    ("delete", "AMT_EventSubscriber", "", '{"Index": "1"}', '{"Extra": 1}', "delete_takes_selectors_only"),
    ("put", "AMT_BootSettingData", "", "", "{bad", "fields is not valid JSON"),
    ("put", "AMT_BootSettingData", "", "", "[1]", "fields must be a JSON object"),
    ("put", "AMT_BootSettingData", "", "{bad", '{"A": 1}', "selectors is not valid JSON"),
    ("put", "AMT_BootSettingData", "", '{"Index": 1}', '{"A": 1}', "selectors must be text values"),
    ("put", "AMT_BootSettingData", "", '{"bad name": "1"}', '{"A": 1}', 'invalid_selector_name:"bad name"'),
]


@pytest.mark.parametrize("op,cls,method,selectors,fields,reason", CASES)
def test_a_call_the_tool_would_refuse_is_stopped_here_with_its_own_code_and_nothing_is_sent(browser, wb, fake_amt, op, cls, method, selectors, fields, reason):
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, op, cls, method, selectors, fields)
        assert run_why(pg) == reason
        pg.click("#ed-run", force=True)
        assert pg.query_selector(".sheet.open") is None
        pg.click("#ed-validate")
        row = text(pg, "#ed-results .result.error")
        assert f"refused here: {reason} · nothing sent" in row
        assert invokes(fake_amt) == [] and pg.evaluate("() => window.__callCount()") == 0
    finally:
        ctx.close()


# The tool checks a field, method or selector NAME's shape after its confirmation guard (before anything is sent), so for these the page is the earlier gate, not a mirror.
LATER = {"invalid_field_name", "invalid_method_name", "invalid_selector_name"}


@pytest.mark.parametrize("op,cls,method,selectors,fields,reason", [c for c in CASES if re.match(r"^[a-z_]+:", c[5]) and c[5].split(":")[0] not in LATER])
def test_the_code_the_page_gives_is_the_one_the_tool_gives_for_the_same_call(op, cls, method, selectors, fields, reason):
    """The client check mirrors the tool's refusal: the same call, run through amt_write.wsman_invoke's own validation, is refused with the same code."""
    code = reason.split(":")[0]
    parsed = lambda t: json.loads(t) if t else None
    with pytest.raises(Exception) as ex:
        amt_write.wsman_invoke(op, cls, method or None, parsed(fields), parsed(selectors), device=KEY, confirmed=False)
    assert str(ex.value).startswith(code), (reason, str(ex.value))


def test_the_page_and_the_tool_agree_on_which_names_are_credentials(browser, wb, fake_amt):
    names = ["RFBPassword", "DigestPassword", "UserPasswordBypass", "Rapid", "Bypass", "ProcessId", "pid", "Pid", "PID", "Token", "TokenId", "hash", "Hashed", "Pass", "PassThrough",
             "passwd", "Passphrase", "SecretKey", "apiKey", "APIKey", "PrivateKey", "SharedKey", "MasterKey", "NetAdminPass", "PSK", "psk", "Psk", "PreSharedKey", "pps", "PPS", "Pwd",
             "UserPwd", "Credential", "CredentialId", "OptInCode", "TimeoutLow", "InstanceID", "ElementName", "HostName", "Name", "Compass", "tokenizer", "Hash2", "PASS", "ActionSd",
             "X509Certificate", "BootMediaIndex", "RSEPassword", "Rapids", "lapsed", "Password", "WPA2PSK", "SnmpCommunity", "Epr", "KeyPassPhrase", "Trapid", "mPass"]
    values = [True, False, "true", "false", " TRUE ", 0, 1, 2, "x", "", None, "0", "1"]
    ctx, pg = open_ws(browser, wb)
    try:
        got = pg.evaluate("([names, values]) => names.map(n => values.map(v => window.amtc.wsman.isSecretField(n, v)))", [names, values])
        want = [[amt_wsman.is_secret_field(n, v) for v in values] for n in names]
        assert got == want
        assert any(any(row) for row in want) and not all(all(row) for row in want) and any(row[0] != row[8] for row in want), "the corpus must hold both answers"
    finally:
        ctx.close()


def test_a_flag_named_like_a_credential_is_allowed_only_while_its_value_is_a_flag(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, "put", "AMT_BootSettingData", fields='{"UserPasswordBypass": true}')
        assert run_why(pg) is None
        pg.fill("#ed-fields", '{"UserPasswordBypass": 7}')
        assert run_why(pg) == "secret_field_refused:UserPasswordBypass"
    finally:
        ctx.close()


def test_validate_only_sends_nothing_and_says_what_it_found(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        pg.click("#ed-validate")
        assert "validate invoke IPS_OptInService.CancelOptIn · no credential-named field and nothing the tool refuses on its shape · nothing sent" in text(pg, "#ed-results .result.ok")
        assert invokes(fake_amt) == [] and pg.evaluate("() => window.__callCount()") == 0
    finally:
        ctx.close()


def test_the_method_field_is_for_invoke_only(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        pg.click('#ed-op [data-op="put"]')
        assert pg.input_value("#ed-method") == "" and pg.get_attribute("#ed-method", "aria-disabled") == "true"
        pg.click('#ed-op [data-op="invoke"]')
        assert pg.get_attribute("#ed-method", "aria-disabled") is None
    finally:
        ctx.close()


# -- running: the sheet, the exact call, the result in its own words -------------------------------------------------------------------------

def run_invoke(pg, fake, n=1):
    pg.click("#ed-run"); confirm_plain(pg)
    wait_for(lambda: len(invokes(fake)) == n, f"invoke {n}")


def test_an_invoke_is_one_sheet_with_the_exact_call_and_lands_with_its_return_value(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        pg.click("#ed-run")
        got = sheet(pg)
        assert got["plain"] and not got["force"] and got["title"] == "Invoke IPS_OptInService.CancelOptIn on my-server-1"
        assert got["say"].startswith("Cancels the pending user-consent request. Calls IPS_OptInService.CancelOptIn on the AMT host with the fields shown.") and "No safeguard other than this confirmation applies." in got["say"]
        assert got["call"] == 'tools/call amt_wsman_invoke {device: "my-server-1", operation: "invoke", class_name: "IPS_OptInService", method: "CancelOptIn", confirmed: true}'
        assert invokes(fake_amt) == []
        confirm_plain(pg)
        wait_for(lambda: len(invokes(fake_amt)) == 1, "the invoke")
        assert invokes(fake_amt) == [{"device": KEY, "operation": "invoke", "class_name": "IPS_OptInService", "method": "CancelOptIn", "confirmed": True}]
        pg.wait_for_selector("#ed-results .result.ok")
        assert "invoke IPS_OptInService.CancelOptIn · ReturnValue 0" in text(pg, "#ed-results .result.ok")
    finally:
        ctx.close()


@pytest.mark.parametrize("op,cls,selectors,fields,sheet_says,row", [
    ("create", "AMT_IPHeadersFilter", "", '{"Name": "f1"}', "Creates a new AMT_IPHeadersFilter instance with the fields shown.", "create AMT_IPHeadersFilter · accepted by AMT (no fault)"),
    ("delete", "AMT_EventSubscriber", '{"Index": "3"}', "", "Deletes the AMT_EventSubscriber instance the selectors pick. A SOAP fault raises. There is no undo.", "delete AMT_EventSubscriber · accepted by AMT (no fault)")])
def test_create_and_delete_are_plain_sheets_that_say_what_they_do(browser, wb, fake_amt, op, cls, selectors, fields, sheet_says, row):
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, op, cls, "", selectors, fields)
        pg.click("#ed-run")
        got = sheet(pg)
        assert got["plain"] and not got["force"] and sheet_says in got["say"] and got["title"].startswith(op.capitalize() + " " + cls)
        confirm_plain(pg)
        wait_for(lambda: len(invokes(fake_amt)) == 1, "the call")
        assert invokes(fake_amt)[0]["operation"] == op and invokes(fake_amt)[0]["confirmed"] is True
        pg.wait_for_selector("#ed-results .result.ok")
        assert row in text(pg, "#ed-results .result.ok")
    finally:
        ctx.close()


def result_text(pg):
    pg.wait_for_selector("#ed-results .result")
    return text(pg, "#ed-results .result")


def test_a_reply_without_a_return_value_is_unknown_never_success(browser, wb, fake_amt):
    fake_amt.host.answer = lambda a: {"device": a["device"], "operation": "invoke", "class": a["class_name"], "method": a["method"], "result": {"Other": "x"},
                                      "return_value": "unknown", "note": "the device replied without a ReturnValue: the request was sent; its outcome is unknown"}
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        run_invoke(pg, fake_amt)
        note = result_text(pg)
        assert "reply with no ReturnValue · return_value unknown · read the instance to confirm" in note and "its outcome is unknown" in note
        assert pg.query_selector("#ed-results .result.ok") is None and "ReturnValue 0" not in note
    finally:
        ctx.close()


def test_a_non_zero_return_value_in_a_result_is_not_called_success(browser, wb, fake_amt):
    fake_amt.host.answer = lambda a: {"device": a["device"], "operation": "invoke", "class": a["class_name"], "method": a["method"], "result": {"ReturnValue": "5"}}
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        run_invoke(pg, fake_amt)
        assert "sent; ReturnValue 5 (not 0): AMT did not confirm it" in result_text(pg) and pg.query_selector("#ed-results .result.ok") is None
    finally:
        ctx.close()


@pytest.mark.parametrize("tool_text,says,nothing", [
    ("Error executing tool amt_wsman_invoke: secret_field_refused:Foo", "", True),
    ("Error executing tool amt_wsman_invoke: unsupported_nested_field:Foo: only {'epr': {'class':..., 'selectors':{...}}}", "", True),
    ("Error executing tool amt_wsman_invoke: wsman_return_value:IPS_OptInService.CancelOptIn:1", "the request was sent and AMT's ReturnValue says it did not succeed", False),
    ("Error executing tool amt_wsman_invoke: wsman_return_value_missing:IPS_OptInService.CancelOptIn: the request was sent; its outcome is unknown", "the request was sent and AMT's ReturnValue says it did not succeed", False),
    ("Error executing tool amt_wsman_invoke: wsman_fault:The server was unable to process the request", "the text does not say whether the host changed: read the instance in the browser to see", False)])
def test_a_refusal_is_verbatim_and_says_only_what_its_text_lets_the_page_say(browser, wb, fake_amt, tool_text, says, nothing):
    fake_amt.host.answer = lambda a: tool_error(tool_text)
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        run_invoke(pg, fake_amt)
        pg.wait_for_selector("#ed-results .result.error")
        note = text(pg, "#ed-results .result.error")
        assert f"refused: {tool_text}" in note and says in note and (" · nothing sent" in note) == nothing
    finally:
        ctx.close()


def test_a_tool_text_is_rendered_as_text_never_as_markup(browser, wb, fake_amt):
    nasty = '<img src=x onerror="window.__pwned=1"><b>x</b>'
    fake_amt.host.instances["AMT_BootSettingData"].update({"Evil": nasty, nasty: "v"})
    fake_amt.host.answer = lambda a: tool_error(f"Error executing tool amt_wsman_invoke: wsman_fault:{nasty}")
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt)
        assert nasty in tree(pg) and pg.query_selector("#ws-tree img, #ws-tree b") is None
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        run_invoke(pg, fake_amt)
        pg.wait_for_selector("#ed-results .result.error")
        assert nasty in text(pg, "#ed-results .result.error") and pg.query_selector("#ed-results img, #ed-results b") is None and pg.evaluate("() => window.__pwned === undefined")
        assert pg.errors == []
    finally:
        ctx.close()


def open_routed(browser, console, path, handler, width=1024):
    ctx = browser.new_context(viewport={"width": width, "height": 900})
    ctx.add_cookies([{"name": "amt_console_session", "value": console.cookie, "domain": console.host, "path": "/", "httpOnly": True, "secure": True, "sameSite": "Strict"}])
    ctx.route(f"{console.origin}/api/call", handler)
    pg = ctx.new_page()
    pg.set_default_timeout(8000)
    pg.goto(f"{console.origin}{path}")
    pg.wait_for_selector("#ws-templates li")
    pg.wait_for_function("() => window.amtc && window.amtc.csrf")
    return ctx, pg


def only(tool, status, code):
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
def test_a_write_the_console_could_not_make_is_not_reported_as_a_refusal_by_the_tool(browser, wb, fake_amt, status, code, says, unsure):
    ctx, pg = open_routed(browser, wb, f"/server/{KEY}/wsman", only("amt_wsman_invoke", status, code))
    try:
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        pg.click("#ed-run"); confirm_plain(pg)
        note = result_text(pg)
        assert says in note and ("did not answer" in note) == unsure and invokes(fake_amt) == []
    finally:
        ctx.close()


@pytest.mark.parametrize("status,code,says", [(502, "amt_mcp_unreachable:TimeoutError", "amt-mcp did not answer (amt_mcp_unreachable:TimeoutError)"),
                                              (503, "console_bearer_unavailable", "refused: console_bearer_unavailable · nothing sent")])
def test_a_read_the_console_could_not_make_is_not_reported_as_a_refusal_by_the_tool(browser, wb, fake_amt, status, code, says):
    ctx, pg = open_routed(browser, wb, f"/server/{KEY}/wsman", only("amt_wsman_get", status, code))
    try:
        pg.click("#ws-read")
        pg.wait_for_selector("#ws-state .result")
        note = text(pg, "#ws-state .result")
        assert says in note and ("did not answer" in note) == (status == 502) and "Nothing read yet" in tree(pg)
    finally:
        ctx.close()
    assert gets(fake_amt) == []


# -- immutable 7: a refused credential pauses the server ----------------------------------------------------------------------------------

def test_a_refused_credential_in_a_write_pauses_the_server_and_the_page_offers_no_more(browser, wb, fake_amt):
    fake_amt.host.answer = lambda a: tool_error("Error executing tool amt_wsman_invoke: wsman_auth_failed_401")
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        run_invoke(pg, fake_amt)
        pg.wait_for_selector("#ws-paused:not([hidden])")
        assert "Reading is paused for this server (credential refused)" in text(pg, "#ws-paused") and pg.get_attribute("#ws-paused a", "href") == f"/server/{KEY}"
        assert wb.app.fleet.public(KEY)["state"] == "paused" and "refused: Error executing tool amt_wsman_invoke: wsman_auth_failed_401" in text(pg, "#ed-results .result.error")
        assert pg.get_attribute("#ed-run", "aria-disabled") == "true" and text(pg, "#ed-run ~ .reason") == "paused · credential refused"
        assert pg.get_attribute("#ws-read", "aria-disabled") == "true" and text(pg, "#ws-read ~ .reason") == "paused · credential refused"
        pg.click("#ed-run", force=True); pg.click("#ws-read", force=True); pg.wait_for_timeout(300)
        assert len(invokes(fake_amt)) == 1 and gets(fake_amt) == [] and pg.query_selector(".sheet.open") is None
        before = len(calls(fake_amt, "amt_status"))
        bump = [0]
        wb.app.fleet.now = lambda: time.time() + bump[0]
        for _ in range(3):
            bump[0] += 31
            assert wb.app.fleet.step() is None
        assert len(calls(fake_amt, "amt_status")) == before
    finally:
        ctx.close()


def test_a_page_opened_on_a_paused_server_reads_and_writes_nothing_and_says_why(browser, wb, fake_amt):
    fake_amt.results["amt_status"] = lambda a: tool_error("Error executing tool amt_status: wsman_auth_failed_401")
    wb.app.fleet.refresh(KEY)
    assert wb.app.fleet.public(KEY)["state"] == "paused"
    ctx, pg = open_ws(browser, wb)
    try:
        pg.wait_for_selector("#ws-paused:not([hidden])")
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        for sel in ("#ws-read", "#ed-run"):
            assert pg.get_attribute(sel, "aria-disabled") == "true" and text(pg, f"{sel} ~ .reason") == "paused · credential refused"
            pg.click(sel, force=True)
        pg.wait_for_timeout(300)
        assert gets(fake_amt) == [] and invokes(fake_amt) == [] and "Retry once from the Status tab" in text(pg, "#ws-paused")
    finally:
        ctx.close()


def test_one_activation_of_read_is_one_read_and_the_control_says_why_it_waits(browser, wb, fake_amt):
    import threading
    gate = threading.Event()
    base = fake_amt.host.get
    fake_amt.results["amt_wsman_get"] = lambda a: (gate.wait(10), base(a))[1]
    ctx, pg = open_ws(browser, wb)
    try:
        pg.click("#ws-read")
        wait_for(lambda: len(gets(fake_amt)) == 1, "the read")
        assert pg.get_attribute("#ws-read", "aria-disabled") == "true" and text(pg, "#ws-read ~ .reason") == "waiting for amt-mcp"
        for _ in range(3):
            pg.click("#ws-read", force=True)
        pg.press("#ws-class", "Enter")
        pg.wait_for_timeout(200)
        assert len(gets(fake_amt)) == 1
        gate.set()
        pg.wait_for_function("() => !document.querySelector('#ws-state .progress') && !document.getElementById('ws-read').hasAttribute('aria-disabled')")
        assert len(gets(fake_amt)) == 1 and "AMT_BootSettingData" in tree(pg)
    finally:
        gate.set()
        ctx.close()


def test_while_a_write_is_out_run_says_why_and_a_second_activation_sends_nothing(browser, wb, fake_amt):
    import threading
    gate = threading.Event()
    fake_amt.host.answer = lambda a: (gate.wait(10), {"device": a["device"], "operation": "invoke", "class": a["class_name"], "method": a["method"], "result": {"ReturnValue": "0"}})[1]
    ctx, pg = open_ws(browser, wb)
    try:
        fill_editor(pg, "invoke", "IPS_OptInService", "CancelOptIn")
        run_invoke(pg, fake_amt)
        assert pg.get_attribute("#ed-run", "aria-disabled") == "true" and text(pg, "#ed-run ~ .reason") == "waiting for amt-mcp"
        pg.click("#ed-run", force=True); pg.wait_for_timeout(200)
        assert pg.query_selector(".sheet.open") is None and len(invokes(fake_amt)) == 1
        gate.set()
        pg.wait_for_selector("#ed-results .result.ok")
        pg.wait_for_function("() => !document.getElementById('ed-run').hasAttribute('aria-disabled')")
    finally:
        gate.set()
        ctx.close()


# ============================== the guarded templates ===========================================================================================

# The design note's list (2.13), as (title, operation, class, method, field names, selector names): what the page must offer and nothing else.
DESIGN = [
    ("OS wake from standby", "invoke", "IPS_PowerManagementService", "RequestOSPowerSavingStateChange", ["OSPowerSavingState", "ManagedElement"], []),
    ("OS power saving", "invoke", "IPS_PowerManagementService", "RequestOSPowerSavingStateChange", ["OSPowerSavingState", "ManagedElement"], []),
    ("Request a user-consent code", "invoke", "IPS_OptInService", "StartOptIn", [], []),
    ("Send a consent code", "invoke", "IPS_OptInService", "SendOptInCode", ["OptInCode"], []),
    ("Cancel a consent request", "invoke", "IPS_OptInService", "CancelOptIn", [], []),
    ("Agent presence watchdog timeouts", "put", "AMT_AgentPresenceWatchdog", None, ["TimeoutLow", "TimeoutHigh", "StartupInterval"], ["DeviceID"]),
    ("Agent presence watchdog action", "invoke", "AMT_AgentPresenceWatchdogAction", "AddAction", ["ActionSd", "ActionEac", "ActionEvent", "ActionEventOnTransition"], []),
    ("System defense filter", "create", "AMT_IPHeadersFilter", None, ["Name", "FilterDirection", "FilterProfile", "FilterProfileData", "ActionDrop", "ActionEventOnMatch"], []),
    ("System defense policy", "create", "AMT_SystemDefensePolicy", None, ["PolicyName", "PolicyPrecedence", "AntiSpoofingSupport", "FilterCreationHandles", "TxDefaultDrop",
                                                                          "TxDefaultMatchEvent", "RxDefaultDrop", "RxDefaultMatchEvent"], []),
    ("Delete an event subscription", "delete", "AMT_EventSubscriber", None, [], ["Index"]),
    ("Wake alarm", "create", "IPS_AlarmClockOccurrence", None, ["InstanceID", "StartTime", "Interval", "DeleteOnCompletion"], []),
    ("Unprovision AMT (factory reset)", "invoke", "AMT_SetupAndConfigurationService", "Unprovision", ["ProvisioningMode"], []),
]


def templates(pg):
    return pg.evaluate("() => window.amtc.wsman.TEMPLATES")


def unplaceholder(v):
    if isinstance(v, str) and re.fullmatch(r"<[^<>]+>", v):
        return "1"
    if isinstance(v, dict):
        return {k: unplaceholder(x) for k, x in v.items()}
    if isinstance(v, list):
        return [unplaceholder(x) for x in v]
    return v


def test_the_templates_are_the_design_notes_list_and_each_is_a_call_the_tool_accepts(browser, wb, fake_amt):
    from amt_tools import ConfirmationRequired
    ctx, pg = open_ws(browser, wb)
    try:
        got = templates(pg)
        assert [(t["title"], t["op"], t["cls"], t.get("method"), sorted(t.get("fields") or {}), sorted(t.get("selectors") or {})) for t in got] == [
            (title, op, cls, method, sorted(fields), sorted(sels)) for title, op, cls, method, fields, sels in DESIGN]
        assert len({t["id"] for t in got}) == len(got)
        by = {t["id"]: t for t in got}
        assert (by["os-wake"]["fields"]["OSPowerSavingState"], by["os-saving"]["fields"]["OSPowerSavingState"], by["unprovision"]["fields"]) == (2, 3, {"ProvisioningMode": 1})
        assert by["os-wake"]["fields"]["ManagedElement"] == {"epr": {"class": "CIM_ComputerSystem", "selectors": {"Name": "ManagedSystem"}}}
        for t in got:
            fields, sels = unplaceholder(t.get("fields") or {}) or None, unplaceholder(t.get("selectors") or {}) or None
            with pytest.raises(ConfirmationRequired):                                        # every pre-I/O rule passed; only the confirmation is missing
                amt_write.wsman_invoke(t["op"], t["cls"], t.get("method"), fields, sels, device=KEY, confirmed=False)
            assert fake_amt.host.invoke({"device": KEY, "operation": t["op"], "class_name": t["cls"], "method": t.get("method"), "fields": fields, "selectors": sels,
                                         "confirmed": True}).get("isError") is None, t["id"]
            for c in t["checks"]:
                assert amt_wsman.CLASS_NAME.fullmatch(c), (t["id"], c)
            assert t["cls"] in t["checks"]
            epr = [f["epr"]["class"] for f in (t.get("fields") or {}).values() if isinstance(f, dict)]
            assert set(epr) <= set(t["checks"])
            assert not [n for n in (t.get("fields") or {}) if amt_wsman.is_secret_field(n, "x")]
    finally:
        ctx.close()


def test_the_template_list_marks_each_class_a_live_check_must_enumerate_and_shows_platform_erase_unavailable(browser, wb, fake_amt):
    schema = GET_SCHEMA
    ctx, pg = open_ws(browser, wb)
    try:
        rows = pg.eval_on_selector_all("#ws-templates li[data-template]", "ls => ls.map(l => [l.getAttribute('data-template'), l.getAttribute('data-class'), l.getAttribute('data-check-classes'), l.querySelector('.txt span').textContent])")
        want = templates(pg)
        assert rows == [[t["id"], t["cls"], " ".join(t["checks"]), t["title"]] for t in want]
        assert len(rows) == 12
        # a live check iterates these: each is an amt_wsman_get enumerate that the live tool schema accepts
        import jsonschema
        for _, _, classes, _ in rows:
            for c in classes.split():
                jsonschema.validate({"device": KEY, "class_name": c, "operation": "enumerate"}, schema)
        assert pg.eval_on_selector_all("#ws-templates li", "ls => ls[ls.length - 1].id") == "platform-erase"
        erase = "#platform-erase"
        body = text(pg, erase)
        assert "Platform Erase at next boot" in body and "AMT ignores a bare Put of AMT_BootSettingData.PlatformErase" in body and "which this editor cannot chain and amt-mcp has no tool for" in body
        assert pg.get_attribute(f"{erase} button", "aria-disabled") == "true" and text(pg, f"{erase} .reason") == "no tool yet"
        pg.click(f"{erase} button", force=True)
        assert editor(pg)["class"] == "" and pg.query_selector(".sheet.open") is None and pg.evaluate("() => window.__callCount()") == 0
        assert pg.query_selector(f"{erase}[data-template]") is None
    finally:
        ctx.close()


def test_load_fills_the_editor_and_nothing_runs_until_it_is_confirmed(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        for t in templates(pg):
            pg.click(f'[data-load="{t["id"]}"]')
            ed = editor(pg)
            assert (ed["op"], ed["class"], ed["method"]) == (t["op"], t["cls"], t.get("method") or ""), t["id"]
            assert (json.loads(ed["selectors"]) if ed["selectors"] else {}) == (t.get("selectors") or {}) and (json.loads(ed["fields"]) if ed["fields"] else {}) == (t.get("fields") or {}), t["id"]
            assert text(pg, "#ed-loaded-text").startswith(f"Template: {t['title']}. Nothing runs until you confirm.")
            has_ph = "<" in ed["fields"] + ed["selectors"]
            assert run_why(pg) == ("replace the <placeholders> first" if has_ph else None), t["id"]
        assert invokes(fake_amt) == [] and gets(fake_amt) == [] and pg.evaluate("() => window.__callCount()") == 0
    finally:
        ctx.close()


def test_a_template_with_a_placeholder_is_runnable_only_once_the_placeholder_is_replaced(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        pg.click('[data-load="consent-send"]')
        assert run_why(pg) == "replace the <placeholders> first"
        pg.click("#ed-validate")
        assert "a <placeholder> is still in the call: replace it before Run · nothing sent" in text(pg, "#ed-results .result.live")
        pg.fill("#ed-fields", '{"OptInCode": 123456}')
        assert run_why(pg) is None
        pg.click("#ed-run")
        assert sheet(pg)["call"] == 'tools/call amt_wsman_invoke {device: "my-server-1", operation: "invoke", class_name: "IPS_OptInService", method: "SendOptInCode", fields: {OptInCode: 123456}, confirmed: true}'
        assert "A wrong code counts against the attempts AMT allows." in sheet(pg)["say"]
        confirm_plain(pg)
        wait_for(lambda: len(invokes(fake_amt)) == 1, "the invoke")
        assert invokes(fake_amt)[0]["fields"] == {"OptInCode": 123456}
    finally:
        ctx.close()


def test_the_watchdog_put_template_names_that_a_put_can_replace_the_whole_instance(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        pg.click('[data-load="watchdog-timeouts"]')
        assert "Get-merge-Put: read the full instance in the browser and use Edit and Put to keep every other field" in text(pg, "#ed-loaded-text")
    finally:
        ctx.close()


# -- Unprovision: the hold, because the one predicate says so --------------------------------------------------------------------------------

def load_unprovision(pg):
    pg.click('[data-load="unprovision"]')
    assert run_why(pg) is None
    pg.click("#ed-run")


def test_unprovision_is_the_hold_and_exactly_one_call_leaves_when_it_is_held(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        load_unprovision(pg)
        got = sheet(pg)
        assert got["force"] and not got["plain"] and got["title"] == "Unprovision AMT on my-server-1"
        assert got["say"].startswith("AMT is factory-reset: every setting, user, certificate and this console's access to the server are gone. Re-provisioning is a hands-on MEBx step at the machine. There is no undo.")
        assert "Calls AMT_SetupAndConfigurationService.Unprovision on the AMT host with the fields shown." in got["say"]
        assert got["call"] == ('tools/call amt_wsman_invoke {device: "my-server-1", operation: "invoke", class_name: "AMT_SetupAndConfigurationService", method: "Unprovision", '
                               'fields: {ProvisioningMode: 1}, confirmed: true}')
        assert pg.inner_text(".sheet.open .force-control .lbl") == "Hold to unprovision" and pg.query_selector(".sheet.open [data-confirm]") is None
        pg.click(".sheet.open .force-control")                                              # a click opens the second sheet; it sends nothing
        assert invokes(fake_amt) == [] and pg.evaluate("() => window.__forceFireCount()") == 0
        pg.evaluate("() => window.__closeSheets()")
        pg.click("#ed-run")
        hold_force(pg)
        wait_for(lambda: len(invokes(fake_amt)) == 1, "the held call")
        assert invokes(fake_amt) == [{"device": KEY, "operation": "invoke", "class_name": "AMT_SetupAndConfigurationService", "method": "Unprovision", "fields": {"ProvisioningMode": 1}, "confirmed": True}]
        assert pg.evaluate("() => window.__forceFireCount()") == 1
        assert pg.evaluate("() => window.__calls().map(c => c.forced)") == [True]
        pg.wait_for_selector("#ed-results .result.ok")
    finally:
        ctx.close()


def test_the_second_sheet_of_unprovision_repeats_the_call_and_names_the_consequence(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        load_unprovision(pg)
        pg.click(".sheet.open .force-control")                                              # a click is not a hold: it opens the second sheet
        pg.wait_for_timeout(500)
        second = sheet(pg)
        assert second["title"] == "Unprovision AMT on my-server-1" and "method: \"Unprovision\"" in second["call"] and "factory-reset" in second["say"]
        assert pg.inner_text(".sheet.open [data-confirm]") == "Unprovision now" and invokes(fake_amt) == []
    finally:
        ctx.close()


EXPECTED_FORCE = {"click": (0, True), "hold600": 0, "hold1400_slideoff": 0, "swipe": 0, "hold1400_release": 1,
                  "click_450_click": (0, True), "click_700_click": (0, True), "dblclick": (0, True), "click_click_wait_confirm": (1, "true"),
                  "enter_held": (0, False), "enter_wait_enter": (0, False), "enter_release_550_tab_enter": (1, "true"),
                  "enter_held_600_not_armed": ("false", 0)}


@pytest.mark.parametrize("width", [1024, 360])
def test_the_force_matrix_on_the_unprovision_control(browser, wb, fake_amt, width):
    ctx, pg = open_ws(browser, wb, width=width)
    try:
        load_unprovision(pg)
        pg.evaluate("() => window.__closeSheets()")
        assert pg.eval_on_selector_all(".force-control[data-hold]", "els => els.length") == 1
        got = check_mockups().force_matrix(pg, 0)
        assert got is not None, "no force control was found"
        assert got["opener_point"] != "CONFIRM", "the second sheet's confirm sits under the opener's point"
        got.pop("opener_point")
        assert got == EXPECTED_FORCE
    finally:
        ctx.close()


def test_a_tap_then_a_tap_500_ms_later_never_fires_unprovision(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb, width=360, has_touch=True)
    try:
        load_unprovision(pg)
        pg.evaluate("() => window.__closeSheets()")
        assert check_mockups().tap_matrix(pg, 0) == (0, True)
        assert invokes(fake_amt) == []
    finally:
        ctx.close()


# -- immutables 4 and 5 on this page ------------------------------------------------------------------------------------------------------------

def test_a_bare_click_on_any_control_sends_no_write_and_fires_no_hold(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, selectors=SEL)
        gets_before = len(gets(fake_amt))
        n = pg.evaluate("""() => {
          document.addEventListener('click', e => { const a = e.target.closest('a[href]'); if (a) e.preventDefault(); }, true);
          const ctrls = () => Array.from(document.querySelectorAll('#wsman-page button, #wsman-page a[href]')).filter(el => !el.closest('.sheet') && !el.closest('#ws-read-wrap'));
          const n = ctrls().length;
          for (let i = 0; i < n; i++) { const el = ctrls()[i]; if (el) el.click(); window.__closeSheets(); }
          return n;
        }""")
        pg.wait_for_timeout(300)
        assert n >= 20, f"the sweep saw {n} controls: it would pass on an empty page"
        assert pg.evaluate("() => window.__callCount()") == 0 and pg.evaluate("() => window.__forceFireCount()") == 0 and pg.query_selector(".sheet.open") is None
        assert invokes(fake_amt) == [] and len(gets(fake_amt)) == gets_before
    finally:
        ctx.close()
    assert [t for t, a, _ in fake_amt.calls if t in WRITE_TOOLS and a.get("action") not in ("status", "list")] == []


def test_every_plain_confirm_sheet_of_the_page_sends_one_call_and_manages_focus(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, selectors=SEL)
        pg.click("#ws-edit"); pg.click("#ed-run"); pg.evaluate("() => window.__closeSheets()")                    # the Put sheet
        pg.click('[data-load="consent-cancel"]'); pg.click("#ed-run"); pg.evaluate("() => window.__closeSheets()")  # the invoke sheet (same id, rebuilt)
        assert pg.eval_on_selector_all(".sheet[data-confirm-sheet]", "ss => ss.length") == 1
        checks = check_mockups().confirm_checks(pg)
        assert len(checks) == 1
        for c in checks:
            assert c["click"] == 1 and c["enter_held"] == 1, c
            assert c["focus_key"] == {"inSheet": True, "isCancel": True} and c["focus_ptr"] and c["trapped"], c
    finally:
        ctx.close()


def test_only_unprovision_is_in_the_destructive_set_and_the_predicates_controls_hold(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        pg.click('[data-load="consent-cancel"]'); pg.click("#ed-run"); confirm_plain(pg)
        wait_for(lambda: len(invokes(fake_amt)) == 1, "the plain call")
        pg.wait_for_selector("#ed-results .result.ok")
        load_unprovision(pg)
        hold_force(pg)
        wait_for(lambda: len(invokes(fake_amt)) == 2, "the held call")
        spy = pg.evaluate("() => window.__calls().map(c => ({ forced: c.forced, destructive: window.__destructiveCall({ tool: c.tool, arguments: c.arguments, then: c.then }, c.ctx), method: c.arguments.method }))")
        assert spy == [{"forced": False, "destructive": False, "method": "CancelOptIn"}, {"forced": True, "destructive": True, "method": "Unprovision"}]
        flags = pg.evaluate("""(ts) => ts.map(t => window.__destructiveCall({ tool: 'amt_wsman_invoke', arguments: { device: 'x', operation: t.op, class_name: t.cls, method: t.method } }))""", templates(pg))
        assert flags == [t["id"] == "unprovision" for t in templates(pg)]
        controls = pg.evaluate("""() => [
          window.__destructiveCall({ tool: 'amt_wsman_invoke', arguments: { operation: 'put', class_name: 'AMT_SetupAndConfigurationService', fields: { Any: 1 } } }),
          window.__destructiveCall({ tool: 'amt_wsman_invoke', arguments: { operation: 'invoke', class_name: 'AMT_SetupAndConfigurationService', method: 'GetPowerSavingState' } }),
          window.__destructiveCall({ tool: 'amt_wsman_invoke', arguments: { operation: 'invoke', class_name: 'AMT_SetupAndConfigurationService', method: 'Unprovision', fields: { ProvisioningMode: 1 } } }),
          window.__destructiveCall({ tool: 'amt_wsman_get', arguments: { class_name: 'AMT_SetupAndConfigurationService' } })]""")
        assert controls == [False, False, True, False]
    finally:
        ctx.close()


def test_no_password_is_a_field_or_an_argument_on_this_page(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt, selectors=SEL)
        pg.click("#ws-edit"); pg.click("#ed-run"); confirm_plain(pg)
        wait_for(lambda: len(invokes(fake_amt)) == 1, "the put")
        body = pg.content()
        assert 'type="password"' not in body and "new-password" not in body and pg.query_selector("input[type=password], [autocomplete=new-password]") is None
        assert "RSEPassword" not in json.dumps(invokes(fake_amt)) and not [s for s in pg.evaluate("() => window.__calls().map(c => JSON.stringify(c.arguments))") if "assword" in s]
        assert not [r for r in fake_amt.calls if "<redacted>" in json.dumps(r[1])]
    finally:
        ctx.close()


# ============================== layout, contrast and the outside world ==========================================================================

def stage(pg, fake):
    """A read tree, a template loaded, a validation result and a refusal, so the walk sees each state."""
    read(pg, fake, selectors=SEL)
    pg.click('[data-load="consent-send"]')
    pg.click("#ed-validate")
    fake.host.answer = lambda a: tool_error("Error executing tool amt_wsman_invoke: wsman_fault:The server was unable to process the request")
    pg.fill("#ed-fields", '{"OptInCode": 123456}')
    pg.click("#ed-run"); confirm_plain(pg)
    pg.wait_for_selector("#ed-results .result.error")


@pytest.mark.parametrize("width", WIDTHS)
def test_the_page_fits_every_width_with_hit_areas_and_a_16_px_gutter(browser, wb, fake_amt, width):
    cm = check_mockups()
    ctx, pg = open_ws(browser, wb, width=width)
    try:
        stage(pg, fake_amt)
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


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_every_text_and_ring_on_the_page_clears_the_contrast_floors(browser, wb, fake_amt, scheme):
    cm = check_mockups()
    ctx, pg = open_ws(browser, wb, scheme=scheme)
    try:
        stage(pg, fake_amt)
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


def test_the_page_loads_nothing_from_outside_the_console_and_never_touches_amt_mcp(browser, wb, fake_amt):
    ctx, pg = open_ws(browser, wb)
    try:
        read(pg, fake_amt)
        origins = {u.split("/")[0] + "//" + u.split("/")[2] for u in pg.requests if u.startswith("http")}
        assert origins == {wb.origin}, origins
        assert not [u for u in pg.requests if fake_amt.base in u or u.endswith("/mcp")]
        body = pg.content()
        assert "type=\"password\"" not in body and "handoffs/" not in body
    finally:
        ctx.close()
