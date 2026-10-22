"""The Servers and Identities pages in a real browser (headless Chromium), in front of amt-mcp's real device and identity code (packet C7).

The fixtures are test_console_manage's: a devices file in a temp folder, a vault that is a child process on a JSON file, the real one-time
PUT. Immutables 4 (a bare click writes nothing; one deliberate activation, one call), 5 (re-pin, remove and identity remove are holds, by the
call's arguments), 9 (the value field, the scan of the page and its requests), 10 (fingerprints in groups of four with the bold prefix, the
mismatch state, the last server) and 21 (write-only identities), plus layout and contrast at every width and nothing from outside."""
import json
import re
import time

import pytest

import amt_upload
from console_fakes import check_mockups
from test_console_fleet import KEY
from test_console_fleet_browser import calls, open_page, text
from test_console_manage import ADDR, ADDR_LAB, ADDR_MOVED, LEAF_A, LEAF_B, LEAF_C, SENTINEL, mg, real  # noqa: F401 - fixtures
from test_console_media import confirm_plain, hold_force, sheet_kind, until

sync_api = pytest.importorskip("playwright.sync_api", reason="playwright is not installed: the browser immutables are NOT checked")

WIDTHS = [360, 600, 1024, 1440]
EXPECTED_FORCE = {"click": (0, True), "hold600": 0, "hold1400_slideoff": 0, "swipe": 0, "hold1400_release": 1,
                  "click_450_click": (0, True), "click_700_click": (0, True), "dblclick": (0, True), "click_click_wait_confirm": (1, "true"),
                  "enter_held": (0, False), "enter_wait_enter": (0, False), "enter_release_550_tab_enter": (1, "true"),
                  "enter_held_600_not_armed": ("false", 0)}
WRITES = ("amt_device_manage", "amt_identity_manage")


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
def mb(mg, real):
    """The signed-in console with the server read once by the fleet (its pin state: matches)."""
    mg.app.fleet.refresh_devices()
    mg.app.fleet.refresh(KEY)
    return mg


def servers_page(browser, mb, width=1024, scheme="light", rows=1, **kw):
    ctx, pg = open_page(browser, mb, "/manage", width=width, scheme=scheme, **kw)
    pg.set_default_timeout(8000)
    until(pg, f"() => document.querySelectorAll('#srv-rows tr').length >= {rows}")
    return ctx, pg


def identities_page(browser, mb, width=1024, scheme="light", **kw):
    ctx, pg = open_page(browser, mb, "/manage/identities", width=width, scheme=scheme, **kw)
    pg.set_default_timeout(8000)
    until(pg, "() => document.querySelectorAll('#id-list li').length >= 1 && document.getElementById('nid-owner').options.length >= 1")
    return ctx, pg


def writes(fake):
    return [(t, a) for t, a, _ in fake.calls if t in WRITES and a.get("confirmed")]


def results(pg, slot):
    return [pg.inner_text(f"#{slot} .result:nth-child({i})").replace("\n", " ") for i in range(1, pg.locator(f"#{slot} .result").count() + 1)]


def row(key=KEY):
    return f'#srv-rows tr[data-key="{key}"]'


def btn(label, key=KEY):
    return f'#srv-rows button[aria-label="{label} {key}"]'


def reason_of(pg, sel):
    return text(pg, f"{sel} ~ .reason")


def second_server(real):
    """A second registered server, added through amt-mcp's own writer (so the file and its pin are real)."""
    out = real.device_manage({"action": "add", "device": "lab", "ip": ADDR_LAB, "amt_vault_key": "lab-amt"})
    assert out["added"]["tls_leaf_sha256"] == LEAF_C


# -- the table: every cell from amt-mcp's answers ---------------------------------------------------------------------------------

def test_the_table_row_has_the_ports_the_identity_chips_the_pin_chip_and_the_full_fingerprint_in_groups_of_four(browser, mb, real):
    ctx, pg = servers_page(browser, mb)
    try:
        r = row()
        assert text(pg, f"{r} td[data-l=Key]") == KEY and text(pg, f"{r} td[data-l='AMT address']") == ADDR and text(pg, f"{r} td[data-l=Ports]") == "16993 / 16995"
        chips = pg.eval_on_selector_all(f"{r} td.ids .chip", "els => els.map(e => [e.getAttribute('data-identity'), e.className, e.textContent.trim()])")
        assert chips == [["present", "chip small ok", f"{KEY}-amt"], ["present", "chip small ok", f"{KEY}-debian"]]
        assert text(pg, f"{r} [data-pin=matches]") == "pin matches" and pg.get_attribute(r, "data-pin-row") == "matches"
        fp = pg.eval_on_selector(f"{r} .fp", "e => ({ text: e.textContent, bold: Array.from(e.querySelectorAll('b')).map(b => b.textContent) })")
        groups = fp["text"].split(" ")
        assert len(groups) == 16 and all(re.fullmatch(r"[0-9a-f]{4}", g) for g in groups) and "".join(groups) == LEAF_A     # in full, never masked
        assert fp["bold"] == [LEAF_A[i:i + 4] for i in (0, 4, 8, 12)]                                                       # the stored 16-hex prefix in bold
        assert text(pg, "#srv-count") == "1 server · the devices file · amt_devices"
        assert real.probes == [] and pg.errors == []                                                                         # nothing read the leaf on its own
    finally:
        ctx.close()


def test_the_last_servers_remove_is_greyed_with_its_reason_as_visible_text(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        rm = btn("Remove")
        assert pg.get_attribute(rm, "aria-disabled") == "true"
        assert reason_of(pg, rm) == "the last server: amt_device_manage refuses to remove it" and pg.is_visible(f"{rm} ~ .reason")
        pg.click(rm, force=True)
        assert pg.locator(".sheet.open").count() == 0 and writes(fake_amt) == []
    finally:
        ctx.close()


def test_a_second_server_makes_remove_available_and_the_count_says_two(browser, mb, real):
    second_server(real)
    ctx, pg = servers_page(browser, mb, rows=2)
    try:
        assert text(pg, "#srv-count") == "2 servers · the devices file · amt_devices"
        for key in (KEY, "lab"):
            assert pg.get_attribute(btn("Remove", key), "aria-disabled") is None
        assert text(pg, f"{row('lab')} td[data-l='AMT address']") == ADDR_LAB
        chips = pg.eval_on_selector_all(f"{row('lab')} td.ids .chip", "els => els.map(e => [e.getAttribute('data-identity'), e.textContent.trim()])")
        assert chips == [["present", "lab-amt"], ["none", "no host logon"]]
    finally:
        ctx.close()


def test_an_identity_that_is_missing_is_an_error_chip_and_an_unreadable_list_says_unknown(browser, mb, real, fake_amt):
    store = real.store
    del store[f"{KEY}-debian"]
    (real.vdir / "store.json").write_text(json.dumps(store))
    ctx, pg = servers_page(browser, mb)
    try:
        chips = pg.eval_on_selector_all(f"{row()} td.ids .chip", "els => els.map(e => [e.getAttribute('data-identity'), e.className, e.textContent.trim()])")
        assert chips[1] == ["missing", "chip small error", f"{KEY}-debian · missing"]
    finally:
        ctx.close()
    real_ids = fake_amt.results["amt_identities"]
    fake_amt.results["amt_identities"] = lambda a: {"isError": True, "content": [{"type": "text", "text": "Error executing tool amt_identities: vault_list_failed"}]}
    ctx, pg = servers_page(browser, mb)
    try:
        pg.wait_for_selector("#srv-rows [data-identity=unknown]")
        assert "vault_list_failed" in text(pg, "#srv-note") and pg.locator(f"{row()} [data-identity=present]").count() == 0
    finally:
        ctx.close()
    fake_amt.results["amt_identities"] = real_ids


def test_an_unreadable_device_list_is_not_an_empty_one(browser, mb, fake_amt):
    fake_amt.results["amt_devices"] = lambda a: {"isError": True, "content": [{"type": "text", "text": "Error executing tool amt_devices: devices_file_unusable:ValueError"}]}
    ctx, pg = open_page(browser, mb, "/manage")
    try:
        until(pg, "() => /could not be read/.test(document.getElementById('srv-note').textContent)")
        assert "devices_file_unusable:ValueError" in text(pg, "#srv-note") and "not an empty list" in text(pg, "#srv-note") and pg.locator("#srv-rows tr").count() == 0
        assert text(pg, "#srv-count") == "unreadable"
    finally:
        ctx.close()


# -- Check pin and the mismatch (immutable 10) ------------------------------------------------------------------------------------

MISMATCH = ("Every call to it is refused until you re-pin. Compare the new fingerprint with what MEBx shows before accepting it: "
            "a changed leaf is either a re-provisioned AMT or something between you and it.")


def pin_calls(fake):
    return [a for a in calls(fake, "amt_devices") if a.get("action") == "pin_check"]


def test_check_pin_is_one_read_made_only_when_asked_and_a_match_is_a_result_row(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        assert pin_calls(fake_amt) == []
        pg.click(btn("Check pin"))
        pg.wait_for_selector("#srv-results .result.ok")
        assert pin_calls(fake_amt) == [{"action": "pin_check", "device": KEY}] and real.probes == [(ADDR, 16993)]
        t = results(pg, "srv-results")[0]
        assert f"pin check {KEY} · the leaf presented by {ADDR}:16993 matches the stored pin · one TLS handshake, no credential sent" in t
        assert re.search(r"checked \d\d:\d\d:\d\d E[SD]T", text(pg, f"{row()} [data-pin=matches]")) and writes(fake_amt) == []
    finally:
        ctx.close()


def mismatch_page(browser, mb, real, **kw):
    real.presented[ADDR] = LEAF_B
    ctx, pg = servers_page(browser, mb, **kw)
    pg.click(btn("Check pin"))
    pg.wait_for_selector("#srv-results .result.error")
    return ctx, pg


def test_a_presented_leaf_that_differs_is_the_error_state_with_every_action_greyed_and_the_way_out_offered(browser, mb, real, fake_amt):
    ctx, pg = mismatch_page(browser, mb, real)
    try:
        t = results(pg, "srv-results")[0]
        assert f"{KEY} presents TLS leaf " in t and ", not the stored pin " in t and t.endswith(MISMATCH)
        fps = pg.eval_on_selector_all("#srv-results .result .fp", "els => els.map(e => ({ text: e.textContent, bold: Array.from(e.querySelectorAll('b')).map(b => b.textContent).join('') }))")
        assert [f["text"].replace(" ", "") for f in fps] == [LEAF_B, LEAF_A] and all(len(f["text"].split(" ")) == 16 for f in fps)
        assert fps[1]["bold"] == LEAF_A[:16]                                      # the stored pin, in full, its 16-hex prefix in bold
        assert pg.get_attribute(row(), "data-pin-row") == "differs" and "pin differs" in text(pg, f"{row()} .chip[data-pin=differs]")
        for label in ("Edit", "Remove"):
            sel = btn(label)
            assert pg.get_attribute(sel, "aria-disabled") == "true" and pg.is_visible(f"{sel} ~ .reason")
        assert reason_of(pg, btn("Edit")) == "the leaf it presents differs from the stored pin: re-pin first"
        # the way out: Re-pin, available because the check read the presented leaf; Check pin stays (it is the read that shows it)
        assert pg.get_attribute(btn("Re-pin"), "aria-disabled") is None and pg.get_attribute(btn("Check pin"), "aria-disabled") is None
        pg.click(btn("Edit"), force=True)
        assert pg.locator(".sheet.open").count() == 0 and writes(fake_amt) == []
    finally:
        ctx.close()


def test_with_two_servers_a_differing_one_greys_its_remove_with_the_pin_reason_and_the_other_stays_free(browser, mb, real, fake_amt):
    second_server(real)
    ctx, pg = mismatch_page(browser, mb, real, rows=2)
    try:
        rm = btn("Remove")
        assert pg.get_attribute(rm, "aria-disabled") == "true" and reason_of(pg, rm) == "the leaf it presents differs from the stored pin: re-pin first"
        assert pg.get_attribute(btn("Remove", "lab"), "aria-disabled") is None and pg.get_attribute(btn("Edit", "lab"), "aria-disabled") is None
        pg.click(rm, force=True)
        assert pg.locator(".sheet.open").count() == 0 and writes(fake_amt) == []
    finally:
        ctx.close()


def test_a_server_the_console_found_differing_greys_its_actions_and_re_pin_waits_for_a_check(browser, mb, real, fake_amt):
    fake_amt.results["amt_status"] = lambda a: {"isError": True, "content": [{"type": "text", "text": "Error executing tool amt_status: tls_leaf_pin_mismatch"}]}
    mb.app.fleet.refresh(KEY)
    ctx, pg = servers_page(browser, mb)
    try:
        assert pg.get_attribute(row(), "data-pin-row") == "differs"
        assert pg.get_attribute(btn("Edit"), "aria-disabled") == "true" and pg.get_attribute(btn("Remove"), "aria-disabled") == "true"
        assert pg.get_attribute(btn("Re-pin"), "aria-disabled") == "true" and "run Check pin" in reason_of(pg, btn("Re-pin"))
        real.presented[ADDR] = LEAF_B
        pg.click(btn("Check pin"))
        pg.wait_for_selector("#srv-results .result.error")
        assert pg.get_attribute(btn("Re-pin"), "aria-disabled") is None
    finally:
        ctx.close()


def test_a_match_found_on_the_page_outranks_an_older_differing_status_read(browser, mb, real, fake_amt):
    fake_amt.results["amt_status"] = lambda a: {"isError": True, "content": [{"type": "text", "text": "Error executing tool amt_status: tls_leaf_pin_mismatch"}]}
    mb.app.fleet.refresh(KEY)
    ctx, pg = servers_page(browser, mb)
    try:
        pg.click(btn("Check pin"))
        pg.wait_for_selector("#srv-results .result.ok")
        assert pg.get_attribute(row(), "data-pin-row") == "matches" and pg.get_attribute(btn("Edit"), "aria-disabled") is None
    finally:
        ctx.close()


@pytest.mark.parametrize("answer", [{"device": KEY, "presented": LEAF_B, "stored": LEAF_A, "matches": True},         # a verdict that contradicts the leaves
                                    {"device": KEY, "presented": "short", "stored": LEAF_A, "matches": False},
                                    {"device": KEY, "presented": LEAF_A, "stored": LEAF_A}, {"device": KEY, "presented": LEAF_A, "stored": LEAF_A, "matches": "yes"}])
def test_an_unreadable_pin_check_concludes_nothing(browser, mb, real, fake_amt, answer):
    fake_amt.results["amt_devices"] = lambda a: {"source": "file", "devices": [d for d in [json_device(real)]]} if a.get("action") == "list" else answer
    ctx, pg = servers_page(browser, mb)
    try:
        pg.click(btn("Check pin"))
        pg.wait_for_selector("#srv-results .result")
        assert "not a readable pin check" in results(pg, "srv-results")[0] and "nothing was concluded" in results(pg, "srv-results")[0]
        assert pg.get_attribute(row(), "data-pin-row") == "matches"                  # still what the status read said: the page invented no verdict
    finally:
        ctx.close()


def json_device(real):
    import dataclasses
    d = real.file_devices[KEY]
    return {**dataclasses.asdict(d), "pinned": d.pinned}


# -- re-pin: the hold, the two fingerprints, the leaf that moved again ------------------------------------------------------------

def test_re_pin_is_the_hold_with_both_fingerprints_and_sends_one_call_on_the_release(browser, mb, real, fake_amt):
    ctx, pg = mismatch_page(browser, mb, real)
    try:
        pg.click(btn("Re-pin"))
        k = sheet_kind(pg)
        assert k["force"] and not k["plain"] and k["title"] == f"Accept the new TLS leaf of {KEY}"
        assert k["call"] == f'tools/call amt_device_manage {{action: "edit", device: "{KEY}", repin: true, confirmed: true}}'
        kv = pg.eval_on_selector_all(".sheet.open dl.kv > *", "els => els.map(e => e.textContent)")
        assert kv[0] == "Stored" and kv[1].replace(" ", "") == LEAF_A and kv[2] == "Presented at the check" and kv[3].replace(" ", "") == LEAF_B
        assert pg.eval_on_selector(".sheet.open dl.kv dd b", "e => e.parentElement.querySelectorAll('b').length") == 4
        assert pg.locator(".sheet.open dd .fp").count() == 2
        assert writes(fake_amt) == [] and pg.evaluate("() => window.__forceFireCount()") == 0
        hold_force(pg)
        pg.wait_for_selector("#srv-results .result.ok")
        assert writes(fake_amt) == [("amt_device_manage", {"action": "edit", "device": KEY, "repin": True, "confirmed": True})]
        assert pg.evaluate("() => window.__forceFireCount()") == 1 and real.file_devices[KEY].tls_leaf_sha256 == LEAF_B
        assert "the stored pin is now" in results(pg, "srv-results")[0] and "every call to it is allowed again" in results(pg, "srv-results")[0]
        until(pg, f"() => document.querySelector('{row()}').getAttribute('data-pin-row') === 'matches'")
        assert "re-pinned" in text(pg, f"{row()} .chip[data-pin=matches]") and pg.get_attribute(btn("Edit"), "aria-disabled") is None and pg.locator(btn("Re-pin")).count() == 0
        assert pg.errors == []
    finally:
        ctx.close()


def test_a_leaf_that_changed_again_between_the_check_and_the_re_pin_is_called_out(browser, mb, real, fake_amt):
    ctx, pg = mismatch_page(browser, mb, real)
    try:
        pg.click(btn("Re-pin"))
        real.presented[ADDR] = LEAF_C                                          # moved once more after the operator's check
        hold_force(pg)
        pg.wait_for_selector("#srv-results .result.error >> text=NOT the leaf you compared")
        t = results(pg, "srv-results")[0]
        assert "this is NOT the leaf you compared at the check" in t and LEAF_C[:4] in t.replace(" ", "") and "compare the stored pin with MEBx" in t
        assert real.file_devices[KEY].tls_leaf_sha256 == LEAF_C
    finally:
        ctx.close()


def test_a_re_pin_the_tool_refuses_is_its_sentence_and_the_page_keeps_the_mismatch(browser, mb, real, fake_amt):
    ctx, pg = mismatch_page(browser, mb, real)
    try:
        pg.click(btn("Re-pin"))
        del real.presented[ADDR]                                               # the address stopped answering
        hold_force(pg)
        pg.wait_for_selector("#srv-results .result.error >> text=connect timed out")
        assert "refused: Error executing tool amt_device_manage: connect timed out · the stored pin is unchanged" in results(pg, "srv-results")[0]
        assert real.file_devices[KEY].tls_leaf_sha256 == LEAF_A and pg.get_attribute(row(), "data-pin-row") == "differs"
    finally:
        ctx.close()


# -- add -------------------------------------------------------------------------------------------------------------------------

def fill_add(pg, key="lab", ip=ADDR_LAB):
    pg.fill("#add-key", key); pg.fill("#add-ip", ip)


def test_an_untouched_add_form_says_why_it_cannot_be_sent_and_each_fault_names_itself(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        go = "#add-go"
        assert pg.get_attribute(go, "aria-disabled") == "true" and "a key is lowercase letters, digits and dashes" in text(pg, "#add-wrap .reason")
        for key, ip, ws, expect in (("Lab", ADDR_LAB, "16993", "lowercase letters"), (KEY, ADDR_LAB, "16993", "a server with this key exists: edit it"),
                                    ("lab", "lab.example.test", "16993", "an IP address, never a host name"), ("lab", "10.0.0.256", "16993", "an IP address"),
                                    ("lab", ADDR_LAB, "70000", "ports are whole numbers 1 to 65535")):
            fill_add(pg, key, ip); pg.fill("#add-wsman", ws)
            assert pg.get_attribute(go, "aria-disabled") == "true" and expect in text(pg, "#add-wrap .reason"), (key, ip, ws)
        fill_add(pg); pg.fill("#add-wsman", "16993"); pg.fill("#add-pin", "abc")
        assert "the expected pin is 64 hex characters" in text(pg, "#add-wrap .reason")
        pg.fill("#add-pin", "")
        assert pg.get_attribute(go, "aria-disabled") is None and pg.locator("#add-wrap .reason").count() == 0
        pg.click(go, force=False)
        pg.click(".sheet.open [data-close]")
        assert writes(fake_amt) == []
    finally:
        ctx.close()


@pytest.mark.parametrize("ip,ok", [("2001:db8::40", True), ("fe80::1", True), ("feed.face", False), ("12:34", False), ("1.2.3", False), ("1.2.3.4.5", False), ("999.1.1.1", False)])
def test_the_address_is_an_ip_address_of_either_family_never_a_name(browser, mb, real, fake_amt, ip, ok):
    ctx, pg = servers_page(browser, mb)
    try:
        fill_add(pg, "lab", ip)
        assert (pg.get_attribute("#add-go", "aria-disabled") is None) is ok, ip
        if not ok:
            assert text(pg, "#add-wrap .reason") == "an IP address, never a host name"
    finally:
        ctx.close()


def test_add_takes_the_names_of_entries_that_exist_never_a_value_and_has_no_password_field(browser, mb, real):
    ctx, pg = servers_page(browser, mb)
    try:
        fill_add(pg)
        opts = pg.eval_on_selector_all("#add-amt option", "els => els.map(e => e.textContent)")
        assert opts[0] == "new entry: lab-amt (must exist in the vault first)" and f"use existing · {KEY}-amt" in opts
        assert pg.eval_on_selector_all("#add-host option", "els => els.map(e => e.textContent)")[0] == "none"
        assert pg.locator("input[type=password], [autocomplete=new-password]").count() == 0 and pg.locator("#add-panel form").count() == 0
        assert pg.input_value("#add-amt") == "__new__" and pg.get_attribute("#add-go", "aria-disabled") is None
    finally:
        ctx.close()


def test_add_sends_one_call_pins_the_presented_leaf_and_proves_the_server_with_a_status_read(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        fill_add(pg)
        pg.click("#add-go")
        k = sheet_kind(pg)
        assert k["plain"] and not k["force"] and k["title"] == "Add the server lab"
        assert k["call"] == (f'tools/call amt_device_manage {{action: "add", device: "lab", ip: "{ADDR_LAB}", wsman_port: 16993, kvm_port: 16995, '
                             f'amt_vault_key: "lab-amt", confirmed: true}} · then amt_status {{device: "lab"}}')
        assert "trust on first use" in k["say"] and writes(fake_amt) == [] and real.probes == []
        confirm_plain(pg)
        pg.wait_for_selector("#add-results .result.ok >> text=amt_status lab")
        assert writes(fake_amt) == [("amt_device_manage", {"action": "add", "device": "lab", "ip": ADDR_LAB, "wsman_port": 16993, "kvm_port": 16995,
                                                          "amt_vault_key": "lab-amt", "confirmed": True})]
        assert calls(fake_amt, "amt_status", "lab") == [{"device": "lab"}]
        added, proved = results(pg, "add-results")[1], results(pg, "add-results")[0]
        assert "added" in added and "trust on first use" in added and LEAF_C[:4] in added.replace(" ", "") and "compare it with what MEBx shows" in added
        assert "succeeded" in proved
        assert real.file_devices["lab"].tls_leaf_sha256 == LEAF_C and pin_text(pg, "lab") == LEAF_C
        until(pg, "() => document.querySelectorAll('#srv-rows tr').length === 2")
        assert pg.input_value("#add-key") == "" and pg.input_value("#add-wsman") == "16993"                  # the form is ready for the next one
        assert pg.evaluate("() => window.__callCount()") == 1
    finally:
        ctx.close()


def pin_text(pg, key):
    return pg.eval_on_selector(f"{row(key)} .fp", "e => e.textContent.replace(/ /g, '')")


def test_an_expected_pin_the_leaf_does_not_match_is_the_tools_refusal_and_nothing_is_added(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        fill_add(pg); pg.fill("#add-pin", LEAF_B.upper())
        pg.click("#add-go")
        assert f'expected_pin: "{LEAF_B}"' in sheet_kind(pg)["call"] and "refuses when it is not the expected pin" in sheet_kind(pg)["say"] or "or refuses" in sheet_kind(pg)["say"]
        confirm_plain(pg)
        pg.wait_for_selector("#add-results .result.error")
        assert f"{ADDR_LAB}:16993 presents leaf {LEAF_C}, not the given pin; nothing written" in results(pg, "add-results")[0]
        assert "lab" not in real.file_devices and calls(fake_amt, "amt_status", "lab") == []
        assert pg.input_value("#add-key") == "lab"                                  # the form keeps what was typed
    finally:
        ctx.close()


def test_a_name_that_is_not_in_the_vault_is_amt_mcps_refusal_naming_it_and_the_page_adds_nothing(browser, mb, real, fake_amt):
    """amt_identities lists the entries servers already name, so the page cannot know which names a server not yet added may take: amt-mcp decides."""
    ctx, pg = servers_page(browser, mb)
    try:
        fill_add(pg, "zzz")
        assert pg.get_attribute("#add-go", "aria-disabled") is None
        pg.click("#add-go"); confirm_plain(pg)
        pg.wait_for_selector("#add-results .result.error")
        assert "refused: Error executing tool amt_device_manage: vault zzz-amt in this server's vault" in results(pg, "add-results")[0] and "zzz" not in real.file_devices
        assert calls(fake_amt, "amt_status", "zzz") == [] and pg.input_value("#add-key") == "zzz"
    finally:
        ctx.close()


def test_the_status_read_after_an_add_is_the_tools_sentence_when_the_server_does_not_answer(browser, mb, real, fake_amt):
    fake_amt.results["amt_status"] = lambda a: {"isError": True, "content": [{"type": "text", "text": "amt_status failed: connect timed out (10 s)"}]} if a["device"] == "lab" else {"device": a["device"]}
    ctx, pg = servers_page(browser, mb)
    try:
        fill_add(pg)
        pg.click("#add-go"); confirm_plain(pg)
        pg.wait_for_selector("#add-results .result.error")
        assert "refused: amt_status failed: connect timed out (10 s) · read-only: nothing on the host was changed" in results(pg, "add-results")[0]
        assert "lab" in real.file_devices                                               # the server was added; the read says whether it answers
    finally:
        ctx.close()


# -- edit ------------------------------------------------------------------------------------------------------------------------

def test_edit_sends_only_the_fields_that_changed_and_a_form_that_changed_nothing_cannot_be_sent(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        pg.click(btn("Edit"))
        k = sheet_kind(pg)
        assert k["plain"] and k["title"] == f"Edit {KEY}" and pg.get_attribute(".sheet.open [data-confirm]", "aria-disabled") == "true"
        assert text(pg, ".sheet.open .reason") == "change at least one field"
        assert [pg.input_value(f".sheet.open [data-field={f}]") for f in ("ip", "wsman_port", "kvm_port", "amt_vault_key", "host_vault_key")] == [ADDR, "16993", "16995", f"{KEY}-amt", f"{KEY}-debian"]
        for value, why in (("lab.example.test", "an IP address, never a host name"),):
            pg.fill(".sheet.open [data-field=ip]", value)
            assert text(pg, ".sheet.open .reason") == why
        pg.fill(".sheet.open [data-field=ip]", ADDR); pg.fill(".sheet.open [data-field=kvm_port]", "0")
        assert text(pg, ".sheet.open .reason") == "ports are whole numbers 1 to 65535"
        pg.fill(".sheet.open [data-field=kvm_port]", "16996")
        assert pg.get_attribute(".sheet.open [data-confirm]", "aria-disabled") is None
        assert sheet_kind(pg)["call"] == f'tools/call amt_device_manage {{action: "edit", device: "{KEY}", kvm_port: 16996, confirmed: true}}'
        confirm_plain(pg)
        pg.wait_for_selector("#srv-results .result.ok")
        assert writes(fake_amt) == [("amt_device_manage", {"action": "edit", "device": KEY, "kvm_port": 16996, "confirmed": True})]
        assert real.file_devices[KEY].kvm_port == 16996 and real.probes == []        # a port that is not the WS-MAN port re-reads no leaf
        until(pg, f"() => document.querySelector('{row()} td[data-l=Ports]').textContent === '16993 / 16996'")
    finally:
        ctx.close()


def test_edit_clears_the_host_logon_when_the_field_is_emptied(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        pg.click(btn("Edit")); pg.fill(".sheet.open [data-field=host_vault_key]", "")
        assert sheet_kind(pg)["call"] == f'tools/call amt_device_manage {{action: "edit", device: "{KEY}", clear_host: true, confirmed: true}}'
        confirm_plain(pg)
        pg.wait_for_selector("#srv-results .result.ok")
        assert real.file_devices[KEY].host_vault_key is None
        until(pg, f"() => document.querySelector('{row()} td.ids [data-identity=none]')")
    finally:
        ctx.close()


def test_an_edit_that_meets_another_leaf_is_the_tools_refusal_and_asks_for_the_separate_hold(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        pg.click(btn("Edit")); pg.fill(".sheet.open [data-field=ip]", ADDR_MOVED)
        confirm_plain(pg)
        pg.wait_for_selector("#srv-results .result.error")
        assert f"{ADDR_MOVED}:16993 presents leaf {LEAF_B}, not the stored pin; pass repin to accept it; nothing written" in results(pg, "srv-results")[0]
        assert real.file_devices[KEY].amt_ip == ADDR and writes(fake_amt)[0][1].get("repin") is None          # Edit never sends repin: that is Re-pin's hold
    finally:
        ctx.close()


# -- remove: the hold; the last-server sentence when the list was stale -----------------------------------------------------------

def test_remove_is_the_hold_and_sends_one_call_on_the_release(browser, mb, real, fake_amt):
    second_server(real)
    ctx, pg = servers_page(browser, mb, rows=2)
    try:
        pg.click(btn("Remove", "lab"))
        k = sheet_kind(pg)
        assert k["force"] and k["title"] == "Remove lab" and k["call"] == 'tools/call amt_device_manage {action: "remove", device: "lab", confirmed: true}'
        assert "every tool then refuses it" in k["say"] and "refuses to remove the last server" in k["say"]
        hold_force(pg)
        pg.wait_for_selector("#srv-results .result.ok")
        assert writes(fake_amt) == [("amt_device_manage", {"action": "remove", "device": "lab", "confirmed": True})]
        assert pg.evaluate("() => window.__forceFireCount()") == 1 and list(real.file_devices) == [KEY]
        assert f"removed · servers now: {KEY}" in results(pg, "srv-results")[0]
        until(pg, "() => document.querySelectorAll('#srv-rows tr').length === 1")
        assert pg.get_attribute(btn("Remove"), "aria-disabled") == "true"                      # one left: now it is the last
    finally:
        ctx.close()


def test_a_remove_made_from_a_stale_list_gets_the_tools_last_server_sentence_verbatim(browser, mb, real, fake_amt):
    second_server(real)
    ctx, pg = servers_page(browser, mb, rows=2)
    try:
        real.device_manage({"action": "remove", "device": "lab"})                              # another operator removed it since this page read
        pg.click(btn("Remove"))                                                                 # the page still thinks there are two
        hold_force(pg)
        pg.wait_for_selector("#srv-results .result.error")
        assert "refused: Error executing tool amt_device_manage: refusing to remove the last device; the server would have nothing to serve · nothing was removed" in results(pg, "srv-results")[0]
        assert list(real.file_devices) == [KEY]
        until(pg, "() => document.querySelectorAll('#srv-rows tr').length === 1")               # the re-read corrects the table
    finally:
        ctx.close()


# -- immutables 4 and 5 on the Servers page ------------------------------------------------------------------------------------------

SWEEP = "#servers-page button, #servers-page select, #servers-page input, #servers-page a[href], .appbar button, .appbar a[href]"


def test_a_bare_click_on_any_control_outside_a_sheet_writes_nothing(browser, mb, real, fake_amt):
    second_server(real)
    ctx, pg = mismatch_page(browser, mb, real, rows=2)
    try:
        pg.evaluate("() => document.addEventListener('click', e => { const a = e.target.closest('a[href]'); if (a) e.preventDefault(); }, true)")
        n = pg.eval_on_selector_all(SWEEP, "els => els.length")
        assert n >= 12
        for i in range(n):
            pg.evaluate("([sel, i]) => { const el = document.querySelectorAll(sel)[i]; if (el) el.click(); window.__closeSheets(); }", [SWEEP, i])
        assert pg.evaluate("() => window.__callCount()") == 0 and pg.evaluate("() => window.__forceFireCount()") == 0
        assert writes(fake_amt) == [] and pg.errors == []
    finally:
        ctx.close()


def build_force_sheets(pg):
    """The re-pin sheet and the remove sheet, so both force controls are in the document (re-pin first)."""
    pg.click(btn("Re-pin")); pg.evaluate("() => window.__closeSheets()")
    pg.click(btn("Remove", "lab")); pg.evaluate("() => window.__closeSheets()")
    assert pg.eval_on_selector_all(".force-control[data-hold]", "els => els.length") == 2


@pytest.mark.parametrize("index,width", [(0, 1024), (1, 1024), (0, 360), (1, 360)])
def test_the_force_matrix_on_re_pin_and_remove(browser, mb, real, fake_amt, index, width):
    second_server(real)
    real.presented[ADDR] = LEAF_B
    ctx, pg = servers_page(browser, mb, width=width, rows=2)
    try:
        pg.click(btn("Check pin")); pg.wait_for_selector("#srv-results .result.error")
        build_force_sheets(pg)
        got = check_mockups().force_matrix(pg, index)
        assert got is not None, "no force control was found"
        assert got["opener_point"] != "CONFIRM", "the second sheet's confirm sits under the opener's point"
        got.pop("opener_point")
        assert got == EXPECTED_FORCE
    finally:
        ctx.close()


def test_a_tap_then_a_tap_500_ms_later_never_fires_re_pin_or_remove(browser, mb, real, fake_amt):
    second_server(real)
    real.presented[ADDR] = LEAF_B
    ctx, pg = servers_page(browser, mb, width=360, rows=2, has_touch=True)
    try:
        pg.click(btn("Check pin")); pg.wait_for_selector("#srv-results .result.error")
        build_force_sheets(pg)
        assert check_mockups().tap_matrix(pg, 0) == (0, True) and check_mockups().tap_matrix(pg, 1) == (0, True)
        assert writes(fake_amt) == []
    finally:
        ctx.close()


def test_every_destructive_call_the_page_sent_was_preceded_by_a_force_fire(browser, mb, real, fake_amt):
    second_server(real)
    real.presented[ADDR] = LEAF_B
    ctx, pg = servers_page(browser, mb, rows=2)
    try:
        pg.click(btn("Check pin")); pg.wait_for_selector("#srv-results .result.error")
        pg.click(btn("Re-pin")); hold_force(pg); pg.wait_for_selector("#srv-results .result.ok")                  # forced by repin: true
        pg.click(btn("Edit", "lab")); pg.fill(".sheet.open [data-field=kvm_port]", "16996"); confirm_plain(pg)    # plain
        pg.wait_for_selector("#srv-results .result.ok >> text=saved")
        pg.click(btn("Remove", "lab")); hold_force(pg); pg.wait_for_timeout(200)                                   # forced
        spy = pg.evaluate("() => window.__calls().map(c => ({ forced: c.forced, destructive: window.__destructiveCall({ tool: c.tool, arguments: c.arguments, then: c.then }, c.ctx) }))")
        assert spy == [{"forced": True, "destructive": True}, {"forced": False, "destructive": False}, {"forced": True, "destructive": True}]
    finally:
        ctx.close()


def test_the_plain_sheets_of_the_page_send_one_call_per_activation_and_manage_focus(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        fill_add(pg)
        pg.click("#add-go"); pg.evaluate("() => window.__closeSheets()")
        checks = check_mockups().confirm_checks(pg)
        assert len(checks) == 1, checks                                                  # the add sheet takes no field (the edit sheet's Confirm is greyed until a field changes)
        c = checks[0]
        assert c["click"] == 1 and c["enter_held"] == 1, c
        assert c["focus_key"] == {"inSheet": True, "isCancel": True} and c["focus_ptr"] and c["trapped"], c
    finally:
        ctx.close()


def test_closing_the_sheet_returns_focus_to_the_control_that_opened_it(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        pg.focus(btn("Edit")); pg.keyboard.press("Enter")
        assert pg.evaluate("() => document.activeElement.hasAttribute('data-close')")
        pg.keyboard.press("Escape")
        until(pg, f"() => document.activeElement && document.activeElement.getAttribute('aria-label') === 'Edit {KEY}'")
        assert writes(fake_amt) == []
    finally:
        ctx.close()


# -- a tool's text is data -----------------------------------------------------------------------------------------------------

def test_a_refusal_with_markup_in_it_is_shown_as_text(browser, mb, real, fake_amt):
    evil = '<img src=x onerror="window.pwned=1"><b>x</b>'
    base = fake_amt.results["amt_device_manage"]
    fake_amt.results["amt_device_manage"] = lambda a: {"isError": True, "content": [{"type": "text", "text": evil}]}
    ctx, pg = servers_page(browser, mb)
    try:
        pg.click(btn("Edit")); pg.fill(".sheet.open [data-field=kvm_port]", "16999"); confirm_plain(pg)
        pg.wait_for_selector("#srv-results .result.error")
        assert evil in text(pg, "#srv-results .result.error") and pg.evaluate("() => window.pwned") is None and pg.locator("#srv-results img, #srv-results b").count() == 0
    finally:
        ctx.close()
    fake_amt.results["amt_device_manage"] = base


# -- more of the Servers page: names, the expected pin, Cancel, Re-read, the source, unreadable shapes, stale state ------------------------------

def test_edit_stops_an_identity_name_that_is_not_a_vault_entry_name(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        pg.click(btn("Edit"))
        pg.fill(".sheet.open [data-field=amt_vault_key]", "Bad Name")
        assert pg.get_attribute(".sheet.open [data-confirm]", "aria-disabled") == "true" and text(pg, ".sheet.open .reason") == "the AMT identity is the name of a vault entry"
        pg.fill(".sheet.open [data-field=amt_vault_key]", f"{KEY}-amt"); pg.fill(".sheet.open [data-field=host_vault_key]", "Bad Name")
        assert text(pg, ".sheet.open .reason") == "the host logon is the name of a vault entry, or empty for none"
        pg.fill(".sheet.open [data-field=host_vault_key]", "other-host")
        assert pg.get_attribute(".sheet.open [data-confirm]", "aria-disabled") is None
        assert sheet_kind(pg)["call"] == f'tools/call amt_device_manage {{action: "edit", device: "{KEY}", host_vault_key: "other-host", confirmed: true}}'
    finally:
        ctx.close()


def test_an_expected_pin_the_leaf_matches_is_said_to_be_the_pin_you_gave(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        fill_add(pg); pg.fill("#add-pin", LEAF_C.upper())
        pg.click("#add-go"); confirm_plain(pg)
        pg.wait_for_selector("#add-results .result.ok >> text=the expected pin you gave")
        pg.wait_for_selector("#add-results .result.ok >> text=amt_status lab")      # the status proof lands after the add; newest first, so the add is then [1]
        assert "trust on first use" not in results(pg, "add-results")[1] and real.file_devices["lab"].tls_leaf_sha256 == LEAF_C
    finally:
        ctx.close()


def test_cancel_clears_the_add_form_and_its_results_and_the_appbar_button_goes_to_the_form(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        fill_add(pg); pg.fill("#add-pin", LEAF_C); pg.fill("#add-wsman", "16994"); pg.fill("#add-kvm", "16996")
        pg.click("#add-cancel")
        assert [pg.input_value(i) for i in ("#add-key", "#add-ip", "#add-pin", "#add-wsman", "#add-kvm")] == ["", "", "", "16993", "16995"]
        assert pg.get_attribute("#add-go", "aria-disabled") == "true" and writes(fake_amt) == []
        pg.click("#add-focus")
        assert pg.evaluate("() => document.activeElement.id") == "add-key"
    finally:
        ctx.close()


def test_re_read_reads_the_list_and_the_identities_again_and_picks_up_what_changed_elsewhere(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        before = (len(calls(fake_amt, "amt_devices")), len(calls(fake_amt, "amt_identities")))
        second_server(real)
        pg.click("#srv-reread")
        until(pg, "() => document.querySelectorAll('#srv-rows tr').length === 2")
        assert (len(calls(fake_amt, "amt_devices")), len(calls(fake_amt, "amt_identities"))) == (before[0] + 1, before[1] + 1) and writes(fake_amt) == []
    finally:
        ctx.close()


def test_a_list_from_the_built_in_registry_says_so_and_that_changes_are_refused(browser, mb, real, fake_amt):
    base = fake_amt.results["amt_devices"]
    fake_amt.results["amt_devices"] = lambda a: {**base(a), "source": "built-in"} if a.get("action", "list") == "list" else base(a)
    ctx, pg = servers_page(browser, mb)
    try:
        assert text(pg, "#srv-count") == "1 server · the built-in registry · amt_devices" and "built-in registry: amt_device_manage changes a devices file" in text(pg, "#srv-note")
    finally:
        ctx.close()


@pytest.mark.parametrize("mutate", [lambda d: {**d, "wsman_port": "16993"}, lambda d: {k: v for k, v in d.items() if k != "amt_ip"},
                                    lambda d: {**d, "tls_leaf_sha256": "nothex"}, lambda d: {**d, "key": "Bad Key"}])
def test_a_server_list_with_an_unreadable_row_is_unreadable_as_a_whole(browser, mb, real, fake_amt, mutate):
    base = fake_amt.results["amt_devices"]
    fake_amt.results["amt_devices"] = lambda a: {**base(a), "devices": [mutate(d) for d in base(a)["devices"]]}
    ctx, pg = open_page(browser, mb, "/manage")
    try:
        until(pg, "() => /could not be read/.test(document.getElementById('srv-note').textContent)")
        assert "not a readable list of servers" in text(pg, "#srv-note") and pg.locator("#srv-rows tr").count() == 0
    finally:
        ctx.close()


def test_a_pin_check_belongs_to_the_pin_it_read_and_is_not_applied_to_a_pin_set_since(browser, mb, real, fake_amt):
    second_server(real)
    ctx, pg = servers_page(browser, mb, rows=2)
    try:
        pg.click(btn("Check pin", "lab")); pg.wait_for_selector("#srv-results .result.ok")
        assert pg.get_attribute(row("lab"), "data-pin-row") == "matches"
        real.presented[ADDR_LAB] = LEAF_B
        real.device_manage({"action": "edit", "device": "lab", "repin": True})              # re-pinned elsewhere: the pin the check read is gone
        pg.click("#srv-reread")
        until(pg, f"() => document.querySelector('{row('lab')}').getAttribute('data-pin-row') === 'unchecked'")
        assert pin_text(pg, "lab") == LEAF_B
    finally:
        ctx.close()


def test_a_re_read_that_finishes_while_a_sheet_is_open_does_not_rebuild_the_table_under_it(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        base = fake_amt.results["amt_devices"]

        def slow(a):
            if a.get("action", "list") == "list":
                time.sleep(0.8)
            return base(a)
        fake_amt.results["amt_devices"] = slow
        pg.click("#srv-reread")
        pg.click(btn("Edit"))                                                               # the sheet opens while the read is still out
        pg.wait_for_timeout(1600)
        assert pg.locator(".sheet.open").count() == 1
        pg.keyboard.press("Escape")
        until(pg, f"() => document.activeElement && document.activeElement.getAttribute('aria-label') === 'Edit {KEY}'")
        assert pg.evaluate("() => document.contains(document.activeElement)") and writes(fake_amt) == []
    finally:
        ctx.close()


def test_a_call_amt_mcp_never_answers_is_not_known_to_have_failed_and_a_missing_bearer_is_nothing_sent(browser, mb, real, fake_amt):
    ctx, pg = servers_page(browser, mb)
    try:
        base = fake_amt.results["amt_device_manage"]
        fake_amt.results["amt_device_manage"] = lambda a: (_ for _ in ()).throw(RuntimeError("the connection ends here"))
        pg.click(btn("Edit")); pg.fill(".sheet.open [data-field=kvm_port]", "16999"); confirm_plain(pg)
        pg.wait_for_selector("#srv-results .result.live")
        t = results(pg, "srv-results")[0]
        assert "amt-mcp did not answer (amt_mcp_unreachable:" in t and "it is not known whether the change was made; Re-read the servers before trying again" in t
        fake_amt.results["amt_device_manage"] = base
        mb.app.mcp.vault.cli = str(real.vdir / "no-such-cli.py"); mb.app.mcp._bearer = None
        pg.click(btn("Edit")); pg.fill(".sheet.open [data-field=kvm_port]", "16999"); confirm_plain(pg)
        pg.wait_for_selector("#srv-results .result.error")
        assert "refused: console_bearer_unavailable · nothing sent" in results(pg, "srv-results")[0]
    finally:
        ctx.close()


# -- the Identities page ------------------------------------------------------------------------------------------------------------

def seed_identities(real):
    real.seed(f"{KEY}-amt-rfb")
    real.seed(f"{KEY}-amt-user-ops", f"{amt_upload.SOURCE_NOTE}; updated: 2026-10-19T18:12:00Z")
    real.seed("orphan-entry", f"{amt_upload.SOURCE_NOTE}; updated: 2026-10-20T09:00:00Z")


def li(name):
    return f'#id-list li[data-name="{name}"]'


def ibtn(label, name):
    return f'#id-list button[aria-label="{label} {name}"]'


def test_the_list_shows_kind_owner_use_source_updated_at_and_a_status_chip_and_never_a_value(browser, mb, real, fake_amt):
    seed_identities(real)
    store = real.store
    del store[f"{KEY}-debian"]                                                              # missing: every call to its server's host sign-in fails
    (real.vdir / "store.json").write_text(json.dumps(store))
    ctx, pg = identities_page(browser, mb)
    try:
        until(pg, "() => document.querySelectorAll('#id-list li').length === 5")
        chip = lambda name: pg.eval_on_selector(f"{li(name)} .chip", "e => [e.getAttribute('data-identity'), e.textContent.trim()]")
        assert chip(f"{KEY}-amt") == ["synced", "present · synced"] and chip(f"{KEY}-amt-user-ops") == ["entered", "present · entered here"]
        assert chip("orphan-entry") == ["unused", "present · unused"] and chip(f"{KEY}-amt-rfb") == ["synced", "present · synced"]
        assert chip(f"{KEY}-debian") == ["missing", f"missing · every call to {KEY} fails"]
        sub = lambda name: text(pg, f"{li(name)} .sub")
        assert sub(f"{KEY}-amt") == "AMT admin password · owner my-server-1 · used by every call to the server · synced from the main vault · updated-at not recorded"
        assert sub(f"{KEY}-amt-user-ops").startswith("AMT user password · owner my-server-1 · read by amt_configure users add · entered here · updated 2026-10-19 14:12:00 EDT")
        assert sub("orphan-entry") == "no server names this entry · used by nothing · entered here · updated 2026-10-20 05:00:00 EDT"
        assert sub(f"{KEY}-amt-rfb").startswith("KVM (RFB) password · owner my-server-1 · written into the KVM settings by amt_configure")
        body = pg.content()
        assert "seed-value" not in body and SENTINEL not in body and "[object" not in body
        assert "5 entries" in text(pg, "#id-note")
    finally:
        ctx.close()


def test_remove_is_greyed_with_its_reason_while_a_server_names_the_entry_and_offered_for_an_unused_one(browser, mb, real, fake_amt):
    seed_identities(real)
    ctx, pg = identities_page(browser, mb)
    try:
        until(pg, "() => document.querySelectorAll('#id-list li').length === 5")
        for name, why in ((f"{KEY}-amt", f"named by {KEY}.amt_vault_key: amt_identity_manage refuses"), (f"{KEY}-amt-user-ops", f"named by {KEY}.AMT users: amt_identity_manage refuses")):
            sel = ibtn("Remove", name)
            assert pg.get_attribute(sel, "aria-disabled") == "true" and text(pg, f"{sel} ~ .reason") == why and pg.is_visible(f"{sel} ~ .reason")
        assert pg.get_attribute(ibtn("Remove", "orphan-entry"), "aria-disabled") is None
        pg.click(ibtn("Remove", f"{KEY}-amt"), force=True)
        assert pg.locator(".sheet.open").count() == 0 and writes(fake_amt) == []
    finally:
        ctx.close()


def test_removing_an_unused_entry_is_the_hold_and_one_call(browser, mb, real, fake_amt):
    seed_identities(real)
    ctx, pg = identities_page(browser, mb)
    try:
        until(pg, "() => document.querySelectorAll('#id-list li').length === 5")
        pg.click(ibtn("Remove", "orphan-entry"))
        k = sheet_kind(pg)
        assert k["force"] and k["title"] == "Remove orphan-entry" and k["call"] == 'tools/call amt_identity_manage {action: "remove", name: "orphan-entry", confirmed: true}'
        hold_force(pg)
        pg.wait_for_selector("#id-results .result.ok")
        assert writes(fake_amt) == [("amt_identity_manage", {"action": "remove", "name": "orphan-entry", "confirmed": True})]
        assert pg.evaluate("() => window.__forceFireCount()") == 1 and "orphan-entry" not in real.store
        until(pg, "() => document.querySelectorAll('#id-list li').length === 4")
    finally:
        ctx.close()


def test_a_remove_of_an_entry_a_server_came_to_name_since_is_the_tools_refusal_and_the_entry_stays(browser, mb, real, fake_amt):
    seed_identities(real)
    ctx, pg = identities_page(browser, mb)
    try:
        until(pg, "() => document.querySelectorAll('#id-list li').length === 5")
        real.device_manage({"action": "add", "device": "lab", "ip": ADDR_LAB, "amt_vault_key": "orphan-entry"})      # a server names it now; the page does not know
        pg.click(ibtn("Remove", "orphan-entry")); hold_force(pg)
        pg.wait_for_selector("#id-results .result.error")
        assert "refused: Error executing tool amt_identity_manage: identity_in_use:orphan-entry: named by lab.amt_vault_key · nothing changed" in results(pg, "id-results")[0]
        assert "orphan-entry" in real.store
    finally:
        ctx.close()


def test_the_admin_password_change_is_shown_unavailable_with_the_reason(browser, mb, real, fake_amt):
    ctx, pg = identities_page(browser, mb)
    try:
        assert pg.get_attribute("#admin-change", "aria-disabled") == "true" and text(pg, "#admin-change ~ .reason") == "no tool: change it in MEBx"
        assert "amt-mcp has no tool that sets an AMT password" in text(pg, "#ident-page .card.outlined")
        pg.click("#admin-change", force=True)
        assert pg.locator(".sheet.open").count() == 0 and fake_amt.calls and all(t != "amt_configure" for t, _, _ in fake_amt.calls) and writes(fake_amt) == []
    finally:
        ctx.close()


# -- the intake: mint, the value field, send, received -------------------------------------------------------------------------------

def replace_button(name):
    return f'#id-list button[aria-label="Replace the stored value of {name}"]'


def test_replace_mints_through_a_plain_sheet_and_the_value_field_appears_with_no_url_anywhere(browser, mb, real, fake_amt):
    ctx, pg = identities_page(browser, mb)
    try:
        assert pg.is_hidden("#intake-block")
        pg.click(replace_button(f"{KEY}-amt"))
        k = sheet_kind(pg)
        assert k["plain"] and k["title"] == f"Replace the stored value of {KEY}-amt"
        assert k["call"] == f'tools/call amt_identity_manage {{action: "intake", name: "{KEY}-amt", confirmed: true}}'
        assert "does NOT change the password on the AMT: change it in MEBx first" in k["say"] and "every call to the server fails after one Digest attempt" in k["say"]
        assert writes(fake_amt) == []
        confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        assert writes(fake_amt) == [("amt_identity_manage", {"action": "intake", "name": f"{KEY}-amt", "confirmed": True})]
        status = text(pg, "#intake-status")
        assert status.startswith("intake minted for my-server-1-amt · one-time PUT url · expires in 1") and "at most 4096 bytes · the url is never shown" in status
        token = real.token()
        assert token not in pg.content() and "/intake/" not in pg.content() and not any(token in u for u in pg.requests)
        field = pg.eval_on_selector("#intake-value", "e => ({ type: e.type, ac: e.getAttribute('autocomplete'), hasValue: e.hasAttribute('value'), form: !!e.closest('form'), cls: e.className, mask: getComputedStyle(e).webkitTextSecurity })")
        assert field == {"type": "text", "ac": "off", "hasValue": False, "form": False, "cls": "secret", "mask": "disc"}
        assert pg.get_attribute("#intake-send", "aria-disabled") == "true" and text(pg, "#intake-wrap .reason") == "enter the value"
    finally:
        ctx.close()


def slow_fetch(pg):
    """Hold every intake request in the page for a moment and record what the value field held when it left, and what it carried."""
    pg.evaluate("""() => {
      const real = window.fetch.bind(window); window.__atFetch = null; window.__body = null;
      window.fetch = (url, init) => {
        if (String(url).indexOf('/api/identities/intake/') !== -1) {
          window.__atFetch = document.getElementById('intake-value').value; window.__body = init.body;
          return new Promise(res => setTimeout(() => res(real(url, init)), 400));
        }
        return real(url, init);
      };
    }""")


def test_the_field_is_cleared_before_the_answer_and_the_value_is_stored_by_name_with_a_status_read_after_it(browser, mb, real, fake_amt):
    ctx, pg = identities_page(browser, mb)
    try:
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        slow_fetch(pg)
        status_before = len(calls(fake_amt, "amt_status", KEY))
        pg.fill("#intake-value", SENTINEL)
        assert pg.get_attribute("#intake-send", "aria-disabled") is None
        pg.click("#intake-send")
        until(pg, "() => window.__atFetch !== null")
        assert pg.input_value("#intake-value") == "" and pg.evaluate("() => window.__atFetch") == "" and pg.evaluate("() => window.__body") == SENTINEL      # cleared, and the body carried it
        assert text(pg, "#intake-wrap .reason") == "sending…" and pg.get_attribute("#intake-send", "aria-disabled") == "true"
        pg.wait_for_selector("#nid-results .result.ok >> text=amt_status")
        rows = results(pg, "nid-results")
        assert re.search(r"intake my-server-1-amt · received · my-server-1-amt present · updated 20\d\d-\d\d-\d\d \d\d:\d\d:\d\d E[SD]T · the field was cleared", rows[1]), rows
        assert re.search(r"amt_status my-server-1 · succeeded \d+ s after the value arrived", rows[0]), rows
        entry = real.store[f"{KEY}-amt"]
        assert entry["value"] == SENTINEL and entry["notes"].startswith(amt_upload.SOURCE_NOTE)
        assert calls(fake_amt, "amt_status", KEY)[status_before:] == [{"device": KEY}] and pg.is_hidden("#intake-block")
        until(pg, f"() => document.querySelector('{li(f'{KEY}-amt')} .chip').getAttribute('data-identity') === 'entered'")
        body = pg.content()
        assert SENTINEL not in body and not any(SENTINEL in u for u in pg.requests) and pg.input_value("#intake-value") == "" and pg.errors == []
        assert pg.evaluate("() => window.__callCount()") == 1                                                       # the mint sheet's call; the send is the named exception
    finally:
        ctx.close()


def test_a_kind_amt_status_does_not_use_reads_no_status(browser, mb, real, fake_amt):
    seed_identities(real)
    ctx, pg = identities_page(browser, mb)
    try:
        until(pg, "() => document.querySelectorAll('#id-list li').length === 5")
        pg.click(replace_button(f"{KEY}-amt-rfb")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        status_before = len(calls(fake_amt, "amt_status"))
        pg.fill("#intake-value", SENTINEL); pg.click("#intake-send")
        pg.wait_for_selector("#nid-results .result >> text=amt_status does not use this entry")
        assert len(calls(fake_amt, "amt_status")) == status_before and real.store[f"{KEY}-amt-rfb"]["value"] == SENTINEL
    finally:
        ctx.close()


def test_a_status_read_that_the_new_value_fails_is_the_tools_sentence(browser, mb, real, fake_amt):
    fake_amt.results["amt_status"] = lambda a: {"isError": True, "content": [{"type": "text", "text": "Error executing tool amt_status: wsman_auth_failed_401"}]}
    ctx, pg = identities_page(browser, mb)
    try:
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        pg.fill("#intake-value", SENTINEL); pg.click("#intake-send")
        pg.wait_for_selector("#nid-results .result.error")
        assert "refused: Error executing tool amt_status: wsman_auth_failed_401 · read-only: nothing on the host was changed" in results(pg, "nid-results")[0]
        assert mb.app.fleet.entries[KEY]["state"] == "paused"                    # a refused credential pauses the server like any call
    finally:
        ctx.close()


def test_a_value_amt_mcp_refuses_is_its_sentence_and_the_url_is_used_up(browser, mb, real, fake_amt, monkeypatch):
    ctx, pg = identities_page(browser, mb)
    try:
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        monkeypatch.setenv("NVAULT_VAULT_PATH", str(real.vdir / "read-only-vault"))
        pg.fill("#intake-value", SENTINEL); pg.click("#intake-send")
        pg.wait_for_selector("#nid-results .result.error")
        t = results(pg, "nid-results")[0]
        assert "refused by the one-time url (503): vault_not_writable: nothing was stored · the url is used up · mint a new intake" in t
        assert pg.is_hidden("#intake-block") and real.store[f"{KEY}-amt"]["value"] == "seed-value" and SENTINEL not in pg.content()
    finally:
        ctx.close()


def test_an_intake_the_console_no_longer_holds_is_gone_and_says_so(browser, mb, real, fake_amt):
    ctx, pg = identities_page(browser, mb)
    try:
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        mb.app.intakes._offers.clear()
        pg.fill("#intake-value", SENTINEL); pg.click("#intake-send")
        pg.wait_for_selector("#nid-results .result.error")
        assert "refused: unknown_intake · the intake is gone: mint a new one" in results(pg, "nid-results")[0] and pg.is_hidden("#intake-block")
        assert fake_amt.puts == []
    finally:
        ctx.close()


def test_the_page_stops_a_value_the_tool_would_refuse_and_keeps_the_intake_open(browser, mb, real, fake_amt):
    ctx, pg = identities_page(browser, mb)
    try:
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        pg.fill("#intake-value", "x" * 4097)
        assert pg.get_attribute("#intake-send", "aria-disabled") == "true" and text(pg, "#intake-wrap .reason") == "larger than 4096 bytes"
        pg.fill("#intake-value", "é" * 2049)                                       # 4098 bytes: the limit is bytes, not characters
        assert text(pg, "#intake-wrap .reason") == "larger than 4096 bytes"
        pg.fill("#intake-value", SENTINEL)
        assert pg.get_attribute("#intake-send", "aria-disabled") is None and fake_amt.puts == []
    finally:
        ctx.close()


def test_an_intake_that_runs_out_is_expired_and_cannot_be_sent(browser, mb, real, fake_amt):
    base = fake_amt.results["amt_identity_manage"]
    fake_amt.results["amt_identity_manage"] = lambda a: {**base(a), "expires_in_s": 2}
    ctx, pg = identities_page(browser, mb)
    try:
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        until(pg, "() => /intake expired/.test(document.getElementById('intake-status').textContent)", seconds=6)
        assert pg.is_disabled("#intake-value") and pg.get_attribute("#intake-send", "aria-disabled") == "true" and text(pg, "#intake-wrap .reason") == "the intake expired: mint a new one"
    finally:
        ctx.close()
    fake_amt.results["amt_identity_manage"] = base


def test_the_new_identity_form_derives_the_name_the_tool_will_accept(browser, mb, real, fake_amt):
    second_server(real)
    ctx, pg = identities_page(browser, mb)
    try:
        until(pg, "() => document.getElementById('nid-owner').options.length === 2")
        name = lambda: pg.input_value("#nid-name")
        pg.select_option("#nid-owner", KEY)
        assert name() == f"{KEY}-amt"
        pg.select_option("#nid-kind", "host_vault_key"); assert name() == f"{KEY}-debian"
        pg.select_option("#nid-kind", "rfb"); assert name() == f"{KEY}-amt-rfb"
        pg.select_option("#nid-kind", "user")
        assert name() == "" and pg.is_visible("#nid-user") and pg.get_attribute("#nid-mint", "aria-disabled") == "true"
        assert "the AMT user name is 1 to 16 characters" in text(pg, "#nid-help")
        pg.fill("#nid-user", "viewer"); assert name() == f"{KEY}-amt-user-viewer" and pg.get_attribute("#nid-mint", "aria-disabled") is None
        pg.fill("#nid-user", "has space"); assert name() == "" and "1 to 16 characters" in text(pg, "#nid-help")
        pg.fill("#nid-user", "viewer")
        pg.select_option("#nid-owner", "lab"); pg.select_option("#nid-kind", "host_vault_key")
        assert name() == "" and "lab names no host logon entry" in text(pg, "#nid-help") and "lab names no host logon entry" in text(pg, "#nid-wrap .reason")
        pg.select_option("#nid-kind", "amt_vault_key"); assert name() == "lab-amt"
    finally:
        ctx.close()


def test_a_new_user_entry_is_minted_through_the_same_sheet_and_stored(browser, mb, real, fake_amt):
    ctx, pg = identities_page(browser, mb)
    try:
        pg.select_option("#nid-kind", "user"); pg.fill("#nid-user", "viewer")
        pg.click("#nid-mint")
        k = sheet_kind(pg)
        assert k["plain"] and k["title"] == f"Mint a one-time intake for {KEY}-amt-user-viewer"
        assert k["call"] == f'tools/call amt_identity_manage {{action: "intake", name: "{KEY}-amt-user-viewer", confirmed: true}}'
        assert "replaces any value now stored under the name" in k["say"] and "no value is a tool argument" in k["say"]
        confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        pg.fill("#intake-value", SENTINEL); pg.click("#intake-send")
        pg.wait_for_selector("#nid-results .result >> text=amt_status does not use this entry")
        assert real.store[f"{KEY}-amt-user-viewer"]["value"] == SENTINEL
        until(pg, f"() => document.querySelector('{li(f'{KEY}-amt-user-viewer')}')")
    finally:
        ctx.close()


def test_a_name_the_tool_refuses_is_its_sentence_and_no_value_field_appears(browser, mb, real, fake_amt):
    ctx, pg = identities_page(browser, mb)
    try:
        pg.fill("#nid-name", "not-a-registered-name")
        pg.click("#nid-mint"); confirm_plain(pg)
        pg.wait_for_selector("#nid-results .result.error")
        assert "refused: Error executing tool amt_identity_manage: identity_name_not_allowed:not-a-registered-name" in results(pg, "nid-results")[0]
        assert "no one-time url was minted" in results(pg, "nid-results")[0] and pg.is_hidden("#intake-block")
    finally:
        ctx.close()


def test_a_missing_entry_has_an_enter_control_that_sets_the_form_to_mint_exactly_that_name(browser, mb, real, fake_amt):
    second_server(real)                                                                    # two owners: the form must be set to the right one
    store = real.store
    del store[f"{KEY}-debian"]
    (real.vdir / "store.json").write_text(json.dumps(store))
    ctx, pg = identities_page(browser, mb)
    try:
        pg.click(ibtn("Enter", f"{KEY}-debian"))
        assert pg.input_value("#nid-kind") == "host_vault_key" and pg.input_value("#nid-owner") == KEY and pg.input_value("#nid-name") == f"{KEY}-debian"
        pg.click("#nid-mint")
        assert sheet_kind(pg)["call"] == f'tools/call amt_identity_manage {{action: "intake", name: "{KEY}-debian", confirmed: true}}'
        assert 'one line of JSON: {"user": "...", "password": "..."}' in sheet_kind(pg)["say"]
    finally:
        ctx.close()


def test_a_missing_entry_no_server_names_has_no_enter_control(browser, mb, real, fake_amt):
    fake_amt.results["amt_identities"] = lambda a: {"identities": [{"name": "ghost", "status": "missing", "used_by": [], "source": None, "updated_at": None}]}
    ctx, pg = open_page(browser, mb, "/manage/identities")
    try:
        until(pg, "() => document.querySelectorAll('#id-list li').length === 1")
        assert pg.get_attribute(li("ghost") + " .chip", "data-identity") == "missing" and pg.locator(ibtn("Enter", "ghost")).count() == 0 and pg.errors == []
    finally:
        ctx.close()


def test_cancel_forgets_a_minted_intake_and_clears_the_field(browser, mb, real, fake_amt):
    ctx, pg = identities_page(browser, mb)
    try:
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        pg.fill("#intake-value", SENTINEL)
        pg.click("#nid-cancel")
        assert pg.is_hidden("#intake-block") and pg.input_value("#intake-value") == "" and fake_amt.puts == []
    finally:
        ctx.close()


def test_an_identity_list_with_an_unreadable_row_is_unreadable_and_an_empty_one_says_so(browser, mb, real, fake_amt):
    fake_amt.results["amt_identities"] = lambda a: {"identities": [{"name": "x", "status": "weird", "used_by": [], "source": "main"}]}
    ctx, pg = open_page(browser, mb, "/manage/identities")
    try:
        until(pg, "() => /could not be read/.test(document.getElementById('id-note').textContent)")
        assert "not a readable list of identities" in text(pg, "#id-note") and "not an empty list" in text(pg, "#id-note") and pg.locator("#id-list li").count() == 0
    finally:
        ctx.close()
    fake_amt.results["amt_identities"] = lambda a: {"vault_entries": 0, "identities": []}
    ctx, pg = open_page(browser, mb, "/manage/identities")
    try:
        until(pg, "() => /names no identity yet/.test(document.getElementById('id-note').textContent)")
        assert pg.locator("#id-list li").count() == 0
    finally:
        ctx.close()


def test_an_unused_entry_copied_from_the_main_vault_cannot_be_removed_here(browser, mb, real, fake_amt):
    fake_amt.results["amt_identities"] = lambda a: {"identities": [{"name": "old-main", "status": "present", "used_by": [], "source": "main", "updated_at": None}]}
    ctx, pg = open_page(browser, mb, "/manage/identities")
    try:
        until(pg, "() => document.querySelectorAll('#id-list li').length === 1")
        sel = ibtn("Remove", "old-main")
        assert pg.get_attribute(sel, "aria-disabled") == "true" and text(pg, f"{sel} ~ .reason") == "copied from the main vault: remove it there"
    finally:
        ctx.close()


def test_a_value_with_a_nul_is_stopped_on_the_page(browser, mb, real, fake_amt):
    ctx, pg = identities_page(browser, mb)
    try:
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        pg.evaluate("() => { const f = document.getElementById('intake-value'); f.value = 'a\\u0000b'; f.dispatchEvent(new Event('input')); }")
        assert pg.get_attribute("#intake-send", "aria-disabled") == "true" and text(pg, "#intake-wrap .reason") == "one line only: no line break"
    finally:
        ctx.close()


def minted_page(browser, mb):
    ctx, pg = identities_page(browser, mb)
    pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
    pg.wait_for_selector("#intake-block:not([hidden])")
    return ctx, pg


def test_a_value_the_console_refuses_before_sending_leaves_the_intake_open(browser, mb, real, fake_amt):
    ctx, pg = minted_page(browser, mb)
    try:
        iid = next(iter(mb.app.intakes._offers))
        mb.app.intakes._offers[iid]["cap"] = 5                                             # the console holds a smaller limit than the page was told
        pg.fill("#intake-value", SENTINEL); pg.click("#intake-send")
        pg.wait_for_selector("#nid-results .result.error")
        assert "refused: value_size_out_of_range · nothing was sent to amt-mcp; the intake is still open" in results(pg, "nid-results")[0]
        assert pg.is_visible("#intake-block") and pg.input_value("#intake-value") == "" and fake_amt.puts == []
        mb.app.intakes._offers[iid]["cap"] = 4096
        pg.fill("#intake-value", SENTINEL); pg.click("#intake-send")
        pg.wait_for_selector("#nid-results .result.ok")
        assert real.store[f"{KEY}-amt"]["value"] == SENTINEL
    finally:
        ctx.close()


def test_an_amt_mcp_that_stops_answering_mid_request_is_not_known_to_have_stored_the_value(browser, mb, real, fake_amt):
    ctx, pg = minted_page(browser, mb)
    try:
        def drop(path, headers, body):
            raise RuntimeError("the connection ends here")
        fake_amt.put_handler = drop
        pg.fill("#intake-value", SENTINEL); pg.click("#intake-send")
        pg.wait_for_selector("#nid-results .result.live")
        t = results(pg, "nid-results")[0]
        assert "amt-mcp did not answer (amt_mcp_unreachable:" in t and "it is not known whether the value was stored; Re-read the identities before minting again" in t
        assert pg.is_hidden("#intake-block") and SENTINEL not in pg.content()
    finally:
        ctx.close()


def test_a_connection_to_the_console_that_ends_is_not_known_to_have_sent_the_value(browser, mb, real, fake_amt):
    ctx, pg = minted_page(browser, mb)
    try:
        pg.route("**/api/identities/intake/**", lambda route: route.abort())
        pg.fill("#intake-value", SENTINEL); pg.click("#intake-send")
        pg.wait_for_selector("#nid-results .result.live")
        assert "the connection to the console ended before an answer · it is not known whether the value was sent" in results(pg, "nid-results")[0]
        assert fake_amt.puts == [] and pg.input_value("#intake-value") == ""
    finally:
        ctx.close()


def test_an_intake_result_without_a_usable_url_waits_for_nothing(browser, mb, real, fake_amt):
    base = fake_amt.results["amt_identity_manage"]
    fake_amt.results["amt_identity_manage"] = lambda a: {**base(a), "url": "https://amt.example.test/intake/" + "A" * 43}
    ctx, pg = identities_page(browser, mb)
    try:
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#nid-results .result.error")
        assert "carried no usable one-time url (intake_url_not_from_amt_mcp) · nothing is waiting for a value" in results(pg, "nid-results")[0] and pg.is_hidden("#intake-block")
    finally:
        ctx.close()
    fake_amt.results["amt_identity_manage"] = base


def test_a_re_read_that_finishes_while_a_sheet_is_open_does_not_rebuild_the_list_under_it(browser, mb, real, fake_amt):
    ctx, pg = identities_page(browser, mb)
    try:
        base = fake_amt.results["amt_identities"]

        def slow(a):
            time.sleep(0.8)
            return base(a)
        fake_amt.results["amt_identities"] = slow
        pg.click("#id-reread")
        pg.click(replace_button(f"{KEY}-amt"))
        pg.wait_for_timeout(1600)
        assert pg.locator(".sheet.open").count() == 1
        pg.keyboard.press("Escape")
        until(pg, f"() => document.activeElement && document.activeElement.getAttribute('aria-label') === 'Replace the stored value of {KEY}-amt'")
        assert writes(fake_amt) == []
    finally:
        ctx.close()


# -- immutable 9 on both pages: no password field, the value field's form ----------------------------------------------------------------

def test_neither_page_has_a_password_field_and_the_value_field_is_outside_any_form(browser, mb, real, fake_amt):
    for opener in (servers_page, identities_page):
        ctx, pg = opener(browser, mb)
        try:
            assert pg.locator("input[type=password]").count() == 0 and pg.locator("[autocomplete=new-password]").count() == 0 and pg.locator("form").count() == 0
            for f in pg.query_selector_all(".secret"):
                assert f.evaluate("e => !e.closest('form') && e.getAttribute('autocomplete') === 'off' && !e.hasAttribute('value') && e.type === 'text'")
        finally:
            ctx.close()


def test_the_pages_load_nothing_from_outside_the_console_and_never_touch_amt_mcp(browser, mb, real, fake_amt):
    for opener in (servers_page, identities_page):
        ctx, pg = opener(browser, mb)
        try:
            origins = {u.split("/")[0] + "//" + u.split("/")[2] for u in pg.requests if u.startswith("http")}
            assert origins == {mb.origin}, origins
            assert not [u for u in pg.requests if fake_amt.base in u or u.endswith("/mcp")]
            body = pg.content()
            assert 'type="password"' not in body and "handoffs/" not in body and "/intake/" not in body
        finally:
            ctx.close()


# -- layout and contrast ---------------------------------------------------------------------------------------------------------------

def prepare_servers(real):
    second_server(real)
    real.presented[ADDR] = LEAF_B


def walk(pg, width):
    cm = check_mockups()
    pg.wait_for_timeout(250)
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
    for t in r["targets"]:
        if not ((t["w"] >= 48 and t["h"] >= 48) or (t["chip"] and t["w"] >= 24 and t["h"] >= 24)): bad.append(("target", t))
    return r, bad


@pytest.mark.parametrize("width", WIDTHS)
def test_the_servers_page_fits_every_width_with_hit_areas_and_a_16_px_gutter(browser, mb, real, fake_amt, width):
    prepare_servers(real)
    ctx, pg = servers_page(browser, mb, width=width, rows=2)
    try:
        pg.click(btn("Check pin")); pg.wait_for_selector("#srv-results .result.error")
        r, bad = walk(pg, width)
        assert bad == [], bad
        assert len(r["targets"]) >= 12 and r["text"], "the walk saw nothing: it would pass on an empty page"
        assert pg.errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("width", WIDTHS)
def test_the_identities_page_fits_every_width_with_hit_areas_and_a_16_px_gutter(browser, mb, real, fake_amt, width):
    seed_identities(real)
    ctx, pg = identities_page(browser, mb, width=width)
    try:
        until(pg, "() => document.querySelectorAll('#id-list li').length === 5")
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        pg.fill("#intake-value", SENTINEL)
        r, bad = walk(pg, width)
        assert bad == [], bad
        assert len(r["targets"]) >= 15 and r["text"], "the walk saw nothing: it would pass on an empty page"
        assert pg.errors == []
    finally:
        ctx.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_every_text_and_ring_on_the_servers_page_clears_the_contrast_floors(browser, mb, real, fake_amt, scheme):
    prepare_servers(real)
    ctx, pg = servers_page(browser, mb, scheme=scheme, rows=2)
    try:
        pg.click(btn("Check pin")); pg.wait_for_selector("#srv-results .result.error")
        pg.wait_for_timeout(250)
        r = pg.evaluate(check_mockups().JS_WALK)
        low = [(t["snippet"], t["ratio"], t["ex"]) for t in r["text"] if t["ratio"] < (3.0 if t["large"] else 4.5)]
        assert low == [], low
        assert len(r["text"]) > 40, "the walk saw too little text: it would pass on an empty page"
    finally:
        ctx.close()


@pytest.mark.parametrize("scheme", ["light", "dark"])
def test_every_text_and_ring_on_the_identities_page_clears_the_contrast_floors(browser, mb, real, fake_amt, scheme):
    seed_identities(real)
    ctx, pg = identities_page(browser, mb, scheme=scheme)
    try:
        until(pg, "() => document.querySelectorAll('#id-list li').length === 5")
        pg.click(replace_button(f"{KEY}-amt")); confirm_plain(pg)
        pg.wait_for_selector("#intake-block:not([hidden])")
        pg.wait_for_timeout(250)
        r = pg.evaluate(check_mockups().JS_WALK)
        low = [(t["snippet"], t["ratio"], t["ex"]) for t in r["text"] if t["ratio"] < (3.0 if t["large"] else 4.5)]
        assert low == [], low
        assert len(r["text"]) > 40, "the walk saw too little text: it would pass on an empty page"
    finally:
        ctx.close()
