"""Parity: every MeshCommander surface maps to an implemented tool or the documented Files
exception; with the display mirror built, nothing is planned and parity is COMPLETE.

The census names below are an independent copy of the tracker's rows (Parity Rows Are Immutable):
removing or rewording a manifest row fails here. Each item's ``checks`` are verified against the
live implementation tables, so a mapping cannot name an option, action or chord the code lacks.
"""
import asyncio
import sys
import typing
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import amt_mirror  # noqa: E402
import amt_parity  # noqa: E402
import amt_tools  # noqa: E402
import amt_wsman  # noqa: E402
import amt_write  # noqa: E402
from amt_server import mcp  # noqa: E402

TOTALS = {"pages": 18, "power_entries": 26, "boot_options": 16, "key_macros": 25}

PAGES = ["System Status", "Remote Desktop", "Files", "Serial-over-LAN", "Hardware Information",
         "Event Log", "Audit Log", "Storage", "Network Settings", "Internet Settings",
         "Security Settings", "Agent Presence", "System Defense", "User Accounts", "Subscriptions",
         "Wake Alarms", "Script Editor", "WSMAN Browser"]
POWER = ["Power up", "Reset", "Power cycle", "Power down", "Soft-off", "Soft-reset", "Sleep",
         "Hibernate", "OS Wake from Standby", "OS Power Saving", "Power on to diagnostic",
         "Reset to diagnostic", "Power up to BIOS", "Reset to BIOS", "Power up to Secure Erase",
         "Reset to Secure Erase", "Power up to Platform Erase", "Reset to Platform Erase",
         "Reset to IDE-R Floppy", "Power on to IDE-R Floppy", "Reset to IDE-R CDROM",
         "Power on to IDE-R CDROM", "Reset to PXE", "Power on to PXE", "Custom action",
         "User consent"]
BOOT = ["BIOS Pause", "Enforce Secure Boot", "BIOS Setup", "Force progress events", "Lock power button",
        "Lock reset button", "Lock sleep button", "Lock keyboard", "BIOS password bypass",
        "Reflash BIOS", "Safe mode", "Use IDER", "Serial-over-LAN", "Intel Remote Secure Erase",
        "Remote Platform Erase", "Clear Intel ME Settings"]
MACROS = ["Win", "Win+Down", "Win+Up", "Win+L", "Win+M", "Win+R", "Win+Left", "Win+Right",
          "Shift+Win+M", "Alt-Tab", "Alt-F4", "Ctrl-W", *[f"F{i}" for i in range(1, 13)], "LS+LA+PrtSc"]
CENSUS = {"pages": PAGES, "power_entries": POWER, "boot_options": BOOT, "key_macros": MACROS}

# The mirror surface, planned until 2026-10-18 and now built: its rows must stay implemented.
MIRROR = {"amt_mirror_link", "mirror_page", "Remote Desktop view shared with the operator",
          "Record session to file", "Plus: live mirror while an agent drives",
          "Remote Desktop keyboard and mouse from the operator's browser"}

# Items covered with a disclosed limit or only through the generic WS-MAN tools. Pinned so a new
# caveat, or a silently dropped one, is a visible change.
CAVEATED = {
    "pages": {"Files", "Storage", "Agent Presence", "System Defense", "Subscriptions", "Wake Alarms"},
    "power_entries": {"OS Wake from Standby", "OS Power Saving", "Power up to Platform Erase",
                      "Reset to Platform Erase", "Custom action", "User consent"},
    "boot_options": {"Intel Remote Secure Erase", "Remote Platform Erase"},
    "key_macros": set(),
}


def _live_tools() -> set[str]:
    return {t.name for t in asyncio.run(mcp.list_tools())}


def _implemented_manifest() -> set[str]:
    return {r["name"] for r in amt_parity.TOOLS if r["status"] == amt_parity.IMPLEMENTED}


def _check_problem(name: str, check: tuple) -> str | None:
    """Verify one check against the implementation; None = holds."""
    kind = check[0]
    try:
        if kind == "power_action":
            _, action, state = check
            if amt_write.POWER_ACTIONS[action][0] != state:
                return f"{name}: power action {action} is not state {state}"
        elif kind == "boot_target":
            if check[1] not in amt_write.BOOT_TARGETS:
                return f"{name}: boot target {check[1]!r} not allowed by amt_set_next_boot"
        elif kind == "boot_option":
            if check[1] not in amt_write.BOOT_OPTIONS:
                return f"{name}: boot option {check[1]!r} unknown to amt_set_next_boot"
        elif kind == "settings_area":
            if check[1] not in amt_tools.SETTINGS_AREA_NAMES:
                return f"{name}: settings area {check[1]!r} unknown to amt_settings"
        elif kind == "configure_area":
            if check[1] not in typing.get_args(amt_write.ConfigureArea):
                return f"{name}: configure area {check[1]!r} unknown to amt_configure"
        elif kind == "wsman_class":
            amt_wsman.resource_uri(check[1])
        elif kind == "chord":
            _, mods, key = check
            steps = amt_write._compile_actions([{"kind": "key", "key": key, "modifiers": list(mods)}])
            if len(steps) != 1 or steps[0][0] not in ("key", "key_char") or steps[0][1] != tuple(mods):
                return f"{name}: chord {mods}+{key} did not compile to one modified key step"
        elif kind == "mirror_route":
            if check[1] not in amt_mirror.ROUTES:
                return f"{name}: mirror route {check[1]!r} is not served"
        elif kind == "mirror_post_route":
            if check[1] not in amt_mirror.POST_ROUTES:
                return f"{name}: mirror route {check[1]!r} is not accepted"
        elif kind == "mirror_action":
            if check[1] not in typing.get_args(amt_mirror.MirrorAction):
                return f"{name}: mirror action {check[1]!r} unknown to amt_mirror_link"
        elif kind == "mirror_shared_session":
            if not _console_tools_share_a_live_mirror():
                return f"{name}: the console tools do not reuse a live mirror's session"
        else:
            return f"{name}: unknown check kind {kind!r}"
    except (KeyError, ValueError) as ex:
        return f"{name}: check {check} failed: {type(ex).__name__}: {ex}"
    return None


def _console_tools_share_a_live_mirror() -> bool:
    """Functional: register a live mirror and ask the console tools' session factory for one."""
    dev = amt_mirror.amt_registry.get_device(amt_tools.DEFAULT_DEVICE)

    class _Alive:
        def is_alive(self):
            return True

    mirror = amt_mirror.Mirror(dev.key, session=None, fps=1, quality=50)
    mirror.thread = _Alive()
    amt_mirror._MIRRORS[dev.key] = mirror
    try:
        return isinstance(amt_tools._kvm_session(dev, "unused"), amt_mirror._Shared)
    finally:
        amt_mirror._MIRRORS.pop(dev.key, None)


def item_problems(item: dict, live: set[str], manifest: set[str]) -> list[str]:
    """Every parity violation of one surface item (empty = it holds)."""
    name, out = item["name"], []
    status = item["status"]
    if status == amt_parity.IMPLEMENTED:
        if not item["tools"]:
            out.append(f"{name}: built surface is mapped to no tool")
        for tool in item["tools"]:
            if tool not in live:
                out.append(f"{name}: tool {tool} is not in the live list_tools()")
            if tool not in manifest:
                out.append(f"{name}: tool {tool} is not an implemented manifest row")
        for check in item["checks"]:
            problem = _check_problem(name, check)
            if problem:
                out.append(problem)
    elif status == amt_parity.EXCEPTION:
        if item["tools"] or not item["caveat"]:
            out.append(f"{name}: an exception maps no tool and states its reason")
    elif status == amt_parity.PLANNED:
        if item["tools"] and set(item["tools"]) != {"amt_mirror_link"}:
            out.append(f"{name}: a planned item may only wait on amt_mirror_link")
    else:
        out.append(f"{name}: unknown status {status!r}")
    return out


# --- coverage totals and census ----------------------------------------------------------------

def test_coverage_totals_are_pinned():
    assert {k: v["total"] for k, v in amt_parity.COVERAGE.items()} == TOTALS
    assert {k: len(v) for k, v in CENSUS.items()} == TOTALS


def test_every_census_item_has_exactly_one_manifest_row():
    for bucket, names in CENSUS.items():
        manifest_names = [i["name"] for i in amt_parity.SURFACES[bucket]]
        assert manifest_names == names, bucket
        assert len(set(manifest_names)) == len(manifest_names) == TOTALS[bucket]


def test_mapped_counts_match_the_tables():
    for bucket, items in amt_parity.SURFACES.items():
        cov = amt_parity.COVERAGE[bucket]
        mapped = sum(i["status"] == amt_parity.IMPLEMENTED for i in items)
        exceptions = sum(i["status"] == amt_parity.EXCEPTION for i in items)
        assert (cov["mapped"], cov["exception"]) == (mapped, exceptions), bucket
        assert cov["mapped"] + cov["exception"] == cov["total"], bucket
    assert amt_parity.COVERAGE["pages"] == {"total": 18, "mapped": 17, "exception": 1}
    assert all(amt_parity.COVERAGE[b]["exception"] == 0 for b in ("power_entries", "boot_options", "key_macros"))


def test_only_the_files_page_is_a_documented_exception():
    exceptions = [(b, i["name"]) for b, items in amt_parity.SURFACES.items() for i in items
                  if i["status"] == amt_parity.EXCEPTION]
    assert exceptions == [("pages", "Files")]


# --- every surface is mapped to a live implemented tool and verified against the code ------------

def test_every_surface_item_holds_against_the_implementation():
    live, manifest = _live_tools(), _implemented_manifest()
    assert live == manifest
    problems = [p for items in amt_parity.SURFACES.values() for i in items
                for p in item_problems(i, live, manifest)]
    assert not problems, "\n".join(problems)


def test_direct_power_entries_use_the_state_meshcommander_sends():
    direct = [i for i in amt_parity.POWER_ENTRIES
              if i["tools"] == ["amt_power"] and len(i["checks"]) == 1]
    assert len(direct) == 8
    for i in direct:
        assert i["checks"][0][2] == i["id"], i["name"]


def test_caveated_items_are_pinned():
    for bucket, items in amt_parity.SURFACES.items():
        assert {i["name"] for i in items if i["caveat"]} == CAVEATED[bucket], bucket


def test_every_implemented_tool_serves_a_surface_or_is_a_composite():
    used = {t for items in (*amt_parity.SURFACES.values(), amt_parity.MIRROR_SURFACES)
            for i in items for t in i["tools"]}
    unused = _implemented_manifest() - used
    # amt_devices and amt_device_manage serve MeshCommander's computer list, its start screen, which is not one of the
    # 18 pages; the manifest row carries it and the immutable page census stays 18. amt_identities and
    # amt_identity_manage serve the vaulted AMT passwords (User Accounts) the same way. amt_captures lists and
    # fetches the files the screenshot and recording tools wrote; it adds no page of its own.
    assert unused == {"amt_remote_logon", "amt_remote_logoff", "amt_devices", "amt_device_manage",
                      "amt_identities", "amt_identity_manage", "amt_captures"}, unused


# --- the mirror surface is built, so parity is complete -----------------------------------------

def test_no_row_is_planned_and_the_mirror_rows_are_built():
    assert amt_parity.planned_rows() == []
    built = {r["name"] for r in amt_parity.TOOLS if r["status"] == amt_parity.IMPLEMENTED}
    built |= {r["name"] for r in amt_parity.ROUTES if r["status"] == amt_parity.IMPLEMENTED}
    built |= {i["name"] for i in amt_parity.MIRROR_SURFACES if i["status"] == amt_parity.IMPLEMENTED}
    assert MIRROR <= built
    assert "amt_mirror_link" in _live_tools()


def test_parity_is_complete():
    assert amt_parity.parity_status() == "complete"
    for i in amt_parity.MIRROR_SURFACES:
        assert item_problems(i, _live_tools(), _implemented_manifest()) == []


# --- the checker itself must be able to fail -----------------------------------------------------

def _item(**kw):
    base = {"name": "X", "tools": ["amt_power"], "checks": [("power_action", "power_on", 2)],
            "caveat": None, "status": amt_parity.IMPLEMENTED}
    return {**base, **kw}


def _problems(item):
    return item_problems(item, _live_tools(), _implemented_manifest())


def test_checker_accepts_a_sound_item():
    assert _problems(_item()) == []


def test_unmapping_a_built_surface_is_flagged():
    assert any("mapped to no tool" in p for p in _problems(_item(tools=[], checks=[])))


def test_a_tool_that_is_not_live_is_flagged():
    assert any("not in the live list_tools()" in p for p in _problems(_item(tools=["amt_nope"])))


def test_each_check_kind_fails_when_the_implementation_lacks_the_target():
    bad = [("power_action", "power_on", 3), ("power_action", "nope", 2), ("boot_target", "usb"),
           ("boot_option", "platform_erase"), ("settings_area", "nope"), ("configure_area", "wake_alarms"),
           ("wsman_class", "bad class!"), ("chord", ("win",), "nonexistent_key"),
           ("chord", ("hyper",), "a"), ("mirror_route", "admin"), ("mirror_action", "share"),
           ("mystery", "x")]
    for check in bad:
        assert _problems(_item(checks=[check])), check


def test_an_exception_or_planned_item_cannot_hide_a_tool_mapping():
    assert _problems(_item(status=amt_parity.EXCEPTION, tools=["amt_power"], caveat="r"))
    assert _problems(_item(status=amt_parity.EXCEPTION, tools=[], caveat=None))
    assert _problems(_item(status=amt_parity.PLANNED, tools=["amt_power"]))
    assert _problems(_item(status="bogus"))
