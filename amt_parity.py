"""Parity manifest: MeshCommander -> amt-mcp tool mapping.

Source: MeshCommander 0.9.5-a ``public/default.htm`` (49,601 lines, sha256 prefix ``7fb8b4d92d2f``).
The 18 pages are its navigation list (lines 816-833), the 26 power entries its power menu
(lines 47013-47050), the 16 advanced boot options its ``d24*`` checkboxes (lines 1488-1503) and
the 25 key macros its ``deskkeys`` list (lines 1030-1060, the commented ``LS+LA+PrtSc`` included).
The rows are fixed by the tracker (Parity Rows Are Immutable); ``tests/test_parity.py`` pins the
names, so a row cannot be removed or reworded silently.

Every surface item names the implemented tool(s) that cover it and ``checks``: facts that
``tests/test_parity.py`` verifies against the live implementation tables, so a mapping cannot name
an option, action or chord the code does not have. ``caveat`` marks the items covered only through
the generic ``amt_wsman_invoke`` / ``amt_wsman_get`` tools or with a disclosed limit.

Parity is PARTIAL while any row is ``planned``. With the display mirror (``amt_mirror_link`` and its
``/m/<token>/`` page) built, no row is planned.
"""
from __future__ import annotations

PLANNED = "planned"
IMPLEMENTED = "implemented"
EXCEPTION = "exception"          # the documented Files-page exception

# Mapped counts are filled from the surface tables below and re-derived by tests/test_parity.py.
# ``exception`` counts items deliberately unmatched (the Files page).
COVERAGE = {
    "pages": {"total": 18, "mapped": 17, "exception": 1},
    "power_entries": {"total": 26, "mapped": 26, "exception": 0},
    "boot_options": {"total": 16, "mapped": 16, "exception": 0},
    "key_macros": {"total": 25, "mapped": 25, "exception": 0},
}


def _row(name: str, kind: str, write_guard: bool = False,
         meshcommander: tuple[str, ...] = ()) -> dict:
    return {
        "name": name,
        "kind": kind,
        "write_guard": write_guard,  # True = carries a `confirmed` parameter
        "status": IMPLEMENTED if meshcommander else PLANNED,
        "meshcommander": list(meshcommander),
    }


TOOLS: list[dict] = [
    # Read tools.
    _row("amt_status", "read", meshcommander=("General summary", "Power state")),
    _row("amt_screenshot", "read", meshcommander=("Remote Desktop screen",)),
    _row("amt_inventory", "read", meshcommander=("Hardware Information",)),
    _row("amt_logs", "read", meshcommander=("Event Log", "Audit Log")),
    _row("amt_settings", "read", meshcommander=(
        "Network Settings", "Internet Settings", "Security Settings", "Agent Presence",
        "System Defense", "User Accounts", "Event Subscriptions", "Wake Alarms",
        "KVM Settings", "Features")),
    _row("amt_wsman_get", "read", meshcommander=("WS-MAN class read",)),
    _row("amt_devices", "read", meshcommander=("Computer list",)),
    _row("amt_identities", "read", meshcommander=("User Accounts: AMT passwords from the vault",)),
    _row("amt_captures", "read", meshcommander=("Remote Desktop screenshot save", "Record session to file")),
    # Write tools (each carries a `confirmed` guard).
    _row("amt_power", "write", True, meshcommander=("Power actions",)),
    _row("amt_set_next_boot", "write", True, meshcommander=("Boot options",)),
    _row("amt_console_input", "write", True, meshcommander=(
        "Remote Desktop keyboard input", "Remote Desktop mouse input", "Key macros")),
    _row("amt_sol", "write", True, meshcommander=("Serial-over-LAN terminal",)),
    _row("amt_ider", "write", True, meshcommander=("IDE-R floppy and CD mount",)),
    _row("amt_images", "write", True, meshcommander=("IDE-R image file choice",)),
    _row("amt_configure", "write", True, meshcommander=(
        "Network Settings", "Internet Settings", "Security Settings", "User Accounts",
        "KVM Settings", "Features")),
    _row("amt_wsman_invoke", "write", True, meshcommander=("Script Editor",)),
    _row("amt_device_manage", "write", True, meshcommander=("Computer list add, edit and remove",)),
    _row("amt_identity_manage", "write", True, meshcommander=("User Accounts: AMT passwords from the vault",)),
    # Mirror: the live display mirror (amt_mirror.py).
    _row("amt_mirror_link", "mirror", True, meshcommander=(
        "Remote Desktop view", "Record session to file")),
    # Serial terminal: the live Serial-over-LAN page (amt_serial.py).
    _row("amt_serial_link", "mirror", True, meshcommander=("Serial-over-LAN terminal",)),
    # Composite logon workflow.
    _row("amt_remote_logon", "composite", True, meshcommander=(
        "Remote Desktop keyboard input", "Remote Desktop screen")),
    _row("amt_remote_logoff", "composite", True, meshcommander=(
        "Remote Desktop keyboard input", "Remote Desktop screen")),
]

ROUTES: list[dict] = [
    {"name": "mirror_page", "path": "/m/<token>/", "status": IMPLEMENTED,
     "meshcommander": ["Remote Desktop view"]},
    {"name": "serial_page", "path": "/s/<token>/", "status": IMPLEMENTED,
     "meshcommander": ["Serial-over-LAN terminal"]},
]

CENSUS = {
    "read": 9,
    "write": 10,
    "mirror": 2,
    "composite": 2,
}


def _item(name: str, tools: tuple[str, ...], checks: tuple[tuple, ...] = (),
          caveat: str | None = None, status: str = IMPLEMENTED, **extra) -> dict:
    return {"name": name, "tools": list(tools), "checks": [tuple(c) for c in checks],
            "caveat": caveat, "status": status, **extra}


_GENERIC = "reached only through the generic amt_wsman_invoke; no typed option"

# --- 18 pages -------------------------------------------------------------------------------
PAGES: list[dict] = [
    _item("System Status", ("amt_status",)),
    _item("Remote Desktop", ("amt_screenshot", "amt_console_input")),
    _item("Files", (), status=EXCEPTION,
          caveat="documented exception: MeshCommander shows Files only over a MeshCentral software "
                 "agent's WebRTC channel (default.htm line 45290), which standalone AMT never has"),
    _item("Serial-over-LAN", ("amt_sol", "amt_serial_link")),
    _item("Hardware Information", ("amt_inventory",)),
    _item("Event Log", ("amt_logs",)),
    _item("Audit Log", ("amt_logs",)),
    _item("Storage", ("amt_inventory",),
          caveat="CIM_PhysicalMedia is not exposed by my-server-1's AMT; amt_inventory discloses "
                 "it under 'unavailable'"),
    _item("Network Settings", ("amt_settings", "amt_configure"),
          (("settings_area", "network"), ("configure_area", "network"))),
    _item("Internet Settings", ("amt_settings", "amt_configure"),
          (("settings_area", "internet"), ("configure_area", "internet"))),
    _item("Security Settings", ("amt_settings", "amt_configure"),
          (("settings_area", "security"), ("configure_area", "security"))),
    _item("Agent Presence", ("amt_settings", "amt_wsman_invoke"), (("settings_area", "agent_presence"),),
          caveat="read typed via amt_settings; writes only through the generic amt_wsman_invoke "
                 "(amt_configure has no agent_presence area)"),
    _item("System Defense", ("amt_settings", "amt_wsman_invoke"), (("settings_area", "system_defense"),),
          caveat="read typed via amt_settings; writes only through the generic amt_wsman_invoke "
                 "(amt_configure has no system_defense area)"),
    _item("User Accounts", ("amt_settings", "amt_configure"),
          (("settings_area", "users"), ("configure_area", "users"))),
    _item("Subscriptions", ("amt_settings", "amt_wsman_invoke"), (("settings_area", "subscriptions"),),
          caveat="read typed via amt_settings; writes only through the generic amt_wsman_invoke "
                 "(amt_configure has no subscriptions area)"),
    _item("Wake Alarms", ("amt_settings", "amt_wsman_invoke"), (("settings_area", "wake_alarms"),),
          caveat="read typed via amt_settings; writes only through the generic amt_wsman_invoke "
                 "(amt_configure has no wake_alarms area)"),
    _item("Script Editor", ("amt_wsman_invoke",)),
    _item("WSMAN Browser", ("amt_wsman_get", "amt_wsman_invoke")),
]

# --- 26 power-menu entries (MeshCommander action id in ``id``) ---------------------------------
_P, _B = "amt_power", "amt_set_next_boot"


def _power(name: str, id_: int, action: str, state: int) -> dict:
    return _item(name, (_P,), (("power_action", action, state),), id=id_)


def _boot_power(name: str, id_: int, boot_check: tuple, action: str, state: int, **kw) -> dict:
    """A 'power on / reset to X' entry: arm the one-time boot request, then power."""
    return _item(name, (_B, _P), (boot_check, ("power_action", action, state)), id=id_, **kw)


POWER_ENTRIES: list[dict] = [
    _power("Power up", 2, "power_on", 2),
    _power("Reset", 10, "hard_reset", 10),
    _power("Power cycle", 5, "immediate_power_cycle", 5),
    _power("Power down", 8, "immediate_shutdown", 8),
    _power("Soft-off", 12, "shutdown", 12),
    _power("Soft-reset", 14, "restart", 14),
    _power("Sleep", 4, "sleep_deep", 4),
    _power("Hibernate", 7, "hibernate", 7),
    _item("OS Wake from Standby", ("amt_wsman_invoke",), (("wsman_class", "IPS_PowerManagementService"),),
          caveat=_GENERIC + " (IPS_PowerManagementService.RequestOSPowerSavingStateChange)", id=500),
    _item("OS Power Saving", ("amt_wsman_invoke",), (("wsman_class", "IPS_PowerManagementService"),),
          caveat=_GENERIC + " (IPS_PowerManagementService.RequestOSPowerSavingStateChange)", id=501),
    _boot_power("Power on to diagnostic", 300, ("boot_target", "diagnostic"), "power_on", 2),
    _boot_power("Reset to diagnostic", 301, ("boot_target", "diagnostic"), "hard_reset", 10),
    _boot_power("Power up to BIOS", 100, ("boot_target", "bios_setup"), "power_on", 2),
    _boot_power("Reset to BIOS", 101, ("boot_target", "bios_setup"), "hard_reset", 10),
    _boot_power("Power up to Secure Erase", 104, ("boot_option", "secure_erase"), "power_on", 2),
    _boot_power("Reset to Secure Erase", 105, ("boot_option", "secure_erase"), "hard_reset", 10),
    _item("Power up to Platform Erase", (_P, "amt_wsman_invoke"),
          (("wsman_class", "AMT_BootSettingData"), ("power_action", "power_on", 2)),
          caveat="Platform Erase is a read-only field for amt_set_next_boot; " + _GENERIC, id=106),
    _item("Reset to Platform Erase", (_P, "amt_wsman_invoke"),
          (("wsman_class", "AMT_BootSettingData"), ("power_action", "hard_reset", 10)),
          caveat="Platform Erase is a read-only field for amt_set_next_boot; " + _GENERIC, id=107),
    _item("Reset to IDE-R Floppy", (_B, "amt_images", "amt_ider", _P),
          (("boot_target", "floppy_ider"), ("power_action", "hard_reset", 10)), id=200),
    _item("Power on to IDE-R Floppy", (_B, "amt_images", "amt_ider", _P),
          (("boot_target", "floppy_ider"), ("power_action", "power_on", 2)), id=201),
    _item("Reset to IDE-R CDROM", (_B, "amt_images", "amt_ider", _P),
          (("boot_target", "cd_ider"), ("power_action", "hard_reset", 10)), id=202),
    _item("Power on to IDE-R CDROM", (_B, "amt_images", "amt_ider", _P),
          (("boot_target", "cd_ider"), ("power_action", "power_on", 2)), id=203),
    _boot_power("Reset to PXE", 400, ("boot_target", "pxe"), "hard_reset", 10),
    _boot_power("Power on to PXE", 401, ("boot_target", "pxe"), "power_on", 2),
    _item("Custom action", ("amt_wsman_invoke",), id=999,
          caveat="the agent composes the WS-MAN call itself; " + _GENERIC),
    _item("User consent", ("amt_configure", "amt_wsman_invoke"), (("configure_area", "kvm"),), id=998,
          caveat="amt_configure kvm sets OptInPolicy only; the consent-code request itself "
                 "(IPS_OptInService) is " + _GENERIC),
]

# --- 16 advanced boot options ----------------------------------------------------------------
_N = "amt_set_next_boot"
BOOT_OPTIONS: list[dict] = [
    _item("BIOS Pause", (_N,), (("boot_option", "bios_pause"),)),
    _item("Enforce Secure Boot", (_N,), (("boot_option", "enforce_secure_boot"),)),
    _item("BIOS Setup", (_N,), (("boot_target", "bios_setup"),)),
    _item("Force progress events", (_N,), (("boot_option", "forced_progress_events"),)),
    _item("Lock power button", (_N,), (("boot_option", "lock_power_button"),)),
    _item("Lock reset button", (_N,), (("boot_option", "lock_reset_button"),)),
    _item("Lock sleep button", (_N,), (("boot_option", "lock_sleep_button"),)),
    _item("Lock keyboard", (_N,), (("boot_option", "lock_keyboard"),)),
    _item("BIOS password bypass", (_N,), (("boot_option", "user_password_bypass"),)),
    _item("Reflash BIOS", (_N,), (("boot_option", "reflash_bios"),)),
    _item("Safe mode", (_N,), (("boot_option", "use_safe_mode"),)),
    _item("Use IDER", (_N,), (("boot_option", "use_ider"),)),
    _item("Serial-over-LAN", (_N,), (("boot_option", "use_sol"),)),
    _item("Intel Remote Secure Erase", (_N,), (("boot_option", "secure_erase"),),
          caveat="the erase flag is typed; MeshCommander's RSEPassword is a credential and is never "
                 "caller-supplied here (dropped from the Put, refused by amt_wsman_invoke)"),
    _item("Remote Platform Erase", ("amt_wsman_invoke",), (("wsman_class", "AMT_BootSettingData"),),
          caveat="PlatformErase is in amt_set_next_boot's read-only drop set; " + _GENERIC),
    _item("Clear Intel ME Settings", (_N,), (("boot_option", "configuration_data_reset"),)),
]

# --- 25 key macros: (modifiers, key) chords sent through amt_console_input -------------------
_C = "amt_console_input"


def _macro(name: str, modifiers: tuple[str, ...], key: str) -> dict:
    return _item(name, (_C,), (("chord", modifiers, key),))


KEY_MACROS: list[dict] = [
    _macro("Win", (), "win"),
    _macro("Win+Down", ("win",), "down"),
    _macro("Win+Up", ("win",), "up"),
    _macro("Win+L", ("win",), "l"),
    _macro("Win+M", ("win",), "m"),
    _macro("Win+R", ("win",), "r"),
    _macro("Win+Left", ("win",), "left"),
    _macro("Win+Right", ("win",), "right"),
    _macro("Shift+Win+M", ("shift", "win"), "m"),
    _macro("Alt-Tab", ("alt",), "tab"),
    _macro("Alt-F4", ("alt",), "f4"),
    _macro("Ctrl-W", ("ctrl",), "w"),
    *[_macro(f"F{i}", (), f"f{i}") for i in range(1, 13)],
    _macro("LS+LA+PrtSc", ("shift", "alt"), "print_screen"),
]

# --- the mirror surface (amt_mirror.py) ---------------------------------------------------------
MIRROR_SURFACES: list[dict] = [
    _item("Remote Desktop view shared with the operator", ("amt_mirror_link",),
          checks=(("mirror_route", "stream"), ("mirror_route", "frame.jpg"))),
    _item("Record session to file", ("amt_mirror_link",), checks=(("mirror_action", "record_start"),)),
    _item("Plus: live mirror while an agent drives", ("amt_mirror_link", "amt_console_input"),
          checks=(("mirror_shared_session",),)),
    _item("Remote Desktop keyboard and mouse from the operator's browser", ("amt_mirror_link",),
          checks=(("mirror_post_route", "input"),)),
]

SURFACES = {"pages": PAGES, "power_entries": POWER_ENTRIES, "boot_options": BOOT_OPTIONS,
            "key_macros": KEY_MACROS}


def planned_rows() -> list[str]:
    """Names of every row still ``planned``: tools, routes and surface items."""
    names = [r["name"] for r in TOOLS if r["status"] == PLANNED]
    names += [r["name"] for r in ROUTES if r["status"] == PLANNED]
    names += [i["name"] for i in MIRROR_SURFACES if i["status"] == PLANNED]
    return names


def parity_status() -> str:
    """``complete`` only when nothing is planned; otherwise ``partial``."""
    return "partial" if planned_rows() else "complete"
