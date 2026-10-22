"""The eight WRITE tools: power, next boot, console input, SOL, IDE-R mount, the IDE-R image library,
configure, WS-MAN invoke.

Each tool can change or interrupt a live machine, so each is ``readOnlyHint: False`` and carries
a ``confirmed: bool = False`` guard that REFUSES (``ConfirmationRequired``, nothing sent, no
vault read, no connection) unless it is True, and whose message names the consequence. The TLS
pin is enforced on every connect (WS-MAN via ``amt_wsman.transport``, KVM/SOL/IDE-R via the
pinned session classes). One Digest attempt per call, no retry. No credential is ever an
argument, a result, a log line or an exception text: the AMT password is resolved in-process by
``amt_vault`` and a credential-named field supplied by a caller is refused.

The sync functions (``power``, ``set_next_boot``, ...) are what tests drive; the ``amt_*``
coroutines are the registered surface and push the blocking work onto a thread under the same
per-device lock the screenshot/logon tools use. Errors raise (FastMCP turns them into
``isError``); no tool returns a success that carries an error field.

Every WS-MAN class/method here that is not marked "MeshCentral" or "proven" is the documented
AMT/CIM/IPS name and has NOT been exercised against the live host: tagged ``TODO verify-live``.
This module is not imported by any read tool (see ``amt_wsman_write``).
"""
from __future__ import annotations

import asyncio
import base64
import hashlib
import json
import os
import re
import stat
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import BaseModel, ConfigDict, Field, StrictBool

import amt_kvm
import amt_redir
import amt_registry
import amt_tools
import amt_upload
import amt_vault
import amt_wsman
import amt_wsman_write as ww
from amt_tools import (ConfirmationRequired, DEFAULT_DEVICE, DeviceParam, _require_confirmed,
                       _session_lock, typed)
from amt_wsman import WsmanError

__all__ = ["ConfirmationRequired", "WRITE_TOOL_SPECS"]

ConfirmedParam = Annotated[StrictBool, Field(
    description="Must be the JSON boolean true to proceed (the text \"true\" or the number 1 is "
                "rejected); false refuses and sends nothing. Set it only on the operator's explicit "
                "approval of this exact action.")]


def _pause(seconds: float) -> None:
    """Every wait in the console tool; tests replace this so none really sleeps."""
    time.sleep(seconds)


def _target(device: str) -> tuple[amt_registry.Device, str]:
    """The registered device and the AMT password, pin gate first (an unpinned device is
    refused before the vault is touched)."""
    dev = amt_registry.get_device(device)
    return dev, amt_wsman.resolve_password(dev, None)


def _wrap(step: str, completed: list[str], ex: Exception) -> WsmanError:
    """A sequence failure names the step and what already happened, never a value."""
    return WsmanError(f"{step}_failed:completed={','.join(completed) or 'none'}:{ex}")


# --- amt_power --------------------------------------------------------------------------

# name -> (CIM_PowerManagementService PowerState, plain description). States are the DMTF
# values; the table of 2/5/8/10 is MeshCentral's (amtmanager.js performPowerAction).
POWER_ACTIONS: dict[str, tuple[int, str]] = {
    "restart": (14, "restart the host through its OS (graceful, OS-aware)"),
    "shutdown": (12, "shut the host down through its OS (graceful soft-off)"),
    "power_cycle": (15, "power-cycle the host (graceful OS shutdown, then power on)"),
    "shutdown_hard_graceful": (13, "shut the host down gracefully to a hard-off state"),
    "power_cycle_hard_graceful": (16, "power-cycle the host (graceful, hard-off cycle)"),
    "power_on": (2, "power the host on"),
    "sleep_light": (3, "put the host into light sleep"),
    "sleep_deep": (4, "put the host into deep sleep"),
    "hibernate": (7, "hibernate the host"),
    "immediate_power_cycle": (5, "power-cycle the host immediately, without asking the OS"),
    "immediate_shutdown": (8, "power the host off immediately, without asking the OS"),
    "hard_power_off": (6, "cut the host's power (hard off)"),
    "hard_power_cycle": (9, "cut and restore the host's power (hard cycle)"),
    "hard_reset": (10, "hard-reset the host (master bus reset) without asking the OS"),
    "nmi": (11, "send a diagnostic interrupt (NMI) to the host"),
}
# Ungraceful: the OS is not asked, so unsaved data can be lost. None of these is a default.
UNGRACEFUL_STATES = frozenset({5, 6, 8, 9, 10, 11})
DEFAULT_POWER_ACTION = "restart"
PowerAction = Literal[tuple(POWER_ACTIONS)]
POWER_SERVICE = ("CIM_PowerManagementService", "RequestPowerStateChange")
# Parameter order and the ManagedElement reference follow MeshCentral's RequestPowerStateChange;
# TODO verify-live: the service is a singleton (no selector) and the reference uses the
# role/anonymous address the proven boot-role call uses.
MANAGED_SYSTEM = {"CreationClassName": "CIM_ComputerSystem", "Name": "ManagedSystem"}


def _power_spec(action: str) -> tuple[int, str]:
    if action not in POWER_ACTIONS:
        raise ValueError(f"unknown_power_action:{action!r}")
    return POWER_ACTIONS[action]


def _power_consequence(action: str) -> str:
    state, what = _power_spec(action)
    if state in UNGRACEFUL_STATES:
        return (f"will {what} (power state {state}) WITHOUT asking the host OS: unsaved work is "
                "lost and the filesystem can be left inconsistent")
    return f"asks the host to {what} (power state {state}); unsaved work is lost if the OS does not save it"


def offered_power_actions(available: Any) -> list[str] | None:
    """The power action names AMT offers now, from ``AvailableRequestedPowerStates`` (one value or
    a list); None when AMT reported no list."""
    if available is None:
        return None
    codes = {int(c) for c in (available if isinstance(available, list) else [available])}
    return [name for name, (state, _) in POWER_ACTIONS.items() if state in codes]


def power(action: str = DEFAULT_POWER_ACTION, device: str = DEFAULT_DEVICE,
          confirmed: bool = False) -> dict[str, Any]:
    state, what = _power_spec(action)
    _require_confirmed(confirmed, _power_consequence(action))
    dev, pw = _target(device)
    # AMT lists the states it will accept right now (live 2026-10-19: only hard reset and NMI at a
    # boot menu, eight states under Windows) and answers anything else with a bare ReturnValue 2.
    # Refuse by name before sending. If the list cannot be read, AMT still decides.
    try:
        available = amt_wsman.get("CIM_AssociatedPowerManagementService", device=device,
                                  password=pw).get("AvailableRequestedPowerStates")
    except WsmanError:
        available = None
    offered = offered_power_actions(available)
    if offered is not None and action not in offered:
        raise ValueError(f"power_state_not_available: AMT does not offer {action} now; it offers "
                         f"{', '.join(offered) or 'nothing'}. Nothing was sent. A boot menu or an OS "
                         f"without the AMT agent offers only the hard actions.")
    # An invoke-level fault/transport error means the request did not go: that raises, and a retry
    # is safe. Past this line the request is sent, so nothing below may raise (a retry would repeat it).
    out = ww.invoke(*POWER_SERVICE, {"PowerState": state,
                                     "ManagedElement": ww.epr("CIM_ComputerSystem", MANAGED_SYSTEM)},
                    device=device, password=pw, rv_required=False)
    rv = out.get("ReturnValue")
    result: dict[str, Any] = {
        "device": dev.key, "action": action, "applied": True if rv == "0" else "unknown",
        "requested_state": state, "power_state_requested": state, "graceful": state not in UNGRACEFUL_STATES,
        "return_value": typed(rv) if rv is not None else "unknown"}
    try:
        after = typed(amt_wsman.get("CIM_AssociatedPowerManagementService", device=device,
                                    password=pw)).get("PowerState")
    except WsmanError as ex:      # the reboot is already applied: a failed readback is not a failed tool
        result.update(readback="unavailable", readback_error=type(ex).__name__)
    else:
        result.update(readback="ok", power_state_after=amt_tools._label(amt_tools.POWER_STATES, after),
                      power_state_after_code=after)
    result["note"] = ("AMT applies the change asynchronously; power_state_after can still show the old state"
                      if rv is not None else
                      "the device replied without a ReturnValue: the request WAS sent and its outcome is "
                      "unknown; check the host before retrying (a retry can repeat the power action)")
    return result


# --- amt_set_next_boot ------------------------------------------------------------------

BOOT_CONFIG_ID = "Intel(r) AMT: Boot Configuration 0"        # proven live (prior art)
BOOT_TARGETS = ("bios_setup", "pxe", "hard_disk", "cd_ider", "floppy_ider", "diagnostic", "clear")
BootTarget = Literal[BOOT_TARGETS]
# The ONLY boot sources this tool can name; a caller string is never placed in a reference.
# "pxe" is MeshCentral's literal; the other three are the documented Intel names
# (TODO verify-live).
BOOT_SOURCES = {
    "pxe": "Intel(r) AMT: Force PXE Boot",
    "hard_disk": "Intel(r) AMT: Force Hard-drive Boot",
    "diagnostic": "Intel(r) AMT: Force Diagnostic Boot",
}
# IDE-R boots (cd_ider, floppy_ider) name NO boot source: the UseIDER / IDERBootDevice flags pick the
# redirected drive. "Force CD/DVD Boot" is a LOCAL optical drive; naming it for an IDE-R boot made
# SetBootConfigRole answer 5 (invalid parameter) live on my-server-1 2026-10-18. MeshCommander
# (default.htm powerActionResponse3x) likewise sends a null source for its IDE-R actions.
# Fields a Put must NEVER echo back: status/capability fields the device owns. The first twelve
# are the proven prior-art skip set; the last two are MeshCentral's extra drops. A secret-named
# field (RSEPassword) is dropped separately, because a Get redacts it to a literal marker.
BOOT_READ_ONLY = frozenset({
    "BIOSLastStatus", "BootguardStatus", "UEFIBootNumberOfParams", "UEFIBootParametersArray",
    "RPEEnabled", "SecureEraseEnabled", "WinREBootEnabled", "UEFILocalPBABootEnabled",
    "UEFIHTTPSBootEnabled", "PlatformErase", "SecureBootControlEnabled", "OptionsCleared",
    "UefiBootParametersArray", "RSEPassword",
})
BOOT_TARGET_FLAGS = {
    "bios_setup": {"BIOSSetup": True},
    "cd_ider": {"UseIDER": True, "IDERBootDevice": 1},        # TODO verify-live
    "floppy_ider": {"UseIDER": True, "IDERBootDevice": 0},    # TODO verify-live
}
# The 16 advanced options -> (AMT_BootSettingData field, kind). TODO verify-live: the field list
# is the documented AMT_BootSettingData writable set, not yet reconciled with MeshCommander's.
BOOT_OPTIONS: dict[str, tuple[str, str]] = {
    "lock_power_button": ("LockPowerButton", "bool"),
    "lock_reset_button": ("LockResetButton", "bool"),
    "lock_sleep_button": ("LockSleepButton", "bool"),
    "lock_keyboard": ("LockKeyboard", "bool"),
    "user_password_bypass": ("UserPasswordBypass", "bool"),
    "forced_progress_events": ("ForcedProgressEvents", "bool"),
    "firmware_verbosity": ("FirmwareVerbosity", "int:0-3"),
    "configuration_data_reset": ("ConfigurationDataReset", "bool"),
    "bios_pause": ("BIOSPause", "bool"),
    "reflash_bios": ("ReflashBIOS", "bool"),
    "use_safe_mode": ("UseSafeMode", "bool"),
    "use_sol": ("UseSOL", "bool"),
    "use_ider": ("UseIDER", "bool"),
    "secure_erase": ("SecureErase", "bool"),
    "enforce_secure_boot": ("EnforceSecureBoot", "bool"),
    "boot_media_index": ("BootMediaIndex", "int:0-255"),
}
# Options that erase or overwrite data, or take over the host's physical controls, at that boot.
DESTRUCTIVE_BOOT_OPTIONS = frozenset({"secure_erase", "reflash_bios", "configuration_data_reset",
                                      "lock_power_button", "lock_reset_button"})
BootOptionName = Literal[tuple(BOOT_OPTIONS)]
# The clean baseline EVERY Put starts from: each boot-option field (all 16 options, BIOSSetup and
# the IDE-R device) at its safe default (false / 0), so nothing a Get still shows from an earlier
# request (a secure erase, a button lock, a bypass) can ride along or be re-armed by a later call.
# Only this call's target flags and options are then applied over it.
BOOT_BASELINE: dict[str, Any] = {
    **{field: (False if kind == "bool" else 0) for field, kind in BOOT_OPTIONS.values()},
    "BIOSSetup": False, "IDERBootDevice": 0}


def _validate_boot_options(options: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for name, value in (options or {}).items():
        if name not in BOOT_OPTIONS:
            raise ValueError(f"unknown_boot_option:{name!r}")
        kind = BOOT_OPTIONS[name][1]
        if kind == "bool":
            if not isinstance(value, bool):
                raise ValueError(f"boot_option_needs_bool:{name}")
        else:
            lo, hi = (int(x) for x in kind[4:].split("-"))
            if isinstance(value, bool) or not isinstance(value, int) or not lo <= value <= hi:
                raise ValueError(f"boot_option_needs_int_{lo}_to_{hi}:{name}")
        out[name] = value
    return out


def _boot_consequence(target: str, options: dict[str, Any]) -> str:
    where = {"bios_setup": "enter BIOS setup", "pxe": "boot from the network (PXE)",
             "hard_disk": "boot from the hard drive", "cd_ider": "boot from the redirected CD/DVD",
             "floppy_ider": "boot from the redirected floppy", "diagnostic": "boot the diagnostic image",
             "clear": "have its one-time boot request cleared"}[target]
    text = f"makes the host's NEXT boot {where}; it does not restart the host by itself"
    risky = sorted(n for n in options if n in DESTRUCTIVE_BOOT_OPTIONS and options[n])
    if risky:
        text += (f" and also requests {', '.join(risky)}, which can erase or overwrite data, or lock the "
                 "host's power/reset buttons, at that boot")
    if target == "clear":
        text += "; every boot option is reset to its safe default (nothing stays armed)"
    return text


def _wire(value: Any) -> str:
    return ("true" if value else "false") if isinstance(value, bool) else str(value)


def boot_put_fields(current: dict[str, Any], target: str, options: dict[str, Any]) -> dict[str, str]:
    """The Put body: the device's CURRENT scalar fields minus every read-only/secret/nested one,
    with every boot-option field forced to ``BOOT_BASELINE`` and then ONLY this call's target flags
    and options applied. Never a full echo of the Get, and never a carry-over of an earlier request."""
    body: dict[str, str] = {}
    for name, value in current.items():
        if (name in BOOT_READ_ONLY or amt_wsman.is_secret_field(name, value)
                or not isinstance(value, str)):
            continue
        body[name] = value
    return {**body, **{k: _wire(v) for k, v in boot_desired(body, target, options).items()}}


def boot_desired(body: dict[str, str], target: str, options: dict[str, Any]) -> dict[str, Any]:
    """The values this request needs on the wire, for readback too: the baseline for every
    option field the device lists, then this call's target flags and options."""
    desired = {k: v for k, v in BOOT_BASELINE.items() if k in body}
    desired.update(BOOT_TARGET_FLAGS.get(target, {}))
    desired.update({BOOT_OPTIONS[n][0]: v for n, v in options.items()})
    return desired


def set_next_boot(target: str, options: dict[str, Any] | None = None, device: str = DEFAULT_DEVICE,
                  confirmed: bool = False) -> dict[str, Any]:
    if target not in BOOT_TARGETS:                      # the allowlist: nothing else is ever sent
        raise ValueError(f"boot_target_not_allowed:{target!r}")
    opts = _validate_boot_options(options)
    _require_confirmed(confirmed, _boot_consequence(target, opts))
    dev, pw = _target(device)
    cls = "AMT_BootSettingData"
    current = amt_wsman.get(cls, device=device, password=pw)
    body = boot_put_fields(current, target, opts)
    completed: list[str] = []
    source = BOOT_SOURCES.get(target)
    # MeshCommander's order (default.htm powerAction*): clear the boot order, Put the settings,
    # activate with SetBootConfigRole(1), THEN set the boot order (a source only for PXE / disk /
    # diagnostic; IDE-R and BIOS setup use the flags alone).
    try:
        ww.invoke("CIM_BootConfigSetting", "ChangeBootOrder", {},
                  selectors={"InstanceID": BOOT_CONFIG_ID}, device=device, password=pw)
        completed.append("clear_boot_order")
        ww.put(cls, body, device=device, password=pw)
        completed.append("put")
        # TODO verify-live: "clear" neutralises the pending request (the order is cleared and the
        # Put leaves every option safe) but sends NO SetBootConfigRole: the exact disarm call /
        # role value is not proven, and the arming Role=1 must never be sent for "clear".
        if target != "clear":    # the activation step; a bare Put is ignored.
            ww.invoke("CIM_BootService", "SetBootConfigRole",
                      {"BootConfigSetting": ww.epr("CIM_BootConfigSetting", {"InstanceID": BOOT_CONFIG_ID}),
                       "Role": 1}, device=device, password=pw)
            completed.append("set_boot_config_role")
            if source:
                ww.invoke("CIM_BootConfigSetting", "ChangeBootOrder",
                          {"Source": ww.epr("CIM_BootSourceSetting", {"InstanceID": source})},
                          selectors={"InstanceID": BOOT_CONFIG_ID}, device=device, password=pw)
                completed.append("change_boot_order")
    except WsmanError as ex:
        raise _wrap("boot_sequence", completed, ex) from None
    after = amt_wsman.get(cls, device=device, password=pw)
    wanted = {k: _wire(v) for k, v in boot_desired(body, target, opts).items()}
    bad = sorted(k for k, v in wanted.items() if str(after.get(k, "")).lower() != v.lower())
    if bad:
        raise WsmanError(f"boot_readback_mismatch:{','.join(bad)}:completed={','.join(completed)}")
    return {"device": dev.key, "target": target, "options": sorted(opts), "steps": completed,
            "readback": {k: typed(after.get(k), k) for k in wanted},
            "note": ("pending request neutralised: every boot option is at its safe default and no boot "
                     "source is set (the role is not changed)" if target == "clear" else
                     "one-time request; it applies at the host's next boot or power cycle")}


# --- amt_console_input ------------------------------------------------------------------

INPUT_PAUSE_SECONDS = 0.25      # AMT KVM drops input sent faster than it can inject
MAX_ACTIONS = 50
MAX_TEXT_CHARS = 500
MAX_WAIT_SECONDS = 10.0
MAX_TOTAL_WAIT_SECONDS = 30.0
EXTRA_KEYSYM = {                # X11 keysyms the engine's KEYSYM table lacks
    **{f"f{i}": 0xFFBD + i for i in range(1, 13)},
    "pageup": 0xFF55, "pagedown": 0xFF56, "insert": 0xFF63, "print": 0xFF61, "print_screen": 0xFF61,
    "capslock": 0xFFE5,
}
MODIFIERS = ("ctrl", "alt", "shift", "win")
# (modifiers, key); ctrl_alt_del is special-cased to the engine's CAD (a firmware-injected HID).
KEY_MACROS: dict[str, tuple[tuple[str, ...], str]] = {
    "ctrl_alt_del": (("ctrl", "alt"), "delete"),
    "alt_tab": (("alt",), "tab"), "alt_f4": (("alt",), "f4"), "alt_esc": (("alt",), "escape"),
    "alt_enter": (("alt",), "enter"), "alt_space": (("alt",), "space"),
    "ctrl_esc": (("ctrl",), "escape"), "ctrl_shift_esc": (("ctrl", "shift"), "escape"),
    "ctrl_a": (("ctrl",), "a"), "ctrl_c": (("ctrl",), "c"), "ctrl_v": (("ctrl",), "v"),
    "ctrl_x": (("ctrl",), "x"), "ctrl_z": (("ctrl",), "z"),
    "win": ((), "win"), "win_r": (("win",), "r"), "win_d": (("win",), "d"), "win_e": (("win",), "e"),
    "win_l": (("win",), "l"), "win_x": (("win",), "x"), "win_tab": (("win",), "tab"),
    "print_screen": ((), "print_screen"), "f2": ((), "f2"), "f10": ((), "f10"), "f12": ((), "f12"),
    "delete": ((), "delete"),
}
MacroName = Literal[tuple(KEY_MACROS)]


class ConsoleAction(BaseModel):
    """One ordered console step. Set only the fields its ``kind`` uses."""
    model_config = ConfigDict(extra="forbid")
    kind: Literal["click", "text", "key", "macro", "wait", "secret"] = Field(
        description="Step type: click (mouse), text (printable ASCII), key (one key, optionally "
                    "with modifiers), macro (a named key combination), wait (pause) or secret (type "
                    "the device's vaulted host account name or password, read in-process).")
    x: float | None = Field(None, ge=0, le=1, description="click: horizontal position as a ratio of "
                                                          "the console width (0 left edge, 1 right edge).")
    y: float | None = Field(None, ge=0, le=1, description="click: vertical position as a ratio of the "
                                                          "console height (0 top, 1 bottom).")
    button: Literal["left", "middle", "right"] = Field("left", description="click: mouse button.")
    text: str | None = Field(None, description="text: printable ASCII to type (max 500 characters). NEVER "
                                               "type a password or other credential here; use a secret step.")
    key: str | None = Field(None, description="key: an engine key name (enter, tab, escape, delete, "
                                              "backspace, space, home, end, up, down, left, right, f1-f12, "
                                              "pageup, pagedown, insert, print_screen) or one character.")
    modifiers: list[Literal["ctrl", "alt", "shift", "win"]] | None = Field(
        None, description="key: modifier keys held while the key is tapped, then released.")
    macro: MacroName | None = Field(None, description="macro: the named key combination to send; "
                                                     "ctrl_alt_del uses the firmware Ctrl-Alt-Del.")
    seconds: float | None = Field(None, gt=0, le=MAX_WAIT_SECONDS,
                                  description="wait: seconds to pause (max 10).")
    secret: Literal["host_user", "host_password"] | None = Field(
        None, description="secret: which field of the device's vaulted host credential to type. "
                          "The value is read from the vault in-process and never returned or logged.")


def _keysym(name: str) -> int:
    low = name.lower()
    ks = amt_kvm.KEYSYM.get(low) or EXTRA_KEYSYM.get(low)
    if ks is None:
        raise ValueError(f"unknown_key:{name!r}")
    return ks


def _compile_actions(actions: list[Any]) -> list[tuple]:
    """Validate every step before any session opens: a malformed list sends nothing."""
    if not actions:
        raise ValueError("console_input_needs_actions")
    if len(actions) > MAX_ACTIONS:
        raise ValueError(f"too_many_actions:max {MAX_ACTIONS}")
    steps: list[tuple] = []
    waited = 0.0
    for i, raw in enumerate(actions):
        a = raw if isinstance(raw, ConsoleAction) else ConsoleAction.model_validate(raw)
        if a.kind == "click":
            if a.x is None or a.y is None:
                raise ValueError(f"action_{i}_click_needs_x_and_y")
            steps.append(("click", a.x, a.y, a.button))
        elif a.kind == "text":
            if not a.text or len(a.text) > MAX_TEXT_CHARS or not all(0x20 <= ord(c) <= 0x7E for c in a.text):
                raise ValueError(f"action_{i}_text_must_be_1_to_{MAX_TEXT_CHARS}_printable_ascii_chars")
            steps.append(("text", a.text))
        elif a.kind == "key":
            if not a.key:
                raise ValueError(f"action_{i}_key_needs_key")
            mods = tuple(a.modifiers or ())
            if len(a.key) == 1:
                if not 0x20 <= ord(a.key) <= 0x7E:
                    raise ValueError(f"action_{i}_key_not_printable_ascii")
                steps.append(("key_char", mods, a.key))
            else:
                steps.append(("key", mods, _keysym(a.key)))
        elif a.kind == "macro":
            if a.macro is None:
                raise ValueError(f"action_{i}_macro_needs_macro")
            steps.append(("cad",) if a.macro == "ctrl_alt_del" else ("macro", a.macro))
        elif a.kind == "secret":
            if a.secret is None:
                raise ValueError(f"action_{i}_secret_needs_secret")
            steps.append(("secret", a.secret))
        else:
            if a.seconds is None:
                raise ValueError(f"action_{i}_wait_needs_seconds")
            waited += a.seconds
            if waited > MAX_TOTAL_WAIT_SECONDS:
                raise ValueError(f"total_wait_over_{MAX_TOTAL_WAIT_SECONDS:g}_seconds")
            steps.append(("wait", a.seconds))
    return steps


# The labels ``expect`` may name: everything ``classify_screen`` can say except ``unknown``, which
# asserts nothing (a guard that admits it would admit every unidentified frame).
EXPECT_LABELS = tuple(l for l in amt_tools.SCREEN_LABELS if l != amt_tools.LABEL_UNKNOWN)
ExpectLabel = Literal[EXPECT_LABELS]


def _compile_expect(expect: list[Any] | None, steps: list[tuple]) -> tuple[str, ...] | None:
    """The validated ``expect`` allow-list, or None (the unguarded behaviour). Checked before any
    session opens: an unknown label or an empty list is a malformed request, and a ``secret``
    step beside a boot or firmware label is refused outright, because no credential is ever typed
    into GRUB, a BIOS setup, an installer or the MOK manager: the vaulted host credential belongs
    to the OS login, and on these screens typed text is a menu key or an edit, not a login."""
    if expect is None:
        return None
    if isinstance(expect, (str, bytes)) or not isinstance(expect, (list, tuple)) or not expect:
        raise ValueError("expect_needs_a_non_empty_list_of_screen_labels")
    bad = [x for x in expect if x not in EXPECT_LABELS]
    if bad:
        raise ValueError(f"expect_unknown_label:{','.join(map(str, bad))}:allowed={','.join(EXPECT_LABELS)}")
    allowed = tuple(dict.fromkeys(expect))
    boot = sorted(set(allowed) & amt_tools.BOOT_FIRMWARE_LABELS)
    if boot and any(s[0] == "secret" for s in steps):
        raise ValueError(f"secret_step_refused_for_boot_screen:{','.join(boot)}")
    return allowed


def _require_expected_screen(session, width: int, height: int, allowed: tuple[str, ...], user: str) -> str:
    """Classify the FIRST frame and return its label, or raise with nothing yet sent: the frame
    could not be read (``screen_not_identified``) or its label is not in ``allowed``
    (``screen_not_expected``, naming the label seen). The error carries labels only, never text."""
    cls = amt_tools.classify_screen((amt_tools._snapshot(session), width, height), user)
    label, problem = cls["label"], cls["markers"].get("ocr_problem")
    if problem:      # a sub-Windows frame keeps its geometry label without OCR: that proves nothing
        raise amt_kvm.AmtError(f"screen_not_identified:{problem}:expected={','.join(allowed)}")
    if label not in allowed:
        raise amt_kvm.AmtError(f"screen_not_expected:saw={label}:expected={','.join(allowed)}")
    return label


def _chord(session, modifiers: tuple[str, ...], tap) -> None:
    """Hold ``modifiers``, run ``tap()``, release in reverse in a ``finally`` so a failure
    never leaves a modifier stuck down on the host."""
    held = []
    try:
        for name in modifiers:
            ks = _keysym(name)
            session._key(ks, True)
            held.append(ks)
        tap()
    finally:
        for ks in reversed(held):
            session._key(ks, False)


def _run_step(session, step: tuple, width: int, height: int, credential: tuple[str, str] | None = None) -> None:
    kind = step[0]
    if kind == "secret":
        user, password = credential
        session.type_text(user if step[1] == "host_user" else password)
    elif kind == "click":
        session.click(*amt_tools._at(width, height, (step[1], step[2])), step[3])
    elif kind == "text":
        session.type_text(step[1])
    elif kind == "key":
        _chord(session, step[1], lambda: session.tap(step[2]))
    elif kind == "key_char":
        if step[1]:
            _chord(session, step[1], lambda: session.tap(ord(step[2].lower())))
        else:
            session.type_char(step[2])
    elif kind == "macro":
        mods, key = KEY_MACROS[step[1]]
        _chord(session, mods, lambda: session.tap(_keysym(key) if len(key) > 1 else ord(key)))
    elif kind == "cad":
        session.cad()
    else:
        _pause(step[1])


def console_input(actions: list[Any], device: str = DEFAULT_DEVICE, confirmed: bool = False,
                  expect: list[Any] | None = None) -> dict[str, Any]:
    steps = _compile_actions(actions)
    allowed = _compile_expect(expect, steps)
    _require_confirmed(confirmed, f"sends {len(steps)} mouse/keyboard step(s) to the host's console, "
                                  "which act on whatever is on screen")
    dev = amt_registry.get_device(device)
    amt_wsman.require_pin(dev)            # unpinned: refuse before the vault, the disk or the wire
    # Resolved before any session opens, so a missing or malformed entry sends nothing.
    credential = amt_tools._host_credential(dev) if any(s[0] == "secret" for s in steps) else None
    # The sign-in tile is matched against the vaulted account, so only a windows-signin
    # expectation needs the user name (the password half is dropped at once).
    tile_user = ""
    if allowed and amt_tools.LABEL_SIGNIN in allowed:
        tile_user = (credential or amt_tools._host_credential(dev))[0]
    out_dir = amt_tools._private_shot_dir()
    session = amt_tools._kvm_session(dev, amt_vault.get_secret(dev.amt_vault_key))
    try:  # AMT allows ONE redirection session: always close, success or not.
        session.open()
        width, height = session.grab_stable()[:2]
        seen = _require_expected_screen(session, width, height, allowed, tile_user) if allowed else None
        for i, step in enumerate(steps):
            try:
                _run_step(session, step, width, height, credential)
            except amt_kvm.AmtError:
                # The engine names the offending character; typed text is not echoed anywhere.
                raise amt_kvm.AmtError(f"console_input_failed:step_{i}:{step[0]}") from None
            _pause(INPUT_PAUSE_SECONDS)
        return {"device": dev.key, "steps_run": len(steps), "kinds": [{"key_char": "key", "cad": "macro"}.get(s[0], s[0]) for s in steps],
                **({"screen_label": seen} if seen else {}),
                "screenshot": amt_tools._result_frame(session, dev, out_dir)}
    finally:
        session.close()


# --- amt_sol ----------------------------------------------------------------------------

MAX_SOL_SEND = 1024
MAX_SOL_READ_SECONDS = 15.0
MAX_SOL_READ_BYTES = 16384


def sol(text: str = "", read_seconds: float = 3.0, max_bytes: int = 4096,
        device: str = DEFAULT_DEVICE, confirmed: bool = False) -> dict[str, Any]:
    if len(text) > MAX_SOL_SEND or not all(ord(c) < 0x80 for c in text):
        raise ValueError(f"sol_text_must_be_ascii_up_to_{MAX_SOL_SEND}_chars")
    if not 0 < read_seconds <= MAX_SOL_READ_SECONDS or not 1 <= max_bytes <= MAX_SOL_READ_BYTES:
        raise ValueError("invalid_sol_read_window")
    _require_confirmed(confirmed, "opens the host's single Serial-over-LAN session, sends the text to its "
                                  "serial console and reads back for a short window; it blocks KVM and "
                                  "IDE-R while open")
    dev = amt_registry.get_device(device)
    import amt_serial   # imported here: amt_serial's terminal is optional and imports this module's peers
    term = amt_serial.shared_terminal(dev.key)
    if term is not None:   # the live terminal owns the session: the operator watches this exchange
        term.in_flight.begin()
        try:
            start = term.total
            if text:
                term.send(text.encode("ascii"))
            data, truncated, error = term.collect(start, read_seconds, max_bytes)
        finally:
            term.in_flight.end()
        return {"device": dev.key, "sent_chars": len(text), "window_seconds": read_seconds,
                "bytes": len(data), "truncated": truncated, "shared_terminal": True,
                **({"error": error} if error else {}), "output": data.decode("utf-8", errors="replace")}
    amt_wsman.require_pin(dev)
    session = amt_redir.pinned(amt_redir.SolSession, dev, amt_vault.get_secret(dev.amt_vault_key))
    try:
        session.open_session()
        if text:
            session.send_text(text.encode("ascii"))
        data, truncated = session.read_window(read_seconds, max_bytes)
    finally:
        session.close()
    return {"device": dev.key, "sent_chars": len(text), "window_seconds": read_seconds,
            "bytes": len(data), "truncated": truncated, "output": data.decode("utf-8", errors="replace")}


# --- amt_ider ---------------------------------------------------------------------------

IMAGE_ROOT_ENV = "AMT_IMAGE_ROOT"
IMAGE_EXTENSIONS = {"iso": ".iso", "floppy": ".img"}
IderStart = Literal["next_boot", "graceful", "now"]
IDER_UNMOUNT_JOIN_SECONDS = 10.0   # how long unmount waits for the serving thread before reporting it still held


class _Mount:
    """One live IDE-R mount: the session, the thread serving the SCSI channel and its images."""

    def __init__(self, session, images: dict[str, str], media: list):
        self.session, self.images, self.media = session, images, media
        self.stop = threading.Event()
        self.error: str | None = None
        self.thread: threading.Thread | None = None

    def alive(self) -> bool:
        return self.thread is not None and self.thread.is_alive()

    def run(self) -> None:
        try:
            self.session.serve(self.stop)
        except Exception as ex:   # noqa: BLE001 - recorded, reported by status; nothing secret in it
            self.error = str(ex) if isinstance(ex, amt_kvm.AmtError) else type(ex).__name__
        finally:
            self.session.close()
            for m in self.media:
                try:
                    os.close(m.fd)
                except OSError:
                    pass


_MOUNTS: dict[str, _Mount] = {}
_MOUNTS_LOCK = threading.Lock()


STATE_DIR_ENV = "AMT_STATE_DIR"     # where the server keeps settings set by tools; default ~/.amt-mcp
FETCH_CHUNK = 1 << 20


def _settings_path() -> Path:
    return Path(os.environ.get(STATE_DIR_ENV) or Path.home() / ".amt-mcp") / "settings.json"


def _load_settings() -> dict[str, Any]:
    path = _settings_path()
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return {}
    except (OSError, ValueError) as ex:   # a corrupt file is reported, never silently ignored
        raise ValueError(f"amt_settings_file_unreadable:{path}:{type(ex).__name__}") from None


def _save_settings(settings: dict[str, Any]) -> None:
    path = _settings_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(settings, indent=2) + "\n")
    os.replace(tmp, path)


def _image_root_setting() -> tuple[str | None, str | None]:
    """(raw root, source): a root set with amt_ider set_root wins over the AMT_IMAGE_ROOT env."""
    tool_root = _load_settings().get("image_root")
    if tool_root:
        return tool_root, "tool"
    env_root = os.environ.get(IMAGE_ROOT_ENV)
    return (env_root, "env") if env_root else (None, None)


def _image_root() -> Path:
    raw, _ = _image_root_setting()
    if not raw:
        raise ValueError("ider_image_root_unset: set it with amt_images action=set_root "
                         f"(or the {IMAGE_ROOT_ENV} env)")
    root = Path(raw).resolve()
    if not root.is_dir():
        raise ValueError("ider_image_root_not_a_directory")
    return root


def ider_set_root(root: str) -> dict[str, Any]:
    """Point the image root at ``root`` (created if missing) and persist it across restarts."""
    if not root or not root.strip():
        raise ValueError("ider_set_root_needs_root")
    new = Path(root).expanduser().resolve()
    new.mkdir(parents=True, exist_ok=True)
    previous, source = _image_root_setting()
    settings = _load_settings()
    settings["image_root"] = str(new)
    _save_settings(settings)
    return {"image_root": str(new), "previous": previous, "previous_source": source,
            "persisted_to": str(_settings_path())}


class _Fetch:
    """One background download into the image root."""

    def __init__(self, url: str, dest: Path, sha256: str | None):
        self.url, self.dest, self.want = url, dest, (sha256 or "").lower() or None
        self.part = dest.with_name(dest.name + ".part")
        self.state, self.error, self.got, self.total, self.sha = "running", None, 0, None, None
        self.thread: threading.Thread | None = None

    def snapshot(self) -> dict[str, Any]:
        return {"name": self.dest.name, "url": self.url, "state": self.state, "bytes": self.got,
                "total_bytes": self.total, "sha256": self.sha, "sha256_expected": self.want,
                "error": self.error}

    def run(self) -> None:
        h = hashlib.sha256()
        try:
            with urllib.request.urlopen(self.url, timeout=60) as resp, open(self.part, "wb") as out:
                length = resp.headers.get("Content-Length")
                self.total = int(length) if length and length.isdigit() else None
                while chunk := resp.read(FETCH_CHUNK):
                    out.write(chunk)
                    h.update(chunk)
                    self.got += len(chunk)
            self.sha = h.hexdigest()
            if self.want and self.sha != self.want:
                raise ValueError(f"sha256_mismatch:got {self.sha}")
            os.replace(self.part, self.dest)
            self.state = "done"
        except Exception as ex:   # noqa: BLE001 - recorded and reported by list
            self.state, self.error = "failed", f"{type(ex).__name__}:{ex}"
            self.part.unlink(missing_ok=True)


_FETCHES: dict[str, _Fetch] = {}
_FETCHES_LOCK = threading.Lock()


def ider_fetch(url: str, name: str | None = None, sha256: str | None = None,
               overwrite: bool = False) -> dict[str, Any]:
    """Start downloading ``url`` into the image root in the background; poll with ider_list."""
    if not url or urllib.parse.urlsplit(url).scheme not in ("http", "https"):
        raise ValueError("ider_fetch_needs_an_http_or_https_url")
    name = _image_name(name or Path(urllib.parse.urlsplit(url).path).name, "fetch")
    if sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise ValueError("ider_fetch_sha256_must_be_64_hex_chars")
    dest = _image_root() / name
    if dest.exists() and overwrite:
        _refuse_if_busy(dest, "fetch")    # before _FETCHES_LOCK: _busy_reason takes it too
    with _FETCHES_LOCK:
        running = _FETCHES.get(name)
        if running is not None and running.state == "running":
            raise ValueError(f"ider_fetch_already_running:{name}")
        if dest.exists() and not overwrite:
            raise ValueError(f"ider_fetch_exists:{name}: pass overwrite=true to replace it")
        job = _Fetch(url, dest, sha256)
        job.thread = threading.Thread(target=job.run, name=f"amt-fetch-{name}", daemon=True)
        _FETCHES[name] = job
    job.thread.start()
    return {**job.snapshot(), "note": "downloading in the background; poll with amt_images action=list"}


def ider_list() -> dict[str, Any]:
    """The image root, every .iso/.img under it, and every download this server started."""
    with _FETCHES_LOCK:
        fetches = [f.snapshot() for f in _FETCHES.values()]
    raw, source = _image_root_setting()
    try:
        root = _image_root()
    except ValueError as ex:
        return {"image_root": raw, "source": source, "error": str(ex), "images": [], "fetches": fetches,
                "uploads": amt_upload.snapshot()}
    images = []
    for p in sorted(root.rglob("*")):
        if p.suffix.lower() in (".iso", ".img") and p.is_file():
            size = p.stat().st_size
            images.append({"path": str(p.relative_to(root)), "bytes": size,
                           "mib": round(size / (1 << 20), 1), "mountable": size > 0 and size % 512 == 0})
    return {"image_root": str(root), "source": source, "images": images, "fetches": fetches,
            "uploads": amt_upload.snapshot()}


def _image_name(name: str | None, action: str) -> str:
    """A plain .iso or .img file name: no directory part, no leading dot."""
    if not name or "/" in name or "\\" in name or name.startswith(".") or \
            Path(name).suffix.lower() not in (".iso", ".img"):
        raise ValueError(f"ider_{action}_name_must_be_a_plain_.iso_or_.img_file_name")
    return name


def _library_file(path: str | None, action: str) -> tuple[Path, Path]:
    """(image root, the image) for a path as list reports it: inside the root, no symlink, a
    regular .iso or .img file."""
    if not path:
        raise ValueError(f"ider_{action}_needs_path")
    root = _image_root()
    rel = Path(path)
    if rel.is_absolute() or ".." in rel.parts:
        raise ValueError("ider_image_path_must_be_relative_to_the_image_root")
    target = root / rel
    try:
        st = os.lstat(target)
    except FileNotFoundError:
        raise ValueError(f"ider_image_not_found:{path}") from None
    if not stat.S_ISREG(st.st_mode) or target.suffix.lower() not in (".iso", ".img") or \
            not target.parent.resolve().is_relative_to(root):
        raise ValueError(f"ider_image_not_a_regular_.iso_or_.img_under_the_root:{path}")
    return root, target


def _busy_reason(target: Path) -> str | None:
    """Why ``target`` must not change now: mounted on a host, being downloaded, or being uploaded."""
    try:
        st = os.stat(target)
    except FileNotFoundError:
        st = None
    with _MOUNTS_LOCK:
        mounts = [(k, m) for k, m in _MOUNTS.items() if m.alive()]
    for key, mount in mounts:
        for media in mount.media:
            try:
                held = os.fstat(media.fd)
            except OSError:
                continue
            if st is not None and (held.st_dev, held.st_ino) == (st.st_dev, st.st_ino):
                return f"mounted_on:{key}"
    with _FETCHES_LOCK:
        if any(f.dest == target and f.state == "running" for f in _FETCHES.values()):
            return "being_downloaded"
    if amt_upload.pending_for(target):
        return "being_uploaded"
    return None


def _refuse_if_busy(target: Path, action: str) -> None:
    reason = _busy_reason(target)
    if reason:
        raise ValueError(f"ider_{action}_image_busy:{target.name}:{reason}")


def ider_delete(path: str | None) -> dict[str, Any]:
    """Delete one image from the root; refused while it is mounted, downloading or uploading."""
    root, target = _library_file(path, "delete")
    _refuse_if_busy(target, "delete")
    size = target.stat().st_size
    target.unlink()
    return {"deleted": str(target.relative_to(root)), "bytes": size}


def ider_rename(path: str | None, new_name: str | None) -> dict[str, Any]:
    """Rename one image within its folder; never replaces an existing file."""
    root, target = _library_file(path, "rename")
    dest = target.with_name(_image_name(new_name, "rename"))
    _refuse_if_busy(target, "rename")
    _refuse_if_busy(dest, "rename")       # a download or upload is about to land on that name
    try:
        os.link(target, dest)          # fails if dest exists: a rename never clobbers
    except FileExistsError:
        raise ValueError(f"ider_rename_target_exists:{dest.name}") from None
    target.unlink()
    return {"renamed": str(target.relative_to(root)), "to": str(dest.relative_to(root))}


def ider_verify(path: str | None, sha256: str | None = None) -> dict[str, Any]:
    """SHA-256 of one image, compared with ``sha256`` when given. Reads only."""
    if sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise ValueError("ider_verify_sha256_must_be_64_hex_chars")
    root, target = _library_file(path, "verify")
    h = hashlib.sha256()
    with open(target, "rb") as fh:
        while chunk := fh.read(FETCH_CHUNK):
            h.update(chunk)
    size = target.stat().st_size
    got = h.hexdigest()
    return {"path": str(target.relative_to(root)), "bytes": size, "sha256": got,
            "sha256_expected": sha256.lower() if sha256 else None,
            "matches": (got == sha256.lower()) if sha256 else None,
            "mountable": size > 0 and size % 512 == 0}


def ider_upload(name: str | None, size_bytes: int | None, sha256: str | None = None,
                overwrite: bool = False) -> dict[str, Any]:
    """Mint a single-use upload url for one image; the bytes arrive over HTTP, never in MCP."""
    name = _image_name(name, "upload")
    if sha256 and not re.fullmatch(r"[0-9a-fA-F]{64}", sha256):
        raise ValueError("ider_upload_sha256_must_be_64_hex_chars")
    if not size_bytes or size_bytes <= 0:
        raise ValueError("ider_upload_needs_size_bytes")
    root = _image_root()
    dest = root / name
    if dest.exists() and not overwrite:
        raise ValueError(f"ider_upload_exists:{name}: pass overwrite=true to replace it")
    _refuse_if_busy(dest, "upload")
    return amt_upload.offer(dest, size_bytes, sha256.lower() if sha256 else None,
                            check=lambda: _busy_reason(dest))


def _open_image(path: str, kind: str, root: Path) -> amt_redir.Media:
    """Open one image read-only. It must resolve inside the image root, have the right
    extension and be a non-empty regular file whose size is a multiple of 512."""
    p = Path(path)
    if ".." in p.parts:
        raise ValueError("ider_image_path_traversal")
    real = (p if p.is_absolute() else root / p)
    try:
        real = real.resolve(strict=True)
    except (OSError, RuntimeError):
        raise ValueError(f"ider_image_not_found:{p.name}") from None
    if not real.is_relative_to(root):
        raise ValueError("ider_image_outside_image_root")
    if real.suffix.lower() != IMAGE_EXTENSIONS[kind]:
        raise ValueError(f"ider_{kind}_image_needs_extension_{IMAGE_EXTENSIONS[kind]}")
    fd = os.open(real, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    st = os.fstat(fd)
    if not stat.S_ISREG(st.st_mode) or st.st_size == 0 or st.st_size % 512:
        os.close(fd)
        raise ValueError(f"ider_image_not_a_512_aligned_regular_file:{real.name}")
    return amt_redir.Media(st.st_size, fd)


def _ider_consequence(action: str, iso_path: str | None, floppy_path: str | None, start: str) -> str:
    names = ", ".join(Path(p).name for p in (iso_path, floppy_path) if p)
    if action == "mount":
        reset = ("; start='graceful'/'now' RESETS the host immediately" if start != "next_boot" else "")
        return (f"attaches {names} to the host as read-only IDE-R drive(s) ({start}) and holds the host's "
                "IDE-R session (no time limit; KVM keeps working alongside it) until "
                f"unmounted; the host can boot from it{reset}")
    return "detaches the mounted IDE-R image(s) from the host and ends the redirection session"


def ider(action: str, iso_path: str | None = None, floppy_path: str | None = None,
         start: str = "next_boot", device: str = DEFAULT_DEVICE, confirmed: bool = False) -> dict[str, Any]:
    if action not in ("mount", "unmount", "status"):
        raise ValueError(f"unknown_ider_action:{action!r}")
    if action == "status":
        return _ider_status(device)
    if start not in amt_redir.START_MODES:
        raise ValueError(f"unknown_ider_start:{start!r}")
    if action == "mount" and not (iso_path or floppy_path):
        raise ValueError("ider_mount_needs_an_image")
    _require_confirmed(confirmed, _ider_consequence(action, iso_path, floppy_path, start))
    return _ider_mount(iso_path, floppy_path, start, device) if action == "mount" else _ider_unmount(device)


def _ider_mount(iso_path: str | None, floppy_path: str | None, start: str, device: str) -> dict[str, Any]:
    dev = amt_registry.get_device(device)
    amt_wsman.require_pin(dev)
    with _MOUNTS_LOCK:
        existing = _MOUNTS.get(dev.key)
        if existing is not None and existing.alive():
            raise ValueError("ider_already_mounted: unmount first (AMT permits one redirection session)")
    root = _image_root()
    media: list = []
    images: dict[str, str] = {}
    try:
        cdrom = floppy = None
        if iso_path:
            cdrom = _open_image(iso_path, "iso", root)
            media.append(cdrom)
            images["iso"] = Path(iso_path).name
        if floppy_path:
            floppy = _open_image(floppy_path, "floppy", root)
            media.append(floppy)
            images["floppy"] = Path(floppy_path).name
        session = amt_redir.pinned(amt_redir.IderSession, dev, amt_vault.get_secret(dev.amt_vault_key))
        session.cdrom, session.floppy, session.start_mode = cdrom, floppy, start
        try:
            session.open_session()
        except Exception:
            session.close()
            raise
    except Exception:
        for m in media:
            os.close(m.fd)
        raise
    mount = _Mount(session, images, media)
    mount.thread = threading.Thread(target=mount.run, name=f"amt-ider-{dev.key}", daemon=True)
    with _MOUNTS_LOCK:
        _MOUNTS[dev.key] = mount
    mount.thread.start()
    return {"device": dev.key, "mounted": True, "images": images, "start": start,
            "note": "the host's redirection session is held until amt_ider unmount"}


def _ider_unmount(device: str) -> dict[str, Any]:
    dev = amt_registry.get_device(device)
    with _MOUNTS_LOCK:
        mount = _MOUNTS.get(dev.key)       # stays registered until its thread has really stopped
    if mount is None:
        raise ValueError("ider_not_mounted")
    mount.stop.set()
    if mount.thread is not None:
        mount.thread.join(timeout=IDER_UNMOUNT_JOIN_SECONDS)
    if mount.alive():
        raise amt_kvm.AmtError("ider_unmount_timeout: the serving thread did not stop; the IDE-R session "
                               "is STILL HELD (not unmounted). Call unmount again, or check amt_ider status")
    with _MOUNTS_LOCK:
        if _MOUNTS.get(dev.key) is mount:
            del _MOUNTS[dev.key]
    return {"device": dev.key, "mounted": False, "images": mount.images,
            "bytes_to_host": mount.session.bytes_to_amt, "ended_with_error": mount.error}


def _ider_status(device: str) -> dict[str, Any]:
    dev = amt_registry.get_device(device)
    with _MOUNTS_LOCK:
        mount = _MOUNTS.get(dev.key)
    if mount is None:
        return {"device": dev.key, "mounted": False}
    return {"device": dev.key, "mounted": mount.alive(), "images": mount.images,
            "bytes_to_host": mount.session.bytes_to_amt, "error": mount.error}


# --- amt_configure ----------------------------------------------------------------------

ConfigureArea = Literal["network", "internet", "security", "users", "kvm", "features"]
# Areas MeshCommander shows that this tool does not write yet; amt_settings reads them and
# amt_wsman_invoke can write them.
UNSUPPORTED_AREAS = ("agent_presence", "system_defense", "subscriptions", "wake_alarms")
IDENTITY_FIELDS = ("ElementName", "InstanceID")


class _PutArea:
    def __init__(self, cls: str, fields: dict[str, str], selectors: dict[str, str] | None = None,
                 rfb: bool = False, read_only: frozenset[str] = frozenset()):
        self.cls, self.fields, self.selectors, self.rfb = cls, fields, selectors, rfb
        self.read_only = read_only      # device-owned fields a Put must not echo


# TODO verify-live: every class, selector and field below except IPS_KVMRedirectionSettingData
# (its Put, including the vaulted RFB password, is the proven prior-art call). Only listed
# fields can be CHANGED, and none can lock the host out of AMT (no network-interface,
# TLS-enable, mutual-auth or address field is listed). A Put can whole-replace the instance, so
# every other writable field is echoed back unchanged (full-instance Get-merge-Put) and the whole
# instance is read back: a field the device reset anyway is reported, not hidden. TODO verify-live:
# the per-area ``read_only`` sets (device-owned fields dropped from the Put) are a best guess.
PUT_AREAS: dict[str, _PutArea] = {
    "network": _PutArea("AMT_GeneralSettings", {
        "HostName": "str", "DomainName": "str", "SharedFQDN": "bool", "PingResponseEnabled": "bool",
        "RmcpPingResponseEnabled": "bool", "DDNSUpdateEnabled": "bool",
        "DDNSPeriodicUpdateInterval": "int", "DDNSTTL": "int", "IdleWakeTimeout": "int"},
        read_only=frozenset({"DigestRealm"})),
    "internet": _PutArea("AMT_EnvironmentDetectionSettingData", {
        "DetectionAlgorithm": "int", "DetectionStrings": "strlist"}),
    "security": _PutArea("AMT_TLSSettingData", {"AcceptNonSecureConnections": "bool"},
                         {"InstanceID": "Intel(r) AMT 802.3 TLS Settings"}),
    "kvm": _PutArea("IPS_KVMRedirectionSettingData", {
        "Is5900PortEnabled": "bool", "OptInPolicy": "bool", "SessionTimeout": "int"}, rfb=True,
        read_only=frozenset({"EnabledByMEBx"})),
}
FEATURE_FIELDS = {"ider_enabled": "bool", "sol_enabled": "bool", "kvm_enabled": "bool"}
USER_FIELDS = ("action", "username", "access_permission", "realms")
USER_NAME = re.compile(r"[A-Za-z0-9_.@-]{1,16}")


def _check_value(area: str, name: str, kind: str, value: Any) -> Any:
    ok = ((kind == "bool" and isinstance(value, bool))
          or (kind == "int" and isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 2**32)
          or (kind == "str" and isinstance(value, str) and 0 < len(value) <= 256 and value.isprintable())
          or (kind == "strlist" and isinstance(value, list) and 0 < len(value) <= 16
              and all(isinstance(v, str) and 0 < len(v) <= 256 and v.isprintable() for v in value)))
    if not ok:
        raise ValueError(f"invalid_value:{area}.{name}:needs {kind}")
    return value


def _validate_changes(area: str, schema: dict[str, str], changes: dict[str, Any]) -> dict[str, Any]:
    unknown = sorted(set(changes) - set(schema))
    if unknown:
        raise ValueError(f"unknown_field:{area}:{','.join(unknown)}; writable: {','.join(schema)}")
    return {n: _check_value(area, n, schema[n], v) for n, v in changes.items()}


def _validate_users(changes: dict[str, Any]) -> dict[str, Any]:
    if set(changes) - set(USER_FIELDS) or changes.get("action") not in ("add", "remove"):
        raise ValueError("users_changes_need: action ('add' or 'remove'), username, and for add "
                         "access_permission (0-2) and realms (list of realm numbers 0-31)")
    name = changes.get("username")
    if not isinstance(name, str) or not USER_NAME.fullmatch(name) or name.lower() == "admin":
        raise ValueError("users_username_invalid_or_admin: the admin account is never changed here")
    if changes["action"] == "add":
        access, realms = changes.get("access_permission"), changes.get("realms")
        if (isinstance(access, bool) or not isinstance(access, int) or not 0 <= access <= 2
                or not isinstance(realms, list) or not realms
                or any(isinstance(r, bool) or not isinstance(r, int) or not 0 <= r <= 31 for r in realms)):
            raise ValueError("users_add_needs_access_permission_0_to_2_and_nonempty_realms_0_to_31")
    return dict(changes)


def validate_configure(area: str, changes: Any) -> dict[str, Any]:
    """Everything that can be checked without I/O. Runs before the confirmation guard."""
    if area in UNSUPPORTED_AREAS:
        raise ValueError(f"area_not_writable_by_this_tool:{area}: read it with amt_settings; "
                         "write it with amt_wsman_invoke")
    if area not in (*PUT_AREAS, "features", "users"):
        raise ValueError(f"unknown_settings_area:{area}")
    if not isinstance(changes, dict) or not changes:
        raise ValueError(f"changes_must_be_a_nonempty_object:{area}")
    ww.refuse_secret_names(changes)
    if area == "users":
        return _validate_users(changes)
    return _validate_changes(area, PUT_AREAS[area].fields if area in PUT_AREAS else FEATURE_FIELDS, changes)


def _same(want: Any, got: Any) -> bool:
    if isinstance(want, list):     # a single repeated element comes back as a bare string
        got_list = got if isinstance(got, list) else [got]
        return [str(x) for x in want] == [str(x) for x in got_list]
    if isinstance(got, list):
        return False
    return str(typed(got)).lower() == str(want).lower()


def _round_trip_body(area: str, spec: _PutArea, current: dict[str, Any]) -> dict[str, Any]:
    """The full-instance Put body: every field the Get returned, in the device's order, minus the
    area's read-only ones. A field this tool cannot echo faithfully (nested, or a credential other
    than the vaulted RFB slot) would be silently reset by a whole-replace Put, so it refuses the
    area before anything is sent."""
    body: dict[str, Any] = {}
    unsafe: list[str] = []
    for name, value in current.items():
        if name in spec.read_only or value is None:
            continue
        if spec.rfb and name == "RFBPassword":
            body[name] = ww.SECRET_SLOT
        elif amt_wsman.is_secret_field(name, value):
            unsafe.append(name)
        elif isinstance(value, str) or (isinstance(value, list) and all(isinstance(v, str) for v in value)):
            body[name] = value
        else:
            unsafe.append(name)
    if unsafe:
        raise WsmanError(f"configure_instance_not_round_trippable:{area}:{','.join(unsafe)}:"
                         "use amt_wsman_get and amt_wsman_invoke for this area")
    return body


def _configure_put(area: str, changes: dict[str, Any], dev: amt_registry.Device, pw: str) -> dict[str, Any]:
    spec = PUT_AREAS[area]
    current = amt_wsman.get(spec.cls, selectors=spec.selectors, device=dev.key, password=pw)
    body = _round_trip_body(area, spec, current)
    body.update(changes)                     # an existing field keeps the device's position
    ww.put(spec.cls, body, selectors=spec.selectors, device=dev.key, password=pw,
           secret_fields={"RFBPassword": f"{dev.amt_vault_key}-rfb"} if spec.rfb else None)
    after = amt_wsman.get(spec.cls, selectors=spec.selectors, device=dev.key, password=pw)
    previous = {n: typed(current.get(n), n) for n in changes}
    bad = sorted(n for n, v in changes.items() if not _same(v, after.get(n)))
    if bad:
        raise WsmanError(f"configure_readback_mismatch:{area}:{','.join(bad)}:previous={previous}")
    echoed = [n for n, v in body.items() if n not in changes and v is not ww.SECRET_SLOT]
    collateral = sorted(n for n in echoed if not _same(body[n], after.get(n)))
    if collateral:
        was = {n: typed(body[n], n) for n in collateral}
        raise WsmanError(f"configure_collateral_change:{area}:{','.join(collateral)}:was={was}:"
                         f"the requested fields were applied; revert these with amt_wsman_invoke put")
    return {"class": spec.cls, "previous": previous, "readback": {n: typed(after.get(n), n) for n in changes},
            "verified_unchanged": sorted(echoed)}


def _redirection_state(dev: amt_registry.Device, pw: str) -> dict[str, Any]:
    redir = typed(amt_wsman.get("AMT_RedirectionService", device=dev.key, password=pw))
    ider_on, sol_on = amt_tools.REDIRECTION_STATES.get(redir.get("EnabledState"), (None, None))
    kvm_code = typed(amt_wsman.get("CIM_KVMRedirectionSAP", device=dev.key, password=pw)).get("EnabledState")
    return {"ider_enabled": ider_on, "sol_enabled": sol_on,
            "kvm_enabled": None if kvm_code is None else kvm_code in (2, 6)}


def _configure_features(changes: dict[str, Any], dev: amt_registry.Device, pw: str) -> dict[str, Any]:
    before = _redirection_state(dev, pw)
    if "ider_enabled" in changes or "sol_enabled" in changes:
        if before["ider_enabled"] is None or before["sol_enabled"] is None:
            raise WsmanError("configure_features_current_redirection_state_unknown")
        want = (changes.get("ider_enabled", before["ider_enabled"]), changes.get("sol_enabled", before["sol_enabled"]))
        if want != (before["ider_enabled"], before["sol_enabled"]):
            code = next(c for c, pair in amt_tools.REDIRECTION_STATES.items() if pair == want)
            ww.invoke("AMT_RedirectionService", "RequestStateChange", {"RequestedState": code},
                      device=dev.key, password=pw)                  # TODO verify-live
    if "kvm_enabled" in changes and changes["kvm_enabled"] != before["kvm_enabled"]:
        ww.invoke("CIM_KVMRedirectionSAP", "RequestStateChange",
                  {"RequestedState": 2 if changes["kvm_enabled"] else 3}, device=dev.key, password=pw)
    after = _redirection_state(dev, pw)
    bad = sorted(n for n, v in changes.items() if after[n] != v)
    if bad:
        raise WsmanError(f"configure_readback_mismatch:features:{','.join(bad)}:previous="
                         f"{ {n: before[n] for n in changes} }")
    return {"class": "AMT_RedirectionService,CIM_KVMRedirectionSAP", "previous": {n: before[n] for n in changes},
            "readback": {n: after[n] for n in changes}}


def _user_entries(dev: amt_registry.Device, pw: str) -> list[tuple[Any, dict[str, Any]]]:
    """``(handle, entry)`` for every AMT user ACL entry, via the read client's allowlisted readers."""
    handles: list[Any] = []
    for _ in range(amt_tools.MAX_LOG_CALLS):
        out = amt_wsman.invoke_read("AMT_AuthorizationService", "EnumerateUserAclEntries",
                                    {"StartIndex": len(handles) + 1}, device=dev.key, password=pw)
        got = amt_tools._as_list(out.get("Handles"))
        handles += got
        total = typed(out.get("TotalCount"), "TotalCount")
        if not got or (isinstance(total, int) and len(handles) >= total):
            break
    return [(h, typed(amt_wsman.invoke_read("AMT_AuthorizationService", "GetUserAclEntryEx", {"Handle": h},
                                            device=dev.key, password=pw))) for h in handles]


def _configure_users(changes: dict[str, Any], dev: amt_registry.Device, pw: str) -> dict[str, Any]:
    name, action = changes["username"], changes["action"]
    existing = [h for h, e in _user_entries(dev, pw) if e.get("DigestUsername") == name]
    if action == "remove":
        if not existing:
            raise ValueError(f"users_no_such_user:{name}")
        ww.invoke("AMT_AuthorizationService", "RemoveUserAclEntry", {"Handle": existing[0]},
                  device=dev.key, password=pw)                        # TODO verify-live
        if any(e.get("DigestUsername") == name for _, e in _user_entries(dev, pw)):
            raise WsmanError(f"configure_readback_mismatch:users:{name}:still_present")
        return {"class": "AMT_AuthorizationService", "previous": {"present": True}, "readback": {"present": False}}
    if existing:
        raise ValueError(f"users_user_exists:{name}")
    user_secret = amt_vault.get_secret(f"{dev.key}-amt-user-{name}")     # the operator vaults it first
    realm = amt_wsman.get("AMT_GeneralSettings", device=dev.key, password=pw).get("DigestRealm")
    if not realm:
        raise WsmanError("configure_users_digest_realm_unavailable")
    digest = base64.b64encode(hashlib.md5(f"{name}:{realm}:{user_secret}".encode()).digest()).decode()
    ww.invoke("AMT_AuthorizationService", "AddUserAclEntryEx",
              {"DigestUsername": name, "AccessPermission": changes["access_permission"],
               "Realms": changes["realms"]},
              device=dev.key, password=pw, secret_params={"DigestPassword": digest})   # TODO verify-live
    if not any(e.get("DigestUsername") == name for _, e in _user_entries(dev, pw)):
        raise WsmanError(f"configure_readback_mismatch:users:{name}:not_present")
    return {"class": "AMT_AuthorizationService", "previous": {"present": False}, "readback": {"present": True}}


# (area, field, value) -> what that change does. Named in the confirmation so it is never a surprise.
RISKY_CONFIGURE = {
    ("kvm", "OptInPolicy", False): "turns OFF user consent for remote KVM sessions",
    ("kvm", "Is5900PortEnabled", True): "opens the unencrypted VNC port 5900",
    ("security", "AcceptNonSecureConnections", True): "accepts non-TLS (plaintext) connections to AMT",
    ("features", "ider_enabled", True): "enables IDE redirection",
    ("features", "sol_enabled", True): "enables Serial-over-LAN",
    ("features", "kvm_enabled", True): "enables KVM redirection",
}


def _configure_consequence(area: str, changes: Any) -> str:
    keys = ", ".join(sorted(changes)) if isinstance(changes, dict) and changes else "(none)"
    risky = sorted(what for (a, f, v), what in RISKY_CONFIGURE.items()
                   if a == area and isinstance(changes, dict) and f in changes and changes[f] is v)
    warn = f"; THIS REQUEST {'; '.join(risky)}" if risky else ""
    return (f"writes the host's AMT '{area}' settings ({keys}); it reads the whole instance first, returns the "
            "changed fields' old values as 'previous' and verifies the new ones and every other "
            f"field by reading the instance back{warn}")


def configure(area: str, changes: dict[str, Any], device: str = DEFAULT_DEVICE,
              confirmed: bool = False) -> dict[str, Any]:
    changes = validate_configure(area, changes)
    _require_confirmed(confirmed, _configure_consequence(area, changes))
    dev, pw = _target(device)
    if area in PUT_AREAS:
        result = _configure_put(area, changes, dev, pw)
    elif area == "features":
        result = _configure_features(changes, dev, pw)
    else:
        result = _configure_users(changes, dev, pw)
    return {"device": dev.key, "area": area, **result,
            "revert": ("call amt_configure with the opposite action" if area == "users"
                       else "call amt_configure again with the 'previous' values")}


# --- amt_wsman_invoke -------------------------------------------------------------------

WsmanOperation = Literal["put", "create", "delete", "invoke"]


def _field_values(fields: dict[str, Any] | None) -> dict[str, Any]:
    """Caller fields -> wire values. ``{"epr": {"class": ..., "selectors": {...}}}`` becomes a
    reference parameter; any other dict is refused."""
    out: dict[str, Any] = {}
    for name, value in (fields or {}).items():
        if isinstance(value, dict):
            if set(value) != {"epr"} or not isinstance(value["epr"], dict) or set(value["epr"]) != {"class", "selectors"}:
                raise ValueError(f"unsupported_nested_field:{name}: only {{'epr': {{'class':..., 'selectors':{{...}}}}}}")
            out[name] = ww.epr(value["epr"]["class"], value["epr"]["selectors"])
        else:
            out[name] = value
    return out


def wsman_invoke(operation: str, class_name: str, method: str | None = None,
                 fields: dict[str, Any] | None = None, selectors: dict[str, str] | None = None,
                 device: str = DEFAULT_DEVICE, confirmed: bool = False) -> dict[str, Any]:
    if operation not in ("put", "create", "delete", "invoke"):
        raise ValueError(f"unknown_operation:{operation!r}")
    amt_wsman.resource_uri(class_name)
    if operation == "invoke" and not method:
        raise ValueError("invoke_needs_method")
    if operation != "invoke" and method:
        raise ValueError("method_only_valid_for_invoke")
    if operation == "delete" and (fields or not selectors):
        raise ValueError("delete_takes_selectors_only")
    wire = _field_values(fields)
    ww.refuse_secret_names(wire)
    ww.refuse_secret_names(selectors)
    ww.fields_xml(wire)                      # field names and values are valid before any I/O
    what = f"{class_name}.{method}" if method else class_name
    _require_confirmed(confirmed, f"sends a WS-MAN {operation} to {what} on the AMT host, which can change "
                                  "its configuration, power state or access; no safeguard other than "
                                  "this confirmation applies")
    _, pw = _target(device)
    if operation == "put":
        out = ww.put(class_name, wire, selectors=selectors, device=device, password=pw)
    elif operation == "create":
        out = ww.create(class_name, wire, selectors=selectors, device=device, password=pw)
    elif operation == "delete":
        out = ww.delete(class_name, selectors=selectors or {}, device=device, password=pw)
    else:
        out = ww.invoke(class_name, method, wire, selectors=selectors, device=device, password=pw,
                        rv_required=False)
    result = {"device": device, "operation": operation, "class": class_name, "method": method, "result": out}
    if operation == "invoke" and out.get("ReturnValue") is None:    # missing is "unknown", never success
        result["return_value"] = "unknown"
        result["note"] = "the device replied without a ReturnValue: the request was sent; its outcome is unknown"
    return result


# --- registered tool surface ------------------------------------------------------------

async def amt_power(
    action: Annotated[PowerAction, Field(
        description="Power action. Default restart is graceful and OS-aware (state 14). Graceful: "
                    "restart, shutdown, power_cycle, shutdown_hard_graceful, power_cycle_hard_graceful. "
                    "Other: power_on, sleep_light, sleep_deep, hibernate. UNGRACEFUL (the OS is not "
                    "asked; data can be lost): immediate_power_cycle, immediate_shutdown, "
                    "hard_power_off, hard_power_cycle, hard_reset, nmi.")] = DEFAULT_POWER_ACTION,
    device: DeviceParam = DEFAULT_DEVICE,
    confirmed: ConfirmedParam = False,
) -> dict:
    """Changes the host's power state over AMT (CIM_PowerManagementService.RequestPowerStateChange).
    Needs confirmed=true; false refuses and sends nothing. The default action restart is
    GRACEFUL (the host OS is asked to restart, power state 14); a hard reset (power state 10) is
    sent only when you name hard_reset, and the ungraceful actions (immediate_*, hard_*, nmi)
    never ask the OS, so unsaved work is lost. A graceful action needs the host's AMT agent to
    answer; there is no silent fallback to a harder one. It first reads the states AMT offers right
    now and refuses one it does not offer, naming the ones it does (a boot menu offers only
    hard_reset and nmi). Returns the requested state, whether it
    was graceful, the device's ReturnValue and a best-effort power state read afterwards (AMT
    applies the change asynchronously). To boot into BIOS or PXE, call amt_set_next_boot first,
    then this tool. Refuses a device whose TLS leaf is unpinned or does not match its pin."""
    _require_confirmed(confirmed, _power_consequence(action))
    async with _session_lock(device):
        return await asyncio.to_thread(power, action, device, confirmed)


async def amt_set_next_boot(
    target: Annotated[BootTarget, Field(
        description="One-time boot target: bios_setup, pxe, hard_disk, cd_ider, floppy_ider, "
                    "diagnostic, or clear (cancel a pending request). Nothing else is accepted.")],
    options: Annotated[dict[BootOptionName, bool | int] | None, Field(
        description="Optional advanced boot options as {name: value}: lock_power_button, "
                    "lock_reset_button, lock_sleep_button, lock_keyboard, user_password_bypass, "
                    "forced_progress_events, firmware_verbosity (0-3), configuration_data_reset, "
                    "bios_pause, reflash_bios, use_safe_mode, use_sol, use_ider, secure_erase, "
                    "enforce_secure_boot, boot_media_index (0-255). Flags are booleans.")] = None,
    device: DeviceParam = DEFAULT_DEVICE,
    confirmed: ConfirmedParam = False,
) -> dict:
    """Sets the host's ONE-TIME next boot target over AMT; it does not restart the host. Needs
    confirmed=true; false refuses and sends nothing. Runs MeshCommander's sequence: clear
    the boot order, Put AMT_BootSettingData (read-only and secret fields dropped, never a full echo
    of the Get; EVERY boot option starts from its safe default and only the options passed in THIS
    call are applied, so nothing from an earlier request carries over), then
    CIM_BootService.SetBootConfigRole(1), the step that activates it (a bare Put is ignored), then
    ChangeBootOrder with the source for pxe, hard_disk and diagnostic, and reads the flags back. Targets are an allowlist: bios_setup, pxe, hard_disk, cd_ider,
    floppy_ider, diagnostic, clear (resets every option to its safe default and sets no boot
    source); an arbitrary or USB target is refused. Advanced options include destructive ones
    (secure_erase, reflash_bios, configuration_data_reset, lock_power_button, lock_reset_button)
    that act at that boot. Follow with amt_power to take effect now. Refuses a device whose TLS leaf is unpinned or does not match its pin."""
    _require_confirmed(confirmed, _boot_consequence(target, _validate_boot_options(options)))
    async with _session_lock(device):
        return await asyncio.to_thread(set_next_boot, target, options, device, confirmed)


async def amt_console_input(
    actions: Annotated[list[ConsoleAction], Field(
        description="Ordered console steps (max 50), each {kind: click|text|key|macro|wait|secret, ...}: "
                    "click needs x and y as 0-1 ratios of the screen; text is printable ASCII; key is "
                    "one key with optional modifiers; macro is a named combination such as "
                    "ctrl_alt_del, alt_tab, win_r, f2, f12; wait is seconds; secret types the "
                    "vaulted host_user or host_password.")],
    expect: Annotated[list[ExpectLabel] | None, Field(
        description="Optional screen guard: the screen labels this call may act on, from the "
                    "classifier (" + ", ".join(EXPECT_LABELS) + "). When given, the first frame is "
                    "classified after the session opens; any other label (or an unreadable frame) "
                    "aborts naming the label seen, with no key or click sent. Omit it for the "
                    "unguarded behaviour. A secret step is refused, before the session opens, "
                    "beside any boot or firmware label (" + ", ".join(sorted(amt_tools.BOOT_FIRMWARE_LABELS))
                    + "): no credential is ever typed into GRUB, BIOS setup, an installer or MOK.")] = None,
    device: DeviceParam = DEFAULT_DEVICE,
    confirmed: ConfirmedParam = False,
) -> dict:
    """Drives the host's console by AMT KVM: ordered mouse clicks, typed text, keys with
    modifiers, key macros and Ctrl-Alt-Del, paced for AMT, then returns a screenshot (server-side
    PNG path). Needs confirmed=true; false refuses and sends nothing. By default it acts on
    whatever is on screen and does no screen check, so look first with amt_screenshot: a secret
    step types the vaulted host account name or password into whatever field has focus. Pass
    expect to drive GRUB, BIOS setup, the text installer or MOK safely: the first frame must be
    one of those labels or nothing is sent. NEVER put a credential in a text step; use a secret
    step. Windows logon goes through amt_remote_logon. Typed text and
    secrets are not echoed in the result (only step counts). Opens the host's
    KVM session and closes it (or shares the display mirror's while one runs); fails if another
    KVM session is open. Refuses a device whose
    TLS leaf is unpinned or does not match its pin."""
    steps = _compile_actions(actions)
    _compile_expect(expect, steps)
    _require_confirmed(confirmed, f"sends {len(steps)} mouse/keyboard step(s) to the host's console")
    async with _session_lock(device):
        return await asyncio.to_thread(console_input, actions, device, confirmed, expect)


async def amt_sol(
    text: Annotated[str, Field(
        description="ASCII text to send to the host's serial console (max 1024 characters), sent exactly "
                    "as received. End a line with a real newline or carriage-return character for Enter: "
                    "a backslash followed by r or n is sent as those two characters, and a Linux getty "
                    "takes them as typed text. Empty means send nothing and only read. Never send a "
                    "credential.")] = "",
    read_seconds: Annotated[float, Field(
        gt=0, le=MAX_SOL_READ_SECONDS, description="How long to collect serial output after sending, "
                                                   "in seconds (max 15).")] = 3.0,
    max_bytes: Annotated[int, Field(
        ge=1, le=MAX_SOL_READ_BYTES, description="Maximum output bytes to return (1-16384).")] = 4096,
    device: DeviceParam = DEFAULT_DEVICE,
    confirmed: ConfirmedParam = False,
) -> dict:
    """Sends text over the host's Serial-over-LAN console and returns a bounded window of the
    serial output. Needs confirmed=true; false refuses and sends nothing. It opens the host's
    SOL session and closes it before returning (SOL beside KVM verified live 2026-10-19); the
    serial port must be enabled in the BIOS and SOL enabled in AMT (amt_configure features).
    Returns the text read (up to max_bytes within read_seconds), its byte count and whether
    more arrived than was kept. Never send credentials. Refuses a device whose TLS leaf is
    unpinned or does not match its pin."""
    _require_confirmed(confirmed, "opens the host's Serial-over-LAN session and sends text to its serial console")
    async with _session_lock(device):
        return await asyncio.to_thread(sol, text, read_seconds, max_bytes, device, confirmed)


async def amt_ider(
    action: Annotated[Literal["mount", "unmount", "status"], Field(
        description="mount attaches image(s) and serves them until unmount; unmount ends the "
                    "session; status reports the mount.")],
    iso_path: Annotated[str | None, Field(
        description="mount: path of a .iso image, relative to the image root or absolute inside it. "
                    "Omit for none.")] = None,
    floppy_path: Annotated[str | None, Field(
        description="mount: path of a .img floppy image under the image root. Omit for none.")] = None,
    start: Annotated[IderStart, Field(
        description="mount: when the host sees the drive: next_boot (default; waits for the host's next "
                    "boot) or graceful / now, which RESET the host at once.")] = "next_boot",
    device: DeviceParam = DEFAULT_DEVICE,
    confirmed: ConfirmedParam = False,
) -> dict:
    """Mounts IDE-R images on the host over AMT, served from the server's image root (manage
    that with amt_images). mount and unmount need confirmed=true (false refuses and sends
    nothing); status needs none. start=graceful or now RESETS the host (only next_boot waits). A
    mount has no time limit and keeps the host's IDE-R session open until unmount (KVM and the
    display mirror keep working alongside it, verified live), so unmount when done; unmount
    reports the session still held if the serving thread will not stop. Images must be .iso or
    .img and a multiple of 512 bytes, and are only ever read. The host can boot from a mounted
    ISO (amt_set_next_boot cd_ider). Refuses a device whose TLS leaf is unpinned or mismatched."""
    if action == "status":
        return await asyncio.to_thread(ider, action, iso_path, floppy_path, start, device, confirmed)
    _require_confirmed(confirmed, _ider_consequence(action, iso_path, floppy_path, start))
    async with _session_lock(device):
        return await asyncio.to_thread(ider, action, iso_path, floppy_path, start, device, confirmed)


async def amt_images(
    action: Annotated[Literal["list", "verify", "set_root", "fetch", "upload", "rename", "delete"], Field(
        description="list: the image root, its images, downloads and uploads. verify: SHA-256 of one "
                    "image. set_root: point the root at a directory (persisted). fetch: download a URL "
                    "into the root in the background. upload: mint a one-time url the file is sent to. "
                    "rename / delete: one image.")] = "list",
    root: Annotated[str | None, Field(
        description="set_root: directory on the server to serve images from; created if missing, kept "
                    "across restarts, and used ahead of the AMT_IMAGE_ROOT env.")] = None,
    url: Annotated[str | None, Field(
        description="fetch: http(s) URL of a .iso or .img to download into the image root.")] = None,
    name: Annotated[str | None, Field(
        description="fetch / upload: plain .iso or .img file name to save as; fetch defaults to the "
                    "URL's file name.")] = None,
    path: Annotated[str | None, Field(
        description="verify / rename / delete: the image's path as list reports it, relative to the "
                    "root, e.g. debian-13.7.0-amd64-netinst.iso.")] = None,
    new_name: Annotated[str | None, Field(
        description="rename: the new plain .iso or .img name, in the same folder; never replaces a "
                    "file.")] = None,
    size_bytes: Annotated[int | None, Field(
        description="upload: exact size of the file in bytes; the upload must match it.", gt=0)] = None,
    sha256: Annotated[str | None, Field(
        description="fetch / upload / verify: optional expected SHA-256 (64 hex chars). fetch and "
                    "upload delete the file and report failure on a mismatch; verify reports "
                    "matches.")] = None,
    overwrite: Annotated[bool, Field(
        description="fetch / upload: replace an existing file of the same name.")] = False,
    confirmed: ConfirmedParam = False,
) -> dict:
    """Manages the server's IDE-R image library, the folder amt_ider mounts from. Touches no host.
    list and verify need no confirmation; set_root, fetch, upload, rename and delete need
    confirmed=true (false refuses and changes nothing). rename, delete and an overwriting fetch or
    upload are refused while that image is mounted on a host, downloading or uploading. fetch
    returns at once and downloads in the background: poll list for progress, the computed SHA-256
    and any error. upload returns a one-time url (needs AMT_PUBLIC_BASE_URL); PUT the raw file to
    it once (curl -T file url) and poll list for the result. The file never passes through MCP. An
    upload must be exactly size_bytes, under the server's cap, with room left on the volume."""
    if action == "list":
        return await asyncio.to_thread(ider_list)
    if action == "verify":
        return await asyncio.to_thread(ider_verify, path, sha256)
    if action == "set_root":
        _require_confirmed(confirmed, f"points the server's IDE-R image root at {root!r} and keeps it "
                                      "across restarts; images are then served from there")
        return await asyncio.to_thread(ider_set_root, root or "")
    if action == "fetch":
        _require_confirmed(confirmed, f"downloads {url!r} into the IDE-R image root on the server")
        return await asyncio.to_thread(ider_fetch, url or "", name, sha256, overwrite)
    if action == "upload":
        _require_confirmed(confirmed, f"opens a one-time url that writes {name!r} into the IDE-R image "
                                      f"root{' replacing the existing file' if overwrite else ''}")
        return await asyncio.to_thread(ider_upload, name, size_bytes, sha256, overwrite)
    if action == "rename":
        _require_confirmed(confirmed, f"renames the image {path!r} to {new_name!r} in the image root")
        return await asyncio.to_thread(ider_rename, path, new_name)
    if action == "delete":
        _require_confirmed(confirmed, f"permanently deletes the image {path!r} from the image root")
        return await asyncio.to_thread(ider_delete, path)
    raise ValueError(f"unknown_images_action:{action!r}")


async def amt_configure(
    area: Annotated[ConfigureArea, Field(
        description="ONE settings area to write: network, internet, security, users, kvm or "
                    "features. (agent_presence, system_defense, subscriptions and wake_alarms are "
                    "read with amt_settings and written with amt_wsman_invoke.)")],
    changes: Annotated[dict[str, Any], Field(
        description="The fields to change for that area as {name: value}. network: HostName, "
                    "DomainName, SharedFQDN, PingResponseEnabled, RmcpPingResponseEnabled, "
                    "DDNSUpdateEnabled, DDNSPeriodicUpdateInterval, DDNSTTL, IdleWakeTimeout. "
                    "internet: DetectionAlgorithm, DetectionStrings. security: "
                    "AcceptNonSecureConnections. kvm: Is5900PortEnabled, OptInPolicy, SessionTimeout. "
                    "features: ider_enabled, sol_enabled, kvm_enabled (booleans). users: action "
                    "add|remove, username, and for add access_permission and realms; the new user's "
                    "password is read from the vault. Passwords are never accepted here.")],
    device: DeviceParam = DEFAULT_DEVICE,
    confirmed: ConfirmedParam = False,
) -> dict:
    """Writes ONE area of the host's AMT settings with a readback. Needs confirmed=true; false
    refuses and sends nothing. It can weaken access: kvm OptInPolicy=false disables user consent,
    kvm Is5900PortEnabled=true opens plaintext VNC port 5900, security AcceptNonSecureConnections=
    true accepts non-TLS connections, and features can enable IDE-R, SOL or KVM. Only the listed
    fields of the chosen area can be changed (others are refused). It reads the whole instance,
    merges the change onto it, writes the merged instance, reads the whole instance back and raises
    if the change or any other field differs; `previous` holds the old values for a revert.
    AMT passwords are never arguments: the KVM password comes from the vault in-process, and a
    new AMT user's password is read from the vault entry `<device>-amt-user-<username>` that the
    operator creates first (the admin account is never changed). Refuses a device whose TLS leaf
    is unpinned or does not match its pin."""
    validate_configure(area, changes)
    _require_confirmed(confirmed, _configure_consequence(area, changes))
    async with _session_lock(device):
        return await asyncio.to_thread(configure, area, changes, device, confirmed)


async def amt_wsman_invoke(
    operation: Annotated[WsmanOperation, Field(
        description="WS-MAN operation: put (replace an instance), create, delete (needs selectors) "
                    "or invoke (call a method).")],
    class_name: Annotated[str, Field(
        description="AMT, CIM or IPS class name, e.g. CIM_PowerManagementService. Must start with "
                    "AMT_, CIM_ or IPS_.")],
    method: Annotated[str | None, Field(
        description="invoke only: the method name, e.g. RequestPowerStateChange.")] = None,
    fields: Annotated[dict[str, Any] | None, Field(
        description="Instance fields (put/create) or method parameters (invoke) as {name: value}; "
                    "values are text, numbers, booleans or lists of those. A reference parameter is "
                    "{\"epr\": {\"class\": \"CIM_X\", \"selectors\": {\"InstanceID\": \"...\"}}}. "
                    "Credential-named fields are refused.")] = None,
    selectors: Annotated[dict[str, str] | None, Field(
        description="Selector name/value pairs that pick the instance, e.g. "
                    "{\"InstanceID\": \"Intel(r) AMT: Boot Configuration 0\"}.")] = None,
    device: DeviceParam = DEFAULT_DEVICE,
    confirmed: ConfirmedParam = False,
) -> dict:
    """General write primitive: WS-MAN Put, Create, Delete or method Invoke on any AMT_, CIM_ or
    IPS_ class (Script-Editor parity). Needs confirmed=true; false refuses and sends nothing. It
    has NO per-class safeguard beyond that confirmation and can reach catastrophic operations:
    AMT_SetupAndConfigurationService.Unprovision (factory-resets AMT and drops all management),
    changes to ports, TLS, certificates or network settings that cut AMT off, user and realm
    changes, and power actions. Prefer amt_power, amt_set_next_boot and amt_configure, which
    validate and read back. A Put may whole-replace the instance and reset fields you omit: Get
    the FULL instance (amt_wsman_get), merge your change, Put the merged instance. Credential-named
    fields, at any depth, are refused; replies and fault text are redacted. A non-zero ReturnValue
    or a SOAP Fault raises; a reply with no ReturnValue reports return_value unknown. Refuses a
    device whose TLS leaf is unpinned or does not match its pin."""
    wire = _field_values(fields)
    ww.refuse_secret_names(wire)
    ww.refuse_secret_names(selectors)
    what = f"{class_name}.{method}" if method else class_name
    _require_confirmed(confirmed, f"sends a WS-MAN {operation} to {what} on the AMT host")
    async with _session_lock(device):
        return await asyncio.to_thread(wsman_invoke, operation, class_name, method, fields, selectors,
                                       device, confirmed)


# (function, name, title, annotation hints). The server applies readOnlyHint False to these.
WRITE_TOOL_SPECS = (
    (amt_power, "amt_power", "AMT Power Action", {"destructiveHint": True}),
    (amt_set_next_boot, "amt_set_next_boot", "AMT Set Next Boot", {"destructiveHint": True}),
    (amt_console_input, "amt_console_input", "AMT Console Input", {"destructiveHint": True}),
    (amt_sol, "amt_sol", "AMT Serial-over-LAN", {"destructiveHint": True}),
    (amt_ider, "amt_ider", "AMT IDE Redirection Mount", {"destructiveHint": True}),
    (amt_images, "amt_images", "AMT IDE-R Image Library", {"destructiveHint": True}),
    (amt_configure, "amt_configure", "AMT Configure Settings", {"destructiveHint": True}),
    (amt_wsman_invoke, "amt_wsman_invoke", "AMT WS-MAN Write or Invoke", {"destructiveHint": True}),
)
