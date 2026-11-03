"""The power and boot page's backend (packet C3): what AMT offers now, and the combined boot-then-power entries.

Both go through ``mcp_client`` like every console action, with the device named and the console's own bearer.

* The offered set is one read-only ``amt_wsman_get`` of ``CIM_AssociatedPowerManagementService``
  (``AvailableRequestedPowerStates``, the list ``amt_power`` itself checks before it sends). A paused server is not
  read at all (a refused credential gets no second attempt from this page); a read that fails says why and the page
  leaves every action to ``amt_power``'s own refusal. The read runs when the page opens and when the operator asks
  again, never on a timer.
* A combined entry (Power on -> target, Reset -> target) is ``amt_set_next_boot`` and then ``amt_power``, in that order.
  The power step is sent only when the boot step came back accepted; a refused boot step, or one that could not be
  made, leaves it unsent. Only these two power actions can follow a boot step (one tool call cannot carry a free
  second write through this route).
"""
from __future__ import annotations

import logging

import fleet
import mcp_client

log = logging.getLogger("amt_console.power")

# action -> AMT PowerState code. Mirrors amt_write.POWER_ACTIONS (console/tests/test_console_power.py pins the two together).
POWER_CODES: dict[str, int] = {
    "restart": 14, "shutdown": 12, "power_cycle": 15, "shutdown_hard_graceful": 13, "power_cycle_hard_graceful": 16,
    "power_on": 2, "sleep_light": 3, "sleep_deep": 4, "hibernate": 7,
    "immediate_power_cycle": 5, "immediate_shutdown": 8, "hard_power_off": 6, "hard_power_cycle": 9, "hard_reset": 10, "nmi": 11,
}
OFFERED_CLASS = "CIM_AssociatedPowerManagementService"
SEQUENCE_TOOLS = ("amt_set_next_boot", "amt_power")
SEQUENCE_POWER_ACTIONS = ("power_on", "hard_reset")      # Power on -> target, Reset -> target


class BadSequence(Exception):
    """The steps are not one of the two combined entries. The message is a fixed code."""


def offered_actions(instance) -> list[str] | None:
    """The action names AMT offers now, from an ``AvailableRequestedPowerStates`` value (one code or a list of codes);
    None when AMT reported no list. A value that is not a code raises ValueError: a guess would grey or enable the wrong
    actions."""
    if instance is None:
        return None
    values = instance if isinstance(instance, list) else [instance]
    codes = set()
    for v in values:
        if isinstance(v, bool) or not isinstance(v, (int, str)):
            raise ValueError("offered_state_not_a_code")
        try:
            codes.add(int(v))
        except ValueError:
            raise ValueError("offered_state_not_a_code") from None
    return [name for name, code in POWER_CODES.items() if code in codes]


def read_offered(client, flt: fleet.Fleet, key: str) -> dict:
    """The offered set for one server, as the page shows it: ``{"read_at", "now", "offered", "error", "paused"}``.
    ``offered`` is None when it is unknown (not read, no list reported, or unreadable), and ``error`` says which."""
    now = flt.now()
    public = flt.public(key)
    paused = public["paused"] if public else None
    out = {"now": now, "read_at": None, "offered": None, "error": None, "paused": paused}
    if paused:
        return out
    args = {"device": key, "class_name": OFFERED_CLASS, "operation": "get"}
    try:
        result = client.call("amt_wsman_get", args)
    except mcp_client.McpError as ex:
        out["error"] = fleet.clip(str(ex), 300)
        return out
    flt.observe("amt_wsman_get", args, result.is_error, result.text)
    if result.is_error:
        out["error"] = fleet.clip(result.text or "amt_wsman_get_failed", 600)
        out["paused"] = flt.public(key)["paused"] if flt.public(key) else None   # this read may have been the one that was refused
        return out
    obj = fleet.result_object(result)
    inst = obj.get("instance") if isinstance(obj, dict) else None
    if not isinstance(inst, dict):
        out["error"] = "amt_wsman_get returned no instance"
        return out
    out["read_at"] = now
    available = inst.get("AvailableRequestedPowerStates")
    try:
        out["offered"] = offered_actions(available)
    except ValueError as ex:
        out["error"] = str(ex)
        return out
    if out["offered"] is None:
        out["error"] = "AMT reported no AvailableRequestedPowerStates"
    return out


def check_sequence(steps) -> list[dict]:
    """The two steps of a combined entry, validated: ``amt_set_next_boot`` then ``amt_power`` with ``power_on`` or
    ``hard_reset``, one device, ``confirmed: true`` on both (mcp_client enforces the rest per call)."""
    if not isinstance(steps, list) or len(steps) != 2 or not all(isinstance(s, dict) for s in steps):
        raise BadSequence("sequence_needs_two_steps")
    if tuple(s.get("tool") for s in steps) != SEQUENCE_TOOLS:
        raise BadSequence("sequence_order_not_allowed")
    boot, power = (s.get("arguments") for s in steps)
    if not isinstance(boot, dict) or not isinstance(power, dict):
        raise BadSequence("arguments_not_an_object")
    if boot.get("device") != power.get("device"):
        raise BadSequence("sequence_devices_differ")
    if power.get("action") not in SEQUENCE_POWER_ACTIONS:
        raise BadSequence("sequence_power_action_not_allowed")
    return [{"tool": s["tool"], "arguments": s["arguments"]} for s in steps]


def run_sequence(steps: list[dict], run) -> dict:
    """Run the boot step; send the power step only if it was accepted. ``run(tool, arguments)`` makes one call and returns
    the reply dict the console sends the browser, or raises ``mcp_client.McpError``. A step that could not be made
    carries ``error`` (its code); a power step that was not attempted carries ``skipped``."""
    out = []
    for i, step in enumerate(steps):
        if i == 1 and not (out[0].get("reply") and not out[0]["reply"]["isError"]):
            out.append({"tool": step["tool"], "sent": False, "skipped": "boot_step_not_accepted"})
            break
        try:
            out.append({"tool": step["tool"], "sent": True, "reply": run(step["tool"], step["arguments"])})
        except mcp_client.McpError as ex:
            code = str(ex)
            # a call refused before it left (vault, validation) was not sent; a transport fault may or may not have been
            out.append({"tool": step["tool"], "sent": "unknown" if code.startswith("amt_mcp_") else False, "error": code})
    return {"steps": out}
