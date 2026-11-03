"""The credential entries amt-mcp's own vault holds: the read tool and the intake / remove writer.

Identities are the vault entries the registered servers name (each device's ``amt_vault_key`` and
``host_vault_key``), plus the ``<amt_vault_key>-rfb`` and ``<device>-amt-user-<name>`` entries the
credential registry describes. ``amt_identities`` reports status only: name, present or missing,
which device field uses it, and its source. ``amt_identity_manage`` never takes a value: ``intake``
mints a single-use url (``amt_upload``) the operator's browser PUTs the value to, and ``remove``
deletes an entry that was entered that way and that no server names. A value never appears in an
argument, a result, a log line or an exception here.
"""
from __future__ import annotations

import asyncio
import re
from typing import Annotated, Any, Literal

from pydantic import Field

import amt_registry
import amt_upload
import amt_vault
from amt_tools import _require_confirmed
from amt_write import USER_NAME, ConfirmedParam

USER_INFIX = "-amt-user-"
RFB_SUFFIX = "-rfb"
_UPDATED = re.compile(r"updated: (\S+)")


def _named(devices: dict[str, amt_registry.Device]) -> dict[str, list[dict[str, str]]]:
    """Entry name -> the device fields that name it."""
    out: dict[str, list[dict[str, str]]] = {}
    for dev in devices.values():
        for field in ("amt_vault_key", "host_vault_key"):
            name = getattr(dev, field)
            if name:
                out.setdefault(name, []).append({"device": dev.key, "field": field})
    return out


def _derived(devices: dict[str, amt_registry.Device], name: str) -> list[dict[str, str]]:
    """The device uses of an entry no device field names: its KVM (RFB) password or an AMT user's."""
    uses = []
    for dev in devices.values():
        if name == dev.amt_vault_key + RFB_SUFFIX:
            uses.append({"device": dev.key, "field": "amt_configure_kvm"})
        elif name.startswith(dev.key + USER_INFIX) and len(name) > len(dev.key + USER_INFIX):
            uses.append({"device": dev.key, "field": "amt_configure_users"})
    return uses


def _source(line: str) -> str:
    return "console" if amt_upload.SOURCE_NOTE in line else "main"


def identities_read(device: str | None) -> dict[str, Any]:
    all_devices = amt_registry.all_devices()
    scoped = {device: amt_registry.get_device(device)} if device else all_devices
    entries = amt_vault.vault_entries()
    named = _named(scoped)
    rows = []
    names = set(named) | {n for n in entries if _derived(scoped, n)}
    if not device:                      # an intake entry no server names yet is still listed
        names |= {n for n, line in entries.items() if _source(line) == "console"}
    for name in sorted(names):
        line = entries.get(name)
        uses = named.get(name, []) + _derived(scoped, name)
        updated = _UPDATED.search(line) if line is not None else None
        rows.append({"name": name, "status": "present" if line is not None else "missing",
                     "used_by": uses, "source": _source(line) if line is not None else None,
                     "updated_at": updated.group(1) if updated else None})
    return {"vault_entries": len(entries), "identities": rows}


async def amt_identities(
    device: Annotated[str | None, Field(
        description="Only this server's entries (its key, e.g. my-server-1); omit for every server.")] = None,
) -> dict:
    """Lists the vault entries amt-mcp's servers use, by NAME and status only. Read-only. Per entry:
    present or missing, which device field uses it (amt_vault_key, host_vault_key, or the
    KVM / AMT-user entries amt_configure reads), its source (main = copied from the main vault by
    vault sync, console = entered through amt_identity_manage) and updated_at when known. A missing
    entry means every call to its server fails. Never a value, never a value's length."""
    return await asyncio.to_thread(identities_read, device)


READ_TOOL_SPECS = (
    (amt_identities, "amt_identities", "AMT Identities"),
)


# --- the write tool -------------------------------------------------------------------------

def _user_entry(devices: dict[str, amt_registry.Device], name: str) -> bool:
    """``<device>-amt-user-<name>`` for a registered device, the name part being one amt_configure
    can add as an AMT user (so mixed case, ``_``, ``.`` and ``@`` are allowed there)."""
    return any(name.startswith(d.key + USER_INFIX) and USER_NAME.fullmatch(name[len(d.key + USER_INFIX):])
               for d in devices.values())


def _allowed_for_intake(devices: dict[str, amt_registry.Device], name: str) -> bool:
    return (name in _named(devices) or _user_entry(devices, name)
            or any(name == d.amt_vault_key + RFB_SUFFIX for d in devices.values()))


def identity_manage(action: str, name: str) -> dict[str, Any]:
    devices = amt_registry.all_devices()
    if not (amt_registry._KEY.fullmatch(name or "") or _user_entry(devices, name or "")):
        raise ValueError("identity_name_invalid: lowercase letters, digits and dashes (an AMT user's name "
                         "part also takes A-Z _ . @, 1 to 16 characters)")
    if action == "intake":
        if not _allowed_for_intake(devices, name):
            raise ValueError(f"identity_name_not_allowed:{name}: it must be an entry a registered server "
                             "names, <amt_vault_key>-rfb, or <device>-amt-user-<name> for a registered device")
        return amt_upload.intake_offer(name)
    if action == "remove":
        users = _named(devices).get(name)
        if users:
            raise ValueError(f"identity_in_use:{name}: named by "
                             + ", ".join(f"{u['device']}.{u['field']}" for u in users))
        entries = amt_vault.vault_entries()
        if name not in entries:
            raise ValueError(f"identity_not_found:{name}")
        if _source(entries[name]) != "console":
            raise ValueError(f"identity_not_console_entry:{name}: only an entry entered through the intake "
                             "can be removed here; a main-vault entry is removed from the main vault")
        amt_vault.delete_secret(name)
        return {"removed": name}
    raise ValueError(f"unknown_identity_manage_action:{action!r}")


def _consequence(action: str, name: str) -> str:
    if action == "intake":
        return (f"mints a one-time url that stores whatever its single PUT sends as the vault entry "
                f"{name!r}, replacing any value now there; this does NOT change the password on the AMT")
    return f"deletes the vault entry {name!r} from this server's vault"


async def amt_identity_manage(
    action: Annotated[Literal["intake", "remove"], Field(
        description="intake: mint a one-time url the value is PUT to. remove: delete an entry that was "
                    "entered through an intake.")],
    name: Annotated[str, Field(
        description="The vault entry's NAME, never its value: an entry a registered server names "
                    "(amt_vault_key or host_vault_key), <amt_vault_key>-rfb (the KVM password), or "
                    "<device>-amt-user-<name> for a registered device. Lowercase letters, digits and "
                    "dashes; an AMT user's name part also takes A-Z _ . @.")],
    confirmed: ConfirmedParam = False,
) -> dict:
    """Mints a one-time intake url for a vault entry, or removes an entry. Needs confirmed=true; false
    refuses and changes nothing. intake stores nothing itself: it returns {url, expires_in_s,
    max_bytes}, and the operator's browser PUTs the value once to the url (raw UTF-8 body, 900 s,
    single use); the value never passes through this tool. The entry's source becomes console.
    Entering a value does NOT change the password on the AMT: change it in MEBx first. remove refuses
    an entry any server still names and an entry copied from the main vault. Use amt_identities to
    read the entries."""
    _require_confirmed(confirmed, _consequence(action, name))
    return await asyncio.to_thread(identity_manage, action, name)


WRITE_TOOL_SPECS = (
    (amt_identity_manage, "amt_identity_manage", "AMT Manage Identities", {"destructiveHint": True}),
)
