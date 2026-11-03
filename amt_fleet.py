"""The servers amt-mcp manages: the read tool and the add / edit / remove rules both writers share.

Two writers change the devices file: ``deploy/amt_admin.py`` on the operator's machine (over ssh)
and the console through the MCP. Both plan a change with the functions here, so one set of rules
decides what a valid server is: its TLS leaf pin is recorded from what the server presents (trust
on first use) and re-checked when its address changes, its vault keys must already exist, and the
last server cannot be removed. A pin check sends no credential: it reads the leaf certificate in
the TLS handshake only.
"""
from __future__ import annotations

import asyncio
import dataclasses
import fcntl
import hashlib
import os
import socket
import ssl
from pathlib import Path
from typing import Annotated, Any, Callable, Literal

from pydantic import Field

import amt_registry
import amt_vault
from amt_registry import Device
from amt_tools import _require_confirmed
from amt_write import ConfirmedParam

PIN_TIMEOUT = 10
Probe = Callable[[str, int], str]


def presented_pin(ip: str, port: int) -> str:
    """SHA-256 of the TLS leaf the server presents. Sends no credential."""
    ctx = ssl._create_unverified_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.create_connection((ip, port), timeout=PIN_TIMEOUT) as raw:
        with ctx.wrap_socket(raw, server_hostname=ip) as tls:
            der = tls.getpeercert(binary_form=True)
    if not der:
        raise ValueError(f"{ip}:{port} presented no certificate")
    return hashlib.sha256(der).hexdigest()


def public(dev: Device) -> dict[str, Any]:
    """Every field of a device. None of them is a secret: vault entries appear by name only."""
    return {**dataclasses.asdict(dev), "pinned": dev.pinned}


def _need_keys(dev: Device, names: set[str], where: str) -> None:
    for needed in (dev.amt_vault_key, dev.host_vault_key):
        if needed and needed not in names:
            raise ValueError(f"vault {needed} in {where} first")


def plan_add(devices: dict[str, Device], key: str, ip: str, amt_vault_key: str,
             host_vault_key: str | None, wsman_port: int, kvm_port: int, pin: str | None,
             names: set[str], where: str, probe: Probe = presented_pin) -> Device:
    """A new device, pinned to the leaf it presents now. ``pin`` refuses any other leaf."""
    if key in devices:
        raise ValueError(f"device {key} exists; edit it instead")
    draft = Device(key=key, amt_ip=ip, wsman_port=wsman_port, kvm_port=kvm_port,
                   amt_vault_key=amt_vault_key, host_vault_key=host_vault_key)
    _need_keys(draft, names, where)
    seen = probe(ip, wsman_port)
    if pin and pin.lower() != seen:
        raise ValueError(f"{ip}:{wsman_port} presents leaf {seen}, not the given pin; nothing written")
    return dataclasses.replace(draft, tls_leaf_sha256=seen, tls_leaf_observed_prefix=seen[:16])


def plan_edit(dev: Device, changes: dict[str, Any], repin: bool, names: set[str], where: str,
              probe: Probe = presented_pin) -> Device:
    """``dev`` with ``changes``. A new address or port, or ``repin``, re-reads the leaf; a leaf
    other than the stored pin is refused unless ``repin``."""
    unknown = set(changes) - {"amt_ip", "wsman_port", "kvm_port", "amt_vault_key", "host_vault_key"}
    if unknown:
        raise ValueError(f"device fields not editable: {sorted(unknown)}")
    new = dataclasses.replace(dev, **changes)
    _need_keys(new, names, where)
    if repin or (new.amt_ip, new.wsman_port) != (dev.amt_ip, dev.wsman_port):
        seen = probe(new.amt_ip, new.wsman_port)
        if seen != dev.tls_leaf_sha256 and not repin:
            raise ValueError(f"{new.amt_ip}:{new.wsman_port} presents leaf {seen}, not the stored pin; "
                             "pass repin to accept it; nothing written")
        new = dataclasses.replace(new, tls_leaf_sha256=seen, tls_leaf_observed_prefix=seen[:16])
    return new


def plan_remove(devices: dict[str, Device], key: str) -> dict[str, Device]:
    if key not in devices:
        raise ValueError(f"no device {key}")
    if len(devices) == 1:
        raise ValueError("refusing to remove the last device; the server would have nothing to serve")
    return {k: d for k, d in devices.items() if k != key}


def pin_check(dev: Device, probe: Probe = presented_pin) -> dict[str, Any]:
    seen = probe(dev.amt_ip, dev.wsman_port)
    return {"device": dev.key, "presented": seen, "stored": dev.tls_leaf_sha256,
            "matches": seen == dev.tls_leaf_sha256}


# --- the read tool --------------------------------------------------------------------------

def devices_read(action: str, device: str | None) -> dict[str, Any]:
    source = "file" if os.environ.get(amt_registry.DEVICES_FILE_ENV) else "built-in"
    if action == "list":
        return {"source": source, "devices": [public(d) for d in amt_registry.all_devices().values()]}
    if not device:
        raise ValueError(f"amt_devices_{action}_needs_device")
    dev = amt_registry.get_device(device)
    if action == "show":
        return {"source": source, "device": public(dev)}
    if action == "pin_check":
        return pin_check(dev)
    raise ValueError(f"unknown_devices_action:{action!r}")


async def amt_devices(
    action: Annotated[Literal["list", "show", "pin_check"], Field(
        description="list: every registered server. show: one server. pin_check: compare the TLS leaf "
                    "the server presents now with its stored pin.")] = "list",
    device: Annotated[str | None, Field(
        description="show / pin_check: the server's key, e.g. my-server-1.")] = None,
) -> dict:
    """Lists the servers amt-mcp manages and checks their TLS pins. Read-only. Each server has a
    key, its AMT address, WS-MAN and KVM ports, the NAMES of its vault entries (never a value),
    its pinned TLS leaf SHA-256 and whether it is pinned; source says whether the list comes from
    the devices file or the built-in registry. pin_check opens one TLS handshake to the server's
    WS-MAN port and reads the leaf certificate, sending no credential; matches=false means the
    server's certificate changed or another machine holds its address, and every other tool
    refuses that server until it is re-pinned."""
    return await asyncio.to_thread(devices_read, action, device)


READ_TOOL_SPECS = (
    (amt_devices, "amt_devices", "AMT Managed Servers"),
)


# --- the write tool -------------------------------------------------------------------------

LOCK_NAME = ".devices.lock"     # deploy/amt_admin.py takes the same lock with flock(1) on the NAS
WHERE = "this server's vault (amt_identity_manage intake, or deploy/amt_admin.py vault sync)"


def _devices_path() -> Path:
    raw = os.environ.get(amt_registry.DEVICES_FILE_ENV)
    if not raw:
        raise ValueError(f"device changes need {amt_registry.DEVICES_FILE_ENV}: this server reads the "
                         "built-in registry, which only a code change can alter")
    return Path(raw)


def _write_locked(path: Path, change: Callable[[dict[str, Device]], dict[str, Device]]) -> dict[str, Device]:
    """Under the devices lock: read the file fresh, apply ``change``, validate, keep the old file as
    .prev-devices.json and rename the new one into place. A refusal in ``change`` writes nothing."""
    with open(path.parent / LOCK_NAME, "a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        devices = amt_registry.devices_from_json(path.read_text(encoding="utf-8"))
        new = change(devices)
        text = amt_registry.devices_to_json(new)
        amt_registry.devices_from_json(text)          # never write a file the server would refuse
        tmp = path.parent / ".devices.json.new"
        tmp.write_text(text, encoding="utf-8")
        os.chmod(tmp, 0o644)
        prev = path.parent / ".prev-devices.json"
        prev.write_bytes(path.read_bytes())
        os.replace(tmp, path)
    return new


def device_manage(action: str, device: str, ip: str | None = None, wsman_port: int | None = None,
                  kvm_port: int | None = None, amt_vault_key: str | None = None,
                  host_vault_key: str | None = None, clear_host: bool = False,
                  expected_pin: str | None = None, repin: bool = False) -> dict[str, Any]:
    path = _devices_path()
    if action == "remove":
        new = _write_locked(path, lambda d: plan_remove(d, device))
        return {"removed": device, "devices": sorted(new)}
    names = amt_vault.vault_names()
    if action == "add":
        if not ip or not amt_vault_key:
            raise ValueError("amt_device_manage_add_needs_ip_and_amt_vault_key")
        new = _write_locked(path, lambda d: {**d, device: plan_add(
            d, device, ip, amt_vault_key, host_vault_key, wsman_port or 16993, kvm_port or 16995,
            expected_pin, names, WHERE, probe=presented_pin)})
        return {"added": public(new[device]), "devices": sorted(new)}
    if action == "edit":
        changes = {k: v for k, v in {"amt_ip": ip, "wsman_port": wsman_port, "kvm_port": kvm_port,
                                     "amt_vault_key": amt_vault_key, "host_vault_key": host_vault_key}.items()
                   if v is not None}
        if clear_host:
            if host_vault_key:
                raise ValueError("amt_device_manage_edit_pass_host_vault_key_or_clear_host_not_both")
            changes["host_vault_key"] = None
        if not changes and not repin:
            raise ValueError("amt_device_manage_edit_needs_a_change_or_repin")

        def edit(d: dict[str, Device]) -> dict[str, Device]:
            if device not in d:
                raise ValueError(f"no device {device}")
            return {**d, device: plan_edit(d[device], changes, repin, names, WHERE, probe=presented_pin)}
        new = _write_locked(path, edit)
        return {"edited": public(new[device]), "devices": sorted(new)}
    raise ValueError(f"unknown_device_manage_action:{action!r}")


def _manage_consequence(action: str, device: str, repin: bool) -> str:
    if action == "remove":
        return f"removes the server {device!r} from amt-mcp; every tool then refuses it"
    if action == "add":
        return (f"adds the server {device!r}, pinned to the TLS leaf it presents now (trust on first use "
                "unless expected_pin is given)")
    return (f"changes the server {device!r}" + ("; repin ACCEPTS whatever TLS leaf it presents now, "
                                                "even a changed one" if repin else ""))


async def amt_device_manage(
    action: Annotated[Literal["add", "edit", "remove"], Field(
        description="add a server, edit one, or remove one.")],
    device: Annotated[str, Field(
        description="The server's key: lowercase letters, digits and dashes, e.g. my-server-1.")],
    ip: Annotated[str | None, Field(
        description="add (required) / edit: the AMT IP address. An address, never a host name: the "
                    "pin is per address.")] = None,
    wsman_port: Annotated[int | None, Field(
        description="add / edit: AMT WS-MAN TLS port; add defaults to 16993.", ge=1, le=65535)] = None,
    kvm_port: Annotated[int | None, Field(
        description="add / edit: AMT redirection TLS port; add defaults to 16995.", ge=1, le=65535)] = None,
    amt_vault_key: Annotated[str | None, Field(
        description="add (required) / edit: NAME of the vault entry holding the AMT admin password. "
                    "It must already exist in this server's vault; never a password.")] = None,
    host_vault_key: Annotated[str | None, Field(
        description="add / edit: NAME of the vault entry holding the host OS logon, if any.")] = None,
    clear_host: Annotated[bool, Field(
        description="edit: drop the host logon entry from this server.")] = False,
    expected_pin: Annotated[str | None, Field(
        description="add: the TLS leaf SHA-256 (64 hex) you expect, e.g. read from MEBx; any other "
                    "leaf is refused. Omit to trust the leaf presented now.")] = None,
    repin: Annotated[bool, Field(
        description="edit: accept the TLS leaf the server presents now even if it differs from the "
                    "stored pin.")] = False,
    confirmed: ConfirmedParam = False,
) -> dict:
    """Adds, edits or removes a server amt-mcp manages (its devices file). Needs confirmed=true;
    false refuses and changes nothing. add reads the TLS leaf the server presents (one handshake,
    no credential) and pins it; with expected_pin any other leaf is refused. edit re-reads the leaf
    when the address or WS-MAN port changes and refuses a different one unless repin=true. remove
    refuses the last server. Vault entries are named, never passed: each named entry must already
    exist in this server's vault. The change is live at the next tool call; the previous file is
    kept as .prev-devices.json. Use amt_devices to read the servers and check pins."""
    _require_confirmed(confirmed, _manage_consequence(action, device, repin))
    return await asyncio.to_thread(device_manage, action, device, ip, wsman_port, kvm_port,
                                   amt_vault_key, host_vault_key, clear_host, expected_pin, repin)


WRITE_TOOL_SPECS = (
    (amt_device_manage, "amt_device_manage", "AMT Manage Servers", {"destructiveHint": True}),
)
