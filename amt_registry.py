"""Device registry: host key -> AMT endpoints and TLS leaf pin slot. No secrets.

Vault entries are referenced by KEY NAME only; values are resolved in-process by amt_vault.

With ``AMT_DEVICES_FILE`` set (the container: ``/config/devices.json``, written under a
lock by ``amt_device_manage`` in the container and by ``deploy/amt_admin.py`` over ssh), that file IS the registry: it is re-read whenever it
changes, so a server added or edited there is live at the next call, no restart. A missing or
malformed file fails closed. Unset (local stdio, tests), the built-in ``DEVICES`` below is used.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
from dataclasses import asdict, dataclass

_HEX64 = re.compile(r"[0-9a-f]{64}")
_KEY = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
DEVICES_FILE_ENV = "AMT_DEVICES_FILE"
FILE_VERSION = 1


@dataclass(frozen=True)
class Device:
    key: str
    amt_ip: str
    wsman_port: int
    kvm_port: int
    amt_vault_key: str
    host_vault_key: str | None = None
    # Full SHA-256 of the AMT TLS leaf certificate. None = unpinned: every WS-MAN/KVM path refuses it.
    tls_leaf_sha256: str | None = None
    # Prefix seen on the first capture. Informational only, never used for verification.
    tls_leaf_observed_prefix: str | None = None

    def __post_init__(self):
        if self.tls_leaf_sha256 is not None and not _HEX64.fullmatch(self.tls_leaf_sha256):
            raise ValueError(f"{self.key}: tls_leaf_sha256 must be 64 lowercase hex characters")
        for name in ("key", "amt_vault_key", *(("host_vault_key",) if self.host_vault_key else ())):
            if not isinstance(getattr(self, name), str) or not _KEY.fullmatch(getattr(self, name)):
                raise ValueError(f"{self.key}: {name} must be lowercase letters, digits and dashes")
        ipaddress.ip_address(self.amt_ip)          # an address, never a hostname (the pin is per address)
        for port in (self.wsman_port, self.kvm_port):
            if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
                raise ValueError(f"{self.key}: ports must be integers 1-65535")

    @property
    def pinned(self) -> bool:
        return self.tls_leaf_sha256 is not None


DEVICES: dict[str, Device] = {
    "my-server-1": Device(
        key="my-server-1",
        amt_ip="198.51.100.26",  # an example: a real deployment names its servers in AMT_DEVICES_FILE
        wsman_port=16993,
        kvm_port=16995,
        amt_vault_key="my-server-1-amt",
        host_vault_key="my-server-1-os",
        tls_leaf_sha256="a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90",
        tls_leaf_observed_prefix="a1b2c3d4e5f60718",
    ),
}


_LOADED: dict[str, object] = {"path": None, "mtime": None}


def devices_from_json(text: str) -> dict[str, Device]:
    """Parse and validate a devices file: ``{"version": 1, "devices": {key: {fields}}}``."""
    data = json.loads(text)
    if not isinstance(data, dict) or data.get("version") != FILE_VERSION or not isinstance(data.get("devices"), dict):
        raise ValueError("devices_file_malformed")
    fields = set(Device.__dataclass_fields__) - {"key"}
    out = {}
    for key, entry in data["devices"].items():
        if not isinstance(entry, dict) or set(entry) - fields:
            raise ValueError(f"devices_file_malformed:{key}")
        out[key] = Device(key=key, **entry)
    return out


def devices_to_json(devices: dict[str, Device]) -> str:
    return json.dumps({"version": FILE_VERSION, "devices": {
        k: {f: v for f, v in asdict(d).items() if f != "key"} for k, d in sorted(devices.items())}},
        indent=2) + "\n"


def _refresh() -> None:
    """Load the devices file when it is configured and changed. Fails closed: an unreadable or
    malformed file raises, it never falls back to the built-in registry."""
    path = os.environ.get(DEVICES_FILE_ENV)
    if not path:
        return
    try:
        mtime = os.stat(path).st_mtime_ns
        if _LOADED["path"] == path and _LOADED["mtime"] == mtime:
            return
        with open(path, encoding="utf-8") as fh:
            devices = devices_from_json(fh.read())
    except (OSError, ValueError) as ex:
        raise RuntimeError(f"devices_file_unusable:{type(ex).__name__}") from None
    DEVICES.clear()
    DEVICES.update(devices)
    _LOADED.update(path=path, mtime=mtime)


def all_devices() -> dict[str, Device]:
    _refresh()
    return dict(DEVICES)


def get_device(key: str) -> Device:
    """Return the registered device, or raise KeyError naming the unknown key."""
    _refresh()
    try:
        return DEVICES[key]
    except KeyError:
        raise KeyError(f"unknown_device:{key}") from None
