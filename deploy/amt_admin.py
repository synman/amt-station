#!/usr/bin/env python3
"""Manage the amt-mcp deployment on its Docker host: its servers and the identities they use.

One command set, two groups, run on the operator's machine (which holds the main vault):

    amt_admin.py device list                 the servers the NAS container serves
    amt_admin.py device init                 write the first devices file from the built-in registry
    amt_admin.py device add KEY --ip IP --amt-vault-key K [--host-vault-key H] [--wsman-port N]
                            [--kvm-port N] [--pin SHA256]
    amt_admin.py device edit KEY [--ip IP] [--amt-vault-key K] [--host-vault-key H | --no-host]
                            [--wsman-port N] [--kvm-port N] [--repin]
    amt_admin.py device remove KEY
    amt_admin.py device pin KEY              the TLS leaf the server presents now vs the stored pin
    amt_admin.py vault keys                  the vault entries the servers need
    amt_admin.py vault status                per entry: its source, on the NAS, and matching the main vault
    amt_admin.py vault sync                  rebuild the NAS dedicated vault from the main vault
    amt_admin.py console enroll-code         mint the management console's one-time enrollment code

Configuration (environment, all required): ``AMT_SECRETS_CLI`` (the main vault's ``secrets.py``),
``AMT_ADMIN_DEPLOY_DIR`` (the deploy directory on the host, beside ``src/``) and ``AMT_ADMIN_SSH_ENTRY``
(the vault entry holding the host's ``ssh_cmd``, ``user`` and ``host``). A command that needs one that is
unset stops before it touches anything.

The servers live in ``<deploy dir>/config/devices.json`` (mounted into the
container as ``/config/devices.json``, ``AMT_DEVICES_FILE``, where ``amt_device_manage`` also writes it); the container re-reads it when it
changes, so an add or edit is live at the next tool call. Every device change runs ``vault sync``
so the NAS vault holds exactly the entries the servers name.

TLS pin: ``add`` connects to the server's WS-MAN port and records the leaf it presents (trust on
first use, from this machine on the LAN); ``--pin`` makes it refuse any other leaf. ``edit``
re-checks the leaf when the address or port changes and refuses a different one unless
``--repin``. A fingerprint is not a secret; it is printed so it can be compared with MEBx.

Credentials: no value is printed, logged, put in argv or left in a file outside the two vault
files. ``vault status`` sends each value's SHA-256 over ssh stdin and the NAS answers match
yes/no; ``vault sync`` builds the new vault in a private temporary directory, streams it over
ssh and renames each file over the old one (no restart; the old pair stays as ``.prev-*``).
SSH is vault-first: the ``AMT_ADMIN_SSH_ENTRY`` entry's ``ssh_cmd``, ``user`` and ``host``.

Entries the console wrote through its intake carry ``source: console`` in their notes and live only
in the NAS vault. ``vault sync`` is merge-aware: it reads those entries (with their values) out of the
container over ssh, holds them in memory, and puts them into the rebuilt vault through the vault CLI's
stdin, as it does the main entries; the values are never printed. An entry in both vaults stays the
console's. An intake that lands between the read and the rename is lost, so sync when no intake is
open. ``vault status`` reports each entry's source; ``device add|edit`` accept a vault key that exists
only as a console entry.

``console enroll-code`` makes the code for the management console's first passkey: 12 characters from
an alphabet without look-alikes, valid 10 minutes, one use. The code is printed once, to this
terminal; only its SHA-256 and the expiry go to the NAS, over ssh stdin, as
``console-data/enroll.json`` (0600) for the console to watch and delete on use. The hash is of the 12
characters in upper case, without the dashes the display adds.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import io
import json
import os
import secrets
import shlex
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
import amt_fleet  # noqa: E402
import amt_registry  # noqa: E402

CLI = os.environ.get("AMT_SECRETS_CLI", "")
NAS_DIR = os.environ.get("AMT_ADMIN_DEPLOY_DIR", "").rstrip("/")
SSH_ENTRY = os.environ.get("AMT_ADMIN_SSH_ENTRY", "")
DEVICES_PATH = f"{NAS_DIR}/config/devices.json"
FILES = ("amt-mcp.vault", "amt-mcp.key")
CONTAINER = "amt-mcp"
NOTES = "amt-mcp dedicated vault copy (deploy/amt_admin.py vault sync)"
EXPIRES = "2035-01-01"
SOURCE_NOTE = "source: console"       # what amt_upload writes into an intake entry's notes
ENROLL_PATH = f"{NAS_DIR}/console-data/enroll.json"
ENROLL_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"    # no I, L, O, 0 or 1
ENROLL_LENGTH = 12
ENROLL_MINUTES = 10


# -- the main vault (this machine) ---------------------------------------------------------

def _need(name: str, value: str) -> str:
    if not value:
        raise SystemExit(f"{name} is not set")
    return value


def _cli(args: list[str], env: dict[str, str], stdin: str | None = None) -> subprocess.CompletedProcess:
    _need("AMT_SECRETS_CLI", CLI)
    return subprocess.run([sys.executable, str(CLI), *args], env=env, input=stdin,
                          capture_output=True, text=True)


def _main_value(key: str) -> str | None:
    r = _cli(["get", key], dict(os.environ))
    return r.stdout.rstrip("\n") if r.returncode == 0 and r.stdout.strip() else None


def _main_names() -> set[str]:
    r = _cli(["list"], dict(os.environ))
    if r.returncode != 0:
        raise SystemExit(f"main vault list failed (rc {r.returncode})")
    return {line.split("❯", 1)[1].split()[0] for line in r.stdout.splitlines() if "❯" in line}


# -- the NAS ---------------------------------------------------------------------------------

def _ssh_argv(remote: str) -> list[str]:
    _need("AMT_ADMIN_DEPLOY_DIR", NAS_DIR)
    raw = _main_value(_need("AMT_ADMIN_SSH_ENTRY", SSH_ENTRY))
    if raw is None:
        raise SystemExit(f"vault entry {SSH_ENTRY} missing")
    entry = json.loads(raw)
    return [*shlex.split(entry["ssh_cmd"]), "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
            f"{entry['user']}@{entry['host']}", remote]


def _nas(remote: str, stdin: bytes | str | None = None) -> str:
    text = not isinstance(stdin, bytes)
    r = subprocess.run(_ssh_argv(remote), input=stdin, capture_output=True, text=text)
    if r.returncode != 0:
        err = r.stderr if text else r.stderr.decode(errors="replace")
        raise SystemExit(f"NAS command failed (rc {r.returncode}): {err.strip()[-200:]}")
    return r.stdout if text else r.stdout.decode(errors="replace")


def read_devices() -> dict[str, amt_registry.Device]:
    out = _nas(f"cat {DEVICES_PATH} 2>/dev/null || echo MISSING")
    if out.strip() == "MISSING":
        raise SystemExit(f"no devices file on the NAS yet ({DEVICES_PATH}); run: device init")
    _READ["sha256"] = hashlib.sha256(out.encode()).hexdigest()
    return amt_registry.devices_from_json(out)


_READ: dict[str, str] = {}      # sha256 of the devices file as read_devices saw it


def _unchanged() -> str:
    """Shell guard, run under the lock: refuse when the file changed since read_devices (the
    console's amt_device_manage may have written it meanwhile). Empty for device init."""
    want = _READ.get("sha256")
    if not want:
        return ""
    return (f"set -- $(sha256sum devices.json); [ \"$1\" = {want} ] || "
            "{ echo devices.json changed since it was read, run the command again >&2; exit 3; }; ")


def write_devices(devices: dict[str, amt_registry.Device]) -> None:
    text = amt_registry.devices_to_json(devices)
    amt_registry.devices_from_json(text)          # never write a file the server would refuse
    # flock on the same .devices.lock the container's amt_device_manage takes, so the two writers
    # never interleave; the lock file sits beside devices.json.
    _nas(f"set -e; mkdir -p {NAS_DIR}/config; chmod 755 {NAS_DIR}/config; cd {NAS_DIR}/config; "
         f"flock {amt_fleet.LOCK_NAME} sh -c '{_unchanged()}cat > .devices.json.new; chmod 644 .devices.json.new; "
         "[ -f devices.json ] && cp -p devices.json .prev-devices.json; mv -f .devices.json.new devices.json'",
         text)


# -- TLS pin ---------------------------------------------------------------------------------

presented_pin = amt_fleet.presented_pin     # one probe for both writers; tests replace it here


# -- vault group -----------------------------------------------------------------------------

def wanted_keys(devices: dict[str, amt_registry.Device], names: set[str]) -> list[str]:
    """The entries the servers read, in registry order, that exist in the main vault."""
    out: list[str] = []
    for dev in devices.values():
        for key in (dev.amt_vault_key, dev.host_vault_key, f"{dev.amt_vault_key}-rfb"):
            if key and key in names and key not in out:
                out.append(key)
        out += sorted(n for n in names if n.startswith(f"{dev.key}-amt-user-") and n not in out)
    return out


# Runs inside the container, both scripts: they use its own vault CLI (AMT_SECRETS_CLI).
_LIST = r"""
import os, re, subprocess, sys
cli = os.environ["AMT_SECRETS_CLI"]
def entries():
    # name -> (source, updated) for every entry in the container's vault, from its list lines
    listing = subprocess.run([sys.executable, cli, "list"], capture_output=True, text=True).stdout
    out = {}
    for line in listing.splitlines():
        words = line.split("❯", 1)[1].split() if "❯" in line else []
        if words:
            rest = " ".join(words[1:])
            m = re.search(r"updated: (\S+)", rest)
            out[words[0]] = ("console" if "source: console" in rest else "main", m.group(1) if m else None)
    return out
def value(key):
    r = subprocess.run([sys.executable, cli, "get", key], capture_output=True, text=True)
    return r.stdout.rstrip("\n") if r.returncode == 0 and r.stdout.strip() else None
"""

# Reads "<key>\t<sha256 or ->" lines on stdin, answers per key and its source ("-": no main value).
_CHECK = _LIST + r"""
import hashlib, json
present = entries()
out = {"extra": {n: s for n, (s, _) in present.items()}}
for line in sys.stdin.read().splitlines():
    key, want = line.split("\t")
    got = value(key)
    source = present.get(key, (None,))[0]
    out[key] = {"source": source, "on_nas": got is not None,
                "matches": None if source == "console" else
                got is not None and hashlib.sha256(got.encode()).hexdigest() == want}
    out["extra"].pop(key, None)
print(json.dumps(out))
"""

# Reads "values" or "names" on stdin; prints the console-sourced entries (with their values for "values").
_CARRY = _LIST + r"""
import json
want_values = sys.stdin.read().strip() == "values"
out = {}
for name, (source, updated) in entries().items():
    if source != "console":
        continue
    out[name] = {"updated": updated}
    if want_values:
        v = value(name)
        if v is None:
            sys.exit("console entry " + name + " has no readable value; nothing changed")
        out[name]["value"] = v
print(json.dumps(out))
"""


def console_entries(values: bool) -> dict[str, dict]:
    """The console-sourced entries in the container's vault: name -> {updated[, value]}. A value
    stays in the returned dict; nothing here prints it. No vault file on the NAS yet means none."""
    vault = f"{NAS_DIR}/vault/{FILES[0]}"
    remote = (f"[ -f {vault} ] || {{ echo '{{}}'; exit 0; }}; "
              f"PATH=/usr/local/bin:$PATH docker exec -i {CONTAINER} python3 -c " + shlex.quote(_CARRY))
    out = _nas(remote, "values\n" if values else "names\n")
    try:
        return json.loads(out)
    except ValueError:
        raise SystemExit("the container's console entry list was unreadable; nothing changed") from None


def known_names() -> set[str]:
    """Every entry a device may name: the main vault's and the console-sourced ones in the NAS vault."""
    return _main_names() | set(console_entries(values=False))


def vault_status(keys: list[str]) -> dict:
    """Per key: ``source`` (main or console), ``on_nas`` and ``matches`` (the NAS value equals the main
    vault's; None for a console entry, which the main vault does not own). ``extra`` maps the NAS
    entries no server names to their source. A key with no main value is sent as ``-``."""
    lines = []
    for key in keys:
        value = _main_value(key)
        lines.append(f"{key}\t{hashlib.sha256(value.encode()).hexdigest() if value is not None else '-'}")
    remote = f"PATH=/usr/local/bin:$PATH docker exec -i {CONTAINER} python3 -c " + shlex.quote(_CHECK)
    return json.loads(_nas(remote, "\n".join(lines) + "\n"))


def status_ok(out: dict, keys: list[str]) -> bool:
    """A main entry must match the main vault; a console entry only has to be on the NAS."""
    return all(out[k]["on_nas"] and (out[k]["source"] == "console" or out[k]["matches"]) for k in keys)


def _build(keys: list[str], directory: Path, carried: dict[str, dict]) -> None:
    env = {k: v for k, v in os.environ.items() if k != "SECRETS_KEY"}
    env.update(NVAULT_VAULT_PATH=str(directory / FILES[0]), NVAULT_MASTER_KEY_FILE=str(directory / FILES[1]),
               NVAULT_KEYCHAIN_SERVICE="amt-mcp-dedicated-vault-unused")
    if _cli(["init"], env).returncode != 0:
        raise SystemExit("dedicated vault init failed")
    for key in keys:
        value = _main_value(key)
        r = _cli(["set", key, "--expires", EXPIRES, "--notes", NOTES], env, stdin=value + "\n")
        value = ""
        if r.returncode != 0:
            raise SystemExit(f"dedicated vault set {key} failed (rc {r.returncode})")
    for key, entry in carried.items():      # the console's entries, values on the child's stdin only
        notes = f"{SOURCE_NOTE}; updated: {entry['updated']}" if entry.get("updated") else SOURCE_NOTE
        r = _cli(["set", key, "--expires", EXPIRES, "--notes", notes], env, stdin=entry["value"] + "\n")
        entry["value"] = ""
        if r.returncode != 0:
            raise SystemExit(f"dedicated vault set {key} failed (rc {r.returncode})")


def vault_sync(keys: list[str]) -> None:
    """Rebuild the NAS vault: the main entries in ``keys`` plus every console entry now in it. A key
    that is also a console entry stays the console's."""
    carried = console_entries(values=True)
    keys = [k for k in keys if k not in carried]
    if not keys and not carried:
        raise SystemExit("no server's vault entry exists in the main vault; refusing to build an empty vault")
    with tempfile.TemporaryDirectory(prefix="amt-nas-vault-") as tmp:
        d = Path(tmp)
        os.chmod(d, 0o700)
        _build(keys, d, carried)
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            for name in FILES:
                info = tar.gettarinfo(str(d / name), arcname=f".new-{name}")
                info.mode = 0o600
                with open(d / name, "rb") as fh:
                    tar.addfile(info, fh)
    # Rename each file over the old one inside the mounted directory: the container keeps the
    # directory's inode, so it sees the new files without a restart. The directory and files stay
    # writable by their owner (0700 / 0600), the container's user, because amt_identity_manage's
    # intake writes the console's entries into this vault. The pair being replaced stays as
    # .prev-<name> for a rollback (rename them back).
    _nas(f"set -e; cd {NAS_DIR}/vault; chmod 700 .; tar -x -f -; "
         + "; ".join(f"cp -p {n} .prev-{n}; chmod 600 .new-{n}; mv -f .new-{n} {n}" for n in FILES)
         + "; chmod 700 .", buf.getvalue())


def _sync_and_report(devices: dict[str, amt_registry.Device]) -> int:
    keys = wanted_keys(devices, known_names())
    vault_sync(keys)
    out = vault_status(keys)
    print(json.dumps({"vault": out}))
    return 0 if status_ok(out, keys) else 1


# -- console group ---------------------------------------------------------------------------

def mint_enroll_code() -> tuple[str, str]:
    """A new code and its SHA-256 (of the 12 characters; the display's dashes are not part of it)."""
    code = "".join(secrets.choice(ENROLL_ALPHABET) for _ in range(ENROLL_LENGTH))
    return code, hashlib.sha256(code.encode()).hexdigest()


def deliver_enroll(digest: str, expires: int) -> None:
    """Put the hash and expiry where the console watches, 0600, over the ssh path every other command
    uses. The hash goes on stdin; the code itself never leaves this process except to the terminal.
    A pending code is replaced."""
    folder = ENROLL_PATH.rsplit("/", 1)[0]
    _nas(f"set -e; umask 077; mkdir -p {folder}; cd {folder}; cat > .enroll.json.new; "
         "chmod 600 .enroll.json.new; mv -f .enroll.json.new enroll.json",
         json.dumps({"sha256": digest, "expires": expires}) + "\n")


def console_enroll_code() -> int:
    code, digest = mint_enroll_code()
    expires = int(time.time()) + ENROLL_MINUTES * 60
    deliver_enroll(digest, expires)             # nothing is shown for a code the console cannot check
    print(json.dumps({"enroll": {"delivered": ENROLL_PATH, "expires": expires, "valid_minutes": ENROLL_MINUTES,
                                 "uses": 1}}))
    print(f"enrollment code (shown once): {code[0:4]}-{code[4:8]}-{code[8:12]}")
    return 0


# -- device group ----------------------------------------------------------------------------

def _public(dev: amt_registry.Device) -> dict:
    return {f: v for f, v in dataclasses.asdict(dev).items()}


def _plan(fn, *args, **kw):
    """Run one shared amt_fleet rule; its refusal ends the command with nothing written."""
    try:
        return fn(*args, **kw)
    except ValueError as ex:
        raise SystemExit(str(ex)) from None


WHERE_KEYS = "the main vault or the console's identities"


def device_add(devices, key, ip, amt_vault_key, host_vault_key, wsman_port, kvm_port, pin) -> amt_registry.Device:
    return _plan(amt_fleet.plan_add, devices, key, ip, amt_vault_key, host_vault_key, wsman_port,
                 kvm_port, pin, known_names(), WHERE_KEYS,
                 probe=presented_pin)


def device_edit(dev: amt_registry.Device, changes: dict, repin: bool) -> amt_registry.Device:
    return _plan(amt_fleet.plan_edit, dev, changes, repin, known_names(),
                 WHERE_KEYS, probe=presented_pin)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="amt_admin.py", description=__doc__.split("\n\n")[0])
    groups = parser.add_subparsers(dest="group", required=True)
    dev_p = groups.add_parser("device").add_subparsers(dest="action", required=True)
    dev_p.add_parser("list")
    dev_p.add_parser("init")
    add = dev_p.add_parser("add")
    add.add_argument("key")
    add.add_argument("--ip", required=True)
    add.add_argument("--amt-vault-key", required=True)
    add.add_argument("--host-vault-key")
    add.add_argument("--wsman-port", type=int, default=16993)
    add.add_argument("--kvm-port", type=int, default=16995)
    add.add_argument("--pin")
    edit = dev_p.add_parser("edit")
    edit.add_argument("key")
    edit.add_argument("--ip")
    edit.add_argument("--amt-vault-key")
    host = edit.add_mutually_exclusive_group()
    host.add_argument("--host-vault-key")
    host.add_argument("--no-host", action="store_true")
    edit.add_argument("--wsman-port", type=int)
    edit.add_argument("--kvm-port", type=int)
    edit.add_argument("--repin", action="store_true")
    dev_p.add_parser("remove").add_argument("key")
    dev_p.add_parser("pin").add_argument("key")
    vault_p = groups.add_parser("vault").add_subparsers(dest="action", required=True)
    for name in ("keys", "status", "sync"):
        vault_p.add_parser(name)
    console_p = groups.add_parser("console").add_subparsers(dest="action", required=True)
    console_p.add_parser("enroll-code")
    a = parser.parse_args(argv)

    if a.group == "console":
        return console_enroll_code()
    if a.group == "device" and a.action == "init":
        if _nas(f"[ -f {DEVICES_PATH} ] && echo EXISTS || echo NONE").strip() == "EXISTS":
            raise SystemExit("a devices file already exists on the NAS; nothing written")
        write_devices(dict(amt_registry.DEVICES))
        print(json.dumps({"written": sorted(amt_registry.DEVICES)}))
        return 0
    devices = read_devices()
    if a.group == "vault":
        keys = wanted_keys(devices, known_names())
        if a.action == "keys":
            print(json.dumps({"keys": keys}))
            return 0
        if a.action == "sync":
            vault_sync(keys)
        out = vault_status(keys)
        print(json.dumps(out))
        return 0 if status_ok(out, keys) else 1
    if a.action == "list":
        print(json.dumps({"devices": [_public(d) for d in devices.values()]}, indent=2))
        return 0
    if a.action == "pin":
        if a.key not in devices:
            raise SystemExit(f"no device {a.key}")
        out = _plan(amt_fleet.pin_check, devices[a.key], probe=presented_pin)
        print(json.dumps(out))
        return 0 if out["matches"] else 1
    if a.action == "add":
        devices[a.key] = device_add(devices, a.key, a.ip, a.amt_vault_key, a.host_vault_key,
                                    a.wsman_port, a.kvm_port, a.pin)
    elif a.action == "edit":
        if a.key not in devices:
            raise SystemExit(f"no device {a.key}")
        changes = {k: v for k, v in {"amt_ip": a.ip, "amt_vault_key": a.amt_vault_key,
                                     "host_vault_key": a.host_vault_key, "wsman_port": a.wsman_port,
                                     "kvm_port": a.kvm_port}.items() if v is not None}
        if a.no_host:
            changes["host_vault_key"] = None
        devices[a.key] = device_edit(devices[a.key], changes, a.repin)
    elif a.action == "remove":
        devices = _plan(amt_fleet.plan_remove, devices, a.key)
    write_devices(devices)
    print(json.dumps({"devices": sorted(devices),
                      **({"device": _public(devices[a.key])} if a.key in devices else {})}))
    return _sync_and_report(devices)


if __name__ == "__main__":
    sys.exit(main())
