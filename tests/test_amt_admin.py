"""deploy/amt_admin.py: the deployment's servers and the identities they use, in one command set.

Every subprocess the script starts is recorded by a fake ``subprocess.run`` and the NAS is a
dict, so the tests prove no secret value reaches an argv, a value crosses to the NAS only as a
SHA-256 on stdin (vault status) or inside the vault files (vault sync), and every device change
writes a devices file the server's own parser accepts.
"""
from __future__ import annotations

import dataclasses
import hashlib
import importlib.util
import io
import json
import os
import shlex
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

import amt_registry
import amt_upload

REAL_RUN = subprocess.run           # the container scripts run for real, against the fake CLI below

REPO = Path(__file__).resolve().parent.parent
spec = importlib.util.spec_from_file_location("amt_admin", REPO / "deploy" / "amt_admin.py")
admin = importlib.util.module_from_spec(spec)
spec.loader.exec_module(admin)
# The site values come from the environment in real use; the tests name a throwaway deploy layout.
admin.CLI, admin.NAS_DIR, admin.SSH_ENTRY = "secrets.py", "/srv/amt-mcp", "nas-ssh"
admin.DEVICES_PATH, admin.ENROLL_PATH = f"{admin.NAS_DIR}/config/devices.json", f"{admin.NAS_DIR}/console-data/enroll.json"

SECRET = {"my-server-1-amt": "Amt-Sentinel-41", "my-server-1-os": '{"user":"admin","password":"Deb-Sentinel-42"}',
          "my-server-1-amt-rfb": "Rfb-Sentinel-43", "my-server-1-amt-user-ops": "User-Sentinel-44",
          "lab-amt": "Lab-Sentinel-46",
          "nas-ssh": json.dumps({"ssh_cmd": "ssh -o IdentityAgent=none", "user": "deploy", "host": "nas.test"}),
          "unrelated-key": "Other-Sentinel-45"}
VALUES = [v for k, v in SECRET.items() if k != "nas-ssh"]
ULTRA = amt_registry.DEVICES["my-server-1"]
PIN_B = "b" * 64
CONSOLE_SENTINEL = "Console-Sentinel-47"
CONSOLE_NOTES = f"{amt_upload.SOURCE_NOTE}; updated: 2026-10-20T10:00:00Z"
MAIN_NOTES = "amt-mcp dedicated vault copy (deploy/amt_admin.py vault sync)"

# The container's vault CLI: reads a JSON file {name: {value, notes}}; list prints the CLI's line shape.
FAKE_CLI = """
import json, os, sys
store = json.load(open(os.environ["FAKE_CONTAINER_VAULT"]))
if sys.argv[1] == "list":
    for name, e in store.items():
        print(f" \U0001F511  credential \u276f {name}  {e['notes']}")
elif sys.argv[1] == "get":
    e = store.get(sys.argv[2])
    if e is None or not e["value"]:
        sys.exit(1)
    print(e["value"])
"""


class Nas:
    """The fake world: the main vault, the NAS files, the container's vault and every subprocess call."""

    def __init__(self, tmp_path, devices_json=None, container=None):
        self.calls, self.files, self.vault_file_exists, self.built = [], {}, True, {}
        if devices_json is not None:
            self.files[admin.DEVICES_PATH] = devices_json
        self.container = container if container is not None else {
            k: {"value": SECRET[k], "notes": MAIN_NOTES}
            for k in ("my-server-1-amt", "my-server-1-os", "my-server-1-amt-rfb", "my-server-1-amt-user-ops")}
        self.cli = tmp_path / "container_cli.py"
        self.cli.write_text(FAKE_CLI)
        self.store = tmp_path / "container_vault.json"

    def __call__(self, argv, input=None, capture_output=False, text=False, env=None, **kw):
        self.calls.append({"argv": list(argv), "input": input, "env": env})
        ok = lambda out="": subprocess.CompletedProcess(argv, 0, out if text else out.encode(), "" if text else b"")
        if argv[0] == sys.executable:
            verb = argv[2]
            if verb == "get":
                v = SECRET.get(argv[3])
                return subprocess.CompletedProcess(argv, 0 if v else 1, (v + "\n") if v else "", "")
            if verb == "list":
                return ok("".join(f" \U0001F511  credential \u276f {k}  note\n" for k in SECRET))
            if verb == "set":
                self.built[argv[3]] = {"value": input.rstrip("\n"), "notes": argv[argv.index("--notes") + 1]}
            if verb == "init":
                self.built = {}
                for name in admin.FILES:
                    Path(env["NVAULT_VAULT_PATH"]).parent.joinpath(name).write_bytes(b"x")
            return ok()
        assert argv[0] == "ssh"
        remote = argv[-1]
        if "docker exec" in remote:           # the real container script, against the fake container vault
            if remote.startswith("[ -f ") and not self.vault_file_exists:
                return ok("{}\n")
            toks = shlex.split(remote)
            self.store.write_text(json.dumps(self.container))
            done = REAL_RUN([sys.executable, "-c", toks[toks.index("-c") + 1]], input=input, text=True,
                            capture_output=True, env={**os.environ, "AMT_SECRETS_CLI": str(self.cli),
                                                      "FAKE_CONTAINER_VAULT": str(self.store)})
            return subprocess.CompletedProcess(argv, done.returncode, done.stdout, done.stderr) \
                if done.returncode == 0 else subprocess.CompletedProcess(argv, done.returncode, "", done.stderr)
        if remote.startswith("cat "):
            return ok(self.files.get(admin.DEVICES_PATH, "MISSING\n"))
        if remote.startswith("[ -f "):
            return ok("EXISTS\n" if admin.DEVICES_PATH in self.files else "NONE\n")
        if "devices.json.new" in remote:
            self.files[admin.DEVICES_PATH] = input
            return ok()
        if "enroll.json" in remote:
            self.files[admin.ENROLL_PATH] = input
            return ok()
        if "tar -x" in remote:           # the rename: the container now holds what was built
            self.files["vault.tar"] = input
            self.container = self.built
            return ok()
        raise AssertionError(remote)

    def sets(self):
        """(key, stdin, notes) of every value written into a dedicated vault being built."""
        return [(c["argv"][3], c["input"], c["argv"][c["argv"].index("--notes") + 1])
                for c in self.calls if c["argv"][0] == sys.executable and c["argv"][2] == "set"]

    def carry_calls(self):
        return [c for c in self.calls if c["argv"][0] == "ssh" and c["input"] in ("values\n", "names\n")]


@pytest.fixture
def world(monkeypatch, tmp_path):
    nas = Nas(tmp_path, amt_registry.devices_to_json({"my-server-1": ULTRA}))
    monkeypatch.setattr(admin.subprocess, "run", nas)
    monkeypatch.setattr(admin, "presented_pin", lambda ip, port: ULTRA.tls_leaf_sha256 if ip == ULTRA.amt_ip else PIN_B)
    return nas


def _no_value_in_any_argv(nas):
    for call in nas.calls:
        blob = " ".join(call["argv"])
        assert not [v for v in VALUES if v in blob], call["argv"][:4]


def _devices(nas):
    return amt_registry.devices_from_json(nas.files[admin.DEVICES_PATH])


# -- the registry file -----------------------------------------------------------------------

def test_the_devices_file_round_trips_and_rejects_unknown_fields():
    text = amt_registry.devices_to_json({"my-server-1": ULTRA})
    assert amt_registry.devices_from_json(text) == {"my-server-1": ULTRA}
    bad = json.loads(text)
    bad["devices"]["my-server-1"]["password"] = "x"
    with pytest.raises(ValueError, match="malformed"):
        amt_registry.devices_from_json(json.dumps(bad))
    with pytest.raises(ValueError):
        amt_registry.Device(key="x", amt_ip="not-an-ip", wsman_port=16993, kvm_port=16995, amt_vault_key="x-amt")


def test_the_server_reads_the_devices_file_live_and_fails_closed(tmp_path, monkeypatch):
    path = tmp_path / "devices.json"
    lab = dataclasses.replace(ULTRA, key="lab", amt_ip="198.51.100.200", amt_vault_key="lab-amt", host_vault_key=None)
    path.write_text(amt_registry.devices_to_json({"lab": lab}))
    monkeypatch.setenv(amt_registry.DEVICES_FILE_ENV, str(path))
    monkeypatch.setattr(amt_registry, "DEVICES", dict(amt_registry.DEVICES))
    monkeypatch.setitem(amt_registry._LOADED, "mtime", None)
    assert amt_registry.get_device("lab").amt_ip == "198.51.100.200"
    with pytest.raises(KeyError):
        amt_registry.get_device("my-server-1")       # the file replaces the built-in list
    path.write_text("{not json")
    import os
    os.utime(path, ns=(1, 1))
    with pytest.raises(RuntimeError, match="devices_file_unusable"):
        amt_registry.get_device("lab")


# -- vault group -----------------------------------------------------------------------------

def test_wanted_keys_come_from_the_devices_and_exist_in_the_main_vault():
    keys = admin.wanted_keys({"my-server-1": ULTRA}, set(SECRET))
    assert keys == ["my-server-1-amt", "my-server-1-os", "my-server-1-amt-rfb", "my-server-1-amt-user-ops"]
    assert admin.wanted_keys({"my-server-1": ULTRA}, {"my-server-1-amt"}) == ["my-server-1-amt"]


def test_vault_status_sends_only_hashes(world):
    out = admin.vault_status(["my-server-1-amt", "my-server-1-os"])
    assert out["my-server-1-amt"]["matches"] is True and out["my-server-1-os"]["matches"] is True
    sent = [c["input"] for c in world.calls if c["argv"][0] == "ssh" and "docker exec" in c["argv"][-1]
            and "\t" in c["input"]][0]
    assert not [v for v in VALUES if v in sent]
    _no_value_in_any_argv(world)


def test_vault_sync_ships_exactly_the_wanted_entries_and_restores_the_directory_mode(world):
    keys = ["my-server-1-amt", "my-server-1-os"]
    admin.vault_sync(keys)
    sets = [c for c in world.calls if c["argv"][0] == sys.executable and c["argv"][2] == "set"]
    assert [c["argv"][3] for c in sets] == keys
    assert [c["input"] for c in sets] == [SECRET[k] + "\n" for k in keys], "values go in on stdin only"
    assert all("SECRETS_KEY" not in c["env"] for c in sets)
    assert sorted(tarfile.open(fileobj=io.BytesIO(world.files["vault.tar"])).getnames()) == \
        [f".new-{n}" for n in sorted(admin.FILES)]
    remote = [c for c in world.calls if c["argv"][0] == "ssh"][-1]["argv"][-1]
    assert remote.startswith("set -e;") and remote.rstrip().endswith("chmod 700 .")
    for n in admin.FILES:
        assert f"cp -p {n} .prev-{n}" in remote and f"mv -f .new-{n} {n}" in remote
        assert f"chmod 600 .new-{n}" in remote, "the container writes console intake entries into this vault"
    assert not Path(sets[0]["env"]["NVAULT_VAULT_PATH"]).parent.exists(), "the local build is removed"
    _no_value_in_any_argv(world)


def test_an_empty_key_set_is_refused_before_anything_is_built(world):
    with pytest.raises(SystemExit, match="refusing to build an empty vault"):
        admin.vault_sync([])
    assert not [c for c in world.calls if c["argv"][0] == sys.executable and c["argv"][2] == "init"]


# -- console-sourced entries: merge-aware sync, sources in status, device keys ------------------

def _console_world(world, **extra):
    """The container holds a console entry the main vault does not: lab2-amt, entered through the intake."""
    world.container["lab2-amt"] = {"value": CONSOLE_SENTINEL, "notes": CONSOLE_NOTES}
    world.container.update(extra)
    return world


def test_the_console_marker_and_far_expiry_are_the_ones_the_intake_writes():
    assert admin.SOURCE_NOTE == amt_upload.SOURCE_NOTE and admin.EXPIRES == amt_upload.INTAKE_EXPIRES


def test_sync_keeps_a_console_entry_and_still_refreshes_the_main_entries(world, capsys):
    _console_world(world)
    keys = ["my-server-1-amt", "my-server-1-os"]
    admin.vault_sync(keys)
    sets = world.sets()
    assert [k for k, _, _ in sets] == keys + ["lab2-amt"]
    by_key = {k: (stdin, notes) for k, stdin, notes in sets}
    for k in keys:                                    # main entries: current main value, main notes
        assert by_key[k] == (SECRET[k] + "\n", admin.NOTES)
    stdin, notes = by_key["lab2-amt"]                 # the console entry: its container value, marker and stamp kept
    assert stdin == CONSOLE_SENTINEL + "\n" and notes == CONSOLE_NOTES
    assert world.carry_calls()[0]["input"] == "values\n"
    assert "vault.tar" in world.files
    _no_value_in_any_argv(world)
    for call in world.calls:
        assert CONSOLE_SENTINEL not in " ".join(call["argv"]), "a console value never rides in argv"
    shown = capsys.readouterr()
    assert CONSOLE_SENTINEL not in shown.out + shown.err and not [v for v in VALUES if v in shown.out + shown.err]


def test_sync_of_a_name_in_both_vaults_keeps_the_console_value(world):
    _console_world(world)
    world.container["my-server-1-amt-rfb"] = {"value": CONSOLE_SENTINEL, "notes": CONSOLE_NOTES}
    admin.vault_sync(["my-server-1-amt", "my-server-1-amt-rfb"])
    sets = world.sets()
    assert [k for k, _, _ in sets].count("my-server-1-amt-rfb") == 1
    assert dict((k, s) for k, s, _ in sets)["my-server-1-amt-rfb"] == CONSOLE_SENTINEL + "\n"


def test_sync_of_only_console_entries_is_allowed_and_of_nothing_is_not(world):
    world.container = {"lab2-amt": {"value": CONSOLE_SENTINEL, "notes": CONSOLE_NOTES}}
    admin.vault_sync([])
    assert [k for k, _, _ in world.sets()] == ["lab2-amt"]


def test_sync_refuses_before_building_when_a_console_entry_cannot_be_read(world):
    _console_world(world)
    world.container["lab2-amt"]["value"] = ""
    with pytest.raises(SystemExit, match="console entry lab2-amt has no readable value"):
        admin.vault_sync(["my-server-1-amt"])
    assert not [c for c in world.calls if c["argv"][0] == sys.executable and c["argv"][2] == "init"]
    assert "vault.tar" not in world.files, "nothing was shipped"


def test_sync_before_the_nas_has_any_vault_has_nothing_to_carry(world):
    world.vault_file_exists = False
    world.container = {}
    admin.vault_sync(["my-server-1-amt"])
    assert [k for k, _, _ in world.sets()] == ["my-server-1-amt"]
    remote = world.carry_calls()[0]["argv"][-1]
    assert remote.startswith(f"[ -f {admin.NAS_DIR}/vault/{admin.FILES[0]} ] ||"), "no vault file: skip docker"


def test_status_reports_each_entrys_source_and_never_asks_the_main_vault_to_match_a_console_entry(world):
    _console_world(world, **{"stray-console": {"value": "x", "notes": CONSOLE_NOTES},
                             "stray-main": {"value": "y", "notes": admin.NOTES}})
    out = admin.vault_status(["my-server-1-amt", "lab2-amt"])
    assert out["my-server-1-amt"] == {"source": "main", "on_nas": True, "matches": True}
    assert out["lab2-amt"] == {"source": "console", "on_nas": True, "matches": None}
    assert out["extra"]["stray-console"] == "console" and out["extra"]["stray-main"] == "main"
    assert admin.status_ok(out, ["my-server-1-amt", "lab2-amt"]) is True
    world.container["my-server-1-amt"]["value"] = "stale"
    stale = admin.vault_status(["my-server-1-amt", "lab2-amt"])
    assert stale["my-server-1-amt"]["matches"] is False
    assert admin.status_ok(stale, ["my-server-1-amt", "lab2-amt"]) is False
    assert admin.status_ok({"k": {"source": "console", "on_nas": False, "matches": None}}, ["k"]) is False
    _no_value_in_any_argv(world)


def test_a_device_may_name_a_console_only_vault_key(world):
    _console_world(world)
    assert "lab2-amt" not in SECRET, "the key exists only as a console entry"
    rc = admin.main(["device", "add", "lab2", "--ip", "198.51.100.201", "--amt-vault-key", "lab2-amt"])
    assert rc == 0 and _devices(world)["lab2"].amt_vault_key == "lab2-amt"
    assert dict((k, s) for k, s, _ in world.sets())["lab2-amt"] == CONSOLE_SENTINEL + "\n", "carried, not re-copied"
    assert [k for k, _, _ in world.sets()].count("lab2-amt") == 1
    assert admin.main(["device", "edit", "my-server-1", "--amt-vault-key", "lab2-amt", "--repin"]) == 0
    assert _devices(world)["my-server-1"].amt_vault_key == "lab2-amt"
    assert admin.main(["vault", "keys"]) == 0


def test_a_device_still_cannot_name_a_key_neither_vault_has(world):
    _console_world(world)
    with pytest.raises(SystemExit, match="vault nope-amt in the main vault or the console's identities"):
        admin.main(["device", "add", "lab2", "--ip", "198.51.100.201", "--amt-vault-key", "nope-amt"])
    with pytest.raises(SystemExit, match="vault nope-amt"):
        admin.main(["device", "edit", "my-server-1", "--amt-vault-key", "nope-amt"])


# -- console enroll-code -----------------------------------------------------------------------

CODE_LINE = "enrollment code (shown once): "


def _enroll(world, capsys, now=1_800_000_000):
    admin.time.time = lambda: now
    rc = admin.main(["console", "enroll-code"])
    shown = capsys.readouterr().out
    line = [l for l in shown.splitlines() if l.startswith(CODE_LINE)]
    return rc, shown, line


@pytest.fixture(autouse=True)
def _real_clock():
    import time
    real = time.time
    yield
    admin.time.time = real


def test_the_alphabet_has_no_look_alikes_and_a_code_is_twelve_characters_from_it():
    assert not set("ILO01") & set(admin.ENROLL_ALPHABET) and len(set(admin.ENROLL_ALPHABET)) == len(admin.ENROLL_ALPHABET)
    assert admin.ENROLL_LENGTH == 12 and admin.ENROLL_MINUTES == 10
    seen = set()
    for _ in range(300):
        code, digest = admin.mint_enroll_code()
        assert len(code) == 12 and set(code) <= set(admin.ENROLL_ALPHABET)
        assert digest == hashlib.sha256(code.encode()).hexdigest()
        seen.add(code)
    assert len(seen) == 300, "codes are drawn at random"


def test_enroll_code_delivers_only_the_hash_and_expiry_on_stdin_and_shows_the_code_once(world, capsys):
    world.files.pop(admin.DEVICES_PATH)               # needs no devices file
    rc, shown, line = _enroll(world, capsys)
    assert rc == 0 and len(line) == 1
    dashed = line[0][len(CODE_LINE):]
    code = dashed.replace("-", "")
    assert [len(g) for g in dashed.split("-")] == [4, 4, 4] and set(code) <= set(admin.ENROLL_ALPHABET)
    delivered = json.loads(world.files[admin.ENROLL_PATH])
    assert delivered == {"sha256": hashlib.sha256(code.encode()).hexdigest(), "expires": 1_800_000_000 + 600}
    assert shown.count(dashed) == 1 and dashed not in shown.splitlines()[0], "printed once, apart from the status"
    assert code not in shown, "the undashed code appears nowhere on stdout, the status line included"
    sends = [c for c in world.calls if c["argv"][0] == "ssh" and "enroll.json" in c["argv"][-1]]
    assert len(sends) == 1
    blob = " ".join(sends[0]["argv"])
    assert delivered["sha256"] not in blob and code not in blob, "neither the hash nor the code rides in argv"
    assert code not in sends[0]["input"] and dashed not in sends[0]["input"]
    remote = sends[0]["argv"][-1]
    assert f"{admin.NAS_DIR}/console-data" in remote and "chmod 600 .enroll.json.new" in remote
    assert remote.rstrip().endswith("mv -f .enroll.json.new enroll.json")
    for call in world.calls:
        assert code not in " ".join(call["argv"]) and code not in str(call["input"] or "")


def test_enroll_code_prints_nothing_when_the_hash_cannot_be_delivered(world, capsys, monkeypatch):
    def refuse(*a, **kw):
        raise SystemExit("NAS command failed (rc 255): connection refused")
    monkeypatch.setattr(admin, "deliver_enroll", refuse)
    with pytest.raises(SystemExit, match="connection refused"):
        admin.main(["console", "enroll-code"])
    assert capsys.readouterr().out == "", "a code the console cannot check is never shown"


def test_each_enroll_code_replaces_the_pending_one(world, capsys):
    first = _enroll(world, capsys)[2][0]
    second = _enroll(world, capsys, now=1_800_000_100)[2][0]
    assert first != second
    assert json.loads(world.files[admin.ENROLL_PATH])["expires"] == 1_800_000_100 + 600


# -- device group ----------------------------------------------------------------------------

def test_add_records_the_presented_pin_writes_a_valid_file_and_syncs_the_vault(world):
    rc = admin.main(["device", "add", "lab", "--ip", "198.51.100.200", "--amt-vault-key", "lab-amt"])
    lab = _devices(world)["lab"]
    assert rc == 0 and lab.tls_leaf_sha256 == PIN_B and lab.tls_leaf_observed_prefix == PIN_B[:16]
    assert set(_devices(world)) == {"my-server-1", "lab"}
    sets = [c["argv"][3] for c in world.calls if c["argv"][0] == sys.executable and c["argv"][2] == "set"]
    assert "lab-amt" in sets and "my-server-1-amt" in sets
    _no_value_in_any_argv(world)


def test_add_refuses_a_leaf_other_than_the_given_pin(world):
    before = world.files[admin.DEVICES_PATH]
    with pytest.raises(SystemExit, match="not the given pin"):
        admin.main(["device", "add", "lab", "--ip", "198.51.100.200", "--amt-vault-key", "lab-amt", "--pin", "c" * 64])
    assert world.files[admin.DEVICES_PATH] == before


def test_add_refuses_a_vault_key_the_main_vault_lacks(world):
    with pytest.raises(SystemExit, match="vault nope-amt in the main vault or the console's identities first"):
        admin.main(["device", "add", "lab", "--ip", "198.51.100.200", "--amt-vault-key", "nope-amt"])


def test_edit_refuses_a_changed_leaf_unless_repin(world):
    with pytest.raises(SystemExit, match="not the stored pin"):
        admin.main(["device", "edit", "my-server-1", "--ip", "198.51.100.127"])
    assert _devices(world)["my-server-1"] == ULTRA
    assert admin.main(["device", "edit", "my-server-1", "--ip", "198.51.100.127", "--repin"]) == 0
    moved = _devices(world)["my-server-1"]
    assert moved.amt_ip == "198.51.100.127" and moved.tls_leaf_sha256 == PIN_B


def test_edit_without_an_address_change_keeps_the_pin_and_can_drop_the_host_key(world):
    assert admin.main(["device", "edit", "my-server-1", "--no-host"]) == 0
    dev = _devices(world)["my-server-1"]
    assert dev.host_vault_key is None and dev.tls_leaf_sha256 == ULTRA.tls_leaf_sha256


def test_remove_refuses_the_last_device(world):
    with pytest.raises(SystemExit, match="last device"):
        admin.main(["device", "remove", "my-server-1"])


def test_init_refuses_to_overwrite_an_existing_file(world):
    with pytest.raises(SystemExit, match="already exists"):
        admin.main(["device", "init"])
