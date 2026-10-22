"""amt_fleet: the amt_devices read tool and the device rules both writers share.

The probe is injected, so no test dials a host. ``deploy/amt_admin.py`` uses the same plan_*
functions (``tests/test_amt_admin.py`` drives them through its command line).
"""
from __future__ import annotations

import asyncio
import dataclasses

import pytest

import amt_fleet
import amt_registry

ULTRA = amt_registry.DEVICES["my-server-1"]
PIN_B = "b" * 64
NAMES = {"my-server-1-amt", "my-server-1-os", "lab-amt"}


def probe(ip, port):
    return ULTRA.tls_leaf_sha256 if ip == ULTRA.amt_ip else PIN_B


def test_list_and_show_report_every_field_and_no_value(monkeypatch):
    monkeypatch.delenv(amt_registry.DEVICES_FILE_ENV, raising=False)
    out = asyncio.run(amt_fleet.amt_devices(action="list"))
    assert out["source"] == "built-in"
    row = next(d for d in out["devices"] if d["key"] == "my-server-1")
    assert row == {**dataclasses.asdict(ULTRA), "pinned": True}
    shown = asyncio.run(amt_fleet.amt_devices(action="show", device="my-server-1"))
    assert shown["device"] == row


def test_show_and_pin_check_need_a_known_device():
    with pytest.raises(ValueError, match="amt_devices_show_needs_device"):
        amt_fleet.devices_read("show", None)
    with pytest.raises(KeyError, match="unknown_device:nope"):
        amt_fleet.devices_read("pin_check", "nope")


def test_pin_check_compares_the_presented_leaf(monkeypatch):
    monkeypatch.setattr(amt_fleet, "presented_pin", probe)
    assert amt_fleet.pin_check(ULTRA, probe)["matches"] is True
    moved = dataclasses.replace(ULTRA, amt_ip="198.51.100.127")
    out = amt_fleet.pin_check(moved, probe)
    assert out == {"device": "my-server-1", "presented": PIN_B, "stored": ULTRA.tls_leaf_sha256,
                   "matches": False}


def test_add_pins_the_presented_leaf_and_refuses_a_missing_vault_key():
    lab = amt_fleet.plan_add({"my-server-1": ULTRA}, "lab", "198.51.100.200", "lab-amt", None,
                             16993, 16995, None, NAMES, "the server's vault", probe)
    assert lab.tls_leaf_sha256 == PIN_B and lab.tls_leaf_observed_prefix == PIN_B[:16]
    with pytest.raises(ValueError, match="vault nope-amt in the server's vault first"):
        amt_fleet.plan_add({}, "lab", "198.51.100.200", "nope-amt", None, 16993, 16995, None,
                           NAMES, "the server's vault", probe)
    with pytest.raises(ValueError, match="not the given pin"):
        amt_fleet.plan_add({}, "lab", "198.51.100.200", "lab-amt", None, 16993, 16995, "c" * 64,
                           NAMES, "x", probe)
    with pytest.raises(ValueError, match="exists"):
        amt_fleet.plan_add({"lab": lab}, "lab", "198.51.100.200", "lab-amt", None, 16993, 16995, None,
                           NAMES, "x", probe)


def test_edit_rechecks_the_leaf_only_on_an_address_change():
    calls = []
    counting = lambda ip, port: (calls.append(ip), probe(ip, port))[1]
    same = amt_fleet.plan_edit(ULTRA, {"host_vault_key": None}, False, NAMES, "x", counting)
    assert same.host_vault_key is None and calls == []
    with pytest.raises(ValueError, match="not the stored pin"):
        amt_fleet.plan_edit(ULTRA, {"amt_ip": "198.51.100.127"}, False, NAMES, "x", counting)
    moved = amt_fleet.plan_edit(ULTRA, {"amt_ip": "198.51.100.127"}, True, NAMES, "x", counting)
    assert moved.tls_leaf_sha256 == PIN_B
    with pytest.raises(ValueError, match="not editable"):
        amt_fleet.plan_edit(ULTRA, {"tls_leaf_sha256": PIN_B}, False, NAMES, "x", counting)


def test_remove_refuses_the_last_and_an_unknown_device():
    with pytest.raises(ValueError, match="last device"):
        amt_fleet.plan_remove({"my-server-1": ULTRA}, "my-server-1")
    with pytest.raises(ValueError, match="no device lab"):
        amt_fleet.plan_remove({"my-server-1": ULTRA}, "lab")


# -- amt_device_manage: the in-container writer ----------------------------------------------

@pytest.fixture
def devfile(tmp_path, monkeypatch):
    path = tmp_path / "config" / "devices.json"
    path.parent.mkdir()
    path.write_text(amt_registry.devices_to_json({"my-server-1": ULTRA}))
    monkeypatch.setenv(amt_registry.DEVICES_FILE_ENV, str(path))
    monkeypatch.setattr(amt_registry, "DEVICES", dict(amt_registry.DEVICES))
    monkeypatch.setitem(amt_registry._LOADED, "mtime", None)
    monkeypatch.setattr(amt_fleet, "presented_pin", probe)
    monkeypatch.setattr(amt_fleet.amt_vault, "vault_names", lambda: set(NAMES))
    return path


def _file(path):
    return amt_registry.devices_from_json(path.read_text())


def test_manage_refuses_without_confirmed_and_writes_nothing(devfile):
    import amt_tools
    before = devfile.read_text()
    with pytest.raises(amt_tools.ConfirmationRequired):
        asyncio.run(amt_fleet.amt_device_manage(action="remove", device="my-server-1"))
    assert devfile.read_text() == before


def test_add_edit_remove_round_trip_and_are_live_at_the_next_call(devfile):
    out = asyncio.run(amt_fleet.amt_device_manage(action="add", device="lab", ip="198.51.100.200",
                                                  amt_vault_key="lab-amt", confirmed=True))
    assert out["added"]["tls_leaf_sha256"] == PIN_B and out["devices"] == ["lab", "my-server-1"]
    assert amt_registry.get_device("lab").amt_ip == "198.51.100.200", "the server sees it at once"
    assert (devfile.parent / ".prev-devices.json").exists()
    out = amt_fleet.device_manage("edit", "lab", kvm_port=16996)
    assert out["edited"]["kvm_port"] == 16996 and out["edited"]["tls_leaf_sha256"] == PIN_B
    assert amt_fleet.device_manage("remove", "lab")["devices"] == ["my-server-1"]
    assert set(_file(devfile)) == {"my-server-1"}
    assert (devfile.stat().st_mode & 0o777) == 0o644


@pytest.mark.parametrize("call,err", [
    (lambda: amt_fleet.device_manage("add", "lab", ip="198.51.100.200", amt_vault_key="nope-amt"),
     "vault nope-amt in this server's vault"),
    (lambda: amt_fleet.device_manage("add", "lab", ip="198.51.100.200", amt_vault_key="lab-amt",
                                     expected_pin="c" * 64), "not the given pin"),
    (lambda: amt_fleet.device_manage("edit", "my-server-1", ip="198.51.100.127"), "not the stored pin"),
    (lambda: amt_fleet.device_manage("edit", "my-server-1"), "needs_a_change_or_repin"),
    (lambda: amt_fleet.device_manage("edit", "nope", kvm_port=1), "no device nope"),
    (lambda: amt_fleet.device_manage("remove", "my-server-1"), "last device"),
    (lambda: amt_fleet.device_manage("add", "lab"), "needs_ip_and_amt_vault_key"),
])
def test_every_refusal_leaves_the_file_untouched(devfile, call, err):
    before = devfile.read_bytes()
    with pytest.raises(ValueError, match=err):
        call()
    assert devfile.read_bytes() == before
    assert not (devfile.parent / ".devices.json.new").exists()


def test_repin_accepts_a_changed_leaf(devfile):
    out = amt_fleet.device_manage("edit", "my-server-1", ip="198.51.100.127", repin=True)
    assert out["edited"]["tls_leaf_sha256"] == PIN_B


def test_without_a_devices_file_changes_are_refused(monkeypatch):
    monkeypatch.delenv(amt_registry.DEVICES_FILE_ENV, raising=False)
    with pytest.raises(ValueError, match="device changes need AMT_DEVICES_FILE"):
        amt_fleet.device_manage("remove", "x")


def test_the_writer_holds_the_lock_another_writer_takes(devfile):
    """A second writer holding .devices.lock makes the tool wait, not interleave."""
    import fcntl
    import threading
    import time
    lock = open(devfile.parent / amt_fleet.LOCK_NAME, "a")
    fcntl.flock(lock, fcntl.LOCK_EX)
    done = []
    t = threading.Thread(target=lambda: done.append(amt_fleet.device_manage("edit", "my-server-1", kvm_port=16996)))
    t.start()
    time.sleep(0.3)
    assert not done, "the tool wrote while another writer held the lock"
    fcntl.flock(lock, fcntl.LOCK_UN)
    lock.close()
    t.join(5)
    assert done and _file(devfile)["my-server-1"].kvm_port == 16996
