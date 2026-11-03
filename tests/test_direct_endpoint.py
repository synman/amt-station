"""Direct AMT for all traffic: every outbound connection a tool opens goes to a registry host on
16993 (WS-MAN) or 16995 (redirection: KVM, SOL, IDE-R), and nothing else leaves the process.

The test sits on the process's outbound seams instead of the AMT fakes the other suites use:
``socket.create_connection`` (the KVM/redirection engine and, through ``http.client``, the pinned
WS-MAN connection), ``socket.socket.connect`` and ``urllib.request.urlopen``. Each seam records
where a tool tried to go and refuses, so no packet leaves and no host is touched. Every tool is
then driven through the real server dispatch with arguments that reach its network step.
Child processes are recorded too: a tool may start only the OCR and video encoders.

Scope: the seams refuse every connection, so each tool stops at its FIRST dial. This file proves
that first dial, per tool. Dials made after a device answers are covered by
``test_sentinel_password``, whose scripted peers answer the handshake and which checks the
endpoint of every redirection session opened there.

Two outbound paths are not AMT traffic and are dispositioned by name, never by a blanket
allowlist:

* ``amt_images action=fetch`` downloads an operator-given URL into the image root. It is the
  only tool that may reach a non-registry host, and only through ``urlopen``.
* ``amt_mirror._urls`` with a wildcard bind connects a UDP socket to (device, 9) to learn the
  LAN-facing address. A UDP connect sends no packet; the test asserts nothing is sent on it.
"""
from __future__ import annotations

import asyncio
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request

import pytest

import amt_gate
import amt_kvm
import amt_mirror
import amt_registry
import amt_serial
import amt_server
import amt_vault

DEV = amt_registry.get_device("my-server-1")
# Literal ports, never read back from the registry: a registry edit must not move the target.
AMT_ENDPOINTS = {(DEV.amt_ip, 16993), (DEV.amt_ip, 16995)}
FETCH_URL = "http://images.example.invalid/x.iso"
# Executables a tool may start: the OCR backend and the recording encoder. None of them dials out.
ALLOWED_CHILDREN = {"tesseract", "ffmpeg", "ffprobe"}
INET = (socket.AF_INET, socket.AF_INET6)


class Recorder:
    """The process's outbound seams. Every attempt is recorded, then refused."""

    def __init__(self):
        self.tcp: list[tuple[str, int]] = []
        self.sock: list[tuple[int, int, tuple]] = []
        self.sent_on_sock = 0
        self.urls: list[str] = []
        self.children: list[str] = []

    def install(self, monkeypatch):
        rec = self
        real_connect = socket.socket.connect

        def create_connection(address, *a, **k):
            rec.tcp.append((address[0], int(address[1])))
            raise ConnectionRefusedError(111, "refused by the test seam")

        def sock_connect(s, address):
            rec.sock.append((s.family, s.type, tuple(address) if isinstance(address, tuple) else (address,)))
            if s.family not in INET:
                return real_connect(s, address)
            if s.type == socket.SOCK_DGRAM:
                return real_connect(s, address)       # a UDP connect sends nothing on the wire
            raise ConnectionRefusedError(111, "refused by the test seam")

        def sock_connect_ex(s, address):
            try:
                sock_connect(s, address)
                return 0
            except ConnectionRefusedError:
                return 111

        def guard(real):
            # Any send on an internet socket is counted and refused. The event loop's own
            # self-pipe is an AF_UNIX socketpair and keeps working.
            def send(s, *a, **k):
                if s.family in INET:
                    rec.sent_on_sock += 1
                    raise OSError("send refused by the test seam")
                return real(s, *a, **k)
            return send

        def urlopen(url, *a, **k):
            rec.urls.append(url if isinstance(url, str) else url.full_url)
            raise urllib.error.URLError("refused by the test seam")

        class Popen(subprocess.Popen):
            def __init__(self, args, *a, **k):
                first = args if isinstance(args, str) else args[0]
                rec.children.append(os.path.basename(str(first)).split()[0])
                super().__init__(args, *a, **k)

        monkeypatch.setattr(socket, "create_connection", create_connection)
        monkeypatch.setattr(socket.socket, "connect", sock_connect)
        monkeypatch.setattr(socket.socket, "connect_ex", sock_connect_ex)
        for attr in ("send", "sendall", "sendto", "sendmsg", "sendfile"):
            monkeypatch.setattr(socket.socket, attr, guard(getattr(socket.socket, attr)))
        monkeypatch.setattr(urllib.request, "urlopen", urlopen)
        monkeypatch.setattr(subprocess, "Popen", Popen)
        return self


def fake_vault(key: str) -> str:
    if key == DEV.host_vault_key:
        return json.dumps({"user": "endpoint-test-user", "password": "endpoint-test-host-pw"})
    return "endpoint-test-amt-pw"


def call(name: str, args: dict) -> str:
    """Dispatch one tool through the real server and return its result or error as text."""
    try:
        out = asyncio.run(amt_server.mcp.call_tool(name, args))
    except Exception as ex:               # a tool error is a legitimate outcome here
        return f"ERROR {type(ex).__name__}: {ex}"
    return json.dumps(out, default=str)


def _image_root(tmp_path, monkeypatch):
    root = tmp_path / "images"
    root.mkdir()
    (root / "x.iso").write_bytes(b"\0" * 4096)
    monkeypatch.setenv("AMT_IMAGE_ROOT", str(root))
    return root


# Arguments that carry each tool to its network step. Write tools need confirmed=True to get
# past their guard; the mirror and serial pages bind a free loopback port (a listen, not an
# outbound connection) and are stopped afterwards.
NETWORK_CALLS = [
    ("amt_status", {}),
    ("amt_screenshot", {}),
    ("amt_inventory", {}),
    ("amt_logs", {"kind": "event"}),
    ("amt_settings", {"area": "network"}),
    ("amt_wsman_get", {"class_name": "AMT_GeneralSettings"}),
    ("amt_remote_logon", {"confirmed": True}),
    ("amt_remote_logoff", {"confirmed": True}),
    ("amt_power", {"action": "restart", "confirmed": True}),
    ("amt_set_next_boot", {"target": "bios_setup", "confirmed": True}),
    ("amt_console_input", {"actions": [{"kind": "key", "key": "esc"}], "confirmed": True}),
    ("amt_sol", {"text": "", "read_seconds": 0.1, "confirmed": True}),
    ("amt_ider", {"action": "mount", "iso_path": "x.iso", "confirmed": True}),
    ("amt_configure", {"area": "network", "changes": {"PingResponseEnabled": True}, "confirmed": True}),
    ("amt_wsman_invoke", {"operation": "invoke", "class_name": "AMT_GeneralSettings",
                          "method": "Nothing", "confirmed": True}),
    ("amt_mirror_link", {"action": "start", "port": 0, "confirmed": True}),
    ("amt_serial_link", {"action": "start", "port": 0, "confirmed": True}),
    ("amt_devices", {"action": "pin_check", "device": "my-server-1"}),
]
COVERED = {name for name, _ in NETWORK_CALLS} | {"amt_images", "amt_device_manage", "amt_identities",
                                                  "amt_identity_manage", "amt_captures"}
# Calls that dial AMT but hold no credential: amt_devices pin_check reads the TLS leaf only.
CREDENTIAL_FREE = {"amt_devices"}
CREDENTIAL_CALLS = [(n, a) for n, a in NETWORK_CALLS if n not in CREDENTIAL_FREE]


@pytest.fixture
def seams(monkeypatch, tmp_path):
    monkeypatch.setenv(amt_gate.TRANSPORT_ENV, "stdio")      # in-process dispatch, no bearer
    monkeypatch.setattr(amt_vault, "get_secret", fake_vault)
    assert not hasattr(amt_kvm, "amt_password"), "amt_kvm reads no vault of its own"
    _image_root(tmp_path, monkeypatch)
    rec = Recorder().install(monkeypatch)
    yield rec
    for key in list(amt_mirror._MIRRORS):
        amt_mirror.stop(key)
    for key in list(amt_serial._TERMS):
        amt_serial.stop(key)
    assert not amt_mirror._MIRRORS and not amt_serial._TERMS and not amt_mirror._SERVER


def test_the_call_table_covers_every_registered_tool():
    registered = {t.name for t in asyncio.run(amt_server.mcp.list_tools())}
    assert COVERED == registered


@pytest.mark.parametrize("name,args", NETWORK_CALLS, ids=[f"{n}-{i}" for i, (n, _) in enumerate(NETWORK_CALLS)])
def test_each_tool_connects_only_to_a_registry_amt_port(seams, name, args):
    text = call(name, args)
    deadline = time.time() + 3        # background starters (IDE-R serve, mirror frame thread)
    while not seams.tcp and time.time() < deadline:
        time.sleep(0.02)
    assert seams.tcp, f"{name} opened no connection, so this case proves nothing: {text[:300]}"
    stray = [ep for ep in seams.tcp if ep not in AMT_ENDPOINTS]
    assert not stray, f"{name} connected outside the AMT ports: {stray}"
    assert seams.urls == [], f"{name} used urlopen: {seams.urls}"
    assert [s for s in seams.sock if s[0] in INET and s[1] == socket.SOCK_STREAM] == []
    assert seams.sent_on_sock == 0
    assert set(seams.children) <= ALLOWED_CHILDREN, f"{name} started {seams.children}"


def test_the_suite_exercised_both_amt_ports(seams):
    for name, args in (("amt_status", {}), ("amt_screenshot", {})):
        call(name, args)
    assert {port for _, port in seams.tcp} == {16993, 16995}


def test_image_fetch_is_the_only_non_registry_target_and_goes_through_urlopen(seams):
    call("amt_images", {"action": "fetch", "url": FETCH_URL, "name": "y.iso", "confirmed": True})
    deadline = time.time() + 3
    while not seams.urls and time.time() < deadline:
        time.sleep(0.02)
    assert seams.urls == [FETCH_URL]
    assert seams.tcp == [], "fetch must not open a raw connection of its own"


def test_list_and_status_actions_open_nothing(seams):
    for name, args in (("amt_images", {"action": "list"}),
                       ("amt_devices", {"action": "list"}),
                       ("amt_devices", {"action": "show", "device": "my-server-1"}),
                       ("amt_ider", {"action": "status"}),
                       ("amt_mirror_link", {"action": "status"}),
                       ("amt_serial_link", {"action": "status"})):
        call(name, args)
    assert seams.tcp == [] and seams.urls == [] and seams.sock == []


def test_the_lan_address_probe_is_udp_and_sends_nothing(seams):
    urls = amt_mirror._urls("0.0.0.0", 8766, "tok", DEV.amt_ip)
    assert urls[0] == "http://127.0.0.1:8766/m/tok/"
    assert seams.sock == [(socket.AF_INET, socket.SOCK_DGRAM, (DEV.amt_ip, 9))]
    assert seams.sent_on_sock == 0 and seams.tcp == []


def test_the_seam_catches_a_connection_to_a_foreign_port(seams, monkeypatch):
    """De-vacuum: point the registry's KVM port at 5900 and the endpoint check must go red."""
    moved = amt_registry.Device(**{**DEV.__dict__, "kvm_port": 5900})
    monkeypatch.setitem(amt_registry.DEVICES, DEV.key, moved)
    call("amt_screenshot", {})
    assert (DEV.amt_ip, 5900) in seams.tcp
    assert [ep for ep in seams.tcp if ep not in AMT_ENDPOINTS] == [(DEV.amt_ip, 5900)]


def test_the_wsman_connection_dials_through_the_recorded_seam(seams):
    """The seam is real for WS-MAN too: http.client resolves create_connection at construction."""
    conn = http.client.HTTPSConnection(DEV.amt_ip, DEV.wsman_port, timeout=1)
    with pytest.raises(ConnectionRefusedError):
        conn.connect()
    assert seams.tcp == [(DEV.amt_ip, DEV.wsman_port)]


def test_the_seams_see_connect_ex_unconnected_udp_and_child_processes(seams):
    """The holes a first review found are closed: each of these is recorded or refused."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        assert s.connect_ex((DEV.amt_ip, 80)) != 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        with pytest.raises(OSError):
            s.sendto(b"x", (DEV.amt_ip, 9))
    subprocess.run([sys.executable, "-c", "pass"], check=True)
    assert (socket.AF_INET, socket.SOCK_STREAM, (DEV.amt_ip, 80)) in seams.sock
    assert seams.sent_on_sock == 1
    assert seams.children and seams.children[-1] == os.path.basename(sys.executable)
    assert not set(seams.children) <= ALLOWED_CHILDREN
