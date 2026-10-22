"""Vault-piped credentials: the AMT password and the host logon password never surface.

Every tool runs with sentinel credentials served by the real ``amt_vault.get_secret`` (through a
fake ``secrets.py``), against two scripted devices: a WS-MAN peer that issues a Digest challenge
and then rejects or faults the answer, and a redirection peer (KVM, SOL, IDE-R) that challenges
and rejects. Those are the paths where a credential could leak: error text, exception chains,
session notes. After each call the test scans the result, the raised error, captured stdout and
stderr, log records, the process environment, every file the run wrote, the redirection
sessions' notes and the WS-MAN requests for either sentinel.

Each sentinel is searched in its literal, base64 and hex forms, and as a base64 ``user:password``
pair (a Basic header). A second scenario lets the KVM session open (a fake session that records
what is typed) so the post-authentication paths run too: a console ``secret`` step types the host
password, and the display mirror records to disk; the typed keystrokes must spell the password
(the path really ran) while every other output stays clean. Every redirection session's endpoint
is checked against the two AMT ports, so dials made after a device answers are covered as well.

The redirection wire is scanned for the AMT sentinel only. The host password is typed into the
console as keystrokes by design (``amt_console_input`` secret steps, ``amt_remote_logon``), so a
wire scan for it would be red by construction.
"""
from __future__ import annotations

import asyncio
import base64
import email.message
import json
import logging
import os
import socket
import struct
import sys
import time
from pathlib import Path

import pytest

import amt_fleet
import amt_gate
import amt_kvm
import amt_mirror
import amt_registry
import amt_serial
import amt_server
import amt_vault
import amt_wsman
import amt_tools
# amt_devices pin_check dials WS-MAN for the TLS handshake alone and holds no credential; it is
# proved credential-free below instead of being made to read a password it never needs.
from test_direct_endpoint import AMT_ENDPOINTS, CREDENTIAL_CALLS as NETWORK_CALLS
from test_mirror import FakeSession

DEV = amt_registry.get_device("my-server-1")
AMT_PW = "AMT-SENTINEL-7f3c9e1d-not-a-real-password"
HOST_PW = "HOST-SENTINEL-2b8a4d6f-not-a-real-password"
SENTINELS = (AMT_PW, HOST_PW)


def _forms(secret: str, user: str) -> tuple[str, ...]:
    raw = secret.encode()
    return (secret, base64.b64encode(raw).decode(), raw.hex(),
            base64.b64encode(f"{user}:{secret}".encode()).decode())


FORMS = {AMT_PW: _forms(AMT_PW, "admin"), HOST_PW: _forms(HOST_PW, "sentinel-user")}
RECORDINGS = Path.home() / "amt-recordings"


def _listing(path: Path) -> set:
    return {(p.name, p.stat().st_mtime_ns) for p in path.iterdir()} if path.is_dir() else set()


# --- scripted peers --------------------------------------------------------------------------

class WsmanPeer:
    """WS-MAN over a fake pinned connection: 401 + Digest challenge, then reject or fault."""

    def __init__(self, mode: str):
        self.mode = mode
        self.requests: list[tuple[dict, bytes]] = []

    def connection(self, device):
        peer = self

        class Resp:
            def __init__(self, status, headers, body):
                self.status, self.msg, self._body = status, email.message.Message(), body
                for k, v in headers.items():
                    self.msg[k] = v

            def read(self):
                return self._body

        class Conn:
            def request(self, method, url, body=None, headers=None):
                peer.requests.append((dict(headers or {}), body or b""))
                self.authed = "Authorization" in (headers or {})

            def getresponse(self):
                if not self.authed:
                    return Resp(401, {"WWW-Authenticate":
                                      'Digest realm="Digest:A1B2", nonce="n0nce", qop="auth"'}, b"")
                if peer.mode == "reject":
                    return Resp(401, {}, b"")
                fault = ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Body>'
                         '<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code><s:Reason>'
                         '<s:Text>access denied by the scripted peer</s:Text></s:Reason></s:Fault>'
                         '</s:Body></s:Envelope>')
                return Resp(400, {}, fault.encode())

            def close(self):
                pass

        return Conn()


class RedirPeer:
    """Redirection handshake: start -> auth query -> Digest challenge -> reject."""

    REALM, NONCE = b"Digest:A1B2", b"n0nce-redir"

    def __init__(self):
        self.sessions: list = []
        self.digest_answers = 0

    def responder(self):
        """One session's peer: the first Digest frame gets the challenge, the next is rejected."""
        digest_frames = 0

        def respond(frame: bytes) -> bytes:
            nonlocal digest_frames
            if frame[:1] == b"\x10":
                return bytes([0x11, 0]) + bytes(10) + bytes([0])
            if frame[:5] == bytes([0x13, 0, 0, 0, 0]):
                return bytes([0x14, 0, 0, 0, 0]) + struct.pack("<I", 1) + bytes([4])
            if frame[:5] == bytes([0x13, 0, 0, 0, 4]):
                digest_frames += 1
                if digest_frames == 1:
                    data = (bytes([len(self.REALM)]) + self.REALM + bytes([len(self.NONCE)])
                            + self.NONCE + bytes([4]) + b"auth")
                    return bytes([0x14, 1, 0, 0, 4]) + struct.pack("<I", len(data)) + data
                self.digest_answers += 1
                return bytes([0x14, 1, 0, 0, 4]) + struct.pack("<I", 0)
            return b""

        return respond


class FakeSock:
    def __init__(self, respond):
        self.respond, self.sent, self.queue = respond, [], bytearray()

    def sendall(self, data):
        self.sent.append(bytes(data))
        self.queue += self.respond(bytes(data)) or b""

    def settimeout(self, t):
        pass

    def gettimeout(self):
        return 1.0

    def recv(self, n):
        if not self.queue:
            time.sleep(0.005)
            raise socket.timeout()
        out, self.queue = bytes(self.queue[:n]), self.queue[n:]
        return out

    def close(self):
        pass


# --- harness ---------------------------------------------------------------------------------

def _fake_secrets(tmp_path: Path) -> Path:
    script = tmp_path / "fake_secrets.py"
    script.write_text(
        "import json, sys\n"
        f"key = sys.argv[2]\n"
        f"if key == {DEV.host_vault_key!r}:\n"
        f"    print(json.dumps({{'user': 'sentinel-user', 'password': {HOST_PW!r}}}))\n"
        "else:\n"
        f"    print({AMT_PW!r})\n")
    return script


class Run:
    def __init__(self, tmp_path, wsman: WsmanPeer, redir: RedirPeer):
        self.tmp_path, self.wsman, self.redir = tmp_path, wsman, redir
        self.vault_reads: list[str] = []
        self.endpoints: list[tuple[str, int]] = []
        self.recordings_before = _listing(RECORDINGS)

    def hits(self, *texts: str) -> list[str]:
        """Every place either sentinel shows up outside the credential's intended use."""
        found = []

        def scan(where: str, text: str, sentinels=SENTINELS):
            for s in sentinels:
                if any(form in text for form in FORMS[s]):
                    found.append(f"{where}: {s[:12]}...")

        for i, t in enumerate(texts):
            scan(f"output[{i}]", t)
        for k, v in os.environ.items():
            scan(f"env {k}", v)
        roots = [self.tmp_path, Path(os.environ["AMT_STATE_DIR"])]
        for root in roots:
            for path in root.rglob("*"):
                if path.is_file() and path.name != "fake_secrets.py":
                    try:
                        data = path.read_bytes()
                    except FileNotFoundError:      # a temp file the encoder removed mid-scan
                        continue
                    scan(f"file {path.name}", data.decode("latin-1"))
        if _listing(RECORDINGS) != self.recordings_before:
            found.append(f"wrote outside the test dirs: {RECORDINGS}")
        for headers, body in self.wsman.requests:
            scan("wsman request", json.dumps(headers) + body.decode("utf-8", "replace"))
        for session in self.redir.sessions:
            scan("session notes", "\n".join(map(str, getattr(session, "log", []))))
            wire = b"".join(getattr(session.fake, "sent", []))
            scan("redirection wire", wire.decode("latin-1"), sentinels=(AMT_PW,))
        return found


@pytest.fixture(params=["reject", "fault"])
def run(request, monkeypatch, tmp_path):
    monkeypatch.setenv(amt_gate.TRANSPORT_ENV, "stdio")
    monkeypatch.setattr(amt_vault, "SECRETS", _fake_secrets(tmp_path))
    root = tmp_path / "images"
    root.mkdir()
    (root / "x.iso").write_bytes(b"\0" * 4096)
    monkeypatch.setenv("AMT_IMAGE_ROOT", str(root))
    monkeypatch.setenv(amt_tools.SHOT_DIR_ENV, str(tmp_path / "shots"))

    r = Run(tmp_path, WsmanPeer(request.param), RedirPeer())
    real_get = amt_vault.get_secret
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: (r.vault_reads.append(key), real_get(key))[1])
    monkeypatch.setattr(amt_wsman, "_open_connection", r.wsman.connection)

    def connect(session):
        session.fake = session.s = FakeSock(r.redir.responder())
        session.cert_fp = DEV.tls_leaf_sha256
        r.redir.sessions.append(session)
        r.endpoints.append((session.host, int(session.port)))

    monkeypatch.setattr(amt_kvm.KvmSession, "connect", connect)
    monkeypatch.setattr(amt_kvm.KvmSession, "close", lambda session: None)
    # The pin check dials only the TLS handshake; answer it here so no test reaches a real address.
    real_pin_check = amt_fleet.pin_check
    monkeypatch.setattr(amt_fleet, "pin_check", lambda dev: real_pin_check(
        dev, probe=lambda ip, port: (r.endpoints.append((ip, port)), DEV.tls_leaf_sha256)[1]))
    yield r
    for key in list(amt_mirror._MIRRORS):
        amt_mirror.stop(key)
    for key in list(amt_serial._TERMS):
        amt_serial.stop(key)


def call(name: str, args: dict) -> str:
    try:
        out = asyncio.run(amt_server.mcp.call_tool(name, args))
    except BaseException as ex:            # the error chain is scanned too
        parts, e = [], ex
        while e is not None:
            parts.append(f"{type(e).__name__}: {e!r} {e}")
            e = e.__cause__ or e.__context__
        return "ERROR " + " | ".join(parts)
    return json.dumps(out, default=str)


# Settle time for tools that finish their network step on a background thread.
def _settle(r: Run, before: int) -> None:
    deadline = time.time() + 2
    while time.time() < deadline and len(r.vault_reads) == before:
        time.sleep(0.02)
    time.sleep(0.1)


@pytest.mark.parametrize("name,args", NETWORK_CALLS, ids=[f"{n}-{i}" for i, (n, _) in enumerate(NETWORK_CALLS)])
def test_no_sentinel_leaves_the_vault_path(run, name, args, caplog, capfd):
    caplog.set_level(logging.DEBUG)
    text = call(name, args)
    _settle(run, 0)
    out, err = capfd.readouterr()
    logs = "\n".join(f"{r.getMessage()} {r.exc_text or ''}" for r in caplog.records)
    assert DEV.amt_vault_key in run.vault_reads, f"{name} never read the AMT password: {text[:300]}"
    assert run.wsman.requests or run.redir.sessions, f"{name} reached no device"
    assert set(run.endpoints) <= AMT_ENDPOINTS, run.endpoints
    assert run.hits(text, out, err, logs) == []


def test_the_wsman_answer_is_a_digest_and_never_the_password(run):
    call("amt_status", {})
    authed = [h["Authorization"] for h, _ in run.wsman.requests if "Authorization" in h]
    # A rejected answer stops the tool: one authenticated attempt, no retry (lockout safety).
    # A SOAP fault is per class, so amt_status goes on to its other classes, each one answer.
    if run.wsman.mode == "reject":
        assert len(authed) == 1
    else:
        assert len(authed) == len(run.wsman.requests) // 2 > 1
    for value in authed:
        assert value.startswith("Digest ") and 'response="' in value
        assert AMT_PW not in value


def test_the_redirection_answer_is_a_digest_and_never_the_password(run):
    call("amt_screenshot", {})
    assert run.redir.digest_answers == 1
    assert run.hits() == []


class TypingSession(FakeSession):
    """An authenticated KVM session that records what is typed (the mirror suite's fake)."""

    def __init__(self, *a, **k):
        super().__init__(*a, **k)
        self.typed: list[str] = []

    def type_text(self, text):
        self.typed.append(text)

    def type_char(self, ch):
        self.typed.append(ch)

    def click(self, *a, **k):
        pass


@pytest.fixture
def authed(run, monkeypatch, tmp_path):
    sessions: list[TypingSession] = []

    def make(dev, password):
        assert password == AMT_PW          # the vaulted AMT password reached the session
        s = TypingSession()
        sessions.append(s)
        return s

    monkeypatch.setattr(amt_tools, "_pinned_kvm_session", make)
    return run, sessions


def test_a_typed_host_password_reaches_the_console_and_nothing_else(authed, capfd):
    run, sessions = authed
    text = call("amt_console_input", {"actions": [{"kind": "secret", "secret": "host_user"},
                                                  {"kind": "key", "key": "tab"},
                                                  {"kind": "secret", "secret": "host_password"}],
                                      "confirmed": True})
    out, err = capfd.readouterr()
    assert not text.startswith("ERROR"), text[:300]
    assert sessions and sessions[0].typed == ["sentinel-user", HOST_PW], "the secret path did not run"
    assert DEV.host_vault_key in run.vault_reads
    assert run.hits(text, out, err) == []


def test_a_recorded_mirror_session_leaves_no_credential_on_disk(authed, capfd, tmp_path):
    run, sessions = authed
    rec_dir = tmp_path / "recordings"
    # record_on_start would use the saved default folder (~/amt-recordings), so the recording is
    # started with an explicit test folder instead.
    started = call("amt_mirror_link", {"action": "start", "port": 0, "confirmed": True})
    assert not started.startswith("ERROR"), started[:300]
    rec = call("amt_mirror_link", {"action": "record_start", "directory": str(rec_dir), "confirmed": True})
    assert not rec.startswith("ERROR"), rec[:300]
    typed = call("amt_console_input", {"actions": [{"kind": "secret", "secret": "host_password"}],
                                       "confirmed": True})
    time.sleep(0.3)
    stopped = call("amt_mirror_link", {"action": "stop", "confirmed": True})
    deadline = time.time() + 60        # the MP4 encode runs after stop; scan its result, not its temp files
    while any(rec_dir.rglob(".encode-*")) and time.time() < deadline:
        time.sleep(0.2)
    assert not any(rec_dir.rglob(".encode-*")), "the recording never finished encoding"
    out, err = capfd.readouterr()
    assert sessions and HOST_PW in sessions[0].typed, "the shared mirror session was not used"
    assert any(rec_dir.rglob("*")), "nothing was recorded, so the disk scan proves nothing"
    assert run.hits(started, rec, typed, stopped, out, err) == []


def test_the_scan_catches_a_planted_leak(run, monkeypatch):
    """De-vacuum: a digest builder that puts the password in its error must turn the scan red."""
    def leaky(challenge, user, password, *a, **k):
        raise amt_wsman.WsmanError(f"digest failed for {password}")
    monkeypatch.setattr(amt_wsman, "digest_authorization", leaky)
    text = call("amt_status", {})
    assert run.hits(text), "the scan missed a password in a tool error"


def _plant_env(run, monkeypatch):
    monkeypatch.setenv("AMT_LEAK_PROBE", AMT_PW)


def _plant_state_file(run, monkeypatch):
    (Path(os.environ["AMT_STATE_DIR"]) / "leak.txt").write_text(HOST_PW)


def _plant_wsman(run, monkeypatch):
    run.wsman.requests.append(({"X-Probe": base64.b64encode(f"admin:{AMT_PW}".encode()).decode()}, b""))


def _plant_notes(run, monkeypatch):
    run.redir.sessions[-1].log.append(f"pw={AMT_PW.encode().hex()}")


def _plant_recordings(run, monkeypatch):
    run.recordings_before = run.recordings_before | {("not-there-before", 0)}


@pytest.mark.parametrize("plant", [_plant_env, _plant_state_file, _plant_wsman, _plant_notes, _plant_recordings])
def test_every_scanned_channel_goes_red_on_a_planted_leak(run, monkeypatch, plant):
    """De-vacuum per channel: a leak planted in each place the scan claims to read is found."""
    call("amt_screenshot", {})
    call("amt_status", {})
    assert run.hits() == []
    plant(run, monkeypatch)
    assert run.hits(), f"{plant.__name__}: the scan missed it"


@pytest.mark.parametrize("stream", ["out", "err"])
def test_the_captured_streams_are_scanned(run, capfd, stream):
    print(AMT_PW, file=sys.stdout if stream == "out" else sys.stderr)
    out, err = capfd.readouterr()
    assert run.hits(out, err)


def test_the_pin_check_reads_no_credential_and_sends_none(run):
    text = call("amt_devices", {"action": "pin_check", "device": DEV.key})
    assert run.vault_reads == [], "a pin check must never read the vault"
    assert run.wsman.requests == [] and not run.redir.sessions, "a pin check sends no request"
    assert 'matches' in text and 'true' in text and run.hits(text) == []
