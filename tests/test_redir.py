"""The SOL and IDE-R engines (``amt_redir``) against a scripted fake socket.

No network: ``Scripted*`` subclasses replace ``connect`` with an in-memory socket whose peer is a
small state machine that answers the redirection handshake the way the reference (MeshCentral's
``amt-redir-ws-0.1.0.js`` / ``amt-ider-module.js``) expects. These tests pin the framing the
engines SEND and how they react; they cannot prove a real device agrees (``TODO verify-live``).
"""
import socket
import struct
import sys
import threading
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import amt_kvm  # noqa: E402
import amt_redir  # noqa: E402
import amt_registry  # noqa: E402

DEV = amt_registry.get_device("my-server-1")
PIN = DEV.tls_leaf_sha256
PW = "REDIR-PW-SENTINEL-not-real"
REALM, NONCE = b"Digest:ABCD1234", b"nonce-0123456789"


def le32(v):
    return struct.pack("<I", v)


def start_reply():
    return bytes([0x11, 0]) + bytes(10) + bytes([0])           # 13 bytes, no OEM data


def auth_reply(auth_type, status, data=b""):
    return bytes([0x14, status, 0, 0, auth_type]) + le32(len(data)) + data


def challenge():
    return auth_reply(4, 1, bytes([len(REALM)]) + REALM + bytes([len(NONCE)]) + NONCE + bytes([4]) + b"auth")


class FakeSock:
    """In-memory peer. ``respond(frame)`` returns the bytes the device answers a client frame with."""

    def __init__(self, respond):
        self.respond, self.sent, self.queue = respond, [], bytearray()
        self.closed = False

    def sendall(self, data):
        self.sent.append(bytes(data))
        self.queue += self.respond(bytes(data)) or b""

    def settimeout(self, t):
        pass

    def recv(self, n):
        if not self.queue:
            time.sleep(0.005)
            raise socket.timeout()
        out, self.queue = bytes(self.queue[:n]), self.queue[n:]
        return out

    def close(self):
        self.closed = True


class Device:
    """The handshake half of the peer: start -> query -> challenge -> (accept | reject)."""

    def __init__(self, accept=True, then=None):
        self.accept, self.then = accept, then or (lambda frame: b"")
        self.digest_frames = 0
        self.authed = False

    def __call__(self, frame):
        if frame[:8] in (amt_redir.START_SOL, amt_redir.START_IDER):
            return start_reply()
        if frame[:5] == bytes([0x13, 0, 0, 0, 0]):
            return auth_reply(0, 0, bytes([4]))
        if frame[:5] == bytes([0x13, 0, 0, 0, 4]):
            self.digest_frames += 1
            if self.digest_frames == 1:
                return challenge()
            self.authed = self.accept
            return auth_reply(4, 0 if self.accept else 1)
        return self.then(frame)


def make(cls, device, fingerprint=PIN):
    class Scripted(cls):
        def connect(self):
            self.fake = self.s = FakeSock(device)       # close() clears self.s; keep a handle for assertions
            self.cert_fp = fingerprint

    return amt_redir.pinned(Scripted, DEV, PW)


# --- shared handshake ----------------------------------------------------------------------

def test_the_handshake_answers_the_digest_challenge_exactly_once_and_never_sends_the_password():
    dev = Device()
    sol = make(amt_redir.SolSession, dev)
    sol.connect()
    sol.send(amt_redir.START_SOL)
    for _ in range(10):
        sol.pump_once(time.time() + 0.05)
    frames = sol.s.sent
    assert frames[0] == amt_redir.START_SOL
    assert dev.digest_frames == 2          # one request for the challenge, ONE answer
    assert PW.encode() not in b"".join(frames)


def test_a_rejected_answer_is_a_hard_stop_with_no_second_answer():
    dev = Device(accept=False)
    sol = make(amt_redir.SolSession, dev)
    with pytest.raises(amt_kvm.AmtError, match="auth_rejected_no_retry"):
        sol.open_session(timeout=2)
    assert dev.digest_frames == 2
    assert not any(f[:1] == b"\x20" for f in sol.s.sent), "no SOL settings sent after a failed login"


def test_a_start_status_error_fails_closed():
    sol = make(amt_redir.SolSession, lambda f: bytes([0x11, 3]) + bytes(10) + bytes([0]))
    with pytest.raises(amt_kvm.AmtError, match="redir_start_status_3"):
        sol.open_session(timeout=2)


def test_an_unexpected_command_fails_closed():
    dev = Device(then=lambda f: bytes([0x99]) + bytes(10) if f[:1] == b"\x20" else b"")
    sol = make(amt_redir.SolSession, dev)
    with pytest.raises(amt_kvm.AmtError, match="unexpected_sol_cmd_0x99"):
        sol.open_session(timeout=2)


@pytest.mark.parametrize("cls", [amt_redir.SolSession, amt_redir.IderSession])
def test_a_pin_mismatch_closes_the_socket_before_any_byte_is_sent(cls):
    dev = Device()
    session = make(cls, dev, fingerprint="0" * 64)
    with pytest.raises(amt_kvm.AmtError, match="tls_leaf_pin_mismatch"):
        session.open_session(timeout=2)
    assert session.fake.sent == [] and session.fake.closed is True


def test_an_unpinned_registry_entry_is_refused_by_the_pinned_wrapper():
    import dataclasses
    unpinned = dataclasses.replace(DEV, tls_leaf_sha256=None)

    class Scripted(amt_redir.SolSession):
        def connect(self):
            self.fake = self.s = FakeSock(Device())
            self.cert_fp = PIN

    session = amt_redir.pinned(Scripted, unpinned, PW)
    with pytest.raises(amt_kvm.AmtError, match="tls_leaf_unpinned_refused"):
        session.open_session(timeout=2)
    assert session.fake.sent == []


# --- SOL ------------------------------------------------------------------------------------

def sol_device(output=b""):
    def then(frame):
        if frame[:1] == b"\x20":
            return bytes([0x21]) + bytes(22) + (bytes([0x2A, 0, 0, 0]) + le32(1) + struct.pack("<H", len(output)) + output
                                                  if output else b"")
        return b""
    return Device(then=then)


def test_sol_sends_settings_then_the_keepalive_ack_and_becomes_ready():
    sol = make(amt_redir.SolSession, sol_device())
    sol.open_session(timeout=2)
    sent = sol.s.sent
    settings = next(f for f in sent if f[:1] == b"\x20")
    assert settings[:4] == bytes([0x20, 0, 0, 0]) and le32(1) == settings[4:8]
    assert struct.unpack("<HHHHHH", settings[8:20]) == (10000, 100, 0, 10000, 100, 0)
    assert settings[20:24] == bytes(4)
    ack = next(f for f in sent if f[:1] == b"\x27")
    assert ack[:4] == bytes([0x27, 0, 0, 0]) and ack[8:] == bytes([0, 0, 0x1B, 0, 0, 0])
    assert sol.ready is True


def test_sol_text_goes_out_as_numbered_0x28_frames_in_chunks():
    sol = make(amt_redir.SolSession, sol_device())
    sol.open_session(timeout=2)
    before = len(sol.s.sent)
    sol.send_text(b"a" * 300 + b"\r")
    frames = sol.s.sent[before:]
    assert [f[:1] for f in frames] == [b"\x28", b"\x28"]
    assert struct.unpack("<H", frames[0][8:10])[0] == 256 and frames[0][10:] == b"a" * 256
    assert frames[1][10:] == b"a" * 44 + b"\r"
    assert struct.unpack("<I", frames[1][4:8])[0] == struct.unpack("<I", frames[0][4:8])[0] + 1


def test_sol_read_window_returns_the_serial_output_and_flags_truncation():
    sol = make(amt_redir.SolSession, sol_device(b"login: _"))
    sol.open_session(timeout=2)
    data, truncated = sol.read_window(0.1, 4)
    assert data == b"logi" and truncated is True
    sol2 = make(amt_redir.SolSession, sol_device(b"login: _"))
    sol2.open_session(timeout=2)
    data, truncated = sol2.read_window(0.1, 100)
    assert data == b"login: _" and truncated is False


def test_sol_sends_a_keepalive_while_it_waits(monkeypatch):
    monkeypatch.setattr(amt_redir, "SOL_KEEPALIVE_SECONDS", 0.0)
    sol = make(amt_redir.SolSession, sol_device())
    sol.open_session(timeout=2)
    before = len(sol.s.sent)
    sol.read_window(0.05, 10)
    assert any(f[:1] == b"\x2b" for f in sol.s.sent[before:])


# --- IDE-R ----------------------------------------------------------------------------------

def open_reply(seq, readbfr=2048, writebfr=2048, proto=0):
    f = bytearray(30)
    f[0] = 0x41
    f[4:8] = le32(seq)
    f[8:12] = bytes([1, 0, 9, 0])
    f[16:18] = struct.pack("<H", readbfr)
    f[18:20] = struct.pack("<H", writebfr)
    f[21] = proto
    return bytes(f)


def status_data(seq, kind, value):
    return bytes([0x49, 0, 0, 0]) + le32(seq) + bytes([kind]) + le32(value)


def cmd_written(seq, cdb, cd=True, feature=0):
    f = bytearray(28)
    f[0] = 0x50
    f[4:8] = le32(seq)
    f[9] = feature
    f[14] = 0x10 if cd else 0x00
    f[16:16 + len(cdb)] = cdb
    return bytes(f)


class IderPeer:
    """Device side of IDE-R: OPEN_SESSION reply, then the feature-toggle acknowledgement."""

    def __init__(self, toggle_value=1, readbfr=2048):
        self.toggle_value, self.readbfr = toggle_value, readbfr
        self.hs = Device(then=self.after_auth)
        self.seq = 0

    def next(self):
        s = self.seq
        self.seq += 1
        return s

    def after_auth(self, frame):
        if frame[:1] == b"\x40":
            return open_reply(self.next(), self.readbfr)
        if frame[:1] == b"\x48":
            return status_data(self.next(), 3, self.toggle_value)
        return b""

    def __call__(self, frame):
        return self.hs(frame)


def make_media(tmp_path, size, name="x.iso", fill=None):
    import os
    p = tmp_path / name
    data = fill if fill is not None else bytes((i * 7 + 3) % 256 for i in range(size))
    p.write_bytes(data)
    return amt_redir.Media(len(data), os.open(p, os.O_RDONLY)), data


def feed(session, peer, raw):
    """Deliver a device command to the session and let it answer."""
    session.s.queue += raw
    session.pump_once(time.time() + 0.05)


@pytest.fixture
def ider(tmp_path):
    peer = IderPeer()
    session = make(amt_redir.IderSession, peer)
    media, data = make_media(tmp_path, 4096)
    session.cdrom = media
    session.open_session(timeout=2)
    session.s.sent.clear()
    return session, peer, data


def test_ider_opens_the_session_sends_the_toggle_and_waits_for_the_ack(tmp_path):
    peer = IderPeer()
    session = make(amt_redir.IderSession, peer)
    session.start_mode = "now"
    session.cdrom, _ = make_media(tmp_path, 2048)
    session.open_session(timeout=2)
    sent = session.s.sent
    assert sent[0] == amt_redir.START_IDER
    open_cmd = next(f for f in sent if f[:1] == b"\x40")
    assert open_cmd == bytes([0x40, 0, 0, 0]) + le32(0) + struct.pack("<HHH", 30000, 0, 20000) + le32(1)
    toggle = next(f for f in sent if f[:1] == b"\x48")
    assert toggle == bytes([0x48, 0, 0, 0]) + le32(1) + bytes([3]) + le32(0x01 + 0x18)
    assert session.ready is True and session.iderinfo["readbfr"] == 2048


@pytest.mark.parametrize("mode,flags", [("next_boot", 0x09), ("graceful", 0x11), ("now", 0x19)])
def test_ider_start_modes_map_to_the_reference_flag_values(tmp_path, mode, flags):
    session = make(amt_redir.IderSession, IderPeer())
    session.start_mode = mode
    session.cdrom, _ = make_media(tmp_path, 2048)
    session.open_session(timeout=2)
    toggle = next(f for f in session.s.sent if f[:1] == b"\x48")
    assert struct.unpack("<I", toggle[9:13])[0] == flags


def test_ider_refusal_of_the_toggle_fails_the_mount(tmp_path):
    session = make(amt_redir.IderSession, IderPeer(toggle_value=0))
    session.cdrom, _ = make_media(tmp_path, 2048)
    with pytest.raises(amt_kvm.AmtError, match="ider_start_refused"):
        session.open_session(timeout=2)


@pytest.mark.parametrize("kwargs", [{"proto": 1}, {"readbfr": 9000}, {"writebfr": 9000}])
def test_ider_rejects_an_unknown_protocol_or_oversized_buffer(tmp_path, kwargs):
    class Peer(IderPeer):
        def after_auth(self, frame):
            return open_reply(self.next(), **kwargs) if frame[:1] == b"\x40" else b""

    session = make(amt_redir.IderSession, Peer())
    session.cdrom, _ = make_media(tmp_path, 2048)
    with pytest.raises(amt_kvm.AmtError, match="ider_unknown_proto|ider_illegal_buffer_size"):
        session.open_session(timeout=2)


def test_read_capacity_reports_the_last_2048_byte_block(ider):
    session, peer, data = ider
    feed(session, peer, cmd_written(peer.next(), bytes([0x25]) + bytes(11)))
    frame, = session.s.sent
    assert frame[0] == 0x54 and frame[3] == 2          # DataToHost, completed
    assert frame[8 + 26:] == struct.pack(">I", 1) + bytes([0, 0, 0x08, 0])


def test_read_10_streams_the_image_in_device_sized_chunks(ider):
    session, peer, data = ider
    cdb = bytes([0x28, 0]) + struct.pack(">I", 0) + bytes([0]) + struct.pack(">H", 2) + bytes(3)
    feed(session, peer, cmd_written(peer.next(), cdb))
    frames = session.s.sent
    assert [f[0] for f in frames] == [0x54, 0x54] and [f[3] for f in frames] == [0, 2]
    assert b"".join(f[8 + 26:] for f in frames) == data        # byte-exact, 2 x 2048
    assert struct.unpack("<H", frames[0][9:11])[0] == 2048


def test_read_10_past_the_end_is_an_error_response_not_data(ider):
    session, peer, data = ider
    cdb = bytes([0x28, 0]) + struct.pack(">I", 1) + bytes([0]) + struct.pack(">H", 2) + bytes(3)
    feed(session, peer, cmd_written(peer.next(), cdb))
    frame, = session.s.sent
    assert frame[0] == 0x51 and frame[8 + 12] == 0xC5


def test_write_attempts_and_unknown_commands_are_refused_without_exposing_the_image(ider):
    session, peer, _ = ider
    feed(session, peer, cmd_written(peer.next(), bytes([0x0A]) + bytes(11)))          # WRITE_6
    feed(session, peer, cmd_written(peer.next(), bytes([0xFE]) + bytes(11)))          # unknown opcode
    write6, unknown = session.s.sent
    assert write6[0] == 0x51 and write6[8 + 12] == 0xC5, "WRITE_6 is answered as an error (read-only media)"
    assert unknown[0] == 0x51 and unknown[-4:] == bytes([0x51, 0x05, 0x20, 0x00])
    data_frames = [f for f in session.s.sent if f[0] == 0x54]
    assert data_frames == []


def test_test_unit_ready_flips_to_ready_after_the_first_probe(ider):
    session, peer, _ = ider
    assert session.cdrom_ready is False
    feed(session, peer, cmd_written(peer.next(), bytes(12)))
    assert session.cdrom_ready is True and session.floppy_ready is False
    feed(session, peer, cmd_written(peer.next(), bytes(12)))
    assert [f[0] for f in session.s.sent] == [0x51, 0x51]


def test_mode_sense_10_and_read_toc_answer_from_the_reference_tables(ider):
    session, peer, _ = ider
    feed(session, peer, cmd_written(peer.next(), bytes([0x5A, 0, 0x2A, 0, 0, 0, 0, 0, 0x22, 0, 0, 0])))
    sense = session.s.sent[0]
    assert sense[8 + 26:] == bytes.fromhex("00200180000000002a18000000002000000000000080000000000000000000000000")
    feed(session, peer, cmd_written(peer.next(), bytes([0x43, 0, 1, 0, 0, 0, 0, 0, 12, 0, 0, 0])))
    assert session.s.sent[1][8 + 26:] == bytes([0x00, 0x0A, 0x01, 0x01, 0x00, 0x14, 0x01, 0, 0, 0, 0, 0])


def test_keepalive_ping_is_answered_and_a_host_write_is_refused(ider):
    session, peer, _ = ider
    feed(session, peer, bytes([0x44, 0, 0, 0]) + le32(peer.next()))
    assert session.s.sent[0][0] == 0x45
    feed(session, peer, bytes([0x53, 0, 0, 0]) + le32(peer.next()) + bytes([0]) + struct.pack("<H", 4)
         + bytes([0, 0, 0, 0]) + b"data")
    assert session.s.sent[1][0] == 0x51


def test_a_command_out_of_sequence_stops_the_session(ider):
    session, peer, _ = ider
    with pytest.raises(amt_kvm.AmtError, match="ider_out_of_sequence"):
        feed(session, peer, bytes([0x44, 0, 0, 0]) + le32(peer.seq + 5))


def test_close_and_unknown_commands_from_the_device_stop_the_session(ider):
    session, peer, _ = ider
    with pytest.raises(amt_kvm.AmtError, match="ider_closed_by_amt"):
        feed(session, peer, bytes([0x43, 0, 0, 0]) + le32(peer.next()))
    session2 = make(amt_redir.IderSession, IderPeer())
    session2.cdrom = ider[0].cdrom
    session2.open_session(timeout=2)
    with pytest.raises(amt_kvm.AmtError, match="ider_unknown_command_0x77"):
        feed(session2, None, bytes([0x77, 0, 0, 0]) + le32(2))


def test_serve_runs_until_stopped(tmp_path):
    session = make(amt_redir.IderSession, IderPeer())
    session.cdrom, _ = make_media(tmp_path, 2048)
    session.open_session(timeout=2)
    stop = threading.Event()
    t = threading.Thread(target=session.serve, args=(stop, 0.02))
    t.start()
    time.sleep(0.1)
    assert t.is_alive()
    stop.set()
    t.join(timeout=2)
    assert not t.is_alive()


def _serve_for(session, seconds):
    stop = threading.Event()
    t = threading.Thread(target=session.serve, args=(stop, 0.01))
    t.start()
    time.sleep(seconds)
    stop.set()
    t.join(timeout=2)
    return [f for f in session.fake.sent if f[:1] == b"\x44"]


def test_an_idle_serve_loop_pings_amt_so_the_session_is_not_dropped(tmp_path, monkeypatch):
    # Live 2026-10-18: AMT closed an IDE-R session 61 s after the client's last frame.
    monkeypatch.setattr(amt_redir, "IDER_KEEPALIVE_SECONDS", 0.05)
    session = make(amt_redir.IderSession, IderPeer())
    session.cdrom, _ = make_media(tmp_path, 2048)
    session.open_session(timeout=2)
    pings = _serve_for(session, 0.4)
    assert 3 <= len(pings) <= 9
    assert all(len(f) == 8 for f in pings)                          # bare header, no payload


def test_a_busy_serve_loop_sends_no_ping(tmp_path, monkeypatch):
    monkeypatch.setattr(amt_redir, "IDER_KEEPALIVE_SECONDS", 60.0)
    session = make(amt_redir.IderSession, IderPeer())
    session.cdrom, _ = make_media(tmp_path, 2048)
    session.open_session(timeout=2)
    assert _serve_for(session, 0.2) == []


def test_the_image_descriptor_is_only_ever_read(ider):
    import os
    session, peer, data = ider
    with pytest.raises(OSError):
        os.write(session.cdrom.fd, b"x")       # opened O_RDONLY: the engine has no write path
