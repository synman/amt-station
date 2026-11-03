"""Redirection-channel engines for Serial-over-LAN (SOL) and IDE redirection (IDE-R).

Both ride the same TLS redirection port and Digest handshake as the KVM engine, so they
subclass ``amt_kvm.KvmSession`` for ``connect``/``send``/``close`` and the Digest answer
(``amt_kvm.py`` itself is untouched) and replace only the post-authentication state machine.

Ported from MeshCentral's ``amt-redir-ws-0.1.0.js`` (SOL framing) and ``amt-ider-module.js``
(IDE-R SCSI responder), Apache-2.0, (c) Intel Corporation. SOL open, read, send and close and an IDE-R ``next_boot``
mount and unmount have run against a live AMT device; every other framing byte and SCSI response
is as the reference sends it and stays tagged ``TODO verify-live``. The pin check is
applied in ``connect`` (``pinned``), before the Digest answer is sent.
"""
from __future__ import annotations

import hmac
import os
import socket
import struct
import threading
import time
from typing import NamedTuple

import amt_kvm

START_SOL = bytes([0x10, 0x00, 0x00, 0x00, 0x53, 0x4F, 0x4C, 0x20])     # "SOL "
START_IDER = bytes([0x10, 0x00, 0x00, 0x00, 0x49, 0x44, 0x45, 0x52])    # "IDER"
OPEN_TIMEOUT_SECONDS = 20.0
SOL_KEEPALIVE_SECONDS = 2.0
SOL_CHUNK = 256            # bytes per 0x28 frame
IDER_RX_TIMEOUT = 30000
IDER_TX_TIMEOUT = 0
IDER_HEARTBEAT = 20000
IDER_VERSION = 1
IDER_MAX_BUFFER = 8192     # the reference rejects a larger device-advertised buffer
# AMT closes an IDE-R session that hears nothing from the client for about 60 s, even while it
# sends its own heartbeats (measured live 2026-10-18: closed 61 s after the last client frame,
# held 2+ min with a ping every 10 s). So an idle serve loop sends KEEPALIVEPING (0x44).
IDER_KEEPALIVE_SECONDS = 10.0
DEV_FLOPPY, DEV_CDDVD = 0xA0, 0xB0
START_MODES = {"next_boot": 0x08, "graceful": 0x10, "now": 0x18}   # OnReboot / Graceful / Now


def pinned(cls, dev, password: str):
    """A ``cls`` session whose ``connect`` verifies the TLS leaf against the registry pin
    BEFORE any byte (or the Digest answer) is sent. No pin means no connection."""
    pin = dev.tls_leaf_sha256

    class Pinned(cls):
        def connect(self):
            super().connect()
            fingerprint = getattr(self, "cert_fp", None) or ""
            if not pin or not hmac.compare_digest(fingerprint, pin):
                self.close()
                raise amt_kvm.AmtError("tls_leaf_pin_mismatch" if pin else "tls_leaf_unpinned_refused")

    return Pinned(dev.amt_ip, dev.kvm_port, pw=password)


class _Redir(amt_kvm.KvmSession):
    """Shared redirection handshake: start -> auth query -> Digest challenge -> ONE answer."""
    MAGIC = b""

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.ready = False
        self.out_seq = 1

    def seq(self) -> bytes:
        v, self.out_seq = self.out_seq, self.out_seq + 1
        return struct.pack("<I", v & 0xFFFFFFFF)

    def open_session(self, timeout: float = OPEN_TIMEOUT_SECONDS) -> None:
        self.connect()
        self.send(self.MAGIC)
        deadline = time.time() + timeout
        while not self.ready:
            if time.time() >= deadline:
                raise amt_kvm.AmtError(self.fail_reason or "redir_open_timeout")
            self.pump_once(deadline)

    def pump_once(self, deadline: float) -> int:
        """Read at most one chunk (waiting up to 1s or until ``deadline``) and feed the parser."""
        self.s.settimeout(max(0.05, min(1.0, deadline - time.time())))
        try:
            chunk = self.s.recv(65536)
        except socket.timeout:
            return 0
        except OSError:
            self._fail("redir_socket_error")
        if not chunk:
            self._fail("redir_socket_closed_by_amt")
        self.acc += chunk
        self.acc = self.redir_feed(self.acc)
        return len(chunk)

    def redir_feed(self, acc):
        while acc:
            c = acc[0]
            if c == 0x11 and not self.digest_answered and not self.ready:   # StartRedirectionSessionReply
                if len(acc) < 13:
                    return acc
                if acc[1] != 0:
                    self._fail("redir_start_status_%d" % acc[1])
                oemlen = acc[12]
                if len(acc) < 13 + oemlen:
                    return acc
                acc = acc[13 + oemlen:]
                self.auth_query()
            elif c == 0x14:                                                # AuthenticateSessionReply
                if len(acc) < 9:
                    return acc
                status, auth_type = acc[1], acc[4]
                dlen = struct.unpack("<I", acc[5:9])[0]
                if len(acc) < 9 + dlen:
                    return acc
                data = acc[9:9 + dlen]
                acc = acc[9 + dlen:]
                if auth_type == 0:
                    if 4 in data:
                        self.auth_request_digest()
                    else:
                        self._fail("no_digest_auth_offered")
                elif auth_type in (3, 4) and status == 1:
                    if self.digest_answered:
                        self._fail("auth_rejected_no_retry")          # ONE answer, never a retry
                    p = 0
                    rlen = data[p]; realm = data[p + 1:p + 1 + rlen].decode("latin-1"); p += rlen + 1
                    nlen = data[p]; nonce = data[p + 1:p + 1 + nlen].decode("latin-1"); p += nlen + 1
                    qop = ""
                    if auth_type == 4:
                        qlen = data[p]; qop = data[p + 1:p + 1 + qlen].decode("latin-1")
                    self.auth_answer(auth_type, realm, nonce, qop)
                elif status == 0:
                    self.on_authenticated()
                else:
                    self._fail(f"auth_failed_status_{status}")
            elif c == 0xF0:                                                # session is being recorded
                acc = acc[1:]
            else:
                n = self.consume(c, acc)
                if n == 0:
                    return acc
                acc = acc[n:]
        return acc

    def on_authenticated(self) -> None:           # pragma: no cover - overridden
        raise NotImplementedError

    def consume(self, c: int, acc: bytes) -> int:  # pragma: no cover - overridden
        self._fail(f"unexpected_redir_cmd_0x{c:02x}")


# --- Serial-over-LAN ---------------------------------------------------------------------

class SolSession(_Redir):
    MAGIC = START_SOL

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.rx = bytearray()
        self.last_keepalive = 0.0

    def on_authenticated(self) -> None:
        # Intel AMT serial settings: MaxTxBuffer, TxTimeout, TxOverflowTimeout, RxTimeout,
        # RxFlushTimeout, Heartbeat (all u16 LE) then a u32 zero.
        self.send(bytes([0x20, 0, 0, 0]) + self.seq() + struct.pack("<HHHHHH", 10000, 100, 0, 10000, 100, 0)
                  + struct.pack("<I", 0))

    def consume(self, c: int, acc: bytes) -> int:
        if c == 0x21:                                   # response to settings
            if len(acc) < 23:
                return 0
            self.send(bytes([0x27, 0, 0, 0]) + self.seq() + bytes([0, 0, 0x1B, 0, 0, 0]))
            self.ready = True
            self.last_keepalive = time.time()
            return 23
        if c == 0x29:                                   # serial settings
            return 10 if len(acc) >= 10 else 0
        if c == 0x2A:                                   # incoming display data
            if len(acc) < 10:
                return 0
            size = 10 + acc[8] + (acc[9] << 8)
            if len(acc) < size:
                return 0
            self.rx += acc[10:size]
            return size
        if c == 0x2B:                                   # keep alive
            return 8 if len(acc) >= 8 else 0
        self._fail(f"unexpected_sol_cmd_0x{c:02x}")

    def send_text(self, data: bytes) -> None:
        for i in range(0, len(data), SOL_CHUNK):
            chunk = data[i:i + SOL_CHUNK]
            self.send(bytes([0x28, 0, 0, 0]) + self.seq() + struct.pack("<H", len(chunk)) + chunk)

    def read_window(self, seconds: float, max_bytes: int) -> tuple[bytes, bool]:
        """Collect serial output for ``seconds`` (or until ``max_bytes``). Returns
        ``(data, truncated)``; ``truncated`` is True when more arrived than was kept."""
        end = time.time() + seconds
        while time.time() < end and len(self.rx) < max_bytes:
            self.pump_once(end)
            if time.time() - self.last_keepalive >= SOL_KEEPALIVE_SECONDS:
                self.send(bytes([0x2B, 0, 0, 0]) + self.seq())
                self.last_keepalive = time.time()
        data = bytes(self.rx[:max_bytes])
        truncated = len(self.rx) > max_bytes
        self.rx.clear()
        return data, truncated


# --- IDE redirection ---------------------------------------------------------------------

class Media(NamedTuple):
    """A read-only disk image: its size in bytes and an open read-only file descriptor."""
    size: int
    fd: int


_LS120_PAGE = bytes.fromhex(
    "0026318000000000051e10a90820020003c300000000000000000000280000000000000002d00000")
_LS120_3F = bytes.fromhex(
    "005c248000000000010a00010000000002000000031600a00000000000120200000000000000a0000000051e10a90820020003c300000000000000000000280000000000000002d00000080a000000000000000000000b06000000112431")
_FLOPPY_PAGE = bytes.fromhex(
    "0026248000000000051e04b002120200005000000000000000000000280000000000000002d00000")
_FLOPPY_3F = bytes.fromhex(
    "005c248000000000010a00010000000002000000031600a00000000000120200000000000000a0000000051e04b002120200005000000000000000000000280000000000000002d00000080a000000000000000000000b06000000112431")
_CD_1A = bytes.fromhex(
    "00120180000000001a0a00000000000000000000")
_CD_1D = bytes.fromhex(
    "00120180000000001d0a00000000000000000000")
_CD_2A = bytes.fromhex(
    "00200180000000002a18000000002000000000000080000000000000000000000000")
_CD_3F = bytes.fromhex(
    "0028018000000000010600ff000000002a18000000000200000000000080000000000000000000000000")
_CD_CONFIG = {                       # GET_CONFIGURATION feature blocks
    0x000: bytes.fromhex(
    "0000030400080100"),
    0x001: bytes.fromhex(
    "0001030400000002"),
    0x002: bytes.fromhex(
    "0002030400000000"),
    0x003: bytes.fromhex(
    "0003030429000002"),
    0x010: bytes.fromhex(
    "001001080000080000010000"),
    0x01E: bytes.fromhex(
    "001e0300"),
    0x100: bytes.fromhex(
    "01000300"),
    0x105: bytes.fromhex(
    "01050300"),
}
_FLOPPY_ERR = bytes.fromhex(
    "0012248000000000010a00010000000002000000")
_LS120_ERR = bytes.fromhex(
    "0012318000000000010a00010000000002000000")
_CD_ERR = bytes.fromhex(
    "000e018000000000010600ff00000000")
_DISC_INFO = bytes.fromhex(
    "00200e0101010120ff00000000000000ffffffffffffffff000000000000000000000000")
_PERFORMANCE = bytes.fromhex(
    "0000000402000000")


def _be16(v: bytes, p: int) -> int:
    return (v[p] << 8) + v[p + 1]


def _be32(v: bytes, p: int) -> int:
    return struct.unpack_from(">I", v, p)[0]


class IderSession(_Redir):
    """Serves a read-only floppy and/or CD-ROM image to the host over IDE-R until stopped."""
    MAGIC = START_IDER

    def __init__(self, *a, **kw):
        super().__init__(*a, **kw)
        self.floppy: Media | None = None
        self.cdrom: Media | None = None
        self.start_mode = "next_boot"
        self.out_seq = 0
        self.in_seq = 0
        self.iderinfo: dict | None = None
        self.enabled = False
        self.toggle_ok = False
        self.floppy_ready = False
        self.cdrom_ready = False
        self.bytes_to_amt = 0
        self.bytes_from_amt = 0
        self.last_sent = 0.0

    # -- framing ------------------------------------------------------------------------
    def send_command(self, cmdid: int, data: bytes = b"", completed: bool = False, dma: bool = False) -> None:
        attributes = 2 if (cmdid > 50 and completed) else 0
        if dma:
            attributes += 1
        frame = bytes([cmdid, 0, 0, attributes]) + self.seq() + data
        self.send(frame)
        self.bytes_to_amt += len(frame)
        self.last_sent = time.time()

    def end_response(self, error: bool, sense: int, device: int, asc: int = 0, asq: int = 0) -> None:
        if error:
            self.send_command(0x51, bytes([0] * 12 + [0xC5, 0, 3, 0, 0, 0, device, 0x50, 0, 0, 0]), True)
        else:
            self.send_command(0x51, bytes([0] * 12 + [0x87, sense << 4, 3, 0, 0, 0, device, 0x51, sense, asc, asq]), True)

    def data_to_host(self, device: int, completed: bool, data: bytes, dma: int = 0) -> None:
        dmalen = 0 if dma else len(data)
        head = [0, len(data) & 0xFF, len(data) >> 8, 0, 0xB4 if dma else 0xB5, 0, 2, 0,
                dmalen & 0xFF, dmalen >> 8, device, 0x58]
        tail = ([0x85, 0, 3, 0, 0, 0, device, 0x50, 0, 0, 0, 0, 0, 0] if completed
                else [0] * 14)
        self.send_command(0x54, bytes(head + tail) + data, completed, bool(dma))

    def get_data_from_host(self, device: int, chunk: int) -> None:
        self.send_command(0x52, bytes([0, chunk & 0xFF, chunk >> 8, 0, 0xB5, 0, 0, 0, chunk & 0xFF, chunk >> 8,
                                       device, 0x58] + [0] * 11), False)

    def toggle_features(self, flags: int) -> None:
        self.send_command(0x48, bytes([3]) + struct.pack("<I", flags))

    # -- session lifecycle --------------------------------------------------------------
    def on_authenticated(self) -> None:
        self.bytes_to_amt = self.bytes_from_amt = 0
        self.in_seq = 0
        self.out_seq = 0
        self.send_command(0x40, struct.pack("<HHH", IDER_RX_TIMEOUT, IDER_TX_TIMEOUT, IDER_HEARTBEAT)
                          + struct.pack("<I", IDER_VERSION))

    def serve(self, stop: threading.Event, poll: float = 0.5) -> None:
        """Pump the channel until ``stop`` is set, pinging AMT whenever the client has been silent
        for ``IDER_KEEPALIVE_SECONDS``. Raises on a protocol failure."""
        while not stop.is_set():
            self.pump_once(time.time() + poll)
            if time.time() - self.last_sent >= IDER_KEEPALIVE_SECONDS:
                self.send_command(0x44)

    # -- incoming commands --------------------------------------------------------------
    def consume(self, c: int, acc: bytes) -> int:
        if len(acc) < 8:
            return 0
        n = self._command(c, acc)
        if n == 0:
            return 0
        if struct.unpack_from("<I", acc, 4)[0] != self.in_seq:
            self._fail("ider_out_of_sequence")
        self.in_seq += 1
        self.bytes_from_amt += n
        return n

    def _command(self, c: int, acc: bytes) -> int:
        if c == 0x41:                                       # OPEN_SESSION reply
            if len(acc) < 30:
                return 0
            size = 30 + acc[29]
            if len(acc) < size:
                return 0
            info = {"major": acc[8], "minor": acc[9], "fwmajor": acc[10], "fwminor": acc[11],
                    "readbfr": struct.unpack_from("<H", acc, 16)[0],
                    "writebfr": struct.unpack_from("<H", acc, 18)[0], "proto": acc[21]}
            self.iderinfo = info
            if info["proto"] != 0:
                self._fail("ider_unknown_proto")
            if info["readbfr"] > IDER_MAX_BUFFER or info["writebfr"] > IDER_MAX_BUFFER:
                self._fail("ider_illegal_buffer_size")
            self.toggle_features(0x01 + START_MODES[self.start_mode])
            return size
        if c == 0x43:                                       # CLOSE
            self._fail("ider_closed_by_amt")
        if c == 0x44:                                       # KEEPALIVEPING
            self.send_command(0x45)
            return 8
        if c in (0x45, 0x4B):                               # PONG / HEARTBEAT
            return 8
        if c == 0x46:                                       # RESETOCCURED
            if len(acc) < 9:
                return 0
            self.send_command(0x47)
            return 9
        if c == 0x49:                                       # STATUS_DATA
            if len(acc) < 13:
                return 0
            kind, value = acc[8], struct.unpack_from("<I", acc, 9)[0]
            if kind == 1 and value & 1:
                self.toggle_features(0x01 + START_MODES[self.start_mode])
            elif kind == 2:
                self.enabled = bool(value & 2)
            elif kind == 3:
                if value != 1:
                    self._fail("ider_start_refused")
                self.toggle_ok = True
                self.ready = True
            return 13
        if c == 0x4A:                                       # ERROR OCCURED
            return 11 if len(acc) >= 11 else 0
        if c == 0x50:                                       # COMMAND WRITTEN
            if len(acc) < 28:
                return 0
            device = DEV_CDDVD if acc[14] & 0x10 else DEV_FLOPPY
            self.handle_scsi(device, bytes(acc[16:28]), acc[9], acc[14])
            return 28
        if c == 0x53:                                       # DATA FROM HOST (write): refuse
            if len(acc) < 14:
                return 0
            size = 14 + struct.unpack_from("<H", acc, 9)[0]
            if len(acc) < size:
                return 0
            self.send_command(0x51, bytes([0] * 12 + [0x87, 0x70, 0x03, 0, 0, 0, 0xA0, 0x51, 0x07, 0x27, 0x00]), True)
            return size
        self._fail(f"ider_unknown_command_0x{c:02x}")

    # -- SCSI responder -----------------------------------------------------------------
    def _media(self, dev: int):
        return self.floppy if dev == DEV_FLOPPY else self.cdrom if dev == DEV_CDDVD else None

    def _blocks(self, dev: int) -> int:
        m = self._media(dev)
        return 0 if m is None else m.size >> (9 if dev == DEV_FLOPPY else 11)

    def handle_scsi(self, dev: int, cdb: bytes, feature: int, device_flags: int) -> None:
        op, fr = cdb[0], feature & 1
        no_medium = lambda: self.end_response(True, 0x02, dev, 0x3A, 0x00)   # noqa: E731
        if op == 0x00:                                      # TEST_UNIT_READY
            if self._media(dev) is None:
                return no_medium()
            if dev == DEV_FLOPPY and not self.floppy_ready:
                self.floppy_ready = True
                return self.end_response(True, 0x06, dev, 0x28, 0x00)
            if dev == DEV_CDDVD and not self.cdrom_ready:
                self.cdrom_ready = True
                return self.end_response(True, 0x06, dev, 0x28, 0x00)
            return self.end_response(True, 0x00, dev, 0x00, 0x00)
        if op == 0x08:                                      # READ_6
            lba = ((cdb[1] & 0x1F) << 16) + (cdb[2] << 8) + cdb[3]
            return self.send_disk_data(dev, lba, cdb[4] or 256, fr)
        if op == 0x0A:                                      # WRITE_6: read-only media
            return no_medium()
        if op == 0x1A:                                      # MODE_SENSE_6
            if cdb[2] == 0x3F and cdb[3] == 0x00:
                if self._media(dev) is None:
                    return no_medium()
                return self.data_to_host(dev, True, bytes([0, 0x00 if dev == DEV_FLOPPY else 0x05, 0x80, 0]), fr)
            return self.end_response(True, 0x05, dev, 0x24, 0x00)
        if op == 0x1B:                                      # START_STOP (eject)
            return self.end_response(True, 0, dev)
        if op == 0x1E:                                      # ALLOW_MEDIUM_REMOVAL
            if self._media(dev) is None:
                return no_medium()
            return self.end_response(True, 0x00, dev, 0x00, 0x00)
        if op == 0x23:                                      # READ_FORMAT_CAPACITIES
            if self._blocks(dev) == 0:
                return self.end_response(False, 0x05, dev, 0x24, 0x00)
            return self.data_to_host(dev, True, struct.pack(">I", 8) + bytes([0x00, 0x00, 0x0B, 0x40, 0x02, 0x00, 0x02, 0x00]), fr)
        if op == 0x25:                                      # READ_CAPACITY
            if self._blocks(dev) == 0:
                return self.end_response(False, 0x02, dev, 0x3A, 0x00)
            last = self._blocks(dev) - 1
            return self.data_to_host(device_flags, True,
                                     struct.pack(">I", last) + bytes([0, 0, 0x08 if dev == DEV_CDDVD else 0x02, 0]), fr)
        if op == 0x28:                                      # READ_10
            return self.send_disk_data(dev, _be32(cdb, 2), _be16(cdb, 7), fr)
        if op in (0x2A, 0x2E):                              # WRITE_10 / WRITE_AND_VERIFY (floppy only)
            return self.get_data_from_host(dev, 512 * _be16(cdb, 7))
        if op == 0x43:                                      # READ_TOC
            if dev == DEV_FLOPPY:
                return self.end_response(True, 0x05, dev, 0x20, 0x00)
            msf = cdb[1] & 0x02
            fmt = cdb[2] & 0x07
            if fmt == 0:
                fmt = cdb[9] >> 6
            if fmt == 1:
                return self.data_to_host(dev, True, bytes([0x00, 0x0A, 0x01, 0x01, 0x00, 0x14, 0x01, 0, 0, 0, 0, 0]), fr)
            if fmt == 0:
                toc = ([0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0, 0, 0, 0x02, 0, 0, 0x14, 0xAA, 0, 0, 0, 0x34, 0x13] if msf
                       else [0x00, 0x12, 0x01, 0x01, 0x00, 0x14, 0x01, 0, 0, 0, 0, 0, 0, 0x14, 0xAA, 0, 0, 0, 0, 0])
                return self.data_to_host(dev, True, bytes(toc), fr)
            return self.end_response(False, 0x05, dev, 0x20, 0x00)   # reference sends nothing here
        if op == 0x46:                                      # GET_CONFIGURATION
            sendall = cdb[1] != 2
            first = _be16(cdb, 2)
            buflen = _be16(cdb, 7)
            if buflen == 0:
                return self.data_to_host(dev, True, struct.pack(">II", 0x3C, 8), fr)
            block = None
            for code in sorted(_CD_CONFIG):
                if first == code or (sendall and first < code):
                    block = _CD_CONFIG[code]
            body = struct.pack(">II", 8, 4) if block is None else struct.pack(">II", 8, len(block) + 4) + block
            return self.data_to_host(dev, True, body[:buflen], fr)
        if op == 0x4A:                                      # GET_EVENT_STATUS_NOTIFICATION
            if cdb[1] != 0x01 and cdb[4] != 0x10:
                return self.end_response(True, 0x05, dev, 0x26, 0x01)
            present = 0x02 if self._media(dev) is not None else 0x00
            return self.data_to_host(dev, True, bytes([0x00, present, 0x80, 0x00]), fr)
        if op == 0x4C:
            return self.send_command(0x51, bytes(12) + bytes([0x87, 0x50, 0x03, 0, 0, 0, 0xB0, 0x51, 0x05, 0x20, 0x00]), True)
        if op == 0x51:                                      # READ_DISC_INFO
            return self.end_response(False, 0x05, dev, 0x20, 0x00)
        if op == 0x55:                                      # MODE_SELECT_10
            return self.end_response(True, 0x05, dev, 0x20, 0x00)
        if op == 0x5A:                                      # MODE_SENSE_10
            buflen = _be16(cdb, 7)
            if buflen == 0:
                return self.data_to_host(dev, True, struct.pack(">II", 0x3C, 8), fr)
            small_floppy = self._blocks(dev) <= 0xB40
            page = cdb[2] & 0x3F
            r = None
            if page == 0x01:
                r = ((_FLOPPY_ERR if small_floppy else _LS120_ERR) if dev == DEV_FLOPPY else _CD_ERR)
            elif page == 0x05 and dev == DEV_FLOPPY:
                r = _FLOPPY_PAGE if small_floppy else _LS120_PAGE
            elif page == 0x3F:
                r = ((_FLOPPY_3F if small_floppy else _LS120_3F) if dev == DEV_FLOPPY else _CD_3F)
            elif dev == DEV_CDDVD and page == 0x1A:
                r = _CD_1A
            elif dev == DEV_CDDVD and page == 0x1D:
                r = _CD_1D
            elif dev == DEV_CDDVD and page == 0x2A:
                r = _CD_2A
            if r is None:
                return self.end_response(False, 0x05, dev, 0x20, 0x00)
            return self.data_to_host(dev, True, r, fr)
        if op == 0xAC:                                      # GET_PERFORMANCE
            return self.data_to_host(dev, True, _PERFORMANCE, fr)
        return self.end_response(False, 0x05, dev, 0x20, 0x00)   # unknown command

    def send_disk_data(self, dev: int, lba: int, nblocks: int, fr: int) -> None:
        media = self._media(dev)
        shift = 9 if dev == DEV_FLOPPY else 11
        if nblocks < 0 or lba + nblocks > self._blocks(dev):
            return self.end_response(True, 0x05, dev, 0x21, 0x00)
        if nblocks == 0:
            return self.end_response(True, 0x00, dev, 0x00, 0x00)
        chunk_max = max(min((self.iderinfo or {}).get("readbfr", 4096), IDER_MAX_BUFFER), 512)
        offset, remaining = lba << shift, nblocks << shift
        while remaining > 0:
            n = min(remaining, chunk_max)
            data = os.pread(media.fd, n, offset)
            data += bytes(n - len(data))          # an image truncated underneath us reads as zeros
            offset += n
            remaining -= n
            self.data_to_host(dev, remaining == 0, data, fr)
