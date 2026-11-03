#!/usr/bin/env python3
"""AMT KVM redirection session — direct TLS to port 16995, no MeshCommander,
no webrelay, no browser. Ported from the proven spike (kvm_probe.py): TLS,
redirection digest handshake, RFB/KVM init, RAW + persistent-zlib RLE decode.
Adds client->server input (RFB KeyEvent type 4, PointerEvent type 5) so a
session can drive a Windows logon.

The AMT password is read from the vault in-process and never printed. A typed
secret (the Windows password) is read from the vault in-process by the server
tool that calls type_text — it is never a tool argument and never returned.
"""
import hashlib
import secrets as _secrets
import socket
import ssl
import string
import struct
import time
import zlib
from pathlib import Path

USER = "admin"
AUTHURI = "/RedirectionService"
SNC = "00000001"
MAX_W = 4096
MAX_H = 2304

# X11 keysyms for the named / control keys a logon needs.
KEYSYM = {
    "enter": 0xFF0D, "return": 0xFF0D, "backspace": 0xFF08, "tab": 0xFF09,
    "escape": 0xFF1B, "esc": 0xFF1B, "delete": 0xFFFF, "space": 0x20,
    "ctrl": 0xFFE3, "control": 0xFFE3, "alt": 0xFFE9, "shift": 0xFFE1,
    "win": 0xFFEB, "super": 0xFFEB, "meta": 0xFFEB,
    "home": 0xFF50, "end": 0xFF57, "up": 0xFF52, "down": 0xFF54,
    "left": 0xFF51, "right": 0xFF53,
}
# US-layout characters that require Shift held. keysym == ord(c) for all of ASCII 0x20-0x7e.
_SHIFT_CHARS = set(string.ascii_uppercase) | set('~!@#$%^&*()_+{}|:"<>?')


def _md5(s: str) -> str:
    return hashlib.md5(s.encode("latin-1")).hexdigest()


def _le32(v):
    return struct.pack("<I", v & 0xFFFFFFFF)


class AmtError(Exception):
    pass


class KvmSession:
    """One AMT redirection/KVM session. AMT permits only ONE at a time, so
    close() is reliable and the server also closes every session at exit."""

    def __init__(self, host, port=16995, pw=None, key_delay=0.02):
        self.host = host
        self.port = port
        self.pw = pw if pw is not None else amt_password()
        self.key_delay = key_delay
        self.log = []
        self.width = self.height = 0
        self.bpp = 2  # RGB565
        self.kvm_state = 0
        self.rects_left = 0
        self.fb = None
        self.frame_done = False
        self.digest_answered = False
        self.covered = 0
        self.encodings_seen = set()
        self.cnonce = _secrets.token_hex(16)
        self.offer_rle = True  # offer RLE(16)+RAW(0)+DesktopSize so either screen mode works
        self.rle_errors = 0
        self.subenc_hist = {}
        self._stream_started = False
        self.inflate = zlib.decompressobj()
        self.acc = b""
        self.kvm = False
        self.fail_reason = None
        self.s = None
        self.incremental = False      # True while grab_update collects one incremental update
        self.update_sent_at = None    # when the outstanding incremental request went out

    def note(self, m):
        self.log.append(m)

    # ---- transport ----
    def connect(self):
        raw = socket.create_connection((self.host, self.port), timeout=15)
        # Spike-era note: AMT ships a self-signed leaf on the LAN. BUILD REQUIREMENT:
        # pin the leaf SHA-256 in a device registry and verify by fingerprint.
        ctx = ssl._create_unverified_context()
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.s = ctx.wrap_socket(raw, server_hostname=self.host)
        self.s.settimeout(10)
        der = self.s.getpeercert(binary_form=True)
        self.cert_fp = hashlib.sha256(der).hexdigest() if der else None
        self.note(f"TLS up: {self.s.version()} leaf-sha256:{(self.cert_fp or '')[:16]}")

    def send(self, b):
        self.s.sendall(b)

    def ksend(self, b):
        self.s.sendall(b)

    def close(self):
        try:
            if self.s:
                self.s.close()
        except Exception:
            pass
        self.s = None

    def _fail(self, reason):
        self.fail_reason = reason
        raise AmtError(reason)

    # ---- open / pump / grab ----
    def open(self, deadline=None):
        deadline = deadline or (time.time() + 40)
        self.connect()
        self.send(bytes([0x10, 0x01, 0x00, 0x00, 0x4B, 0x56, 0x4D, 0x52]))  # KVMR start
        self._pump(deadline)
        if not self.frame_done:
            raise AmtError(self.fail_reason or "open_no_frame")
        return self.width, self.height

    def _pump(self, deadline):
        while time.time() < deadline and not self.frame_done:
            try:
                chunk = self.s.recv(65536)
            except socket.timeout:
                break
            if not chunk:
                self.note("socket closed by AMT")
                break
            self.acc += chunk
            if self.kvm:
                self.acc = self.kvm_feed(self.acc)
                continue
            self.acc = self.redir_feed(self.acc)
            if self.kvm and self.acc:
                self.acc = self.kvm_feed(self.acc)

    def grab_frame(self, deadline=None):
        """Request and collect one full non-incremental framebuffer."""
        if not self.kvm:
            raise AmtError("grab_before_open")
        deadline = deadline or (time.time() + 30)
        self.frame_done = False
        self.covered = 0
        self.update_sent_at = None    # re-request incrementals after a full frame
        self.ksend(bytes([3, 0]) + struct.pack(">HHHH", 0, 0, self.width, self.height))
        self._pump(deadline)
        if not self.frame_done:
            raise AmtError(self.fail_reason or "grab_no_frame")
        return self.width, self.height

    UPDATE_RESEND_SECONDS = 1.0

    def grab_update(self, wait=0.25):
        """Collect the next INCREMENTAL framebuffer update (changed tiles only), waiting at most
        ``wait`` seconds. Returns True when an update arrived and was applied to ``fb``; False
        when the screen did not change in time (normal for a still screen). Cheap enough to call
        several times a second, unlike ``grab_frame``, which pulls every tile. One request stays
        outstanding between calls and is re-sent after UPDATE_RESEND_SECONDS."""
        if not self.kvm:
            raise AmtError("grab_before_open")
        now = time.time()
        if self.update_sent_at is None or now - self.update_sent_at > self.UPDATE_RESEND_SECONDS:
            self.ksend(bytes([3, 1]) + struct.pack(">HHHH", 0, 0, self.width, self.height))
            self.update_sent_at = now
        self.incremental, self.frame_done = True, False
        old = self.s.gettimeout()
        self.s.settimeout(wait)
        try:
            self._pump(now + wait)
        finally:
            self.s.settimeout(old)
            self.incremental = False
        if self.frame_done:
            self.update_sent_at = None
        return self.frame_done

    @staticmethod
    def _fb_delta(a, b):
        # Fast changed-bit count between two framebuffers (C-level big-int XOR).
        if len(a) != len(b):
            return len(a) * 8
        return (int.from_bytes(a, "big") ^ int.from_bytes(b, "big")).bit_count()

    # A blinking text caret toggles a tiny region, so "fully identical" never
    # converges; treat frames within STABLE_BITS as settled.
    STABLE_BITS = 20000

    def grab_stable(self, max_iters=8, settle=0.5, deadline=None):
        """Grab repeatedly until the screen settles (defeats queued-stale frames
        AND render lag). Returns (w, h, iters, stable, delta)."""
        prev = None
        delta = None
        for i in range(max_iters):
            self.grab_frame(deadline=deadline)
            cur = bytes(self.fb)
            if prev is not None:
                delta = self._fb_delta(prev, cur)
                if delta <= self.STABLE_BITS:
                    return self.width, self.height, i + 1, True, delta
            prev = cur
            time.sleep(settle)
        return self.width, self.height, max_iters, False, delta

    # ---- redirection handshake ----
    def auth_query(self):
        self.send(bytes([0x13, 0, 0, 0, 0]) + _le32(0))

    def auth_request_digest(self):
        body = (bytes([len(USER)]) + USER.encode() + bytes([0, 0]) +
                bytes([len(AUTHURI)]) + AUTHURI.encode() + bytes([0, 0, 0, 0]))
        self.send(bytes([0x13, 0, 0, 0, 4]) + _le32(len(USER) + len(AUTHURI) + 8) + body)

    def auth_answer(self, authType, realm, nonce, qop):
        cn = self.cnonce
        extra = (SNC + ":" + cn + ":" + qop + ":") if authType == 4 else ""
        digest = _md5(_md5(f"{USER}:{realm}:{self.pw}") + ":" + nonce + ":" + extra + _md5("POST:" + AUTHURI))
        parts = [bytes([len(USER)]), USER.encode(),
                 bytes([len(realm)]), realm.encode(),
                 bytes([len(nonce)]), nonce.encode(),
                 bytes([len(AUTHURI)]), AUTHURI.encode(),
                 bytes([len(cn)]), cn.encode(),
                 bytes([len(SNC)]), SNC.encode(),
                 bytes([len(digest)]), digest.encode()]
        if authType == 4:
            parts += [bytes([len(qop)]), qop.encode()]
        body = b"".join(parts)
        total = len(USER) + len(realm) + len(nonce) + len(AUTHURI) + len(cn) + len(SNC) + len(digest) + 7
        if authType == 4:
            total += len(qop) + 1
        self.send(bytes([0x13, 0, 0, 0, authType]) + _le32(total) + body)
        self.digest_answered = True

    def redir_feed(self, acc):
        while acc:
            c = acc[0]
            if c == 0x11:  # StartRedirectionSessionReply
                if len(acc) < 13:
                    return acc
                if acc[1] != 0:
                    self._fail("redir_start_status_%d" % acc[1])
                oemlen = acc[12]
                if len(acc) < 13 + oemlen:
                    return acc
                acc = acc[13 + oemlen:]
                self.note("redir session ok; querying auth")
                self.auth_query()
            elif c == 0x14:  # AuthenticateSessionReply
                if len(acc) < 9:
                    return acc
                status = acc[1]
                authType = acc[4]
                dlen = struct.unpack("<I", acc[5:9])[0]
                if len(acc) < 9 + dlen:
                    return acc
                data = acc[9:9 + dlen]
                acc = acc[9 + dlen:]
                if authType == 0:
                    if 4 in data:
                        self.note("digest(type4) offered; requesting challenge")
                        self.auth_request_digest()
                    else:
                        self._fail("no_digest_auth_offered")
                elif authType in (3, 4) and status == 1:
                    if self.digest_answered:
                        self._fail("auth_rejected_no_retry")
                    p = 0
                    rlen = data[p]; realm = data[p + 1:p + 1 + rlen].decode("latin-1"); p += rlen + 1
                    nlen = data[p]; nonce = data[p + 1:p + 1 + nlen].decode("latin-1"); p += nlen + 1
                    qop = ""
                    if authType == 4:
                        qlen = data[p]; qop = data[p + 1:p + 1 + qlen].decode("latin-1"); p += qlen + 1
                    self.note(f"challenge realm={realm!r} qop={qop!r}; answering once")
                    self.auth_answer(authType, realm, nonce, qop)
                elif status == 0:
                    self.note("redirection auth OK; starting KVM channel")
                    self.send(bytes([0x40, 0, 0, 0, 0, 0, 0, 0]))
                else:
                    self._fail(f"auth_failed_status_{status}")
            elif c == 0x41:  # KVM channel open
                if len(acc) < 8:
                    return acc
                self.note("KVM channel open (0x41)")
                self.kvm = True
                return acc[8:]
            elif c == 0xF0:  # recording notice
                self.note("session is being recorded (0xF0)")
                acc = acc[1:]
            else:
                self._fail(f"unexpected_redir_cmd_0x{c:02x}")
        return acc

    # ---- KVM / RFB read path ----
    def kvm_feed(self, acc):
        # Also loop on an empty buffer when an update's last rectangle has just been consumed,
        # so the update completes now rather than when the next unrelated bytes arrive.
        while acc or (self.kvm_state == 100 and self.rects_left == 0):
            st = self.kvm_state
            if st == 0:
                if len(acc) < 12:
                    return acc
                ver = acc[:12]; acc = acc[12:]
                self.note(f"RFB server version {ver!r}")
                self.ksend(b"RFB 003.008\n")
                self.kvm_state = 1
            elif st == 1:
                if len(acc) < 1:
                    return acc
                ntypes = acc[0]
                if len(acc) < 1 + ntypes:
                    return acc
                offered = set(acc[1:1 + ntypes]); acc = acc[1 + ntypes:]
                if 1 not in offered:
                    self._fail(f"rfb_no_none_security_{sorted(offered)}")
                self.ksend(bytes([1]))
                self.kvm_state = 2
            elif st == 2:
                if len(acc) < 4:
                    return acc
                res = struct.unpack(">I", acc[:4])[0]; acc = acc[4:]
                if res != 0:
                    self._fail("rfb_security_result_%d" % res)
                self.ksend(bytes([1]))  # ClientInit: share desktop
                self.kvm_state = 3
                self.note("RFB security ok; ClientInit (share)")
            elif st == 3:
                if len(acc) < 24:
                    return acc
                namelen = struct.unpack(">I", acc[20:24])[0]
                if namelen > 4096:
                    self._fail("serverinit_namelen_too_large")
                if len(acc) < 24 + namelen:
                    return acc
                self.width = struct.unpack(">H", acc[0:2])[0]
                self.height = struct.unpack(">H", acc[2:4])[0]
                bpp = acc[4]
                rmax = struct.unpack(">H", acc[8:10])[0]
                gmax = struct.unpack(">H", acc[10:12])[0]
                bmax = struct.unpack(">H", acc[12:14])[0]
                self.note(f"pixfmt bpp={bpp} rgbmax={rmax},{gmax},{bmax}")
                if not (bpp == 16 and rmax == 31 and gmax == 63 and bmax == 31):
                    self._fail(f"unexpected_pixfmt_bpp{bpp}_max{rmax}.{gmax}.{bmax}")
                if self.width < 1 or self.height < 1 or self.width > MAX_W or self.height > MAX_H:
                    self._fail(f"serverinit_bad_geometry_{self.width}x{self.height}")
                acc = acc[24 + namelen:]
                self.note(f"ServerInit: {self.width}x{self.height}")
                self.fb = bytearray(self.width * self.height * 3)
                if self.offer_rle:
                    encs = struct.pack(">iii", 16, 0, -223); n = 3
                else:
                    encs = struct.pack(">ii", 0, -223); n = 2
                self.ksend(bytes([2, 0]) + struct.pack(">H", n) + encs)
                self.ksend(bytes([3, 0]) + struct.pack(">HHHH", 0, 0, self.width, self.height))
                self.kvm_state = 4
            elif st == 4:
                if len(acc) < 1:
                    return acc
                mt = acc[0]
                if mt == 0:  # FramebufferUpdate
                    if len(acc) < 4:
                        return acc
                    nrects = struct.unpack(">H", acc[2:4])[0]; acc = acc[4:]
                    self.rects_left = nrects
                    self.raw_this_frame = 0
                    self.covered = 0
                    self.kvm_state = 100
                    self.note(f"FramebufferUpdate: {nrects} rects")
                elif mt == 2:  # bell
                    acc = acc[1:]
                elif mt == 3:  # ServerCutText
                    if len(acc) < 8:
                        return acc
                    ln = struct.unpack(">I", acc[4:8])[0]
                    if len(acc) < 8 + ln:
                        return acc
                    acc = acc[8 + ln:]
                else:
                    self._fail("rfb_unknown_msg_%d" % mt)
            elif st == 100:
                if self.rects_left == 0:
                    self.kvm_state = 4
                    if self.rle_errors > 0:
                        self._fail(f"rle_decode_errors_{self.rle_errors}")
                    if self.incremental:      # grab_update: any completed update is the answer
                        self.frame_done = True
                        return acc
                    full = self.width * self.height
                    if self.raw_this_frame > 0 and self.covered >= full:
                        self.note(f"frame complete: {self.covered}/{full} px (100%)")
                        self.frame_done = True
                        return acc
                    pct = (100 * self.covered // full) if full else 0
                    self.note(f"frame not full ({self.covered}/{full}px {pct}%); re-requesting")
                    self.ksend(bytes([3, 0]) + struct.pack(">HHHH", 0, 0, self.width, self.height))
                    continue
                if len(acc) < 12:
                    return acc
                x, y, w, h = struct.unpack(">HHHH", acc[:8])
                enc = struct.unpack(">i", acc[8:12])[0]
                self.encodings_seen.add(enc)
                if enc == 0:  # RAW
                    if x + w > self.width or y + h > self.height or w > 64 or h > 64:
                        self._fail(f"raw_tile_out_of_bounds_{x},{y},{w},{h}")
                    need = 12 + w * h * self.bpp
                    if len(acc) < need:
                        return acc
                    self._blit_raw(acc[12:need], x, y, w, h)
                    acc = acc[need:]; self.rects_left -= 1
                    self.raw_this_frame += 1; self.covered += w * h
                elif enc == -223 or enc == 0xFFFFFF21:  # DesktopSize
                    if w < 1 or h < 1 or w > MAX_W or h > MAX_H:
                        self._fail(f"desktopsize_bad_geometry_{w}x{h}")
                    self.width, self.height = w, h
                    self.fb = bytearray(self.width * self.height * 3)
                    acc = acc[12:]; self.rects_left -= 1
                    self.note(f"DesktopSize -> {w}x{h}")
                    self.ksend(bytes([3, 0]) + struct.pack(">HHHH", 0, 0, self.width, self.height))
                elif enc == 16:  # RLE
                    if not self.offer_rle:
                        self._fail("amt_sent_rle_despite_raw_offer")
                    if len(acc) < 16:
                        return acc
                    datalen = struct.unpack(">I", acc[12:16])[0]
                    if len(acc) < 16 + datalen:
                        return acc
                    if x + w > self.width or y + h > self.height or w > 64 or h > 64:
                        self._fail(f"rle_tile_out_of_bounds_{x},{y},{w},{h}")
                    block = bytes(acc[16:16 + datalen])
                    acc = acc[16 + datalen:]; self.rects_left -= 1
                    try:
                        sub, rc, ptr_end, dlen = self._decode_rle(block, x, y, w, h)
                        self.subenc_hist[sub] = self.subenc_hist.get(sub, 0) + 1
                        if rc != w * h or ptr_end != dlen:
                            raise ValueError(f"short decode rc={rc}/{w*h} ptr={ptr_end}/{dlen}")
                        self.raw_this_frame += 1; self.covered += w * h
                    except Exception as ex:
                        self.rle_errors += 1
                        if self.rle_errors <= 3:
                            self.note(f"rle err tile {x},{y} {w}x{h}: {type(ex).__name__}: {ex}")
                else:
                    self._fail("rfb_unknown_encoding_%d" % enc)
        return acc

    # ---- pixel decode (verbatim from the proven spike) ----
    def _put565(self, idx, v, x, y, w):
        W = self.width
        col = idx % w; row = idx // w
        o = ((y + row) * W + (x + col)) * 3
        r = (v >> 11) & 0x1F; g = (v >> 5) & 0x3F; b = v & 0x1F
        fb = self.fb
        fb[o] = (r << 3) | (r >> 2)
        fb[o + 1] = (g << 2) | (g >> 4)
        fb[o + 2] = (b << 3) | (b >> 2)

    def _decode_rle(self, block, x, y, w, h):
        if len(block) >= 2 and block[0] == 0x78 and block[1] in (0x01, 0x9C, 0xDA) and self._stream_started:
            self.note("mid-stream zlib header -> stream reset")
            self.inflate = zlib.decompressobj()
        self._stream_started = True
        data = self.inflate.decompress(block)
        s = w * h; rc = 0; ptr = 0
        sub = data[ptr]; ptr += 1
        if sub == 0:
            for i in range(s):
                v = data[ptr] | (data[ptr + 1] << 8); ptr += 2
                self._put565(i, v, x, y, w)
            rc = s
        elif sub == 1:
            v = data[ptr] | (data[ptr + 1] << 8); ptr += 2
            for i in range(s):
                self._put565(i, v, x, y, w)
            rc = s
        elif 2 <= sub <= 16:
            pal = []
            for _ in range(sub):
                pal.append(data[ptr] | (data[ptr + 1] << 8)); ptr += 2
            br, bm = (1, 1) if sub == 2 else (2, 3) if sub <= 4 else (4, 15)
            rc = 0
            while rc < s and ptr < len(data):
                vb = data[ptr]; ptr += 1
                i = 8 - br
                while i >= 0 and rc < s:
                    self._put565(rc, pal[(vb >> i) & bm], x, y, w); rc += 1; i -= br
        elif sub == 128:
            rc = 0
            while rc < s and ptr < len(data):
                v = data[ptr] | (data[ptr + 1] << 8); ptr += 2
                runlength = 1
                while True:
                    d = data[ptr]; ptr += 1; runlength += d
                    if d != 255:
                        break
                for _ in range(runlength):
                    if rc >= s:
                        break
                    self._put565(rc, v, x, y, w); rc += 1
        elif sub > 129:
            pal = []
            for _ in range(sub - 128):
                pal.append(data[ptr] | (data[ptr + 1] << 8)); ptr += 2
            rc = 0
            while rc < s and ptr < len(data):
                runlength = 1
                index = data[ptr]; ptr += 1
                v = pal[index % 128]
                if index > 127:
                    while True:
                        d = data[ptr]; ptr += 1; runlength += d
                        if d != 255:
                            break
                for _ in range(runlength):
                    if rc >= s:
                        break
                    self._put565(rc, v, x, y, w); rc += 1
        else:
            raise ValueError(f"rle_subencoding_{sub}_unhandled")
        return sub, rc, ptr, len(data)

    def _blit_raw(self, data, x, y, w, h):
        fb = self.fb; W = self.width; p = 0
        for row in range(h):
            base = ((y + row) * W + x) * 3
            for col in range(w):
                v = data[p] | (data[p + 1] << 8); p += 2
                r = (v >> 11) & 0x1F; g = (v >> 5) & 0x3F; b = v & 0x1F
                o = base + col * 3
                fb[o] = (r << 3) | (r >> 2)
                fb[o + 1] = (g << 2) | (g >> 4)
                fb[o + 2] = (b << 3) | (b >> 2)

    def write_png(self, path):
        W, H = self.width, self.height
        raw = bytearray()
        for row in range(H):
            raw.append(0)
            raw += self.fb[row * W * 3:(row + 1) * W * 3]
        comp = zlib.compress(bytes(raw), 9)

        def chunk(typ, data):
            c = struct.pack(">I", len(data)) + typ + data
            return c + struct.pack(">I", zlib.crc32(typ + data) & 0xFFFFFFFF)
        png = b"\x89PNG\r\n\x1a\n"
        png += chunk(b"IHDR", struct.pack(">IIBBBBB", W, H, 8, 2, 0, 0, 0))
        png += chunk(b"IDAT", comp)
        png += chunk(b"IEND", b"")
        Path(path).write_bytes(png)
        return path

    # ---- client->server input (RFB KeyEvent type 4, PointerEvent type 5) ----
    def _key(self, keysym, down):
        self.ksend(bytes([4, 1 if down else 0, 0, 0]) + struct.pack(">I", keysym))
        if self.key_delay:
            time.sleep(self.key_delay)

    def tap(self, keysym):
        self._key(keysym, True)
        self._key(keysym, False)

    def named_key(self, name):
        ks = KEYSYM.get(name.lower())
        if ks is None:
            raise AmtError(f"unknown_key_{name}")
        self.tap(ks)

    def type_char(self, c):
        o = ord(c)
        if o < 0x20 or o > 0x7E:
            raise AmtError(f"non_ascii_char_0x{o:02x}")
        shift = c in _SHIFT_CHARS
        if shift:
            self._key(0xFFE1, True)
        self.tap(o)
        if shift:
            self._key(0xFFE1, False)

    def type_text(self, text):
        for c in text:
            self.type_char(c)
        return len(text)

    def cad(self):
        """Ctrl+Alt+Del — AMT injects it as a firmware USB HID, so the Windows
        secure attention sequence honors it at the logon secure desktop."""
        self._key(0xFFE3, True)   # Control_L down
        self._key(0xFFE9, True)   # Alt_L down
        self._key(0xFFFF, True)   # Delete down
        self._key(0xFFFF, False)
        self._key(0xFFE9, False)
        self._key(0xFFE3, False)

    def clear_field(self, max_back=64):
        """Select-all then delete, with a backspace sweep fallback."""
        self._key(0xFFE3, True)   # Control_L
        self.tap(ord('a'))
        self._key(0xFFE3, False)
        self.tap(0xFFFF)          # Delete
        for _ in range(max_back):
            self.tap(0xFF08)      # BackSpace

    def pointer(self, x, y, button_mask=0):
        self.ksend(bytes([5, button_mask & 0xFF]) + struct.pack(">HH", x, y))
        if self.key_delay:
            time.sleep(self.key_delay)

    def click(self, x, y, button="left"):
        mask = {"left": 1, "middle": 2, "right": 4}.get(button, 1)
        self.pointer(x, y, 0)          # move
        self.pointer(x, y, mask)       # down
        self.pointer(x, y, 0)          # up

    def button(self, x, y, down, button="left"):
        """Press (down=True) or release (down=False) a mouse button WITHOUT the
        paired release — for press-and-hold gestures such as the Windows
        password eye-reveal, which shows plaintext only while held."""
        mask = {"left": 1, "middle": 2, "right": 4}.get(button, 1) if down else 0
        self.pointer(x, y, mask)
