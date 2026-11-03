"""amt_kvm incremental updates: a completed update counts as done in grab_update mode and as a
partial frame (re-requested) in grab_frame mode; a still screen returns False; the outstanding
request is re-sent only after UPDATE_RESEND_SECONDS."""
import socket
import struct

import amt_kvm


class _Sock:
    def __init__(self, chunks=()):
        self.chunks, self.timeout = list(chunks), 10

    def gettimeout(self):
        return self.timeout

    def settimeout(self, t):
        self.timeout = t

    def recv(self, n):
        if not self.chunks:
            raise socket.timeout()
        return self.chunks.pop(0)


def _session(chunks=()):
    s = amt_kvm.KvmSession("127.0.0.1", pw="x", key_delay=0)
    s.kvm, s.kvm_state, s.width, s.height = True, 4, 2, 2
    s.fb = bytearray(2 * 2 * 3)
    s.sent = []
    s.ksend = s.sent.append
    s.s = _Sock(chunks)
    return s


ONE_RAW_PIXEL = (b"\x00\x00\x00\x01" + struct.pack(">HHHHi", 0, 0, 1, 1, 0) + b"\xff\xff")


def test_grab_update_applies_a_partial_update_and_reports_change():
    s = _session([ONE_RAW_PIXEL])
    assert s.grab_update(wait=0.05) is True
    assert s.fb[:3] != b"\x00\x00\x00"                         # the one pixel was drawn
    assert s.sent == [bytes([3, 1]) + struct.pack(">HHHH", 0, 0, 2, 2)]   # one incremental request


def test_the_same_partial_update_in_full_frame_mode_is_re_requested():
    s = _session()
    s.acc = s.kvm_feed(ONE_RAW_PIXEL)
    assert s.frame_done is False
    assert s.sent[-1][:2] == bytes([3, 0])                      # non-incremental re-request


def test_a_still_screen_returns_false_and_does_not_spam_requests():
    s = _session()
    assert s.grab_update(wait=0.01) is False
    assert s.grab_update(wait=0.01) is False
    assert len(s.sent) == 1                                     # request still outstanding
    s.update_sent_at -= amt_kvm.KvmSession.UPDATE_RESEND_SECONDS + 0.1
    s.grab_update(wait=0.01)
    assert len(s.sent) == 2                                     # re-sent after the resend window
    assert s.s.timeout == 10                                    # socket timeout restored
