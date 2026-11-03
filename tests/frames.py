"""Frame helpers for the composite-tool tests: a stdlib PNG decoder (so real console captures
can be fed to the detectors as the RGB framebuffer ``KvmSession.fb`` holds) and small synthetic
console frames for the sequence tests.

The synthetic frames are NOT the grounding: they only drive the ordered-call tests, and
``test_screen_context_real_frames.py`` pins that the detectors read them as intended AND reads
the real captures. Each is deliberately more than a flat fill: a smooth wallpaper gradient (as
a real sign-in/desktop has) with a taskbar strip carrying icons, a sign-in box, a Run dialog.
"""
from __future__ import annotations

import hashlib
import struct
import zlib
from collections import namedtuple
from pathlib import Path

Shot = namedtuple("Shot", "width height fb")

# What each synthetic frame stands for, by content digest. The synthetic frames carry no
# legible text, so the composite-tool tests fake the OCR seam with this registry (see
# ``test_composite_tools.fake_ocr``); a frame not registered here reads as "no text".
KIND_BY_DIGEST: dict[str, str] = {}


def digest(fb) -> str:
    return hashlib.sha1(bytes(fb)).hexdigest()


def _tag(shot: Shot, kind: str) -> Shot:
    KIND_BY_DIGEST[digest(shot.fb)] = kind
    return shot


# --- PNG decode ------------------------------------------------------------------------

def decode_png(path) -> Shot:
    """Decode an 8-bit RGB (or RGBA, alpha dropped) non-interlaced PNG to a packed RGB buffer."""
    data = Path(path).read_bytes()
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError(f"not_a_png:{path}")
    pos, idat, ihdr = 8, bytearray(), None
    while pos < len(data):
        (length,) = struct.unpack(">I", data[pos:pos + 4])
        kind, body = data[pos + 4:pos + 8], data[pos + 8:pos + 8 + length]
        pos += 12 + length
        if kind == b"IHDR":
            ihdr = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            idat += body
        elif kind == b"IEND":
            break
    width, height, depth, ctype, _comp, _filt, interlace = ihdr
    if depth != 8 or ctype not in (2, 6) or interlace:
        raise ValueError(f"unsupported_png:{depth}/{ctype}/{interlace}")
    bpp = 3 if ctype == 2 else 4
    stride = width * bpp
    raw = zlib.decompress(bytes(idat))
    out = bytearray()
    prev = bytearray(stride)
    for row in range(height):
        ft = raw[row * (stride + 1)]
        cur = bytearray(raw[row * (stride + 1) + 1:(row + 1) * (stride + 1)])
        if ft == 1:
            for i in range(bpp, stride):
                cur[i] = (cur[i] + cur[i - bpp]) & 0xFF
        elif ft == 2:
            for i in range(stride):
                cur[i] = (cur[i] + prev[i]) & 0xFF
        elif ft == 3:
            for i in range(stride):
                left = cur[i - bpp] if i >= bpp else 0
                cur[i] = (cur[i] + ((left + prev[i]) >> 1)) & 0xFF
        elif ft == 4:
            for i in range(stride):
                a = cur[i - bpp] if i >= bpp else 0
                b = prev[i]
                c = prev[i - bpp] if i >= bpp else 0
                p = a + b - c
                pa, pb, pc = abs(p - a), abs(p - b), abs(p - c)
                pred = a if pa <= pb and pa <= pc else (b if pb <= pc else c)
                cur[i] = (cur[i] + pred) & 0xFF
        elif ft != 0:
            raise ValueError(f"png_filter_{ft}")
        prev = cur
        if bpp == 3:
            out += cur
        else:
            for i in range(0, stride, 4):
                out += cur[i:i + 3]
    return Shot(width, height, bytes(out))


# --- synthetic frames --------------------------------------------------------------------

def _build(width: int, height: int, row) -> bytes:
    out = bytearray()
    for y in range(height):
        out += row(y)
    return bytes(out)


def _paint(fb: bytes, width: int, height: int, box: tuple[float, float, float, float],
           colour: tuple[int, int, int]) -> bytes:
    """A copy of ``fb`` with the ratio box (x0, y0, x1, y1) filled with one colour."""
    buf = bytearray(fb)
    x0, y0, x1, y1 = int(width * box[0]), int(height * box[1]), int(width * box[2]), int(height * box[3])
    span = bytes(colour) * (x1 - x0)
    for y in range(y0, y1):
        buf[(y * width + x0) * 3:(y * width + x1) * 3] = span
    return bytes(buf)


def _gradient(width: int, height: int, top: tuple[int, int, int], bottom: tuple[int, int, int]) -> bytes:
    def row(y):
        t = y / max(height - 1, 1)
        return bytes(round(a + (b - a) * t) for a, b in zip(top, bottom)) * width
    return _build(width, height, row)


def signin_shot(width: int = 1280, height: int = 800) -> Shot:
    """Dark-blue smooth wallpaper, a user avatar and a password box: no taskbar."""
    fb = _gradient(width, height, (12, 30, 170), (8, 14, 70))
    fb = _paint(fb, width, height, (0.42, 0.22, 0.58, 0.42), (230, 230, 245))     # avatar
    fb = _paint(fb, width, height, (0.38, 0.55, 0.62, 0.60), (28, 28, 58))        # password box
    return _tag(Shot(width, height, fb), "signin")


def lock_shot(width: int = 1280, height: int = 800) -> Shot:
    """The lock-screen clock over a smooth wallpaper: not a desktop, no taskbar."""
    fb = _gradient(width, height, (10, 40, 200), (6, 10, 60))
    fb = _paint(fb, width, height, (0.43, 0.17, 0.57, 0.28), (250, 250, 250))     # the clock
    return _tag(Shot(width, height, fb), "lock")


def desktop_shot(width: int = 1280, height: int = 800,
                 bar_colour: tuple[int, int, int] = (16, 32, 58)) -> Shot:
    """Light wallpaper with the taskbar: a full-width strip, icons on the left, tray right."""
    bar = round(height * 0.06)
    fb = _gradient(width, height, (170, 205, 235), (120, 175, 225))
    fb = _paint(fb, width, height, (0.0, 1 - bar / height, 1.0, 1.0), bar_colour)
    for i in range(7):
        x0 = 0.015 + i * 0.035
        fb = _paint(fb, width, height, (x0, 1 - 0.045, x0 + 0.02, 1 - 0.012), (225, 225, 230))
    fb = _paint(fb, width, height, (0.90, 1 - 0.045, 0.98, 1 - 0.012), (210, 210, 215))
    return _tag(Shot(width, height, fb), "desktop")


def run_dialog_shot(base: Shot | None = None) -> Shot:
    """The desktop with the Win+R Run dialog open in the bottom-left."""
    base = base or desktop_shot()
    return Shot(base.width, base.height,
                _paint(base.fb, base.width, base.height, (0.02, 0.70, 0.30, 0.90), (245, 245, 245)))


def blank_shot(width: int = 1280, height: int = 800) -> Shot:
    return Shot(width, height, bytes(width * height * 3))


def bios_shot() -> Shot:
    """A 640x480 BIOS/POST-class frame: tiles on a smooth light background."""
    fb = _gradient(640, 480, (140, 175, 250), (180, 210, 255))
    fb = _paint(fb, 640, 480, (0.1, 0.72, 0.9, 0.88), (60, 80, 200))
    return Shot(640, 480, fb)


def horizon_shot(width: int = 1280, height: int = 800) -> Shot:
    """A sign-in-class screen whose wallpaper has a HARD full-width horizon edge near the bottom,
    under which the band is multicoloured rather than one colour: an edge without a taskbar."""
    bar = round(height * 0.06)
    base = _gradient(width, height, (12, 30, 170), (8, 14, 70))
    palette = [(200, 30, 30), (30, 200, 30), (30, 30, 200), (220, 220, 40), (40, 220, 220), (220, 40, 220)]
    stripe = b"".join(bytes(palette[(x * len(palette)) // 64 % len(palette)]) for x in range(width))
    buf = bytearray(base)
    for y in range(height - bar, height):
        buf[y * width * 3:(y + 1) * width * 3] = stripe
    return _tag(Shot(width, height, bytes(buf)), "signin")


TTY_STAGES = ("login", "password", "shell", "incorrect", "motd", "stale_login", "stale_password",
              "echo")


def tty_shot(stage: str, width: int = 1280, height: int = 800) -> Shot:
    """A Linux text console at one getty/login ``stage`` (``TTY_STAGES``); the composite tests
    serve the OCR text for it. The dark gradients differ per stage only to give each its own digest."""
    shade = TTY_STAGES.index(stage) + 1
    return _tag(Shot(width, height, _gradient(width, height, (shade, 0, 0), (0, 0, shade))), "tty_" + stage)


def console_shot(width: int = 1280, height: int = 800) -> Shot:
    """A non-Windows text screen (a Linux console over a framebuffer background, a boot loader,
    an installer): Windows-sized, no taskbar, not blank. Structurally indistinguishable from a
    sign-in, which is the point: only its text tells them apart."""
    return _tag(Shot(width, height, _gradient(width, height, (110, 20, 80), (16, 0, 16))), "console")


# --- REAL-OCR synthetic frames (PIL; the text is genuinely rendered, then read by a backend) ---

def rendered_text_shot(lines, *, left: float = 0.02, top: float = 0.04, size: int = 26,
                       background=None, width: int = 1280, height: int = 800) -> Shot:
    """Plain light-grey text lines at the left margin of a dark screen, as a text console prints
    them. ``background`` is a (top, bottom) gradient pair; None is flat black, which the blank
    detector reads as blank (as a real black console would be)."""
    from PIL import Image, ImageDraw, ImageFont
    if background is None:
        im = Image.new("RGB", (width, height), (0, 0, 0))
    else:
        im = Image.frombytes("RGB", (width, height), _gradient(width, height, *background))
    font = None
    for path in ("/System/Library/Fonts/Menlo.ttc", "/usr/share/fonts/truetype/dejavu/DejaVuSansMono.ttf"):
        try:
            font = ImageFont.truetype(path, size)
            break
        except OSError:
            continue
    if font is None:
        font = ImageFont.load_default(size=size)
    draw = ImageDraw.Draw(im)
    y = int(height * top)
    for line in lines:
        draw.text((int(width * left), y), line, fill=(215, 215, 215), font=font)
        y += size + 10
    return Shot(width, height, im.tobytes())
