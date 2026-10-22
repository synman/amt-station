"""A minimal, verified WebAuthn relying party for the console's passkeys.

Only what this console asks of an authenticator is accepted: ES256 (COSE alg -7, P-256), attestation
"none", user verification required, one origin, one RP id. Registration and assertion are both
verified here, server-side, with ``cryptography`` for the signature and a small strict CBOR reader
for the authenticator's data. Anything outside that profile is refused with a ``WebAuthnError``
whose text names the failed check, never a value from the request.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import struct
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec

ALG_ES256 = -7
FLAG_UP, FLAG_UV, FLAG_AT, FLAG_ED = 0x01, 0x04, 0x40, 0x80


class WebAuthnError(Exception):
    """A registration or assertion failed verification. The message names the check."""


def b64u_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def b64u_decode(text: str) -> bytes:
    if not isinstance(text, str) or not text.isascii():
        raise WebAuthnError("bad_base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise WebAuthnError("bad_base64url") from None


# -- CBOR: definite lengths only; unsigned/negative ints, byte/text strings, arrays, maps, bool/null ----------

_MAX_DEPTH = 8


def cbor_decode(data: bytes, offset: int = 0, depth: int = 0) -> tuple[object, int]:
    """Decode one item from ``data[offset:]``; returns (value, offset after it)."""
    if depth > _MAX_DEPTH or offset >= len(data):
        raise WebAuthnError("bad_cbor")
    head = data[offset]
    major, info = head >> 5, head & 0x1F
    offset += 1
    if major == 7:
        if info in (20, 21):
            return info == 21, offset
        if info == 22:
            return None, offset
        raise WebAuthnError("bad_cbor")
    if info < 24:
        arg = info
    elif info in (24, 25, 26, 27):
        size = {24: 1, 25: 2, 26: 4, 27: 8}[info]
        if offset + size > len(data):
            raise WebAuthnError("bad_cbor")
        arg = int.from_bytes(data[offset:offset + size], "big")
        offset += size
    else:
        raise WebAuthnError("bad_cbor")                      # indefinite lengths and reserved values
    if major == 0:
        return arg, offset
    if major == 1:
        return -1 - arg, offset
    if major in (2, 3):
        if offset + arg > len(data):
            raise WebAuthnError("bad_cbor")
        raw = data[offset:offset + arg]
        offset += arg
        if major == 2:
            return bytes(raw), offset
        try:
            return raw.decode("utf-8"), offset
        except UnicodeDecodeError:
            raise WebAuthnError("bad_cbor") from None
    if major == 4:
        if arg > len(data):
            raise WebAuthnError("bad_cbor")
        out = []
        for _ in range(arg):
            item, offset = cbor_decode(data, offset, depth + 1)
            out.append(item)
        return out, offset
    if major == 5:
        if arg > len(data):
            raise WebAuthnError("bad_cbor")
        mapping: dict = {}
        for _ in range(arg):
            key, offset = cbor_decode(data, offset, depth + 1)
            value, offset = cbor_decode(data, offset, depth + 1)
            if not isinstance(key, (int, str)) or key in mapping:
                raise WebAuthnError("bad_cbor")
            mapping[key] = value
        return mapping, offset
    raise WebAuthnError("bad_cbor")                          # tags and floats are not part of the profile


# -- the checks both ceremonies share ---------------------------------------------------------------------------

def _client_data(client_data_json: bytes, ceremony: str, challenge: str, origin: str) -> bytes:
    """Verify clientDataJSON; returns its SHA-256 (the signature input for an assertion)."""
    try:
        data = json.loads(client_data_json.decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise WebAuthnError("bad_client_data") from None
    if not isinstance(data, dict):
        raise WebAuthnError("bad_client_data")
    if data.get("type") != ceremony:
        raise WebAuthnError("wrong_ceremony_type")
    got = data.get("challenge")
    if not isinstance(got, str) or not hmac.compare_digest(got.encode(), challenge.encode()):
        raise WebAuthnError("challenge_mismatch")
    if data.get("origin") != origin:
        raise WebAuthnError("origin_mismatch")
    if data.get("crossOrigin") is True:
        raise WebAuthnError("cross_origin_refused")
    return hashlib.sha256(client_data_json).digest()


def _auth_data_head(auth_data: bytes, rp_id: str) -> tuple[int, int]:
    """rpIdHash, flags (user presence AND verification required) and signCount of authenticator data."""
    if len(auth_data) < 37:
        raise WebAuthnError("bad_authenticator_data")
    if not hmac.compare_digest(auth_data[:32], hashlib.sha256(rp_id.encode()).digest()):
        raise WebAuthnError("rp_id_mismatch")
    flags = auth_data[32]
    if not flags & FLAG_UP or not flags & FLAG_UV:
        raise WebAuthnError("user_verification_required")
    return flags, struct.unpack(">I", auth_data[33:37])[0]


@dataclass(frozen=True)
class Credential:
    credential_id: bytes
    x: bytes
    y: bytes
    sign_count: int


def verify_registration(client_data_json: bytes, attestation_object: bytes, challenge: str,
                        origin: str, rp_id: str) -> Credential:
    """Verify a ``navigator.credentials.create`` response (attestation "none", ES256) and return the credential."""
    _client_data(client_data_json, "webauthn.create", challenge, origin)
    att, end = cbor_decode(attestation_object)
    if end != len(attestation_object) or not isinstance(att, dict):
        raise WebAuthnError("bad_attestation")
    if att.get("fmt") != "none" or att.get("attStmt") != {}:
        raise WebAuthnError("attestation_not_none")
    auth_data = att.get("authData")
    if not isinstance(auth_data, bytes):
        raise WebAuthnError("bad_attestation")
    flags, count = _auth_data_head(auth_data, rp_id)
    if not flags & FLAG_AT or len(auth_data) < 55:
        raise WebAuthnError("no_credential_data")
    cred_len = struct.unpack(">H", auth_data[53:55])[0]
    if cred_len == 0 or cred_len > 1023 or 55 + cred_len > len(auth_data):
        raise WebAuthnError("bad_credential_id")
    cred_id = bytes(auth_data[55:55 + cred_len])
    cose, end = cbor_decode(auth_data, 55 + cred_len)
    if end != len(auth_data) and not flags & FLAG_ED:
        raise WebAuthnError("bad_authenticator_data")
    if (not isinstance(cose, dict) or cose.get(1) != 2 or cose.get(3) != ALG_ES256 or cose.get(-1) != 1
            or not isinstance(cose.get(-2), bytes) or not isinstance(cose.get(-3), bytes)
            or len(cose[-2]) != 32 or len(cose[-3]) != 32):
        raise WebAuthnError("unsupported_key")
    _public_key(cose[-2], cose[-3])                          # rejects a point that is not on the curve
    return Credential(cred_id, cose[-2], cose[-3], count)


def _public_key(x: bytes, y: bytes) -> ec.EllipticCurvePublicKey:
    try:
        return ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"),
                                             ec.SECP256R1()).public_key()
    except ValueError:
        raise WebAuthnError("unsupported_key") from None


def verify_assertion(client_data_json: bytes, auth_data: bytes, signature: bytes, challenge: str, origin: str,
                     rp_id: str, x: bytes, y: bytes, stored_count: int) -> int:
    """Verify a ``navigator.credentials.get`` response against the stored key; returns the new signCount.

    A counter that does not advance (when either side is non-zero) is a cloned authenticator and is refused;
    authenticators that never count (both zero) pass."""
    client_hash = _client_data(client_data_json, "webauthn.get", challenge, origin)
    _, count = _auth_data_head(auth_data, rp_id)
    try:
        _public_key(x, y).verify(signature, auth_data + client_hash, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        raise WebAuthnError("bad_signature") from None
    if (count or stored_count) and count <= stored_count:
        raise WebAuthnError("counter_did_not_advance")
    return count
