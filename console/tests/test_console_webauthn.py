"""The relying party's verification: every refusal names its check, and a valid ceremony passes."""
import json

import pytest

import webauthn_min as wa
from console_fakes import Authenticator, cbor

ORIGIN, RP = "https://console.example.test", "console.example.test"
CHALLENGE = wa.b64u_encode(b"c" * 32)


def opts():
    return {"publicKey": {"challenge": CHALLENGE}}


def register(**kw):
    a = Authenticator(RP, ORIGIN)
    r = a.register(opts(), **kw)
    return a, r


def verify_reg(r, **kw):
    args = dict(challenge=CHALLENGE, origin=ORIGIN, rp_id=RP)
    args.update(kw)
    return wa.verify_registration(wa.b64u_decode(r["clientDataJSON"]), wa.b64u_decode(r["attestationObject"]), **args)


def verify_ass(a, r, cred, **kw):
    args = dict(challenge=CHALLENGE, origin=ORIGIN, rp_id=RP, x=cred.x, y=cred.y, stored_count=0)
    args.update(kw)
    return wa.verify_assertion(wa.b64u_decode(r["clientDataJSON"]), wa.b64u_decode(r["authenticatorData"]),
                               wa.b64u_decode(r["signature"]), **args)


def test_a_valid_registration_and_assertion_pass():
    a, r = register()
    cred = verify_reg(r)
    assert cred.credential_id == a.cred_id
    assert verify_ass(a, a.assert_(opts()), cred) == 1


@pytest.mark.parametrize("name,kw,verify_kw,why", [
    ("flags_without_uv", {"flags": 0x41}, {}, "user_verification_required"),
    ("flags_without_up", {"flags": 0x44}, {}, "user_verification_required"),
    ("wrong_origin", {"origin": "https://evil.example"}, {}, "origin_mismatch"),
    ("wrong_rp", {"rp_id": "evil.example"}, {}, "rp_id_mismatch"),
    ("not_none_attestation", {"fmt": "packed"}, {}, "attestation_not_none"),
    ("wrong_algorithm", {"alg": -257}, {}, "unsupported_key"),
    ("wrong_challenge", {}, {"challenge": wa.b64u_encode(b"x" * 32)}, "challenge_mismatch"),
    ("no_attested_data", {"flags": 0x05}, {}, "no_credential_data"),
])
def test_registration_refusals_name_their_check(name, kw, verify_kw, why):
    _, r = register(**kw)
    with pytest.raises(wa.WebAuthnError, match=why):
        verify_reg(r, **verify_kw)


def test_registration_refuses_a_point_not_on_the_curve():
    a = Authenticator(RP, ORIGIN)
    r = a.register(opts())
    att = wa.cbor_decode(wa.b64u_decode(r["attestationObject"]))[0]
    auth = bytearray(att["authData"])
    auth[-1] ^= 0xFF                                         # corrupt the last byte of y
    att["authData"] = bytes(auth)
    r["attestationObject"] = wa.b64u_encode(cbor(att))
    with pytest.raises(wa.WebAuthnError, match="unsupported_key"):
        verify_reg(r)


def _reencode(r, edit):
    att = wa.cbor_decode(wa.b64u_decode(r["attestationObject"]))[0]
    edit(att)
    return dict(r, attestationObject=wa.b64u_encode(cbor(att)))


def test_registration_refuses_trailing_bytes_and_bad_credential_lengths():
    a, r = register()
    raw = wa.b64u_decode(r["attestationObject"])
    with pytest.raises(wa.WebAuthnError, match="bad_attestation"):
        verify_reg(dict(r, attestationObject=wa.b64u_encode(raw + b"\x00")))
    with pytest.raises(wa.WebAuthnError, match="bad_authenticator_data"):
        verify_reg(_reencode(r, lambda att: att.update(authData=att["authData"] + b"\x00")))
    for length in (0, 1000):
        def edit(att, n=length):
            auth = bytearray(att["authData"])
            auth[53:55] = n.to_bytes(2, "big")
            att["authData"] = bytes(auth)
        with pytest.raises(wa.WebAuthnError, match="bad_credential_id"):
            verify_reg(_reencode(r, edit))


def test_registration_refuses_a_cross_origin_client_data():
    a = Authenticator(RP, ORIGIN)
    r = a.register(opts())
    client = json.loads(wa.b64u_decode(r["clientDataJSON"]))
    client["crossOrigin"] = True
    r["clientDataJSON"] = wa.b64u_encode(json.dumps(client).encode())
    with pytest.raises(wa.WebAuthnError, match="cross_origin_refused"):
        verify_reg(r)


def test_assertion_refusals():
    a, r = register()
    cred = verify_reg(r)
    with pytest.raises(wa.WebAuthnError, match="user_verification_required"):
        verify_ass(a, a.assert_(opts(), flags=0x01), cred)
    with pytest.raises(wa.WebAuthnError, match="origin_mismatch"):
        verify_ass(a, a.assert_(opts(), origin="https://evil.example"), cred)
    with pytest.raises(wa.WebAuthnError, match="wrong_ceremony_type"):
        verify_ass(a, a.assert_(opts(), typ="webauthn.create"), cred)
    with pytest.raises(wa.WebAuthnError, match="challenge_mismatch"):
        verify_ass(a, a.assert_(opts()), cred, challenge=wa.b64u_encode(b"z" * 32))
    other = Authenticator(RP, ORIGIN)
    with pytest.raises(wa.WebAuthnError, match="bad_signature"):
        verify_ass(a, other.assert_(opts()), cred)           # signed by a different key


def test_a_counter_that_does_not_advance_is_a_clone_but_zero_counters_pass():
    a, r = register()
    cred = verify_reg(r)
    with pytest.raises(wa.WebAuthnError, match="counter_did_not_advance"):
        verify_ass(a, a.assert_(opts(), count=5), cred, stored_count=5)
    with pytest.raises(wa.WebAuthnError, match="counter_did_not_advance"):
        verify_ass(a, a.assert_(opts(), count=3), cred, stored_count=5)
    assert verify_ass(a, a.assert_(opts(), count=0), cred, stored_count=0) == 0    # authenticators that never count


@pytest.mark.parametrize("blob", [b"", b"\x1f", b"\x5f\x41a\xff", b"\xa2\x01\x01\x01\x02", b"\xc1\x01", b"\xf9\x00\x00", b"\x61"])
def test_cbor_rejects_what_the_profile_does_not_allow(blob):
    with pytest.raises(wa.WebAuthnError):
        wa.cbor_decode(blob)


def test_cbor_depth_is_bounded():
    with pytest.raises(wa.WebAuthnError, match="bad_cbor"):
        wa.cbor_decode(b"\x81" * 30 + b"\x00")
