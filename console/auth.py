"""Passkey enrollment, sign-in and sessions for the console. No password exists.

State lives in the console's own data folder (``AMT_CONSOLE_DATA``), 0600 files in a 0700 folder:
``passkeys.json`` (the enrolled public keys), ``sessions.json`` (SHA-256 of each session id, never the
id), and ``enroll.json`` (written by ``deploy/amt_admin.py console enroll-code``: the SHA-256 of the
12-character code and an expiry; this module deletes it on the first successful enrollment).

A session idles out after ``idle_seconds`` (12 h). An expired session is kept as a tombstone for a week
so the sign-in page can say "signed out after 12 hours idle" instead of showing a fresh sign-in.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import re
import secrets
import threading
import time
from pathlib import Path

import webauthn_min as wa

log = logging.getLogger("amt_console.auth")

ENROLL_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"      # the alphabet deploy/amt_admin.py mints from
ENROLL_LENGTH = 12
CHALLENGE_TTL = 300.0
MAX_PENDING = 256
TOMBSTONE_SECONDS = 7 * 86400
TOUCH_SECONDS = 60.0                                      # last_seen is persisted at most this often
USER_ID = hashlib.sha256(b"amt-console operator").digest()[:16]


class AuthError(Exception):
    """A refusal. ``code`` is a short stable reason; the message never carries a request value."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _write_json(path: Path, obj: object) -> None:
    tmp = path.with_name(f".{path.name}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "w") as fh:
        json.dump(obj, fh)
    os.replace(tmp, path)


def _read_json(path: Path, default: object) -> object:
    try:
        return json.loads(path.read_text())
    except FileNotFoundError:
        return default


def clean_name(name: object) -> str:
    """A passkey name: 1-64 printable characters."""
    if not isinstance(name, str):
        raise AuthError("bad_passkey_name")
    name = name.strip()
    if not 1 <= len(name) <= 64 or not name.isprintable():
        raise AuthError("bad_passkey_name")
    return name


def _b64_field(response: dict, key: str) -> bytes:
    value = response.get(key)
    if not isinstance(value, str):
        raise AuthError("bad_response")
    try:
        return wa.b64u_decode(value)
    except wa.WebAuthnError:
        raise AuthError("bad_response") from None


class Store:
    def __init__(self, data_dir: str | Path, rp_id: str, origin: str, *, idle_seconds: float = 12 * 3600,
                 enroll_attempts: int = 5, now=time.time):
        self.dir = Path(data_dir)
        self.rp_id, self.origin = rp_id, origin
        self.idle_seconds, self.enroll_attempts, self.now = idle_seconds, enroll_attempts, now
        self._lock = threading.RLock()
        self._pending: dict[str, dict] = {}
        self._enroll_failures = 0
        self.dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        if not os.access(self.dir, os.W_OK):
            raise PermissionError("console data folder is not writable")

    # -- files ----------------------------------------------------------------------------------------------
    @property
    def _passkeys_path(self) -> Path:
        return self.dir / "passkeys.json"

    @property
    def _sessions_path(self) -> Path:
        return self.dir / "sessions.json"

    @property
    def _enroll_path(self) -> Path:
        return self.dir / "enroll.json"

    def _passkeys(self) -> list[dict]:
        return _read_json(self._passkeys_path, [])

    def passkeys(self) -> list[dict]:
        """The enrolled passkeys, without key material."""
        with self._lock:
            return [{k: p[k] for k in ("id", "name", "created", "last_used")} for p in self._passkeys()]

    def has_passkeys(self) -> bool:
        with self._lock:
            return bool(self._passkeys())

    # -- challenges -----------------------------------------------------------------------------------------
    def _new_challenge(self, purpose: str, **data) -> str:
        with self._lock:
            now = self.now()
            for key in [k for k, v in self._pending.items() if v["exp"] < now]:
                del self._pending[key]
            if len(self._pending) >= MAX_PENDING:
                raise AuthError("too_many_pending")
            challenge = wa.b64u_encode(secrets.token_bytes(32))
            self._pending[challenge] = {"purpose": purpose, "exp": now + CHALLENGE_TTL, **data}
            return challenge

    def _take_challenge(self, client_data_json: bytes, purpose: str) -> tuple[str, dict]:
        """One-time: the challenge named in clientDataJSON is removed whether or not verification succeeds."""
        try:
            challenge = json.loads(client_data_json.decode("utf-8")).get("challenge")
        except (UnicodeDecodeError, ValueError, AttributeError):
            raise AuthError("bad_response") from None
        with self._lock:
            pending = self._pending.pop(challenge, None) if isinstance(challenge, str) else None
        if not pending or pending["purpose"] != purpose or pending["exp"] < self.now():
            raise AuthError("challenge_unknown")
        return challenge, pending

    def _creation_options(self, challenge: str, name: str) -> dict:
        return {"publicKey": {
            "rp": {"id": self.rp_id, "name": "amt-console"},
            "user": {"id": wa.b64u_encode(USER_ID), "name": "operator", "displayName": name},
            "challenge": challenge,
            "pubKeyCredParams": [{"type": "public-key", "alg": wa.ALG_ES256}],
            "timeout": 120000,
            "attestation": "none",
            "authenticatorSelection": {"residentKey": "required", "userVerification": "required"},
            "excludeCredentials": [{"type": "public-key", "id": p["id"]} for p in self._passkeys()],
        }}

    # -- enrollment (one-time code) -------------------------------------------------------------------------
    def _enroll_record(self) -> dict:
        try:
            rec = _read_json(self._enroll_path, None)
        except (OSError, ValueError):
            raise AuthError("enroll_not_open") from None
        if (not isinstance(rec, dict) or not re.fullmatch(r"[0-9a-f]{64}", str(rec.get("sha256")))
                or not isinstance(rec.get("expires"), (int, float))):
            raise AuthError("enroll_not_open")
        if rec["expires"] < self.now():
            self._enroll_path.unlink(missing_ok=True)
            raise AuthError("enroll_code_expired")
        return rec

    def enroll_begin(self, code: object, name: object) -> dict:
        name = clean_name(name)
        with self._lock:
            rec = self._enroll_record()
            text = re.sub(r"[\s-]", "", code).upper() if isinstance(code, str) else ""
            digest = hashlib.sha256(text.encode()).hexdigest()
            well_formed = len(text) == ENROLL_LENGTH and all(c in ENROLL_ALPHABET for c in text)
            if not (well_formed and hmac.compare_digest(digest, rec["sha256"])):
                self._enroll_failures += 1
                if self._enroll_failures >= self.enroll_attempts:
                    self._enroll_path.unlink(missing_ok=True)       # a guessed-at code is dead: mint a new one
                    self._enroll_failures = 0
                    log.warning("enrollment code withdrawn after %d wrong attempts", self.enroll_attempts)
                    raise AuthError("enroll_locked")
                raise AuthError("enroll_code_wrong")
            self._enroll_failures = 0
            challenge = self._new_challenge("enroll", name=name, digest=rec["sha256"])
            return self._creation_options(challenge, name)

    def enroll_finish(self, response: dict) -> dict:
        client_json = _b64_field(response, "clientDataJSON")
        challenge, pending = self._take_challenge(client_json, "enroll")
        cred = self._verify_registration(response, client_json, challenge)
        with self._lock:
            rec = self._enroll_record()
            if not hmac.compare_digest(rec["sha256"], pending["digest"]):
                raise AuthError("enroll_not_open")
            try:
                self._enroll_path.unlink()                           # consumed: one passkey per code
            except OSError:
                raise AuthError("enroll_consume_failed") from None
            return self._store_passkey(cred, pending["name"])

    # -- add a passkey from a signed-in session -------------------------------------------------------------
    def add_begin(self, name: object) -> dict:
        name = clean_name(name)
        return self._creation_options(self._new_challenge("add", name=name), name)

    def add_finish(self, response: dict) -> dict:
        client_json = _b64_field(response, "clientDataJSON")
        challenge, pending = self._take_challenge(client_json, "add")
        cred = self._verify_registration(response, client_json, challenge)
        return self._store_passkey(cred, pending["name"])

    def _verify_registration(self, response: dict, client_json: bytes, challenge: str) -> wa.Credential:
        try:
            return wa.verify_registration(client_json, _b64_field(response, "attestationObject"), challenge,
                                          self.origin, self.rp_id)
        except wa.WebAuthnError as ex:
            raise AuthError(f"registration_refused:{ex}") from None

    def _store_passkey(self, cred: wa.Credential, name: str) -> dict:
        with self._lock:
            keys = self._passkeys()
            cid = wa.b64u_encode(cred.credential_id)
            if any(p["id"] == cid for p in keys):
                raise AuthError("passkey_already_enrolled")
            rec = {"id": cid, "name": name, "x": wa.b64u_encode(cred.x), "y": wa.b64u_encode(cred.y),
                   "sign_count": cred.sign_count, "created": int(self.now()), "last_used": None}
            keys.append(rec)
            _write_json(self._passkeys_path, keys)
            log.info("passkey enrolled id=%s", cid[:22])
            return {k: rec[k] for k in ("id", "name", "created", "last_used")}

    # -- sign-in --------------------------------------------------------------------------------------------
    def signin_begin(self) -> dict:
        return {"publicKey": {"challenge": self._new_challenge("signin"), "rpId": self.rp_id, "timeout": 120000,
                              "userVerification": "required", "allowCredentials": []}}

    def signin_finish(self, response: dict) -> tuple[str, dict]:
        """Verify an assertion; returns (session cookie value, session)."""
        client_json = _b64_field(response, "clientDataJSON")
        challenge, _ = self._take_challenge(client_json, "signin")
        cid = response.get("id")
        with self._lock:
            key = next((p for p in self._passkeys() if p["id"] == cid), None)       # ids are public; no secret to time
            if key is None:
                log.warning("sign-in refused: passkey not enrolled id=%s", str(cid)[:22])
                raise AuthError("passkey_not_enrolled")
            try:
                count = wa.verify_assertion(client_json, _b64_field(response, "authenticatorData"),
                                            _b64_field(response, "signature"), challenge, self.origin, self.rp_id,
                                            wa.b64u_decode(key["x"]), wa.b64u_decode(key["y"]), key["sign_count"])
            except wa.WebAuthnError as ex:
                log.warning("sign-in refused: %s id=%s", ex, key["id"][:22])
                raise AuthError(f"assertion_refused:{ex}") from None
            keys = self._passkeys()
            for p in keys:
                if p["id"] == key["id"]:
                    p["sign_count"], p["last_used"] = count, int(self.now())
            _write_json(self._passkeys_path, keys)
            log.info("signed in id=%s", key["id"][:22])
            return self.new_session()

    # -- sessions -------------------------------------------------------------------------------------------
    @staticmethod
    def _session_key(cookie: str) -> str:
        return hashlib.sha256(cookie.encode()).hexdigest()

    def _sessions(self) -> dict:
        return _read_json(self._sessions_path, {})

    def new_session(self) -> tuple[str, dict]:
        with self._lock:
            now = self.now()
            sessions = {k: v for k, v in self._sessions().items()
                        if not (v.get("state") == "expired" and v.get("expired_at", 0) < now - TOMBSTONE_SECONDS)}
            cookie = secrets.token_urlsafe(32)
            sessions[self._session_key(cookie)] = rec = {"state": "live", "csrf": secrets.token_urlsafe(24),
                                                         "created": int(now), "last_seen": now}
            _write_json(self._sessions_path, sessions)
            return cookie, dict(rec)

    def lookup(self, cookie: str | None) -> tuple[str, dict | None]:
        """("ok", session) | ("expired", None) | ("none", None). An idle session is turned into a tombstone."""
        if not cookie:
            return "none", None
        with self._lock:
            sessions = self._sessions()
            key = self._session_key(cookie)
            rec = sessions.get(key)
            if rec is None:
                return "none", None
            now = self.now()
            if rec.get("state") == "expired":
                return "expired", None
            if now - rec["last_seen"] > self.idle_seconds:
                sessions[key] = {"state": "expired", "expired_at": now}
                _write_json(self._sessions_path, sessions)
                return "expired", None
            if now - rec["last_seen"] > TOUCH_SECONDS:
                rec["last_seen"] = now
                _write_json(self._sessions_path, sessions)
            return "ok", dict(rec)

    def session_ref(self, cookie: str | None) -> str | None:
        """The stable handle of a session (the hash its record is filed under), or None without a cookie. It names a session without
        being the cookie, so a holder of it (the embed keys, embed.Keys) can ask whether the session still lives but cannot act as it."""
        return self._session_key(cookie) if cookie else None

    def is_live(self, ref: str | None) -> bool:
        """Whether the session behind ``session_ref`` is signed in and not idle-expired. It does not touch the session: only the
        page's own cookie-carrying requests keep a session alive."""
        if not ref:
            return False
        with self._lock:
            rec = self._sessions().get(ref)
            return bool(rec) and rec.get("state") == "live" and self.now() - rec["last_seen"] <= self.idle_seconds

    def destroy(self, cookie: str | None) -> None:
        if not cookie:
            return
        with self._lock:
            sessions = self._sessions()
            if sessions.pop(self._session_key(cookie), None) is not None:
                _write_json(self._sessions_path, sessions)

    @staticmethod
    def csrf_ok(session: dict, presented: str | None) -> bool:
        return bool(presented) and hmac.compare_digest(session["csrf"].encode(), presented.encode())
