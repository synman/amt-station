"""WS-MAN client for Intel AMT (TLS to the device's wsman_port, HTTP-digest auth).

Ported from the proven spike (``amtws_prior_art.py``) and narrowed to READ operations:
Get, Enumerate/Pull, and an allowlisted set of read-only method invocations (log and ACL
readers). There is deliberately no Put and no general Invoke here; write tools arrive in a
later packet behind a ``confirmed`` guard.

The AMT password is resolved through ``amt_vault.get_secret`` at call time, never stored on
disk, never logged, never placed in an exception message or URL. ``transport`` is the only
function that touches the network, which makes it the single seam tests replace.
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import os
import re
import secrets
import ssl
import uuid
import xml.etree.ElementTree as ET
from typing import Any, Iterable
from xml.sax.saxutils import escape, quoteattr

import amt_registry
import amt_vault

# The device a call that names none acts on; a deployment sets AMT_DEFAULT_DEVICE to one of its own keys.
DEFAULT_DEVICE = os.environ.get("AMT_DEFAULT_DEVICE") or "my-server-1"
USER = "admin"
TIMEOUT_SECONDS = 60
PAGE_SIZE = 20
MAX_PAGES = 100          # Pull requests per enumerate; bounds a never-ending EnumerationContext
WSMAN_PATH = "/wsman"

NS = {
    "AMT_": "http://intel.com/wbem/wscim/1/amt-schema/1/",
    "IPS_": "http://intel.com/wbem/wscim/1/ips-schema/1/",
    "CIM_": "http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/",
}
CLASS_NAME = re.compile(r"(AMT|CIM|IPS)_[A-Za-z0-9_]{1,80}")
SELECTOR_NAME = re.compile(r"[A-Za-z0-9_.-]{1,64}")

A_GET = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
A_ENUMERATE = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate"
A_PULL = "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull"
ENUM_NS = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"

# Method invocations this module will send. All are record READERS; anything that changes
# AMT state is absent on purpose (see module docstring).
READ_METHODS = frozenset({
    ("AMT_MessageLog", "GetRecords"),
    ("AMT_AuditLog", "ReadRecords"),
    ("AMT_AuthorizationService", "EnumerateUserAclEntries"),
    ("AMT_AuthorizationService", "GetUserAclEntryEx"),
})

# A field is credential-like when its name contains one of these long markers (case-insensitive)...
SECRET_FIELD = re.compile(r"password|passwd|passphrase|secret|credential|privatekey|sharedkey|apikey|"
                          r"masterkey|netadminpass|psk", re.I)
# ...or when one of its CamelCase/underscore WORDS is one of these short ones (a substring match
# would redact "Rapid" for "pid" and "Bypass" for "pass").
SECRET_WORDS = frozenset({"pwd", "pass", "token", "hash", "pps", "pid"})
_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")
# Flags whose name merely contains "password" but which carry no credential (a boot option).
# Such a name is exempt ONLY while its value is boolean-ish (``is_secret_field``).
NOT_CREDENTIAL_NAMES = frozenset({"UserPasswordBypass"})
_BOOLISH = frozenset({"true", "false", "0", "1"})


def is_secret_name(name: str) -> bool:
    """True for a field whose name marks it as a credential: redacted on every read, refused as a
    caller-supplied value on every write. Name-only: the ``NOT_CREDENTIAL_NAMES`` exemption is
    granted by ``is_secret_field``, which also looks at the value."""
    if name in NOT_CREDENTIAL_NAMES:
        return False
    return bool(SECRET_FIELD.search(name)) or any(w.lower() in SECRET_WORDS for w in _WORD.findall(name))


def is_boolish(value: Any) -> bool:
    if isinstance(value, bool):
        return True
    if isinstance(value, int):
        return value in (0, 1)
    return isinstance(value, str) and value.strip().lower() in _BOOLISH


def is_secret_field(name: str, value: Any) -> bool:
    """``is_secret_name``, except that an exempt flag name is a secret again unless its value is
    boolean-ish: a credential must not travel under a name the exemption makes invisible."""
    if name in NOT_CREDENTIAL_NAMES:
        return not is_boolish(value)
    return is_secret_name(name)


# ``Name=value``, ``Name: value`` or ``Name 'value'`` inside fault text, for a credential-like Name.
_TEXT_ASSIGN = re.compile(r"""(?P<name>[A-Za-z][A-Za-z0-9_]*)(?P<sep>\s*[=:]\s*|\s+(?=['"]))"""
                          r"""(?P<val>"[^"]*"|'[^']*'|[^\s,;|]+)""")


def redact_text(text: str, known_secrets: Iterable[str] = ()) -> str:
    """Fault/error text with credential-like ``Name=value`` pairs and any ``known_secrets`` removed."""
    for secret in known_secrets:
        if secret:
            text = text.replace(secret, "<redacted>")
    out, pos = [], 0
    while (m := _TEXT_ASSIGN.search(text, pos)) is not None:
        if is_secret_name(m["name"]):                 # consume the value only for a credential name,
            out.append(text[pos:m.start("val")] + "<redacted>")     # so "x:Password=v" is still seen
            pos = m.end()
        else:
            out.append(text[pos:m.end("sep")])
            pos = m.end("sep")
    return "".join(out) + text[pos:]


class WsmanError(Exception):
    """WS-MAN failure. Messages carry class names, codes and fault text, never credentials."""


class WsmanFault(WsmanError):
    """The device answered with a SOAP Fault (e.g. a class it does not expose). Distinct from
    transport/auth/pin failures, which say nothing about one class and must never be
    swallowed as "this class is unavailable"."""


def resource_uri(cls: str) -> str:
    if not CLASS_NAME.fullmatch(cls or ""):
        raise ValueError(f"invalid_class_name:{cls!r}")
    return NS[cls[:4]] + cls


def _selector_set(selectors: dict[str, str] | None) -> str:
    if not selectors:
        return ""
    parts = []
    for name, value in selectors.items():
        if not SELECTOR_NAME.fullmatch(str(name)):
            raise ValueError(f"invalid_selector_name:{name!r}")
        parts.append(f"<w:Selector Name={quoteattr(str(name))}>{escape(str(value))}</w:Selector>")
    return "<w:SelectorSet>" + "".join(parts) + "</w:SelectorSet>"


def envelope(action: str, uri: str, body: str = "", selectors: dict[str, str] | None = None) -> str:
    return (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<Envelope xmlns="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd">'
        f"<Header><a:Action>{action}</a:Action><a:To>/wsman</a:To>"
        f"<w:ResourceURI>{uri}</w:ResourceURI>"
        f"<a:MessageID>uuid:{uuid.uuid4()}</a:MessageID>"
        "<a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous"
        "</a:Address></a:ReplyTo>"
        f"<w:OperationTimeout>PT{TIMEOUT_SECONDS}S</w:OperationTimeout>"
        f"{_selector_set(selectors)}</Header><Body>{body}</Body></Envelope>"
    )


# --- network: the only part that touches the wire ---------------------------------------

class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """HTTPS connection that checks the leaf SHA-256 against the registry pin on EVERY connect.

    Fails closed: no pin means no connection (the chain is unverified, so the pin is the only
    identity check there is).
    """

    def __init__(self, *args: Any, pin: str | None = None, **kwargs: Any):
        super().__init__(*args, **kwargs)
        self._pin = pin

    def connect(self) -> None:
        super().connect()
        if not self._pin:
            self.sock.close()
            raise WsmanError("tls_leaf_unpinned_refused")
        der = self.sock.getpeercert(binary_form=True)
        fingerprint = hashlib.sha256(der).hexdigest() if der else ""
        if not hmac.compare_digest(fingerprint, self._pin):
            self.sock.close()
            raise WsmanError("tls_leaf_pin_mismatch")


def require_pin(device: amt_registry.Device) -> None:
    if not device.tls_leaf_sha256:
        raise WsmanError("tls_leaf_unpinned_refused")


def _open_connection(device: amt_registry.Device) -> http.client.HTTPSConnection:
    """Build one pinned connection. Tests replace this to avoid any socket."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # self-signed AMT leaf; identity comes from the pin
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    return _PinnedHTTPSConnection(device.amt_ip, device.wsman_port, timeout=TIMEOUT_SECONDS,
                                  context=ctx, pin=device.tls_leaf_sha256)


_HASHES = {"MD5": hashlib.md5, "SHA-256": hashlib.sha256}
_AUTH_PARAM = re.compile(r'([A-Za-z][A-Za-z0-9_-]*)\s*=\s*("(?:[^"\\]|\\.)*"|[^\s,]+)')


def parse_digest_challenge(header: str) -> dict[str, str]:
    """Parse a ``WWW-Authenticate: Digest ...`` value into a lower-cased-key dict."""
    head, _, rest = header.strip().partition(" ")
    if head.lower() != "digest":
        raise WsmanError("wsman_auth_unsupported_challenge")
    out = {}
    for name, val in _AUTH_PARAM.findall(rest):
        out[name.lower()] = re.sub(r"\\(.)", r"\1", val[1:-1]) if val.startswith('"') else val
    if "nonce" not in out or "realm" not in out:
        raise WsmanError("wsman_auth_unsupported_challenge")
    return out


def _quote(value: str) -> str:
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def digest_authorization(challenge: dict[str, str], user: str, password: str, method: str,
                         uri: str, cnonce: str, nc: int = 1) -> str:
    """RFC 2617/7616 Digest ``Authorization`` value for ONE request (MD5/SHA-256, -sess, qop=auth)."""
    algorithm = challenge.get("algorithm", "MD5")
    base = algorithm.upper().removesuffix("-SESS")
    if base not in _HASHES:
        raise WsmanError("wsman_auth_unsupported_algorithm")
    qops = [q.strip() for q in challenge.get("qop", "").split(",") if q.strip()]
    if qops and "auth" not in qops:
        raise WsmanError("wsman_auth_unsupported_qop")
    h = lambda text: _HASHES[base](text.encode("utf-8")).hexdigest()  # noqa: E731
    realm, nonce = challenge["realm"], challenge["nonce"]
    ha1 = h(f"{user}:{realm}:{password}")
    if algorithm.upper().endswith("-SESS"):
        ha1 = h(f"{ha1}:{nonce}:{cnonce}")
    ha2 = h(f"{method}:{uri}")
    ncv = f"{nc:08x}"
    if qops:
        response = h(f"{ha1}:{nonce}:{ncv}:{cnonce}:auth:{ha2}")
    else:
        response = h(f"{ha1}:{nonce}:{ha2}")
    parts = [f"username={_quote(user)}", f"realm={_quote(realm)}", f"nonce={_quote(nonce)}",
             f"uri={_quote(uri)}", f"response={_quote(response)}"]
    if "opaque" in challenge:
        parts.append(f"opaque={_quote(challenge['opaque'])}")
    parts.append(f"algorithm={_quote(algorithm)}")  # as the proven urllib client sent it
    if qops:
        parts += ["qop=auth", f"nc={ncv}", f"cnonce={_quote(cnonce)}"]
    return "Digest " + ", ".join(parts)


def _exchange(device: amt_registry.Device, data: bytes, headers: dict[str, str]):
    """One POST on a fresh pinned connection -> (status, response headers, body text)."""
    conn = _open_connection(device)
    try:
        conn.request("POST", WSMAN_PATH, body=data, headers=headers)
        resp = conn.getresponse()
        text = resp.read().decode("utf-8", errors="replace")
        return resp.status, resp, text
    finally:
        conn.close()


def resolve_password(device: amt_registry.Device, password: str | None) -> str:
    """Pin gate first (no secret is touched for an unpinned device), then the vault."""
    require_pin(device)
    return password if password is not None else amt_vault.get_secret(device.amt_vault_key)


def transport(device: amt_registry.Device, xml: str, password: str | None = None) -> str:
    """POST one SOAP envelope to the device and return the response body text.

    Tests replace this function. AT MOST ONE authenticated request is sent per call: one
    unauthenticated request obtains the Digest challenge, one authenticated request answers
    it, and a second 401 raises ``wsman_auth_failed_401`` with no further attempt (a wrong or
    rotated password must not be hammered into an AMT account lockout). A SOAP Fault
    delivered with a 4xx/5xx status is returned as text so ``parse`` can raise it with the
    fault's own reason. ``password`` lets a caller resolve the vault once for many calls.
    """
    pw = resolve_password(device, password)
    data = xml.encode("utf-8")
    base = {"Content-Type": "application/soap+xml;charset=UTF-8", "Connection": "close"}
    try:
        status, resp, text = _exchange(device, data, base)
        if status == 401:
            challenges = [v for v in resp.msg.get_all("WWW-Authenticate") or []
                          if v.strip().lower().startswith("digest")]
            if not challenges:
                raise WsmanError("wsman_auth_unsupported_challenge")
            auth = digest_authorization(parse_digest_challenge(challenges[0]), USER, pw, "POST",
                                        WSMAN_PATH, secrets.token_hex(8))
            status, resp, text = _exchange(device, data, {**base, "Authorization": auth})
            if status == 401:
                raise WsmanError("wsman_auth_failed_401")
    except WsmanError:
        raise
    except http.client.BadStatusLine:
        raise WsmanError("wsman_bad_status_line") from None
    except http.client.IncompleteRead:
        raise WsmanError("wsman_incomplete_read") from None
    except http.client.HTTPException as ex:
        raise WsmanError(f"wsman_http_protocol_error:{type(ex).__name__}") from None
    except OSError as ex:  # refused/reset/timeout/DNS/TLS handshake
        raise WsmanError(f"wsman_unreachable:{type(ex).__name__}") from None
    if 200 <= status < 300 or "Fault" in text:
        return text
    raise WsmanError(f"wsman_http_{status}")


# --- response parsing --------------------------------------------------------------------

def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _is_nil(el: ET.Element) -> bool:
    return any(_local(k) == "nil" and v.lower() == "true" for k, v in el.attrib.items())


def _value(el: ET.Element) -> Any:
    """Element -> str | None | dict. Repeated child names become lists; a secret-named field
    (``is_secret_name``) is redacted so no credential can leave through any read."""
    children = list(el)
    if not children:
        return None if _is_nil(el) else (el.text or "").strip()
    out: dict[str, Any] = {}
    for child in children:
        name = _local(child.tag)
        if name == "Selector" and child.get("Name"):
            name = f"Selector_{child.get('Name')}"
        val = _value(child)
        if is_secret_field(name, val):
            val = "<redacted>"
        if name in out:
            if not isinstance(out[name], list):
                out[name] = [out[name]]
            out[name].append(val)
        else:
            out[name] = val
    return out


def parse(xml: str) -> ET.Element:
    """Return the SOAP Body element, or raise WsmanError for a Fault or unparsable text."""
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        raise WsmanError("wsman_unparsable_response") from None
    body = next((c for c in root if _local(c.tag) == "Body"), None)
    if body is None:
        raise WsmanError("wsman_no_body")
    fault = next((c for c in body if _local(c.tag) == "Fault"), None)
    if fault is not None:
        texts = [(e.text or "").strip() for e in fault.iter() if _local(e.tag) in ("Text", "Value")]
        raise WsmanFault("wsman_fault:" + redact_text(" | ".join(t for t in texts if t))[:300])
    return body


def instance(el: ET.Element) -> dict[str, Any]:
    val = _value(el)
    return val if isinstance(val, dict) else {"value": val}


# --- operations ---------------------------------------------------------------------------

def get(cls: str, *, selectors: dict[str, str] | None = None,
        device: str = DEFAULT_DEVICE, password: str | None = None) -> dict[str, Any]:
    """WS-Transfer Get of one instance. Raises WsmanError on a fault."""
    dev = amt_registry.get_device(device)
    uri = resource_uri(cls)
    pw = resolve_password(dev, password)
    body = parse(transport(dev, envelope(A_GET, uri, "", selectors), pw))
    first = next(iter(body), None)
    if first is None:
        raise WsmanError(f"wsman_empty_body:{cls}")
    return instance(first)


def enumerate_(cls: str, *, max_items: int = 500, device: str = DEFAULT_DEVICE,
               password: str | None = None) -> tuple[list[dict[str, Any]], bool]:
    """WS-Enumeration Enumerate + Pull. Returns ``(instances, truncated)``.

    ``truncated`` is True whenever completeness is not proven: more instances than
    ``max_items``, the ``MAX_PAGES`` Pull budget ran out (an endless empty-page context
    cannot loop forever), or the sequence ended with neither EndOfSequence nor a context.
    """
    dev = amt_registry.get_device(device)
    uri = resource_uri(cls)
    pw = resolve_password(dev, password)
    body = parse(transport(dev, envelope(A_ENUMERATE, uri, f'<Enumerate xmlns="{ENUM_NS}"/>'), pw))
    items: list[dict[str, Any]] = []
    pulls = 0
    truncated = False
    while True:
        for el in body.iter():  # Enumerate may carry items already; Pull always does
            if _local(el.tag) == "Items":
                items += [instance(c) for c in el]
        if any(_local(el.tag) == "EndOfSequence" for el in body.iter()):
            truncated = len(items) > max_items
            break
        context = _find_text(body, "EnumerationContext")
        if context is None:  # no end marker and nothing to pull: completeness unprovable
            truncated = True
            break
        if len(items) >= max_items or pulls >= MAX_PAGES:
            truncated = True
            break
        pull = (f'<Pull xmlns="{ENUM_NS}"><EnumerationContext>{escape(context)}</EnumerationContext>'
                f"<MaxElements>{PAGE_SIZE}</MaxElements></Pull>")
        body = parse(transport(dev, envelope(A_PULL, uri, pull), pw))
        pulls += 1
    return items[:max_items], truncated


def _find_text(root: ET.Element, name: str) -> str | None:
    for el in root.iter():
        if _local(el.tag) == name and el.text and el.text.strip():
            return el.text.strip()
    return None


def invoke_read(cls: str, method: str, params: dict[str, Any] | None = None, *,
                selectors: dict[str, str] | None = None, device: str = DEFAULT_DEVICE,
                password: str | None = None) -> dict[str, Any]:
    """Invoke an allowlisted record-reading method and return its output dict."""
    if (cls, method) not in READ_METHODS:
        raise ValueError(f"method_not_allowed:{cls}.{method}")
    dev = amt_registry.get_device(device)
    uri = resource_uri(cls)
    pw = resolve_password(dev, password)
    inner = "".join(f"<h:{k}>{escape(str(v))}</h:{k}>" for k, v in (params or {}).items())
    xml = envelope(f"{uri}/{method}", uri, f'<h:{method}_INPUT xmlns:h="{uri}">{inner}</h:{method}_INPUT>',
                   selectors)
    body = parse(transport(dev, xml, pw))
    first = next(iter(body), None)
    if first is None:  # an empty reply is not a successful empty result
        raise WsmanError(f"wsman_empty_body:{cls}.{method}")
    out = instance(first)
    rv = out.get("ReturnValue")
    if rv not in (None, "0"):
        raise WsmanError(f"wsman_return_value:{cls}.{method}:{rv}")
    return out
