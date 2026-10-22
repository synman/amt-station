"""WS-MAN WRITE path: Put, Create, Delete and general method Invoke.

This module is deliberately SEPARATE from ``amt_wsman``, whose read client carries a fixed
``READ_METHODS`` allowlist and no Put/Create/Delete/Invoke. Nothing in the read tools imports
this module (``tests/test_write_tools.py`` pins that); only the confirmed-gated write tools in
``amt_write`` do. It reuses the read client's single network seam (``amt_wsman.transport``),
so every write inherits the same guarantees: the TLS leaf pin is enforced on connect, exactly
ONE authenticated attempt is made (no retry on a 401), and a Fault raises.

Secrets: a field whose NAME looks like a credential (at any depth, selectors and reference
parameters included) is refused as a caller-supplied value (``secret_field_refused``). The only way a credential enters a request is ``secret_fields``,
which maps a field name to a VAULT KEY resolved in-process; the value is never returned, and
any echo of it is scrubbed from the parsed response (the read client's name-based redaction
already masks password-named fields).
"""
from __future__ import annotations

import re
from typing import Any, NamedTuple
from xml.sax.saxutils import escape, quoteattr

import amt_registry
import amt_vault
import amt_wsman
from amt_wsman import WsmanError

A_PUT = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Put"
A_CREATE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create"
A_DELETE = "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete"
ADDR = "http://schemas.xmlsoap.org/ws/2004/08/addressing"
WSMAN = "http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd"

SECRET_SLOT = object()   # marks WHERE (in element order) a vault-resolved secret field goes
FIELD_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
METHOD_NAME = re.compile(r"[A-Za-z][A-Za-z0-9_]{0,63}")
MAX_FIELDS = 64
MAX_VALUE_CHARS = 4096
MAX_LIST_ITEMS = 64


class Epr(NamedTuple):
    """An endpoint reference to one instance (the shape CIM method parameters take)."""
    cls: str
    selectors: dict[str, str]


def epr(cls: str, selectors: dict[str, str]) -> Epr:
    amt_wsman.resource_uri(cls)          # validates the class name
    for name in selectors:
        if not amt_wsman.SELECTOR_NAME.fullmatch(str(name)):
            raise ValueError(f"invalid_selector_name:{name!r}")
    return Epr(cls, dict(selectors))


def _epr_xml(ref: Epr) -> str:
    sels = "".join(f"<Selector Name={quoteattr(str(k))}>{escape(str(v))}</Selector>"
                   for k, v in ref.selectors.items())
    return (f'<Address xmlns="{ADDR}">{ADDR}/role/anonymous</Address>'
            f'<ReferenceParameters xmlns="{ADDR}">'
            f'<ResourceURI xmlns="{WSMAN}">{amt_wsman.resource_uri(ref.cls)}</ResourceURI>'
            f'<SelectorSet xmlns="{WSMAN}">{sels}</SelectorSet></ReferenceParameters>')


def refuse_secret_names(fields) -> None:
    """A credential never travels as a caller-supplied field. Walks the whole structure: field
    names, reference-parameter (EPR) selector names, nested dicts and lists; the boolean-flag
    exemption (``UserPasswordBypass``) holds only for a boolean-ish value."""
    if isinstance(fields, Epr):                  # a NamedTuple, so it must be tested before tuple
        refuse_secret_names(fields.selectors)
    elif isinstance(fields, dict):
        for name, value in fields.items():
            if amt_wsman.is_secret_field(str(name), value):
                raise ValueError(f"secret_field_refused:{name}")
            refuse_secret_names(value)
    elif isinstance(fields, (list, tuple)):
        for value in fields:
            refuse_secret_names(value)


def _scalar(value: Any) -> str:
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        if len(value) > MAX_VALUE_CHARS:
            raise ValueError("field_value_too_long")
        return escape(value)
    raise ValueError(f"unsupported_field_value_type:{type(value).__name__}")


def fields_xml(fields: dict[str, Any]) -> str:
    """Render ``fields`` as ``<h:Name>`` children. Values: str/int/float/bool, a list of those
    (repeated elements), or an ``Epr`` (a reference parameter). Insertion order is preserved:
    AMT is sensitive to element order."""
    if len(fields) > MAX_FIELDS:
        raise ValueError("too_many_fields")
    parts = []
    for name, value in fields.items():
        if not FIELD_NAME.fullmatch(str(name)):
            raise ValueError(f"invalid_field_name:{name!r}")
        if value is None:
            continue
        if isinstance(value, Epr):
            parts.append(f"<h:{name}>{_epr_xml(value)}</h:{name}>")
        elif isinstance(value, (list, tuple)):
            if len(value) > MAX_LIST_ITEMS:
                raise ValueError("too_many_list_items")
            parts += [f"<h:{name}>{_scalar(v)}</h:{name}>" for v in value]
        else:
            parts.append(f"<h:{name}>{_scalar(value)}</h:{name}>")
    return "".join(parts)


class _Target:
    """Device, resolved AMT password (pin gate first) for one write call."""

    def __init__(self, device: str, password: str | None):
        self.device = device
        self.dev = amt_registry.get_device(device)
        self.password = amt_wsman.resolve_password(self.dev, password)

    def send(self, xml: str, secrets_: list[str] = ()) -> Any:
        """Send one envelope; a fault or transport error is re-raised with every credential this
        call knows (the AMT password and any vaulted value) and any credential-named ``Name=value``
        removed from its text."""
        try:
            return amt_wsman.parse(amt_wsman.transport(self.dev, xml, self.password))
        except amt_wsman.WsmanError as ex:
            clean = amt_wsman.redact_text(str(ex), [self.password, *secrets_])
            if clean == str(ex):
                raise
            raise type(ex)(clean) from None


def _vault_values(secret_fields: dict[str, str] | None) -> dict[str, str]:
    """``{field: resolved value}`` for in-process insertion; the keys are checked, values kept
    only for the duration of the call."""
    out = {}
    for name, vault_key in (secret_fields or {}).items():
        if not FIELD_NAME.fullmatch(str(name)):
            raise ValueError(f"invalid_field_name:{name!r}")
        out[name] = amt_vault.get_secret(vault_key)
    return out


def _scrub(value: Any, secrets_: list[str]) -> Any:
    """Defence in depth: remove any resolved secret that a device echoed under a name the
    name-based redaction did not catch."""
    if isinstance(value, dict):
        return {k: _scrub(v, secrets_) for k, v in value.items()}
    if isinstance(value, list):
        return [_scrub(v, secrets_) for v in value]
    if isinstance(value, str):
        for s in secrets_:
            if s and s in value:
                value = value.replace(s, "<redacted>")
    return value


def _first(body) -> dict[str, Any]:
    first = next(iter(body), None)
    return amt_wsman.instance(first) if first is not None else {}


def put(cls: str, fields: dict[str, Any], *, selectors: dict[str, str] | None = None,
        device: str = amt_wsman.DEFAULT_DEVICE, password: str | None = None,
        secret_fields: dict[str, str] | None = None) -> dict[str, Any]:
    """WS-Transfer Put of one instance. Returns the (redacted) instance the device sent back.

    ``secret_fields`` maps a field name to a VAULT KEY; the value is resolved here and inserted
    at the position of that name in ``fields`` when it carries ``SECRET_SLOT`` (AMT is
    sensitive to element order), else appended. Any other credential-named field is refused.
    """
    plain = {k: v for k, v in fields.items() if v is not SECRET_SLOT}
    refuse_secret_names(plain)
    refuse_secret_names(selectors)
    uri = amt_wsman.resource_uri(cls)
    fields_xml(plain)                               # validate names/values/selectors before any I/O
    amt_wsman.envelope(A_PUT, uri, "", selectors)
    if any(v is SECRET_SLOT and k not in (secret_fields or {}) for k, v in fields.items()):
        raise ValueError("secret_slot_without_vault_key")
    target = _Target(device, password)              # pin gate, then the AMT password
    secrets_ = _vault_values(secret_fields)         # only now the vaulted field values
    merged = {k: (secrets_[k] if v is SECRET_SLOT else v) for k, v in fields.items()}
    merged.update({k: v for k, v in secrets_.items() if k not in merged})
    xml = amt_wsman.envelope(A_PUT, uri, f'<h:{cls} xmlns:h="{uri}">{fields_xml(merged)}</h:{cls}>', selectors)
    return _scrub(_first(target.send(xml, list(secrets_.values()))), [target.password, *secrets_.values()])


def create(cls: str, fields: dict[str, Any], *, selectors: dict[str, str] | None = None,
           device: str = amt_wsman.DEFAULT_DEVICE, password: str | None = None) -> dict[str, Any]:
    """WS-Transfer Create of one instance. Returns the device's reply (the new reference)."""
    refuse_secret_names(fields)
    refuse_secret_names(selectors)
    uri = amt_wsman.resource_uri(cls)
    xml = amt_wsman.envelope(A_CREATE, uri, f'<h:{cls} xmlns:h="{uri}">{fields_xml(fields)}</h:{cls}>', selectors)
    target = _Target(device, password)
    return _scrub(_first(target.send(xml)), [target.password])


def delete(cls: str, *, selectors: dict[str, str], device: str = amt_wsman.DEFAULT_DEVICE,
           password: str | None = None) -> dict[str, Any]:
    """WS-Transfer Delete of the instance ``selectors`` names. A Delete with no selector is
    refused: it would name no instance."""
    if not selectors:
        raise ValueError("delete_requires_selectors")
    refuse_secret_names(selectors)
    xml = amt_wsman.envelope(A_DELETE, amt_wsman.resource_uri(cls), "", selectors)
    target = _Target(device, password)
    return _scrub(_first(target.send(xml)), [target.password])


def invoke(cls: str, method: str, params: dict[str, Any] | None = None, *,
           selectors: dict[str, str] | None = None, device: str = amt_wsman.DEFAULT_DEVICE,
           password: str | None = None, secret_params: dict[str, str] | None = None,
           rv_required: bool = True) -> dict[str, Any]:
    """Invoke any method on any AMT_/CIM_/IPS_ class. A non-zero ``ReturnValue`` raises.

    A reply with NO ``ReturnValue`` is "unknown", never "0": with ``rv_required`` (the default) it
    raises ``wsman_return_value_missing``; a caller that has already acted (a power request) passes
    ``rv_required=False`` and must treat the absent value as an unknown outcome itself.

    ``secret_params`` carries credential-derived VALUES a trusted in-process caller computed
    (for example a vaulted password's digest); it is the only place a credential-named
    parameter may appear, and it is scrubbed from the reply. Tools never pass caller input here.
    """
    if not METHOD_NAME.fullmatch(method or ""):
        raise ValueError(f"invalid_method_name:{method!r}")
    params = params or {}
    refuse_secret_names(params)
    refuse_secret_names(selectors)
    uri = amt_wsman.resource_uri(cls)
    inner = fields_xml(params) + fields_xml(secret_params or {})
    xml = amt_wsman.envelope(f"{uri}/{method}", uri, f'<h:{method}_INPUT xmlns:h="{uri}">{inner}</h:{method}_INPUT>',
                             selectors)
    target = _Target(device, password)
    sent = list((secret_params or {}).values())
    out = _scrub(_first(target.send(xml, sent)), [target.password, *sent])
    if not out:  # an empty reply is not a successful result
        raise WsmanError(f"wsman_empty_body:{cls}.{method}")
    rv = out.get("ReturnValue")
    if rv is None and rv_required:
        raise WsmanError(f"wsman_return_value_missing:{cls}.{method}: the request was sent; its outcome is unknown")
    if rv not in (None, "0"):
        raise WsmanError(f"wsman_return_value:{cls}.{method}:{rv}")
    return out
