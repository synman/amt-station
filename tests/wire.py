"""A recording fake of the WS-MAN transport for the write-tool tests.

``Wire.transport`` replaces ``amt_wsman.transport``, the single network seam, so no socket is
opened and no host is touched. It parses the SOAP request the code under test really built
(action, class, selectors, body fields), records it as a ``Call`` and answers like a small device:
Get returns a stored instance, Put merges into it, a method invocation returns ``ReturnValue``
(0 unless a test says otherwise) plus any handler-supplied output.
"""
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Any, Callable
from xml.sax.saxutils import escape

import amt_wsman

S = "http://www.w3.org/2003/05/soap-envelope"
XSI = "http://www.w3.org/2001/XMLSchema-instance"


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def soap(body: str) -> str:
    return f'<s:Envelope xmlns:s="{S}"><s:Header/><s:Body>{body}</s:Body></s:Envelope>'


def fault_xml(text: str) -> str:
    return soap(f"<s:Fault><s:Code><s:Value>s:Sender</s:Value></s:Code><s:Reason><s:Text>{escape(text)}</s:Text>"
                "</s:Reason></s:Fault>")


def fields_xml(fields: dict[str, Any]) -> str:
    out = []
    for name, value in fields.items():
        values = value if isinstance(value, list) else [value]
        for v in values:
            if v is None:
                out.append(f'<h:{name} xmlns:xsi="{XSI}" xsi:nil="true"/>')
            else:
                out.append(f"<h:{name}>{escape(str(v))}</h:{name}>")
    return "".join(out)


def instance_xml(cls: str, fields: dict[str, Any]) -> str:
    uri = amt_wsman.resource_uri(cls)
    return f'<h:{cls} xmlns:h="{uri}">{fields_xml(fields)}</h:{cls}>'


@dataclass
class Call:
    op: str                       # get | put | create | delete | invoke | other
    action: str
    cls: str
    method: str | None
    selectors: dict[str, str]
    fields: dict[str, Any]        # Put/Create/Invoke body children, in request order
    xml: str
    order: list[str] = field(default_factory=list)   # body child names in request order


def _field_value(el: ET.Element) -> Any:
    if any(_local(c.tag) == "ReferenceParameters" for c in el):
        ref = next(c for c in el if _local(c.tag) == "ReferenceParameters")
        uri = next(e.text for e in ref.iter() if _local(e.tag) == "ResourceURI")
        sels = {s.get("Name"): s.text for s in ref.iter() if _local(s.tag) == "Selector"}
        return {"epr": {"class": uri.rsplit("/", 1)[-1], "selectors": sels}}
    return el.text or ""


def parse_request(xml: str) -> Call:
    root = ET.fromstring(xml)
    header = next(c for c in root if _local(c.tag) == "Header")
    body = next(c for c in root if _local(c.tag) == "Body")
    action = next(e.text for e in header if _local(e.tag) == "Action")
    uri = next(e.text for e in header if _local(e.tag) == "ResourceURI")
    selectors = {s.get("Name"): s.text for s in header.iter() if _local(s.tag) == "Selector"}
    cls = uri.rsplit("/", 1)[-1]
    first = next(iter(body), None)
    fields: dict[str, Any] = {}
    order: list[str] = []
    if first is not None:
        for child in first:
            name = _local(child.tag)
            order.append(name)
            value = _field_value(child)
            if name in fields:
                fields[name] = (fields[name] if isinstance(fields[name], list) else [fields[name]]) + [value]
            else:
                fields[name] = value
    method = None
    if action.endswith("/transfer/Get"):
        op = "get"
    elif action.endswith("/transfer/Put"):
        op = "put"
    elif action.endswith("/transfer/Create"):
        op = "create"
    elif action.endswith("/transfer/Delete"):
        op = "delete"
    elif "/enumeration/" in action:
        op = "other"
    else:
        op, method = "invoke", action.rsplit("/", 1)[-1]
    return Call(op, action, cls, method, selectors, fields, xml, order)


class Wire:
    """Install with ``monkeypatch.setattr(amt_wsman, "transport", wire.transport)``."""

    def __init__(self):
        self.calls: list[Call] = []
        self.instances: dict[str, dict[str, Any]] = {}          # class -> fields served by Get
        self.faults: dict[tuple, str] = {}                      # ("put", cls) / ("invoke", cls, method) -> text
        self.return_values: dict[tuple[str, str], str] = {}     # (cls, method) -> ReturnValue text
        self.handlers: dict[tuple[str, str], Callable[[Call], dict[str, Any]]] = {}   # extra OUTPUT fields
        self.on_put: dict[str, Callable[[Call], None]] = {}
        self.ignore_put: set[str] = set()                       # classes whose Put the device silently ignores
        self.echo_extra: dict[str, dict[str, Any]] = {}         # class -> extra fields echoed on Put

    def transport(self, device, xml, password=None):
        call = parse_request(xml)
        self.calls.append(call)
        if call.op == "get":
            if call.cls not in self.instances:
                return fault_xml(f"no such class {call.cls}")
            return soap(instance_xml(call.cls, self.instances[call.cls]))
        if call.op == "put":
            if ("put", call.cls) in self.faults:
                return fault_xml(self.faults[("put", call.cls)])
            if call.cls not in self.ignore_put:
                self.instances.setdefault(call.cls, {}).update(call.fields)
            if call.cls in self.on_put:
                self.on_put[call.cls](call)
            return soap(instance_xml(call.cls, {**call.fields, **self.echo_extra.get(call.cls, {})}))
        if call.op == "create":
            return soap('<x:ResourceCreated xmlns:x="http://schemas.xmlsoap.org/ws/2004/08/addressing">'
                        "<x:Address>created</x:Address></x:ResourceCreated>")
        if call.op == "delete":
            return soap("")
        if call.op == "invoke":
            key = (call.cls, call.method)
            if ("invoke", *key) in self.faults:
                return fault_xml(self.faults[("invoke", *key)])
            extra = self.handlers[key](call) if key in self.handlers else {}
            rv = self.return_values.get(key, "0")
            uri = amt_wsman.resource_uri(call.cls)
            return soap(f'<h:{call.method}_OUTPUT xmlns:h="{uri}">'
                        f"{fields_xml({'ReturnValue': rv, **extra})}</h:{call.method}_OUTPUT>")
        return fault_xml("unsupported in fake")

    # -- helpers for assertions -------------------------------------------------------------
    def actions(self) -> list[str]:
        return [c.action.rsplit("/", 1)[-1] for c in self.calls]

    def ops(self) -> list[tuple[str, str, str | None]]:
        return [(c.op, c.cls, c.method) for c in self.calls]

    def writes(self) -> list[Call]:
        return [c for c in self.calls if c.op != "get"]

    def all_xml(self) -> str:
        return "\n".join(c.xml for c in self.calls)
