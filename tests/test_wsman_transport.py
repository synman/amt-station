"""WS-MAN transport tests: manual Digest (one authenticated attempt), TLS pin, loop bounds,
completeness, redaction. No socket is opened and the real vault is never read: the single
network seam ``amt_wsman._open_connection`` is replaced by ``FakeConn``."""
import http.client
import hashlib
import re
import sys
import urllib.request
from email.message import Message
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import amt_registry  # noqa: E402
import amt_vault  # noqa: E402
import amt_wsman  # noqa: E402

PW = "PW-SENTINEL-transport-test"
DEV = amt_registry.get_device("my-server-1")
CHALLENGE = ('Digest realm="Digest:A1B2", nonce="abc123nonce", stale=false, '
             'qop="auth", opaque="opq-1", algorithm=MD5')


# The WWW-Authenticate value the live AMT 19.0.5 sent (captured read-only, no credentials sent).
AMT_LIVE_CHALLENGE = ('Digest realm="Digest:5688065F57A415FAA5135911FE20343F", '
                      'nonce="kZevBEBAAAAAAAAA6P+IqlgcBl5N4Nxi",stale="false",qop="auth,auth-int, auth"')


def soap(body: str) -> str:
    return ('<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"><s:Header/>'
            f"<s:Body>{body}</s:Body></s:Envelope>")


class FakeResp:
    def __init__(self, status, text="", headers=()):
        self.status, self._text = status, text
        self.msg = Message()
        for k, v in headers:
            self.msg[k] = v

    def read(self):
        return self._text.encode()


class FakeConn:
    def __init__(self, responder, log):
        self._responder, self._log, self._sent = responder, log, None

    def request(self, method, path, body=None, headers=None):
        self._sent = (method, path, body, dict(headers or {}))
        self._log.append(self._sent)

    def getresponse(self):
        out = self._responder(self._sent[3], len(self._log))
        if isinstance(out, Exception):
            raise out
        return out

    def close(self):
        pass


@pytest.fixture
def wire(monkeypatch):
    """Install a responder; returns the request log [(method, path, body, headers), ...]."""
    log = []

    def install(responder):
        monkeypatch.setattr(amt_wsman, "_open_connection", lambda dev: FakeConn(responder, log))
        return log

    install.log = log
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: PW)
    return install


def authed(log):
    return [r for r in log if "Authorization" in r[3]]


# --- item 1: exactly one authenticated attempt ------------------------------------------------

def test_always_401_sends_at_most_one_authenticated_request(wire):
    log = wire(lambda h, n: FakeResp(401, "denied", [("WWW-Authenticate", CHALLENGE)]))
    with pytest.raises(amt_wsman.WsmanError) as ex:
        amt_wsman.transport(DEV, "<x/>")
    assert str(ex.value) == "wsman_auth_failed_401" and PW not in str(ex.value)
    assert len(log) == 2 and len(authed(log)) == 1
    assert "Authorization" not in log[0][3]


def test_401_without_a_digest_challenge_sends_no_credentials(wire):
    for header in ([], [("WWW-Authenticate", 'Basic realm="x"')], [("WWW-Authenticate", "Negotiate")]):
        log = wire(lambda h, n, header=header: FakeResp(401, "", header))
        log.clear()
        with pytest.raises(amt_wsman.WsmanError, match="wsman_auth_unsupported_challenge"):
            amt_wsman.transport(DEV, "<x/>")
        assert len(log) == 1 and authed(log) == []


def test_challenge_then_success_answers_with_a_valid_digest(wire):
    def responder(headers, n):
        if "Authorization" not in headers:
            return FakeResp(401, "", [("WWW-Authenticate", CHALLENGE)])
        return FakeResp(200, "<ok/>")

    log = wire(responder)
    assert amt_wsman.transport(DEV, "<x/>") == "<ok/>"
    assert len(log) == 2
    method, path, body, headers = log[1]
    assert (method, path, body) == ("POST", "/wsman", b"<x/>")
    parsed = dict(re.findall(r'(\w+)="?([^",]+)"?', headers["Authorization"]))
    ha1 = hashlib.md5(f"admin:Digest:A1B2:{PW}".encode()).hexdigest()
    ha2 = hashlib.md5(b"POST:/wsman").hexdigest()
    want = hashlib.md5(
        f"{ha1}:abc123nonce:00000001:{parsed['cnonce']}:auth:{ha2}".encode()).hexdigest()
    assert parsed["response"] == want and parsed["nc"] == "00000001" and parsed["opaque"] == "opq-1"
    assert PW not in headers["Authorization"]


def test_digest_matches_the_urllib_reference_implementation(monkeypatch):
    """Same inputs through urllib's digest handler (the code being replaced) must give the
    same response value: this is the offline proof the header math is right."""
    mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
    mgr.add_password(None, "https://h:16993/wsman", "admin", PW)
    handler = urllib.request.HTTPDigestAuthHandler(mgr)
    monkeypatch.setattr(handler, "get_cnonce", lambda nonce: "fixedcnonce0123")
    req = urllib.request.Request("https://h:16993/wsman", data=b"<x/>")
    for header in (CHALLENGE, 'Digest realm="Digest:A1B2", nonce="n2", opaque="o2"', AMT_LIVE_CHALLENGE):
        ref_chal = urllib.request.parse_keqv_list(
            urllib.request.parse_http_list(header.split(" ", 1)[1]))
        ref = handler.get_authorization(req, ref_chal)
        ours = amt_wsman.digest_authorization(
            amt_wsman.parse_digest_challenge(header), "admin", PW, "POST", "/wsman", "fixedcnonce0123")
        pick = lambda text: dict(re.findall(r'(\w+)="?([^",]+)"?', text))  # noqa: E731
        assert pick(ours) == pick(ref), header      # every field, not just the response


def test_digest_rfc_vectors():
    c = amt_wsman.parse_digest_challenge(
        'Digest realm="testrealm@host.com", qop="auth,auth-int", '
        'nonce="dcd98b7102dd2f0e8b11d0f600bfb0c093", opaque="5ccc069c403ebaf9f0171e9517f40e41"')
    hdr = amt_wsman.digest_authorization(c, "Mufasa", "Circle Of Life", "GET", "/dir/index.html", "0a4f113b")
    assert 'response="6629fae49393a05397450978507c4ef1"' in hdr
    c = amt_wsman.parse_digest_challenge(
        'Digest realm="http-auth@example.org", qop="auth, auth-int", algorithm=SHA-256, '
        'nonce="7ypf/xlj9XXwfDPEoM4URrv/xwf94BcCAzFZH4GiTo0v", opaque="FQhe/qaU925kfnzjCev0ciny7QMkPqMAFRtzCUYo5tdS"')
    hdr = amt_wsman.digest_authorization(c, "Mufasa", "Circle of Life", "GET", "/dir/index.html",
                                         "f2/wE4q74E6zIJEtWaHKaf5wv/H5QzzpXusqGemxURZJ")
    assert 'response="753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1"' in hdr


def test_unsupported_digest_algorithm_or_qop_refused():
    with pytest.raises(amt_wsman.WsmanError, match="unsupported_algorithm"):
        amt_wsman.digest_authorization({"realm": "r", "nonce": "n", "algorithm": "SHA-512-256"},
                                       "admin", PW, "POST", "/wsman", "c")
    with pytest.raises(amt_wsman.WsmanError, match="unsupported_qop"):
        amt_wsman.digest_authorization({"realm": "r", "nonce": "n", "qop": "auth-int"},
                                       "admin", PW, "POST", "/wsman", "c")


# --- transport failure mapping ----------------------------------------------------------------

def test_transport_failure_mapping(wire):
    wire(lambda h, n: FakeResp(500, "<Envelope><Fault>boom</Fault></Envelope>"))
    assert "Fault" in amt_wsman.transport(DEV, "<x/>")
    wire(lambda h, n: FakeResp(503, "gateway text"))
    with pytest.raises(amt_wsman.WsmanError, match="wsman_http_503"):
        amt_wsman.transport(DEV, "<x/>")
    for exc, want in ((http.client.BadStatusLine("garbage"), "wsman_bad_status_line"),
                      (http.client.IncompleteRead(b"par"), "wsman_incomplete_read"),
                      (http.client.RemoteDisconnected("eof"), "wsman_bad_status_line"),
                      (http.client.ImproperConnectionState("x"), "wsman_http_protocol_error:ImproperConnectionState"),
                      (ConnectionRefusedError(), "wsman_unreachable:ConnectionRefusedError"),
                      (TimeoutError(), "wsman_unreachable:TimeoutError")):
        wire(lambda h, n, exc=exc: exc)
        with pytest.raises(amt_wsman.WsmanError) as ex:
            amt_wsman.transport(DEV, "<x/>")
        assert str(ex.value) == want, (exc, str(ex.value))


# --- item 2: the pin ----------------------------------------------------------------------------

class PinSock:
    def __init__(self, der=b"leaf-der"):
        self.der, self.closed = der, False

    def getpeercert(self, binary_form=False):
        return self.der

    def close(self):
        self.closed = True


@pytest.fixture
def pin_sock(monkeypatch):
    def fake_connect(self):
        self.sock = PinSock()

    monkeypatch.setattr(http.client.HTTPSConnection, "connect", fake_connect)


def test_pinned_connection_match_mismatch_and_none(pin_sock):
    good = hashlib.sha256(b"leaf-der").hexdigest()
    ok = amt_wsman._PinnedHTTPSConnection("h", 1, pin=good)
    ok.connect()
    assert ok.sock.closed is False
    bad = amt_wsman._PinnedHTTPSConnection("h", 1, pin="0" * 64)
    with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_pin_mismatch"):
        bad.connect()
    assert bad.sock.closed is True
    none = amt_wsman._PinnedHTTPSConnection("h", 1, pin=None)
    with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
        none.connect()
    assert none.sock.closed is True


def test_open_connection_carries_the_registry_pin():
    conn = amt_wsman._open_connection(DEV)
    assert isinstance(conn, amt_wsman._PinnedHTTPSConnection) and conn._pin == DEV.tls_leaf_sha256
    assert DEV.tls_leaf_sha256 == "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"


def test_unpinned_device_is_refused_before_vault_or_network(monkeypatch):
    unpinned = amt_registry.Device(key="u", amt_ip="192.0.2.1", wsman_port=1, kvm_port=2,
                                   amt_vault_key="k", tls_leaf_sha256=None)
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: pytest.fail("vault read for unpinned device"))
    monkeypatch.setattr(amt_wsman, "_open_connection", lambda dev: pytest.fail("dialled unpinned device"))
    with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
        amt_wsman.transport(unpinned, "<x/>")
    monkeypatch.setitem(amt_registry.DEVICES, "u", unpinned)
    for call in (lambda: amt_wsman.get("AMT_X", device="u"),
                 lambda: amt_wsman.enumerate_("AMT_X", device="u"),
                 lambda: amt_wsman.invoke_read("AMT_MessageLog", "GetRecords", {}, device="u")):
        with pytest.raises(amt_wsman.WsmanError, match="tls_leaf_unpinned_refused"):
            call()


# --- items 5, 6, 8, 11 ----------------------------------------------------------------------------

ENUM_NS = "http://schemas.xmlsoap.org/ws/2004/09/enumeration"


def test_enumerate_terminates_at_the_page_cap_on_endless_empty_pages(monkeypatch):
    calls = []

    def endless(dev, xml, password=None):
        calls.append(xml)
        return soap(f"<n:PullResponse xmlns:n='{ENUM_NS}'><n:Items/>"
                    "<n:EnumerationContext>ctx</n:EnumerationContext></n:PullResponse>")

    monkeypatch.setattr(amt_wsman, "transport", endless)
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: PW)
    items, truncated = amt_wsman.enumerate_("AMT_X")
    assert items == [] and truncated is True
    assert len(calls) == 1 + amt_wsman.MAX_PAGES


def test_enumerate_without_end_marker_or_context_is_not_complete(monkeypatch):
    monkeypatch.setattr(amt_wsman, "transport", lambda dev, xml, password=None: soap(
        f"<n:PullResponse xmlns:n='{ENUM_NS}'><n:Items><g:A xmlns:g='u'><g:N>1</g:N></g:A></n:Items></n:PullResponse>"))
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: PW)
    items, truncated = amt_wsman.enumerate_("AMT_X")
    assert items == [{"N": "1"}] and truncated is True


def test_enumerate_complete_sequence_is_not_truncated(monkeypatch):
    monkeypatch.setattr(amt_wsman, "transport", lambda dev, xml, password=None: soap(
        f"<n:PullResponse xmlns:n='{ENUM_NS}'><n:Items><g:A xmlns:g='u'><g:N>1</g:N></g:A></n:Items>"
        "<n:EndOfSequence/></n:PullResponse>"))
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: PW)
    assert amt_wsman.enumerate_("AMT_X") == ([{"N": "1"}], False)


def test_invoke_read_raises_on_an_empty_soap_body(monkeypatch):
    monkeypatch.setattr(amt_wsman, "transport", lambda dev, xml, password=None: soap(""))
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: PW)
    with pytest.raises(amt_wsman.WsmanError, match="wsman_empty_body:AMT_MessageLog.GetRecords"):
        amt_wsman.invoke_read("AMT_MessageLog", "GetRecords", {})


def test_fault_is_a_distinct_error_type(monkeypatch):
    fault = soap("<s:Fault xmlns:s='http://www.w3.org/2003/05/soap-envelope'><s:Reason><s:Text>nope</s:Text></s:Reason></s:Fault>")
    with pytest.raises(amt_wsman.WsmanFault, match="wsman_fault:nope"):
        amt_wsman.parse(fault)
    assert not issubclass(type(amt_wsman.WsmanError("wsman_auth_failed_401")), amt_wsman.WsmanFault)


def test_secret_named_fields_are_redacted_on_every_read(monkeypatch):
    body = soap("<g:C xmlns:g='u'><g:PSKPassPhrase>psk-clear</g:PSKPassPhrase>"
                "<g:SharedSecret>shared-clear</g:SharedSecret><g:PrivateKeyBlob>key-clear</g:PrivateKeyBlob>"
                "<g:DigestPassword>pw-clear</g:DigestPassword><g:Name>keep</g:Name>"
                "<g:Nested><g:MyPSK>deep-clear</g:MyPSK></g:Nested></g:C>")
    monkeypatch.setattr(amt_wsman, "transport", lambda dev, xml, password=None: body)
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: PW)
    got = amt_wsman.get("AMT_X")
    assert got["Name"] == "keep" and got["Nested"] == {"MyPSK": "<redacted>"}
    for field in ("PSKPassPhrase", "SharedSecret", "PrivateKeyBlob", "DigestPassword"):
        assert got[field] == "<redacted>", field
    assert "clear" not in str(got)


def test_read_methods_is_exactly_the_reviewed_set():
    assert amt_wsman.READ_METHODS == frozenset({
        ("AMT_MessageLog", "GetRecords"),
        ("AMT_AuditLog", "ReadRecords"),
        ("AMT_AuthorizationService", "EnumerateUserAclEntries"),
        ("AMT_AuthorizationService", "GetUserAclEntryEx"),
    })
