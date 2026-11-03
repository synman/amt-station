"""Servers and identities (packet C7): the Manage section's two pages, and the backend they rest on.

amt-mcp's own code answers behind the fake: the devices file is a real file in a temp folder read and rewritten by the real
``amt_fleet`` functions (the TLS probe is a scripted table, never a socket), the vault is a real child process (a small fake CLI
keeping its entries in a JSON file) driven by the real ``amt_vault`` and ``amt_identity`` code, and the one-time PUT lands in the real
``amt_upload.receive_intake``. So a refusal a test reads is amt-mcp's own sentence, and the stored value is in the fake vault by name or
nowhere. Nothing here reaches a host, the NAS, any 198.51.100.x address or a real vault, and every value is a throwaway sentinel.
Immutables 4 and 5 (sheets, the hold), 9 (no value anywhere it must not be), 10 (fingerprints, the mismatch, re-pin and remove as holds,
the last server) and 21 (write-only identities, remove refused while in use, a one-time url used once)."""
import asyncio
import hashlib
import json
import logging
import re
from pathlib import Path

import pytest

import amt_fleet
import amt_handoff
import amt_identity
import amt_registry
import amt_upload
import amt_vault
import images
import intake
import server
from console_fakes import BEARER, Authenticator, Console, check_mockups, enroll_first_passkey
from test_console_fleet import KEY, STATUS, tool_error

SENTINEL = "Sentinel-Intake-7731-xQ-NOT-A-REAL-SECRET"
LEAF_A = hashlib.sha256(b"leaf-a").hexdigest()
LEAF_B = hashlib.sha256(b"leaf-b").hexdigest()
LEAF_C = hashlib.sha256(b"leaf-c").hexdigest()
ADDR, ADDR_MOVED, ADDR_LAB = "192.0.2.26", "192.0.2.27", "192.0.2.40"       # TEST-NET-1: documentation addresses, never dialled
FAKE_CLI = r'''
import json, os, sys
d = os.environ["FAKE_VAULT_DIR"]
store_path, log_path = os.path.join(d, "store.json"), os.path.join(d, "argv.jsonl")
store = json.load(open(store_path)) if os.path.exists(store_path) else {}
with open(log_path, "a") as log:
    log.write(json.dumps(sys.argv[1:]) + "\n")
verb = sys.argv[1]
if os.environ.get("FAKE_VAULT_FAIL") == verb:
    sys.stderr.write(sys.stdin.read() if verb == "set" else "boom")   # a CLI that echoes its input on failure
    sys.exit(1)
if verb == "list":
    for name, e in sorted(store.items()):
        print(f" key  credential ❯ {name}  {e['notes']}")
elif verb == "set":
    args = sys.argv[3:]
    store[sys.argv[2]] = {"value": sys.stdin.read().rstrip("\n"), "notes": args[args.index("--notes") + 1]}
    json.dump(store, open(store_path, "w"))
elif verb == "delete":
    store.pop(sys.argv[2], None)
    json.dump(store, open(store_path, "w"))
'''


# -- amt-mcp's own code behind the fake ---------------------------------------------------------------------------------------

class Real:
    """amt_devices / amt_device_manage / amt_identities / amt_identity_manage answered by amt-mcp's real functions, the one-time PUT by the
    real ``receive_intake``. ``minted`` keeps every intake result the way the tool returned it, url and all; ``presented`` is the leaf each
    address shows; ``probes`` records every handshake the tool would have made."""

    def __init__(self, fake, tmp_path, monkeypatch):
        self.fake, self.minted, self.probes = fake, [], []
        self.vdir = tmp_path / "fakevault"
        self.vdir.mkdir()
        cli = self.vdir / "fake_secrets.py"
        cli.write_text(FAKE_CLI)
        monkeypatch.setattr(amt_vault, "SECRETS", cli)
        monkeypatch.setenv("FAKE_VAULT_DIR", str(self.vdir))
        monkeypatch.delenv("FAKE_VAULT_FAIL", raising=False)
        monkeypatch.delenv("NVAULT_VAULT_PATH", raising=False)
        self.presented = {ADDR: LEAF_A, ADDR_MOVED: LEAF_B, ADDR_LAB: LEAF_C}
        self.devfile = tmp_path / "config" / "devices.json"
        self.devfile.parent.mkdir()
        ultra = amt_registry.Device(key=KEY, amt_ip=ADDR, wsman_port=16993, kvm_port=16995, amt_vault_key=f"{KEY}-amt",
                                    host_vault_key=f"{KEY}-debian", tls_leaf_sha256=LEAF_A, tls_leaf_observed_prefix=LEAF_A[:16])
        self.devfile.write_text(amt_registry.devices_to_json({KEY: ultra}))
        monkeypatch.setenv(amt_registry.DEVICES_FILE_ENV, str(self.devfile))
        monkeypatch.setattr(amt_registry, "DEVICES", dict(amt_registry.DEVICES))
        monkeypatch.setitem(amt_registry._LOADED, "mtime", None)
        monkeypatch.setitem(amt_registry._LOADED, "path", None)
        monkeypatch.setattr(amt_fleet, "presented_pin", self.probe)
        monkeypatch.setattr(amt_fleet.pin_check, "__defaults__", (self.probe,))      # pin_check bound the real probe as a default at import
        monkeypatch.setenv(amt_handoff.BASE_URL_ENV, fake.base)
        amt_upload._INTAKES.clear()
        for name in (f"{KEY}-amt", f"{KEY}-debian", "lab-amt"):
            self.seed(name)
        fake.results["amt_devices"] = self.wrap("amt_devices", lambda a: amt_fleet.devices_read(a.get("action", "list"), a.get("device")))
        fake.results["amt_device_manage"] = self.wrap("amt_device_manage", self.device_manage)
        fake.results["amt_identities"] = self.wrap("amt_identities", lambda a: amt_identity.identities_read(a.get("device")))
        fake.results["amt_identity_manage"] = self.wrap("amt_identity_manage", self.identity_manage)
        fake.results["amt_status"] = lambda a: {**STATUS, "device": a["device"]}
        fake.results["amt_mirror_link"] = lambda a: {"device": a["device"], "live": False}
        fake.results["amt_serial_link"] = lambda a: {"device": a["device"], "live": False}
        fake.results["amt_ider"] = lambda a: {"device": a["device"], "mounted": False}
        fake.put_handler = self.put

    def probe(self, ip, port):
        assert not ip.startswith("198.51.100."), "a test must never name a real address"
        self.probes.append((ip, port))
        if ip not in self.presented:
            raise OSError("connect timed out")
        return self.presented[ip]

    @staticmethod
    def wrap(name, fn):
        def run(a):
            try:
                return fn(a)
            except (ValueError, KeyError, OSError, amt_vault.VaultError) as ex:         # what FastMCP turns an exception into
                return tool_error(f"Error executing tool {name}: {ex}")
        return run

    @staticmethod
    def device_manage(a):
        return amt_fleet.device_manage(a["action"], a["device"], a.get("ip"), a.get("wsman_port"), a.get("kvm_port"), a.get("amt_vault_key"),
                                       a.get("host_vault_key"), a.get("clear_host", False), a.get("expected_pin"), a.get("repin", False))

    def identity_manage(self, a):
        out = amt_identity.identity_manage(a["action"], a["name"])
        if a["action"] == "intake":
            self.minted.append(out)
        return out

    def put(self, path, headers, body):
        """The body as it arrived handed to amt-mcp's real receive with the headers it was sent."""
        from starlette.requests import Request
        scope = {"type": "http", "method": "PUT", "path": path, "query_string": b"", "path_params": {"token": path.rsplit("/", 1)[-1]},
                 "headers": [(b"content-length", headers["Content-Length"].encode())]}
        sent = []

        async def receive():
            if sent:
                return {"type": "http.disconnect"}
            sent.append(1)
            return {"type": "http.request", "body": body, "more_body": False}
        resp = asyncio.run(amt_upload.receive_intake(Request(scope, receive)))
        return resp.status_code, resp.body, resp.media_type or "text/plain"

    # -- the fake vault ------------------------------------------------------------------------------------------
    @property
    def store(self) -> dict:
        p = self.vdir / "store.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def seed(self, name, notes="amt-mcp dedicated vault copy", value="seed-value"):
        store = self.store
        store[name] = {"value": value, "notes": notes}
        (self.vdir / "store.json").write_text(json.dumps(store))

    @property
    def argv_log(self) -> str:
        p = self.vdir / "argv.jsonl"
        return p.read_text() if p.exists() else ""

    @property
    def file_devices(self) -> dict:
        return amt_registry.devices_from_json(self.devfile.read_text())

    def token(self) -> str:
        return self.minted[-1]["url"].rsplit("/", 1)[1]

    def cleanup(self):
        amt_upload._INTAKES.clear()


@pytest.fixture()
def real(tmp_path, fake_amt, monkeypatch):
    r = Real(fake_amt, tmp_path, monkeypatch)
    yield r
    r.cleanup()


@pytest.fixture()
def mg(tmp_path, fake_amt, real):
    """A signed-in console in front of the real tools; its fleet is read by hand."""
    folder = tmp_path / "console"
    folder.mkdir()
    console = Console(folder, fake_amt, fleet_poll=False)
    enroll_first_passkey(console, Authenticator(console.app.cfg.rp_id, console.origin))
    yield console
    console.close()


def call(me, tool, **args):
    return me.post("/api/call", {"tool": tool, "arguments": args})


def mint(me, name=f"{KEY}-amt"):
    reply = call(me, "amt_identity_manage", action="intake", name=name, confirmed=True)
    assert reply.status == 200, reply.text
    return reply


def relay(me, iid, value, *, length=None, ctype="text/plain; charset=utf-8", headers=None, **kw):
    data = value if isinstance(value, bytes) else value.encode("utf-8")
    head = {"Content-Type": ctype, "Content-Length": str(len(data) if length is None else length), **(headers or {})}
    return me.request("POST", f"/api/identities/intake/{iid}", raw=data, headers=head, **kw)


def manage(me, **args):
    return call(me, "amt_device_manage", confirmed=True, **args)


def pin_in_file(real, key=KEY):
    return real.file_devices[key].tls_leaf_sha256


# -- the minting: the url stays in the console ----------------------------------------------------------------------------------

def test_a_minted_intake_reaches_the_browser_as_an_id_never_as_a_url(mg, fake_amt, real):
    reply = mint(mg)
    s = reply.json()["structured"]
    token = real.token()
    assert token and token not in reply.text and "/intake/" not in reply.text.replace("[one-time url withheld]", "")
    assert set(s) >= {"intake_id", "name", "max_bytes", "expires_in_s"} and s["name"] == f"{KEY}-amt" and s["max_bytes"] == 4096 and s["expires_in_s"] == 900
    assert len(s["intake_id"]) == 22 and s["intake_id"] != token and s["url"] == "[one-time url withheld]"
    assert [(t, a) for t, a, _ in fake_amt.calls] == [("amt_identity_manage", {"action": "intake", "name": f"{KEY}-amt", "confirmed": True})]
    assert fake_amt.calls[0][2] == f"Bearer {BEARER}"
    assert real.argv_log == "", "minting touches no vault"


def test_a_name_no_server_names_is_the_tools_own_refusal_and_keeps_no_offer(mg, real):
    reply = call(mg, "amt_identity_manage", action="intake", name="not-a-registered-name", confirmed=True).json()
    assert reply["isError"] and "identity_name_not_allowed:not-a-registered-name" in reply["text"] and "intake_id" not in json.dumps(reply)
    assert mg.app.intakes._offers == {} and not amt_upload._INTAKES


@pytest.mark.parametrize("url", [
    "https://amt.example.test/intake/" + "A" * 43,                     # another origin
    "FAKE/intake/" + "A" * 42,                                         # a token one character short
    "FAKE/intake/" + "A" * 43 + "?x=1", "FAKE/intake/" + "A" * 43 + "#f", "FAKE/uploads/" + "A" * 43, "FAKE/intake/" + "A" * 43 + "/more",
    "ftp://127.0.0.1/intake/" + "A" * 43, "not a url", None, 7])
def test_a_url_that_is_not_amt_mcps_own_one_time_intake_is_never_kept(mg, fake_amt, url):
    if isinstance(url, str):
        url = url.replace("FAKE", fake_amt.base)
    fake_amt.results["amt_identity_manage"] = lambda a: {"name": f"{KEY}-amt", "url": url, "method": "PUT", "expires_in_s": 900, "max_bytes": 4096}
    s = call(mg, "amt_identity_manage", action="intake", name=f"{KEY}-amt", confirmed=True).json()["structured"]
    assert "intake_id" not in s and s["intake_refused"] in ("intake_url_not_from_amt_mcp", "intake_result_unreadable")
    assert mg.app.intakes._offers == {}                                 # nothing is waiting for a value


def test_a_url_with_userinfo_or_another_port_is_not_amt_mcps_origin(mg, fake_amt):
    host = fake_amt.base.split("//")[1]
    for bad in (f"http://u:p@{host}/intake/" + "A" * 43, f"http://127.0.0.1:{fake_amt.port + 1}/intake/" + "A" * 43):
        fake_amt.results["amt_identity_manage"] = lambda a, bad=bad: {"name": "n", "url": bad}
        assert call(mg, "amt_identity_manage", action="intake", name="n", confirmed=True).json()["structured"]["intake_refused"] == "intake_url_not_from_amt_mcp"


def test_a_result_without_a_name_is_never_kept(mg, fake_amt):
    fake_amt.results["amt_identity_manage"] = lambda a: {"url": f"{fake_amt.base}/intake/" + "A" * 43}
    assert call(mg, "amt_identity_manage", action="intake", name="n", confirmed=True).json()["structured"]["intake_refused"] == "intake_result_unreadable"


# -- the relay: the value goes to the url once, the answer comes back, the value stays in the vault by name -----------------------------

def test_the_value_goes_to_the_vault_by_name_with_the_console_source_and_nowhere_else(mg, fake_amt, real):
    iid = mint(mg).json()["structured"]["intake_id"]
    reply = relay(mg, iid, SENTINEL)
    assert reply.status == 200 and reply.json() == {"ok": True, "name": f"{KEY}-amt"}
    entry = real.store[f"{KEY}-amt"]
    assert entry["value"] == SENTINEL and entry["notes"].startswith(amt_upload.SOURCE_NOTE)       # present in the vault, by name
    assert fake_amt.puts == [(f"/intake/{real.token()}", len(SENTINEL), len(SENTINEL))]
    listed = call(mg, "amt_identities").json()["structured"]["identities"]
    row = next(r for r in listed if r["name"] == f"{KEY}-amt")
    assert row["status"] == "present" and row["source"] == "console" and row["updated_at"]


def test_a_second_put_to_the_used_url_is_refused_by_amt_mcp_and_by_the_console(mg, fake_amt, real):
    iid = mint(mg).json()["structured"]["intake_id"]
    assert relay(mg, iid, SENTINEL).json()["ok"] is True
    again = relay(mg, iid, "another-value-entirely")                    # the console's id is used up
    assert again.status == 404 and again.json() == {"error": "unknown_intake"} and len(fake_amt.puts) == 1
    status, body, _ = fake_amt.put_handler(f"/intake/{real.token()}", {"Content-Length": "5"}, b"other")    # the url itself, replayed straight at amt-mcp
    assert status == 404 and body == b"not found"
    assert real.store[f"{KEY}-amt"]["value"] == SENTINEL and "other" not in json.dumps(real.store)


def test_a_replaced_value_replaces_the_stored_one_and_only_that_entry(mg, real):
    real.seed(f"{KEY}-amt", value="old-value")
    iid = mint(mg).json()["structured"]["intake_id"]
    assert relay(mg, iid, SENTINEL).json()["ok"] is True
    store = real.store
    assert store[f"{KEY}-amt"]["value"] == SENTINEL and store[f"{KEY}-debian"]["value"] == "seed-value" and set(store) == {f"{KEY}-amt", f"{KEY}-debian", "lab-amt"}


@pytest.mark.parametrize("value,length,code", [
    (b"", None, "value_size_out_of_range"), (b"x" * 4097, None, "value_size_out_of_range"),
    (b"two\nlines", None, "value_has_a_line_break_or_nul"), (b"cr\rhere", None, "value_has_a_line_break_or_nul"), (b"nul\x00here", None, "value_has_a_line_break_or_nul"),
    (b"\xff\xfe-not-utf8", None, "value_not_utf8"), (b"short", 20, "value_incomplete")])
def test_a_value_amt_mcp_would_refuse_is_refused_here_first_and_keeps_the_url_for_a_better_one(mg, fake_amt, real, value, length, code):
    iid = mint(mg).json()["structured"]["intake_id"]
    if length:                                                           # the browser promised more than it sent: the connection ends after the answer
        import socket
        sock = socket.create_connection(("127.0.0.1", mg.port), timeout=5)
        head = (f"POST /api/identities/intake/{iid} HTTP/1.1\r\nHost: {mg.host}:{mg.port}\r\nOrigin: {mg.origin}\r\nCookie: amt_console_session={mg.cookie}\r\n"
                f"X-CSRF-Token: {mg.csrf}\r\nContent-Type: text/plain\r\nContent-Length: {length}\r\n\r\n").encode()
        sock.sendall(head + value)
        sock.shutdown(socket.SHUT_WR)
        data = b""
        while chunk := sock.recv(4096):
            data += chunk
        sock.close()
        assert b" 400 " in data.split(b"\r\n")[0] and code.encode() in data
    else:
        refused = relay(mg, iid, value)
        assert refused.status == 400 and refused.json() == {"error": code}
    assert fake_amt.puts == [] and real.store[f"{KEY}-amt"]["value"] == "seed-value"      # nothing reached amt-mcp
    assert relay(mg, iid, SENTINEL).json()["ok"] is True                                  # the same id still takes a good value


def test_the_relay_route_needs_the_session_the_csrf_token_the_same_origin_and_plain_text(mg, fake_amt, real):
    iid = mint(mg).json()["structured"]["intake_id"]
    assert relay(mg, iid, SENTINEL, cookie=False).status == 401
    assert relay(mg, iid, SENTINEL, csrf=False).status == 403
    assert relay(mg, iid, SENTINEL, origin=False).status == 403
    assert relay(mg, iid, SENTINEL, headers={"Origin": "https://evil.example.test"}).status == 403
    assert relay(mg, iid, SENTINEL, ctype="application/json").status == 415
    assert relay(mg, iid, SENTINEL, ctype="application/octet-stream").status == 415
    assert fake_amt.puts == []
    assert relay(mg, iid, SENTINEL).json()["ok"] is True                 # none of the refusals used the id up


def test_the_relay_route_wants_a_content_length(mg, fake_amt, real):
    import socket
    iid = mint(mg).json()["structured"]["intake_id"]
    sock = socket.create_connection(("127.0.0.1", mg.port), timeout=5)
    sock.sendall((f"POST /api/identities/intake/{iid} HTTP/1.1\r\nHost: {mg.host}:{mg.port}\r\nOrigin: {mg.origin}\r\nCookie: amt_console_session={mg.cookie}\r\n"
                  f"X-CSRF-Token: {mg.csrf}\r\nContent-Type: text/plain\r\n\r\n").encode())
    assert sock.recv(4096).startswith((b"HTTP/1.0 411", b"HTTP/1.1 411")) and fake_amt.puts == []
    sock.close()


def test_an_unknown_or_malformed_id_is_a_404_and_sends_nothing(mg, fake_amt, real):
    for iid in ("A" * 22, "short", "A" * 23, "../../x"):
        assert relay(mg, iid, SENTINEL).status == 404
    assert fake_amt.puts == []


def test_an_expired_id_is_gone(mg, fake_amt, real):
    iid = mint(mg).json()["structured"]["intake_id"]
    clock = mg.app.intakes.now
    mg.app.intakes.now = lambda: clock() + 901
    try:
        assert relay(mg, iid, SENTINEL).status == 404 and fake_amt.puts == []
    finally:
        mg.app.intakes.now = clock


def test_a_vault_amt_mcp_cannot_write_is_its_503_verbatim_and_nothing_is_stored(mg, fake_amt, real, monkeypatch):
    iid = mint(mg).json()["structured"]["intake_id"]
    monkeypatch.setenv("NVAULT_VAULT_PATH", str(real.vdir / "read-only-vault"))             # not writable: amt-mcp answers before reading the body
    j = relay(mg, iid, SENTINEL).json()
    assert j == {"ok": False, "status": 503, "text": "vault_not_writable: nothing was stored"}
    assert real.store[f"{KEY}-amt"]["value"] == "seed-value"
    assert relay(mg, iid, SENTINEL).status == 404                                           # the console's id is used up either way


def test_a_failing_vault_write_is_amt_mcps_503_and_the_value_never_comes_back(mg, fake_amt, real, monkeypatch):
    iid = mint(mg).json()["structured"]["intake_id"]
    monkeypatch.setenv("FAKE_VAULT_FAIL", "set")                                            # the CLI echoes its stdin (the value) on stderr when it fails
    reply = relay(mg, iid, SENTINEL)
    j = reply.json()
    assert j["ok"] is False and j["status"] == 503 and "vault_write_failed" in j["text"] and SENTINEL not in reply.text


def test_an_answer_that_contains_the_value_is_withheld(mg, fake_amt, real):
    iid = mint(mg).json()["structured"]["intake_id"]
    fake_amt.put_handler = lambda path, headers, body: (400, b"refused " + body, "text/plain")
    reply = relay(mg, iid, SENTINEL)
    assert reply.json() == {"ok": False, "status": 400, "text": "[answer withheld: it contained the value]"} and SENTINEL not in reply.text


def test_a_value_that_is_a_substring_of_the_stored_answer_is_still_a_stored_value(mg, fake_amt, real):
    iid = mint(mg).json()["structured"]["intake_id"]
    assert relay(mg, iid, "t").json() == {"ok": True, "name": f"{KEY}-amt"} and real.store[f"{KEY}-amt"]["value"] == "t"     # "t" is in {"stored": true, ...}
    iid = mint(mg).json()["structured"]["intake_id"]
    fake_amt.put_handler = lambda path, headers, body: (400, b'{"stored": true}', "application/json")                       # not a 201: the echo check still holds
    assert relay(mg, iid, "t").json() == {"ok": False, "status": 400, "text": "[answer withheld: it contained the value]"}


def test_a_one_time_url_in_amt_mcps_answer_never_reaches_the_browser(mg, fake_amt, real):
    iid = mint(mg).json()["structured"]["intake_id"]
    token = real.token()
    fake_amt.put_handler = lambda path, headers, body: (400, f"refused for {fake_amt.base}/intake/{token} and /intake/{token}".encode(), "text/plain")
    reply = relay(mg, iid, SENTINEL)
    assert reply.json()["text"] == "refused for [one-time url withheld] and [one-time url withheld]" and token not in reply.text


def test_an_upstream_that_drops_the_connection_is_not_answering_not_a_refusal(mg, fake_amt, real):
    iid = mint(mg).json()["structured"]["intake_id"]

    def drop(path, headers, body):
        raise RuntimeError("the connection ends here")
    fake_amt.put_handler = drop
    j = relay(mg, iid, SENTINEL).json()
    assert j["ok"] is False and j["code"].startswith("amt_mcp_unreachable:") and "status" not in j and "text" not in j


def test_a_201_that_does_not_say_stored_is_not_a_stored_value(mg, fake_amt, real):
    iid = mint(mg).json()["structured"]["intake_id"]
    fake_amt.put_handler = lambda path, headers, body: (201, b'{"name": "x"}', "application/json")
    assert relay(mg, iid, SENTINEL).json() == {"ok": False, "status": 201, "text": '{"name": "x"}'}
    iid = mint(mg).json()["structured"]["intake_id"]
    fake_amt.put_handler = lambda path, headers, body: (201, b"stored", "text/plain")             # not JSON at all
    assert relay(mg, iid, SENTINEL).json() == {"ok": False, "status": 201, "text": "stored"}


def test_an_unreachable_amt_mcp_sends_nothing_and_keeps_the_id():
    up = intake.Intakes("http://127.0.0.1:1")
    s = up.register({"name": "n", "url": "http://127.0.0.1:1/intake/" + "B" * 43})
    with pytest.raises(images.UploadError) as ex:
        up.send(s["intake_id"], 4, lambda n: b"abcd")
    assert ex.value.status == 502 and ex.value.code.startswith("amt_mcp_unreachable:") and s["intake_id"] in up._offers


def test_the_registry_is_bounded_and_an_offer_lives_as_long_as_amt_mcp_says_at_most():
    up = intake.Intakes("http://127.0.0.1:9", now=lambda: 1000.0)
    url = "http://127.0.0.1:9/intake/" + "B" * 43
    first = up.register({"name": "n", "url": url})["intake_id"]
    for _ in range(intake.MAX_OFFERS):
        up.register({"name": "n", "url": url})
    assert len(up._offers) == intake.MAX_OFFERS and first not in up._offers
    life = lambda expires: up._offers[up.register({"name": "n", "url": url, "expires_in_s": expires})["intake_id"]]["expires"] - 1000.0
    assert life(30) == 30.0 and life(900) == 900.0
    assert life(5000) == 900.0 and life(0) == 900.0 and life(-5) == 900.0 and life("soon") == 900.0 and life(None) == 900.0 and life(True) == 900.0
    size = lambda cap: up._offers[up.register({"name": "n", "url": url, "max_bytes": cap})["intake_id"]]["cap"]
    assert size(100) == 100 and size(4096) == 4096 and size(1 << 20) == 4096 and size(0) == 4096 and size(True) == 4096 and size("big") == 4096


# -- immutable 9 and 21: the value is in no response, log, url or tool argument ---------------------------------------------------------

def leaks(needle, surfaces):
    """The names of the surfaces (a dict of name -> text) that contain ``needle``."""
    return [name for name, text in surfaces.items() if needle in text]


def everything_seen(mg, fake_amt, real, caplog, replies):
    """Every surface a value must not reach, as text, by name. (The urls amt-mcp was asked for are one: its PUT path carries the token.)"""
    surfaces = {f"reply {i}": r.text + json.dumps(r.headers) for i, r in enumerate(replies)}
    surfaces.update({"log": caplog.text, "tool arguments": json.dumps([a for _, a, _ in fake_amt.calls]),
                     "urls and headers amt-mcp saw": json.dumps([(m, p, h) for m, p, h in fake_amt.requests]), "vault argv": real.argv_log})
    surfaces.update({f"file {f.name}": f.read_bytes().decode("utf-8", "replace") for f in mg.data.rglob("*") if f.is_file()})
    return surfaces


def lifecycle(mg, real):
    """Mint, relay, relay again, then every page and read that could echo it."""
    out = [mint(mg)]
    iid = out[0].json()["structured"]["intake_id"]
    out += [relay(mg, iid, SENTINEL), relay(mg, iid, SENTINEL)]
    for path in ("/manage", "/manage/identities", "/api/fleet", f"/api/server/{KEY}"):
        out.append(mg.get(path))
    out += [call(mg, "amt_identities"), call(mg, "amt_devices", action="list"), call(mg, "amt_identity_manage", action="intake", name=f"{KEY}-amt", confirmed=True)]
    return out


def test_the_fixture_value_is_in_the_vault_by_name_and_in_no_response_log_url_argument_or_file(mg, fake_amt, real, caplog):
    caplog.set_level(logging.DEBUG)
    replies = lifecycle(mg, real)
    assert real.store[f"{KEY}-amt"]["value"] == SENTINEL                  # positive control: the value really travelled to the vault, by name
    seen = everything_seen(mg, fake_amt, real, caplog, replies)
    assert leaks(SENTINEL, seen) == []
    token = real.minted[0]["url"].rsplit("/", 1)[1]
    assert leaks(token, seen) == ["urls and headers amt-mcp saw"] and fake_amt.puts[0][0] == f"/intake/{token}"      # the url's token went to amt-mcp and nowhere else
    iid = replies[0].json()["structured"]["intake_id"]
    assert leaks(iid, {k: v for k, v in seen.items() if k != "reply 0"}) == [], "the id is returned once, in the mint reply"
    assert leaks(SENTINEL, {"planted": "x" + SENTINEL + "x"}) == ["planted"]                                          # the scan catches a planted copy


def test_the_scan_catches_a_value_a_deliberately_broken_route_logs(mg, fake_amt, real, caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    real_send = mg.app.intakes.send
    log = logging.getLogger("amt_console")

    def broken(iid, length, read):
        raw = read(length)
        log.info("value=%s", raw.decode())                                  # the defect the scan exists to find
        return real_send(iid, length, lambda n: raw)
    monkeypatch.setattr(mg.app.intakes, "send", broken)
    iid = mint(mg).json()["structured"]["intake_id"]
    relay(mg, iid, SENTINEL)
    assert leaks(SENTINEL, {"log": caplog.text}) == ["log"]


def test_the_intake_id_is_in_no_log_line_even_when_the_request_is_refused_or_faults(mg, fake_amt, real, caplog, monkeypatch):
    caplog.set_level(logging.DEBUG)
    iid = mint(mg).json()["structured"]["intake_id"]
    assert relay(mg, iid, SENTINEL, headers={"Origin": "https://evil.example.test"}).status == 403          # the cross-site refusal logs its path
    monkeypatch.setattr(mg.app.intakes, "send", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert relay(mg, iid, SENTINEL).status == 500                                                           # a handler fault logs its path
    assert "cross-site POST refused" in caplog.text and "handler fault RuntimeError" in caplog.text
    assert iid not in caplog.text and "/api/identities/intake/<id>" in caplog.text


def test_the_log_of_a_relay_names_no_url_no_value_and_no_entry(mg, fake_amt, real, caplog):
    caplog.set_level(logging.DEBUG)
    iid = mint(mg).json()["structured"]["intake_id"]
    relay(mg, iid, SENTINEL)
    assert "/intake/" not in caplog.text.replace("/api/identities/intake/<id>", "") and SENTINEL not in caplog.text and f"{KEY}-amt" not in caplog.text


def test_a_received_value_resumes_a_server_paused_on_its_refused_credential(mg, fake_amt, real):
    """The fleet paused my-server-1 on a 401 and read its identity's updated-at then; the new value moves it, and the console resumes the reads."""
    fleet = mg.app.fleet
    real.seed(f"{KEY}-amt", f"{amt_upload.SOURCE_NOTE}; updated: 2026-01-01T00:00:00Z")      # an identity with an updated-at to compare
    fleet.refresh_devices()
    fake_amt.results["amt_status"] = lambda a: tool_error("Error executing tool amt_status: wsman_auth_failed_401")
    fleet.refresh(KEY)
    assert fleet.public(KEY)["state"] == "paused" and fleet.entries[KEY]["paused"]["identity"] == "2026-01-01T00:00:00Z"
    iid = mint(mg).json()["structured"]["intake_id"]
    assert relay(mg, iid, SENTINEL).json()["ok"] is True
    assert fleet.public(KEY)["state"] == "loading"


# -- the servers: add, the pin mismatch, re-pin, the last server (amt-mcp's own refusals, verbatim) ----------------------------------

def test_an_added_server_is_pinned_to_the_leaf_it_presents_and_is_in_the_fleet_at_once(mg, fake_amt, real):
    mg.app.fleet.refresh_devices()
    assert list(mg.app.fleet.devices) == [KEY]
    reply = manage(mg, action="add", device="lab", ip=ADDR_LAB, wsman_port=16993, kvm_port=16995, amt_vault_key="lab-amt").json()
    assert not reply["isError"] and reply["structured"]["added"]["tls_leaf_sha256"] == LEAF_C and reply["structured"]["devices"] == ["lab", KEY]
    assert pin_in_file(real, "lab") == LEAF_C and real.probes == [(ADDR_LAB, 16993)]
    assert list(mg.app.fleet.devices) == ["lab", KEY] and mg.app.fleet.public("lab")["pinned"] is True


def test_an_expected_pin_another_leaf_does_not_match_is_refused_and_nothing_is_written(mg, fake_amt, real):
    before = real.devfile.read_bytes()
    reply = manage(mg, action="add", device="lab", ip=ADDR_LAB, amt_vault_key="lab-amt", expected_pin=LEAF_B).json()
    assert reply["isError"] and f"{ADDR_LAB}:16993 presents leaf {LEAF_C}, not the given pin; nothing written" in reply["text"]
    assert real.devfile.read_bytes() == before


def test_a_server_whose_vault_entry_does_not_exist_is_refused_naming_it(mg, fake_amt, real):
    before = real.devfile.read_bytes()
    reply = manage(mg, action="add", device="lab", ip=ADDR_LAB, amt_vault_key="nope-amt").json()
    assert reply["isError"] and "vault nope-amt in this server's vault" in reply["text"] and real.devfile.read_bytes() == before


def test_a_pin_check_after_a_scripted_leaf_change_reports_the_mismatch_and_changes_nothing(mg, fake_amt, real):
    ok = call(mg, "amt_devices", action="pin_check", device=KEY).json()["structured"]
    assert ok == {"device": KEY, "presented": LEAF_A, "stored": LEAF_A, "matches": True}
    real.presented[ADDR] = LEAF_B                                          # the AMT was re-provisioned, or something sits in front of it
    bad = call(mg, "amt_devices", action="pin_check", device=KEY).json()["structured"]
    assert bad == {"device": KEY, "presented": LEAF_B, "stored": LEAF_A, "matches": False} and pin_in_file(real) == LEAF_A


def test_a_show_reaches_amt_mcp_through_the_relay_and_is_the_record_the_list_holds(mg, fake_amt, real):
    shown = call(mg, "amt_devices", action="show", device=KEY).json()["structured"]
    listed = call(mg, "amt_devices", action="list").json()["structured"]
    assert shown["device"] == next(d for d in listed["devices"] if d["key"] == KEY) and shown["source"] == listed["source"]
    assert call(mg, "amt_devices", action="show", device="no-such-server").json()["isError"]


def test_an_edit_that_meets_a_different_leaf_is_refused_without_repin_and_accepted_with_it(mg, fake_amt, real):
    before = real.devfile.read_bytes()
    refused = manage(mg, action="edit", device=KEY, ip=ADDR_MOVED).json()
    assert refused["isError"] and f"{ADDR_MOVED}:16993 presents leaf {LEAF_B}, not the stored pin; pass repin to accept it; nothing written" in refused["text"]
    assert real.devfile.read_bytes() == before
    accepted = manage(mg, action="edit", device=KEY, ip=ADDR_MOVED, repin=True).json()
    assert not accepted["isError"] and accepted["structured"]["edited"]["tls_leaf_sha256"] == LEAF_B and pin_in_file(real) == LEAF_B


def test_a_re_pin_resumes_a_server_the_console_paused_on_its_changed_leaf(mg, fake_amt, real):
    fleet = mg.app.fleet
    fleet.refresh_devices()
    fake_amt.results["amt_status"] = lambda a: tool_error("Error executing tool amt_status: tls_leaf_pin_mismatch")
    fleet.refresh(KEY)
    assert fleet.public(KEY)["state"] == "paused"
    real.presented[ADDR] = LEAF_B
    assert not manage(mg, action="edit", device=KEY, repin=True).json()["isError"]
    assert fleet.devices[KEY]["leaf"] == LEAF_B and fleet.public(KEY)["state"] == "loading"


def test_the_last_server_cannot_be_removed_and_the_tools_sentence_is_returned_verbatim(mg, fake_amt, real):
    before = real.devfile.read_bytes()
    reply = manage(mg, action="remove", device=KEY).json()
    assert reply["isError"] and "refusing to remove the last device; the server would have nothing to serve" in reply["text"]
    assert real.devfile.read_bytes() == before and list(real.file_devices) == [KEY]


def test_with_a_second_server_remove_works_and_the_fleet_drops_it(mg, fake_amt, real):
    manage(mg, action="add", device="lab", ip=ADDR_LAB, amt_vault_key="lab-amt")
    reply = manage(mg, action="remove", device="lab").json()
    assert not reply["isError"] and reply["structured"] == {"removed": "lab", "devices": [KEY]}
    assert list(mg.app.fleet.devices) == [KEY] and (real.devfile.parent / ".prev-devices.json").exists()


def test_a_refused_device_change_does_not_touch_the_fleet(mg, fake_amt, real):
    mg.app.fleet.refresh_devices()
    asked = len([c for c in fake_amt.calls if c[0] == "amt_devices"])
    assert manage(mg, action="remove", device=KEY).json()["isError"]
    assert len([c for c in fake_amt.calls if c[0] == "amt_devices"]) == asked


# -- the identities: remove refused while in use ----------------------------------------------------------------------------------------

def test_an_entry_a_server_names_cannot_be_removed_and_stays(mg, fake_amt, real):
    reply = call(mg, "amt_identity_manage", action="remove", name=f"{KEY}-amt", confirmed=True).json()
    assert reply["isError"] and f"identity_in_use:{KEY}-amt: named by {KEY}.amt_vault_key" in reply["text"] and f"{KEY}-amt" in real.store
    assert "delete" not in real.argv_log


def test_an_unused_console_entry_is_removed_and_a_main_entry_is_not(mg, fake_amt, real):
    real.seed("orphan-entry", amt_upload.SOURCE_NOTE)
    real.seed("old-main-entry")
    assert call(mg, "amt_identity_manage", action="remove", name="orphan-entry", confirmed=True).json()["structured"] == {"removed": "orphan-entry"}
    assert "orphan-entry" not in real.store
    refused = call(mg, "amt_identity_manage", action="remove", name=f"{KEY}-debian", confirmed=True).json()
    assert refused["isError"] and "identity_in_use" in refused["text"] and f"{KEY}-debian" in real.store


# -- the pages are served, signed in only, with no password field and no token --------------------------------------------------------

def test_both_pages_are_built_need_a_session_and_carry_their_scripts(mg):
    servers, identities = mg.get("/manage").text, mg.get("/manage/identities").text
    assert 'id="servers-page"' in servers and "/static/servers.js" in servers and "/static/status.js" in servers and "/static/identities.js" not in servers
    assert 'id="ident-page"' in identities and "/static/identities.js" in identities and 'class="content split"' in identities
    for page in (servers, identities):
        assert "built in a later step" not in page and "@@" not in page and page.count('aria-current="page"') == 2
        assert 'type="password"' not in page and "new-password" not in page and not re.search(r"[A-Za-z0-9_-]{43}", re.sub(r"<svg.*?</svg>", "", page, flags=re.S))
    for path in ("/manage", "/manage/identities"):
        r = mg.get(path, cookie=False)
        assert (r.status, r.headers["Location"]) == (302, "/signin")


def test_the_value_field_is_a_masked_text_input_outside_any_form_with_no_value(mg):
    page = mg.get("/manage/identities").text
    field = re.search(r'<input[^>]*id="intake-value"[^>]*>', page).group(0)
    assert 'type="text"' in field and 'class="secret"' in field and 'autocomplete="off"' in field and " value=" not in field
    assert "<form" not in page and "</form" not in page


def test_the_fleet_and_server_pages_link_to_the_identities_page(mg):
    static = Path(server.__file__).parent / "static"
    for name in ("fleet.js", "server.js"):
        assert "'/manage/identities'" in (static / name).read_text(), name
