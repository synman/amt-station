"""The console's MCP client: the bearer and the device ride on every call, the design's per-call rules are
enforced before anything is sent, and the tool table follows the live amt-mcp schemas."""
import asyncio
import http.server
import threading

import pytest

import mcp_client
from console_fakes import BEARER, FakeAmt, write_vault_cli


def live_tools():
    import amt_server
    return {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}


def client_for(fake, tmp_path, **kw):
    return mcp_client.Client(f"{fake.base}/mcp", mcp_client.Vault(str(write_vault_cli(tmp_path))), 15)


# -- the table follows the live schemas ----------------------------------------------------------------------------

def test_the_tool_table_matches_the_live_amt_mcp_schemas():
    live = live_tools()
    assert set(mcp_client.TOOLS) == set(live), "a tool was added or removed in amt-mcp: update console/mcp_client.py TOOLS"
    optional_device = {"amt_devices", "amt_identities"}
    for name, (needs_device, read_only) in mcp_client.TOOLS.items():
        props = live[name].inputSchema.get("properties", {})
        assert read_only == bool(live[name].annotations.readOnlyHint), name
        assert needs_device == ("device" in props and name not in optional_device), name
        assert ("confirmed" in props) == (not read_only), name
    for name, actions in mcp_client.UNCONFIRMED_ACTIONS.items():
        enum = live[name].inputSchema["properties"]["action"]["enum"]
        assert set(actions) <= set(enum), name


# -- the per-call rules (immutable 6) -------------------------------------------------------------------------------

@pytest.mark.parametrize("tool,args,why", [
    ("amt_nope", {"device": "x"}, "unknown_tool"),
    (None, {}, "unknown_tool"),
    ("amt_status", [], "arguments_not_an_object"),
    ("amt_status", {}, "device_not_named"),
    ("amt_status", {"device": ""}, "device_not_named"),
    ("amt_status", {"device": 3}, "device_not_named"),
    ("amt_power", {"action": "restart"}, "device_not_named"),
    ("amt_power", {"device": "x", "action": "restart"}, "confirmed_not_true"),
    ("amt_power", {"device": "x", "action": "restart", "confirmed": "true"}, "confirmed_not_true"),
    ("amt_power", {"device": "x", "action": "restart", "confirmed": 1}, "confirmed_not_true"),
    ("amt_images", {"action": "delete", "name": "a.iso"}, "confirmed_not_true"),
    ("amt_identity_manage", {"action": "remove", "name": "n"}, "confirmed_not_true"),
    ("amt_mirror_link", {"device": "x", "action": "start"}, "confirmed_not_true"),
    ("amt_ider", {"device": "x", "action": "mount"}, "confirmed_not_true"),
])
def test_a_call_that_breaks_a_rule_is_refused_before_anything_is_sent(tool, args, why, fake_amt, tmp_path):
    with pytest.raises(mcp_client.McpError, match=why):
        client_for(fake_amt, tmp_path).call(tool, args)
    assert fake_amt.calls == []


@pytest.mark.parametrize("tool,args", [
    ("amt_status", {"device": "my-server-1"}), ("amt_devices", {"action": "list"}), ("amt_identities", {}), ("amt_captures", {"action": "list"}),
    ("amt_images", {"action": "list"}), ("amt_images", {"action": "verify", "name": "a.iso"}), ("amt_mirror_link", {"device": "x", "action": "status"}),
    ("amt_mirror_link", {"device": "x", "action": "stop"}), ("amt_serial_link", {"device": "x", "action": "record_stop"}),
    ("amt_ider", {"device": "x", "action": "status"}), ("amt_power", {"device": "x", "action": "restart", "confirmed": True}),
    ("amt_images", {"action": "delete", "name": "a.iso", "confirmed": True}),
])
def test_calls_that_follow_the_rules_are_sent_with_the_bearer(tool, args, fake_amt, tmp_path):
    res = client_for(fake_amt, tmp_path).call(tool, args)
    assert fake_amt.calls == [(tool, args, f"Bearer {BEARER}")] and not res.is_error


@pytest.mark.parametrize("sse", [False, True])
def test_a_json_or_event_stream_reply_is_parsed(sse, tmp_path):
    fake = FakeAmt(sse=sse)
    try:
        fake.results["amt_status"] = lambda a: {"power": "on", "device": a["device"]}
        res = client_for(fake, tmp_path).call("amt_status", {"device": "my-server-1"})
        assert res.structured == {"power": "on", "device": "my-server-1"} and not res.is_error and "on" in res.text
    finally:
        fake.close()


def test_the_fake_answers_in_the_real_server_s_shape():
    """amt-mcp's tools declare no output schema, so the server sends a dict as JSON text and no structuredContent. The fake does the same
    (console_fakes.FakeAmt); a fake that sent structuredContent hid, until the first live deploy, that every console path read a null."""
    live = live_tools()
    assert len(live) > 20
    assert [n for n, t in live.items() if t.outputSchema is not None] == []
    fake = FakeAmt()
    try:
        fake.results["amt_status"] = lambda a: {"power": "on"}
        import json, urllib.request
        req = urllib.request.Request(f"{fake.base}/mcp", method="POST", headers={"Authorization": f"Bearer {BEARER}", "Content-Type": "application/json"},
                                     data=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": "amt_status", "arguments": {}}}).encode())
        result = json.loads(urllib.request.urlopen(req, timeout=10).read())["result"]
        assert "structuredContent" not in result and json.loads(result["content"][0]["text"]) == {"power": "on"}
    finally:
        fake.close()


@pytest.mark.parametrize("result,structured", [
    ({"content": [{"type": "text", "text": '{"a": 1}'}], "isError": False}, {"a": 1}),                                  # the real server's shape
    ({"content": [{"type": "text", "text": "{}"}], "structuredContent": {"b": 2}, "isError": False}, {"b": 2}),        # sent: it wins
    ({"content": [{"type": "text", "text": "plain words"}], "isError": False}, None),                                  # not JSON
    ({"content": [{"type": "text", "text": "3"}], "isError": False}, None),                                           # JSON, not an object
])
def test_a_text_only_result_is_parsed_into_its_structured_value(result, structured, fake_amt, tmp_path):
    fake_amt.results["amt_status"] = lambda a: result
    assert client_for(fake_amt, tmp_path).call("amt_status", {"device": "my-server-1"}).structured == structured


def test_a_tool_refusal_comes_back_as_an_error_result_with_its_reason(fake_amt, tmp_path):
    fake_amt.results["amt_power"] = lambda a: {"content": [{"type": "text", "text": "refused: host is already on; nothing sent"}], "isError": True}
    res = client_for(fake_amt, tmp_path).call("amt_power", {"device": "x", "action": "power_on", "confirmed": True})
    assert res.is_error and res.text == "refused: host is already on; nothing sent"


# -- the bearer: read in-process, held in memory, never leaked --------------------------------------------------------

@pytest.mark.parametrize("make,why", [
    (lambda tmp: None, "vault_unconfigured:amt-console-token"),
    (lambda tmp: str(tmp / "missing.py"), "vault_miss:amt-console-token"),
    (lambda tmp: _script(tmp, "raise SystemExit(0)"), "vault_empty:amt-console-token"),
    (lambda tmp: _script(tmp, "import sys; print('LEAK-stdout'); sys.stderr.write('LEAK-stderr'); raise SystemExit(3)"), "vault_miss:amt-console-token"),
    (lambda tmp: _script(tmp, "import time; time.sleep(60)"), "vault_unavailable:amt-console-token:TimeoutExpired"),
])
def test_a_vault_fault_fails_closed_and_names_the_entry_only(make, why, tmp_path, monkeypatch, fake_amt):
    monkeypatch.setattr(mcp_client, "TIMEOUT_SECONDS", 1)
    client = mcp_client.Client(f"{fake_amt.base}/mcp", mcp_client.Vault(make(tmp_path)), 5)
    with pytest.raises(mcp_client.VaultError) as err:
        client.call("amt_status", {"device": "x"})
    assert str(err.value) == why and "LEAK" not in str(err.value)
    assert fake_amt.calls == []                                           # no call goes out without a bearer


def _script(tmp, body):
    path = tmp / "cli.py"
    path.write_text(body + "\n")
    return str(path)


def test_the_bearer_is_read_once_and_forgotten_when_the_gate_refuses_it(fake_amt, tmp_path):
    cli = write_vault_cli(tmp_path, bearer="stale-token")
    reads = tmp_path / "reads"
    cli.write_text(cli.read_text().replace("print(", f"open({str(reads)!r}, 'a').write('x'); print(", 1))
    client = mcp_client.Client(f"{fake_amt.base}/mcp", mcp_client.Vault(str(cli)), 15)
    assert client.call("amt_status", {"device": "x"}).is_error                # the fake expects another token: refused
    assert client.call("amt_status", {"device": "x"}).is_error
    assert reads.read_text() == "xx"                                          # a refusal made the next call read the vault again
    fake_amt.results["amt_status"] = lambda a: {"ok": True}
    cli.write_text(write_vault_cli(tmp_path).read_text().replace("print(", f"open({str(reads)!r}, 'a').write('x'); print(", 1))
    assert not client.call("amt_status", {"device": "x"}).is_error
    assert not client.call("amt_status", {"device": "x"}).is_error
    assert reads.read_text() == "xxx"                                         # then it is kept in memory


def test_the_vault_cli_is_given_the_entry_name_only(tmp_path, fake_amt):
    argv_file = tmp_path / "argv"
    cli = tmp_path / "cli.py"
    cli.write_text(f"import sys; open({str(argv_file)!r}, 'w').write(repr(sys.argv)); print({BEARER!r})\n")
    mcp_client.Client(f"{fake_amt.base}/mcp", mcp_client.Vault(str(cli)), 15).call("amt_status", {"device": "x"})
    assert argv_file.read_text().endswith("'get', 'amt-console-token']") and BEARER not in argv_file.read_text()


# -- transport faults and redirects -----------------------------------------------------------------------------------

def test_an_unreachable_amt_mcp_is_an_error_without_the_bearer(tmp_path):
    client = mcp_client.Client("http://127.0.0.1:9/mcp", mcp_client.Vault(str(write_vault_cli(tmp_path))), 5)
    with pytest.raises(mcp_client.McpError, match=r"^amt_mcp_unreachable:\w+Error$") as err:
        client.call("amt_status", {"device": "x"})
    assert BEARER not in str(err.value)


def test_a_redirect_is_not_followed_so_the_bearer_goes_nowhere_else(tmp_path):
    seen = []

    class Target(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self): seen.append(dict(self.headers)); self.send_response(200); self.send_header("Content-Length", "0"); self.end_headers()

    target = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Target)
    threading.Thread(target=target.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()

    hits = []

    class Redirect(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            hits.append(dict(self.headers))
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(307); self.send_header("Location", f"http://127.0.0.1:{target.server_address[1]}/mcp"); self.send_header("Content-Length", "0"); self.end_headers()

    hop = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Redirect)
    threading.Thread(target=hop.serve_forever, kwargs={"poll_interval": 0.01}, daemon=True).start()
    try:
        client = mcp_client.Client(f"http://127.0.0.1:{hop.server_address[1]}/mcp", mcp_client.Vault(str(write_vault_cli(tmp_path))), 5)
        with pytest.raises(mcp_client.McpError, match="amt_mcp_http_307"):
            client.call("amt_status", {"device": "x"})
        assert len(hits) == 1 and hits[0]["Authorization"] == f"Bearer {BEARER}"   # the first hop did get it (the control)
        assert seen == []
    finally:
        for s in (target, hop):
            s.shutdown(); s.server_close()


# -- through the console's /api/call (immutable 6 on real calls) -------------------------------------------------------

def test_api_call_names_device_and_bearer_on_every_forwarded_call(signed_in, fake_amt):
    for tool, args in (("amt_status", {"device": "my-server-1"}), ("amt_power", {"device": "my-server-1", "action": "restart", "confirmed": True}),
                       ("amt_images", {"action": "list"}), ("amt_devices", {"action": "list"})):
        r = signed_in.post("/api/call", {"tool": tool, "arguments": args})
        assert r.status == 200 and r.json()["isError"] is False
    assert [(t, a.get("device")) for t, a, _ in fake_amt.calls] == [("amt_status", "my-server-1"), ("amt_power", "my-server-1"), ("amt_images", None), ("amt_devices", None)]
    assert {auth for _, _, auth in fake_amt.calls} == {f"Bearer {BEARER}"}
    for tool, args, _ in fake_amt.calls:                                  # the spy: the rules hold over what was really sent
        mcp_client.validate_call(tool, args)


@pytest.mark.parametrize("body,status,error", [
    ({"tool": "amt_status", "arguments": {}}, 400, "device_not_named"),
    ({"tool": "amt_power", "arguments": {"device": "x", "action": "restart"}}, 400, "confirmed_not_true"),
    ({"tool": "rm_rf", "arguments": {}}, 400, "unknown_tool"),
    ({"arguments": {"device": "x"}}, 400, "unknown_tool"),
])
def test_api_call_refuses_a_call_that_breaks_a_rule(signed_in, fake_amt, body, status, error):
    r = signed_in.post("/api/call", body)
    assert (r.status, r.json()["error"]) == (status, error) and fake_amt.calls == []


def test_api_call_reports_a_vault_fault_and_an_unreachable_amt_mcp(tmp_path, fake_amt):
    from console_fakes import Console, enroll_first_passkey, Authenticator
    c = Console(tmp_path, fake_amt, secrets_cli=None)
    try:
        enroll_first_passkey(c, Authenticator(c.app.cfg.rp_id, c.origin))
        r = c.post("/api/call", {"tool": "amt_status", "arguments": {"device": "x"}})
        assert (r.status, r.json()["error"]) == (503, "console_bearer_unavailable")
    finally:
        c.close()
    (tmp_path / "b").mkdir()
    c2 = Console(tmp_path / "b", fake_amt, mcp_url="http://127.0.0.1:9/mcp")
    try:
        enroll_first_passkey(c2, Authenticator(c2.app.cfg.rp_id, c2.origin))
        r = c2.post("/api/call", {"tool": "amt_status", "arguments": {"device": "x"}})
        assert r.status == 502 and r.json()["error"].startswith("amt_mcp_unreachable:")
    finally:
        c2.close()


# -- an `action` that is not a string is a refusal in the fixed vocabulary, never a fault ---------------------------------

@pytest.mark.parametrize("action", [["list"], {"list": 1}, 3, None, True])
def test_a_non_string_action_is_refused_as_unconfirmed_not_raised(action, signed_in, fake_amt):
    with pytest.raises(mcp_client.McpError, match="confirmed_not_true"):
        mcp_client.validate_call("amt_images", {"action": action})
    r = signed_in.post("/api/call", {"tool": "amt_images", "arguments": {"action": action}})
    assert (r.status, r.json()["error"]) == (400, "confirmed_not_true") and fake_amt.calls == []
    # the control: the same tool with a listed read action needs no confirmed, and with confirmed true anything goes
    assert mcp_client.validate_call("amt_images", {"action": "list"}) == {"action": "list"}
    assert mcp_client.validate_call("amt_images", {"action": action, "confirmed": True})


# -- the reply is matched to its request by JSON-RPC id --------------------------------------------------------------------

def rpc(rid, **kw):
    import json
    return json.dumps({"jsonrpc": "2.0", "id": rid, **kw})


def test_a_reply_for_another_request_id_is_not_taken_for_ours():
    with pytest.raises(mcp_client.McpError, match="amt_mcp_bad_response"):
        mcp_client._rpc_message(rpc(8, result={"x": 1}), "application/json", 7)
    assert mcp_client._rpc_message(rpc(7, result={"x": 1}), "application/json", 7)["result"] == {"x": 1}


def test_an_event_stream_is_searched_for_our_id_past_other_messages():
    stream = (f"event: message\ndata: {rpc(6, result={'x': 'other'})}\n\n"
              f"event: message\ndata: not json\n\n"
              f"event: message\ndata: {rpc(7, result={'x': 'ours'})}\n\n")
    assert mcp_client._rpc_message(stream, "text/event-stream", 7)["result"] == {"x": "ours"}
    with pytest.raises(mcp_client.McpError, match="amt_mcp_bad_response"):
        mcp_client._rpc_message(stream, "text/event-stream", 9)
