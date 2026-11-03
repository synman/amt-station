"""amt_identities, amt_identity_manage, the PUT /intake/<token> route and CORS on the intake and upload routes.

The vault CLI is a real child process (a small fake script keeping its entries in a JSON file), so the
subprocess boundary the production code crosses is the one under test: what reaches argv, what reaches
stdin, what comes back. No test touches a real vault, a host or the network. ``SENTINEL`` is the secret
value every test sends; it must appear in the fake vault's store and nowhere else.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import amt_handoff
import amt_identity
import amt_mirror
import amt_registry
import amt_server
import amt_tools
import amt_upload
import amt_vault
import amt_write

BASE = "https://amt.test.invalid"
CONSOLE = "https://console.test.invalid"
SENTINEL = "Sentinel-Ident-7731-xQ"
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


class World:
    def __init__(self, tmp_path: Path):
        self.dir = tmp_path / "fakevault"
        self.dir.mkdir()
        self.cli = tmp_path / "fake_secrets.py"
        self.cli.write_text(FAKE_CLI)

    @property
    def store(self) -> dict:
        p = self.dir / "store.json"
        return json.loads(p.read_text()) if p.exists() else {}

    def seed(self, name: str, notes: str = "amt-mcp dedicated vault copy") -> None:
        store = self.store
        store[name] = {"value": "seed-value", "notes": notes}
        (self.dir / "store.json").write_text(json.dumps(store))

    @property
    def argv_log(self) -> str:
        p = self.dir / "argv.jsonl"
        return p.read_text() if p.exists() else ""


@pytest.fixture
def world(tmp_path, monkeypatch):
    w = World(tmp_path)
    monkeypatch.setattr(amt_vault, "SECRETS", w.cli)
    monkeypatch.setenv("FAKE_VAULT_DIR", str(w.dir))
    monkeypatch.delenv("FAKE_VAULT_FAIL", raising=False)
    monkeypatch.delenv("NVAULT_VAULT_PATH", raising=False)
    monkeypatch.delenv(amt_registry.DEVICES_FILE_ENV, raising=False)
    monkeypatch.delenv(amt_mirror.CONSOLE_ORIGIN_ENV, raising=False)
    amt_upload._INTAKES.clear()
    w.seed("my-server-1-amt")
    w.seed("my-server-1-os")
    return w


@pytest.fixture
def client(monkeypatch, world):
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, BASE)
    monkeypatch.setenv(amt_server.TRANSPORT_ENV, "http")
    return TestClient(amt_server.build_http_app(amt_server.mcp))


def mint(name="my-server-1-amt") -> dict:
    return asyncio.run(amt_identity.amt_identity_manage(action="intake", name=name, confirmed=True))


def path(url: str) -> str:
    return "/" + url.split("/", 3)[3]


# -- the tools' schemas ----------------------------------------------------------------------

def test_neither_tool_has_a_parameter_that_could_carry_a_secret():
    tools = {t.name: t for t in asyncio.run(amt_server.mcp.list_tools())}
    expected = {"amt_identities": {"device"}, "amt_identity_manage": {"action", "name", "confirmed"}}
    for name, props in expected.items():
        schema = tools[name].inputSchema["properties"]
        assert set(schema) == props, name
        assert not [p for p in schema if any(w in p.lower() for w in
                                             ("value", "secret", "pass", "token", "credential", "key", "data"))]
        for p in schema.values():          # only an enum, a name, a flag: nothing free-form beyond a name
            assert p.get("maxLength") is None or p["maxLength"] <= 64
    ann = tools["amt_identity_manage"].annotations
    assert ann.readOnlyHint is False and ann.destructiveHint is True
    assert tools["amt_identities"].annotations.readOnlyHint is True
    assert tools["amt_identities"].annotations.title == "AMT Identities"


# -- amt_identities --------------------------------------------------------------------------

def test_identities_report_status_source_and_use_and_never_a_value(world):
    world.seed("my-server-1-amt-rfb")
    world.seed("my-server-1-amt-user-ops", f"{amt_upload.SOURCE_NOTE}; updated: 2026-10-20T15:04:05Z")
    world.seed("orphan-entry", amt_upload.SOURCE_NOTE)
    world.seed("unrelated-key")
    store = world.store
    store["my-server-1-amt"]["value"] = SENTINEL
    (world.dir / "store.json").write_text(json.dumps(store))
    out = asyncio.run(amt_identity.amt_identities())
    rows = {r["name"]: r for r in out["identities"]}
    assert set(rows) == {"my-server-1-amt", "my-server-1-os", "my-server-1-amt-rfb",
                         "my-server-1-amt-user-ops", "orphan-entry"}, "unrelated main entries are not listed"
    assert rows["my-server-1-amt"] == {"name": "my-server-1-amt", "status": "present", "source": "main",
                                       "used_by": [{"device": "my-server-1", "field": "amt_vault_key"}],
                                       "updated_at": None}
    assert rows["my-server-1-os"]["used_by"] == [{"device": "my-server-1", "field": "host_vault_key"}]
    assert rows["my-server-1-amt-rfb"]["used_by"] == [{"device": "my-server-1", "field": "amt_configure_kvm"}]
    user = rows["my-server-1-amt-user-ops"]
    assert user["source"] == "console" and user["updated_at"] == "2026-10-20T15:04:05Z"
    assert user["used_by"] == [{"device": "my-server-1", "field": "amt_configure_users"}]
    assert rows["orphan-entry"] == {"name": "orphan-entry", "status": "present", "source": "console",
                                    "used_by": [], "updated_at": None}
    text = json.dumps(out)
    assert SENTINEL not in text and "seed-value" not in text
    assert not any("len" in k or "size" in k for r in rows.values() for k in r)


def test_a_missing_entry_is_reported_missing_and_a_device_filter_scopes_the_rows(world):
    (world.dir / "store.json").write_text(json.dumps({"other": {"value": "v", "notes": amt_upload.SOURCE_NOTE}}))
    out = amt_identity.identities_read("my-server-1")
    rows = {r["name"]: r for r in out["identities"]}
    assert rows["my-server-1-amt"]["status"] == "missing" and rows["my-server-1-amt"]["source"] is None
    assert "other" not in rows, "a device filter lists that server's entries only"
    with pytest.raises(KeyError, match="unknown_device:nope"):
        amt_identity.identities_read("nope")


def test_an_unreadable_vault_is_a_tool_error_naming_no_value(world, monkeypatch):
    monkeypatch.setenv("FAKE_VAULT_FAIL", "list")
    with pytest.raises(amt_vault.VaultError, match="vault_list_failed"):
        amt_identity.identities_read(None)


# -- amt_identity_manage: refusals -----------------------------------------------------------

def test_manage_refuses_without_confirmed_and_does_nothing(world, client):
    with pytest.raises(amt_tools.ConfirmationRequired, match="one-time url"):
        asyncio.run(amt_identity.amt_identity_manage(action="intake", name="my-server-1-amt"))
    assert not amt_upload._INTAKES
    world.seed("my-server-1-amt-user-x", amt_upload.SOURCE_NOTE)
    with pytest.raises(amt_tools.ConfirmationRequired, match="deletes the vault entry"):
        asyncio.run(amt_identity.amt_identity_manage(action="remove", name="my-server-1-amt-user-x"))
    assert "my-server-1-amt-user-x" in world.store and "delete" not in world.argv_log


@pytest.mark.parametrize("name,err", [
    ("not-a-registered-name", "identity_name_not_allowed"),
    ("my-server-1-amt-user-", "identity_name_not_allowed"),       # a user entry needs a user name
    ("nope-amt-user-ops", "identity_name_not_allowed"),           # no such registered device
    ("my-server-1-amt-rfb2", "identity_name_not_allowed"),        # only <amt_vault_key>-rfb itself
    ("nope-amt-rfb", "identity_name_not_allowed"),                # no such registered device
    ("Bad Name", "identity_name_invalid"),
    ("My-Server-1-amt", "identity_name_invalid"),                 # only a user's name part takes capitals
    ("my-server-1-amt-user-" + "X" * 17, "identity_name_invalid"),     # amt_configure's 16 character cap
    ("my-server-1-amt-user-" + "x" * 17, "identity_name_not_allowed"),  # lowercase: a plain name, not a user
    ("my-server-1-amt-user-a b", "identity_name_invalid"),
    ("", "identity_name_invalid")])
def test_intake_names_a_registered_entry_or_a_user_entry_of_a_registered_device(world, client, name, err):
    with pytest.raises(ValueError, match=err):
        amt_identity.identity_manage("intake", name)
    assert not amt_upload._INTAKES


def test_intake_accepts_the_names_the_servers_use_and_a_new_user_entry(world, client):
    for name in ("my-server-1-amt", "my-server-1-os", "my-server-1-amt-user-ops", "my-server-1-amt-rfb"):
        out = mint(name)
        assert set(out) == {"name", "url", "method", "expires_in_s", "max_bytes", "url_note"}
        assert out["name"] == name and out["method"] == "PUT" and out["expires_in_s"] == 900
        assert out["max_bytes"] == amt_upload.INTAKE_MAX_BYTES == 4096
        assert out["url"].startswith(BASE + "/intake/") and len(out["url"].rsplit("/", 1)[1]) == 43
    assert world.argv_log == "", "minting touches no vault"


@pytest.mark.parametrize("user", ["Ops", "ops_1", "a.b@c", "A" * 16])
def test_intake_and_remove_take_every_user_name_amt_configure_can_add(world, client, user):
    name = f"my-server-1-amt-user-{user}"
    assert amt_identity.USER_NAME is amt_write.USER_NAME
    assert amt_identity.identity_manage("intake", name)["name"] == name
    world.seed(name, amt_upload.SOURCE_NOTE)
    assert amt_identity.identity_manage("remove", name) == {"removed": name}
    assert name not in world.store


def test_intake_needs_the_public_base_url(world, monkeypatch):
    monkeypatch.delenv(amt_handoff.BASE_URL_ENV, raising=False)
    with pytest.raises(ValueError, match="identity_intake_needs_AMT_PUBLIC_BASE_URL"):
        amt_identity.identity_manage("intake", "my-server-1-amt")


def test_remove_is_refused_while_a_server_names_the_entry(world):
    store = world.store
    store["my-server-1-os"]["notes"] = amt_upload.SOURCE_NOTE      # console-entered, still named
    (world.dir / "store.json").write_text(json.dumps(store))
    with pytest.raises(ValueError, match=r"identity_in_use:my-server-1-os: named by my-server-1.host_vault_key"):
        amt_identity.identity_manage("remove", "my-server-1-os")
    assert "my-server-1-os" in world.store and "delete" not in world.argv_log


def test_remove_is_refused_for_a_main_sourced_entry(world):
    world.seed("my-server-1-amt-rfb")                                  # synced from the main vault, unnamed
    with pytest.raises(ValueError, match="identity_not_console_entry:my-server-1-amt-rfb"):
        amt_identity.identity_manage("remove", "my-server-1-amt-rfb")
    assert "my-server-1-amt-rfb" in world.store and "delete" not in world.argv_log


def test_remove_deletes_a_console_entry_no_server_names_and_refuses_an_absent_one(world):
    world.seed("my-server-1-amt-user-ops", amt_upload.SOURCE_NOTE)
    assert asyncio.run(amt_identity.amt_identity_manage(
        action="remove", name="my-server-1-amt-user-ops", confirmed=True)) == {"removed": "my-server-1-amt-user-ops"}
    assert "my-server-1-amt-user-ops" not in world.store
    with pytest.raises(ValueError, match="identity_not_found:my-server-1-amt-user-ops"):
        amt_identity.identity_manage("remove", "my-server-1-amt-user-ops")


# -- the intake route ------------------------------------------------------------------------

def test_the_value_lands_in_the_vault_through_stdin_and_nowhere_else(world, client, caplog):
    caplog.set_level(logging.DEBUG)
    out = mint("my-server-1-amt-user-ops")
    url = path(out["url"])
    r = client.put(url, content=SENTINEL.encode())
    assert r.status_code == 201 and r.json() == {"name": "my-server-1-amt-user-ops", "stored": True}
    entry = world.store["my-server-1-amt-user-ops"]
    assert entry["value"] == SENTINEL
    assert amt_upload.SOURCE_NOTE in entry["notes"] and "updated: 20" in entry["notes"]
    calls = [json.loads(line) for line in world.argv_log.splitlines()]
    sets = [c for c in calls if c[0] == "set"]
    assert len(sets) == 1 and sets[0][1] == "my-server-1-amt-user-ops", "one write, to the minted name"
    assert SENTINEL not in world.argv_log, "the value never reaches the CLI's argv"
    assert SENTINEL not in r.text and SENTINEL not in json.dumps(out)
    assert SENTINEL not in caplog.text and not [x for x in caplog.records if SENTINEL in x.getMessage()]
    # read back: the new entry reports as entered here, with an updated-at, and no value
    row = {x["name"]: x for x in amt_identity.identities_read(None)["identities"]}["my-server-1-amt-user-ops"]
    assert row["source"] == "console" and row["updated_at"].startswith("20")
    assert SENTINEL not in json.dumps(row)


def test_a_replaced_value_makes_the_entry_console_sourced_and_json_logon_is_exact(world, client):
    logon = json.dumps({"user": "jdoe", "password": SENTINEL})
    r = client.put(path(mint("my-server-1-os")["url"]), content=logon.encode())
    assert r.status_code == 201
    assert world.store["my-server-1-os"]["value"] == logon
    assert amt_upload.SOURCE_NOTE in world.store["my-server-1-os"]["notes"]


def test_a_second_put_while_the_first_is_still_arriving_is_refused_and_writes_nothing(world, client):
    from starlette.requests import Request
    token = path(mint()["url"]).rsplit("/", 1)[1]

    def request(receive):
        return Request({"type": "http", "method": "PUT", "headers": [], "path_params": {"token": token}},
                       receive)

    async def scenario():
        release = asyncio.Event()

        async def slow():                      # the first body, held until the second request is answered
            await release.wait()
            return {"type": "http.request", "body": b"first-one", "more_body": False}

        async def fast():
            return {"type": "http.request", "body": b"second-one", "more_body": False}

        first = asyncio.create_task(amt_upload.receive_intake(request(slow)))
        await asyncio.sleep(0.05)              # the first has claimed the offer and waits on its body
        second = await amt_upload.receive_intake(request(fast))
        release.set()
        return await first, second

    first, second = asyncio.run(scenario())
    assert second.status_code == 404 and first.status_code == 201
    assert world.store["my-server-1-amt"]["value"] == "first-one"
    assert [json.loads(l)[1] for l in world.argv_log.splitlines() if json.loads(l)[0] == "set"] == ["my-server-1-amt"]


def test_the_url_is_single_use(world, client):
    url = path(mint()["url"])
    assert client.put(url, content=b"first-one").status_code == 201
    second = client.put(url, content=SENTINEL.encode())
    assert second.status_code == 404
    assert world.store["my-server-1-amt"]["value"] == "first-one", "the second PUT wrote nothing"
    assert not amt_upload._INTAKES


def test_an_expired_or_malformed_or_unknown_token_is_404_and_writes_nothing(world, client):
    out = mint()
    for o in amt_upload._INTAKES.values():
        o.expires = time.time() - 1
    assert client.put(path(out["url"]), content=SENTINEL.encode()).status_code == 404
    assert client.put("/intake/short", content=SENTINEL.encode()).status_code == 404
    assert client.put("/intake/" + "A" * 43, content=SENTINEL.encode()).status_code == 404
    assert "set" not in world.argv_log


@pytest.mark.parametrize("body,status,err", [
    (lambda: b"", 400, "value_empty"),
    (lambda: SENTINEL.encode() + b"\n", 400, "value_has_a_line_break_or_nul"),
    (lambda: b"a\x00" + SENTINEL.encode(), 400, "value_has_a_line_break_or_nul"),
    (lambda: b"\xff\xfe" + SENTINEL.encode(), 400, "value_not_utf8"),
    (lambda: SENTINEL.encode() * 200, 413, "value_larger_than_4096_bytes"),                  # one sized body
    (lambda: iter([SENTINEL.encode() * 100, SENTINEL.encode() * 100]), 413, "value_larger_than")])  # chunked
def test_a_bad_body_is_refused_stores_nothing_and_still_spends_the_url(world, client, body, status, err):
    url = path(mint()["url"])
    r = client.put(url, content=body())
    assert r.status_code == status and err in r.text and SENTINEL not in r.text
    assert world.store["my-server-1-amt"]["value"] == "seed-value" and "set" not in world.argv_log
    assert client.put(url, content=b"retry").status_code == 404, "consumed before the body was judged"


def test_exactly_max_bytes_is_accepted(world, client):
    body = b"x" * amt_upload.INTAKE_MAX_BYTES
    assert client.put(path(mint()["url"]), content=body).status_code == 201
    assert world.store["my-server-1-amt"]["value"] == body.decode()


def test_an_unwritable_vault_answers_503_writes_nothing_and_keeps_the_url(world, client, monkeypatch, tmp_path):
    monkeypatch.setenv("NVAULT_VAULT_PATH", str(tmp_path / "no-such-dir" / "amt-mcp.vault"))
    url = path(mint()["url"])
    r = client.put(url, content=SENTINEL.encode())
    assert r.status_code == 503 and "vault_not_writable" in r.text and SENTINEL not in r.text
    assert "set" not in world.argv_log and world.store["my-server-1-amt"]["value"] == "seed-value"
    monkeypatch.delenv("NVAULT_VAULT_PATH")                         # the mount is fixed: the same url works
    assert client.put(url, content=SENTINEL.encode()).status_code == 201


def test_vault_writable_judges_the_dedicated_vault_path(monkeypatch, tmp_path):
    vault = tmp_path / "amt-mcp.vault"
    vault.write_text("x")
    monkeypatch.setenv("NVAULT_VAULT_PATH", str(vault))
    assert amt_vault.vault_writable() is True
    monkeypatch.setattr(os, "access", lambda p, mode: p != str(tmp_path))          # a read-only directory
    assert amt_vault.vault_writable() is False
    monkeypatch.setattr(os, "access", lambda p, mode: p != str(vault))             # a read-only file
    assert amt_vault.vault_writable() is False
    monkeypatch.delenv("NVAULT_VAULT_PATH")
    assert amt_vault.vault_writable() is True


def test_a_failing_cli_never_echoes_the_value(world, client, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("FAKE_VAULT_FAIL", "set")                    # this CLI writes its stdin to stderr
    url = path(mint()["url"])
    r = client.put(url, content=SENTINEL.encode())
    assert r.status_code == 503 and "vault_write_failed:my-server-1-amt" in r.text
    assert SENTINEL not in r.text and SENTINEL not in caplog.text and SENTINEL not in world.argv_log
    with pytest.raises(amt_vault.VaultError) as ex:
        amt_vault.set_secret("k", SENTINEL, "n", "2035-01-01")
    assert str(ex.value) == "vault_write_failed:k"
    assert client.put(url, content=b"again").status_code == 404, "a failed write spends the url too"


def test_a_vault_timeout_is_a_503_naming_no_value(world, client, monkeypatch):
    monkeypatch.setattr(amt_vault, "TIMEOUT_SECONDS", 0.2)
    world.cli.write_text("import time\ntime.sleep(5)\n")
    r = client.put(path(mint()["url"]), content=SENTINEL.encode())
    assert r.status_code == 503 and SENTINEL not in r.text


def test_the_tool_path_through_the_gated_server_logs_no_value(world, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv(amt_handoff.BASE_URL_ENV, BASE)
    monkeypatch.setenv(amt_server.TRANSPORT_ENV, "stdio")
    with pytest.raises(Exception, match="confirmation_required"):
        asyncio.run(amt_server.mcp.call_tool("amt_identity_manage", {"action": "intake", "name": "my-server-1-amt"}))
    assert not amt_upload._INTAKES
    out = asyncio.run(amt_server.mcp.call_tool(
        "amt_identity_manage", {"action": "intake", "name": "my-server-1-amt", "confirmed": True}))
    assert "/intake/" in json.dumps(out, default=str)
    listed = asyncio.run(amt_server.mcp.call_tool("amt_identities", {}))
    assert "my-server-1-amt" in json.dumps(listed, default=str)
    assert SENTINEL not in caplog.text


# -- CORS ------------------------------------------------------------------------------------

def _preflight(client, route, origin=CONSOLE):
    return client.options(route, headers={"Origin": origin, "Access-Control-Request-Method": "PUT"})


@pytest.mark.parametrize("route", ["/intake/" + "A" * 43, "/uploads/" + "A" * 43])
def test_the_console_origin_gets_a_preflight_answer_and_nobody_else_does(world, client, monkeypatch, route):
    monkeypatch.setenv(amt_mirror.CONSOLE_ORIGIN_ENV, CONSOLE)
    ok = _preflight(client, route)
    assert ok.status_code == 204
    assert ok.headers["access-control-allow-origin"] == CONSOLE
    assert ok.headers["access-control-allow-methods"] == "PUT, POST, OPTIONS"
    assert ok.headers["vary"] == "Origin"
    assert "access-control-allow-credentials" not in ok.headers
    for other in ("https://evil.test.invalid", CONSOLE + ".evil.test.invalid", "http://console.test.invalid"):
        bad = _preflight(client, route, other)
        assert not [h for h in bad.headers if h.startswith("access-control-")], other
    assert not [h for h in client.options(route).headers if h.startswith("access-control-")], "no Origin"


@pytest.mark.parametrize("env", [None, "", "not an origin", "https://console.test.invalid/path", "*", "null"])
def test_without_a_valid_configured_origin_no_cors_header_is_ever_sent(world, client, monkeypatch, env):
    if env is not None:
        monkeypatch.setenv(amt_mirror.CONSOLE_ORIGIN_ENV, env)
    for origin in (CONSOLE, "*", "null", "'none'", "https://console.test.invalid/path"):
        r = _preflight(client, "/intake/" + "A" * 43, origin)
        assert not [h for h in r.headers if h.startswith("access-control-")], (env, origin)
        r = client.put("/intake/" + "A" * 43, content=b"x", headers={"Origin": origin})
        assert not [h for h in r.headers if h.startswith("access-control-")], (env, origin)


def test_the_actual_responses_carry_the_origin_only_for_the_console(world, client, monkeypatch):
    monkeypatch.setenv(amt_mirror.CONSOLE_ORIGIN_ENV, CONSOLE)
    stored = client.put(path(mint()["url"]), content=SENTINEL.encode(), headers={"Origin": CONSOLE})
    assert stored.status_code == 201 and stored.headers["access-control-allow-origin"] == CONSOLE
    gone = client.put(path(mint()["url"]) + "x", content=b"x", headers={"Origin": CONSOLE})
    assert gone.status_code == 404 and gone.headers["access-control-allow-origin"] == CONSOLE, \
        "the browser can read a refusal"
    other = client.put(path(mint()["url"]), content=SENTINEL.encode(), headers={"Origin": "https://evil.test.invalid"})
    assert other.status_code == 201 and "access-control-allow-origin" not in other.headers
    assert all("access-control-allow-credentials" not in r.headers for r in (stored, gone, other))
