"""Skeleton smoke tests: bare server, bearer gate over real ASGI HTTP, vault, registry, parity.

No test touches a real vault entry, the network or an AMT host. Every token here is a
throwaway test string; only its SHA-256 is placed in MCP_ADMIN_TOKEN_HASH.
"""
import asyncio
import hashlib
import json
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import amt_gate  # noqa: E402
import amt_parity  # noqa: E402
import amt_registry  # noqa: E402
import amt_server  # noqa: E402
import amt_vault  # noqa: E402

TOKEN = "test-token-not-a-secret"
TOKEN_HASH = hashlib.sha256(TOKEN.encode()).hexdigest()
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}


@pytest.fixture(autouse=True)
def _gate_env(monkeypatch):
    monkeypatch.setenv(amt_gate.HASH_ENV, TOKEN_HASH)
    monkeypatch.delenv(amt_gate.TRANSPORT_ENV, raising=False)


def _server_with_ping(calls):
    server = amt_server.build_server()

    @server.tool(name="ping", annotations={"title": "Ping", "readOnlyHint": True})
    def ping() -> dict:
        """Test tool."""
        calls.append(1)
        return {"pong": True}

    return server


def _rpc(client, method, params=None, token=None, rid=1):
    headers = dict(HEADERS)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    resp = client.post(
        "/mcp", headers=headers,
        json={"jsonrpc": "2.0", "id": rid, "method": method, "params": params or {}},
    )
    body = resp.text
    if resp.status_code != 200:
        return resp.status_code, None
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        body = next(l[5:].strip() for l in body.splitlines() if l.startswith("data:"))
    return resp.status_code, json.loads(body)


def _call(client, name, token=None):
    status, msg = _rpc(client, "tools/call", {"name": name, "arguments": {}}, token)
    assert status == 200, "refusal must be an MCP tool error, never an HTTP status"
    return msg["result"]


def _client(server, host="127.0.0.1:8765", extra_hosts=""):
    return TestClient(amt_server.build_http_app(server, extra_hosts), base_url=f"http://{host}")


# --- skeleton shape -------------------------------------------------------------------

def test_build_server_is_bare_and_mcp_carries_exactly_the_read_composite_and_write_tools():
    assert len(asyncio.run(amt_server.build_server().list_tools())) == 0
    names = {t.name for t in asyncio.run(amt_server.mcp.list_tools())}
    assert names == {"amt_status", "amt_screenshot", "amt_inventory", "amt_logs",
                     "amt_settings", "amt_wsman_get", "amt_remote_logon", "amt_remote_logoff",
                     "amt_power", "amt_set_next_boot", "amt_console_input", "amt_sol", "amt_ider",
                     "amt_images", "amt_configure", "amt_wsman_invoke", "amt_mirror_link",
                     "amt_serial_link", "amt_devices", "amt_device_manage", "amt_identities",
                     "amt_identity_manage", "amt_captures"}


def test_server_is_stateless_and_instructions_fit():
    assert amt_server.mcp.settings.stateless_http is True
    assert len(amt_server.mcp.instructions) <= 2048


# --- bearer gate over real HTTP --------------------------------------------------------

def test_gate_refuses_absent_and_wrong_token_and_accepts_correct():
    calls = []
    with _client(_server_with_ping(calls)) as c:
        for token in (None, "wrong-token"):
            res = _call(c, "ping", token)
            assert res["isError"] is True
            assert "mcp-admin-token" in res["content"][0]["text"]
        assert calls == [], "tool body must not run on a refused call"

        res = _call(c, "ping", TOKEN)
        assert not res.get("isError")
        assert calls == [1], "tripwire: the gated branch let the correct token through"


def test_http_layer_rejects_nothing():
    with _client(_server_with_ping([])) as c:
        status, msg = _rpc(c, "tools/list")  # anonymous, no bearer
        assert status == 200 and "error" not in msg
        assert [t["name"] for t in msg["result"]["tools"]] == ["ping"]


def test_unknown_tool_is_refused_before_dispatch_without_token():
    with _client(amt_server.build_server()) as c:
        anon = _call(c, "does_not_exist")
        assert anon["isError"] and "mcp-admin-token" in anon["content"][0]["text"]
        authed = _call(c, "does_not_exist", TOKEN)
        assert authed["isError"] and "mcp-admin-token" not in authed["content"][0]["text"]


@pytest.mark.parametrize("bad", [None, "", "not-hex", "abc123", "Z" * 64])
def test_unresolvable_hash_fails_closed(monkeypatch, bad):
    if bad is None:
        monkeypatch.delenv(amt_gate.HASH_ENV, raising=False)
    else:
        monkeypatch.setenv(amt_gate.HASH_ENV, bad)
    calls = []
    with _client(_server_with_ping(calls)) as c:
        assert _call(c, "ping", TOKEN)["isError"] is True
    assert calls == []


def test_stdio_skip_is_exact_and_nonstdio_stays_gated(monkeypatch):
    # Only the exact value "stdio" is honored as the ungated transport.
    monkeypatch.setenv(amt_gate.TRANSPORT_ENV, "stdio")
    assert amt_gate.is_stdio_transport() is True
    # Building the HTTP mount while env=stdio now FAILS CLOSED (the fail-open fix);
    # the dedicated assertion is test_build_http_app_refuses_when_env_marks_stdio.
    monkeypatch.setenv(amt_gate.TRANSPORT_ENV, "stdio-ish")
    assert amt_gate.is_stdio_transport() is False
    calls = []
    with _client(_server_with_ping(calls)) as c:  # "stdio-ish" is treated as HTTP
        assert _call(c, "ping")["isError"] is True  # gated: no bearer
        assert not _call(c, "ping", TOKEN).get("isError")
    assert calls == [1]


def test_verify_bearer_unit():
    assert amt_gate.verify_bearer(TOKEN) is True
    assert amt_gate.verify_bearer("nope") is False
    assert amt_gate.verify_bearer("") is False
    assert amt_gate.verify_bearer(None) is False


def test_ingress_host_needs_allowed_hosts_and_portless_is_listed():
    srv = lambda: amt_server.build_server()  # noqa: E731
    with _client(srv(), host="other.example.net") as c:
        status, _ = _rpc(c, "tools/list")
        assert status == 421  # default allowlist is loopback only
    with _client(srv(), host="other.example.net", extra_hosts="other.example.net") as c:
        status, _ = _rpc(c, "tools/list")
        assert status == 200


# --- vault resolution ------------------------------------------------------------------

def _fake_secrets(tmp_path, body):
    p = tmp_path / "fake_secrets.py"
    p.write_text(body)
    return p


def test_vault_resolves_in_process_and_fails_closed(tmp_path, monkeypatch):
    dummy = "dummy-vault-value"
    monkeypatch.setattr(amt_vault, "SECRETS", _fake_secrets(
        tmp_path, f"import sys\nassert sys.argv[1:] == ['get', 'k']\nprint({dummy!r})\n"))
    assert amt_vault.get_secret("k") == dummy

    monkeypatch.setattr(amt_vault, "SECRETS", _fake_secrets(
        tmp_path, f"import sys\nsys.stderr.write({dummy!r})\nsys.exit(1)\n"))
    with pytest.raises(amt_vault.VaultError) as ex:
        amt_vault.get_secret("k")
    assert str(ex.value) == "vault_miss:k" and dummy not in str(ex.value)

    monkeypatch.setattr(amt_vault, "SECRETS", _fake_secrets(tmp_path, "print('')\n"))
    with pytest.raises(amt_vault.VaultError, match="vault_empty:k"):
        amt_vault.get_secret("k")

    monkeypatch.setattr(amt_vault, "SECRETS", tmp_path / "absent.py")
    with pytest.raises(amt_vault.VaultError, match="vault_miss:k"):
        amt_vault.get_secret("k")

    with pytest.raises(amt_vault.VaultError):
        amt_vault.get_secret("  ")

    monkeypatch.setattr(amt_vault, "SECRETS", None)
    with pytest.raises(amt_vault.VaultError, match="vault_cli_unset"):
        amt_vault.get_secret("k")


def test_the_vault_cli_path_comes_from_amt_secrets_cli(tmp_path):
    """Read in a fresh interpreter: reloading amt_vault here would swap VaultError for every importer."""
    import os
    import subprocess
    root = Path(__file__).resolve().parent.parent
    probe = ["-c", "import amt_vault; print(amt_vault.SECRETS)"]
    env = {k: v for k, v in os.environ.items() if k != "AMT_SECRETS_CLI"}
    default = subprocess.run([sys.executable, *probe], cwd=root, env=env, capture_output=True, text=True, check=True)
    assert default.stdout.strip() == "None"                      # unset: no default path, every call refuses
    cli = tmp_path / "mounted" / "secrets.py"
    moved = subprocess.run([sys.executable, *probe], cwd=root, env={**env, "AMT_SECRETS_CLI": str(cli)},
                           capture_output=True, text=True, check=True)
    assert moved.stdout.strip() == str(cli)


# --- registry and parity ---------------------------------------------------------------

def test_registry_has_my_server_and_no_secret_material():
    d = amt_registry.get_device("my-server-1")
    assert (d.amt_ip, d.wsman_port, d.kvm_port) == ("198.51.100.26", 16993, 16995)
    assert d.pinned is True and d.tls_leaf_observed_prefix == "a1b2c3d4e5f60718"
    assert d.tls_leaf_sha256 == "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90"
    assert d.tls_leaf_sha256.startswith(d.tls_leaf_observed_prefix)
    with pytest.raises(KeyError):
        amt_registry.get_device("nope")
    with pytest.raises(ValueError):
        amt_registry.Device("x", "1.2.3.4", 1, 2, "v", tls_leaf_sha256="e683")


def test_parity_manifest_census_and_status():
    rows = amt_parity.TOOLS
    by_kind = {}
    for r in rows:
        by_kind[r["kind"]] = by_kind.get(r["kind"], 0) + 1
        assert r["name"].startswith("amt_")
        assert r["write_guard"] == (r["kind"] in ("write", "composite", "mirror"))
        # Every row is implemented (the mirror landed 2026-10-18), and names its surface.
        assert r["status"] == amt_parity.IMPLEMENTED
        assert bool(r["meshcommander"]) == (r["status"] == amt_parity.IMPLEMENTED)
    assert by_kind == amt_parity.CENSUS
    assert len({r["name"] for r in rows}) == len(rows) == 23
    assert {k: v["total"] for k, v in amt_parity.COVERAGE.items()} == {
        "pages": 18, "power_entries": 26, "boot_options": 16, "key_macros": 25}
    # Mapped counts are reconciled and pinned in tests/test_parity.py.
    assert all(v["mapped"] + v["exception"] == v["total"] for v in amt_parity.COVERAGE.values())
    registered = {t.name for t in asyncio.run(amt_server.mcp.list_tools())}
    assert registered == {r["name"] for r in rows if r["status"] == amt_parity.IMPLEMENTED}


# --- gate covers resources and prompts, not just tools (review finding 1) --------------

def _server_with_resource_and_prompt(calls):
    server = amt_server.build_server()

    @server.resource("test://secret")
    def secret_res() -> str:
        calls.append("res")
        return "SECRET-RESOURCE-BODY"

    @server.prompt(name="secret_prompt")
    def secret_prompt() -> str:
        calls.append("prompt")
        return "SECRET-PROMPT-BODY"

    return server


def test_resources_and_prompts_are_gated():
    calls = []
    with _client(_server_with_resource_and_prompt(calls)) as c:
        # Anonymous: neither secret body may be served, and neither handler may run.
        _, r1 = _rpc(c, "resources/read", {"uri": "test://secret"})
        _, r2 = _rpc(c, "prompts/get", {"name": "secret_prompt", "arguments": {}})
        assert "SECRET-RESOURCE-BODY" not in json.dumps(r1 or {})
        assert "SECRET-PROMPT-BODY" not in json.dumps(r2 or {})
        assert calls == [], "resource/prompt handler ran without a bearer"
        # Authed: the resource is served and its handler runs.
        _, r3 = _rpc(c, "resources/read", {"uri": "test://secret"}, token=TOKEN)
        assert "SECRET-RESOURCE-BODY" in json.dumps(r3 or {})
        assert "res" in calls


# --- bearer compare is full-width and case-normalized (review finding 2) ---------------

def test_bearer_compare_full_width_and_case_normalized(monkeypatch):
    # Near-miss: expected hash identical EXCEPT the final hex char. A prefix-only
    # compare (digest[:8]) would wrongly accept; the real full compare must reject.
    near = TOKEN_HASH[:-1] + ("0" if TOKEN_HASH[-1] != "0" else "1")
    monkeypatch.setenv(amt_gate.HASH_ENV, near)
    assert amt_gate.verify_bearer(TOKEN) is False
    # Uppercase hash env must still verify (kills dropping .lower() in configured_hash).
    monkeypatch.setenv(amt_gate.HASH_ENV, TOKEN_HASH.upper())
    assert amt_gate.verify_bearer(TOKEN) is True


def test_only_bearer_scheme_is_read():
    assert amt_gate._bearer_from_scope({"headers": [(b"authorization", b"Basic abc123")]}) is None
    assert amt_gate._bearer_from_scope({"headers": [(b"authorization", b"Bearer tok")]}) == "tok"


# --- main() and build_http_app fail-closed paths (review findings 4, 7) ----------------

def test_main_http_refuses_to_start_without_valid_hash(monkeypatch):
    monkeypatch.delenv(amt_gate.HASH_ENV, raising=False)
    assert amt_server.main(["--transport", "http"]) == 2
    monkeypatch.setenv(amt_gate.HASH_ENV, "not-a-sha")
    assert amt_server.main(["--transport", "http"]) == 2


def test_build_http_app_refuses_when_env_marks_stdio(monkeypatch):
    monkeypatch.setenv(amt_gate.TRANSPORT_ENV, "stdio")
    with pytest.raises(RuntimeError, match="stdio"):
        amt_server.build_http_app(amt_server.build_server())
