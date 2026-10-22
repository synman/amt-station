"""Fleet MCP Patterns rows the skeleton tests do not already cover, over the real HTTP app.

`tests/test_skeleton.py` holds the basic gate rows: absent and wrong token, the stdio skip, an
unresolvable hash, resources and prompts, the bearer scheme. This file adds the Test Plan rows
that need the real tools or the process seams from `test_direct_endpoint`:

* a tool registered with no annotations is still gated (fail-closed derivation);
* a tokenless read AND write are refused as an MCP tool error with HTTP 200, before the vault or
  the network is touched, and both pass the gate with the bearer;
* the paired zero-write probe: tokenless is refused at the gate, bearer'd fails argument
  validation, and neither reaches the device;
* the gate is per call, not per session, in all three directions;
* the presented bearer is hashed and compared with ``hmac.compare_digest``, and a raw token
  placed in the environment is never accepted as configuration;
* a vault miss refuses every call that would reach a device, with no connection opened;
* host and port come from code (``AMT_BIND_HOST``/``AMT_PORT`` with code defaults), and the
  Dockerfile pins the base image and every pip-installed package. The apt packages
  (``tesseract-ocr``, ``ffmpeg``) are not version-pinned; that is a deploy-packet finding, not
  something this file asserts.

No test touches a real vault entry, the network or an AMT host. The token is a throwaway string.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import amt_gate
import amt_server
import amt_vault
from test_direct_endpoint import CREDENTIAL_CALLS, Recorder, fake_vault

TOKEN = "gate-pattern-test-token-not-a-secret"
TOKEN_HASH = hashlib.sha256(TOKEN.encode()).hexdigest()
HEADERS = {"Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture(autouse=True)
def _env(monkeypatch, tmp_path):
    monkeypatch.setenv(amt_gate.HASH_ENV, TOKEN_HASH)
    monkeypatch.delenv(amt_gate.TRANSPORT_ENV, raising=False)
    root = tmp_path / "images"
    root.mkdir()
    (root / "x.iso").write_bytes(b"\0" * 4096)
    monkeypatch.setenv("AMT_IMAGE_ROOT", str(root))


@pytest.fixture
def seams(monkeypatch):
    return Recorder().install(monkeypatch)


@pytest.fixture
def vault_reads(monkeypatch):
    reads: list[str] = []
    monkeypatch.setattr(amt_vault, "get_secret", lambda key: (reads.append(key), fake_vault(key))[1])
    return reads


def _client(server=None):
    # A streamable-HTTP session manager runs once per server, so every client gets a fresh one.
    server = server or amt_server.register_tools(amt_server.build_server())
    return TestClient(amt_server.build_http_app(server), base_url="http://127.0.0.1:8765")


def _call(client, name, args, token=None):
    headers = dict(HEADERS)
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    resp = client.post("/mcp", headers=headers, json={
        "jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": args}})
    assert resp.status_code == 200, "a refusal is an MCP tool error, never an HTTP status"
    body = resp.text
    if resp.headers.get("content-type", "").startswith("text/event-stream"):
        body = next(line[5:].strip() for line in body.splitlines() if line.startswith("data:"))
    return json.loads(body)["result"]


def _refused_at_gate(result) -> bool:
    return result.get("isError") is True and "mcp-admin-token" in result["content"][0]["text"]


# --- fail-closed derivation ------------------------------------------------------------------

def test_a_tool_registered_without_annotations_is_still_gated():
    calls = []
    server = amt_server.build_server()

    @server.tool(name="bare")
    def bare() -> dict:
        """Fixture tool with no annotations at all."""
        calls.append(1)
        return {"ran": True}

    with _client(server) as c:
        assert _refused_at_gate(_call(c, "bare", {}))
        assert calls == [], "an unannotated tool ran without the bearer"
        assert not _call(c, "bare", {}, TOKEN).get("isError")
    assert calls == [1]


# --- real tools: tokenless read and write refused before vault and network --------------------

@pytest.mark.parametrize("name,args", [("amt_status", {}),
                                       ("amt_power", {"action": "restart", "confirmed": True})])
def test_a_tokenless_read_and_write_are_refused_before_vault_or_network(seams, vault_reads, name, args):
    with _client() as c:
        assert _refused_at_gate(_call(c, name, args))
        assert vault_reads == [] and seams.tcp == [], "a refused call touched the vault or the network"
        authed = _call(c, name, args, TOKEN)
    assert not _refused_at_gate(authed), "the bearer'd call did not pass the gate"
    assert vault_reads and seams.tcp, "the bearer'd call never reached its device step"


def test_the_paired_zero_write_probe(seams, vault_reads):
    with _client() as c:
        anon = _call(c, "amt_set_next_boot", {})
        authed = _call(c, "amt_set_next_boot", {}, TOKEN)
    assert _refused_at_gate(anon)
    assert authed["isError"] is True and not _refused_at_gate(authed)
    assert re.search(r"target|required|validation", authed["content"][0]["text"], re.I)
    assert vault_reads == [] and seams.tcp == []


# --- per call, not per session ---------------------------------------------------------------

def test_the_gate_is_per_call_in_all_three_directions():
    calls = []

    def server():
        s = amt_server.build_server()

        @s.tool(name="ping", annotations={"title": "Ping", "readOnlyHint": True})
        def ping() -> dict:
            """Fixture tool."""
            calls.append(1)
            return {"pong": True}

        return s

    with _client(server()) as c:
        assert not _call(c, "ping", {}, TOKEN).get("isError")         # bearer first ...
        assert _refused_at_gate(_call(c, "ping", {}))                  # ... then tokenless refuses
    with _client(server()) as c:
        assert _refused_at_gate(_call(c, "ping", {}))                  # anonymous first ...
        assert not _call(c, "ping", {}, TOKEN).get("isError")         # ... then the bearer passes
    with _client(server()) as c:
        assert _refused_at_gate(_call(c, "ping", {}))                  # fully anonymous
        assert _refused_at_gate(_call(c, "ping", {}))
    assert calls == [1, 1]


# --- hashed bearer ---------------------------------------------------------------------------

def test_the_bearer_is_hashed_and_compared_in_constant_time(monkeypatch):
    seen = []
    real = amt_gate.hmac.compare_digest

    def tripwire(a, b):
        seen.append((a, b))
        return real(a, b)

    monkeypatch.setattr(amt_gate.hmac, "compare_digest", tripwire)
    with _client(amt_server.build_server()) as c:
        _call(c, "nothing", {}, TOKEN)
    assert seen == [(TOKEN_HASH, TOKEN_HASH)], "the gate must compare SHA-256 digests via compare_digest"


@pytest.mark.parametrize("var", [amt_gate.HASH_ENV, "MCP_ADMIN_TOKEN"])
def test_a_raw_token_in_the_environment_is_never_accepted(monkeypatch, var):
    monkeypatch.delenv(amt_gate.HASH_ENV, raising=False)
    monkeypatch.setenv(var, TOKEN)                 # the plaintext token, not its hash
    calls = []
    server = amt_server.build_server()

    @server.tool(name="ping", annotations={"title": "Ping", "readOnlyHint": True})
    def ping() -> dict:
        """Fixture tool."""
        calls.append(1)
        return {"pong": True}

    with _client(server) as c:
        assert _refused_at_gate(_call(c, "ping", {}, TOKEN))
    assert calls == []


# --- vault miss fails closed -----------------------------------------------------------------

@pytest.mark.parametrize("name,args", CREDENTIAL_CALLS, ids=[f"{n}-{i}" for i, (n, _) in enumerate(CREDENTIAL_CALLS)])
def test_a_vault_miss_refuses_every_device_call_with_nothing_opened(seams, monkeypatch, tmp_path, name, args):
    monkeypatch.setattr(amt_vault, "SECRETS", tmp_path / "absent-secrets.py")
    import amt_mirror, amt_serial   # noqa: E401  - stopped below if a start half-succeeded
    with _client() as c:
        result = _call(c, name, args, TOKEN)
    for key in list(amt_mirror._MIRRORS):
        amt_mirror.stop(key)
    for key in list(amt_serial._TERMS):
        amt_serial.stop(key)
    assert result.get("isError") is True, f"{name} did not fail on a vault miss: {result}"
    assert "vault_miss" in result["content"][0]["text"]
    assert seams.tcp == [] and seams.urls == [], f"{name} opened a connection without a credential"


# --- host, port and pinned versions ----------------------------------------------------------

def test_host_and_port_come_from_code_not_fastmcp_env(monkeypatch):
    captured = {}

    class FakeServer:
        def __init__(self, config):
            captured.update(host=config.host, port=config.port)

        def run(self):
            pass

    import uvicorn
    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    monkeypatch.setenv("FASTMCP_HOST", "0.0.0.0")
    monkeypatch.setenv("FASTMCP_PORT", "9999")
    monkeypatch.delenv("AMT_BIND_HOST", raising=False)
    monkeypatch.delenv("AMT_PORT", raising=False)
    assert amt_server.main(["--transport", "http"]) == 0
    assert captured == {"host": amt_server.DEFAULT_BIND_HOST, "port": amt_server.DEFAULT_PORT}

    monkeypatch.setenv("AMT_BIND_HOST", "10.0.0.5")
    monkeypatch.setenv("AMT_PORT", "18765")
    assert amt_server.main(["--transport", "http"]) == 0
    assert captured == {"host": "10.0.0.5", "port": 18765}


def test_the_dockerfile_pins_the_base_image_and_every_pip_package():
    text = (ROOT / "Dockerfile").read_text()
    assert re.search(r"^FROM python:\d+\.\d+\.\d+-", text, re.M), "base image must carry an exact version tag"
    args = dict(re.findall(r"^ARG (\w+)=(\S+)$", text, re.M))
    code = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    installs = re.findall(r"pip install[^\n]*", code)
    assert installs, "no pip install found: the scan would be vacuous"
    for line in installs:
        specs = re.findall(r'"([^"]+)"', line)
        assert specs, f"unquoted pip install: {line}"
        for spec in specs:
            m = re.fullmatch(r"[A-Za-z0-9_.-]+==\$\{(\w+)\}", spec)
            assert m and re.fullmatch(r"\d+(\.\d+)+", args.get(m.group(1), "")), f"unpinned: {spec}"


def test_the_dockerfile_copies_every_server_module():
    """The image runs amt_server.py and imports its amt_* siblings at start: a module left out of the COPY line is a container that
    restarts forever on ModuleNotFoundError (amt_captures.py, the 2026-10-21 console deploy). The COPY list must be every amt_*.py."""
    text = (ROOT / "Dockerfile").read_text()
    copied = set(re.findall(r"\b(amt_\w+)\.py\b", " ".join(re.findall(r"^COPY (.*) \./$", text, re.M))))
    modules = {p.stem for p in ROOT.glob("amt_*.py")}
    assert modules, "no amt_*.py found: the check would be vacuous"
    assert copied == modules, f"missing from the image: {sorted(modules - copied)}; copied but absent: {sorted(copied - modules)}"


def test_the_package_ships_every_server_module_and_the_vendored_xterm():
    """`pip install .` must give a server that starts: py-modules is every amt_*.py (amt_server imports them all at start),
    and the serial page's vendored xterm.js ships beside them (amt_serial serves <module dir>/vendor/xterm)."""
    import tomllib
    st = tomllib.loads((ROOT / "pyproject.toml").read_text())["tool"]["setuptools"]
    modules = {p.stem for p in ROOT.glob("amt_*.py")}
    assert modules, "no amt_*.py found: the check would be vacuous"
    assert set(st["py-modules"]) == modules, f"missing: {sorted(modules - set(st['py-modules']))}"
    assert st["packages"] == ["vendor.xterm"]
    patterns = st["package-data"]["vendor.xterm"]
    shipped = {p.name for p in (ROOT / "vendor" / "xterm").iterdir() if any(p.match(g) for g in patterns)}
    assert {"xterm.js", "xterm.css", "addon-fit.js", "LICENSE.xterm", "LICENSE.addon-fit"} <= shipped
