"""The management console's own bearer (``MCP_CONSOLE_TOKEN_HASH``) and principal tagging.

The gate accepts the fleet bearer and, when configured, a second one for the console. Either runs
a call; each call that passed the gate is logged with its principal name, never a token or a hash.
Every token here is a throwaway string; only SHA-256 digests are placed in the environment.
"""
import asyncio
import hashlib
import logging
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import amt_gate  # noqa: E402
import amt_server  # noqa: E402
from test_skeleton import TOKEN, TOKEN_HASH, _call, _client, _server_with_ping  # noqa: E402

CONSOLE_TOKEN = "console-test-token-not-a-secret"
CONSOLE_HASH = hashlib.sha256(CONSOLE_TOKEN.encode()).hexdigest()
OTHER_TOKEN = "some-other-token-not-a-secret"
LOGGER = "amt_mcp.calls"


@pytest.fixture(autouse=True)
def _env(monkeypatch, caplog):
    monkeypatch.setenv(amt_gate.HASH_ENV, TOKEN_HASH)
    monkeypatch.setenv(amt_gate.CONSOLE_HASH_ENV, CONSOLE_HASH)
    monkeypatch.delenv(amt_gate.TRANSPORT_ENV, raising=False)
    caplog.set_level(logging.INFO, logger=LOGGER)
    yield
    for handler in list(amt_gate.call_log.handlers):
        amt_gate.call_log.removeHandler(handler)


def _refused(res):
    return res["isError"] is True and "mcp-admin-token" in res["content"][0]["text"]


def _records(caplog):
    return [r.getMessage() for r in caplog.records if r.name == LOGGER]


def test_console_bearer_is_accepted_and_the_tool_runs():
    calls = []
    with _client(_server_with_ping(calls)) as c:
        res = _call(c, "ping", CONSOLE_TOKEN)
    assert not res.get("isError")
    assert calls == [1], "tripwire: the console branch let the console token through"


def test_wrong_console_bearer_is_refused_and_nothing_runs():
    calls = []
    with _client(_server_with_ping(calls)) as c:
        assert _refused(_call(c, "ping", OTHER_TOKEN))
        # One character off the real console token must not pass: full-width compare.
        assert _refused(_call(c, "ping", CONSOLE_TOKEN + "x"))
    assert calls == []


def test_fleet_bearer_still_accepted_with_a_console_hash_configured():
    calls = []
    with _client(_server_with_ping(calls)) as c:
        res = _call(c, "ping", TOKEN)
    assert not res.get("isError")
    assert calls == [1]


@pytest.mark.parametrize("bad", [None, "", "not-hex", "abc123", "Z" * 64])
def test_unset_or_malformed_console_hash_refuses_a_console_token(monkeypatch, bad):
    if bad is None:
        monkeypatch.delenv(amt_gate.CONSOLE_HASH_ENV, raising=False)
    else:
        monkeypatch.setenv(amt_gate.CONSOLE_HASH_ENV, bad)
    calls = []
    with _client(_server_with_ping(calls)) as c:
        assert _refused(_call(c, "ping", CONSOLE_TOKEN))
        assert calls == []
        # The fleet bearer is unchanged by the console hash being absent.
        assert not _call(c, "ping", TOKEN).get("isError")
    assert calls == [1]


def test_an_unresolvable_fleet_hash_refuses_the_console_token_too(monkeypatch):
    monkeypatch.delenv(amt_gate.HASH_ENV, raising=False)
    calls = []
    with _client(_server_with_ping(calls)) as c:
        assert _refused(_call(c, "ping", CONSOLE_TOKEN))
    assert calls == []


def test_each_call_is_logged_with_its_principal_and_no_token_or_hash(caplog):
    with _client(_server_with_ping([])) as c:
        _call(c, "ping", CONSOLE_TOKEN)
        _call(c, "ping", TOKEN)
        _call(c, "ping", OTHER_TOKEN)           # refused: no principal, no record
        _call(c, "ping", CONSOLE_TOKEN)
    assert _records(caplog) == [
        "tool=ping principal=console",
        "tool=ping principal=fleet",
        "tool=ping principal=console",
    ]
    everything = " ".join(f"{r.getMessage()} {r.args} {r.exc_text}" for r in caplog.records)
    for secret in (TOKEN, TOKEN_HASH, CONSOLE_TOKEN, CONSOLE_HASH, OTHER_TOKEN):
        assert secret not in everything


def test_the_principal_does_not_outlive_its_request():
    seen = []

    async def inner(scope, receive, send):
        seen.append(amt_gate._principal.get())

    async def drive():
        mw = amt_gate.BearerContextMiddleware(inner)
        await mw({"type": "http", "headers": [(b"authorization", b"Bearer " + CONSOLE_TOKEN.encode())]}, None, None)
        after = amt_gate._principal.get()
        await mw({"type": "http", "headers": []}, None, None)
        return after

    assert asyncio.run(drive()) is None, "the principal stayed set after the request ended"
    assert seen == ["console", None], "an anonymous request inherited the previous principal"


def test_both_configured_hashes_are_compared_in_full_whichever_matches(monkeypatch):
    seen = []
    real = amt_gate.hmac.compare_digest

    def tripwire(a, b):
        seen.append(b)
        return real(a, b)

    monkeypatch.setattr(amt_gate.hmac, "compare_digest", tripwire)
    assert amt_gate.identify_bearer(TOKEN) == "fleet"
    assert seen == [TOKEN_HASH, CONSOLE_HASH], "a match on the fleet hash must not skip the console compare"
    seen.clear()
    assert amt_gate.identify_bearer(CONSOLE_TOKEN) == "console"
    assert seen == [TOKEN_HASH, CONSOLE_HASH]


def test_equal_hashes_name_the_fleet_principal(monkeypatch):
    monkeypatch.setenv(amt_gate.CONSOLE_HASH_ENV, TOKEN_HASH)
    assert amt_gate.identify_bearer(TOKEN) == "fleet"
    assert amt_gate.identify_bearer(CONSOLE_TOKEN) is None


def test_console_hash_is_case_normalized(monkeypatch):
    monkeypatch.setenv(amt_gate.CONSOLE_HASH_ENV, CONSOLE_HASH.upper())
    assert amt_gate.identify_bearer(CONSOLE_TOKEN) == "console"
    near = CONSOLE_HASH[:-1] + ("0" if CONSOLE_HASH[-1] != "0" else "1")
    monkeypatch.setenv(amt_gate.CONSOLE_HASH_ENV, near)
    assert amt_gate.identify_bearer(CONSOLE_TOKEN) is None


def test_a_stdio_call_is_logged_as_stdio(monkeypatch, caplog):
    monkeypatch.setenv(amt_gate.TRANSPORT_ENV, "stdio")
    asyncio.run(_server_with_ping([]).call_tool("ping", {}))
    assert _records(caplog) == ["tool=ping principal=stdio"]


def test_configure_call_log_writes_the_record_to_stderr_once(capsys):
    amt_gate.configure_call_log()
    amt_gate.configure_call_log()
    assert len(amt_gate.call_log.handlers) == 1
    amt_gate.call_log.info("tool=ping principal=console")
    captured = capsys.readouterr()
    assert "tool=ping principal=console" in captured.err
    assert captured.out == "", "stdout is the stdio MCP channel"


def test_the_http_start_turns_the_call_log_on(monkeypatch):
    import uvicorn

    monkeypatch.setattr(uvicorn.Server, "run", lambda self: None)
    monkeypatch.setattr(amt_server.mcp.settings, "host", "127.0.0.1")
    monkeypatch.setattr(amt_server.mcp.settings, "port", 8765)
    assert amt_gate.call_log.handlers == []
    assert amt_server.main(["--transport", "http"]) == 0
    assert len(amt_gate.call_log.handlers) == 1


@pytest.mark.parametrize("hostile", [
    "nosuch\n2026-10-20 amt_mcp.calls tool=amt_power principal=fleet",
    "nosuch principal=fleet",
    "nosuch\r",
    "x" * 65,
    "",
])
def test_a_hostile_tool_name_cannot_forge_a_log_record(hostile, monkeypatch, caplog):
    monkeypatch.setenv(amt_gate.TRANSPORT_ENV, "stdio")
    with pytest.raises(Exception):
        asyncio.run(_server_with_ping([]).call_tool(hostile, {}))
    assert _records(caplog) == ["tool=<invalid-name> principal=stdio"]


def test_the_stdio_start_turns_the_call_log_on(monkeypatch):
    monkeypatch.setattr(amt_server.mcp, "run", lambda transport: None)
    assert amt_gate.call_log.handlers == []
    assert amt_server.main(["--transport", "stdio"]) == 0
    assert len(amt_gate.call_log.handlers) == 1
