"""deploy/verify_endpoint.py: its pinned facts match the server, and its checks run end to end offline."""
from __future__ import annotations

import asyncio
import importlib.util
import json
from pathlib import Path

import pytest
from starlette.testclient import TestClient

import amt_gate
import amt_server as server

SCRIPT = Path(__file__).resolve().parent.parent / "deploy" / "verify_endpoint.py"


@pytest.fixture(scope="module")
def verify():
    spec = importlib.util.spec_from_file_location("verify_endpoint", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_pinned_facts_match_the_server(verify):
    tools = {tool.name for tool in asyncio.run(server.mcp.list_tools())}
    assert verify.EXPECTED_TOOLS == len(tools)
    assert verify.GATED_TOOL in tools
    assert verify.source_version() == server.__version__
    assert verify.APP_NAME == "amt-mcp"
    assert verify.REFUSAL in amt_gate._REFUSAL


def _offline(verify, monkeypatch, client):
    def request(url, body=None):
        if body is None:
            response = client.get("/mcp")
        else:
            response = client.post("/mcp", headers=verify.JSON_HEADERS, json=body)
        return response.status_code, response.text

    monkeypatch.setattr(verify, "request", request)


def test_every_check_passes_against_the_in_process_app(verify, monkeypatch):
    monkeypatch.setenv("AMT_TRANSPORT", "http")
    monkeypatch.setenv("AMT_BEARER_SHA256", "a" * 64)
    app = server.build_http_app(server.register_tools(server.build_server()))
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        _offline(verify, monkeypatch, client)
        results = verify.checks("offline")
    assert [name for name, _, _ in results] == ["bare GET", "serverInfo", "tools/list", "tokenless call refused"]
    assert all(ok for _, ok, detail in results), results


def test_a_wrong_expected_count_fails_that_check_alone(verify, monkeypatch):
    monkeypatch.setenv("AMT_TRANSPORT", "http")
    monkeypatch.setenv("AMT_BEARER_SHA256", "a" * 64)
    monkeypatch.setattr(verify, "EXPECTED_TOOLS", verify.EXPECTED_TOOLS + 1)
    app = server.build_http_app(server.register_tools(server.build_server()))
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        _offline(verify, monkeypatch, client)
        results = verify.checks("offline")
    assert {name: ok for name, ok, _ in results} == {
        "bare GET": True, "serverInfo": True, "tools/list": False, "tokenless call refused": True}


def test_an_ungated_server_fails_the_refusal_check(verify, monkeypatch):
    def request(url, body=None):
        if body is None:
            return 406, ""
        method = body["method"]
        result = {"initialize": {"serverInfo": {"name": verify.APP_NAME, "version": verify.source_version()}},
                  "tools/list": {"tools": [{}] * verify.EXPECTED_TOOLS},
                  "tools/call": {"isError": False, "content": [{"type": "text", "text": "{}"}]}}[method]
        return 200, json.dumps({"jsonrpc": "2.0", "id": body["id"], "result": result})

    monkeypatch.setattr(verify, "request", request)
    results = verify.checks("offline")
    assert {name: ok for name, ok, _ in results}["tokenless call refused"] is False
