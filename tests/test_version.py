"""The server's version-of-record: one constant, semver, reported by initialize, equal to pyproject."""
from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from starlette.testclient import TestClient

import amt_server as server

REPO = Path(__file__).resolve().parent.parent
SEMVER = re.compile(r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)")
INITIALIZE = {"jsonrpc": "2.0", "id": 1, "method": "initialize",
              "params": {"protocolVersion": "2025-03-26", "capabilities": {},
                         "clientInfo": {"name": "version-test", "version": "0"}}}
HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}


def test_version_is_a_plain_semver_triple():
    assert SEMVER.fullmatch(server.__version__), server.__version__


def test_pyproject_version_equals_the_server_constant():
    declared = tomllib.loads((REPO / "pyproject.toml").read_text())["project"]["version"]
    assert declared == server.__version__


def test_the_lowlevel_server_carries_the_constant():
    assert server.mcp._mcp_server.version == server.__version__
    options = server.mcp._mcp_server.create_initialization_options()
    assert options.server_version == server.__version__


def test_initialize_over_http_reports_the_constant_not_the_sdk_version(monkeypatch):
    monkeypatch.setenv("AMT_TRANSPORT", "http")
    monkeypatch.setenv("AMT_BEARER_SHA256", "a" * 64)
    app = server.build_http_app(server.register_tools(server.build_server()))
    with TestClient(app, base_url="http://127.0.0.1:8765") as client:
        response = client.post("/mcp", headers=HEADERS, json=INITIALIZE)
    assert response.status_code == 200
    data = next(line[6:] for line in response.text.splitlines() if line.startswith("data: "))
    info = json.loads(data)["result"]["serverInfo"]
    assert info == {"name": "amt-mcp", "version": server.__version__}
