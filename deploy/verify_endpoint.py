#!/usr/bin/env python3
"""Tokenless liveness check for a deployed amt-mcp mount. Exit 0 only if every check passes.

Four checks, none needs the bearer and none writes:
  1. A bare GET with no Accept header answers 406. That is the live streamable-HTTP signal.
     404 means the route is absent, 421 a Host-guard mismatch, anything else a broken mount.
  2. initialize reports this repo's own name and ``__version__`` (read from the source file).
  3. tools/list returns EXPECTED_TOOLS tools. A live proxy over a dead backend fails here.
  4. A tokenless tools/call of a gated tool is refused with the gate's own message. tools/list
     cannot prove the gate is live, because listing is open by design. The call dies at the gate,
     before the tool body, so it writes nothing.

Usage: verify_endpoint.py [URL]   (default: the public LAN mount, or http://127.0.0.1:8765/mcp on the NAS)
"""
from __future__ import annotations

import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

DEFAULT_URL = "https://amt.example.net/mcp"
APP_NAME = "amt-mcp"
EXPECTED_TOOLS = 23
GATED_TOOL = "amt_status"
REFUSAL = "requires the admin bearer token header"
VERSION_FILE = Path(__file__).resolve().parent.parent / "amt_server.py"
JSON_HEADERS = {"Content-Type": "application/json", "Accept": "application/json, text/event-stream"}
TIMEOUT = 20


def source_version() -> str:
    """The version of record, read from the source text so the script needs no dependency."""
    found = re.search(r'^__version__\s*=\s*"([^"]+)"', VERSION_FILE.read_text(), re.MULTILINE)
    if not found:
        raise SystemExit(f"no __version__ in {VERSION_FILE}")
    return found.group(1)


def request(url: str, body: dict | None = None) -> tuple[int, str]:
    headers = {} if body is None else JSON_HEADERS
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, headers=headers, method="GET" if body is None else "POST")
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as response:
            return response.status, response.read().decode()
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode()


def rpc_result(text: str) -> dict:
    """The JSON-RPC message from a JSON or event-stream body."""
    data = next((line[6:] for line in text.splitlines() if line.startswith("data: ")), text)
    return json.loads(data)


def rpc(url: str, method: str, params: dict, rid: int) -> dict:
    status, text = request(url, {"jsonrpc": "2.0", "id": rid, "method": method, "params": params})
    if status != 200:
        raise RuntimeError(f"{method} answered HTTP {status}")
    return rpc_result(text)["result"]


def checks(url: str) -> list[tuple[str, bool, str]]:
    results: list[tuple[str, bool, str]] = []
    status, _ = request(url)
    results.append(("bare GET", status == 406, f"HTTP {status}, want 406"))
    info = rpc(url, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {},
                                   "clientInfo": {"name": "verify", "version": "0"}}, 1)["serverInfo"]
    want = {"name": APP_NAME, "version": source_version()}
    results.append(("serverInfo", info == want, f"{info}, want {want}"))
    tools = rpc(url, "tools/list", {}, 2)["tools"]
    results.append(("tools/list", len(tools) == EXPECTED_TOOLS, f"{len(tools)} tools, want {EXPECTED_TOOLS}"))
    call = rpc(url, "tools/call", {"name": GATED_TOOL, "arguments": {}}, 3)
    text = " ".join(part.get("text", "") for part in call.get("content", []))
    results.append(("tokenless call refused", bool(call.get("isError")) and REFUSAL in text,
                    f"isError={call.get('isError')}, refusal text {'found' if REFUSAL in text else 'missing'}"))
    return results


def main(argv: list[str]) -> int:
    url = argv[1] if len(argv) > 1 else DEFAULT_URL
    try:
        results = checks(url)
    except (RuntimeError, OSError, ValueError, KeyError) as exc:
        print(f"FAIL {url} {type(exc).__name__}: {exc}")
        return 1
    for name, ok, detail in results:
        print(f"{'ok  ' if ok else 'FAIL'} {name}: {detail}")
    return 0 if all(ok for _, ok, _ in results) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
