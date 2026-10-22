"""The console's MCP client: every action is a ``tools/call`` to amt-mcp's ``/mcp`` with the console bearer.

The bearer is read in-process from the console's OWN vault (``AMT_CONSOLE_SECRETS_CLI`` names the
node-vault-mcp ``secrets.py``; ``NVAULT_*`` in the environment select the vault file), entry
``amt-console-token``. It is held in this process's memory only: never in env, argv, a log line, an
exception, a response or a file. There is deliberately no default CLI path, so an unconfigured console
fails closed instead of reaching for the operator's main vault.

The rules the design fixes for every call are enforced here, before anything is sent: the tool must be
a known one, a tool whose ``device`` matters names it explicitly (the server's default is never relied
on), and a write carries the JSON boolean ``confirmed: true`` unless its action needs none.
"""
from __future__ import annotations

import http.client
import json
import os
import subprocess
import sys
import threading
import urllib.parse

TOKEN_ENTRY = "amt-console-token"
TIMEOUT_SECONDS = 15

# name -> (needs an explicit device, read-only). Cross-checked against the live amt-mcp tool schemas by
# console/tests/test_console_mcp_client.py, so a tool added or changed there fails here until this follows.
TOOLS: dict[str, tuple[bool, bool]] = {
    "amt_status": (True, True), "amt_screenshot": (True, True), "amt_inventory": (True, True),
    "amt_logs": (True, True), "amt_settings": (True, True), "amt_wsman_get": (True, True),
    "amt_devices": (False, True), "amt_identities": (False, True), "amt_captures": (False, True),
    "amt_remote_logon": (True, False), "amt_remote_logoff": (True, False), "amt_power": (True, False),
    "amt_set_next_boot": (True, False), "amt_console_input": (True, False), "amt_sol": (True, False),
    "amt_ider": (True, False), "amt_images": (False, False), "amt_configure": (True, False),
    "amt_wsman_invoke": (True, False), "amt_mirror_link": (True, False), "amt_serial_link": (True, False),
    "amt_device_manage": (True, False), "amt_identity_manage": (False, False),
}
# Write tools whose listed actions need no ``confirmed`` (they read or release only).
UNCONFIRMED_ACTIONS = {"amt_mirror_link": {"stop", "status", "record_stop"},
                       "amt_serial_link": {"stop", "status", "record_stop"},
                       "amt_ider": {"status"}, "amt_images": {"list", "verify"}}


class McpError(Exception):
    """The call was not made, or amt-mcp could not be reached. The message never carries a value."""


class VaultError(McpError):
    """The bearer could not be read. Names the entry only."""


def validate_call(tool: object, arguments: object) -> dict:
    """The design's per-call rules (immutable 6). Returns the arguments; raises McpError naming the rule."""
    if not isinstance(tool, str) or tool not in TOOLS:
        raise McpError("unknown_tool")
    if not isinstance(arguments, dict):
        raise McpError("arguments_not_an_object")
    needs_device, read_only = TOOLS[tool]
    if needs_device and (not isinstance(arguments.get("device"), str) or not arguments["device"].strip()):
        raise McpError("device_not_named")
    if not read_only:
        action = arguments.get("action")
        unconfirmed = isinstance(action, str) and action in UNCONFIRMED_ACTIONS.get(tool, ())   # a list is unhashable
        if arguments.get("confirmed") is not True and not unconfirmed:
            raise McpError("confirmed_not_true")
    return arguments


class Vault:
    """Reads the console bearer through the vault CLI as a child process (a vault fault is an error here, never
    a SystemExit in this process)."""

    def __init__(self, cli: str | None):
        self.cli = cli

    def bearer(self) -> str:
        if not self.cli:
            raise VaultError(f"vault_unconfigured:{TOKEN_ENTRY}")
        try:
            out = subprocess.run([sys.executable, self.cli, "get", TOKEN_ENTRY], capture_output=True, text=True,
                                 stdin=subprocess.DEVNULL, timeout=TIMEOUT_SECONDS)
        except UnicodeDecodeError:
            raise VaultError(f"vault_decode_error:{TOKEN_ENTRY}") from None
        except (OSError, subprocess.SubprocessError) as ex:
            raise VaultError(f"vault_unavailable:{TOKEN_ENTRY}:{type(ex).__name__}") from None
        value = out.stdout.rstrip("\n")
        if out.returncode != 0:
            raise VaultError(f"vault_miss:{TOKEN_ENTRY}")
        if not value:
            raise VaultError(f"vault_empty:{TOKEN_ENTRY}")
        return value


def http_request(url: str, method: str, headers: dict, body: bytes | None, timeout: float) -> http.client.HTTPResponse:
    """One request, no redirects (a redirect would carry the bearer elsewhere). The caller reads and closes."""
    parts = urllib.parse.urlsplit(url)
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise McpError("bad_url")
    cls = http.client.HTTPSConnection if parts.scheme == "https" else http.client.HTTPConnection
    conn = cls(parts.hostname, parts.port, timeout=timeout)
    target = parts.path or "/"
    try:
        conn.request(method, target + (f"?{parts.query}" if parts.query else ""), body=body, headers=headers)
        sock = conn.sock                                      # a response that ends with the connection takes it over: keep the socket
        resp = conn.getresponse()
    except (OSError, http.client.HTTPException) as ex:
        conn.close()
        raise McpError(f"amt_mcp_unreachable:{type(ex).__name__}") from None
    resp._conn, resp._sock = conn, sock                        # kept so close_response can release the socket (and a relay can cut it)
    return resp


def close_response(resp: http.client.HTTPResponse) -> None:
    resp.close()
    conn = getattr(resp, "_conn", None)
    if conn is not None:
        conn.close()


def _rpc_message(body: str, content_type: str, rid: int) -> dict:
    """The JSON-RPC message with id ``rid`` from a JSON body or a text/event-stream body."""
    candidates = []
    if content_type.startswith("text/event-stream"):
        candidates = [line[5:].strip() for line in body.splitlines() if line.startswith("data:")]
    else:
        candidates = [body]
    for text in candidates:
        try:
            msg = json.loads(text)
        except ValueError:
            continue
        if isinstance(msg, dict) and msg.get("id") == rid:
            return msg
    raise McpError("amt_mcp_bad_response")


def _json_value(text: str):
    """A result's text as the object or list it holds. amt-mcp's tools declare no output schema, so the server sends its dict as JSON text only and
    no ``structuredContent``; this is where it becomes the structured value every caller reads. Text that is not JSON (an error) is None."""
    try:
        value = json.loads(text)
    except ValueError:
        return None
    return value if isinstance(value, (dict, list)) else None


class Result:
    """A tool result: ``is_error``, the joined ``text`` and the ``structured`` content (a dict) when sent."""

    def __init__(self, is_error: bool, text: str, structured):
        self.is_error, self.text, self.structured = is_error, text, structured


class Client:
    def __init__(self, url: str, vault: Vault, timeout: float = 60.0):
        self.url, self.vault, self.timeout = url, vault, timeout
        self._bearer: str | None = None
        self._lock = threading.Lock()
        self._rid = 0

    def _token(self) -> str:
        with self._lock:
            if self._bearer is None:
                self._bearer = self.vault.bearer()
            return self._bearer

    def _forget_token(self) -> None:
        with self._lock:
            self._bearer = None

    def call(self, tool: str, arguments: dict) -> Result:
        arguments = validate_call(tool, arguments)
        with self._lock:
            self._rid += 1
            rid = self._rid
        payload = json.dumps({"jsonrpc": "2.0", "id": rid, "method": "tools/call",
                              "params": {"name": tool, "arguments": arguments}}).encode()
        headers = {"Authorization": f"Bearer {self._token()}", "Accept": "application/json, text/event-stream",
                   "Content-Type": "application/json"}
        resp = http_request(self.url, "POST", headers, payload, self.timeout)
        try:
            status, ctype, raw = resp.status, resp.getheader("Content-Type", ""), resp.read(64 * 1024 * 1024)
        except (OSError, http.client.HTTPException) as ex:
            raise McpError(f"amt_mcp_unreachable:{type(ex).__name__}") from None
        finally:
            close_response(resp)
        if status != 200:
            raise McpError(f"amt_mcp_http_{status}")
        try:
            msg = _rpc_message(raw.decode("utf-8"), ctype, rid)
        except UnicodeDecodeError:
            raise McpError("amt_mcp_bad_response") from None
        if "error" in msg:
            err = msg["error"] if isinstance(msg["error"], dict) else {}
            raise McpError(f"amt_mcp_rpc_error:{err.get('code')}")
        result = msg.get("result")
        if not isinstance(result, dict):
            raise McpError("amt_mcp_bad_response")
        text = "\n".join(c.get("text", "") for c in result.get("content", []) if isinstance(c, dict)
                         and c.get("type") == "text")
        is_error = result.get("isError") is True
        if is_error and "bearer" in text:                     # the gate refused the token: re-read the vault next call
            self._forget_token()
        structured = result.get("structuredContent")
        if not isinstance(structured, (dict, list)):
            structured = _json_value(text)
        return Result(is_error, text, structured)


def from_env(env=os.environ) -> Client:
    url = env.get("AMT_CONSOLE_MCP_URL", "https://amt.example.com/mcp")
    return Client(url, Vault(env.get("AMT_CONSOLE_SECRETS_CLI") or None),
                  float(env.get("AMT_CONSOLE_MCP_TIMEOUT", "60")))
