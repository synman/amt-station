"""Fleet admin-token bearer gate for amt-mcp (Wiring B: pure ASGI + contextvar).

Convention: ``mcp-builder/reference/mcp_admin_token_gate.md``.

Invariants implemented here:

1. The HTTP layer rejects nothing. ``BearerContextMiddleware`` only records whether the
   presented bearer verified; every request reaches the MCP session manager unchanged.
2. The gate lives in the tool-dispatch wrapper (``GatedFastMCP.call_tool``), evaluated per
   call. amt-mcp is a FULLY GATED mount: every tool call, reads included, needs the bearer,
   because a read returns the managed host's live screen.
3. Refusal is an MCP tool-error result (``ToolError`` -> ``isError: true``), never an HTTP
   status code.
4. The transport is checked explicitly. Only an explicit ``AMT_TRANSPORT=stdio`` skips the
   check; any other value, or none, is treated as HTTP and gated (fail closed).
5. An unresolvable hash (``MCP_ADMIN_TOKEN_HASH`` unset or malformed) refuses every token.
6. A second principal, the management console, may hold its own bearer, configured the same way
   (``MCP_CONSOLE_TOKEN_HASH``, a SHA-256 hex digest). Either valid bearer runs a call; each call
   is logged with its principal name (``fleet`` or ``console``), never the token or a hash. An
   unset or malformed console hash leaves only the fleet bearer working.

The raw token is never stored, logged or accepted in configuration: only its SHA-256 hash
is configured, and a presented bearer is hashed and compared with ``hmac.compare_digest``.
"""
from __future__ import annotations

import contextvars
import hashlib
import hmac
import logging
import os
import re
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.fastmcp.exceptions import ResourceError, ToolError

HASH_ENV = "MCP_ADMIN_TOKEN_HASH"
CONSOLE_HASH_ENV = "MCP_CONSOLE_TOKEN_HASH"
FLEET, CONSOLE = "fleet", "console"
TRANSPORT_ENV = "AMT_TRANSPORT"
TOKEN_NAME = "mcp-admin-token"

_HEX64 = re.compile(r"[0-9a-f]{64}")

# One record per call that passed the gate: tool name and principal name, nothing else.
call_log = logging.getLogger("amt_mcp.calls")
# The tool name is client-supplied and is logged before FastMCP validates it, so only a
# plain identifier is written; anything else (newline, space, control byte) is replaced,
# so a caller cannot forge a second record or an extra principal field.
_LOGGABLE_NAME = re.compile(r"[A-Za-z0-9_.\-]{1,64}")

# True only for the request currently being served, and only when its bearer verified.
# Default False: a process that never installs the middleware (stdio) fails closed.
_bearer_verified: contextvars.ContextVar[bool] = contextvars.ContextVar(
    "amt_bearer_verified", default=False
)
# Which principal the verified bearer belongs to ("fleet" or "console"); None when unverified.
_principal: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "amt_principal", default=None
)


# The (log-safe) name of the tool call being served, None outside a gated dispatch. A worker
# thread started with asyncio.to_thread inherits it, so code that shares a viewer's session can
# say which tool holds it (``amt_tools.InFlight``) without the call's arguments ever being kept.
_current_tool: contextvars.ContextVar[str | None] = contextvars.ContextVar(
    "amt_current_tool", default=None
)


def current_tool() -> str | None:
    """The name of the gated tool call this code runs under, or None."""
    return _current_tool.get()


def _hash_from_env(name: str) -> str | None:
    value = os.environ.get(name, "").strip().lower()
    return value if _HEX64.fullmatch(value) else None


def configured_hash() -> str | None:
    """Return the configured fleet SHA-256 hex digest, or None when unset or malformed."""
    return _hash_from_env(HASH_ENV)


def configured_console_hash() -> str | None:
    """Return the configured console SHA-256 hex digest, or None when unset or malformed."""
    return _hash_from_env(CONSOLE_HASH_ENV)


def identify_bearer(presented: str | None) -> str | None:
    """Return the principal name ("fleet" or "console") whose configured hash the presented
    bearer hashes to, else None. An unresolvable fleet hash refuses every token, the console's
    included. Each configured hash is compared in full with ``hmac.compare_digest`` and neither
    comparison is skipped once the other matches. If both hashes are equal the token is the
    fleet's, so the principal is "fleet"."""
    fleet = configured_hash()
    if fleet is None or not presented:
        return None
    digest = hashlib.sha256(presented.encode("utf-8")).hexdigest()
    is_fleet = hmac.compare_digest(digest, fleet)
    console = configured_console_hash()
    is_console = console is not None and hmac.compare_digest(digest, console)
    return FLEET if is_fleet else CONSOLE if is_console else None


def verify_bearer(presented: str | None) -> bool:
    """True only when the presented bearer belongs to a configured principal."""
    return identify_bearer(presented) is not None


def configure_call_log() -> None:
    """Send the per-call record to stderr (stdout is the stdio MCP channel). Idempotent."""
    if not call_log.handlers:
        handler = logging.StreamHandler(sys.stderr)
        handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(message)s"))
        call_log.addHandler(handler)
    call_log.setLevel(logging.INFO)


def is_stdio_transport() -> bool:
    """Explicit stdio only. Unset or unknown is HTTP, so the gate applies."""
    return os.environ.get(TRANSPORT_ENV, "").strip().lower() == "stdio"


def _bearer_from_scope(scope: dict) -> str | None:
    for key, value in scope.get("headers", []):
        if key.lower() == b"authorization":
            scheme, _, token = value.decode("latin-1").partition(" ")
            if scheme.lower() == "bearer" and token.strip():
                return token.strip()
            return None
    return None


class BearerContextMiddleware:
    """Pure ASGI middleware: records the bearer check result, rejects nothing."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        principal = identify_bearer(_bearer_from_scope(scope))
        reset = _bearer_verified.set(principal is not None)
        reset_principal = _principal.set(principal)
        try:
            await self.app(scope, receive, send)
        finally:
            _principal.reset(reset_principal)
            _bearer_verified.reset(reset)


_REFUSAL = (
    f"this call requires the {TOKEN_NAME} bearer header "
    "(Authorization: Bearer <token>); the call was refused and nothing ran"
)


class GatedFastMCP(FastMCP):
    """FastMCP whose every dispatch — tools, resources AND prompts — passes the
    admin-token gate over HTTP. The gate must cover more than ``tools/call``: a
    resource or prompt would otherwise be anonymous, and a screen-capture
    resource would hand out the managed host's live screen with no bearer.
    Custom HTTP routes sit outside dispatch and MUST check ``_bearer_verified``
    themselves, or carry their own key: the download handoff route
    (``amt_handoff``) is keyed by a one-time token minted only into a gated
    tool result."""

    def _require_bearer(self) -> None:
        # Fail closed: stdio is the only ungated transport, and only when set
        # explicitly; the contextvar defaults False so a missing middleware refuses.
        if not is_stdio_transport() and not _bearer_verified.get():
            raise ToolError(_REFUSAL)

    async def call_tool(self, name: str, arguments: dict[str, Any]):
        self._require_bearer()
        logged = name if _LOGGABLE_NAME.fullmatch(name) else "<invalid-name>"
        call_log.info("tool=%s principal=%s", logged, _principal.get() or "stdio")
        reset = _current_tool.set(logged)
        try:
            return await super().call_tool(name, arguments)
        finally:
            _current_tool.reset(reset)

    async def read_resource(self, *args: Any, **kwargs: Any):
        if not is_stdio_transport() and not _bearer_verified.get():
            raise ResourceError(_REFUSAL)
        return await super().read_resource(*args, **kwargs)

    async def get_prompt(self, *args: Any, **kwargs: Any):
        # FastMCP surfaces a ValueError from get_prompt as an error result.
        if not is_stdio_transport() and not _bearer_verified.get():
            raise ValueError(_REFUSAL)
        return await super().get_prompt(*args, **kwargs)
