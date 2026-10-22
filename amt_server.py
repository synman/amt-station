#!/usr/bin/env python3
"""amt-mcp - Intel AMT / MeshCommander-parity MCP server (streamable HTTP, bearer-gated).

Registers 23 tools: nine READ tools (status, screenshot, inventory, logs, settings, wsman_get from
``amt_tools``; devices from ``amt_fleet``; identities from ``amt_identity``; captures from
``amt_captures``) and fourteen WRITE tools (power, set_next_boot, console_input, sol, ider, images,
configure, wsman_invoke from ``amt_write``; remote_logon / remote_logoff from ``amt_tools``;
device_manage, identity_manage; the viewers mirror_link and serial_link). ``build_server`` returns a
bare gated server; ``register_tools`` adds the tools, so tests can build either. What the
server provides:

* streamable-HTTP FastMCP, ``stateless_http=True``;
* the fleet admin-token bearer gate (``amt_gate``) as a per-call dispatch wrapper;
* refusals are MCP tool errors, never HTTP 401/403.

Configuration (all environment, none secret):
    MCP_ADMIN_TOKEN_HASH  SHA-256 hex of the fleet ``mcp-admin-token``. Required over HTTP.
    MCP_CONSOLE_TOKEN_HASH  Optional SHA-256 hex of the management console's own bearer; unset or
                          malformed means only the fleet bearer works.
    AMT_TRANSPORT         ``http`` (default) or ``stdio``; set by ``main`` from --transport.
    AMT_BIND_HOST         bind address, default 127.0.0.1.
    AMT_PORT              bind port, default 8765.
    AMT_ALLOWED_HOSTS     comma-separated extra Host names accepted behind an ingress.
    AMT_PUBLIC_BASE_URL   scheme://host[:port] clients reach the server at; turns on one-time
                          download urls for files tools write (``amt_handoff``).
"""
from __future__ import annotations

import argparse
import os
import sys

from mcp.server.transport_security import TransportSecuritySettings

import amt_captures
import amt_fleet
import amt_handoff
import amt_identity
import amt_upload
import amt_mirror
import amt_serial
import amt_tools
import amt_write
from amt_gate import (
    HASH_ENV,
    TRANSPORT_ENV,
    BearerContextMiddleware,
    GatedFastMCP,
    configure_call_log,
    configured_hash,
    is_stdio_transport,
)

DEFAULT_BIND_HOST = "127.0.0.1"
DEFAULT_PORT = 8765

INSTRUCTIONS = (
    "Intel AMT remote management for registered hosts, direct over AMT TLS with no "
    "MeshCommander. Over HTTP every call needs the fleet mcp-admin-token bearer; a call "
    "without it is refused as a tool error and nothing runs. A local stdio run needs no "
    "bearer: the process boundary is the control. Read tools: amt_status, amt_screenshot, "
    "amt_inventory, amt_logs, amt_settings, amt_wsman_get, amt_devices (the managed servers and their TLS pins) and amt_identities (their vault entries, by name and status only) and amt_captures (screenshots and finished recordings, each fetchable as a one-time url). Every host tool takes an optional device (default " + amt_tools.DEFAULT_DEVICE + "). Write tools, each needing "
    "confirmed=true (false sends nothing): amt_power (default restart is graceful), "
    "amt_set_next_boot, amt_console_input, amt_sol, amt_ider (mount), amt_images (image folder), amt_configure, amt_wsman_invoke, "
    "amt_remote_logon and amt_remote_logoff. amt_identity_manage mints a one-time url for a vault value or removes an entry. amt_mirror_link serves a live view of the console "
    "for the operator to watch (and record) while the agent works; while it runs, the console "
    "tools share its KVM session. amt_serial_link does the same for the Serial-over-LAN "
    "console (an xterm page the operator watches or types into; amt_sol shares its session). "
    "AMT allows one KVM session per host; an IDE-R mount runs "
    "alongside KVM (verified live). Credentials are read from the vault "
    "in-process and are never a tool argument or a returned value."
)


def build_server() -> GatedFastMCP:
    """Construct a fresh gated, stateless FastMCP with no tools registered."""
    return GatedFastMCP("amt-mcp", instructions=INSTRUCTIONS, stateless_http=True)


def register_tools(server: GatedFastMCP) -> GatedFastMCP:
    """Register the nine read tools (read-only, titled, no ``confirmed``) and the fourteen
    write tools (eight in ``amt_write``, the two composite logon tools, the two viewers and the two
    management tools; ``readOnlyHint`` False, each with a ``confirmed`` guard) on ``server``. Being on ``GatedFastMCP`` they are bearer-gated
    automatically."""
    for fn, name, title in (*amt_tools.TOOL_SPECS, *amt_fleet.READ_TOOL_SPECS,
                            *amt_identity.READ_TOOL_SPECS, *amt_captures.READ_TOOL_SPECS):
        server.tool(
            name=name,
            annotations={"title": title, "readOnlyHint": True, "destructiveHint": False,
                         "idempotentHint": True, "openWorldHint": True,
                         **amt_tools.TOOL_ANNOTATION_OVERRIDES.get(name, {})},
        )(fn)
    for fn, name, title, hints in (*amt_tools.COMPOSITE_TOOL_SPECS, *amt_write.WRITE_TOOL_SPECS,
                                   *amt_mirror.MIRROR_TOOL_SPECS, *amt_serial.SERIAL_TOOL_SPECS,
                                   *amt_fleet.WRITE_TOOL_SPECS, *amt_identity.WRITE_TOOL_SPECS):
        server.tool(
            name=name,
            annotations={"title": title, "readOnlyHint": False, "idempotentHint": False,
                         "openWorldHint": True, **hints},
        )(fn)
    amt_handoff.register(server)
    amt_upload.register(server)
    return server


mcp = register_tools(build_server())


def _allowed_hosts(extra: str) -> tuple[list[str], list[str]]:
    hosts = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
    origins = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]
    for name in (h.strip() for h in extra.split(",")):
        if not name:
            continue
        # A `host:*` wildcard does not match a portless forwarded Host: list both.
        hosts += [name, f"{name}:*"]
        origins += [f"http://{name}", f"http://{name}:*", f"https://{name}", f"https://{name}:*"]
    return hosts, origins


def build_http_app(server: GatedFastMCP, extra_hosts: str = ""):
    """Return the ASGI app: the bearer-recording middleware around streamable_http_app().

    Transport security must be set before streamable_http_app() bakes it in. DNS-rebinding
    protection stays on; the default allowlist is loopback only.
    """
    # Fail closed: refuse to build the HTTP app while the env marks stdio, so a
    # stray AMT_TRANSPORT=stdio (compose, leftover shell) can never serve the
    # HTTP mount ungated. main() sets AMT_TRANSPORT=http on the http path.
    if is_stdio_transport():
        raise RuntimeError(
            f"refusing to build the HTTP app while {TRANSPORT_ENV}=stdio; "
            "the stdio skip would leave the mount ungated (fail closed)"
        )
    hosts, origins = _allowed_hosts(extra_hosts)
    server.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True, allowed_hosts=hosts, allowed_origins=origins
    )
    return BearerContextMiddleware(server.streamable_http_app())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="amt-mcp")
    parser.add_argument("--transport", choices=("http", "stdio"), default="http")
    args = parser.parse_args(argv)

    os.environ[TRANSPORT_ENV] = args.transport
    # stderr only: stdout is the stdio MCP channel. Every transport logs its calls.
    configure_call_log()
    if args.transport == "stdio":
        mcp.run(transport="stdio")
        return 0

    if configured_hash() is None:
        print(
            f"amt-mcp: refusing to start the HTTP mount: {HASH_ENV} is unset or is not a "
            "64-character SHA-256 hex digest (fail closed)",
            file=sys.stderr,
        )
        return 2

    import uvicorn

    # Set host/port in code after construction: FastMCP.__init__ sets them explicitly and
    # would shadow FASTMCP_* environment values.
    mcp.settings.host = os.environ.get("AMT_BIND_HOST", DEFAULT_BIND_HOST)
    mcp.settings.port = int(os.environ.get("AMT_PORT", DEFAULT_PORT))
    app = build_http_app(mcp, os.environ.get("AMT_ALLOWED_HOSTS", ""))
    uvicorn.Server(
        uvicorn.Config(app, host=mcp.settings.host, port=mcp.settings.port, log_level="info")
    ).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
