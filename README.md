# amt-station

Intel AMT remote management for AI agents and people: an MCP server that talks directly to each
host's AMT over TLS, and a web console that drives the same tools. amt-station is the two together.

- **amt-mcp** is a Python [MCP](https://modelcontextprotocol.io) server (FastMCP, streamable HTTP,
  bearer-gated). It reaches a host's AMT ports itself (WS-MAN on 16993, KVM and redirection on
  16995): no MeshCommander, no relay, no browser. Its goal is MeshCommander feature parity
  (`amt_parity.py` tracks it).
- **amt-console** (`console/`) is a web UI for the same work. It holds no AMT state of its own:
  every action is an MCP `tools/call` to amt-mcp with the console's own bearer.

## What it does

| Area | Tools |
|------|-------|
| Read the host | `amt_status`, `amt_screenshot`, `amt_inventory`, `amt_logs`, `amt_settings`, `amt_wsman_get` |
| Power and boot | `amt_power` (graceful first, hard actions only by name), `amt_set_next_boot` |
| Screen and keyboard | `amt_console_input`, `amt_mirror_link` (live KVM view an operator can watch or take over) |
| Serial console | `amt_sol`, `amt_serial_link` (live Serial-over-LAN terminal) |
| Boot media | `amt_ider` (mount an ISO over IDE-R), `amt_images` (the image library) |
| Settings | `amt_configure` (six typed areas), `amt_wsman_invoke` (any AMT/CIM/IPS write) |
| Sign in | `amt_remote_logon`, `amt_remote_logoff` (Windows, Linux tty, serial; type only into a screen OCR positively identifies) |
| Fleet | `amt_devices`, `amt_device_manage`, `amt_identities`, `amt_identity_manage`, `amt_captures` |

23 tools in all. Every action that changes something takes `confirmed: true` and sends nothing without it.

## How it stays safe

- **Credentials never pass through a tool.** Passwords are read from a
  [node-vault-mcp](https://github.com/synman/node-vault-mcp) vault inside the server process. No
  secret is a tool argument, a result, a log line or an environment value. The server is
  configured with the SHA-256 of its bearer, never the bearer.
- **Each host is pinned.** AMT ships a self-signed certificate, so the full SHA-256 of each host's
  TLS leaf is recorded and checked on every connection. A host with no pin, or a different leaf,
  is refused.
- **One login attempt per call.** WS-MAN Digest auth is answered once. A second 401 fails the call,
  so a stale password cannot lock the AMT account.
- **Fail closed.** A missing vault, pin, OCR engine or confirmation stops the call with nothing sent.

## Architecture

```
 AI agent ──MCP + fleet bearer──┐
                                ├─► reverse proxy (TLS, LAN) ─► amt-mcp :8765 /mcp ──TLS──► AMT 16993 / 16995
 browser ─► amt-console :8767 ──┘   (console bearer)            viewer pages :8766
            passkeys, CSRF                                        vault (in-process reads)
```

The console never mounts amt-mcp's vault, devices file or image root. The browser never sees a
bearer, a one-time url or a viewer token.

## Documentation

| Guide | For |
|-------|-----|
| [Install amt-mcp](docs/install-mcp.md) | Running the MCP server locally or in Docker, preparing AMT hosts, the reverse proxy, connecting an MCP client |
| [Install amt-console](docs/install-console.md) | Deploying the web console, its bearer, the first passkey |
| [Operator's guide](docs/operators-guide.md) | Day-to-day work: servers, credentials, power, KVM, serial, media, paused servers, updates, incidents |
| [MCP deep dive](docs/mcp-guide.md) | Every tool, the gate, pinning, sessions, viewers, handoffs, errors, testing and extending |
| [Console deep dive](docs/console-guide.md) | The UI's routes, auth, pages, embedded viewers, theme and tests |
| [Agent guidance](CLAUDE.md) | The invariants a coding agent must keep when changing this repo |

Design history: [UX design](docs/ux-design-2026-10-20.md) with the mockups in `design/`, and the
review notes in `docs/`.

## Quick start

Local, for development (no AMT host needed to list tools):

```bash
pip install 'mcp>=1.26,<2' pillow
python3 amt_server.py --transport stdio        # stdio: no bearer check, for a local MCP client
```

Over HTTP the server needs the SHA-256 of its bearer in `MCP_ADMIN_TOKEN_HASH` and refuses to
start without it. A real deployment runs both services with `deploy/compose.yaml`, its site
values in `site.vars` (see `deploy/site.vars.example`). The [install guide](docs/install-mcp.md)
walks through both.

## Repository layout

| Path | What |
|------|------|
| `amt_server.py` | Entry point: the gated FastMCP server and tool registration |
| `amt_*.py` | The server's modules: gate, registry, vault, WS-MAN, KVM, redirection, tools, viewers, handoffs ([module map](docs/mcp-guide.md)) |
| `console/` | amt-console: `server.py` backend, `pages/` and `static/` client, `tests/` |
| `deploy/` | `compose.yaml`, `site.vars.example`, `amt_admin.py` (servers, vault sync, console enrollment) |
| `design/` | UI mockups, theme tokens and the mockup verifier |
| `docs/` | The guides above and the design history |
| `tests/` | Server tests, including real console frames in `tests/real_frames/` |
| `vendor/xterm/` | xterm.js 5.5.0 for the serial terminal page (MIT, licenses included) |

## Tests

```bash
pip install pytest pytest-xdist httpx pillow playwright
python3 -m playwright install chromium
python3 -m pytest              # every core (pytest-xdist); -n 0 runs one process
```

About 2,950 tests, a few minutes on a laptop. No AMT host is contacted: AMT is mocked.

## Status

All 23 tools are built. Reads, the display mirror, the serial terminal, IDE-R mounts and the
Linux console logon have run against a real AMT 19 host. Several write paths are tested only
against mocks; the [MCP deep dive](docs/mcp-guide.md) lists the known gaps.
