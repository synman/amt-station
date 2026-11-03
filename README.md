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
  a vault CLI vault inside the server process. No
  secret is a tool argument, a result, a log line or an environment value. The server is
  configured with the SHA-256 of its bearer, never the bearer.
- **Each host is pinned.** AMT ships a self-signed certificate, so the full SHA-256 of each host's
  TLS leaf is recorded and checked on every connection. A host with no pin, or a different leaf,
  is refused.
- **One login attempt per call.** WS-MAN Digest auth is answered once. A second 401 fails the call,
  so a stale password cannot lock the AMT account.
- **Fail closed.** A missing vault, pin, OCR engine or confirmation stops the call with nothing sent.

## Dependencies

What the servers need to run. `tests/test_dependencies_declared.py` fails when a module imports a
package this table does not name.

| Dependency | Why |
|---|---|
| Python 3.11 or newer | The runtime. |
| `mcp` (1.26 or newer, below 2) | The MCP server framework. Its HTTP stack brings `pydantic`, `starlette` and `uvicorn`, which the server also imports. |
| `pillow` | Encodes the mirror's JPEG frames and prepares screen images for text recognition. |
| `cryptography` | The console's passkey sign-in, and any vault CLI that needs it. |
| `ocrmac` (optional, macOS) | Apple Vision text recognition for development nodes. The container uses the `tesseract` binary instead. |
| `tesseract` and `ffmpeg` binaries (container) | Screen-text recognition for remote sign-in, and H.264 encoding of recordings. |
| A vault CLI | Any script that runs as `python <cli> get <entry>` and prints the value. `AMT_SECRETS_CLI` and `AMT_CONSOLE_SECRETS_CLI` name it. |
| An Intel AMT host | The managed machine, reached over its WS-MAN and redirection ports. |

## Architecture

```
 AI agent ──MCP + shared bearer──┐
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
| [Agent guidance](AGENTS.md) | The invariants a coding agent must keep when changing this repo |
| [Agent guardrails, full text](docs/agent-guardrails.md) | The mechanisms, thresholds and live-verification notes behind each constraint in `AGENTS.md` |

Design history: [UX design](docs/ux-design-2026-10-20.md) with the mockups in `design/`, and the
review notes in `docs/`.

## Quick start

Local, for development (no AMT host needed to list tools):

```bash
pip install 'mcp>=1.26,<2' pillow
python3 amt_server.py --transport stdio        # stdio: no bearer check, for a local MCP client
```

Over HTTP the server needs the SHA-256 of its bearer in `AMT_BEARER_SHA256` and refuses to
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

## Versioning

The version of record is `__version__` in `amt_server.py`, plain semver `MAJOR.MINOR.PATCH`, and `pyproject.toml` carries the same string. `build_server` sets it on the low-level server, so `initialize` reports it as `serverInfo.version` (the SDK would otherwise report its own version). It is never derived from a library or package metadata. The management console (`console/`) is a separate web image, not an MCP server, and is outside this policy.

- **Bump with every change to a serving file**, the modules and the vendored tree the Dockerfile copies into the image. A new tool or new behaviour is MINOR, a fix or a wording change to a description, docstring or the server instructions is PATCH, a removed or renamed tool or a changed parameter or return shape is MAJOR. The owner judges each step. A docs-, test-, deploy- or console-only change needs no bump.
- **Gate:** `hooks/version_bump_gate.py` is a repo-local pre-commit hook that blocks a commit staging a serving file while `__version__` is unchanged against HEAD. Install it once per clone with `python3 hooks/version_bump_gate.py --install`.
- **Commit subject ends with the version**, for example `Add a tool, 1.1.0`. No tags and no changelog; the commit is the release, and a push stays operator-gated.
- **Read the running version back after every deploy:** POST an `initialize` to the container and check `serverInfo.version` equals `__version__` at the deployed commit, then make one authenticated tool call.

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
