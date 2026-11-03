# amt-mcp

> Guidance for coding agents working in this repository.

Intel AMT MCP server (MeshCommander parity). Streamable-HTTP, stateless, behind the fleet
admin-token bearer gate; direct TLS to AMT (16993 WS-MAN, 16995 KVM). No MeshCommander, no
Intel AMT MCP server (MeshCommander parity) plus a separate web console. Streamable-HTTP, stateless, behind the shared admin-token bearer gate; direct TLS to AMT (16993 WS-MAN, 16995 KVM). 23 tools (9 read, 14 write; the count is pinned in `tests/test_conformity.py`). See `README.md` for the tool map and `docs/mcp-guide.md` / `docs/console-guide.md` for the deep dives. A change to a tool, a route, an env var or a deploy step updates the matching guide in `docs/` in the same commit.

## Hard constraints

Full text, mechanisms and live-verification notes for each: `docs/agent-guardrails.md`.

- **Bearer gate is mandatory and fails closed.** Every tool call is gated in `amt_gate.py`; refusals are MCP tool errors, never HTTP 401/403. Never pass `auth=`/`token_verifier=` to `FastMCP`, never add a tool outside `GatedFastMCP`.
- **Only the token's SHA-256 is ever configured** (`AMT_BEARER_SHA256`; the console's second bearer is `AMT_CONSOLE_BEARER_SHA256`). The raw token is never stored, logged, put in env/argv/compose/image or accepted in plaintext. Never add a principal check to a tool body.
- **Secrets stay in-process.** The AMT password and any typed host credential are resolved via `amt_vault` at call time; none is a tool argument, return value, log line, exception text or file. Typed credentials go only through the vaulted-secret path.
- **Do not run a write tool against a host without the operator's per-action approval.** Most write tools are mock-tested only; a class or method tagged `TODO verify-live` is unverified.
- **One authenticated WS-MAN attempt per call** (manual Digest, no retry on a second 401; never urllib's `HTTPDigestAuthHandler`) and **one logon attempt** (accounts lock out).
- **TLS leaf pinning is enforced and fails closed.** Never register a device without its pin.
- **One KVM session at a time.** Pair every open with a close. IDE-R and SOL run beside KVM; while `amt_mirror_link` runs the console tools share its session.
- **Composite tools (`amt_remote_logon`/`amt_remote_logoff`) type only into a positively identified screen.** `classify_screen` is the single source of truth and OCR is the required proceed gate; a negative check alone is fail-open. Retune thresholds only against real captures.
- **`amt_console_input` `expect` aborts on any other screen label before sending anything.** A `secret` step beside a boot or firmware label is refused. It is a parameter, never a new tool.
- **Identity values reach the vault only through the one-time intake url** (`amt_identity_manage`), never as a tool argument; the CLI gets them on stdin.
- **The console (`console/`) has no write path into amt-mcp's state.** It uses its own bearer and vault, every call names its `device` and carries `confirmed: true` for writes, one-time urls are masked, relayed viewer pages run in an opaque sandboxed origin, and a paused server is never read on a timer.
- **Every tool declares `title` and `readOnlyHint`, and every write tool carries `confirmed: StrictBool = False`** whose refusal names the consequence. Update `amt_parity.py` and `EXPECTED_TOOLS` in the same change.
- **The write path is separate from the read path.** Put/Create/Delete/Invoke live in `amt_wsman_write.py` and are reached only from `amt_write.py`; no read module imports a write module. A credential-named field is never a caller-supplied write value.
- **`amt_power` never defaults to a hard reset and refuses a state AMT does not offer.** `amt_set_next_boot` accepts only allowlisted targets and never echoes a Get. Every write tool is `destructiveHint: true`.
- **Never rename, delete or overwrite a mounted, downloading or uploading image.**
- **`amt_kvm.py` is the proven engine;** change it only with a test against the real host.
- **One-time urls are the only handoff:** screenshots, recordings and casts via `amt_handoff.py`, uploads and intake via `amt_upload.py`, viewers via their tokens. Fetching a capture never joins a name onto a path. The HTTP servers never write to stdout. xterm.js is vendored, never loaded from a CDN. Behind nginx, streams need `X-Accel-Buffering: no`.

## Dedicated vault on the NAS

The container's vault is a copy of the entries its servers name, made by `deploy/amt_admin.py vault sync`.
After rotating any of them in the main vault, run `vault sync`; `vault status` must then report every
main entry `matches: true` (a console-sourced entry reports `source: console`, `matches: null`, and only has to be on the NAS). The servers themselves live in the NAS `config/devices.json`, changed only with
`deploy/amt_admin.py device add|edit|remove` (each records or re-checks the TLS pin and syncs the
vault) or the `amt_device_manage` tool (same rules, `amt_fleet.py`; it needs the entries already in the
NAS vault). Both take `flock` on `config/.devices.lock`, and `amt_admin.py` also refuses when the file
changed since it read it. Never edit either by hand and never copy a value through the transcript.

## Credential Registry

| Secret | Vault Service | Notes |
|--------|--------------|-------|
| AMT admin password | `my-server-1-amt` | Intel AMT redirection/WS-MAN auth |
| Host logon (Debian 13 console) | `my-server-1-os` | `{"user":...,"password":...}` for the vaulted-secret typing path; `host_vault_key` in `amt_registry.py` |
| Former Windows GUI logon | `my-server-1-windows` | Same value, kept from the Windows install; no longer referenced |
| AMT KVM (RFB) password | `my-server-1-amt-rfb` | Written into the KVM settings by `amt_configure` area `kvm` (in-process only) |
| New AMT user password | `<device>-amt-user-<username>` | Operator vaults it first; `amt_configure` area `users` action `add` sends only its digest |
| Shared admin token | the admin bearer token | Shared bearer; only its SHA-256 reaches this server (`AMT_BEARER_SHA256`) |
| Console token | `amt-console-token` | The management console's bearer, in a console-only vault; only its SHA-256 reaches this server (`AMT_CONSOLE_BEARER_SHA256`) |

## Deployment

Deployment is a separate, operator-authorized step: `deploy/compose.yaml`, with the site values in
`site.vars` (see `deploy/site.vars.example`).

## Versioning

- **Semver, bumped by hand with every serving change.** `__version__` in `amt_server.py` is the version of record, equal to `pyproject.toml` and reported by `initialize`. `hooks/version_bump_gate.py` (install with `--install`) blocks a commit that stages a serving module or `vendor/` without a bump. Commit subjects end with the version. After a deploy, read `serverInfo.version` back from the container. The console image is outside this policy. Details in `README.md` (Versioning).
