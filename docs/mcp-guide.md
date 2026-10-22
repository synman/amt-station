# amt-mcp: MCP server guide

This is the reference for the amt-mcp server: what it is made of, how a call travels through it, what each of its 23 tools does and refuses, and how to change it safely. It is written for a developer or agent who needs to understand, operate or extend the server.

Everything here was checked against the source in this repository. Where a number comes from the code (a limit, a default, a timeout) the symbol that holds it is named, so the guide can be re-checked with `grep`. Section 15 lists the anchors and the changes that make this guide stale.

Related guides: [install-mcp.md](install-mcp.md) (running and deploying), [operators-guide.md](operators-guide.md) (day-to-day work), [console-guide.md](console-guide.md) (the web console, a separate client of this server), [../README.md](../README.md) (the map) and [../CLAUDE.md](../CLAUDE.md) (the invariants a coding agent must keep).

## Contents

1. [Overview and design principles](#1-overview-and-design-principles)
2. [Architecture](#2-architecture)
3. [Transport and the bearer gate](#3-transport-and-the-bearer-gate)
4. [Device registry and TLS pinning](#4-device-registry-and-tls-pinning)
5. [Credentials](#5-credentials)
6. [Tool reference](#6-tool-reference)
7. [Live viewers](#7-live-viewers)
8. [Files in and out of the server](#8-files-in-and-out-of-the-server)
9. [Screen classification and logon safety](#9-screen-classification-and-logon-safety)
10. [Log decoding and the parity manifest](#10-log-decoding-and-the-parity-manifest)
11. [Environment variables](#11-environment-variables)
12. [Error reference](#12-error-reference)
13. [Testing](#13-testing)
14. [Extending the server](#14-extending-the-server)
15. [Known gaps and keeping this guide current](#15-known-gaps-and-keeping-this-guide-current)

Example values used throughout: device `my-server-1`, addresses `198.51.100.x`, the MCP endpoint `https://amt.example.com/mcp`, the viewer front `https://amt-viewer.example.com`, the console `https://amt-console.example.com`, and the user `jdoe`.

---

## 1. Overview and design principles

amt-mcp is a Python MCP server (FastMCP, streamable HTTP, stateless) that manages Intel AMT hosts. It opens its own TLS connections to each host: WS-MAN on port 16993 and the redirection channel (KVM, Serial-over-LAN, IDE-R) on port 16995. There is no MeshCommander, no relay and no browser in the path. Its goal is MeshCommander feature parity, tracked by `amt_parity.py` (section 10).

The server is one process. Tool calls arrive on `/mcp` (port 8765 by default). Live viewer pages (the display mirror and the serial terminal) are served by a second, small HTTP server inside the same process (port 8766 by default). Both are described below.

### Design principles

| Principle | What it means in the code |
|-----------|---------------------------|
| **One redirection session per host** | AMT allows one KVM session at a time. While `amt_mirror_link` runs, `amt_screenshot`, `amt_console_input` and `amt_remote_logon` / `amt_remote_logoff` reuse its session (`amt_tools._kvm_session` returns the mirror's `_Shared` wrapper) instead of opening a second one. The same holds for SOL: while `amt_serial_link` runs, `amt_sol` and the serial logon use its terminal. An IDE-R mount runs beside KVM, and SOL runs beside KVM (both noted as verified live in `CLAUDE.md`). Within the process, a per-device `asyncio.Lock` (`amt_tools._session_lock`) serializes tools that take a session. Every open is paired with a close in a `finally`. |
| **Fail closed** | An unset or malformed token hash refuses every call. A device with no TLS pin is refused. A missing vault CLI, an unreadable devices file, a missing OCR backend, an unrecognized screen and a missing `confirmed: true` each stop the call with nothing sent. |
| **Secrets stay in the process** | The AMT password and any typed host credential are read from the vault at call time by `amt_vault`. No secret is a tool argument, a returned value, a log line, an exception text or a file. Only the SHA-256 of the bearer token is ever configured. |
| **Pinned TLS leaf instead of a chain** | AMT presents a self-signed certificate, so the chain is not verified. The identity check is the full SHA-256 of the leaf certificate stored per device. It is compared on every WS-MAN connection and inside the redirection socket's `connect()`, before any protocol byte or password digest is sent. |
| **One authenticated attempt per call** | WS-MAN Digest auth is manual: one unauthenticated request to get the challenge, one authenticated request, and a second 401 raises `wsman_auth_failed_401` with no retry. The redirection handshake also answers its challenge once (`auth_rejected_no_retry`). A stale password therefore costs one failed login per call, not a burst. An agent that sees `wsman_auth_failed_401` should stop, not retry. |
| **`confirmed` is a strict boolean** | Every write takes `confirmed: StrictBool = False`. Only the JSON boolean `true` proceeds; `"true"` and `1` are rejected by schema validation, and `false` refuses with a message that names the consequence and sends nothing. |
| **Positive match or abort** | The tools that type into a console (`amt_remote_logon`, `amt_remote_logoff`, and `amt_console_input` when `expect` is given) type only into a screen they positively identify. An unreadable, unrecognized or unexpected screen aborts. |
| **Writes are separate from reads** | The WS-MAN client in `amt_wsman.py` has no Put, Create, Delete or general Invoke, only Get, Enumerate and an allowlist of record-reading methods (`READ_METHODS`). Those write operations live in `amt_wsman_write.py`, which only `amt_write.py` imports (pinned by `tests/test_wsman_write.py::test_no_read_module_imports_a_write_module`). |
| **Errors are tool errors** | A failure raises, and FastMCP returns it as `isError: true` with the text `Error executing tool <name>: <message>`. A tool does not return a success that carries an error. The disclosed exceptions are a composite tool's abort result (`{"aborted": true, ...}`, a refusal to act), `amt_images action=list` (reports an unusable image root in an `error` field) and `amt_sol` on a shared terminal (reports `error` when the terminal ended during the read). |

---

## 2. Architecture

### Module map

| Module | Responsibility |
|--------|----------------|
| `amt_server.py` | Entry point. Builds the `GatedFastMCP` server (`build_server`), registers every tool and the custom routes (`register_tools`), builds the HTTP app with DNS-rebinding protection (`build_http_app`), and parses `--transport` (`main`). Holds `INSTRUCTIONS`, the text clients see on connect (kept under 2048 characters by a test). |
| `amt_gate.py` | The bearer gate. `BearerContextMiddleware` (pure ASGI) records whether the presented bearer verified and which principal it belongs to. `GatedFastMCP` overrides `call_tool`, `read_resource` and `get_prompt` to refuse an ungated call. Also the per-call log. |
| `amt_registry.py` | The device registry: `Device` dataclass, the built-in `DEVICES` example, the `AMT_DEVICES_FILE` loader with live re-read, `get_device`, `all_devices`. No secrets. |
| `amt_vault.py` | Vault access through the vault CLI as a child process (`AMT_SECRETS_CLI`). Reads, lists, writes (stdin only) and deletes entries. Fails closed with key-only `VaultError`s. |
| `amt_wsman.py` | The read-only WS-MAN client: pinned HTTPS connection, manual Digest, Get, Enumerate/Pull, allowlisted record readers, response parsing, credential redaction (`is_secret_name`, `redact_text`). `transport()` is the one function that touches the network. |
| `amt_wsman_write.py` | The WS-MAN write path: Put, Create, Delete, general method Invoke, reference parameters, vaulted secret fields, secret-name refusal. Reuses `amt_wsman.transport`, so the pin and the one-attempt rule apply. |
| `amt_kvm.py` | The KVM engine: TLS connect, the redirection Digest handshake, RFB decode (RAW and RLE), framebuffer grabs (full and incremental), keyboard and pointer input, PNG writing. Treated as proven; change it only with a test against a real host. |
| `amt_redir.py` | The SOL and IDE-R engines. Subclasses of the KVM session for the handshake only (`SolSession`, `IderSession`), the `pinned()` factory, and the SCSI responder that serves read-only images. |
| `amt_tools.py` | The read tools `amt_status`, `amt_screenshot`, `amt_inventory`, `amt_logs`, `amt_settings`, `amt_wsman_get`; the composite tools `amt_remote_logon` / `amt_remote_logoff`; the screen classifier and OCR gate; `InFlight`; the per-device session lock; the private screenshot directory. |
| `amt_write.py` | The eight write tools `amt_power`, `amt_set_next_boot`, `amt_console_input`, `amt_sol`, `amt_ider`, `amt_images`, `amt_configure`, `amt_wsman_invoke`, plus the IDE-R mount registry and the persisted settings file. |
| `amt_mirror.py` | The display mirror: the `amt_mirror_link` tool, the frame thread, the viewer HTTP server (which also serves `/s/<token>/` for the serial terminal), recording and MP4 encoding. |
| `amt_serial.py` | The serial terminal: the `amt_serial_link` tool, the reader thread, scrollback, the SSE stream, asciinema recording, and the serial-console logon and logoff used by `console="serial"`. |
| `amt_handoff.py` | One-time download urls for files a tool wrote: `GET /handoffs/<token>`. |
| `amt_upload.py` | The one-time `PUT /uploads/<token>` image route, the one-time `PUT /intake/<token>` identity-value route, and the CORS wrapper both use. |
| `amt_fleet.py` | The `amt_devices` read tool and the `amt_device_manage` write tool, and the add / edit / remove rules (`plan_add`, `plan_edit`, `plan_remove`) that `deploy/amt_admin.py` shares. |
| `amt_identity.py` | The `amt_identities` read tool and the `amt_identity_manage` write tool: vault entries by name and status only. |
| `amt_captures.py` | The `amt_captures` read tool: lists the files the tools wrote and mints a fresh handoff url for one. |
| `amt_logdecode.py` | Readable meaning for event-log and audit-log records, ported from MeshCommander's decoders. |
| `amt_parity.py` | The MeshCommander-to-tool parity manifest (`TOOLS`, `PAGES`, `POWER_ENTRIES`, `BOOT_OPTIONS`, `KEY_MACROS`, `parity_status()`). |

Other directories: `deploy/` (compose file, `amt_admin.py`), `console/` (the web console; see [console-guide.md](console-guide.md)), `vendor/xterm/` (xterm.js 5.5.0 for the serial page), `tests/`.

Some imports are deliberately late (inside a function) to break cycles: `amt_tools` imports `amt_mirror` and `amt_serial` only when needed, and `amt_mirror` reaches `amt_serial` the same way.

### Request flow

```
MCP client
   |  POST https://amt.example.com/mcp      Authorization: Bearer <token>
   v
reverse proxy (TLS)  ->  uvicorn  127.0.0.1:8765  (bind via AMT_BIND_HOST / AMT_PORT)
   v
BearerContextMiddleware     hashes the bearer, stores principal fleet|console|none
   |                        in a contextvar; rejects nothing
   v
Starlette route /mcp  ->  SDK transport security (Host, Origin, Content-Type)
   v                       stateless streamable-HTTP session manager
GatedFastMCP.call_tool      refuses unless stdio or a verified bearer;
   |                        writes the call-log line; records the tool name
   v
tool coroutine (amt_*)      schema validation (StrictBool, enums, bounds);
   |                        _require_confirmed for writes
   v
per-device asyncio lock     only for tools that take a session
   v
asyncio.to_thread(sync implementation)
   v
amt_registry.get_device  ->  require_pin          unknown_device / tls_leaf_unpinned_refused
   v
amt_vault.get_secret         child process: python <AMT_SECRETS_CLI> get <key>
   v
   +-- WS-MAN:   amt_wsman.transport -> pinned HTTPS to <ip>:16993
   |             (one unauthenticated request, one authenticated request)
   +-- KVM / SOL / IDE-R: pinned socket to <ip>:16995
                 (pin compared in connect(), before any protocol byte)
```

Outside this path, three kinds of route exist. The download, upload and intake routes (`/handoffs/<token>`, `/uploads/<token>`, `/intake/<token>`) are custom routes on the same app; they are outside the bearer gate and outside the Host/Origin check, and each is keyed by a one-time token (section 8). The viewer pages (`/m/<token>/`, `/s/<token>/`) are on the separate viewer server and are keyed by per-session tokens (section 7).

### Process model

The server is a single process with worker threads. Blocking network work runs in `asyncio.to_thread`. State that tools keep in memory (live mirrors and terminals, IDE-R mounts, background downloads, open upload and intake offers, the per-device locks) is per process: a restart drops all of it, and running several uvicorn workers would split it. Run one worker.

---

## 3. Transport and the bearer gate

### Transports

| Transport | How to run | Bearer |
|-----------|------------|--------|
| HTTP (default) | `python3 amt_server.py` (or `--transport http`) | Required. Endpoint `/mcp`, default bind `127.0.0.1:8765`. |
| stdio | `python3 amt_server.py --transport stdio` | None; the process boundary is the control. |

`main()` writes `AMT_TRANSPORT` into the environment from `--transport`. **Only an explicit `stdio` skips the gate**; an unset or unknown value is treated as HTTP and gated. `build_http_app` raises `RuntimeError` if it is called while `AMT_TRANSPORT=stdio`, so a stray variable cannot serve the HTTP mount ungated. The HTTP path exits with status 2 and a message on stderr if `MCP_ADMIN_TOKEN_HASH` is unset or not a 64-character hex digest. Stdout is never written to (it is the stdio MCP channel); the call log goes to stderr.

The server is created with `stateless_http=True`: there is no MCP session id, each request stands alone, and everything a later call depends on lives in the process (above).

### What the gate guarantees

- **Fully gated.** Every tool call needs the bearer, reads included, because a read can return a host's live screen. The gate also covers `read_resource` and `get_prompt` (none is registered today).
- **It lives in dispatch, not in HTTP.** `GatedFastMCP.call_tool` checks the contextvar set by the middleware. The HTTP layer rejects nothing on authentication: a refusal is an MCP tool error (`isError: true`, HTTP 200), never a 401 or 403. The text is `this call requires the mcp-admin-token bearer header (Authorization: Bearer <token>); the call was refused and nothing ran`.
- **Other HTTP rejections do exist, from the SDK's transport security** (not the bearer gate): an unlisted `Host` gets 421, an unlisted `Origin` (when sent) gets 403, and a POST without a JSON `Content-Type` gets 400.
- **Never pass `auth=` or `token_verifier=` to FastMCP** and never register a tool outside `GatedFastMCP`; either would bypass or duplicate the gate.

### Tokens and principals

Only a SHA-256 hex digest is configured. The raw token is never stored, logged or accepted in configuration. Derive the digest in a terminal without echoing the token:

```bash
export MCP_ADMIN_TOKEN_HASH="$(<command that prints the token> \
  | python3 -c 'import sys,hashlib; print(hashlib.sha256(sys.stdin.read().strip().encode()).hexdigest())')"
```

| Variable | Principal | Rule |
|----------|-----------|------|
| `MCP_ADMIN_TOKEN_HASH` | `fleet` | Required over HTTP. Must be 64 hex characters after strip and lower-casing (`_HEX64`). |
| `MCP_CONSOLE_TOKEN_HASH` | `console` | Optional, same form. Unset or malformed: only the fleet bearer works. |

`identify_bearer` hashes the presented token and compares it to each configured digest with `hmac.compare_digest`, computing both comparisons every time. If the two hashes are equal the token is the fleet's. **If the fleet hash is unresolvable, every token is refused, the console's included.** The `Authorization` header must use the `Bearer` scheme (case-insensitive); only the first `Authorization` header is read. A tool body never checks the principal; the principal only labels the log.

### The call log

One record per call that passed the gate, written to stderr by the `amt_mcp.calls` logger:

```
<asctime> amt_mcp.calls tool=<name> principal=<fleet|console|stdio>
```

`stdio` appears when the transport is stdio. The record carries no token, no hash and no arguments. The tool name is client-supplied and is logged before FastMCP validates it, so only a name matching `[A-Za-z0-9_.\-]{1,64}` is written; anything else is logged as `<invalid-name>` (a newline cannot forge a second record). `configure_call_log()` is idempotent and is called from `main()`. A refused call is not logged.

### Allowed hosts and DNS-rebinding protection

DNS-rebinding protection is always on. The default allowlist is loopback: Hosts `127.0.0.1:*`, `localhost:*`, `[::1]:*` and the matching `http://` Origins. `AMT_ALLOWED_HOSTS` is a comma-separated list of extra names (the ingress host name, for example `amt.example.com`); each name is allowed bare and with `:*`, and as `http://` and `https://` Origins with and without a port. The `host:*` wildcard does not match a portless forwarded Host, which is why both forms are added. The protection is set before `streamable_http_app()` is built, because the SDK bakes it in.

The protection covers `/mcp` only. The download, upload and intake routes are plain Starlette routes outside it (by design, so `curl` and scripts can reach them), and the viewer server is a separate listener.

### Process and bind

`AMT_BIND_HOST` (default `127.0.0.1`) and `AMT_PORT` (default `8765`) are read in `main()` and set on `mcp.settings` after construction, because `FastMCP.__init__` sets host and port explicitly and would shadow `FASTMCP_*` variables. The container image sets `AMT_BIND_HOST=0.0.0.0`; the compose file publishes the ports on the host loopback only and expects a TLS reverse proxy in front.

---

## 4. Device registry and TLS pinning

### The `Device` record

| Field | Type | Rule |
|-------|------|------|
| `key` | string | `[a-z0-9][a-z0-9-]{0,62}`. The name tools take as `device`. |
| `amt_ip` | string | An IP address (`ipaddress.ip_address`), never a host name: the pin is per address. |
| `wsman_port` | int | 1 to 65535. Conventionally 16993. |
| `kvm_port` | int | 1 to 65535. Conventionally 16995 (also SOL and IDE-R). |
| `amt_vault_key` | string | Name of the vault entry holding the AMT admin password. Same pattern as `key`. |
| `host_vault_key` | string or null | Name of the vault entry holding the host OS logon, if any. |
| `tls_leaf_sha256` | string or null | Full SHA-256 of the AMT TLS leaf, 64 lowercase hex. **Null means unpinned: every WS-MAN, KVM, SOL and IDE-R path refuses the device.** |
| `tls_leaf_observed_prefix` | string or null | First 16 hex characters seen at capture time. Informational only, never used for verification. |

`Device.__post_init__` validates all of this, so a bad file fails at load.

### Built-in registry and the devices file

With `AMT_DEVICES_FILE` unset, the built-in `DEVICES` dict in `amt_registry.py` is the registry (a single example entry, `my-server-1`, documentation address and placeholder pin). That is the mode for local stdio use and tests. Changing it takes a code change; `amt_device_manage` refuses with `device changes need AMT_DEVICES_FILE`.

With `AMT_DEVICES_FILE` set (the container uses `/config/devices.json`), that file **is** the registry:

```json
{
  "version": 1,
  "devices": {
    "my-server-1": {
      "amt_ip": "198.51.100.26",
      "wsman_port": 16993,
      "kvm_port": 16995,
      "amt_vault_key": "my-server-1-amt",
      "host_vault_key": "my-server-1-os",
      "tls_leaf_sha256": "<64 lowercase hex characters>",
      "tls_leaf_observed_prefix": "<first 16 of the above>"
    }
  }
}
```

- `version` must be `1`; `devices` must be an object; each entry may carry only the fields above (an unknown field is rejected as `devices_file_malformed:<key>`).
- **Live re-read.** `get_device` and `all_devices` call `_refresh()`, which compares the file's `st_mtime_ns` with the last load and re-reads when it changed. An add or edit is live at the next tool call, with no restart.
- **Fail closed.** A missing, unreadable or invalid file raises `RuntimeError("devices_file_unusable:<ExceptionType>")`. The server never falls back to the built-in registry. (The detail of a malformed file is deliberately reduced to the exception type; the text `devices_file_malformed` itself is only seen from `amt_device_manage` and `deploy/amt_admin.py`, which call the parser directly.)
- Writes are normally atomic renames done by `amt_device_manage` or `deploy/amt_admin.py`; never edit the file by hand.

`AMT_DEFAULT_DEVICE` names the device a call that omits `device` acts on (default `my-server-1`). It is read **once at import** (`amt_wsman.DEFAULT_DEVICE`), so set it before the process starts. The default also appears in every tool's `device` parameter description and in the server `INSTRUCTIONS`.

### Where the pin is enforced

| Path | Enforcement point | Timing |
|------|-------------------|--------|
| WS-MAN (reads and writes) | `amt_wsman.require_pin` in `resolve_password`, then `_PinnedHTTPSConnection.connect` compares the peer leaf SHA-256 with `hmac.compare_digest` on **every** connection | An unpinned device is refused before the vault is touched; a mismatch closes the socket before any HTTP request |
| KVM (`amt_screenshot`, mirror, console tools) | `amt_tools._pinned_kvm_session` subclasses `KvmSession` and compares `cert_fp` in `connect()` | Before the KVMR start bytes and before the Digest answer |
| SOL and IDE-R | `amt_redir.pinned()` does the same in `connect()` | Before any protocol byte; no pin gives `tls_leaf_unpinned_refused` |
| Tool entry | `amt_wsman.require_pin(dev)` at the top of each session tool (screenshot, logon, logoff, console input, IDE-R, mirror, serial, and SOL when it opens its own session; a shared terminal's session was pinned when it opened) | Before the vault, the disk or the wire |

The errors are `tls_leaf_unpinned_refused` and `tls_leaf_pin_mismatch` (section 12). A mismatch means the certificate changed, or another machine holds the address.

`amt_devices action=pin_check` is a read: it opens one TLS handshake to the device's WS-MAN port, reads the leaf, and sends no credential. It returns `{device, presented, stored, matches}`. It does not enforce anything itself and does not test the KVM port.

### Managing devices: `amt_device_manage`

The same rules apply whether the change comes from the tool or from `deploy/amt_admin.py device ...` (both call the `plan_*` functions in `amt_fleet.py`):

| Action | Rule |
|--------|------|
| `add` | Requires `ip` and `amt_vault_key`; ports default to 16993 and 16995. The named vault entries must already exist in the server's vault (`vault <name> in <where> first`). The leaf the device presents on its WS-MAN port is recorded (trust on first use). With `expected_pin` (for example read from the AMT firmware setup screen), any other leaf is refused and nothing is written. An existing key is refused ("edit it instead"). |
| `edit` | Editable: `ip`, `wsman_port`, `kvm_port`, `amt_vault_key`, `host_vault_key`; `clear_host=true` drops the host entry (not together with `host_vault_key`). A change of address or WS-MAN port, or `repin=true`, re-reads the leaf. A leaf different from the stored pin is refused unless `repin=true`; `repin` accepts whatever the device presents now. A `kvm_port` change alone does not re-probe. An edit with no change and no `repin` is refused. |
| `remove` | The last device cannot be removed ("the server would have nothing to serve"). |

Every change is made under `flock(LOCK_EX)` on `.devices.lock` beside the file: the file is re-read fresh inside the lock, the change is applied, the result is validated by parsing it back (never write a file the server would refuse), the previous file is kept as `.prev-devices.json`, and the new file is renamed into place (mode 0644). The change is live at the next tool call. `amt_device_manage` does not take the per-device session lock.

---

## 5. Credentials

### How the server reads the vault

`amt_vault.py` runs the vault CLI as a **child process**: `python <AMT_SECRETS_CLI> get <key>`, with a 15 second timeout. It is a child, not an in-process import, because the in-process reader raises `SystemExit` on a vault fault, which would end the server.

- `AMT_SECRETS_CLI` has no default. Unset, every vault call fails with `vault_cli_unset:AMT_SECRETS_CLI`. It is read once at import. In a container it points at a mounted copy of the vault CLI, and `NVAULT_VAULT_PATH` / `NVAULT_MASTER_KEY_FILE` (read by the CLI) select a dedicated vault.
- Only the CLI's trailing newline is stripped; edge whitespace in a value is preserved, because a password wrong by a space risks lockout.
- Every failure raises `VaultError` naming the **key only**: `vault_miss:<key>`, `vault_empty:<key>`, `vault_unavailable:<key>:<ExceptionType>`, `vault_decode_error:<key>:<ExceptionType>`. Never a value, never stderr.
- `vault_entries()` lists entry names with the rest of each list line (the notes column) by parsing the CLI's `list` output, which uses the `❯` separator. `vault_names()` is its name set. A change to the CLI's list format would break `amt_identities`, `amt_identity_manage remove` and the vault checks in `amt_device_manage`.
- `set_secret` writes a value to the CLI on **stdin** (never argv or env) and drops the CLI's output. `delete_secret` deletes an entry. `vault_writable()` is false when `NVAULT_VAULT_PATH` or its directory is not writable.

### Entry naming

| Entry | Name | Used by |
|-------|------|---------|
| AMT admin password | the device's `amt_vault_key`, conventionally `<device>-amt` | Every host tool |
| Host logon | the device's `host_vault_key`, conventionally `<device>-os`; the value is JSON `{"user": "...", "password": "..."}` | `amt_remote_logon` and `amt_console_input` `secret` steps |
| KVM (RFB) password | `<amt_vault_key>-rfb` | `amt_configure area=kvm` (inserted at the `RFBPassword` position of the Put, in process) |
| New AMT user's password | `<device>-amt-user-<username>` | `amt_configure area=users action=add` (only its Digest is sent) |

The WS-MAN user is always `admin` (`amt_wsman.USER`). The host logon's `user` is matched against the sign-in tile as Windows spells it, without a `DOMAIN\` prefix (`_account_name` strips one and lower-cases).

### Redaction and refusal

**On reads.** A field whose name marks it as a credential is replaced by `<redacted>` in every parsed response (`amt_wsman._value`), so no tool that reads WS-MAN can return one. The rule (`is_secret_name`) is: the name matches `password|passwd|passphrase|secret|credential|privatekey|sharedkey|apikey|masterkey|netadminpass|psk` (case-insensitive substring), or one of its CamelCase or underscore **words** is `pwd`, `pass`, `token`, `hash`, `pps` or `pid`. Words are matched whole, so `Rapid` and `Bypass` are not redacted. `UserPasswordBypass` is exempt only while its value is boolean-ish (`true`, `false`, `0`, `1`); with any other value it counts as a secret again (`is_secret_field`). SOAP fault text goes through `redact_text`, which removes credential-named `Name=value` pairs and any known secret. Certificate blobs (`X509Certificate`, `DERKey`) in `amt_settings` are reduced to a size note.

**On writes.** A credential-named field in a caller-supplied value, at any depth (field names, selector names, reference-parameter selectors, nested dicts and lists), is refused with `secret_field_refused:<name>` before any I/O (`amt_wsman_write.refuse_secret_names`). The only way a credential enters a write is in-process: `secret_fields` (a field name mapped to a vault key, resolved by the tool) or `secret_params` (a value computed by trusted code, such as a password digest). Both are scrubbed from the reply, and errors from the device are passed through `redact_text` with the password and every vaulted value as known secrets.

### Identities: `amt_identities` and `amt_identity_manage`

`amt_identities` reports the entries the registered servers use, by name and status only: `present` or `missing`, which device field uses each (`amt_vault_key`, `host_vault_key`, `amt_configure_kvm`, `amt_configure_users`), its `source` and `updated_at` (parsed from `updated: <timestamp>` in the entry's notes). `source` is `console` when the notes carry `source: console` (the value was entered through the intake route below), else `main` (copied from the main vault by `deploy/amt_admin.py vault sync`). It never returns a value or a value's length. Without a `device` filter it also lists console-sourced entries no server names yet.

`amt_identity_manage` never takes a value:

- **`intake`** checks the name (`identity_name_not_allowed` unless it is an entry a registered server names, `<amt_vault_key>-rfb`, or `<device>-amt-user-<name>` for a registered device) and mints a one-time url (section 8). The operator PUTs the raw value once; it is stored through `amt_vault.set_secret` (stdin) with notes `source: console; updated: <UTC>` and a far-future expiry (`2035-01-01`), replacing any value there. **Storing a value does not change the password on the AMT**: change it in the AMT firmware setup first.
- **`remove`** deletes an entry that was entered that way, and refuses (`identity_in_use`, `identity_not_found`, `identity_not_console_entry`) an entry any server names, a missing entry, and an entry that came from the main vault.

---

## 6. Tool reference

The surface is **23 tools**: 9 read, 14 write (including the two composite tools and the two viewer tools). To regenerate the tables below from the live server:

```bash
cd amt-mcp && python3 -c "import asyncio, amt_server; [print(t.name, t.annotations.title, t.annotations.readOnlyHint, t.annotations.destructiveHint, sorted(t.inputSchema.get('properties', {}))) for t in asyncio.run(amt_server.mcp.list_tools())]"
```

### Annotations and guards at a glance

Every tool declares `title` and `readOnlyHint`; all set `openWorldHint: true`. A tool's description (its docstring) is capped at 2048 characters and its first sentence at 400 by `tests/test_conformity.py`.

| Tool | Title | `readOnlyHint` | `destructiveHint` | `idempotentHint` | `confirmed` needed | Per-device lock |
|------|-------|:--:|:--:|:--:|----------------------|:--:|
| `amt_status` | AMT Host Status | true | false | true | no | no |
| `amt_screenshot` | AMT Console Screenshot | true | false | **false** | no | yes |
| `amt_inventory` | AMT Hardware Inventory | true | false | true | no | no |
| `amt_logs` | AMT Event and Audit Logs | true | false | true | no | no |
| `amt_settings` | AMT Settings Area | true | false | true | no | no |
| `amt_wsman_get` | AMT WS-MAN Get or Enumerate | true | false | true | no | no |
| `amt_devices` | AMT Managed Servers | true | false | true | no | no |
| `amt_identities` | AMT Identities | true | false | true | no | no |
| `amt_captures` | AMT Captures | true | false | **false** | no | no |
| `amt_remote_logon` | AMT Remote Windows Logon | false | true | false | always | yes |
| `amt_remote_logoff` | AMT Remote Windows Logoff | false | true | false | always | yes |
| `amt_power` | AMT Power Action | false | true | false | always | yes |
| `amt_set_next_boot` | AMT Set Next Boot | false | true | false | always | yes |
| `amt_console_input` | AMT Console Input | false | true | false | always | yes |
| `amt_sol` | AMT Serial-over-LAN | false | true | false | always | yes |
| `amt_ider` | AMT IDE Redirection Mount | false | true | false | `mount`, `unmount` | `mount`, `unmount` |
| `amt_images` | AMT IDE-R Image Library | false | true | false | all but `list`, `verify` | no |
| `amt_configure` | AMT Configure Settings | false | true | false | always | yes |
| `amt_wsman_invoke` | AMT WS-MAN Write or Invoke | false | true | false | always | yes |
| `amt_mirror_link` | AMT Display Mirror | false | **false** | false | `start`, `record_start` | `start`, `stop` |
| `amt_serial_link` | AMT Serial Terminal | false | **false** | false | `start`, `record_start` | `start`, `stop` |
| `amt_device_manage` | AMT Manage Servers | false | true | false | always | no |
| `amt_identity_manage` | AMT Manage Identities | false | true | false | always | no |

`amt_screenshot` is a read of the host but takes the host's one redirection session, so it is not idempotent; `amt_captures` mints a new url on each `fetch`. The two viewer tools are not marked destructive: they serve a view and send no input of their own. `readOnlyHint` and `destructiveHint` come from which registration tuple a tool is in and from its `hints` (section 14), not from its name.

Parameters common to host tools: `device` (optional, defaults to `AMT_DEFAULT_DEVICE`; the device must be registered and pinned). `amt_images`, `amt_captures` and `amt_identity_manage` take no `device`; `amt_devices` and `amt_identities` take one only as a filter with no default; `amt_device_manage` requires one.

### Read tools

#### amt_status

Parameters: `device`.
Reads nine WS-MAN classes in one call: `CIM_AssociatedPowerManagementService`, `CIM_SoftwareIdentity` (enumerated), `AMT_SetupAndConfigurationService`, `IPS_HostBasedSetupService`, `AMT_RedirectionService`, `CIM_KVMRedirectionSAP`, `IPS_KVMRedirectionSettingData`, `IPS_OptInService` and `AMT_BootSettingData`. Returns `power` (`state` label and `code`), `amt` (`version`, `build_number`, `sku`, `firmware`), `provisioning`, `redirection` (`sol_enabled`, `ider_enabled`, and `kvm` with `enabled`, `port_5900_enabled`, `session_timeout`), `user_consent`, `next_boot` and the coverage fields. Values are typed (ints and bools), with a readable label beside each enumerated code (power: 2 `on`, 3 `sleep_light`, 4 `sleep_deep`, 6 `off_hard`, 7 `hibernate`, 8 `off_soft`).
**Coverage.** A SOAP Fault means the device does not expose that class: it is listed in `unavailable` (with `unavailable_reasons`, cut to 200 characters) and the rest is returned. `truncated` names classes cut at the item cap. Auth, pin, unreachable and protocol errors are not class-specific and always propagate, so a lockout or a man-in-the-middle cannot hide behind a partial result.

#### amt_screenshot

Parameters: `device`.
Opens the host's single KVM session (or shares a live mirror's), waits for the screen to settle, writes a PNG, and closes the session. Order: pin check, then the private screenshot directory, then the vault, then the session. `grab_stable` re-grabs up to 8 times, 0.5 s apart, until two consecutive frames differ by at most 20,000 changed bits (`STABLE_BITS`, so a blinking caret does not prevent settling). Returns `path`, the handoff fields (`url`, `sha256`, `expires_in_s`, or `path_note` without a public base URL), `width`, `height`, `bytes`, `iterations`, `stable`, `delta_bits` and `tls_leaf_sha256` (the leaf the session saw).
While open it blocks every other KVM, SOL or IDE-R user of the host's redirection channel, and where user consent is required it may raise a consent prompt on the host. It fails if another session is open or consent is pending (`redir_start_status_<N>`). It sends no input. Calls for one device are serialized in the process.

#### amt_inventory

Parameters: `device`, `sections` (any of the seven below; omit for all).

| Section | Class |
|---------|-------|
| `chassis` | `CIM_Chassis` |
| `baseboard` | `CIM_Card` |
| `bios` | `CIM_BIOSElement` |
| `processors` | `CIM_Processor` |
| `memory` | `CIM_PhysicalMemory` |
| `storage_media` | `CIM_MediaAccessDevice` |
| `physical_media` | `CIM_PhysicalMedia` |

Returns `sections` (instances as typed dicts), `classes` (the class behind each returned section) and coverage. A faulting class is left out of `sections` and named in `unavailable`; the reference host does not expose `CIM_PhysicalMedia`. Enumerations stop at 500 instances per class and set `truncated`.

#### amt_logs

Parameters: `kind` (`event` or `audit`, default `event`), `since`, `until` (ISO-8601; no zone means UTC), `offset` (default 0), `limit` (1 to 500, default 50), `device`.
Fetches the whole log, decodes it, applies the time filter, sorts newest first and pages. The event log is read with `AMT_MessageLog.GetRecords` (`MaxReadRecords` 390 per call); the audit log with `AMT_AuditLog.ReadRecords` from `StartIndex`; each stops after 50 calls (`MAX_LOG_CALLS`). The result says how complete it is: `fetched`, `fetch_complete` (true only when the device said `NoMoreRecords`, or the audit total was reached), `undecodable`, `undated` (written before the AMT clock was set; `epoch` null), `matched`, `returned`, `records`. A record that fails to decode is returned with `decoded: false` and `raw_hex` instead of being dropped. A time filter drops records with no timestamp. Event records are little-endian; audit records are big-endian (live-verified; a little-endian read gave year-2105 timestamps). Section 10 lists the decoded fields.

#### amt_settings

Parameters: `area` (required), `device`.
Reads one area as typed sections plus the class behind each. Reads are strict here: a SOAP Fault raises instead of being listed as unavailable.

| Area | Sections (class, `get` or `enum`) |
|------|-----------------------------------|
| `network` | `ethernet_ports` (`AMT_EthernetPortSettings`, enum), `general` (`AMT_GeneralSettings`) |
| `internet` | `mps_servers` (`AMT_ManagementPresenceRemoteSAP`, enum), `remote_access_policy_rules` (`AMT_RemoteAccessPolicyRule`, enum), `environment_detection` (`AMT_EnvironmentDetectionSettingData`) |
| `security` | `tls` (`AMT_TLSSettingData`, enum), `certificates` (`AMT_PublicKeyCertificate`, enum), `authorization` (`AMT_AuthorizationService`) |
| `agent_presence` | `watchdogs` (`AMT_AgentPresenceWatchdog`, enum), `capabilities` (`AMT_AgentPresenceCapabilities`) |
| `system_defense` | `policies` (`AMT_SystemDefensePolicy`, enum), `service` (`AMT_SystemDefenseService`) |
| `users` | the ACL entries, through `AMT_AuthorizationService.EnumerateUserAclEntries` and `GetUserAclEntryEx` |
| `subscriptions` | `filter_subscriptions` (`CIM_FilterCollectionSubscription`, enum), `indication_filters` (`CIM_IndicationFilter`, enum) |
| `wake_alarms` | `service` (`AMT_AlarmClockService`), `occurrences` (`IPS_AlarmClockOccurrence`, enum) |
| `kvm` | `redirection_sap` (`CIM_KVMRedirectionSAP`), `settings` (`IPS_KVMRedirectionSettingData`), `opt_in` (`IPS_OptInService`) |
| `features` | `redirection_service` (`AMT_RedirectionService`), `kvm_sap` (`CIM_KVMRedirectionSAP`), `opt_in` (`IPS_OptInService`), `setup` (`AMT_SetupAndConfigurationService`) |

Credential-named fields are redacted and certificate blobs reduced to a size note. Six areas are writable with `amt_configure` (`network`, `internet`, `security`, `users`, `kvm`, `features`); `agent_presence`, `system_defense`, `subscriptions` and `wake_alarms` are read here and written only through `amt_wsman_invoke`. The `users` area does not say whether its handle list was complete.

#### amt_wsman_get

Parameters: `class_name` (required), `operation` (`get` or `enumerate`, default `get`), `selectors`, `max_items` (1 to 1000, default 200), `device`.
The general read primitive: a WS-Transfer Get or a WS-Enumeration Enumerate and Pull of any class whose name matches `(AMT|CIM|IPS)_[A-Za-z0-9_]{1,80}`. `selectors` (names `[A-Za-z0-9_.-]{1,64}`) pick one instance for `get`; with `enumerate` they are refused (`selectors_not_supported_for_enumerate`). Fields come back as the device sent them, as strings, nested structures kept and repeated elements as lists; credential-named fields are redacted. Enumeration pulls 20 at a time (`PAGE_SIZE`), at most 100 pulls (`MAX_PAGES`), and returns `count`, `truncated` (true whenever completeness is not proven: more than `max_items`, the pull budget ran out, or no end marker) and `instances`. There is no Put and no method invocation here: the `operation` enum has no other values.

#### amt_devices

Parameters: `action` (`list`, `show`, `pin_check`; default `list`), `device` (needed for `show` and `pin_check`).
`list` and `show` return every `Device` field (vault entries by name only) plus `pinned`, and `source` (`file` when `AMT_DEVICES_FILE` is set, else `built-in`). `pin_check` is described in section 4. It touches the network only for `pin_check`.

#### amt_identities

Parameters: `device` (optional filter). See section 5. Reads the vault's entry names only.

#### amt_captures

Parameters: `action` (`list` or `fetch`, default `list`), `name`, `offset`, `limit` (1 to 200, default 50).
Touches no host. `list` returns screenshots (from the screenshot directory), finished mirror recordings (`.mp4`) and finished serial casts (`.cast`) as `name`, `kind` (`screenshot`, `recording`, `serial_cast`), `device`, `bytes` and `modified`, newest first, with `total`, `next_offset` (null on the last page) and the folders searched. A file is listed only when its name has the exact shape a tool gives its own output, it is a regular file (never a symlink), and it is finished: a recording still being written, an MP4 still being encoded (its `.mjpeg` still exists) and a cast a live terminal is writing are not listed. `fetch` looks one bare name up in that listing (it is never joined onto a path, so a traversal or symlink cannot name a file outside the folders) and returns a fresh handoff url with its `sha256`. Refusals: `capture_name_required`, `capture_name_invalid`, `capture_not_found`.

### Write tools

All write tools below refuse with `confirmation_required: ...` and send nothing unless `confirmed` is the JSON boolean `true`. The check runs before the vault is read, a connection is opened or the lock is taken.

#### amt_power

Parameters: `action` (default `restart`), `device`, `confirmed`.
Calls `CIM_PowerManagementService.RequestPowerStateChange` with the state below and a `ManagedElement` reference to `CIM_ComputerSystem` `ManagedSystem`.

| Action | State | Graceful |
|--------|:-----:|:--------:|
| `restart` (default) | 14 | yes |
| `shutdown` | 12 | yes |
| `power_cycle` | 15 | yes |
| `shutdown_hard_graceful` | 13 | yes |
| `power_cycle_hard_graceful` | 16 | yes |
| `power_on` | 2 | yes |
| `sleep_light` | 3 | yes |
| `sleep_deep` | 4 | yes |
| `hibernate` | 7 | yes |
| `immediate_power_cycle` | 5 | **no** |
| `immediate_shutdown` | 8 | **no** |
| `hard_power_off` | 6 | **no** |
| `hard_power_cycle` | 9 | **no** |
| `hard_reset` | 10 | **no** |
| `nmi` | 11 | **no** |

The default is graceful. A hard reset is sent only when `hard_reset` is named, and a graceful request that AMT refuses is never downgraded. Before sending, the tool reads `AvailableRequestedPowerStates` and refuses an action AMT does not offer now (`power_state_not_available`, naming the actions it does offer; a boot menu offers only `hard_reset` and `nmi`). If that list cannot be read, AMT decides. Once the request is sent nothing below it raises: the result carries `applied` (`true`, or `"unknown"` when the reply had no `ReturnValue`), `requested_state`, `graceful`, `return_value`, and a readback (`readback: "ok"` with `power_state_after`, or `readback: "unavailable"`). AMT applies the change asynchronously, so `power_state_after` can still show the old state. To boot into firmware setup or PXE, call `amt_set_next_boot` first.

#### amt_set_next_boot

Parameters: `target` (required), `options`, `device`, `confirmed`.
Sets a one-time boot target; it does not restart the host. Targets (an allowlist; nothing else is accepted): `bios_setup`, `pxe`, `hard_disk`, `cd_ider`, `floppy_ider`, `diagnostic`, `clear`.

Sequence (`amt_write.set_next_boot`):
1. Get `AMT_BootSettingData`.
2. `CIM_BootConfigSetting.ChangeBootOrder` with no source (clears the boot order).
3. Put `AMT_BootSettingData`: the device's current scalar fields minus the read-only and secret ones (`BOOT_READ_ONLY`), with **every** boot-option field forced to its safe default and then only this call's target flags and options applied. Nothing from an earlier request carries over.
4. `CIM_BootService.SetBootConfigRole(1)`, the step that activates the request (a bare Put is ignored). Not sent for `clear`.
5. For `pxe`, `hard_disk` and `diagnostic` only, `ChangeBootOrder` with the named boot source. IDE-R and firmware-setup boots name no source (`UseIDER` / `IDERBootDevice` / `BIOSSetup` pick them).
6. Get again and compare. A difference raises `boot_readback_mismatch:<fields>:completed=<steps>`.

A failed step raises `boot_sequence_failed:completed=<steps>:<cause>`, naming what already happened. `clear` resets every option to its default and sets no boot source and no role; the exact disarm call is not proven live (tagged `TODO verify-live`).

`options` maps these names to values (booleans unless noted): `lock_power_button`, `lock_reset_button`, `lock_sleep_button`, `lock_keyboard`, `user_password_bypass`, `forced_progress_events`, `firmware_verbosity` (integer 0 to 3), `configuration_data_reset`, `bios_pause`, `reflash_bios`, `use_safe_mode`, `use_sol`, `use_ider`, `secure_erase`, `enforce_secure_boot`, `boot_media_index` (integer 0 to 255). `secure_erase`, `reflash_bios`, `configuration_data_reset`, `lock_power_button` and `lock_reset_button` can erase or overwrite data or lock the host's controls at that boot; the confirmation text names them. Platform Erase is not a typed option: it is in the read-only drop set and is reachable only through `amt_wsman_invoke`.

#### amt_console_input

Parameters: `actions` (required, 1 to 50), `expect`, `device`, `confirmed`.
Drives the KVM console: ordered steps, paced 0.25 s apart, then a screenshot. By default it acts on whatever is on screen with no check, so look first with `amt_screenshot`. Each step is an object with a `kind` (the model forbids extra fields):

| `kind` | Fields | Limits |
|--------|--------|--------|
| `click` | `x`, `y` (0 to 1, ratio of the console size), `button` (`left`, `middle`, `right`) | |
| `text` | `text` | 1 to 500 printable ASCII characters (0x20 to 0x7E). Never a credential. |
| `key` | `key`, optional `modifiers` (`ctrl`, `alt`, `shift`, `win`) | A key name (`enter`, `tab`, `escape`, `delete`, `backspace`, `space`, `home`, `end`, arrows, `f1` to `f12`, `pageup`, `pagedown`, `insert`, `print_screen`, `capslock`) or one printable character. Modifiers are released in a `finally`. |
| `macro` | `macro` | One of the 25 names below. `ctrl_alt_del` uses the engine's firmware-injected sequence. |
| `wait` | `seconds` | Greater than 0 and at most 10 each; at most 30 in total. |
| `secret` | `secret` (`host_user` or `host_password`) | Types the device's vaulted host account name or password, read in process, never returned. |

Macros: `ctrl_alt_del`, `alt_tab`, `alt_f4`, `alt_esc`, `alt_enter`, `alt_space`, `ctrl_esc`, `ctrl_shift_esc`, `ctrl_a`, `ctrl_c`, `ctrl_v`, `ctrl_x`, `ctrl_z`, `win`, `win_r`, `win_d`, `win_e`, `win_l`, `win_x`, `win_tab`, `print_screen`, `f2`, `f10`, `f12`, `delete`. (This is a different list from MeshCommander's 25 key macros in the parity manifest; those are covered with `key` steps and modifiers.)

The whole list is validated before any session opens, so a malformed request sends nothing. **`expect`** is an optional list of classifier labels (`windows-signin`, `desktop`, `lock`, `bios-setup`, `linux-console`, `grub`, `text-installer`, `mok-manager`; `unknown` and an empty list are refused). When given, the first frame is classified after the session opens and before any step; any other label, or a frame OCR could not read, aborts with `screen_not_expected:saw=<label>:expected=<labels>` or `screen_not_identified:<problem>:expected=<labels>`, having sent no key, click or text. A `secret` step beside `bios-setup`, `grub`, `text-installer` or `mok-manager` in `expect` is refused before the session opens (`secret_step_refused_for_boot_screen`): no credential is ever typed into a boot or firmware screen. The result has `steps_run`, `kinds`, `screen_label` (with `expect`) and `screenshot`; typed text and secrets are never echoed. An engine error during a step is reported as `console_input_failed:step_<i>:<kind>` without the offending character. Windows sign-in goes through `amt_remote_logon`, not this tool.

#### amt_sol

Parameters: `text` (default empty = only read), `read_seconds` (greater than 0, at most 15; default 3), `max_bytes` (1 to 16384; default 4096), `device`, `confirmed`.
Sends ASCII text (at most 1024 characters, sent verbatim) over Serial-over-LAN and returns a bounded read window. Enter is a real CR or LF character; a backslash followed by `r` reaches a getty as two typed characters. If an `amt_serial_link` terminal is live, the tool sends and reads through it (`shared_terminal: true`) so the viewer sees the exchange; otherwise it opens its own pinned SOL session and closes it. The serial port must be enabled in the host firmware and SOL enabled in AMT (`amt_configure area=features`). Returns `sent_chars`, `window_seconds`, `bytes`, `truncated` and `output`. Never send a credential.

#### amt_ider

Parameters: `action` (`mount`, `unmount`, `status`), `iso_path`, `floppy_path`, `start` (`next_boot` default, `graceful`, `now`), `device`, `confirmed`.
IDE redirection: serves read-only images from the image root to the host. `status` needs no confirmation or lock. `mount` opens an IDE-R session, starts a serving thread and **holds the host's IDE-R session until `unmount`** (no time limit; KVM keeps working beside it). Images must be `.iso` (CD) or `.img` (floppy), resolve inside the image root (no `..`, no symlink: `O_NOFOLLOW`), be regular, non-empty files, and a multiple of 512 bytes. `start` maps to AMT's start mode: `next_boot` (0x08, waits for the host's next boot), `graceful` (0x10) and `now` (0x18); the last two reset the host at once. A second mount for a device is refused (`ider_already_mounted`). `unmount` waits up to 10 s for the serving thread; if it will not stop it raises `ider_unmount_timeout` and the session is **still held**, so call it again or check `status`. AMT drops an IDE-R session after about 60 s of client silence, so an idle serve loop sends a keep-alive ping every 10 s. Mounts live in process memory; a restart ends them. To boot from a mounted ISO, call `amt_set_next_boot` with `cd_ider`.

#### amt_images

Parameters: `action` (default `list`), `root`, `url`, `name`, `path`, `new_name`, `size_bytes`, `sha256`, `overwrite`, `confirmed`. Touches no host.

| Action | Needs `confirmed` | What it does |
|--------|:--:|--------------|
| `list` | no | The image root, every `.iso` / `.img` under it (`path`, `bytes`, `mib`, `mountable`), background downloads, and uploads (`open`, `finished`, `max_bytes`). If the root is unset or invalid it returns an `error` field with empty lists. |
| `verify` | no | SHA-256 of one image, compared with `sha256` when given. |
| `set_root` | yes | Points the image root at a directory (created if missing) and persists it. |
| `fetch` | yes | Starts a background download of an http(s) `url` into the root (`name` defaults to the url's file name; optional `sha256` check; `overwrite`). The server fetches from its own network position. Poll `list` for progress. A mismatch deletes the part file and reports failure. |
| `upload` | yes | Mints a one-time `PUT` url for a plain `.iso` / `.img` `name` of exactly `size_bytes` (section 8). |
| `rename` | yes | Renames an image within its folder with a hard link, so it never replaces an existing file. |
| `delete` | yes | Deletes one image. |

The root is whatever `set_root` stored in `settings.json` (in `AMT_STATE_DIR`, default `~/.amt-mcp`), else the `AMT_IMAGE_ROOT` variable; unset is `ider_image_root_unset`. `rename`, `delete` and an overwriting `fetch` or `upload` are refused while the image is mounted (matched by the mount's open descriptor's inode), downloading or uploading (`ider_<action>_image_busy:<name>:<reason>`). A name must be plain: no directory part, no leading dot, extension `.iso` or `.img`.

#### amt_configure

Parameters: `area` (`network`, `internet`, `security`, `users`, `kvm`, `features`), `changes`, `device`, `confirmed`.
Writes **one** area, with a readback. Only the fields listed here can change; others are refused (`unknown_field`). No listed field can lock the host out of AMT.

| Area | Class | Writable fields (kind) |
|------|-------|------------------------|
| `network` | `AMT_GeneralSettings` | `HostName`, `DomainName` (string); `SharedFQDN`, `PingResponseEnabled`, `RmcpPingResponseEnabled`, `DDNSUpdateEnabled` (bool); `DDNSPeriodicUpdateInterval`, `DDNSTTL`, `IdleWakeTimeout` (int) |
| `internet` | `AMT_EnvironmentDetectionSettingData` | `DetectionAlgorithm` (int), `DetectionStrings` (list of strings, 1 to 16) |
| `security` | `AMT_TLSSettingData` (selector `InstanceID: Intel(r) AMT 802.3 TLS Settings`) | `AcceptNonSecureConnections` (bool) |
| `kvm` | `IPS_KVMRedirectionSettingData` | `Is5900PortEnabled`, `OptInPolicy` (bool); `SessionTimeout` (int) |
| `features` | `AMT_RedirectionService`, `CIM_KVMRedirectionSAP` | `ider_enabled`, `sol_enabled`, `kvm_enabled` (bool), via `RequestStateChange` |
| `users` | `AMT_AuthorizationService` | `action` (`add` or `remove`), `username` (`[A-Za-z0-9_.@-]{1,16}`, never `admin`), and for add `access_permission` (0 to 2) and `realms` (list of 0 to 31) |

Strings are printable and at most 256 characters; ints are 0 to 2^32-1. For the Put areas the tool reads the whole instance, merges the change, writes the merged instance and reads it back, and raises if a requested field differs (`configure_readback_mismatch`) or any other field changed (`configure_collateral_change`, naming the old values). An instance holding a field the tool cannot echo faithfully (nested, or a credential other than the vaulted KVM password) is refused before anything is sent (`configure_instance_not_round_trippable`). Returns `previous` (the old values, for a revert), `readback` and `verified_unchanged`. For `users`, revert with the opposite action. The KVM password for `area=kvm` comes from `<amt_vault_key>-rfb`; a new user's password from `<device>-amt-user-<username>` (the operator vaults it first), sent only as an MD5 Digest hash computed with the device's `DigestRealm`. The confirmation text names the risky changes: `OptInPolicy=false` (user consent off), `Is5900PortEnabled=true` (plaintext VNC port), `AcceptNonSecureConnections=true`, and enabling IDE-R, SOL or KVM. `agent_presence`, `system_defense`, `subscriptions` and `wake_alarms` are refused (`area_not_writable_by_this_tool`).

#### amt_wsman_invoke

Parameters: `operation` (`put`, `create`, `delete`, `invoke`), `class_name`, `method` (invoke only), `fields`, `selectors`, `device`, `confirmed`.
The general write primitive (MeshCommander's Script Editor). It has **no per-class safeguard** beyond the confirmation and can reach `AMT_SetupAndConfigurationService.Unprovision`, port, TLS and certificate changes, user and realm changes, and power actions. Prefer `amt_power`, `amt_set_next_boot` and `amt_configure`. A Put may whole-replace the instance and reset fields you omit: Get the full instance with `amt_wsman_get`, merge, then Put.
Rules: `method` is required for `invoke` and refused otherwise; `delete` takes selectors only. Field values are text, numbers, booleans or lists of those (at most 64 fields, 4096 characters per value, 64 list items); a reference parameter is `{"epr": {"class": "CIM_X", "selectors": {...}}}` and no other nested object is accepted. Credential-named fields are refused at any depth. A non-zero `ReturnValue` or a SOAP Fault raises; an `invoke` reply with no `ReturnValue` returns `return_value: "unknown"` with a note, because the request was sent and its outcome is not known.

#### amt_remote_logon and amt_remote_logoff

Parameters: `device`, `confirmed`, `console` (`kvm` default or `serial`).
Composite tools that sign the host's console in or out with the vaulted credential, titled "Windows" but also handling a Linux text console. They type only into a positively identified screen and otherwise abort. The full flows, the classifier and the abort reasons are in section 9. Each takes exactly one attempt and never retries. Results carry `aborted`, `logged_in` or `logged_off` with a `*_basis` statement of how it was judged, the OCR backend and yes/no findings, and a result `screenshot` (KVM). They never return recognized text, the password or its length. The host must have a `host_vault_key` for logon.

#### amt_mirror_link and amt_serial_link

Parameters (mirror): `action` (`start`, `stop`, `status`, `record_start`, `record_stop`; default `status`), `device`, `bind` (default `127.0.0.1`), `port` (default 8766; 0 picks a free one), `fps` (1 to 30, default 15), `quality` (JPEG 10 to 95, default 70), `record_on_start`, `directory`, `confirmed`. The serial tool has the same shape without `fps` and `quality`.
`start` and `record_start` need `confirmed`; `stop`, `status` and `record_stop` do not. `start` opens the device's KVM (or SOL) session once and serves view-only `urls` and `control_urls` (a second token whose page can drive the host). `stop` releases the session. `directory` applies to `record_start` and is persisted as the recording folder. **Quirk:** `status` with the default device lists every live mirror (or terminal) with a `server` block; with any other `device` it returns that device's entry, or `{device, live: false}`. Everything else about the viewers is in section 7.

#### amt_device_manage and amt_identity_manage

Covered in sections 4 and 5. Neither takes the per-device session lock.

---

## 7. Live viewers

`amt_mirror_link` and `amt_serial_link` give an operator a browser view of the console while an agent works. Both are served by **one** HTTP server (`http.server.ThreadingHTTPServer` in a daemon thread) started by the first `start` and stopped when the last mirror and terminal stop (`_stop_server_if_idle`).

### Shared server, bind and port

- Default bind `127.0.0.1`, default port 8766 (`DEFAULT_BIND`, `DEFAULT_PORT`); `bind=0.0.0.0` lets the LAN watch. The pages are plain HTTP: bind to loopback or a trusted LAN, and put a TLS front in front of anything wider. What an operator types on a control page, a login password included, crosses that HTTP.
- One server carries every live mirror and terminal. A `start` with a different bind or port while any is live is refused (`viewer_server_in_use`); with none live the old server is replaced after the new one has bound.
- **`urls` and `control_urls`.** Each lists viewer addresses. With `AMT_VIEWER_PUBLIC_BASE_URL` set (for example `https://amt-viewer.example.com`) and a bind of `0.0.0.0` or `::`, the public front url is listed first; a loopback-bound viewer gets no front url because the front cannot reach it. Direct urls follow: `127.0.0.1`, and for a wildcard bind the address this host uses toward the device.
- Behind a reverse proxy, streams must send no buffering (`X-Accel-Buffering: no`); the MJPEG and SSE responses already send it.

### Tokens

Each mirror and each terminal has two random tokens (`secrets.token_urlsafe(24)`): a **view** token and a **control** token. Nothing is served without a valid token (a miss is a 404 that does not say whether a token exists; tokens are compared with `hmac.compare_digest` against every live token). The view token never reaches `input`, `ider`, `power`, `boot`, `media.json` or `power.json`; those answer only the control token. The viewer server itself has no bearer: the token in the url is the only key, so share a url only with whoever should hold it.

### Every viewer response

`Referrer-Policy: no-referrer` (a token in the page url never leaves in a Referer) and `Content-Security-Policy: frame-ancestors <origin>`, where the origin is `AMT_CONSOLE_ORIGIN` when it is a plain `http(s)://host[:port]` origin, else `'none'` (no framing). A malformed value is never copied into a header. Responses are `Cache-Control: no-store`. The server writes no request log.

### Display mirror (`/m/<token>/`)

| Route | Method | Token | Purpose |
|-------|--------|-------|---------|
| `/m/<token>/` | GET | view or control | The page. A missing trailing slash gets a 301 that keeps the query (`?embed=1` survives). |
| `stream` | GET | either | MJPEG (`multipart/x-mixed-replace`). |
| `frame.jpg` | GET | either | The latest frame (503 `no frame yet` before the first). |
| `status.json` | GET | either | The mirror's state (below). |
| `media.json` | GET | control | Mountable ISO images under the image root. |
| `power.json` | GET | control | Power state, offered actions and next-boot settings (two WS-MAN reads; 502 if AMT is unreachable). |
| `input` | POST | control | A batch of keyboard and pointer events (below). |
| `ider` | POST | control | Mount or unmount: runs the registered `amt_ider` tool. |
| `power` | POST | control | One named `amt_power` action: runs the registered tool. |
| `boot` | POST | control | `{target, then?}`: runs `amt_set_next_boot`, then optionally `amt_power`. |
| `record` | POST | either | `?on=1` starts, otherwise stops, recording. |

**Frames.** One thread owns the session: one full frame, then incremental updates (`grab_update` with a 30 ms wait slice, so browser input waits at most one slice), JPEG-encoded at up to `fps`. Every socket call is serialized on the mirror's lock because a TLS socket is not thread-safe. A shared session never sends its own full-frame request, because AMT answers it only after the outstanding incremental one, which waits for a screen change; the shared wrapper reads the live framebuffer instead.

**Idle keepalive versus the AMT session timeout.** AMT ends a KVM session when the client has sent no keyboard or mouse event for the KVM `SessionTimeout` (a device setting, readable as `redirection.kvm.session_timeout` from `amt_status`; the reference host measured 3 minutes), whatever the screen does. An idle mirror therefore sends a no-op Shift_R release (a key that is not held) every 60 s (`KVM_KEEPALIVE_SECONDS`). Any input the agent or the page sends resets that clock.

**Input.** `POST input` takes `{"events": [...]}` of 1 to 500 events, body at most 64 KiB. An event is `["k", keysym, 0|1]` (key up or down) or `["p", x, y, buttonmask]`. The whole batch is validated before any event is sent; pointer coordinates are clamped to the current screen size.

**Power, boot and media from the page.** These routes do not call `amt_write` directly. `amt_mirror.run_tool` runs the registered tool coroutine on the server's event loop (recorded by `remember_tool_loop` whenever a viewer tool runs), so a click takes the same per-device lock, validation and refusals as an agent's call. Mounts from the page are always `start=next_boot`, never a reset. In the page, any action that resets, powers off or interrupts the host needs a second click within 4 s, and the power pill is polled every 15 s. Errors map to 409 (a `ValueError` refusal) or 502 (an AMT or TLS failure).

**Recording.** `record_start` writes frames to `amt-<device>-<UTC stamp>.mjpeg` with a `.times` sidecar (crash-safe). On stop, `ffmpeg` encodes an H.264 `.mp4` (yuv420p, `+faststart`, variable frame rate at the real frame times; 900 s timeout) in a background thread, and the raw pair is deleted only after the MP4 is written. Without `ffmpeg`, or if encoding fails, the raw pair is kept and `last_recording.encoding` says why (`ffmpeg_missing`, `ffmpeg_failed`, `recording_empty`). The finished MP4 is offered as a handoff url. The folder is `~/amt-recordings` unless a `directory` was given to `record_start` (persisted in `settings.json` as `recording_dir`).

**`status.json` / `status`.** `device`, `live`, `error`, `fps`, `frames`, `viewers`, `in_flight`, `last_frame_age_s`, `uptime_s`, `width`, `height`, `recording`, `recording_dir`, `hostname`, `ider` (the mount status), `last_recording`; the tool's `status` adds `urls` and `control_urls`. **`in_flight`** is `null`, or `{tool, started_at}` for the oldest tool call now using the shared session: the tool name and start time only, never arguments (`unknown` when the call did not come through the gated dispatch). It is set by `amt_tools.InFlight` between a shared session's open and close. The console uses it to show that an agent is typing.

### Serial terminal (`/s/<token>/`)

| Route | Method | Token | Purpose |
|-------|--------|-------|---------|
| `/s/<token>/` | GET | either | The page (xterm.js, vendored). |
| `events` | GET | either | Server-sent events (below). |
| `status.json` | GET | either | State: `bytes_received`, `bytes_sent`, `scrollback_bytes`, `viewers`, `in_flight`, `last_output_age_s`, `last_input_age_s`, `recording`, `recording_dir`, `last_recording`. |
| `xterm.js`, `xterm.css`, `addon-fit.js` | GET | either | The vendored assets from `vendor/xterm/` (never loaded from a CDN). |
| `input` | POST | control | `{"data": "<text>"}`, at most 4096 bytes of UTF-8 per request (413 `input_too_long`). |
| `record` | POST | either | `?on=1` starts, otherwise stops, recording. |

- **One SOL session per device.** A reader thread pumps the session 50 ms per read under the socket lock, keeps a **256 KiB** scrollback, and sends AMT's SOL keepalive every 2 s. A viewer that joins late gets the last 256 KiB.
- **SSE and resume.** `events` sends `retry: 2000`, then `out` events whose `data` is `{"d": "<base64 bytes>", "gap": <bool>}` and whose `id` is the next stream offset, so an `EventSource` reconnect (`Last-Event-ID`) resumes where it left off. `gap: true` means scrollback no longer reaches the requested offset. An idle stream sends a `: idle` comment every 15 s and ends with `event: end` when the session ends.
- **Recording** writes an asciinema v2 `.cast` (`<device>-serial-<UTC stamp>.cast`, 120x36 header), opened exclusively so an earlier recording is never overwritten. A write error ends the recording and is reported without taking the console down.
- While a terminal is live, `amt_sol` and the serial logon use it instead of opening a second session.

### Embed mode (`?embed=1`)

A url with `?embed=1` renders the page for the management console's frame. `amt_mirror.render_page` deletes the regions marked `standalone` from the page source before serving it, so the embed page carries no code that reaches those routes: Capture (Record, and the Screenshot download), Media, Power and Boot on the mirror; Capture (Record, Download .txt) on the terminal. View and Control remain. Besides, a `POST` to `record`, `ider`, `power` or `boot` carrying `embed=1` is refused with 403 `embed_mode`; recording from the console is the tools' `record_start` / `record_stop`. (`GET media.json` and `GET power.json` are control-token routes and are not embed-gated; the embed page simply never calls them.) `input` is allowed in embed mode.

---

## 8. Files in and out of the server

Three one-time-url routes carry files and values that must not pass through MCP. Each is a custom route on the MCP app, outside the bearer gate and the Host/Origin allowlist, keyed only by a 256-bit random token (`secrets.token_urlsafe(32)`, 43 characters, matched against `[A-Za-z0-9_-]{43}`). A token is minted only into a bearer-gated tool result, is claimed by the first request that presents it, and expires unused after 900 seconds (`TTL_SECONDS`). All answer `Cache-Control: no-store`, and an unknown, malformed, used or expired token is a plain 404. All three need `AMT_PUBLIC_BASE_URL` (a `scheme://host[:port]` origin) to be offered at all.

### Download handoffs: `GET /handoffs/<token>`

Over HTTP, the server's disk is not the caller's, so a returned path is useless. With `AMT_PUBLIC_BASE_URL` set, a tool that writes a file also returns `url`, `sha256`, `expires_in_s` (900) and `url_note`; without it, a `path_note` says to set the variable. Files that get a handoff: screenshots (`amt_screenshot` and the result frame of `amt_console_input`, `amt_remote_logon` and `amt_remote_logoff`), a finished mirror MP4, a finished serial cast, and any file named in `amt_captures action=fetch` (which mints a fresh url each time).

- The handoff is a **hard link** (a copy if linking fails) in `<AMT_STATE_DIR or ~/.amt-mcp>/handoffs`, created 0700 and refused if it is a symlink, not a directory or owned by another user (`handoff_dir_unsafe`). A fetch claims the link by an atomic rename, serves it, then deletes the link: it never deletes the original. A second or concurrent fetch finds nothing. Expired, unfetched handoffs are reaped when the next one is offered.
- The route accepts only `GET`.

### Image uploads: `PUT /uploads/<token>`

`amt_images action=upload` validates a plain `.iso` / `.img` name, an exact `size_bytes` and an optional SHA-256, then mints the url (`PUT` or `POST`, `curl -T <file> <url>`). Refusals before minting: no public base URL (`ider_upload_needs_AMT_PUBLIC_BASE_URL`), a size over `AMT_UPLOAD_MAX_BYTES` (default 16 GiB; a non-numeric or non-positive value falls back to the default; `ider_upload_too_large`), less than the size plus **1 GiB** free on the image volume (`ider_upload_no_room_on_the_image_volume`), an existing file without `overwrite` (`ider_upload_exists`), a busy destination, and a second open offer for the same file.

The body streams to a hidden `.<name>.upload` file beside the destination. It must be exactly the declared size (checked against `Content-Length` first, then while streaming) and match the SHA-256 when one was given. Any failure deletes the part file and answers 400 with the reason (`content_length_not_declared_size`, `body_larger_than_declared_size`, `body_shorter_than_declared_size`, `sha256_mismatch`, `destination_busy`). A good upload is moved into place with `os.replace` after the owner's busy check passes once more, and answers 201 `{name, bytes, sha256}`. Offers live in memory, so a restart drops them; `amt_images list` shows open offers and the last 20 results, never a token.

### Identity intake: `PUT /intake/<token>`

Minted by `amt_identity_manage action=intake` for one vault entry (section 5). The body is the secret: UTF-8, at most **4096 bytes**, no line break or NUL. It is read in chunks (stopping at the cap), handed to the vault CLI on stdin and dropped. The offer is consumed **before** the body is judged, so every later refusal burns it: 413 `value_larger_than_4096_bytes`, 400 `value_empty` / `value_not_utf8` / `value_has_a_line_break_or_nul`, 503 `vault_write_failed:<name>: nothing was stored`, 500 `intake_failed:<ExceptionType>` (the type only, because the text could carry the value). One refusal leaves the offer open: if the vault cannot be written (`vault_writable()` is false), the route answers 503 `vault_not_writable: nothing was stored` before reading the body. Success is 201 `{name, stored: true}`. No log line, response or exception carries the value. The shipped compose file mounts the server's vault read-only, so intake answers 503 there until the mount is made writable.

### CORS

The upload and intake routes answer a CORS preflight and add `Access-Control-Allow-Origin` for **one** origin: the request's `Origin` when it equals `AMT_CONSOLE_ORIGIN` (validated as for `frame-ancestors`; unset or malformed means no origin matches). Allowed methods `PUT, POST, OPTIONS`, header `Content-Type`, max age 600, `Vary: Origin`, never credentials. Any other origin gets no CORS header. The download route has no CORS.

### Directories the server writes

| What | Where | Rules |
|------|-------|-------|
| Screenshots | `AMT_SHOT_DIR`, default `<tempdir>/amt-mcp-shots` | Created 0700. A symlink, a non-directory or a directory owned by another user is refused (`shot_dir_unsafe:...`). The default directory is tightened to 0700 if it was looser; a directory named by `AMT_SHOT_DIR` is not re-chmodded. Each PNG is created with `O_CREAT`, `O_EXCL` and `O_NOFOLLOW` and mode 0600 and a name `amt-<device>-<UTC stamp>Z-<16 hex>.png`. |
| Handoffs | `<AMT_STATE_DIR or ~/.amt-mcp>/handoffs` | 0700, owner-checked, as above. |
| Settings | `<AMT_STATE_DIR or ~/.amt-mcp>/settings.json` | `image_root` and `recording_dir`. A corrupt file is reported (`amt_settings_file_unreadable`), never ignored. |
| Recordings | `~/amt-recordings` or the persisted `recording_dir` | Mirror `.mjpeg`/`.times`/`.mp4` and serial `.cast`. |
| Images | the image root | Written by `fetch` and `upload`; read-only to mounts. |

---

## 9. Screen classification and logon safety

### `classify_screen`

`amt_tools.classify_screen(frame, user="", ocr=True)` is the **single source of truth for what the console shows**. It accepts a PNG (bytes), a `(framebuffer, width, height)` tuple or an object with `fb`, `width`, `height`, and returns `{"label": ..., "markers": {...}}`. The logon, logoff and `expect` gates derive their decisions from the label and hold no screen logic of their own. `markers` are yes/no findings only (geometry, taskbar, blank, OCR backend name, which signals matched); recognized text never leaves the function, because the sign-in tile holds the account name.

| Label | Meaning |
|-------|---------|
| `windows-signin` | The vaulted account's name as a centred tile with a `Password` field below it. |
| `desktop` | Windows-sized frame, a taskbar, readable text, no foreign marker, no sign-in furniture. |
| `lock` | No taskbar, no sign-in furniture, and a clock and a long date mid-screen (away from the tray corner). |
| `grub` | GRUB's own menu text (`GNU GRUB`, `GRUB Command line`, `entry is highlighted`). |
| `text-installer` | The Debian text installer's dialogs (`[!!]` / `[!]` titles, `<Go Back>`, `<Continue>`, `<Tab> moves`). |
| `mok-manager` | shim's MOK screens (`MOK management`, `Enroll MOK`, `Shim UEFI key`). |
| `bios-setup` | A sub-Windows frame (below 1024x720: 640x480 BIOS/POST, 800x600) that no boot signature claims. A geometry fallback, not proof of a BIOS; it also covers 800x600 frames nothing recognizes. |
| `linux-console` | A text console: a console marker word (`login`, `kernel`, `tty<N>`, `linux`, `ubuntu`, `debian`) or a shell prompt, and no taskbar. |
| `unknown` | Everything else, and the fail-closed answer: no OCR backend, a recognizer error, no text, an unreadable frame, a frame matching two boot signatures, UEFI shells and firmware boot-device menus (no real capture of one exists, so no signature was invented). |

Rule order (`_label_for`, most specific first): (1) sub-Windows geometry gives the boot label OCR found, else `bios-setup`; (2) an unreadable frame or an OCR problem gives `unknown`; (3) exactly one boot signature and no taskbar gives that label; (4) a foreign marker or a shell prompt gives `linux-console` when there is a console marker or a shell prompt and no taskbar, else `unknown`; (5) with a taskbar, `unknown` if sign-in furniture shows, else `desktop`; (6) a positioned tile and field gives `windows-signin`; (7) clock plus date and no furniture gives `lock`; (8) `unknown`. A boot label is claimed only when exactly one of the three signatures matches.

**Structural detectors** run first and cheaply (`classify_screen(..., ocr=False)` never invokes a recognizer): Windows geometry (at least 1024x720), the taskbar detector (a horizontal edge over at least 85% of 96 sampled columns in the bottom band, above a strip that is mostly one colour), and the blank detector (99% of a 48x48 grid within tolerance of the median colour). They are calibrated on real frames (below).

### OCR backends

`ocr_fragments` returns `(backend name, [Fragment(text, cx, cy)])`. Backends, in order (`OCR_BACKENDS`): `ocrmac` (Apple Vision, macOS development nodes), then `tesseract` (the binary plus Pillow; the container image). A backend that is **not installed** is skipped; one that is installed and **fails** raises, with no silent fall-through to a second opinion. None usable gives `OcrUnavailable`, which the gates turn into `ocr_unavailable`. The tesseract path reduces the frame to black text on white (luma above 150 is text), doubles its size, discards words below confidence 20, times out after 30 s, and reads a mostly-black frame (at least 95% near-black pixels, a text console) as one block (`--psm 6`) because sparse mode (`--psm 11`) dropped the colon of `login:` on a live frame.

### Calibration on real frames

Thresholds and signatures are calibrated on real captures and retuned only against real captures. `tests/real_frames/` holds 16 console captures kept in the repo (GRUB menus, installer dialogs, MOK screens, a Debian tty login, and negatives: BIOS setup pages, an installer progress bar mentioning GRUB, a Windows desktop). No frame with a password prompt or typed text was kept. Frames that show an account (Windows sign-in, lock and desktop captures, further Debian tty frames) are not in the repo: `AMT_LOCAL_FRAMES` names a local folder holding them and `AMT_LOCAL_FRAMES_USER` the account their tile shows (default `jdoe`); without them those tests skip (section 13). A UEFI shell and a firmware boot-device menu are `unknown` until a real capture exists.

### The logon flow (`amt_remote_logon`)

Common start: confirm; pin; the private screenshot directory; the AMT password; the host credential from `host_vault_key` (a missing or malformed entry is `no_host_credential:<device>` / `vault_bad_credential_shape:<key>`, before any session opens); one WS-MAN read of the power state, which must be `on` (`host_not_powered_on`, with no session opened). `console="serial"` then takes the serial path (below); otherwise the KVM path.

**KVM, Windows path** (the first frame is not OCR-gated, because the usual start is the lock screen, which only a wake turns into the sign-in):
1. Open the session; require Windows geometry and no taskbar (a taskbar means already logged in).
2. Classify the first frame. If it is `linux-console`, go to the Linux path before sending anything (the wake's Esc would land in a getty line).
3. Wake: click at (0.5, 0.5) and press Esc, wait 2.5 s. While the frame is still `lock`, re-read up to 3 more times, 2 s apart, sending nothing.
4. The frame must now pass the structural checks plus blank **and** the OCR match: `windows-signin`.
5. Click the password field (0.5, 0.575), Ctrl+A, Delete (never the 64-Backspace sweep).
6. Re-read and re-check the frame right before typing. Only then type the password once and press Enter.
7. Up to 6 checks, 3 s apart, until at least 35% of the sign-in region has changed. `logged_in` is a heuristic on that region (`logged_in_basis` says so) and is `null` when it cannot be judged.

**KVM, Linux text console** (`_console_logon`; taken only when the first frame is `linux-console`): the last text line decides. A getty `login:` prompt proceeds: Ctrl+U (a tty's line kill; Ctrl+A is a literal there), the account name, Enter; then the password only after a `Password:` prompt is read (3 reads, 2 s apart; otherwise abort `password_prompt_not_identified` with `typed_nothing: false`, `account_typed: true`, `password_typed: false`). After the password, up to 8 reads, 2 s apart. `logged_in` is true on a shell prompt, false on `Login incorrect` after the last `Password:` line or a new login prompt, `null` otherwise. Prompts are matched on how the line ends, never on the hostname (both recognizers misread its `0`); `Last login:` is not a prompt; a line that starts like a shell prompt is never a getty prompt. The blank check does not apply to a console.

**Serial** (`console="serial"`, `amt_serial.console_logon`): shares a live serial terminal (the viewer watches) or opens its own SOL session. It reads first and sends one Enter only when nothing readable came back; a `Password:` prompt is never answered (login(1) drops it after 60 s, so an Enter into a silent fresh session is the one residual). The same prompt classifier judges the text (`enter_sent_to_find_prompt` in the result). No screenshot.

**Already logged in.** A console the classifier labels `desktop` (on the first frame or the frame after the wake), or a Linux shell prompt, is the goal met, not an abort: `{aborted: false, already_logged_in: true, logged_in: true, typed_nothing: true}` with `logged_in_basis`. Nothing is typed or cleared. The frame right before typing is not given that exit (the field clear has already gone out), so a desktop there aborts `host_already_logged_in`.

### The logoff flow (`amt_remote_logoff`)

Same start (no host credential needed). **Windows:** the frame must be a Windows-sized `desktop` with a taskbar and no sign-in furniture; Win+R; after 1.5 s the bottom-left region must have changed by at least 5% (the Run dialog), else Esc and abort `run_dialog_not_detected`; type `logoff`, Enter; wait 2 s; return the result frame. **Linux console** (no taskbar and label `linux-console`): only a shell prompt on the last line proceeds: Ctrl+U, `exit`, Enter, then re-read until getty's login prompt is back (`logged_off` true; false if a shell prompt remains, such as a nested `sudo -i`; `null` otherwise). **Serial:** `exit` and Enter at a shell prompt.

### Abort reasons

An abort is `{"aborted": true, "reason": ..., "device": ..., "typed_nothing": true, "screenshot": ...}` plus a `note` for the non-obvious reasons and the yes/no findings. `typed_nothing` means no character or credential was typed; on the Windows logon path the wake's one click and Esc may already have been sent before a later check aborts.

| Reason | Where | Meaning |
|--------|-------|---------|
| `host_not_powered_on` | both | AMT power state is not `on`; no session opened (`screenshot` is null). |
| `not_windows_resolution` | both | Frame is below 1024x720 (BIOS, POST, boot software). |
| `screen_unreadable` | both | The frame could not be read. |
| `host_already_logged_in` | logon | A taskbar shows (unless the classifier confirms `desktop`, which is the no-op success). |
| `no_desktop_taskbar` | logoff | No taskbar (a Linux console is routed to the console logoff instead). |
| `screen_blank` | logon | The frame after the wake is one colour. |
| `ocr_unavailable` / `ocr_failed` / `ocr_no_text` | both | No usable OCR backend / the backend failed / it read no text. Fail closed. |
| `foreign_console_detected` | both | A non-Windows marker (`login`, GRUB, UEFI, BIOS, kernel, tty, Linux, Ubuntu, Debian) where Windows was expected. A Linux console is handled only when the **first** frame already shows it. |
| `signin_not_identified` | logon | Not the vaulted account's tile with a `Password` field below it. A PIN-only sign-in or an account tile whose display name differs from the vaulted `user` lands here. |
| `signin_screen_detected` | logoff | Sign-in furniture is showing. |
| `desktop_not_identified` | logoff | The frame was not positively a desktop. |
| `run_dialog_not_detected` | logoff | Win+R did not open the Run dialog. |
| `console_not_at_login_prompt` | logon, serial | The last line is not a fresh getty `login:` prompt. |
| `password_prompt_not_identified` | logon, serial | The account name was typed but no `Password:` prompt followed; the password was **not** typed. |
| `console_not_at_shell_prompt` | logoff, serial | The last line is not a shell prompt; `exit` would land in a login or password prompt. |

GRUB, the installer and the MOK manager fail the geometry check (800x600) and the foreign-marker veto, so both Windows paths abort on them.

---

## 10. Log decoding and the parity manifest

### `amt_logdecode`

Pure decoding, no I/O, ported from MeshCommander's decoders with two deliberate departures where MeshCommander's own code is wrong: the packet-filter handle is read as an unsigned 32-bit value (a JavaScript signed shift made its named-filter checks never match), and every lookup that would give `undefined` returns a labelled fallback (`Unknown ... code N`), so a record always has a description.

| Log | Fields `amt_logdecode` adds (raw codes and hex stay alongside) |
|-----|------|
| Event | `description`, `source` (the entity name), `severity`, `level`, `event_data` (8 bytes). `level` follows MeshCommander's icons: severity code below 8 is `info`, 8 to 15 `warning`, 16 and up `critical`. |
| Audit | `app`, `event`, `initiator_kind`, `extended_data` (null where MeshCommander has no reading, or the data is too short for its layout), `extended_data_hex`. The initiator is Digest user name, Kerberos SID, `Local` or `KVM Default Port`; an unknown initiator type raises so a misread time never follows. |

### `amt_parity`

`amt_parity.py` is the machine-readable answer to "what does this server cover of MeshCommander?". It is fixed against MeshCommander 0.9.5-a's `default.htm` (its own header names the line ranges and a hash prefix), and `tests/test_parity.py` pins the row names so a row cannot be removed or reworded silently.

- `TOOLS`: one row per tool (`kind` is `read`, `write`, `composite` or `mirror`; `write_guard` is true when it carries `confirmed`), with the MeshCommander surfaces it covers. `CENSUS` is 9 read, 10 write, 2 mirror, 2 composite.
- `PAGES` (18 pages: 17 mapped and the Files page as the one documented exception, since MeshCommander shows Files only over a software agent's WebRTC channel), `POWER_ENTRIES` (26), `BOOT_OPTIONS` (16), `KEY_MACROS` (25). Each item names its tools and `checks` that the test verifies against the live implementation tables, so a mapping cannot name an option, action or chord the code does not have. A `caveat` marks items reached only through `amt_wsman_invoke` or with a disclosed limit (for example Platform Erase and the OS power-saving entries).
- `ROUTES`: the `/m/<token>/` and `/s/<token>/` pages.
- `planned_rows()` lists every row still `planned`; `parity_status()` returns `complete` when none is and `partial` otherwise. Today it returns `complete`.

---

## 11. Environment variables

All configuration is environment. None is secret except the vault CLI's own variables (paths, not values). "When read" matters: a variable read at import needs the process restarted.

| Variable | Default | When read | Meaning |
|----------|---------|-----------|---------|
| `MCP_ADMIN_TOKEN_HASH` | none | each request; at startup | SHA-256 hex of the fleet bearer. Required over HTTP; unset or malformed refuses to start and refuses every call. |
| `MCP_CONSOLE_TOKEN_HASH` | none | each request | SHA-256 hex of the console's bearer. Unset or malformed: fleet only. |
| `AMT_TRANSPORT` | none (= HTTP) | each request | Set by `--transport`. Only `stdio` skips the gate. Never set it by hand. |
| `AMT_BIND_HOST` | `127.0.0.1` | startup | MCP listener address. The image sets `0.0.0.0`. |
| `AMT_PORT` | `8765` | startup | MCP listener port. |
| `AMT_ALLOWED_HOSTS` | loopback only | startup | Comma-separated extra Host names accepted behind an ingress. |
| `AMT_PUBLIC_BASE_URL` | none | each use | `scheme://host[:port]` clients reach the server at. Enables download, upload and intake urls. |
| `AMT_VIEWER_PUBLIC_BASE_URL` | none | each use | Public base url of the TLS front for the viewer pages; listed first in `urls` for a wildcard bind. |
| `AMT_CONSOLE_ORIGIN` | none (= `'none'`) | each response | The one origin that may frame a viewer page and the only CORS origin for uploads and intake. |
| `AMT_SECRETS_CLI` | none | **import** | Path of the vault CLI `amt_vault` runs. Unset: every vault call fails closed. |
| `NVAULT_VAULT_PATH`, `NVAULT_MASTER_KEY_FILE` | none | by the CLI child | Select a dedicated vault. `amt_vault` itself reads `NVAULT_VAULT_PATH` to judge whether the vault is writable. |
| `AMT_DEFAULT_DEVICE` | `my-server-1` | **import** | The device a call that names none acts on. |
| `AMT_DEVICES_FILE` | none (= built-in registry) | each call | JSON devices file that replaces the built-in registry; re-read when it changes. |
| `AMT_STATE_DIR` | `~/.amt-mcp` | each use | Holds `settings.json` and `handoffs/`. |
| `AMT_SHOT_DIR` | `<tempdir>/amt-mcp-shots` | each use | Screenshot directory. |
| `AMT_IMAGE_ROOT` | none | each use | Image root for IDE-R; overridden by a root stored with `amt_images set_root`. Unset: every mount is refused. |
| `AMT_UPLOAD_MAX_BYTES` | 16 GiB | each use | Largest accepted image upload. |
| `AMT_LOCAL_FRAMES`, `AMT_LOCAL_FRAMES_USER` | none, `jdoe` | tests only | Folder of local real frames and the account their tile shows (section 13). |

`HOME` decides `~/.amt-mcp` and `~/amt-recordings`. The container image also sets `PYTHONDONTWRITEBYTECODE=1` and `PYTHONUNBUFFERED=1`. The management console has its own variables (`AMT_CONSOLE_*`); see [console-guide.md](console-guide.md).

---

## 12. Error reference

Errors reach the client as `Error executing tool <name>: <message>` with `isError: true`. A schema-validation failure (a non-boolean `confirmed`, a value outside an enum or bound) arrives the same way with the validator's text. A `KeyError` shows its message in quotes, for example `'unknown_device:nope'`. Where a string ends in `:<x>`, `<x>` varies.

### Gate and confirmation

| String | Meaning |
|--------|---------|
| `this call requires the mcp-admin-token bearer header ...; the call was refused and nothing ran` | No valid bearer over HTTP (or the fleet hash is unresolvable). Nothing ran. |
| `confirmation_required: this <consequence>. Nothing was done. Re-call with confirmed=true ...` | A write without `confirmed: true`. The consequence is named. |
| validation error `Input should be a valid boolean` for `confirmed` | `confirmed` was `"true"` or `1`, not the JSON boolean. |
| HTTP 421 / 403 / 400 | Host not allowed / Origin not allowed / POST without a JSON content type (SDK transport security). |

### Registry, pin and vault

| String | Meaning |
|--------|---------|
| `unknown_device:<key>` | `device` is not registered. |
| `tls_leaf_unpinned_refused` | The device has no pin; nothing was sent. Pin it (`amt_device_manage`). |
| `tls_leaf_pin_mismatch` | The presented TLS leaf differs from the stored pin: the certificate changed or another machine holds the address. Check with `amt_devices pin_check`; re-pin only after comparing against the AMT firmware setup. |
| `devices_file_unusable:<ExceptionType>` | `AMT_DEVICES_FILE` is missing, unreadable or invalid. Fails closed. |
| `devices_file_malformed[:<key>]` | The devices file failed validation (seen from `amt_device_manage` and `amt_admin.py`). |
| `vault_cli_unset:AMT_SECRETS_CLI` | The vault CLI is not configured. |
| `vault_miss:<key>` / `vault_empty:<key>` | The entry does not exist / has an empty value. |
| `vault_unavailable:<key>:<ExceptionType>` | The CLI could not run or timed out (15 s). |
| `vault_key_missing`, `vault_list_failed`, `vault_write_failed:<key>`, `vault_delete_failed:<key>`, `vault_decode_error:<key>:<ExceptionType>` | Other vault CLI failures; always key-only. |
| `no_host_credential:<device>` | The device has no `host_vault_key`. |
| `vault_bad_credential_shape:<key>` | The host entry is not JSON `{"user", "password"}` with non-empty values. |
| `shot_dir_unsafe:not_a_plain_directory` / `:not_owned_by_this_user` | The screenshot directory is a symlink, not a directory, or owned by someone else. |
| `handoff_dir_unsafe` | Same check for the handoff directory. |

### WS-MAN

| String | Meaning |
|--------|---------|
| `wsman_auth_failed_401` | The authenticated request got a second 401. One attempt was made and none is retried; the stored password is wrong or rotated. Stop and fix the credential. |
| `wsman_auth_unsupported_challenge` / `_algorithm` / `_qop` | The device offered no usable Digest challenge. |
| `wsman_unreachable:<ExceptionType>` | Connection refused, reset, timed out (60 s), or the TLS handshake failed. |
| `wsman_http_<status>` | A non-2xx reply that was not a SOAP Fault. |
| `wsman_bad_status_line`, `wsman_incomplete_read`, `wsman_http_protocol_error:<Type>`, `wsman_unparsable_response`, `wsman_no_body` | Protocol-level failures. |
| `wsman_fault:<text>` | The device answered with a SOAP Fault (redacted text, cut to 300 characters). On the tolerant read tools a fault means "this class is unavailable". |
| `wsman_empty_body:<class[.method]>` | An empty reply is not a successful empty result. |
| `wsman_return_value:<class.method>:<code>` | A method returned non-zero. |
| `wsman_return_value_missing:<class.method>` | A reply without a `ReturnValue`: the request was sent and its outcome is unknown. |
| `invalid_class_name`, `invalid_selector_name`, `invalid_field_name`, `invalid_method_name` | A name failed its pattern, before any I/O. |
| `method_not_allowed:<class.method>` | A method outside the read allowlist `READ_METHODS`. |
| `secret_field_refused:<name>` | A credential-named field in a caller-supplied write value. Nothing was sent. |
| `unsupported_nested_field`, `field_value_too_long`, `too_many_fields`, `too_many_list_items`, `unsupported_field_value_type` | `amt_wsman_invoke` input limits. |

### Redirection (KVM, SOL, IDE-R)

| String | Meaning |
|--------|---------|
| `redir_start_status_<N>` | AMT refused to start the redirection session (a non-zero status). The tool descriptions say this happens when another session is open or consent is pending; which status number AMT uses for a busy host has not been recorded. |
| `auth_rejected_no_retry`, `auth_failed_status_<N>`, `no_digest_auth_offered` | The redirection Digest handshake failed; it is answered once. |
| `redir_open_timeout`, `redir_socket_closed_by_amt`, `open_no_frame`, `grab_no_frame` | Open or read timed out, or AMT closed the socket. |
| `ider_closed_by_amt`, `ider_start_refused`, `ider_unknown_proto`, `ider_illegal_buffer_size`, `ider_out_of_sequence` | IDE-R protocol failures. |
| `console_input_failed:step_<i>:<kind>` | The engine failed on step `i` (the offending character is not named). |
| `logon_type_failed` | Typing the credential failed. |

### Write tools

| String | Meaning |
|--------|---------|
| `power_state_not_available: AMT does not offer <action> now; it offers ...` | `amt_power` refusal with nothing sent. |
| `boot_target_not_allowed`, `unknown_boot_option`, `boot_option_needs_bool`, `boot_option_needs_int_<lo>_to_<hi>` | `amt_set_next_boot` input. |
| `boot_sequence_failed:completed=<steps>:...` / `boot_readback_mismatch:<fields>` | A step failed / the flags read back differ. |
| `area_not_writable_by_this_tool:<area>`, `unknown_field:<area>:...`, `invalid_value:<area>.<field>:needs <kind>` | `amt_configure` input. |
| `configure_readback_mismatch`, `configure_collateral_change`, `configure_instance_not_round_trippable` | `amt_configure` verification. Collateral change names the old values and says the requested fields were applied. |
| `users_username_invalid_or_admin`, `users_user_exists`, `users_no_such_user`, `users_add_needs_access_permission_0_to_2_and_nonempty_realms_0_to_31` | `amt_configure area=users`. |
| `screen_not_expected:saw=<label>:expected=<labels>`, `screen_not_identified:<problem>:expected=<labels>` | `amt_console_input` `expect` guard; nothing was sent. |
| `secret_step_refused_for_boot_screen:<labels>`, `expect_unknown_label`, `expect_needs_a_non_empty_list_of_screen_labels` | `expect` validation. |
| `too_many_actions`, `console_input_needs_actions`, `action_<i>_...`, `total_wait_over_30_seconds` | `amt_console_input` validation. |
| `sol_text_must_be_ascii_up_to_1024_chars`, `invalid_sol_read_window`, `terminal_not_live`, `terminal_ended_during_read` | `amt_sol`. |
| `ider_image_root_unset`, `ider_image_root_not_a_directory`, `ider_already_mounted`, `ider_not_mounted`, `ider_unmount_timeout`, `ider_image_not_found`, `ider_image_outside_image_root`, `ider_image_not_a_512_aligned_regular_file`, `ider_<action>_image_busy:<name>:<reason>` | IDE-R and the image library. |
| `ider_upload_needs_AMT_PUBLIC_BASE_URL`, `ider_upload_too_large`, `ider_upload_no_room_on_the_image_volume`, `ider_upload_exists`, `ider_upload_already_open` | Upload minting. |
| `viewer_server_in_use`, `mirror_not_live`, `mirror_bad_settings`, `serial_bad_settings`, `embed_mode` | Viewers (`embed_mode` is the 403 body). |
| `ffmpeg_missing`, `ffmpeg_failed`, `recording_empty` | Recording encode, reported in `last_recording.encoding`. |
| `identity_in_use`, `identity_not_found`, `identity_not_console_entry`, `identity_name_invalid`, `identity_name_not_allowed`, `identity_intake_needs_AMT_PUBLIC_BASE_URL` | `amt_identity_manage`. |
| `capture_name_required`, `capture_name_invalid`, `capture_not_found` | `amt_captures`. |

Composite-tool abort reasons are a structured result, not an error; they are in section 9.

---

## 13. Testing

```bash
pip install pytest pytest-xdist httpx pillow playwright
python3 -m playwright install chromium     # only for the console's browser tests
python3 -m pytest                          # whole suite
python3 -m pytest tests                    # the server only
python3 -m pytest -n 0 tests/test_mirror.py   # one process, one file
```

`pyproject.toml` sets `addopts = "-n auto --dist worksteal"`, so pytest runs on every core with pytest-xdist; `-n 0` (or `-p no:xdist`) runs in one process. `tests/` collected 1591 tests when this guide was written (`python3 -m pytest tests --collect-only -q -n 0`); `console/tests/` collected another 1354. **No test contacts an AMT host.** Every AMT conversation is faked at one seam: `amt_wsman.transport` or `_open_connection` for WS-MAN, `FakeKvm` / `FakeSol` / `FakeIder` for the redirection engines, a dict or a fake vault CLI child process for the vault. `tests/conftest.py` keeps `AMT_STATE_DIR` and `AMT_SHOT_DIR` in temporary directories and removes `AMT_PUBLIC_BASE_URL`, so a test opts in to handoffs explicitly.

| Suite | What it covers |
|-------|----------------|
| `test_conformity.py` | The tool list a client actually receives (see below). |
| `test_skeleton.py`, `test_gate_patterns.py`, `test_console_bearer.py` | The gate over the real ASGI app: absent and wrong token, the stdio skip, an unresolvable hash, resources and prompts, the bearer scheme, a tool registered with no annotations is still gated, both principals and the call log. |
| `test_direct_endpoint.py` | Every outbound connection a tool opens goes to a registry host on 16993 or 16995 and nothing else leaves the process (it sits on the process's socket and `urlopen` seams, so each tool stops at its first dial). The two dispositioned exceptions are `amt_images action=fetch`, the only tool that may reach a non-registry host, and the UDP `connect` a wildcard-bound viewer makes to learn the LAN-facing address, which sends no packet. |
| `test_wsman_transport.py` | Manual Digest (one authenticated attempt), the pin, loop bounds, completeness, redaction. |
| `test_wsman_write.py` | Exact SOAP actions, secret handling, one-attempt auth, the pin, and `test_no_read_module_imports_a_write_module` (the read/write import separation). |
| `test_read_tools.py`, `test_write_tools.py` | The read and write tools against mocked AMT. Every write is checked for the `confirmed=false` refusal sending nothing (no vault read, no wire, no session). |
| `test_composite_tools.py`, `test_ocr_gate.py`, `test_screen_context_real_frames.py` | Logon and logoff flows with a mocked engine; the OCR gate's pure logic; the detectors and classifier on real frames with the real recognizers. |
| `test_redir.py`, `test_kvm_incremental.py` | SOL and IDE-R framing against a scripted fake socket; incremental KVM updates. These pin the framing the engines send; they cannot prove a real device accepts it. |
| `test_mirror.py`, `test_serial.py` | The viewer pages and streams over a real loopback server, the token gate, control-only input, recording, shared sessions, the confirmed gate. |
| `test_handoff.py`, `test_captures.py`, `test_image_library.py`, `test_ider_images.py`, `test_identity.py` | The one-time routes through the real HTTP app (with tripwires that prove the single-claim path ran), the image library, the intake route with a real fake-CLI child process, CORS. |
| `test_fleet.py`, `test_amt_admin.py` | The device rules and the admin command set (a fake `subprocess.run`; no secret reaches an argv). |
| `test_logdecode.py`, `test_parity.py` | Log decoding against live vectors; the parity census. |
| `test_sentinel_password.py` | A sentinel credential (searched literal, base64 and hex) never surfaces in any tool's result, raised error, stdout, stderr, log records, process environment, written files or session notes, on the paths where a credential could leak (a WS-MAN peer and a redirection peer that challenge and then reject). The host password is typed as keystrokes by design, so the redirection wire is scanned for the AMT sentinel only. |

### The conformity test

`tests/test_conformity.py` reads `mcp.list_tools()` (what a client receives, not the decorators) and asserts: exactly 23 tools (`EXPECTED_TOOLS`) split into the literal `READ_TOOLS` (9) and `WRITE_TOOLS` (14) sets, independent of the parity manifest; every tool has a non-empty description of at most 2048 characters, a title (unique across tools) and a `readOnlyHint`; every parameter has a schema description and a name in `[A-Za-z0-9_.-]{1,64}`; read tools are `readOnlyHint: true` with no `confirmed`; write tools are `readOnlyHint: false` with a boolean `confirmed` defaulting to false; each description's first sentence is at most 400 characters; the server `INSTRUCTIONS` fit in 2048 characters; the manifest's kinds agree with the sets; and `evaluation.xml` holds 10 well-formed question and answer pairs. The checker itself is tested with deliberately broken tools, so a vacuous pass is not possible.

### Real frames and frames kept outside the repo

`tests/real_frames/` (16 PNGs) is committed. Windows frames and some Debian tty frames are not, because they show an account. Set `AMT_LOCAL_FRAMES` to a local folder holding them (the expected names are in `tests/test_screen_context_real_frames.py`) and `AMT_LOCAL_FRAMES_USER` to the account their sign-in tile shows (default `jdoe`). Without them those tests skip with the missing path in the reason (`pytest -rs`); a missing capture is never replaced by an invented one. Tests that need a recognizer skip when neither `ocrmac` nor `tesseract` is usable, and each backend is asserted separately (the container only has tesseract).

---

## 14. Extending the server

### Adding a tool

1. **Implement it** as a plain sync function (what tests drive) plus an `async def amt_<name>(...)` coroutine (the registered surface) that pushes blocking work onto `asyncio.to_thread`. Put it in the module that owns the domain, or a new `amt_*.py`.
2. **Describe every parameter** with `Annotated[..., Field(description=...)]` (the conformity test fails on a bare property). Take `device: DeviceParam` for a host tool. The docstring is the tool description: lead with the key fact, stay under 2048 characters.
3. **Guard writes.** Take `confirmed: ConfirmedParam = False` (a `StrictBool`), call `_require_confirmed(confirmed, consequence)` first, before the vault, the wire or the lock, with a consequence that names what will happen. Reads must not take `confirmed`.
4. **Gate the pin first.** Call `amt_wsman.require_pin(dev)` (or go through `amt_wsman.resolve_password`) before touching the vault, the disk or the network. Use the per-device lock (`async with _session_lock(device)`) for anything that opens a redirection session or must not interleave with another write to the host.
5. **Keep secrets in process.** Resolve credentials with `amt_vault`, never accept or return one, and re-raise engine errors that could name a character without the character.
6. **Register it** in a `*_TOOL_SPECS` tuple. Reads are `(fn, name, title)` and get `readOnlyHint: true`, `idempotentHint: true`, `destructiveHint: false`; an exception to a default goes in `amt_tools.TOOL_ANNOTATION_OVERRIDES`. Writes are `(fn, name, title, hints)` and get `readOnlyHint: false`, `idempotentHint: false`; `hints` carries `destructiveHint` (true for anything that changes a host or server state). **Derive `readOnlyHint` from behavior, not from the name**: a tool whose purpose is a write is a write. A new tuple needs a line in the loops of `amt_server.register_tools`. The title must be unique.
7. **Update the pinned counts and tables in the same change:** `EXPECTED_TOOLS`, `READ_TOOLS` / `WRITE_TOOLS` and the `(9, 14)` split in `tests/test_conformity.py`; a row in `amt_parity.TOOLS` and `CENSUS`, with the MeshCommander surface it covers, and the census in `tests/test_parity.py`; the `INSTRUCTIONS` text in `amt_server.py` (and its length); the console's client table, which `console/tests/test_console_mcp_client.py` pins to the live schemas.
8. **Packaging.** If the tool lives in a new module, add it to the `Dockerfile` `COPY` list **and** to `py-modules` in `pyproject.toml` (`tests/test_gate_patterns.py` fails until both list it).
9. **Tests** with a mocked transport: the `confirmed=false` refusal sending nothing, the unpinned refusal before the vault, the exact SOAP or byte sequence, and a positive control for each refusal.
10. **Docs:** section 6 of this guide, the README tool table, the count paragraph in `CLAUDE.md`, and [operators-guide.md](operators-guide.md) if an operator now does something new.

### Adding to the read side of WS-MAN

There is **no class allowlist** for reading. `amt_wsman_get` accepts any name matching `(AMT|CIM|IPS)_[A-Za-z0-9_]{1,80}`, so reading a new class needs no code. What the read side does restrict is *methods*, and what it types is *tables*:

- **A record-reading method invocation** (a method that returns log records or list entries and changes nothing): add `(class, method)` to `amt_wsman.READ_METHODS`. Anything that changes AMT state does not belong there; it belongs in `amt_wsman_write.py`, reached only from `amt_write.py`. A class prefix other than `AMT_`, `CIM_` or `IPS_` also needs `NS` and `CLASS_NAME` extended.
- **A typed section** in `amt_inventory`: add it to `INVENTORY_CLASSES` and the `InventorySection` literal. In `amt_settings`: add it to `SETTINGS_AREAS` (and the `SettingsArea` literal for a new area). `amt_inventory` and `amt_status` tolerate a SOAP Fault per class (`_Reads` with `tolerant=True`); `amt_settings` does not. The console pins `INVENTORY_CLASSES` and the settings tables in its tests.
- **A writable area** for `amt_configure`: add a `_PutArea` to `PUT_AREAS` (class, writable fields and kinds, selectors, device-owned `read_only` fields) or extend `FEATURE_FIELDS`; add any risky value to `RISKY_CONFIGURE` so the confirmation names it. Round-trip it against a real device before trusting it: the full-instance Get, merge and Put can reset a field the tool did not echo.
- Tag any class, method or byte sequence not exercised against a real device `TODO verify-live`, as the code does.

### Rules that keep the invariants

Never add `auth=` or `token_verifier=`; never add a tool outside `GatedFastMCP`; never reintroduce urllib's `HTTPDigestAuthHandler`; never add a principal check inside a tool body; never put Put, Create, Delete or Invoke in `amt_wsman.py`; never register a device without its pin; change `amt_kvm.py` only with a test against a real host. See [../CLAUDE.md](../CLAUDE.md) for the full list.

---

## 15. Known gaps and keeping this guide current

### Known gaps

Verified against the code and tests unless marked otherwise.

- **Most write paths are mock-tested only.** Classes, methods and byte sequences not proven live carry `TODO verify-live` (`grep -rn "TODO verify-live" amt_*.py`). The repository's agent notes record these as run against a real host: the reads, the display mirror, the serial terminal, `amt_sol` (open, read, send, close, and a getty login), `amt_ider` (an `next_boot` mount and unmount, and the keepalive), the Linux console logon and logoff on KVM and serial, and the `expect` refusal path. Not established: `amt_power`'s `ManagedElement` reference form, the non-PXE boot source names, `amt_configure` (every class and field except the KVM settings Put), the `expect` proceed path, an IDE-R *boot*, and SOL beside IDE-R. This guide did not re-run any of it.
- **`amt_settings area=users`** does not report whether its ACL handle list was complete.
- **The OCR gate is calibrated on a small set of real frames:** one host's Windows 11 sign-in, lock and desktop at 1280x800, a Debian tty, and the boot-software frames in `tests/real_frames/`. A PIN-default sign-in (no `Password` field) or a Microsoft-account tile whose display name differs from the vaulted `user` aborts rather than types. UEFI shells and firmware boot-device menus stay `unknown`. The two recognizers do not read identically: both misread the hostname's `0` on a getty prompt, and `ocrmac` misreads the brackets of a synthetic installer `[!!]` title that tesseract reads (the committed real boot frames each match exactly one signature with both backends, asserted per backend). Where a recognizer misses a signature, a sub-Windows frame falls back to `bios-setup`.
- **Intake needs a writable vault.** The shipped `deploy/compose.yaml` mounts the server's vault read-write and `amt_admin.py vault sync` leaves it 0700 / 0600; a read-only or 0500 vault answers `PUT /intake/<token>` with 503. `vault_entries()` also depends on the vault CLI's list format.
- **Cancelling a tool call** (a client disconnect) releases the in-process per-device lock while the worker thread is still running, so a second call can start before the first closed its session. AMT's own single-session refusal is the backstop.
- **Everything stateful is in process memory:** live mirrors and terminals, IDE-R mounts, background downloads, open upload and intake offers. A restart drops them (a mount's session ends with the process). Run one worker.
- **Viewer pages are plain HTTP;** bind them to loopback or a trusted LAN and front them with TLS.
- **The image is pinned by tag, not digest** (`python:3.12.7-slim-bookworm`; `mcp`, Pillow and `cryptography` are pinned). Re-verify the SDK version against the deploy target; the gate relies on `tools/call`, `resources/read` and `prompts/get` routing through `call_tool`, `read_resource` and `get_prompt` (floor `mcp>=1.26`; `tests/test_skeleton.py` checks it).
- **Platform Erase** is not a typed boot option; it is reachable only through `amt_wsman_invoke`.

### Keeping this guide current

Update this guide in the same change as the code. The source anchors:

| Section | Anchor in the source | Update when |
|---------|----------------------|-------------|
| 2 Module map | `ls amt_*.py`, `Dockerfile` COPY list | A module is added, renamed or split |
| 3 Gate | `amt_gate.py` (`identify_bearer`, `GatedFastMCP`, `call_log`); `amt_server._allowed_hosts`, `main` | The gate, the log line, the transport rules or the bind defaults change |
| 4 Registry and pin | `amt_registry.Device`, `_refresh`; `_PinnedHTTPSConnection`, `require_pin`; `amt_redir.pinned`; `amt_fleet.plan_*` | A device field, the file format or a pin check point changes |
| 5 Credentials | `amt_vault.py`; `amt_wsman.is_secret_name`; `amt_wsman_write.refuse_secret_names`; `amt_identity.py`, `amt_upload.receive_intake` | A redaction rule, an entry name pattern or the intake rules change |
| 6 Tools | the schema dump command in section 6; `amt_server.register_tools`; each tool's docstring and `*_TOOL_SPECS` | **Any** tool, parameter, default, bound, annotation or refusal changes. Re-run the dump and diff it against the tables. |
| 7 Viewers | `amt_mirror.py` (`ROUTES`, `POST_ROUTES`, `CONTROL_ROUTES`, `KVM_KEEPALIVE_SECONDS`, `_Handler`), `amt_serial.py` (`SCROLLBACK_BYTES`, `MAX_INPUT_BYTES`, `_events`) | A route, a token rule, a header, a limit or embed behavior changes |
| 8 Files | `amt_handoff.py`, `amt_upload.py`, `amt_tools._private_shot_dir` | A route, TTL, size rule, CORS rule or directory rule changes |
| 9 Screens and logon | `amt_tools._label_for`, `classify_screen`, `BOOT_SIGNATURES`, `ABORT_NOTES`, `remote_logon`, `remote_logoff`; `amt_serial.console_logon` | A label, signature, threshold, abort reason or flow step changes; also when new real frames are added to `tests/real_frames/` |
| 10 Decode and parity | `amt_logdecode.describe_*`; `amt_parity.CENSUS`, `parity_status` | A decoded field or a parity row changes |
| 11 Environment | `grep -n "environ" amt_*.py` and `grep -n "_ENV *=" amt_*.py` | A variable is added, removed or its default changes |
| 12 Errors | `grep -ohE "(ValueError\|WsmanError\|AmtError\|VaultError\|PermissionError\|RuntimeError)\(f?\"[a-z_0-9]+" amt_*.py` | An error string is added or renamed |
| 13 Testing | `pyproject.toml` `addopts`; `python3 -m pytest tests --collect-only -q -n 0`; `tests/test_conformity.py` | The runner, the counts' order of magnitude or the conformity rules change |
| 15 Known gaps | `grep -rn "TODO verify-live" amt_*.py`; `CLAUDE.md` live-verification notes | A path is verified live, or a gap is closed |

Counts in this guide (23 tools, 9 read and 14 write, 15 power actions, 16 boot options, 25 macros, 10 settings areas, 16 real frames) come from the code; re-derive them with the commands above rather than editing the numbers by hand.
