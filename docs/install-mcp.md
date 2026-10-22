# Installing the amt-mcp server

This guide takes an operator from nothing to a running, verified amt-mcp server. It covers the MCP server only. The management web console in `console/` has its own guide: [install-console.md](install-console.md). For what the tools do once the server is up, see [mcp-guide.md](mcp-guide.md) and [operators-guide.md](operators-guide.md). The project overview is in [../README.md](../README.md).

Every value in this guide is an example: device key `my-server-1`, AMT addresses `198.51.100.x`, host names `amt.example.com`, `amt-viewer.example.com` and `amt-console.example.com`, user `jdoe`, deploy directory `/srv/amt-mcp`. Replace them with your own.

## 1. What you are installing

amt-mcp is a Python MCP server (FastMCP) that manages Intel AMT hosts directly over TLS: WS-MAN on port 16993 and KVM, Serial-over-LAN and IDE-R redirection on port 16995. It registers 23 tools: 9 read-only (status, screenshot, inventory, logs, settings, WS-MAN get, devices, identities, captures) and 14 that change something and need `confirmed=true`. There is no MeshCommander, web relay or browser in the path.

There are two ways to run it.

| | Local | Docker |
|---|---|---|
| Command | `python3 amt_server.py` (HTTP) or `python3 amt_server.py --transport stdio` | `docker compose ... up -d --build amt-mcp` from `deploy/compose.yaml` |
| Listens on | HTTP: `127.0.0.1:8765`, endpoint `/mcp`. stdio: no socket | Host loopback only: `127.0.0.1:8765` (MCP) and `127.0.0.1:8766` (viewer pages) |
| Bearer check | HTTP: every tool call. stdio: none (the process boundary is the control) | Every tool call |
| Credentials | The vault your user can read | A dedicated vault holding only this server's entries |
| Use it for | Trying it out, development, a single operator's machine | A shared server behind a TLS reverse proxy |

The server needs a Unix-like OS (Linux or macOS): `amt_fleet.py` imports `fcntl`, so native Windows is not supported.

Things the server never does: it takes no secret as a tool argument, returns none, and never accepts the raw bearer token in configuration (only its SHA-256).

## 2. Prerequisites

| Need | Detail | Where it comes from |
|---|---|---|
| Python | 3.10 or newer. The image uses 3.12.7; this guide was checked on 3.12 only | `pyproject.toml` (`requires-python`), `Dockerfile` |
| `mcp` SDK | `mcp>=1.26,<2`. The image pins `mcp==1.26.0`. The floor is 1.26 because the bearer gate overrides `FastMCP.call_tool`, `read_resource` and `get_prompt`. `starlette`, `uvicorn` and `pydantic` arrive with it | `pyproject.toml`, `Dockerfile` |
| Pillow | `pillow>=10` (the image pins 12.1.1). JPEG encoding for the display mirror, and the OCR path | `pyproject.toml`, `Dockerfile` |
| OCR backend | Needed by `amt_remote_logon` and `amt_remote_logoff`, which type a password only into a screen they positively identify by reading it. macOS: `pip install ocrmac` (Apple Vision). Linux and the image: the `tesseract` binary plus Pillow (`apt-get install tesseract-ocr`). `ocrmac` is tried first, then `tesseract`. With neither, both tools abort with `ocr_unavailable` and type nothing. No other tool needs OCR | `amt_tools.py` (`OCR_BACKENDS`), `Dockerfile` |
| ffmpeg | Encodes mirror recordings to H.264 `.mp4` when a recording stops. Without it the raw `.mjpeg` and `.times` files are kept. The image installs it | `amt_mirror.py`, `Dockerfile` |
| Vault CLI | [node-vault-mcp](https://github.com/synman/node-vault-mcp), specifically its `services/secrets.py`. amt-mcp runs it as a child process with the same Python interpreter (`sys.executable`), so whatever it imports must be installed in that interpreter's environment. The image installs `cryptography==46.0.3` for it | `amt_vault.py`, `Dockerfile` |
| Docker route only | Docker Engine with the Compose plugin on the host that will run the container, and ssh access to that host from the machine where you run `deploy/amt_admin.py` | `deploy/compose.yaml`, `deploy/amt_admin.py` |
| Network | The server must reach each AMT host on its WS-MAN port (16993) and redirection port (16995). Clients reach the server on 443 through a proxy (Docker route) | `amt_registry.py` |

You can run from a checkout, or install the package: `pip install .` installs every `amt_*.py` module, the vendored xterm.js the serial page serves, and an `amt-mcp` command (the same as `python3 amt_server.py`). `tests/test_gate_patterns.py` keeps the package list equal to the modules on disk. The Docker image copies every module and `vendor/` explicitly.

## 3. Prepare each AMT host

amt-mcp only talks to AMT. It does not provision AMT, enable TLS on it or change MEBx. Do these on each host before you register it.

1. **AMT is provisioned.** `amt_status` reports `provisioning.control_mode` (`not_provisioned`, `client_control_mode` or `admin_control_mode`). Nothing in the code checks the mode or requires a particular one; it only reports it. Admin control mode is the usual choice for unattended management (Intel AMT background, not something this code verifies).
2. **TLS is on for WS-MAN (16993) and redirection (16995).** amt-mcp uses only the TLS ports. Nothing in this repository turns TLS on: the `security` area of `amt_configure` can change only `AcceptNonSecureConnections`. Enable TLS in AMT's own configuration.
3. **You know the admin password.** Every request authenticates as the AMT user `admin` (hard-coded in `amt_wsman.py` and `amt_kvm.py`) with HTTP Digest (MD5 or SHA-256). That password goes in the vault (section 4) and nowhere else.
4. **Redirection features are enabled as you need them.** KVM for `amt_screenshot`, `amt_mirror_link`, `amt_console_input` and the logon tools; SOL for `amt_sol` and `amt_serial_link`; IDE-R for `amt_ider`. `amt_status` shows which are on (`redirection.kvm.enabled`, `sol_enabled`, `ider_enabled`). Once the server runs, `amt_configure` with `area: "features"` and `changes: {"kvm_enabled": true}` (likewise `sol_enabled`, `ider_enabled`) turns them on. KVM may also need to be allowed in MEBx: the KVM settings class carries an `EnabledByMEBx` field that amt-mcp treats as device-owned and never writes.
5. **User consent for KVM is not pending.** If `amt_status` shows `user_consent.required_for` of `kvm` or `all`, AMT displays a consent code on the host. amt-mcp has no tool that enters a consent code, and `amt_screenshot` fails while consent is pending. Either leave consent off for KVM, or turn it off deliberately with `amt_configure` area `kvm` and `OptInPolicy: false`, which the tool itself flags as a risky change.
6. **One session at a time.** AMT allows one KVM session per host. A second open fails; an IDE-R mount runs alongside KVM.
7. **Use the AMT address, not a host name.** The registry accepts only an IP address for `amt_ip`, because the TLS pin is per address.

### The TLS pin

AMT presents a self-signed leaf certificate, so the certificate chain is not verified. Identity comes from the leaf's full SHA-256 fingerprint, stored per host as `tls_leaf_sha256` (64 lowercase hex characters).

- WS-MAN checks the pin on every connection. KVM, SOL and IDE-R check it right after the TLS handshake, before any protocol byte or the password digest is sent.
- A device with no pin is refused (`tls_leaf_unpinned_refused`). A mismatch is refused (`tls_leaf_pin_mismatch`). Neither is retried or bypassed.
- Reading a leaf for pinning or checking (`presented_pin`) completes a TLS handshake and sends no credential.

How the pin gets recorded:

| Route | What happens |
|---|---|
| `amt_admin.py device add` / `amt_device_manage add` | Reads the leaf the host presents now and pins it: trust on first use. Run it from a network position you trust. |
| The same, with `--pin` / `expected_pin` | Refuses to write anything unless the host presents exactly that leaf. Use this when you have an independent fingerprint. |
| `edit` with a new address or WS-MAN port | Reads the leaf again and refuses a different one unless you pass `--repin` / `repin: true`. |
| `edit` with `--repin` / `repin: true` | Accepts whatever leaf is presented now, even a changed one. |
| Hand-written `devices.json` | Whatever `tls_leaf_sha256` you wrote. Omit it and the device is unpinned and refused. |

Compare the recorded pin with an independent reading. The tool text suggests MEBx. You can also read the leaf yourself from a machine that can reach the host, and lower-case it and strip the colons:

```bash
openssl s_client -connect 198.51.100.26:16993 </dev/null 2>/dev/null | openssl x509 -noout -fingerprint -sha256
```

`amt_devices` with `action: "pin_check"` (or `amt_admin.py device pin KEY`) compares the leaf presented now with the stored pin and reports `matches`.

## 4. Vault entries

The server never stores a secret on disk, in an environment variable or in a tool argument. It reads each value from a vault by running `secrets.py get <name>` as a child process (15-second timeout) and keeping the value in memory for the call.

Entries the server reads, by name:

| Entry name | Holds | Used by | Required |
|---|---|---|---|
| the device's `amt_vault_key`, e.g. `my-server-1-amt` | The AMT `admin` password | Every tool that touches the host | Yes, per device |
| the device's `host_vault_key`, e.g. `my-server-1-os` | JSON `{"user": "...", "password": "..."}`, the host operating system logon | `amt_remote_logon`, and `secret` steps in `amt_console_input`. A value that is not that shape fails with `vault_bad_credential_shape:<name>` | Only if you use those; the device may have no `host_vault_key` |
| `<amt_vault_key>-rfb`, e.g. `my-server-1-amt-rfb` | The KVM (RFB) password | `amt_configure` area `kvm`, which writes it into AMT's KVM settings | Only for that write |
| `<device>-amt-user-<name>`, e.g. `my-server-1-amt-user-jdoe` | The password for a new AMT user | `amt_configure` area `users`, action `add` | Only for that write |
| `mcp-admin-token` | The fleet bearer token | Not read by the server. You derive its SHA-256 for `MCP_ADMIN_TOKEN_HASH` | Yes, in the vault you operate from |

A device key and the `amt_vault_key` and `host_vault_key` it names use lowercase letters, digits and dashes (1 to 63 characters, starting with a letter or digit). The name part of a `<device>-amt-user-<name>` entry is an AMT user name and may also use `A-Z`, `_`, `.` and `@`. Storing a value in the vault does not change the password on the AMT; change that in AMT first.

`amt_identities` lists these entries by name and status (`present` or `missing`) and never a value.

### How secrets reach the server

- `AMT_SECRETS_CLI` is the path to `secrets.py`. It is read once, when the server process starts. Unset, every vault read fails with `vault_cli_unset:AMT_SECRETS_CLI`.
- With nothing else set, the CLI reads your default vault.
- For a dedicated vault, set `NVAULT_VAULT_PATH` (the vault file) and `NVAULT_MASTER_KEY_FILE` (its key file). The container does this (section 6). Their meaning belongs to node-vault-mcp; amt-mcp passes its environment through to the child and itself reads `NVAULT_VAULT_PATH` only to decide whether the vault is writable.
- Install node-vault-mcp by its README and create your main vault once with `secrets.py init`.
- Store values with node-vault-mcp's `secrets.py set`, in your own terminal. For a password, read it without echo into a shell variable and pipe it with the shell's built-in `printf` (no process sees it in its arguments):

  ```bash
  read -rsp 'AMT admin password for my-server-1: ' pw; echo
  printf '%s\n' "$pw" | python3 "$AMT_SECRETS_CLI" set my-server-1-amt --expires 2035-01-01 --notes 'AMT admin'
  unset pw
  ```

  The same form replaces an existing entry's value.
- Never pass a value on a command line, in an environment variable or in a file. amt-mcp itself writes an entry by sending the value on the CLI's stdin, with `--expires` and `--notes` options; run in a terminal with no pipe, `set` prompts for the value instead (check this against the version of node-vault-mcp you installed).

### The fleet token and its hash

Create the token without printing it, using the same stdin form amt-mcp uses:

```bash
export AMT_SECRETS_CLI=/path/to/node-vault-mcp/services/secrets.py
python3 -c 'import secrets; print(secrets.token_urlsafe(32))' \
  | python3 "$AMT_SECRETS_CLI" set mcp-admin-token --expires 2035-01-01 --notes 'amt-mcp fleet bearer'
```

Derive the hash. Only this hash is ever configured on the server; the token is piped and not printed:

```bash
export MCP_ADMIN_TOKEN_HASH="$(python3 "$AMT_SECRETS_CLI" get mcp-admin-token \
  | python3 -c 'import sys,hashlib; print(hashlib.sha256(sys.stdin.read().strip().encode()).hexdigest())')"
echo "${#MCP_ADMIN_TOKEN_HASH}"    # expect 64
```

The hash is of the token with surrounding whitespace removed, which is how the server treats the bearer it receives. The hash is not a secret; the token is. The `echo` prints only the length.

## 5. Run it locally

1. **Get the code and an environment.**

   ```bash
   cd amt-mcp
   python3 -m venv .venv && . .venv/bin/activate
   pip install "mcp>=1.26,<2" "pillow>=10"
   ```

   Add an OCR backend if you will use the logon tools (`pip install ocrmac` on macOS, or install the `tesseract` binary) and ffmpeg if you want `.mp4` recordings. Install node-vault-mcp's own requirements into the same environment so `secrets.py` runs.

2. **Store the vault entries** from section 4 (at least the device's `amt_vault_key`) and derive `MCP_ADMIN_TOKEN_HASH`.

3. **Create the devices file.** The server's registry is either the built-in `amt_registry.DEVICES` or, when `AMT_DEVICES_FILE` is set, that file.

   - The built-in registry holds one example (`my-server-1` at `198.51.100.26` with a placeholder pin). Only a code change can alter it, and `amt_device_manage` refuses to work without `AMT_DEVICES_FILE`. Use the file.
   - The file format is `{"version": 1, "devices": {...}}`. The server re-reads it whenever it changes, so an edit is live at the next call with no restart. A missing or malformed file fails closed (`devices_file_unusable`); it never falls back to the built-in registry.
   - An empty `devices` object is valid, so you can start empty and add servers with `amt_device_manage`:

   ```bash
   mkdir -p "$HOME/.amt-mcp"
   export AMT_DEVICES_FILE="$HOME/.amt-mcp/devices.json"
   printf '{"version": 1, "devices": {}}\n' > "$AMT_DEVICES_FILE"
   ```

   Or write an entry yourself, with a pin you obtained independently. The `devices` object maps each key to these fields (`tls_leaf_observed_prefix` is informational):

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
         "tls_leaf_observed_prefix": "<first 16 of the same>"
       }
     }
   }
   ```

   An unknown field is rejected (`devices_file_malformed:<key>`). `kvm_port` is the redirection port for KVM, SOL and IDE-R alike. The directory holding the file must be writable by the server's user, because `amt_device_manage` takes a lock file there and keeps `.prev-devices.json`.

4. **Start the server.**

   ```bash
   export AMT_DEFAULT_DEVICE=my-server-1
   python3 amt_server.py                      # HTTP on 127.0.0.1:8765, endpoint /mcp
   python3 amt_server.py --transport stdio    # stdio: no socket, no bearer check
   ```

   HTTP mode refuses to start, with exit status 2, unless `MCP_ADMIN_TOKEN_HASH` is a 64-character hex digest. Success is uvicorn's listen line on stderr and no further output until a call arrives. In stdio mode the process speaks MCP on stdout and logs only to stderr; point your client at the command, with the same environment variables set for it.

5. **Connect a client and verify** (sections 8 and 9). With `AMT_DEVICES_FILE` empty, add the first server with `amt_device_manage` (`action: "add"`, `confirmed: true`). The vault entries it names must already exist; the call then pins the leaf the host presents.

### Environment variables

All configuration is environment. None of it is secret.

| Variable | Default | Meaning |
|---|---|---|
| `MCP_ADMIN_TOKEN_HASH` | none | SHA-256 hex of the fleet token. Required over HTTP. Unset or malformed: the server refuses to start, and an already-running one refuses every token. |
| `MCP_CONSOLE_TOKEN_HASH` | none | Optional second bearer, for the management console, in the same form. Calls with it are logged as `principal=console`. Unset or malformed: only the fleet bearer works. See [install-console.md](install-console.md). |
| `AMT_TRANSPORT` | `http` | Set by `--transport`; do not set it yourself. Only an explicit `stdio` skips the bearer check, and the HTTP app refuses to build while it says `stdio`. |
| `AMT_BIND_HOST` | `127.0.0.1` (the image sets `0.0.0.0`) | Bind address of the MCP HTTP listener. |
| `AMT_PORT` | `8765` | Port of the MCP HTTP listener. Must be an integer. |
| `AMT_ALLOWED_HOSTS` | empty | Comma-separated host names (no scheme) accepted in the `Host` header on `/mcp`. Loopback is always accepted. Each name is allowed with and without a port, and its `https://` and `http://` origins are allowed. |
| `AMT_PUBLIC_BASE_URL` | unset | `scheme://host[:port]` clients reach the server at, with no path. When set, tools that write a file return a one-time download `url`, and `amt_images upload` and `amt_identity_manage intake` can mint upload urls. Unset: file paths only, and those two refuse. |
| `AMT_SECRETS_CLI` | unset | Path to `secrets.py`. Read once at start. |
| `NVAULT_VAULT_PATH`, `NVAULT_MASTER_KEY_FILE` | unset | Select a dedicated vault for the CLI (section 4). |
| `AMT_DEFAULT_DEVICE` | `my-server-1` | The registry key used by a call that names no device. Read once at start. If it is not in your registry, those calls fail with `unknown_device`. |
| `AMT_DEVICES_FILE` | unset | Devices file that replaces the built-in registry. |
| `AMT_STATE_DIR` | `~/.amt-mcp` | Settings (`settings.json`, holding the image root and recording folder set by tools) and the `handoffs/` folder. |
| `AMT_SHOT_DIR` | `<temp dir>/amt-mcp-shots` | Screenshot folder, created mode 0700. A symlink or a folder owned by another user is refused. |
| `AMT_IMAGE_ROOT` | unset | Folder `amt_ider` serves `.iso` and `.img` images from. A root set by `amt_images set_root` takes precedence. Unset and none set: mounts are refused (`ider_image_root_unset`). |
| `AMT_UPLOAD_MAX_BYTES` | 16 GiB | Largest image `amt_images upload` accepts. An upload also needs 1 GiB free on the image volume. |
| `AMT_VIEWER_PUBLIC_BASE_URL` | unset | Public base URL of the front for the mirror and serial pages. The viewer's front url is listed first only when the viewer was started with `bind` set to `0.0.0.0`. |
| `AMT_CONSOLE_ORIGIN` | unset | The one origin allowed to frame viewer pages (`Content-Security-Policy: frame-ancestors`) and the one origin the upload and intake routes answer CORS for. Unset or not a plain `http(s)://host[:port]`: `frame-ancestors 'none'` and no CORS header. |
| `HOME` | the user's | Mirror and serial recordings go to `$HOME/amt-recordings` unless a folder was set with `record_start directory`. |

Two things use their own ports and are independent of `AMT_PORT`:

- The mirror and serial viewer pages are served by a second, plain-HTTP server inside the same process, started on demand by `amt_mirror_link` or `amt_serial_link`. It binds to `127.0.0.1:8766` unless you pass `bind` and `port` to the tool. To let other machines (or the reverse proxy in a container) reach it, start it with `bind: "0.0.0.0"`. Its pages are keyed by an unguessable token in the URL, not by the bearer.
- The one-time routes `/handoffs/<token>`, `/uploads/<token>` and `/intake/<token>` are served on the MCP port, outside the bearer check, and are keyed by their own single-use tokens.

## 6. Run it in Docker

The compose file defines two services, `amt-mcp` and `amt-console`. This section brings up `amt-mcp` only. The console is covered in [install-console.md](install-console.md).

### 6.1 Directory layout

Everything lives under one deploy directory, owned by one deploy user (`DEPLOY_UID`, `DEPLOY_GID`). The layout, from the header of `deploy/compose.yaml`:

```
/srv/amt-mcp/
  site.vars             site values; no secret
  src/                  this repository
  node-vault-mcp/       node-vault-mcp's services/ tree (secrets.py and vault_secrets), mounted read-only
  vault/                amt-mcp.vault and amt-mcp.key: a vault holding only this server's entries (0600 in a 0700 folder; the container writes console intake entries here)
  config/devices.json   the servers this container serves (0644)
  amt-mcp.env           MCP_ADMIN_TOKEN_HASH=<sha256 of the fleet token> (0600); never the token
  data/                 HOME in the container: state/ (settings, screenshots) and amt-recordings/
  iso/                  IDE-R images
```

The console's own folders (`console-data/`, `console-vault/`) are in the install-console guide.

Create the directories yourself, as the deploy user, before the first `up`. Docker creates a missing bind-mount source owned by root, and then the container (running as `DEPLOY_UID`) cannot write it and `amt_admin.py` cannot `chmod` it. `amt_admin.py` creates `config/` itself but `cd`s into `vault/` without creating it.

### 6.2 Steps

Run these in `/srv/amt-mcp` as the deploy user unless noted.

1. **Create the directories.**

   ```bash
   mkdir -p src config data iso vault node-vault-mcp
   ```

2. **Copy the repository into `src/`.** From a clone of the repository:

   ```bash
   git archive HEAD | tar -x -C /srv/amt-mcp/src
   # to a remote Docker host:
   git archive HEAD | ssh jdoe@198.51.100.10 'tar -x -C /srv/amt-mcp/src'
   ```

3. **Copy node-vault-mcp's `services/` contents** into `node-vault-mcp/`, so that `node-vault-mcp/secrets.py` and `node-vault-mcp/vault_secrets/` exist. Compose mounts that directory at `/opt/node-vault-mcp/services` and points `AMT_SECRETS_CLI` at `/opt/node-vault-mcp/services/secrets.py`.

   ```bash
   cp -R /path/to/node-vault-mcp/services/. /srv/amt-mcp/node-vault-mcp/
   ```

4. **Write `site.vars`.** Copy the example and fill it in. Compose is run with `--env-file ./site.vars`.

   ```bash
   cp src/deploy/site.vars.example site.vars
   id -u; id -g          # use these for DEPLOY_UID and DEPLOY_GID
   ```

   | Variable | Example | Meaning |
   |---|---|---|
   | `DEPLOY_UID`, `DEPLOY_GID` | `1000` | The user and group that own the deploy directory. The container runs as this uid and gid. |
   | `AMT_ALLOWED_HOSTS` | `amt.example.com` | Host names the MCP mount answers to. |
   | `AMT_PUBLIC_BASE_URL` | `https://amt.example.com` | Origin clients reach the MCP mount at. |
   | `AMT_VIEWER_PUBLIC_BASE_URL` | `https://amt-viewer.example.com` | Origin of the mirror and serial pages. |
   | `AMT_CONSOLE_ORIGIN` | `https://amt-console.example.com` | The console's origin (the one origin allowed to frame viewer pages). |
   | `AMT_CONSOLE_RP_ID` | `amt-console.example.com` | The console's WebAuthn relying-party id. |
   | `AMT_DEFAULT_DEVICE` | `my-server-1` | The registry key a call that names no device acts on. |

   **Fill in every line, including the console ones.** Compose interpolates the whole file even when you start only `amt-mcp`; with `AMT_CONSOLE_RP_ID` left out, `docker compose ... config amt-mcp` fails with `required variable AMT_CONSOLE_RP_ID is missing a value: set in site.vars` (checked with Compose v5.6.0). The compose file also requires `amt-mcp.env` to exist (step 5).

5. **Write `amt-mcp.env`** with the fleet token's hash, from the machine whose vault holds `mcp-admin-token` (section 4):

   ```bash
   test "${#MCP_ADMIN_TOKEN_HASH}" -eq 64 || echo "derive MCP_ADMIN_TOKEN_HASH first (section 4)"
   (umask 077; printf 'MCP_ADMIN_TOKEN_HASH=%s\n' "$MCP_ADMIN_TOKEN_HASH" > amt-mcp.env)
   ls -l amt-mcp.env     # -rw-------
   ```

   If that machine is not the Docker host, copy the file over with a method that keeps mode 0600. Add `MCP_CONSOLE_TOKEN_HASH=...` here later if you deploy the console.

6. **Build and start.**

   ```bash
   docker compose --env-file ./site.vars -f src/deploy/compose.yaml --project-directory . up -d --build amt-mcp
   docker logs amt-mcp
   ```

   Success: the container is running and its log shows uvicorn's startup lines, including the listen address (port 8765 inside the container). No call can succeed yet: there is no devices file and no vault, so a tool call answers `devices_file_unusable:...` or a vault error. Start the container before the next step because `amt_admin.py` finishes each device change by running `docker exec` in a container named `amt-mcp`.

7. **Create the dedicated vault and the devices file with `deploy/amt_admin.py`.** This script runs on your own machine, which holds the main vault. It reaches the Docker host over ssh and has no local mode. On a single box, point the ssh entry at the box itself (`"host": "127.0.0.1"`); if you would rather not use it at all, the manual route below applies. Prerequisites on your machine:

   - Python with the `mcp` SDK installed (the script imports `amt_fleet`, which imports the tool modules), run from a checkout of the repository.
   - Network reach to each AMT host's WS-MAN port, because `add` and `edit` read the TLS leaf from your machine.
   - The main-vault entries for each server already stored (section 4). `add` and `edit` refuse a vault key that does not exist.
   - ssh access to the Docker host as the deploy user, and that user must be allowed to run `docker` (typically by membership of the docker group): every device change and `vault status` ends with a `docker exec` over ssh, and without Docker access it fails with `NAS command failed (rc ...)` and the remote error text. Its connection details are in a vault entry holding JSON with `ssh_cmd`, `user` and `host`:

     ```bash
     printf '%s\n' '{"ssh_cmd": "ssh -i /path/to/key", "user": "jdoe", "host": "198.51.100.10"}' \
       | python3 "$AMT_SECRETS_CLI" set docker-host-ssh --expires 2035-01-01 --notes 'docker host ssh'
     ```

   The script requires three environment variables and stops before touching anything if one is unset:

   | Variable | Value |
   |---|---|
   | `AMT_SECRETS_CLI` | Path to the main vault's `secrets.py` |
   | `AMT_ADMIN_DEPLOY_DIR` | The deploy directory on the Docker host: `/srv/amt-mcp` |
   | `AMT_ADMIN_SSH_ENTRY` | The vault entry above: `docker-host-ssh` |

   The remote side needs `flock`, `sha256sum`, `tar`, `sh` and `docker`; the script puts `/usr/local/bin` ahead of `PATH` for `docker`.

   Commands:

   ```text
   amt_admin.py device list
   amt_admin.py device init
   amt_admin.py device add KEY --ip IP --amt-vault-key K [--host-vault-key H] [--wsman-port N] [--kvm-port N] [--pin SHA256]
   amt_admin.py device edit KEY [--ip IP] [--amt-vault-key K] [--host-vault-key H | --no-host] [--wsman-port N] [--kvm-port N] [--repin]
   amt_admin.py device remove KEY
   amt_admin.py device pin KEY
   amt_admin.py vault keys
   amt_admin.py vault status
   amt_admin.py vault sync
   amt_admin.py console enroll-code        (console only; see install-console.md)
   ```

   The first-time sequence. `device init` writes the first devices file from the built-in example registry: one server keyed `my-server-1` with a placeholder pin. It refuses if a file already exists.

   ```bash
   export AMT_ADMIN_DEPLOY_DIR=/srv/amt-mcp AMT_ADMIN_SSH_ENTRY=docker-host-ssh
   python3 deploy/amt_admin.py device init
   # expect: {"written": ["my-server-1"]}
   python3 deploy/amt_admin.py device edit my-server-1 --ip 198.51.100.26 --repin
   python3 deploy/amt_admin.py device add my-server-2 --ip 198.51.100.27 --amt-vault-key my-server-2-amt --pin <64 hex>
   ```

   `edit ... --repin` replaces the placeholder pin with the leaf the host presents now. Here it reuses the key `my-server-1` and the entries `my-server-1-amt` and `my-server-1-os` that `init` seeded; pass `--no-host` if there is no `my-server-1-os` entry. To start with a different key, `add` it, then `device remove my-server-1` (the last server cannot be removed, so add first).

   Every `add`, `edit` and `remove` does three things: writes `config/devices.json` on the Docker host under `flock` on `config/.devices.lock`, rebuilds the dedicated vault (`vault sync`), and prints `vault status`. Success is a final line starting `{"vault": ` and exit status 0. A non-zero status means a needed entry is missing from the vault or its value differs from the main vault.

   Then check:

   ```bash
   python3 deploy/amt_admin.py device list
   python3 deploy/amt_admin.py device pin my-server-1     # expect "matches": true, exit status 0
   python3 deploy/amt_admin.py vault status               # expect every entry on_nas true and matches true
   ```

   How `vault sync` works: it builds a new vault in a private temporary directory on your machine, from the main-vault entries the servers name (each device's `amt_vault_key`, `host_vault_key`, `<amt_vault_key>-rfb` and `<device>-amt-user-*` entries that exist), streams it over ssh, and renames each file over the old one with the old pair kept as `.prev-amt-mcp.vault` and `.prev-amt-mcp.key`. The container keeps its mount and sees the new files without a restart. The vault directory is left at mode 0700 and the files at 0600, so the container can store console intake entries. Re-run `vault sync` after you rotate any of those values in the main vault.

   **Ownership.** Those files are 0600, owned by the ssh user. The container reads and writes them as `DEPLOY_UID`, so the ssh user must be that same uid.

   **Manual route (no ssh, or you are working on the Docker host).** The source has no local mode for this, so there is no command to give; the script always goes over ssh. What it does can be done by hand with the vault CLI: set `NVAULT_VAULT_PATH` and `NVAULT_MASTER_KEY_FILE` to files inside `vault/`, run `secrets.py init` (which creates the key, as `amt_admin.py` does), store each entry with `secrets.py set <name> --expires <date>`, leave the files mode 0400 and owned by `DEPLOY_UID`, and write `config/devices.json` in the format in section 5 (the empty file `{"version": 1, "devices": {}}` is enough to start). Then add servers with the `amt_device_manage` tool, which pins the leaf each presents. That tool needs the vault entries it names to exist in the container's vault already. Whatever pin you write by hand is trusted as written, so take it from an independent reading (section 3).

8. **Check the result** with the first calls in section 9.

### 6.3 What the compose file sets

For reference, `amt-mcp` runs with `user: DEPLOY_UID:DEPLOY_GID`, `HOME=/data`, `AMT_BIND_HOST=0.0.0.0`, `AMT_PORT=8765`, `AMT_DEVICES_FILE=/config/devices.json`, `AMT_STATE_DIR=/data/state`, `AMT_SHOT_DIR=/data/state/shots`, `AMT_IMAGE_ROOT=/iso`, `AMT_SECRETS_CLI=/opt/node-vault-mcp/services/secrets.py`, `NVAULT_VAULT_PATH=/vault/amt-mcp.vault` and `NVAULT_MASTER_KEY_FILE=/vault/amt-mcp.key`, plus the values from `site.vars`. Mounts: `./data` to `/data`, `./iso` to `/iso`, `./vault` to `/vault` read-write, `./config` to `/config`, `./node-vault-mcp` to `/opt/node-vault-mcp/services` read-only. Ports are published on the host loopback only: `127.0.0.1:8765` and `127.0.0.1:8766`. Nothing listens on the LAN; the proxy in the next section is the only way in.

Two behaviours follow from those mounts:

- **The vault is writable by the container.** `amt_identity_manage intake` (storing a value through a one-time url) writes the console's entries into it, and `amt_identity_manage remove` deletes them. `amt_admin.py vault sync` rebuilds it from the main vault and carries those console entries over.
- **The config directory is writable by the container.** `amt_device_manage` and `amt_admin.py device` both write `config/devices.json` under the same lock.

The image listens on `0.0.0.0` inside the container only. The mirror and serial viewer pages start on the container's `127.0.0.1:8766` by default, which the published port cannot reach; start them with `bind: "0.0.0.0"` (section 5).

## 7. Reverse proxy

Put a TLS reverse proxy in front of the loopback ports, on 443, reachable from your LAN only. The bearer must never cross plain HTTP. Any proxy works; the requirements are:

| Host name | Forward to | Carries |
|---|---|---|
| `amt.example.com` | `127.0.0.1:8765` | `/mcp`, and the one-time `/handoffs/<token>`, `/uploads/<token>`, `/intake/<token>` routes. Forward every path. |
| `amt-viewer.example.com` | `127.0.0.1:8766` | Viewer pages `/m/<token>/` (mirror) and `/s/<token>/` (serial terminal), with their `stream`, `frame.jpg`, `status.json` and `events` sub-paths. |
| `amt-console.example.com` | `127.0.0.1:8767` | The management console. See [install-console.md](install-console.md). |

Requirements:

1. **Host header.** Forward the original name (`Host: amt.example.com`) and list it in `AMT_ALLOWED_HOSTS`. DNS-rebinding protection stays on; a Host not on the list is answered `421 Invalid Host header`. A browser-style client whose `Origin` is not on the list gets `403 Invalid Origin header`.
2. **No response buffering.** The mirror's MJPEG stream and the serial terminal's server-sent events are long-lived streaming responses. The server sends `X-Accel-Buffering: no` on both, which nginx honours, but set buffering off explicitly as well.
3. **Long timeouts** on the viewer host: a stream stays open for as long as someone watches. Set the read timeout to hours, not the default.
4. **Large uploads.** `amt_images upload` PUTs an ISO to `/uploads/<token>` on the MCP host. Remove the proxy's request-size limit on that host and stream the request rather than buffering it (nginx's default limit is 1 MB).
5. **LAN only.** Restrict the listeners to your LAN. The viewer URLs carry their access token in the path; do not publish them.
6. **The console needs a way in.** If you deploy the console, its calls to these two sites come from Docker's default bridge (`172.17.0.0/16`): add that range to both allow lists ([install-console.md](install-console.md), section 7).
7. **A client on the Docker host itself** can skip the proxy and use `http://127.0.0.1:8765/mcp`: loopback `Host` values are always accepted. Anything else goes through the proxy.
8. **Origins match the configuration.** `AMT_PUBLIC_BASE_URL` must be the origin clients actually use, because the one-time urls the server returns are built from it.

An nginx example, trimmed to the parts that matter:

```nginx
server {
    listen 443 ssl;
    server_name amt.example.com;
    ssl_certificate     /etc/ssl/amt.example.com.pem;
    ssl_certificate_key /etc/ssl/amt.example.com.key;
    allow 198.51.100.0/24;
    deny  all;

    client_max_body_size 0;
    proxy_request_buffering off;

    location / {
        proxy_pass http://127.0.0.1:8765;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_read_timeout 3600s;
    }
}

server {
    listen 443 ssl;
    server_name amt-viewer.example.com;
    ssl_certificate     /etc/ssl/amt-viewer.example.com.pem;
    ssl_certificate_key /etc/ssl/amt-viewer.example.com.key;
    allow 198.51.100.0/24;
    deny  all;

    location / {
        proxy_pass http://127.0.0.1:8766;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_buffering off;
        proxy_read_timeout 86400s;
    }
}
```

Success: from a machine on the LAN, `curl -sI https://amt.example.com/` returns an HTTP response rather than a TLS or connection error (the endpoint itself is `/mcp`), and an address outside the allowed range is refused by the proxy.

## 8. Connect an MCP client

Endpoint: `https://amt.example.com/mcp` (locally, `http://127.0.0.1:8765/mcp`). The transport is streamable HTTP and the server is stateless. Every call, reads included, must carry `Authorization: Bearer <token>`, where `<token>` is the value stored as `mcp-admin-token`.

A generic client entry has this shape (field names vary by client):

```json
{
  "mcpServers": {
    "amt-mcp": {
      "type": "http",
      "url": "https://amt.example.com/mcp",
      "headers": { "Authorization": "Bearer <supplied by the client's secret mechanism>" }
    }
  }
}
```

The token has to come from the client's own secret mechanism, such as a command the client runs at connect time that reads it from the vault, or the client's secret store. Do not paste the token into the file, and do not export it in a shell profile: both leave it where it should not be. The vault side of such a helper is `secrets.py get mcp-admin-token`.

For a local stdio run there is no bearer. The client starts the process, so give it the command and the non-secret environment:

```json
{
  "mcpServers": {
    "amt-mcp": {
      "command": "python3",
      "args": ["/path/to/amt-mcp/amt_server.py", "--transport", "stdio"],
      "env": {
        "AMT_SECRETS_CLI": "/path/to/node-vault-mcp/services/secrets.py",
        "AMT_DEVICES_FILE": "/path/to/devices.json",
        "AMT_DEFAULT_DEVICE": "my-server-1"
      }
    }
  }
}
```

A refusal for a missing or wrong bearer is an MCP tool error (an `isError` result on an HTTP 200), never an HTTP 401 or 403.

## 9. Verify the install

Run these from your client, in order. Each one builds on the last.

1. **`amt_devices` with `action: "list"`.** Success: `source` is `file` (or `built-in` if you did not set `AMT_DEVICES_FILE`), and each device shows `pinned: true` and its vault entry names. This proves the bearer, the transport, the Host check, and the devices file.
2. **`amt_devices` with `action: "pin_check"`, `device: "my-server-1"`.** One TLS handshake, no credential. Success: `matches: true`, with `presented` equal to `stored`. This proves the server can reach the host's WS-MAN port.
3. **`amt_identities`.** Success: every entry the servers need shows `status: "present"`. A `missing` entry means every call to that server fails.
4. **`amt_status` with `device: "my-server-1"`.** Several WS-MAN requests, one authenticated attempt each. Success: power state, AMT version, `provisioning.control_mode` (expect `admin_control_mode`), redirection states and the user-consent policy. This proves the vault read, the admin password and the pin. `unavailable` may list classes the host does not expose; that is not a failure.

The call log. Every call that passes the bearer check writes one line to stderr (visible with `docker logs amt-mcp` in Docker):

```text
2026-10-22 11:00:00,123 amt_mcp.calls tool=amt_status principal=fleet
```

The format is `<time> amt_mcp.calls tool=<name> principal=<fleet|console>`; a stdio run logs `principal=stdio`. It never contains a token, a hash or an argument. A call refused for a missing bearer is refused before this line is written, so it leaves no entry. A tool name that is not a plain identifier is logged as `<invalid-name>`.

If a step fails, go to the table below.

## 10. Troubleshooting

Errors raised inside a tool reach the client as `Error executing tool <name>: <message>`; the messages below are the `<message>` part. The bearer refusal is the exception: it is raised before the tool runs and arrives as written.

| Symptom | Cause | Fix |
|---|---|---|
| Server exits at start with `amt-mcp: refusing to start the HTTP mount: MCP_ADMIN_TOKEN_HASH is unset or is not a 64-character SHA-256 hex digest (fail closed)`, status 2 | The hash is missing or not exactly 64 hex characters | Derive it again (section 4). In Docker, check `amt-mcp.env` has the `MCP_ADMIN_TOKEN_HASH=` line, mode 0600, and that `docker compose` is run from the deploy directory so it finds the file. |
| `this call requires the mcp-admin-token bearer header (Authorization: Bearer <token>); the call was refused and nothing ran` | No bearer, a wrong bearer, a hash that does not match the token's SHA-256, or an unusable fleet hash (which refuses every token, the console's too) | Check the client really sends the header and the proxy forwards `Authorization`. Re-derive the hash from the same token. The refusal is an MCP error, not an HTTP status. |
| HTTP `421 Invalid Host header` | The `Host` the proxy forwards is not in `AMT_ALLOWED_HOSTS` | Add the name (no scheme), and make the proxy forward the original Host. |
| HTTP `403 Invalid Origin header` | A browser-based client sent an `Origin` that is not allowed | Add the client's host to `AMT_ALLOWED_HOSTS`. |
| `devices_file_unusable:<ErrorType>` (`FileNotFoundError`, `PermissionError`, `ValueError`, ...) | `AMT_DEVICES_FILE` is set but the file is missing, unreadable or malformed. The server fails closed and does not fall back to the built-in registry | Check the path and the mount, that `DEPLOY_UID` can read it, and that it parses as `{"version": 1, "devices": {...}}`. |
| `unknown_device:<key>` | The key is not in the registry, or a call that names no device used `AMT_DEFAULT_DEVICE` (default `my-server-1`) which is not in your file | Use a key from `amt_devices list`; set `AMT_DEFAULT_DEVICE` to one of your keys and restart. |
| `tls_leaf_unpinned_refused` | The device has no `tls_leaf_sha256` | Pin it: `amt_device_manage` `edit` with `repin: true`, or `amt_admin.py device edit KEY --repin`. Verify the leaf independently first. |
| `tls_leaf_pin_mismatch` | The host presents a different certificate than the stored pin: it was regenerated, TLS was reconfigured, or another machine holds the address | Run `amt_devices pin_check` and compare the presented leaf with an independent reading. If the change is legitimate, re-pin; if it is not, treat it as an incident. |
| `wsman_auth_failed_401` | The AMT rejected the `admin` password from the vault: wrong, rotated, or the account is locked | Fix the vault value (and make sure it matches AMT) **before** calling again. The server makes one unauthenticated and one authenticated request per call and never retries a second 401, so a bad password is not hammered, but each new call tries once more and repeated calls can lock the account out. Changing a vault value does not change the password on the AMT. |
| KVM, SOL or IDE-R fail with `auth_failed_status_<n>` or `auth_rejected_no_retry` | Same cause as above, on the redirection port. One answer, no retry | Same fix. |
| `wsman_unreachable:<ExceptionType>` (for example `TimeoutError`, `ConnectionRefusedError`) | The server cannot open a connection to `amt_ip:wsman_port`: wrong address or port, AMT TLS not enabled, or a network path problem | Test reachability from the machine running the server. Check the address in `amt_devices show`. |
| `vault_cli_unset:AMT_SECRETS_CLI` | `AMT_SECRETS_CLI` was not set in the server's environment when it started | Set it and restart (it is read once). In Docker it comes from the compose file. |
| `vault_miss:<name>` | The entry does not exist in the vault the server reads, or the CLI exited non-zero (including a master key it cannot read) | Run `amt_identities`; store the entry; in Docker run `amt_admin.py vault sync`. Check `NVAULT_VAULT_PATH` and `NVAULT_MASTER_KEY_FILE` and that `DEPLOY_UID` can read the files. |
| `vault_unavailable:<name>:<ErrorType>` | The CLI could not be run, or timed out (15 s) | Check the CLI path and that its dependencies are installed in the server's Python environment. |
| `vault_empty:<name>` or `vault_bad_credential_shape:<name>` | The entry has no value, or the host logon entry is not JSON with `user` and `password` | Re-store the value. |
| `vault <name> in this server's vault (...) first` on `amt_device_manage add` or `edit` | A vault entry the device names does not exist yet | Store the entry, sync it into the dedicated vault, then repeat. |
| `device changes need AMT_DEVICES_FILE: ...` | `amt_device_manage` was called on a server using the built-in registry | Set `AMT_DEVICES_FILE`. |
| `confirmation_required: this ... Nothing was done. Re-call with confirmed=true only on the operator's explicit approval.` | A write tool was called without the JSON boolean `true` | Intended behaviour. Re-call with `confirmed: true` when you mean it. |
| Compose stops with `required variable <NAME> is missing a value: set in site.vars` | A line is missing or empty in `site.vars`. The whole compose file is checked, including the console's variables | Fill in every line of `site.vars` (section 6.2, step 4). |
| Compose stops with `env file .../amt-mcp.env not found` | `amt-mcp.env` does not exist in the deploy directory | Create it (section 6.2, step 5). |
| `PermissionError`, or `shot_dir_unsafe:...` / `handoff_dir_unsafe` in the container | `data/` (or another mount) is not owned by `DEPLOY_UID`, often because Docker created it as root | `chown` the directories to the deploy user and restart. |
| `amt_remote_logon` / `amt_remote_logoff` return `aborted: true` with `reason: "ocr_unavailable"` and `typed_nothing: true` | No OCR backend on the server | Install `tesseract` plus Pillow (already in the image), or `ocrmac` on macOS. |
| `ffmpeg_missing: install ffmpeg to get .mp4 recordings` | No `ffmpeg` on the server's `PATH` | Install it. The raw `.mjpeg` and `.times` files are kept. |
| The mirror or serial link does not open through the front | The viewer started on `127.0.0.1` inside the container, so the proxy cannot reach it, and no front url is listed | Start it with `bind: "0.0.0.0"`. |
| `viewer_server_in_use: pages are live at <bind>:<port>; ...` | A mirror or terminal is live on a different bind or port | Use that bind and port, or stop the live mirrors and terminals first. |
| `ider_upload_needs_AMT_PUBLIC_BASE_URL` or `identity_intake_needs_AMT_PUBLIC_BASE_URL` | `AMT_PUBLIC_BASE_URL` is unset | Set it to the origin clients use. |
| Intake PUT answers `503 vault_not_writable: nothing was stored` | The container cannot write `vault/`: the mount is read-only, or the folder or files are not writable by `DEPLOY_UID` (an older `vault sync` left them 0500 and 0400) | Run `amt_admin.py vault sync` from this version (it leaves 0700 and 0600), or `chmod 700 vault; chmod 600 vault/amt-mcp.*` as the deploy user. Keep the mount without `:ro`. |
| A stream (mirror, serial terminal) freezes or drops after a short time | The proxy is buffering or its read timeout is too short | Section 7, requirements 2 and 3. |
| `ider_image_root_unset: set it with amt_images action=set_root (or the AMT_IMAGE_ROOT env)` | No image folder configured | Set `AMT_IMAGE_ROOT`, or run `amt_images` with `action: "set_root"`. |

## 11. Upgrading

1. Put the new code in place. `tar -x` over `src/` does not delete files that were removed, so extract into a fresh directory and swap:

   ```bash
   cd /srv/amt-mcp
   mkdir src.new && git archive <ref> | tar -x -C src.new     # run git in a clone; or pipe over ssh as in step 2
   mv src src.prev && mv src.new src
   ```

2. Rebuild and restart from the deploy directory:

   ```bash
   docker compose --env-file ./site.vars -f src/deploy/compose.yaml --project-directory . up -d --build amt-mcp
   ```

3. Repeat the checks in section 9.
4. To roll back the code: `mv src src.bad && mv src.prev src`, then step 2 again. The data rollback files are below.

What survives an upgrade: everything outside `src/`. The devices file (`config/devices.json`), the dedicated vault (`vault/`), `amt-mcp.env`, `site.vars`, `data/` and `iso/` are bind-mounted from the host and are not touched by a rebuild. Compare `site.vars` with the new `deploy/site.vars.example` for lines added in the new version, since Compose rejects a missing one.

Rollback files:

- `config/.prev-devices.json`: the devices file as it was before the last change, kept by both `amt_device_manage` and `amt_admin.py`.
- `vault/.prev-amt-mcp.vault` and `vault/.prev-amt-mcp.key`: the vault pair before the last `vault sync`. To roll back, rename them over the live pair.

Each is one generation deep: the next change overwrites it.

The image pins the base image by tag (`python:3.12.7-slim-bookworm`), not by digest, and does not version-pin its `apt` packages (`tesseract-ocr`, `ffmpeg`), so a rebuild can pick up newer ones. The Python pins are `mcp==1.26.0`, `pillow==12.1.1` and `cryptography==46.0.3`. Re-verify them against your deployment before changing them.

## 12. Keeping this guide current

| Section | Proven by | Update it when |
|---|---|---|
| 1. What you install | `amt_server.py` (`register_tools`, `main`), `amt_tools.py`, `amt_write.py`, `amt_fleet.py`, `amt_identity.py`, `amt_captures.py`, `amt_mirror.py`, `amt_serial.py` | A tool is added, removed or changes its read/write class (recount: 9 read, 14 write) |
| 2. Prerequisites | `pyproject.toml`, `Dockerfile`, `amt_tools.py` (`OCR_BACKENDS`), `amt_mirror.py` | A dependency, a pin, the Python floor or an OCR backend changes; a module is added to or removed from `pyproject.toml` |
| 3. AMT host and TLS pin | `amt_wsman.py` (`_PinnedHTTPSConnection`), `amt_redir.py` (`pinned`), `amt_kvm.py`, `amt_fleet.py`, `amt_registry.py`, `amt_tools.py` (`status`) | Pin handling, the account name, a redirection port or the registry fields change |
| 4. Vault entries | `amt_vault.py`, `amt_tools.py`, `amt_write.py`, `amt_identity.py`, `amt_gate.py` | A new entry name pattern is read, or the CLI contract changes |
| 5. Local run, env table | `amt_server.py`, `amt_gate.py`, `amt_handoff.py`, `amt_upload.py`, `amt_mirror.py`, `amt_write.py`, `amt_tools.py`, `amt_registry.py`, `amt_wsman.py`. Re-list with `grep -n 'environ' amt_*.py` | Any environment variable is added, removed or changes its default |
| 6. Docker | `deploy/compose.yaml`, `deploy/site.vars.example`, `deploy/amt_admin.py`, `Dockerfile` | A mount, port, variable, directory or `amt_admin.py` command changes |
| 7. Reverse proxy | `amt_server.py` (`_allowed_hosts`), `amt_mirror.py`, `amt_serial.py` (stream headers), `amt_handoff.py`, `amt_upload.py` | A route, a stream, a port or a header requirement changes |
| 8-9. Client and verification | `amt_gate.py` (`call_log`, `_REFUSAL`), `amt_fleet.py` (`amt_devices`), `amt_tools.py` (`status`) | The log format, the refusal text or the first-call outputs change |
| 10. Troubleshooting | The error strings quoted from the files named in each row; check each with `grep -n '<string>' amt_*.py` | An error string is renamed or a new common failure appears |

Any change to a tool, a route, an environment variable or a deploy step updates this guide in the same commit. Keep [mcp-guide.md](mcp-guide.md), [operators-guide.md](operators-guide.md) and [../README.md](../README.md) consistent with it.
