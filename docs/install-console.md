# Install amt-console

This guide installs the amt-console web UI (`console/`) beside a running amt-mcp. It covers the
console's bearer, the settings amt-mcp needs for it, the Docker deployment, the reverse proxy, the
first passkey, checks that prove the install, and the failures you are most likely to meet.

It assumes amt-mcp is already installed, running and reachable through the TLS reverse proxy. If
it is not, start with [install-mcp.md](install-mcp.md). For using the console once it runs, see
[console-guide.md](console-guide.md) (the UI in depth) and [operators-guide.md](operators-guide.md)
(day-to-day work). The repository map is in [../README.md](../README.md).

Example values used throughout (replace them with yours): device key `my-server-1`, AMT addresses
`198.51.100.x`, MCP origin `https://amt.example.com`, viewer origin `https://amt-viewer.example.com`,
console origin `https://amt-console.example.com`, deploy directory `/srv/amt-mcp`.

## Install checklist

| # | Step | Automated by the repo? |
|---|------|------------------------|
| 1 | Prerequisites: amt-mcp up, Docker, passkey authenticator, TLS (section 2) | no |
| 2 | Mint the console bearer, store it in the console's own vault, put its SHA-256 in `amt-mcp.env`, recreate amt-mcp (section 3) | **no**: nothing in `deploy/amt_admin.py` creates the console vault or edits `amt-mcp.env` |
| 3 | Check amt-mcp's side settings in `site.vars` (section 4) | no (compose requires them) |
| 4 | Create `console-data/`, fill `site.vars`, build and start `amt-console` (section 6) | compose builds and starts it |
| 5 | Add the console's reverse-proxy site, and let the console reach the MCP and viewer origins (section 7) | no |
| 6 | Mint the one-time enrollment code and create the first passkey (section 8) | `amt_admin.py console enroll-code` (or write the file by hand) |
| 7 | Verify (section 10) | no |

## 1. What the console is and how it is wired

amt-console is a Python standard-library HTTP backend (`console/server.py`) plus a static browser
client (`console/pages`, `console/static`). It holds no AMT state of its own. Every action the
browser asks for becomes one MCP `tools/call` to amt-mcp, made by the backend with the console's own
bearer. The browser never calls `/mcp` and never holds a bearer, a one-time url or a viewer token.
The only third-party Python package is `cryptography` (WebAuthn signature checks).

```
 browser ──HTTPS 443──► reverse proxy ──HTTP──► amt-console   127.0.0.1:8767 (container 8767)
                        amt-console.example.com      │
                                                     ├─ tools/call, bearer = console token
                                                     │   HTTPS ─► reverse proxy ─► amt-mcp 127.0.0.1:8765  /mcp
                                                     │            amt.example.com
                                                     │
                                                     └─ viewer pages (KVM, SOL), relayed to the browser under /embed/
                                                         HTTPS ─► reverse proxy ─► amt-mcp viewer 127.0.0.1:8766
                                                                  amt-viewer.example.com
```

The settings behind the arrows:

| Hop | Setting | Value in the example |
|-----|---------|----------------------|
| Browser to console | `AMT_CONSOLE_ORIGIN`, `AMT_CONSOLE_RP_ID` | `https://amt-console.example.com`, `amt-console.example.com` |
| Console to amt-mcp | `AMT_CONSOLE_MCP_URL` (compose: `AMT_PUBLIC_BASE_URL` + `/mcp`) | `https://amt.example.com/mcp` |
| Console to viewer pages | `AMT_CONSOLE_VIEWER_ORIGIN` (compose: `AMT_VIEWER_PUBLIC_BASE_URL`) | `https://amt-viewer.example.com` |

**Why the console runs on Docker's default bridge and calls amt-mcp through the proxy.**

- The console is a separate container with none of amt-mcp's mounts (vault, devices file, image
  root). Its only door into amt-mcp is the public `/mcp` mount, so it calls it the way any client
  does.
- amt-mcp keeps DNS-rebinding protection on: it accepts `Host` values for loopback and for the names
  in `AMT_ALLOWED_HOSTS` only (`amt_server.py`, `_allowed_hosts`). A call by compose service name
  would carry a `Host` that is not on that list. (The MCP SDK this repo pins, 1.26.0, answers an
  unlisted host with HTTP 421 `Invalid Host header`.) Calling the public name keeps the list as it is.
- amt-mcp builds every one-time url (download handoff, image upload, identity intake) from
  `AMT_PUBLIC_BASE_URL`, and the console follows such a url only when its scheme and host:port equal
  those of `AMT_CONSOLE_MCP_URL`. The two must therefore be the same origin.
- `network_mode: bridge` in `deploy/compose.yaml` puts the container on Docker's default bridge
  (172.17.0.0/16) instead of a compose-created network (172.24/16). A proxy whose allow rule admits
  only the LAN and the default bridge then lets the console's own calls through; a compose network
  would need its own allow rule.
- Every port is bound to the host's loopback (`127.0.0.1:8767:8767`). Nothing listens on the LAN;
  the proxy is the only way in.

## 2. Prerequisites

1. **amt-mcp running and reachable through the proxy** at its public origin, with its own bearer
   already working ([install-mcp.md](install-mcp.md)).
2. **Docker with the compose plugin** on the host that runs amt-mcp, and the deploy directory from
   the amt-mcp install (`/srv/amt-mcp`: `site.vars`, `src/` holding this repository, `node-vault-mcp/`,
   `vault/`, `config/`, `amt-mcp.env`).
3. **TLS on the console's origin.** WebAuthn only works in a secure context, and the session cookie is
   `Secure`. Plain HTTP to the console's address does not work for sign-in.
4. **TLS the console itself trusts.** The console calls the MCP and viewer origins over HTTPS and
   verifies the proxy's certificate with Python's default settings (`console/mcp_client.py` passes no
   custom context, and there is no setting for a private CA). Those certificates must chain to a CA
   the `python:3.12.7-slim-bookworm` image trusts. A certificate from a private CA fails with
   `amt_mcp_unreachable:SSLCertVerificationError` (section 11). Names must also resolve from inside
   the container.
5. **A browser with WebAuthn and a passkey authenticator**: a platform authenticator (Touch ID,
   Windows Hello), a phone, or a FIDO2 security key. The console requires ES256, a discoverable
   credential (`residentKey: required`), user verification (PIN or biometric) and attestation `none`
   (`console/auth.py`, `console/webauthn_min.py`). An authenticator that cannot do all of those is
   refused.
6. **For a local run only** (section 9): Python 3.10 or newer (`pyproject.toml` `requires-python`;
   the image uses 3.12.7) and `cryptography==46.0.3` (`console/requirements.txt`, kept equal to the
   root `Dockerfile`'s pin).
7. **On the machine you run `deploy/amt_admin.py` from** (section 8): the repository checked out with
   amt-mcp's own dependencies installed (`pip install 'mcp>=1.26,<2' pillow`, because `amt_admin.py`
   imports `amt_fleet`, which imports the server modules), a node-vault-mcp vault, and ssh access to
   the Docker host.

## 3. The console bearer

The console authenticates to amt-mcp with its own bearer, separate from the fleet bearer
(`mcp-admin-token`). amt-mcp is configured with the SHA-256 of that bearer only. The token itself
lives in a vault that holds nothing else.

How amt-mcp checks it (`amt_gate.py`):

- `MCP_CONSOLE_TOKEN_HASH` must be 64 hex characters (case ignored, whitespace trimmed). Unset or
  malformed, the console token never matches and only the fleet bearer works.
- A presented bearer is hashed with SHA-256 and compared in full with `hmac.compare_digest` against
  the fleet hash and the console hash.
- `MCP_ADMIN_TOKEN_HASH` (the fleet hash) must be valid as well: when it is not, every token is
  refused, the console's included. (Over HTTP the server does not start without it.)
- A refusal is an MCP tool error, never an HTTP 401 or 403. Its text is `this call requires the
  mcp-admin-token bearer header (Authorization: Bearer <token>); the call was refused and nothing ran`.
- Each call that passes the gate is logged to stderr as `tool=<name> principal=fleet` or
  `tool=<name> principal=console`. The line never holds a token or a hash.

Nothing in `deploy/amt_admin.py` creates the console's vault or its token. Do it by hand, once, with
the node-vault-mcp CLI `secrets.py`, using only the forms this repository already uses
(`deploy/amt_admin.py`, `_build`): `secrets.py init`, and `secrets.py set <key> --expires <date>
--notes <text>` reading the value from stdin. `NVAULT_VAULT_PATH` and `NVAULT_MASTER_KEY_FILE` choose
the vault.

The block below generates the token inside one Python process, pipes it straight into `secrets.py set`
on stdin, and prints only its SHA-256. The token is never in argv, in the environment, in a file or on
the terminal. Run it on the Docker host as the deploy user (so the files end up with the right owner),
from the deploy directory. The host needs `python3` with `cryptography` installed for `secrets.py`. If
it has none, run the block on any machine that does, then copy the two files over an authenticated
channel (scp) and `chown` them to `DEPLOY_UID:DEPLOY_GID`.

```bash
cd /srv/amt-mcp
BUILD="$(mktemp -d)"        # a private (0700) scratch folder; holds the new vault until step 4

(
  export NVAULT_VAULT_PATH="$BUILD/amt-console.vault" NVAULT_MASTER_KEY_FILE="$BUILD/amt-console.key"
  unset SECRETS_KEY                     # init refuses to run while a key is supplied this way
  python3 node-vault-mcp/secrets.py init
  python3 - node-vault-mcp/secrets.py <<'PY'
import hashlib, secrets, subprocess, sys
token = secrets.token_urlsafe(32)
r = subprocess.run([sys.executable, sys.argv[1], "set", "amt-console-token",
                    "--expires", "2035-01-01", "--notes", "amt-console bearer"],
                   input=token + "\n", text=True)
if r.returncode:
    sys.exit(r.returncode)
print("MCP_CONSOLE_TOKEN_HASH=" + hashlib.sha256(token.encode()).hexdigest())
PY
)
```

Expected: `init` reports that the key and an empty vault were written; `set` reports `Stored:
amt-console-token`; the last line printed is `MCP_CONSOLE_TOKEN_HASH=` followed by 64 hex characters.
A hash is not a secret, so printing it is fine.

1. **Put the hash in amt-mcp's environment file.** Add that line to `/srv/amt-mcp/amt-mcp.env` (mode
   0600), replacing any earlier `MCP_CONSOLE_TOKEN_HASH` line. Keep the existing
   `MCP_ADMIN_TOKEN_HASH` line.
2. **Check the hash against the vault** (re-derive it from the stored token; nothing is shown but the
   hash):

   ```bash
   (
     export NVAULT_VAULT_PATH="$BUILD/amt-console.vault" NVAULT_MASTER_KEY_FILE="$BUILD/amt-console.key"
     unset SECRETS_KEY
     python3 node-vault-mcp/secrets.py get amt-console-token \
       | python3 -c 'import sys,hashlib; print(hashlib.sha256(sys.stdin.read().strip().encode()).hexdigest())'
   )
   ```

   The 64 hex characters must equal the value in `amt-mcp.env`.
3. **Install the vault for the container.** Copy only the two vault files (the scratch folder also
   holds a lock file and a `.backups` folder, which the console does not need):

   ```bash
   mkdir -p console-vault
   install -m 0400 "$BUILD/amt-console.vault" "$BUILD/amt-console.key" console-vault/
   chmod 500 console-vault
   rm -r "$BUILD"
   ```

   `console-vault/` holds exactly `amt-console.vault` and `amt-console.key`, each 0400 and owned by
   `DEPLOY_UID`; compose mounts the folder read-only at `/vault`.
4. **Recreate amt-mcp so it reads the new variable.** The hash is read from the process environment, and
   `docker compose restart` does not re-read `env_file`, so recreate the container:

   ```bash
   docker compose --env-file ./site.vars -f src/deploy/compose.yaml --project-directory . \
     up -d --force-recreate amt-mcp
   ```

   Success signal: after the console runs (section 10), `docker logs amt-mcp` shows
   `tool=... principal=console`.

**Rotating the token** is the same procedure with a fresh scratch folder: build a new vault, replace the
hash in `amt-mcp.env`, recreate amt-mcp, replace the two files in `console-vault/`, and restart
`amt-console`. The console keeps the token in memory and re-reads the vault after a refusal, but a
restart is the sure way.

## 4. Settings amt-mcp needs for the console

These are the amt-mcp container settings the console depends on: four that compose takes from
`site.vars`, plus the hash from section 3. Each is verified in source:

| Setting (amt-mcp side) | Where | What it does for the console |
|------------------------|-------|------------------------------|
| `MCP_CONSOLE_TOKEN_HASH` | `amt-mcp.env` | Admits the console's bearer; calls are logged `principal=console` (`amt_gate.py`). |
| `AMT_PUBLIC_BASE_URL` | `site.vars` | `scheme://host[:port]` that clients, the console included, reach amt-mcp at. Every one-time url amt-mcp returns (download handoff, image upload, identity intake) starts with it, and the console accepts such a url only from the origin of `AMT_CONSOLE_MCP_URL`. Compose derives `AMT_CONSOLE_MCP_URL` as this value plus `/mcp`, so they cannot drift apart. Unset, tools return paths and no handoff urls (`amt_handoff.py`). |
| `AMT_ALLOWED_HOSTS` | `site.vars` | Must include the host name of `AMT_PUBLIC_BASE_URL` (the `Host` the proxy forwards). Without it the SDK answers 421. |
| `AMT_VIEWER_PUBLIC_BASE_URL` | `site.vars` | Origin of the viewer front. A viewer started with `bind=0.0.0.0` lists its front url first (`amt_mirror.py`, `_urls`); the console starts viewers that way and relays only a control url whose scheme and host:port equal `AMT_CONSOLE_VIEWER_ORIGIN`. |
| `AMT_CONSOLE_ORIGIN` | `site.vars` | A plain `http(s)://host[:port]` origin (trailing slash stripped; anything else is treated as unset). It sets `frame-ancestors` on every viewer response (`'none'` when unset) and is the only origin that gets CORS headers on the `PUT /uploads/<token>` and `PUT /intake/<token>` routes (`amt_upload.py`). Compose requires it. |

Notes:

- Compare `AMT_PUBLIC_BASE_URL` and `AMT_CONSOLE_MCP_URL` character by character. `https://amt.example.com`
  and `https://amt.example.com:443` are different origins to the console.
- With this console, `AMT_CONSOLE_ORIGIN` on amt-mcp is not what lets a KVM or SOL frame display. The
  console fetches the viewer page itself and re-serves it under its own `/embed/` path with its own
  headers; the viewer's framing headers are never copied back (`console/embed.py`). The setting still
  matters for any direct framing of a viewer url and for CORS on the upload and intake routes, so set it
  to the console's origin as compose requires.
- One `site.vars` value, `AMT_CONSOLE_ORIGIN`, feeds both containers: the amt-mcp setting above and the
  console's own `AMT_CONSOLE_ORIGIN`.

## 5. Console configuration

The console reads these from the environment at start (`console/server.py`, `Config.from_env`). The
defaults in the code are example values, so set every origin explicitly.

| Variable | Default in code | Meaning | Set by compose |
|----------|-----------------|---------|----------------|
| `AMT_CONSOLE_ORIGIN` | `https://amt-console.example.com` | The console's public origin, exactly as the browser shows it: `scheme://host[:port]`, no path, no trailing slash (a slash stops the console at start). Compared exactly with each POST's `Origin` and with the origin inside passkey data. | from `site.vars` |
| `AMT_CONSOLE_RP_ID` | `amt-console.example.com` | WebAuthn relying-party id: the console's host name, no scheme or port. | from `site.vars` |
| `AMT_CONSOLE_DATA` | `/console-data` | Folder for passkeys, sessions, captures and the enrollment file. Created 0700 if missing; must be writable. | `/console-data` |
| `AMT_CONSOLE_MCP_URL` | `https://amt.example.com/mcp` | amt-mcp's MCP endpoint. Its scheme and host:port also fix where handoff, upload and intake urls may point. | `${AMT_PUBLIC_BASE_URL}/mcp` |
| `AMT_CONSOLE_VIEWER_ORIGIN` | `https://amt-viewer.example.com` | Origin of the viewer front; same format rule as `AMT_CONSOLE_ORIGIN`. | `${AMT_VIEWER_PUBLIC_BASE_URL}` |
| `AMT_CONSOLE_SECRETS_CLI` | none (unset means no bearer can be read) | Path of node-vault-mcp's `secrets.py`, run as a child process to read `amt-console-token`. | `/opt/node-vault-mcp/services/secrets.py` |
| `NVAULT_VAULT_PATH` | none in the console; the CLI falls back to its own default vault | The console's vault file. Always set it, or the CLI looks at a different vault. | `/vault/amt-console.vault` |
| `NVAULT_MASTER_KEY_FILE` | none in the console; the CLI has its own default | The key file for that vault. Always set it. | `/vault/amt-console.key` |
| `AMT_CONSOLE_BIND` | `0.0.0.0` | Address the server binds. | `0.0.0.0` (the image sets the same) |
| `AMT_CONSOLE_PORT` | `8767` | Listen port. | `8767` |
| `AMT_CONSOLE_IDLE_HOURS` | `12` | Idle time before a session expires. | `12` |
| `AMT_CONSOLE_CAPTURE_HOURS` | `24` | How long a fetched capture (screenshot, recording) is kept. | `24` |
| `AMT_CONSOLE_MCP_TIMEOUT` | `60` (seconds) | Timeout of one HTTP call to amt-mcp. | not set; default applies |
| `AMT_CONSOLE_FLEET_SECONDS` | `30` (seconds) | Interval over which the fleet poller spreads one read per server; it polls only while a page is open. | not set; default applies |

Compose also sets `HOME=/console-data` and runs the container as `DEPLOY_UID:DEPLOY_GID`. A malformed
number in any of the numeric variables stops the server at start.

## 6. Docker deployment

### Directory layout

Under the deploy directory (`/srv/amt-mcp`), owned by the deploy user (`DEPLOY_UID`):

```
site.vars               site values, no secret in it
src/                    this repository (the build context)
node-vault-mcp/         node-vault-mcp's services/ tree (secrets.py and vault_secrets), mounted read-only
amt-mcp.env             MCP_ADMIN_TOKEN_HASH=..., MCP_CONSOLE_TOKEN_HASH=...   (0600, hashes only)
console-data/           the console's state, 0700, owned by DEPLOY_UID, mounted read-write at /console-data
console-vault/          amt-console.vault + amt-console.key, 0400 each, mounted read-only at /vault
```

plus the amt-mcp folders (`vault/`, `config/`, `data/`, `iso/`) from [install-mcp.md](install-mcp.md).
The console container mounts exactly three paths: `console-data`, `console-vault` and `node-vault-mcp`.

### Steps

1. **Create the state folder as the deploy user**, before the first start (Docker would otherwise
   create a missing bind-mount folder owned by root, and the console runs as `DEPLOY_UID`):

   ```bash
   cd /srv/amt-mcp
   mkdir -p console-data
   chmod 700 console-data
   ```

2. **Fill `site.vars`** (start from `src/deploy/site.vars.example`). The console uses these:

   | Variable | Example | Used for |
   |----------|---------|----------|
   | `DEPLOY_UID`, `DEPLOY_GID` | `1000`, `1000` | The container user; owner of `console-data/` and the vault files. |
   | `AMT_PUBLIC_BASE_URL` | `https://amt.example.com` | Becomes `AMT_CONSOLE_MCP_URL` (plus `/mcp`). |
   | `AMT_VIEWER_PUBLIC_BASE_URL` | `https://amt-viewer.example.com` | Becomes `AMT_CONSOLE_VIEWER_ORIGIN`. |
   | `AMT_CONSOLE_ORIGIN` | `https://amt-console.example.com` | The console's origin, and the amt-mcp setting of the same name. |
   | `AMT_CONSOLE_RP_ID` | `amt-console.example.com` | WebAuthn relying-party id. |

   Compose stops before starting anything if any required value in the file is missing, so the whole
   file must be complete (`AMT_ALLOWED_HOSTS` and `AMT_DEFAULT_DEVICE` too), even though the console does
   not use those two.
3. **Do section 3** (vault, hash, amt-mcp recreate) so `console-vault/` is populated and amt-mcp admits
   the token.
4. **Build and start the console:**

   ```bash
   docker compose --env-file ./site.vars -f src/deploy/compose.yaml --project-directory . \
     up -d --build amt-console
   ```

5. **Read its log:**

   ```bash
   docker logs amt-console
   ```

   Success signals: a line `amt_console amt-console on 0.0.0.0:8767 for https://amt-console.example.com`,
   preceded by the warning `no passkey is enrolled: mint a code with deploy/amt_admin.py console
   enroll-code` on a first start. A container that keeps restarting has failed at start (see section 11,
   "Container restarts").
6. **Check the console answers on loopback**, bypassing the proxy. The console refuses any request
   whose `Host` header is not its own origin's host, so send that header:

   ```bash
   curl -sS -D - -o /dev/null -H 'Host: amt-console.example.com' http://127.0.0.1:8767/signin
   ```

   Expect `200`. Without the `-H` you get 421 `{"error": "host_not_allowed"}`; that is the check
   working, not a fault.

Then continue with the proxy (section 7) and enrollment (section 8).

## 7. Reverse proxy for the console origin

Any proxy that meets these requirements works. They come from the console's behavior:

- **TLS on 443** for `amt-console.example.com`, a certificate your browsers trust (WebAuthn and the
  `Secure` cookie need it).
- **Forward to the console's loopback port**, `http://127.0.0.1:8767`, plain HTTP.
- **Pass the original `Host` unchanged.** The console answers 421 `host_not_allowed` to any `Host` other
  than its origin's host:port. Many proxies replace `Host` with the upstream address by default.
- **Pass `Origin` and `Sec-Fetch-Site` unchanged.** Every POST is checked against them.
- **No response buffering, long timeouts.** The embedded KVM view relays an MJPEG stream and the SOL view a
  server-sent-event stream through the console. The console marks those responses
  `X-Accel-Buffering: no`, and a proxy that buffers or times out an idle stream stalls the view.
- **Large request bodies, not buffered.** An image upload goes browser, console, amt-mcp as one streamed
  `POST` of the whole file (`console/images.py`); amt-mcp's own cap is `AMT_UPLOAD_MAX_BYTES` (default
  16 GiB). Set the proxy's limit at least as high as the largest image you will upload.
- **LAN only.** The console is not meant to be reachable from outside the LAN. Restrict the site to the
  LAN with the proxy's allow rules.

An nginx site that does all of that (adapt the certificate paths and the LAN range):

```nginx
server {
    listen 443 ssl;
    server_name amt-console.example.com;

    ssl_certificate     /etc/ssl/amt-console.example.com.pem;
    ssl_certificate_key /etc/ssl/amt-console.example.com.key;

    allow 198.51.100.0/24;                 # the LAN
    deny  all;

    client_max_body_size 20g;              # at least the largest image you upload
    proxy_request_buffering off;           # stream uploads instead of spooling them to disk

    location / {
        proxy_pass         http://127.0.0.1:8767;
        proxy_http_version 1.1;
        proxy_set_header   Host $host;     # use $http_host if the origin carries a non-default port
        proxy_buffering    off;            # MJPEG and server-sent-event streams
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

**The other two origins also have to admit the console.** The console's own calls travel to
`amt.example.com` and `amt-viewer.example.com` through the proxy, from inside the container on
Docker's default bridge. If those sites use LAN-only allow rules, add the default bridge subnet
(`172.17.0.0/16`, per the comment in `deploy/compose.yaml`) to their allow lists. A proxy that
answers 403 to the console's calls is the symptom (section 11). The viewer front must not buffer
streams either (amt-mcp's viewers send `X-Accel-Buffering: no`), and the amt-mcp site needs the same
upload size settings as above for image uploads. Those two sites are described in
[install-mcp.md](install-mcp.md).

## 8. First sign-in

There is no password. The first passkey is created with a one-time enrollment code.

### With `deploy/amt_admin.py` (the normal way)

`amt_admin.py` runs on the operator's machine, reads the main vault and reaches the Docker host over
ssh. It needs three environment variables:

| Variable | Meaning |
|----------|---------|
| `AMT_SECRETS_CLI` | Path of node-vault-mcp's `secrets.py` for the main vault on this machine. |
| `AMT_ADMIN_DEPLOY_DIR` | The deploy directory on the Docker host, `/srv/amt-mcp`. |
| `AMT_ADMIN_SSH_ENTRY` | Name of a main-vault entry holding a JSON value with `ssh_cmd`, `user` and `host`. The script runs `ssh_cmd` plus `-o BatchMode=yes -o LogLevel=ERROR <user>@<host> <command>`. |

If that ssh entry does not exist yet, store it (this value holds a key path and addresses, not a
password; the other `amt_admin.py` commands use the same entry):

```bash
printf '%s\n' '{"ssh_cmd": "ssh -i <path-to-private-key> -o IdentitiesOnly=yes", "user": "<deploy-user>", "host": "198.51.100.10"}' \
  | python3 "$AMT_SECRETS_CLI" set docker-host-ssh --expires 2035-01-01 --notes "ssh to the Docker host"
```

The ssh user must be the same user as `DEPLOY_UID`: the code file is written as that user with mode
0600, and the console (running as `DEPLOY_UID`) must be able to read and delete it.

Mint the code:

```bash
export AMT_SECRETS_CLI=/path/to/node-vault-mcp/services/secrets.py
export AMT_ADMIN_DEPLOY_DIR=/srv/amt-mcp
export AMT_ADMIN_SSH_ENTRY=docker-host-ssh
python3 deploy/amt_admin.py console enroll-code
```

Expected output:

```
{"enroll": {"delivered": "/srv/amt-mcp/console-data/enroll.json", "expires": <unix seconds>, "valid_minutes": 10, "uses": 1}}
enrollment code (shown once): ABCD-EFGH-JKMN
```

What the code is (`deploy/amt_admin.py`, `console/auth.py`):

| Property | Value |
|----------|-------|
| Length and alphabet | 12 characters from `ABCDEFGHJKMNPQRSTUVWXYZ23456789` (no I, L, O, 0 or 1), shown as three groups of four. |
| Validity | 10 minutes from minting. An expired file is deleted when it is next used. |
| Uses | One. A successful enrollment deletes the file, so one code creates one passkey. |
| Delivery | Only the SHA-256 of the 12 characters and the expiry are written to the host, over ssh stdin, as `console-data/enroll.json` (0600). The code itself is printed to your terminal once and goes nowhere else. |
| Replacement | Minting again replaces a pending code. |
| Wrong attempts | The fifth wrong code deletes the file (log line `enrollment code withdrawn after 5 wrong attempts`, response `enroll_locked`). The count is global, held in memory, and reset by a correct code or a console restart. Mint a new code to continue. |

Enter the code in the browser:

1. Open `https://amt-console.example.com/`. With no session you land on the sign-in page.
2. Choose **First time here? Enroll a passkey**.
3. Type the code into the three boxes (the console ignores spaces and dashes and upper-cases what you
   type, so case does not matter) and give the passkey a name (1 to 64 printable characters).
4. Choose **Create passkey** and complete the browser's prompt.

Success signal: you land on the Fleet page signed in, `console-data/` now holds `passkeys.json` and
`sessions.json`, and `enroll.json` is gone. From then on, **Sign in with passkey** on the sign-in page
signs you in (the sign-in is passkey-discoverable; there is no user name).

**Adding more passkeys later:** signed in, open **Settings**, choose **Add a passkey** in the Passkeys
card, name it and complete the prompt. The console has no control to remove a passkey. To revoke one, edit the JSON
list in `console-data/passkeys.json` (the file is read on each request, so no restart is needed).

### Without `amt_admin.py` (the console runs somewhere else, or you have no ssh path)

The console only needs a file named `enroll.json` in its `AMT_CONSOLE_DATA` folder, readable and
deletable by the user the console runs as:

```json
{"sha256": "<64 lowercase hex characters>", "expires": 1790000000}
```

- `sha256` is the SHA-256 of the 12-character code in **upper case, without dashes**.
- `expires` is a Unix time in seconds (an integer or a float). The console deletes the file when it is
  past and next consulted.
- Any other shape (missing key, `sha256` not 64 hex characters, `expires` not a number, unreadable
  file) is treated as no code open (`enroll_not_open`).

This block, run as the deploy user from the deploy directory, mints a code and writes a valid file
(0600, replaced atomically); it prints the code once. For a console started outside Docker, change
`path` to its `AMT_CONSOLE_DATA` folder:

```bash
cd /srv/amt-mcp
python3 - <<'PY'
import hashlib, json, os, secrets, time
alphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"
code = "".join(secrets.choice(alphabet) for _ in range(12))
record = {"sha256": hashlib.sha256(code.encode()).hexdigest(), "expires": int(time.time()) + 600}
path = "console-data/enroll.json"
fd = os.open(path + ".new", os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
with os.fdopen(fd, "w") as fh:
    json.dump(record, fh)
os.replace(path + ".new", path)
print(f"{code[:4]}-{code[4:8]}-{code[8:]}")
PY
```

Then enter the code on the sign-in page as above. The console does not check whether a passkey already
exists before honoring a code, so the same procedure recovers access after every passkey is lost. It
also means anyone who can write into `console-data/` can enroll a passkey: keep that folder 0700.

## 9. Running locally for development

`console/server.py` takes no arguments; everything comes from the environment. From a checkout:

```bash
pip install cryptography==46.0.3
cd console
AMT_CONSOLE_ORIGIN=http://localhost:8767 \
AMT_CONSOLE_RP_ID=localhost \
AMT_CONSOLE_BIND=127.0.0.1 \
AMT_CONSOLE_DATA="$HOME/.amt-console-dev" \
AMT_CONSOLE_MCP_URL=http://127.0.0.1:8765/mcp \
AMT_CONSOLE_VIEWER_ORIGIN=http://127.0.0.1:8766 \
AMT_CONSOLE_SECRETS_CLI=/path/to/node-vault-mcp/services/secrets.py \
NVAULT_VAULT_PATH=/path/to/dev/amt-console.vault \
NVAULT_MASTER_KEY_FILE=/path/to/dev/amt-console.key \
python3 server.py
```

Points that matter:

- **Bind to loopback.** The default `AMT_CONSOLE_BIND` is `0.0.0.0`.
- **A dev vault, not your main one.** Build it as in section 3 (any folder; both `NVAULT_*` variables
  set). Run a local amt-mcp (`python3 amt_server.py`, which listens on `127.0.0.1:8765`) with both
  `MCP_ADMIN_TOKEN_HASH` and `MCP_CONSOLE_TOKEN_HASH` set. Section 3's `MCP_CONSOLE_TOKEN_HASH=` line is
  exactly what to export.
- **WebAuthn needs the browser's address to match the configuration.** `AMT_CONSOLE_ORIGIN` must equal
  the origin in the address bar, `AMT_CONSOLE_RP_ID` its host name, and the console only answers a
  `Host` equal to the origin's host:port. Browsers generally treat `localhost` as a secure context,
  which is what makes plain-HTTP `http://localhost:8767` workable in Chrome and Firefox; that is browser
  behavior, not something this repository checks, and Safari does not accept the `Secure` session cookie
  over HTTP. If it does not work in your browser, put a local TLS proxy in front and use its https
  origin.
- **Enrollment** is the same file as section 8, written into `AMT_CONSOLE_DATA` (the hand-written form).
  `amt_admin.py` needs the Docker host and is not useful locally.
- **The embedded viewers** relay only a control url whose scheme and host:port equal
  `AMT_CONSOLE_VIEWER_ORIGIN`. A viewer started on `0.0.0.0` lists `http://127.0.0.1:8766/...` among its
  urls, which is why the example uses that origin. Without a viewer front, the KVM and SOL tabs report
  a session as not reachable from here.
- The test suite (`console/tests`) runs the server against fakes and needs no AMT host; see
  [console-guide.md](console-guide.md).

## 10. Verify the install

1. **Loopback** (section 6, step 6) answers 200 for `/signin`.
2. **Through the proxy, security headers.** Use a GET and dump the headers:

   ```bash
   curl -sS -D - -o /dev/null https://amt-console.example.com/signin
   ```

   The response carries these (header-name case may differ by proxy):

   ```
   content-security-policy: default-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'
   x-frame-options: DENY
   referrer-policy: no-referrer
   x-content-type-options: nosniff
   cross-origin-opener-policy: same-origin
   cache-control: no-store
   ```

   Do not use `curl -I`. The console has no HEAD handler, so a HEAD request returns 501
   `{"error": "not_implemented"}` (carrying the same headers).
3. **Signed-out behavior.** `curl -sS -D - -o /dev/null https://amt-console.example.com/` returns a 302
   with `Location: /signin`. `curl -sS https://amt-console.example.com/api/fleet` returns 401
   `{"error": "not_signed_in"}`.
4. **In the browser**, sign in (section 8). The Fleet page lists one card per server in amt-mcp's
   devices file. A card moves from `loading` to `live` once `amt_status` answers; `unreachable` and
   `paused` cards carry their reason (a `paused` card is a credential or pin problem on that server,
   not an install fault; see [operators-guide.md](operators-guide.md)). No red banner
   `amt-mcp could not list its servers: ...` appears.
5. **amt-mcp sees the console principal.** The console's reads show up in amt-mcp's stderr:

   ```bash
   docker logs --since 5m amt-mcp 2>&1 | grep 'principal=console'
   ```

   Expect lines of the form `<time> amt_mcp.calls tool=amt_devices principal=console`, followed by
   `tool=amt_status principal=console` and the three session reads (`amt_mirror_link`,
   `amt_serial_link`, `amt_ider`) for each server. The Fleet poller reads only while a page is open.
6. **Console log.** `docker logs amt-console` shows one `amt_console <METHOD> <path> <status>` line per
   request and `amt_console.auth signed in id=...` for each sign-in. No `call not made:` lines.

The KVM and SOL streams are first exercised when you start a mirror or terminal from the console, which
opens a real session on a host. Do that deliberately; see [operators-guide.md](operators-guide.md).

## 11. Troubleshooting

The strings below come from the source. The console shows many of them in a banner or in a sheet; the
rest are in `docker logs amt-console` or in the JSON body of a failing `/api/...` request.

| Symptom or text | Cause | Fix |
|-----------------|-------|-----|
| `vault_unconfigured:amt-console-token` (Fleet banner; log `call not made: ...`; `/api/call` answers 503 `console_bearer_unavailable`) | `AMT_CONSOLE_SECRETS_CLI` is unset. There is deliberately no default. | Set it (compose does), recreate the container. |
| `vault_miss:amt-console-token` | The vault CLI exited non-zero: wrong `NVAULT_*` paths, `console-vault/` empty or not readable by `DEPLOY_UID`, entry missing, `cryptography` missing, wrong key file. | Run the CLI as the container does and read its own error: `docker exec amt-console python /opt/node-vault-mcp/services/secrets.py get amt-console-token >/dev/null` (output discarded, error shown). Exit 1 means no such entry, 2 a vault I/O or decryption error. Rebuild the vault as in section 3. |
| `vault_empty:amt-console-token`, `vault_decode_error:...`, `vault_unavailable:amt-console-token:<ErrorName>` | Entry has an empty value; the output was not text; the CLI could not run or timed out (15 s). | Re-store the token (section 3); check the `node-vault-mcp` mount. |
| Banner text `this call requires the mcp-admin-token bearer header (Authorization: Bearer <token>); the call was refused and nothing ran` | amt-mcp does not accept the console's bearer: `MCP_CONSOLE_TOKEN_HASH` missing or malformed in the running container, hash not from this token, or the container was restarted but not recreated. | Compare the hash in `amt-mcp.env` with the re-derived one (section 3, step 2); recreate amt-mcp; restart `amt-console`. |
| `amt_mcp_http_403` | The proxy refused the console's call (its allow rule does not admit the console's source address; typical for a container on a compose-created network). | Keep `network_mode: bridge` and admit the default bridge subnet on the amt-mcp (and viewer) site. |
| `amt_mcp_http_421` | amt-mcp's host check: the `Host` is not in `AMT_ALLOWED_HOSTS`, or the proxy rewrote it. | Add the MCP origin's host to `AMT_ALLOWED_HOSTS`; forward `Host` unchanged. |
| `amt_mcp_http_<other>` | amt-mcp or the proxy answered with that status. | Check the amt-mcp site and `docker logs amt-mcp`. |
| `amt_mcp_unreachable:<ErrorName>` | Network or TLS failure toward amt-mcp: `gaierror` (name does not resolve in the container), `ConnectionRefusedError`, `TimeoutError`, `SSLCertVerificationError` (certificate not trusted by the image, see section 2). | Fix DNS, the proxy, or the certificate chain; test from the container with `docker exec amt-console python -c "import urllib.request as u; print(u.urlopen('https://amt.example.com/').status)"`: a printed status, or a traceback ending `HTTP Error 4xx`, proves the name resolves and the certificate is trusted; a `URLError` names the failure. |
| `amt_mcp_bad_response`, `amt_mcp_rpc_error:<code>` | The endpoint is not amt-mcp's `/mcp`, or the call failed in the MCP layer. | Check `AMT_CONSOLE_MCP_URL` ends in `/mcp` and points at amt-mcp. |
| 421 `host_not_allowed` from the console | The `Host` header is not the origin's host:port. | Proxy: pass `Host` unchanged. |
| 403 `cross_site_refused` (log `cross-site POST refused path=...`) | A POST whose `Origin` is not exactly `AMT_CONSOLE_ORIGIN`, or whose `Sec-Fetch-Site` is not `same-origin`: the page was opened at a different address (IP instead of name, other port, http instead of https), or a proxy dropped or changed `Origin`. | Always browse to the exact origin; check the proxy passes `Origin`. |
| 401 `not_signed_in`, 403 `csrf_token_invalid` | No or expired session (12 h idle), or a stale page. | Reload and sign in. |
| 415 `json_required`, 411 `length_required`, 413 `body_too_large` | A request the console would not parse (body over 64 KiB for JSON routes). | Usually a proxy altering the request. |
| Passkey step fails with `registration_refused:origin_mismatch` (enroll or add) or `assertion_refused:origin_mismatch` (sign-in) | The origin the browser reports is not `AMT_CONSOLE_ORIGIN`. | Make the setting equal the address bar (scheme, host, port). |
| `registration_refused:rp_id_mismatch`, `assertion_refused:rp_id_mismatch` | The passkey was made for another RP id than `AMT_CONSOLE_RP_ID`. A passkey enrolled under an old RP id cannot sign in after you change it. | Correct `AMT_CONSOLE_RP_ID`; if it changed after enrollment, mint a new code and enroll again. |
| `registration_refused:user_verification_required`, `...:unsupported_key`, `...:attestation_not_none` | The authenticator did not verify the user, or offered a key type other than ES256, or attestation. | Use an authenticator that does discoverable credentials with PIN or biometric. |
| `assertion_refused:counter_did_not_advance` (log `sign-in refused: counter_did_not_advance id=...`) | The authenticator's signature counter went backward or stood still: a cloned or restored authenticator. | Enroll a fresh passkey; do not keep the old one. |
| `challenge_unknown` | The sign-in or enrollment challenge expired (5 minutes) or the console restarted between the two steps. | Try again. |
| Sign-in page "Passkey not recognized" (`passkey_not_enrolled`, log `sign-in refused: passkey not enrolled`) | That passkey is not in `passkeys.json`. | Sign in with an enrolled one, or enroll with a new code. |
| `enroll_not_open` | No usable `enroll.json`: not minted, minted into another folder, wrong shape, or unreadable by the console's user (an ssh user other than `DEPLOY_UID` writes a 0600 file the console cannot read). | Mint again; `ls -l console-data/enroll.json` must show owner `DEPLOY_UID`. |
| `enroll_code_expired`, `enroll_code_wrong`, `enroll_locked` | Older than 10 minutes; mistyped; five wrong tries withdrew the file. | Mint a new code. |
| `too_many_pending` | 256 open challenges (the cap). | Wait five minutes. |
| Container restarts; `docker logs` shows `PermissionError: console data folder is not writable` | `console-data/` is missing its owner or mode: it was created by Docker as root, or is not writable by `DEPLOY_UID`. | `chown` it to `DEPLOY_UID:DEPLOY_GID`, `chmod 700`. |
| Container restarts; `ValueError: origin must be scheme://host[:port]` (or `viewer_origin must be ...`) | The origin has a path or trailing slash, or no scheme. | Fix the value in `site.vars`. |
| KVM or SOL tab: `Held by an agent · not reachable from here · bind 127.0.0.1` | An agent started the viewer with the tool's default bind, which the viewer front cannot reach; the console only frames a viewer it can reach. | Stop it and start it from the console (it binds `0.0.0.0`). |
| KVM or SOL frame stays blank or shows an error, no session shown as live | `session_not_live` (409), `viewer_not_reachable` (409: no control url on `AMT_CONSOLE_VIEWER_ORIGIN`; `AMT_VIEWER_PUBLIC_BASE_URL` on amt-mcp differs from the console's `AMT_CONSOLE_VIEWER_ORIGIN`), `viewer_unreachable` (502: the console cannot reach the viewer front: DNS, proxy allow list, TLS trust), `viewer_redirected` (502: the viewer front redirected the console). | Compare the two viewer origins character by character; admit the Docker bridge on the viewer site; check trust. Setting `AMT_CONSOLE_ORIGIN` on amt-mcp does not fix this, because the console does not rely on the viewer's framing headers. |
| KVM or SOL picture appears, then freezes or drops after a while | A proxy in the path buffers or times out the stream: the console's site, or the viewer front. | `proxy_buffering off` and long read timeouts on both (section 7). |
| Capture record shows `handoff_url_not_from_amt_mcp`; image upload says `upload_url_not_from_amt_mcp`; identity entry says `intake_url_not_from_amt_mcp` | The one-time url amt-mcp returned does not start with the origin of `AMT_CONSOLE_MCP_URL`: `AMT_PUBLIC_BASE_URL` on amt-mcp differs (an explicit `:443`, `http` against `https`, another name). Nothing is fetched or sent. | Make `AMT_PUBLIC_BASE_URL` and the origin of `AMT_CONSOLE_MCP_URL` identical; recreate amt-mcp. |
| Capture record `failed` with `sha256_mismatch`, `fetch_status_<n>`, or `expired` (not fetched within 15 minutes) | The file could not be fetched once from the handoff url, or the link had died. | Take the screenshot or recording again. |
| Large image upload: 413 from the proxy, or an upload that stops early (`browser_stream_ended_early`) | The proxy's body limit or timeout. | Raise `client_max_body_size` (and turn off request buffering) on the console's site and on the amt-mcp site. |
| `500 {"error": "internal"}` and `handler fault <Type> on <path>` in the log | An unforeseen fault in a handler. | The type is in the log, never a message; report it. |

## 12. Upgrading and backups

### What lives in `console-data/`

| File or folder | Contents | Back up? |
|----------------|----------|----------|
| `passkeys.json` | Enrolled passkeys: public keys, signature counters, names, times. | **Yes.** Without it you re-enroll with a new code (section 8). |
| `sessions.json` | Session records: the SHA-256 of each session id and its CSRF token, plus expired-session tombstones (kept a week). | No. Losing it signs everyone out. Treat any copy as sensitive. |
| `enroll.json` | A pending enrollment code's hash and expiry. Deleted on use or expiry. | No. |
| `captures/` | Fetched screenshots and recordings with their records, kept `AMT_CONSOLE_CAPTURE_HOURS` (24) and then deleted. | No. The one-time links cannot be fetched again. |
| `host-sessions.json` | Which KVM, SOL and IDE-R sessions this console started, so the holder shows as "you" after a restart. | No. |

All files are 0600 in a 0700 folder. The console's vault (`console-vault/`) holds only the bearer; back
it up only if you do not want to mint a new token (section 3 rotates it in minutes). Never put the key
file and the vault in a backup that more people can read than can read the vault.

### Upgrading

1. Update `src/` to the revision you want. Upgrade the console and amt-mcp from the same revision: the
   console's tool table is pinned to amt-mcp's tool schemas (`console/mcp_client.py`, `TOOLS`), and a
   console older or newer than its amt-mcp can miss or reject a tool.
2. Optionally keep the running image for a rollback: `docker tag amt-console:local amt-console:prev`.
3. Rebuild and recreate: `docker compose --env-file ./site.vars -f src/deploy/compose.yaml
   --project-directory . up -d --build amt-console` (add `amt-mcp` when it changed).
4. Expect: a few seconds of proxy 502 while the container restarts; signed-in sessions survive (they are
   in `sessions.json`); open KVM and SOL embeds remint their keys; the bearer is re-read from the vault.
   A KVM mirror or SOL terminal that is running lives in amt-mcp and is unaffected by a console restart.
5. Rollback: retag `amt-console:prev` as `amt-console:local` and run `up -d amt-console` without
   `--build`.

## 13. Keeping this guide current

Update this guide in the same change as any of these:

| If you change | Update |
|---------------|--------|
| `Config.from_env` or `App.__init__` in `console/server.py` (variables, defaults, origin checks, `_host_ok`, `_same_origin`, the response headers) | Sections 1, 5, 7, 10, 11 |
| `console/auth.py` (`ENROLL_ALPHABET`, `ENROLL_LENGTH`, `enroll_attempts`, `CHALLENGE_TTL`, the `enroll.json` shape, the error codes) or `console/webauthn_min.py` (authenticator requirements) | Sections 2, 8, 11 |
| `deploy/amt_admin.py` (`console enroll-code`, `ENROLL_*`, the environment it needs) | Section 8 |
| `deploy/compose.yaml` or `deploy/site.vars.example` (mounts, variables, `network_mode`, ports) | Sections 1, 5, 6 |
| `console/Dockerfile`, `console/requirements.txt` (Python and `cryptography` pins) | Sections 2, 9 |
| `console/mcp_client.py` (`TOKEN_ENTRY`, error strings, TLS handling) | Sections 3, 11 |
| `amt_gate.py` (`MCP_CONSOLE_TOKEN_HASH`, the call-log line) | Sections 3, 10 |
| `amt_server.py` (`AMT_ALLOWED_HOSTS`), `amt_handoff.py` (`AMT_PUBLIC_BASE_URL`), `amt_mirror.py` (`AMT_CONSOLE_ORIGIN`, `AMT_VIEWER_PUBLIC_BASE_URL`), `amt_upload.py` (CORS) | Sections 1, 4 |
| `console/embed.py`, `console/captures.py`, `console/images.py`, `console/intake.py` (where a url may point, what is relayed, stream headers) | Sections 1, 7, 11 |

Verification status: the vault procedure in section 3 and the enrollment file in section 8 were run
against scratch files with the real CLI and the console's own `auth` module. The nginx site, the Docker
commands and the browser steps follow from the source and standard behavior of those tools, and were not
run against a live proxy, a Docker host or an AMT host.
