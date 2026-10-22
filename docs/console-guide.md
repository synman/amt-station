# amt-console guide

This is the reference for the management console: a web UI in `console/` that drives amt-mcp.
It is written for someone who wants to understand, operate or change the console. Everything
here was checked against the source; where a rule is pinned by a test, the test file is named.

Related reading:

- [Install amt-console](install-console.md): deploying it, its bearer and the first passkey.
- [Operator's guide](operators-guide.md): day-to-day work in the UI.
- [MCP deep dive](mcp-guide.md): the tools the console calls, the gate and the viewers.
- [UX design note](ux-design-2026-10-20.md): the design spec and its numbered "immutables".
- [Repository README](../README.md).

Tab names: the server page labels its tabs **KVM** and **SOL**, but their URL slugs and much of
the code and test vocabulary still say `console` and `serial`. This guide uses the labels and
gives the slug where it matters. The authoritative list is `SERVER_TABS` in `console/server.py`.

## 1. What the console is

amt-console is a Python standard-library HTTP backend plus a static client (HTML pages and
plain JavaScript, no build step, no framework, no external requests). It holds no AMT state of
its own. It reaches amt-mcp only through MCP `tools/call` requests to amt-mcp's `/mcp` endpoint,
authenticated with the console's own bearer. It mounts none of amt-mcp's vault, devices file
or image root.

### Trust model

```
 browser                      amt-console (:8767)                       amt-mcp
 -------                      -------------------                       -------
 passkey (WebAuthn) ───────►  cookie session  ──┐
 cookie: HttpOnly, Strict     CSRF token         │  tools/call over HTTPS
 X-CSRF-Token on POSTs        exact Origin       ├──────────────────►  /mcp
                              Host check         │  Authorization: Bearer <console bearer>
                              CSP, no framing    │  (gate logs principal "console")
                                                 │
 sandboxed iframe (opaque) ─► /embed/... relay ──┘  GET/POST to the viewer front
 embed key in the path        (key, no cookie)      (control url kept in memory)
```

What the boundaries mean:

- The browser talks only to the console. It never calls `/mcp`, and no response, header, log
  line or page ever carries the console bearer, a one-time url or a viewer token. The scans in
  `console/tests/test_console_secrets.py` enforce this against every response body, header,
  log record and url amt-mcp saw, with a planted leak as the positive control for each scan.
- The bearer lives in the console's own vault (entry `amt-console-token`), is read in-process
  through the vault CLI that `AMT_CONSOLE_SECRETS_CLI` names, and is held in memory only. There
  is no default path for that variable on purpose: an unconfigured console fails closed instead
  of reaching for another vault.
- amt-mcp sees the console as principal `console` (its second bearer, `MCP_CONSOLE_TOKEN_HASH`).
  The console never relies on a principal check inside a tool.
- Sign-in is by passkey only. There is no password anywhere in the console.

## 2. Backend architecture

### 2.1 Module map

All console modules are top-level (`import auth`, not `import console.auth`). The Dockerfile's
`COPY` list must name each one; `console/tests/test_console_deploy.py` checks that the list
equals the set of `console/*.py` files, except `make_theme.py`, which is a developer tool.

| Module | Role |
|--------|------|
| `server.py` | `Config`, `App`, the request handler, routing, headers, `/api/call`, `/api/sequence`, page assembly. Entry point (`python3 server.py`). |
| `auth.py` | `Store`: passkey enrollment, sign-in, sessions, CSRF comparison. State in `passkeys.json`, `sessions.json`, `enroll.json`. |
| `webauthn_min.py` | A minimal WebAuthn relying party: strict CBOR reader, ES256 signature check with `cryptography`. |
| `mcp_client.py` | `Client` (one `tools/call` per request), `Vault` (bearer read), the `TOOLS` allowlist and `validate_call`, and the plain HTTP helpers shared by the relay and the stores. |
| `fleet.py` | `Fleet`: per-server status cache, staggered poller, pause/resume, session holder attribution, `past_captures`. |
| `power.py` | The offered-power-states read (`read_offered`), the action-to-code table, and the boot-then-power sequence (`check_sequence`, `run_sequence`). |
| `embed.py` | `Keys` (embed keys), `Embed` (session lookup and relay), `Upstream` (one relayed response, stream copy). |
| `captures.py` | `CaptureStore`: one-time handoff fetch, sha256 check, retention; `mask_one_time_urls`. |
| `images.py` | `Uploads`: keeps an upload url in memory, streams the browser's file to it. |
| `intake.py` | `Intakes`: keeps an identity-intake url in memory, relays one value to it. |
| `make_theme.py` | Generates `static/theme.css` from `design/tokens.json`; `--check` verifies it. |

Third-party dependency: `cryptography` only (pinned in `console/requirements.txt`). A test
(`test_the_console_runs_on_the_standard_library_and_the_pinned_requirement`) fails if any other
non-standard-library import appears.

### 2.2 Pages and static client

The backend assembles pages from templates; there is no client-side routing.

- `pages/shell.html` is the frame for every signed-in page: navigation rail (width 600 and
  up), bottom bar (under 600), app bar, content area, and the shared scripts.
- `pages/signin.html` is standalone (no shell).
- For a section, the shell is filled with `content-<name>.html` and `appbar-<name>.html`:
  `fleet`, `manage`, `manage-identities`, `settings`, `server` (the Status tab), and
  `server-<tab>` for each other tab. A page that does not exist falls back to
  `content-unbuilt.html`. `@@KEY@@`, `@@LABEL@@`, `@@TITLE@@` and similar markers are
  replaced by the backend (server keys and labels are HTML-escaped or match a strict regex).
- Navigation sections (`NAV`): Fleet `/`, Manage `/manage`, Images `/images`, Settings
  `/settings`. A server page is a Fleet page (the Fleet item stays highlighted).
- The Images section is the Media tab's content with a server picker (`@@PICK@@` is empty),
  while a server's Media tab hides the picker.

Scripts loaded by every signed-in page: `components.js` (sheets, force control, predicate),
`webauthn.js`, `app.js` (theme, session, sign-out), `shortcuts.js`, `passkeys.js`. Then the
page scripts, chosen by the backend:

| Page | Page scripts |
|------|--------------|
| Fleet `/` | `status.js`, `fleet.js` |
| Manage `/manage` | `status.js`, `servers.js` |
| Identities `/manage/identities` | `status.js`, `identities.js` |
| Images `/images` | `status.js`, `media.js` |
| Settings `/settings` | none beyond the shared ones |
| Any server tab | `status.js`, `server.js`, plus `embed.js` for KVM and SOL, plus the tab's own script (`power`, `console`, `serial`, `media`, `logs`, `inventory`, `settings`, `wsman`; the Status tab has none) |

`status.js` holds the shared pieces (power pill, session and pin chips, fingerprints, times,
result rows, capture rows). `base.css` is the component layer and `theme.css` is generated.

### 2.3 Request handling rules

These apply to every request unless a route says otherwise.

- **Host check.** The `Host` header must equal the host (and port, if the origin names one) of `AMT_CONSOLE_ORIGIN`
  (`421 host_not_allowed` otherwise). A reverse proxy must pass the original `Host`.
- **JSON POST bodies.** `Content-Type: application/json`, a `Content-Length`, at most 64 KiB,
  and a JSON object (`415 json_required`, `411 length_required`, `413 body_too_large`,
  `400 bad_json`). The upload, intake and `/embed/` routes have their own body rules.
- **Errors.** Every error body is `{"error": "<fixed code>"}`. A handler fault is
  `500 internal` with no detail; only the exception type is logged. Methods with no handler
  (PUT, DELETE, PATCH, HEAD, and OPTIONS outside `/embed/`) are `501 not_implemented`, sent
  through the same header path as every other response (HEAD gets the status and headers, no
  body). A request line that cannot be parsed is answered `400 bad_request` the same way.
- **Logging.** Request lines are logged with `loggable()`, which replaces an upload id, an
  intake id and an embed key in the path with `<id>` or `<key>`.
- **Server keys** in paths match `[a-z0-9][a-z0-9-]{0,62}`.

### 2.4 Response headers

Every response, including http.server's own error pages, carries:

| Header | Value |
|--------|-------|
| `Content-Security-Policy` | `default-src 'self'; frame-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'` |
| `X-Frame-Options` | `DENY` |
| `Referrer-Policy` | `no-referrer` |
| `X-Content-Type-Options` | `nosniff` |
| `Cross-Origin-Opener-Policy` | `same-origin` |
| `Cache-Control` | `no-store` (static files: `no-cache`) |

Exception: a request so malformed that it names no HTTP version gets a bare error body,
because HTTP/0.9 has no header block. Responses under `/embed/` replace the CSP and
`X-Frame-Options` with the relay's own pair (section 8.3) and add CORS.

### 2.5 Route table

Auth column: **none** = no session needed; **cookie** = a live session cookie;
**+CSRF** = also a matching `X-CSRF-Token`; **origin** = the exact `Origin` check (below);
**embed key** = the key in the path. Every POST outside `/embed/` passes the origin check first.

The origin check: the `Origin` header must equal `AMT_CONSOLE_ORIGIN` exactly, and
`Sec-Fetch-Site`, when the browser sends it, must be `same-origin`. A failure is
`403 cross_site_refused` and nothing is sent anywhere.

**GET**

| Path | Auth | Purpose |
|------|------|---------|
| `/signin` | none | Sign-in page; the idle hours and origin are filled in. |
| `/static/<name>` | none | Static file. The name must match `[a-z0-9][a-z0-9._-]*` and end in `.css`, `.js` or `.svg`; anything else is 404. |
| `/`, `/manage`, `/images`, `/settings` | cookie, else 302 | Section pages. |
| `/manage/identities` | cookie, else 302 | Identities page. |
| `/server/<key>` and `/server/<key>/<tab>` | cookie, else 302 | Server pages. `<tab>` is one of `power console serial media logs inventory settings wsman`. Any other tab name falls through (401 signed out, 404 signed in). |
| `/api/session` | cookie | `{csrf, idle_seconds}`. Every page calls this first. |
| `/api/passkeys` | cookie | Enrolled passkeys: id, name, created, last used. No key material. |
| `/api/captures` | cookie | Every capture record in the store. No page script calls it; pages use the per-server list below. |
| `/api/fleet` | cookie | Snapshot of all servers (section 6). Counts as "a page is looking". |
| `/api/server/<key>` | cookie | `{now, interval, server}` for one server. 404 `unknown_server`. |
| `/api/server/<key>/power` | cookie | One read of what AMT offers (section 7.4). |
| `/api/server/<key>/captures` | cookie | amt-mcp's captures for this server, joined to the store. 502 for `amt_mcp_*` faults, 503 for other call faults. |
| `/api/embed/<kind>/<key>` | cookie | Whitelisted live view of a mirror or terminal, plus `key_live`. `<kind>` is `mirror` or `serial`, `<key>` the server key. |
| `/captures/<id>` | cookie | Download of a kept capture, as an attachment. |
| `/embed/<kind>/<key>/<embed key>/<route>` | embed key | The relayed viewer page and its sub-routes (section 8). |

A signed-out request for a page is `302` to `/signin` (or `/signin?expired=1` when the
session idled out) and clears the cookie; a signed-out request for any `/api/` or
`/captures/` path is `401 not_signed_in`.

**POST**

| Path | Auth | Purpose |
|------|------|---------|
| `/auth/enroll/options` | none, origin | `{code, name}` to WebAuthn creation options. |
| `/auth/enroll/verify` | none, origin | Finish enrollment; starts a session. |
| `/auth/signin/options` | none, origin | Sign-in challenge. |
| `/auth/signin/verify` | none, origin | Verify the assertion; sets the session cookie. |
| `/auth/signout` | cookie, +CSRF | Ends the session and revokes its embed keys. |
| `/api/passkeys/options`, `/api/passkeys/verify` | cookie, +CSRF | Add a passkey while signed in. |
| `/api/call` | cookie, +CSRF | One `tools/call` (section 4). |
| `/api/sequence` | cookie, +CSRF | Boot step then power step (section 4.5). |
| `/api/fleet/refresh` | cookie, +CSRF | `{device}`: one read now, even of a paused server. No `device`: every unpaused server becomes due. |
| `/api/embed/key` | cookie, +CSRF | `{kind, device}`: mint an embed key (section 8.2). |
| `/api/images/upload/<upload_id>` | cookie, +CSRF | The file, `application/octet-stream` (section 9.1). |
| `/api/identities/intake/<intake_id>` | cookie, +CSRF | The value, `text/plain` (section 9.2). |
| `/embed/<kind>/<key>/<embed key>/input` | embed key, Origin `null` or the console's | The viewer's live keyboard and mouse. The one POST that is not a tool call. |

`OPTIONS` is answered only under `/embed/` and only for a valid key (a CORS preflight).

Auth refusals use these codes: `401 not_signed_in`, `403 csrf_token_invalid`,
`403 passkey_not_enrolled`, `429 enroll_locked`, `429 too_many_pending`; any other
`AuthError` is `400` with its fixed code.

## 3. Authentication and sessions

### 3.1 Passkeys

The console accepts exactly the WebAuthn profile in `webauthn_min.py` and refuses everything
else, naming the failed check:

| Rule | Detail |
|------|--------|
| Algorithm | ES256 only (COSE alg -7, P-256). The public point must be on the curve. |
| Attestation | `none` only; `attStmt` must be empty. |
| User verification | Required, in both the options (`userVerification: required`, `residentKey: required`) and the authenticator flags (user presence and user verification bits). |
| Origin and RP ID | `clientDataJSON.origin` must equal `AMT_CONSOLE_ORIGIN`; the RP ID hash must match `AMT_CONSOLE_RP_ID`; a `crossOrigin: true` assertion is refused. |
| Challenge | 32 random bytes, valid 300 s, consumed on first use whether or not verification succeeds. At most 256 pending; a full table refuses new ones (`too_many_pending`). |
| Signature counter | If either the stored or presented counter is non-zero, the presented one must be higher. A counter that does not advance is treated as a cloned authenticator. Authenticators that never count (both zero) pass. |
| Credential id | At most 1023 bytes. A passkey cannot be enrolled twice (`passkey_already_enrolled`); creation options list existing ids in `excludeCredentials`. |
| Sign-in | Discoverable: `allowCredentials` is empty. An unknown credential id is `403 passkey_not_enrolled`; the log line carries the id only. |
| Names | 1 to 64 printable characters. |

State files live in `AMT_CONSOLE_DATA` (0600 files in a 0700 folder): `passkeys.json` (public
keys, counters, timestamps), `sessions.json` (SHA-256 of each session id, never the id) and
`enroll.json`.

### 3.2 Enrollment code flow

The first passkey is enrolled with a one-time code, minted outside the console:

1. An operator runs `deploy/amt_admin.py console enroll-code`. It generates 12 characters from
   an alphabet without look-alikes (`ABCDEFGHJKMNPQRSTUVWXYZ23456789`), valid 10 minutes, one
   use, prints it once as `XXXX-XXXX-XXXX`, and delivers only the SHA-256 of the 12 characters
   (upper case, no dashes) and an expiry to `enroll.json` in the console's data folder.
2. On the sign-in page the operator chooses "First time here? Enroll a passkey", types the code
   (case and dashes are ignored) and a passkey name, and the browser creates the passkey.
3. The console checks the code with a constant-time compare. After **five** wrong codes the
   console deletes `enroll.json` (`429 enroll_locked`); a new code must be minted. A correct
   code resets the counter.
4. On a successful enrollment the console deletes `enroll.json` (one passkey per code) and
   starts a session.

An absent or malformed `enroll.json` is `enroll_not_open`; an expired one is deleted and
reported as `enroll_code_expired`. Enrollment refuses to finish if the file vanished or was
replaced by a newer code between the options call and the verify call.

The console logs a warning at startup when no passkey is enrolled.

### 3.3 Adding passkeys

Settings has an "Add a passkey" sheet. While signed in, no code is needed:
`POST /api/passkeys/options` (name) then `POST /api/passkeys/verify` (needs the cookie and the
CSRF token). Removing a passkey is not offered in the UI.

### 3.4 Sessions

- The session id is `secrets.token_urlsafe(32)`, set as cookie `amt_console_session` with
  `Path=/; Secure; HttpOnly; SameSite=Strict`. Because the cookie is `Secure`, the console must
  be reached over HTTPS (a reverse proxy in front of the container does this).
- **Idle timeout:** `AMT_CONSOLE_IDLE_HOURS` (default 12). `last_seen` is refreshed on each
  cookie-carrying request and persisted at most once a minute. A session past its limit becomes
  a tombstone kept for seven days, so the sign-in page can say "signed out after N hours idle"
  (`/signin?expired=1`) instead of showing a fresh sign-in. Requests authenticated by an embed
  key do not touch the session; the page's own polls (which carry the cookie) do.
- **Sign-out:** the Sign out control posts `/auth/signout`, which revokes the session's embed
  keys at once, deletes the session and clears the cookie. A KVM mirror or serial terminal the
  console started keeps running on amt-mcp; the console shows it again after the next sign-in.
- **CSRF:** each session has a token (`token_urlsafe(24)`) returned by `/api/session` and
  stored in `amtc.csrf` by `app.js`. The client sends it as `X-CSRF-Token` on every POST;
  the backend compares it in constant time.
- On a 401 from `/api/session` or from `S.get` (the shared GET helper), the client redirects to
  `/signin?expired=1`.

### 3.5 Framing

No normal console response can be framed (`frame-ancestors 'none'`, `X-Frame-Options: DENY`).
The only exception is the relayed viewer page under `/embed/`, which allows `'self'` and is
framed by a console page. The shell's `frame-src` is `'self'`. Tests:
`test_every_response_refuses_to_be_framed_and_carries_the_policy` and the embed tests in
`test_console_embed.py`.

## 4. The /api/call contract

### 4.1 Request

```json
{"tool": "amt_power", "arguments": {"device": "my-server-1", "action": "restart", "confirmed": true}}
```

`mcp_client.validate_call` runs before anything is sent to amt-mcp. The browser cannot reach a
tool outside the table below, and cannot skip `device` or `confirmed`.

| Check | Failure code (HTTP 400) |
|-------|-------------------------|
| `tool` is a string in `TOOLS` | `unknown_tool` |
| `arguments` is an object | `arguments_not_an_object` |
| A tool that takes a device has a non-empty string `device` (the server's default device is never relied on) | `device_not_named` |
| A write tool carries the JSON boolean `confirmed: true` (the string `"true"` and `1` fail) | `confirmed_not_true` |

Reply codes from the backend: `503 console_bearer_unavailable` (the bearer could not be read,
shown as a fixed code, never the cause), `502 amt_mcp_*` (amt-mcp could not be reached or gave
an unusable answer, such as `amt_mcp_unreachable:<ErrorType>`, `amt_mcp_http_<status>`,
`amt_mcp_rpc_error:<code>`, `amt_mcp_bad_response`), and `400` for the validation codes above
and `bad_url`.

### 4.2 The tool table

`mcp_client.TOOLS` has 23 entries, mapping name to (needs an explicit `device`, read-only).
`console/tests/test_console_mcp_client.py::test_the_tool_table_matches_the_live_amt_mcp_schemas`
checks the table against the live amt-mcp schemas: the same tool names, `read_only` equals
`readOnlyHint`, `device` required exactly where the schema has it (except the optional-device
tools), and `confirmed` present exactly on write tools.

| Group | Tools | Device required | Read-only |
|-------|-------|-----------------|-----------|
| Reads | `amt_status`, `amt_screenshot`, `amt_inventory`, `amt_logs`, `amt_settings`, `amt_wsman_get` | yes | yes |
| Lists | `amt_devices`, `amt_identities`, `amt_captures` | no | yes |
| Power and boot | `amt_power`, `amt_set_next_boot` | yes | no |
| Screen, keyboard, serial | `amt_console_input`, `amt_sol`, `amt_mirror_link`, `amt_serial_link`, `amt_remote_logon`, `amt_remote_logoff` | yes | no |
| Media | `amt_ider` (device), `amt_images` (no device) | `amt_ider` yes | no |
| Settings | `amt_configure`, `amt_wsman_invoke` | yes | no |
| Fleet writes | `amt_device_manage` (device), `amt_identity_manage` (no device) | `amt_device_manage` yes | no |

`amt_screenshot` is read-only per its annotation: the console confirms it with a sheet but
sends it without `confirmed`.

### 4.3 Writes that need no `confirmed`

A write tool is exempt only for the listed actions, which read or release and write nothing:

| Tool | Actions without `confirmed` |
|------|------------------------------|
| `amt_mirror_link` | `stop`, `status`, `record_stop` |
| `amt_serial_link` | `stop`, `status`, `record_stop` |
| `amt_ider` | `status` |
| `amt_images` | `list`, `verify` |

A non-string `action` is treated as unconfirmed, so it needs `confirmed: true`.

### 4.4 The reply, and what is withheld

A forwarded call returns HTTP 200 with:

```json
{"isError": false, "text": "<tool text, one-time urls masked>", "structured": { ... }}
```

`isError` is the tool's own flag: a tool refusal is a 200 with `isError: true` and the tool's
words in `text`. The client treats `status !== 200` as "the console could not make the call"
and `isError` as "the tool refused", and words the two differently.

`structured` is the tool's JSON result (amt-mcp sends its dict as JSON text; the client parses
it). Before it leaves the console:

- **Download handoffs.** A result with a `url` on `/handoffs/<43 chars>` and a `sha256` is
  fetched once by the backend (section 10). The `url` and `url_note` keys are removed and a
  `capture` record is added in their place.
- **Every other one-time url** is replaced by `[one-time url withheld]`, in `text` and in every
  string of `structured`, wherever it sits. The pattern is an optional scheme and host, then
  `/handoffs/`, `/uploads/`, `/intake/`, `/m/` or `/s/`, then 32 or more url-safe characters.
  This covers mirror and serial viewer urls (`/m/`, `/s/`), upload and intake urls.
- **Upload and intake mints.** A successful `amt_images upload` or `amt_identity_manage intake`
  result gets an `upload_id` or `intake_id` merged into `structured`; the url stays in the
  console's memory (section 9).

The mask is shape-based: it removes urls of the listed shapes. Tool results that could carry a
bare token with no url around it would not be recognized, which is why the console never
requests such fields into the browser (the fleet reader keeps a whitelist, section 6.4).

### 4.5 Side effects of a call

After a call returns, the backend updates its own state:

- `Fleet.observe` records a mirror or terminal start or stop (for "held by you"), a refused KVM
  open (for "another client"), an `amt_ider` mount, and any `wsman_auth_failed_401` (which
  pauses that server).
- A mirror or serial `start` or `stop` forgets the cached viewer target and, on success,
  re-reads that server's session views at once.
- An `amt_ider` `mount`, `unmount` or `status` re-reads the session views.
- A successful `amt_device_manage` re-reads the device list.

### 4.6 /api/sequence

The combined boot entries ("Power on to target", "Reset to target") are two tool calls the
backend sequences:

```json
{"steps": [
  {"tool": "amt_set_next_boot", "arguments": {"device": "my-server-1", "target": "pxe", "confirmed": true}},
  {"tool": "amt_power",         "arguments": {"device": "my-server-1", "action": "power_on", "confirmed": true}}]}
```

`power.check_sequence` accepts exactly two steps, in that tool order, for one device, with the
power action `power_on` or `hard_reset` (codes `sequence_needs_two_steps`,
`sequence_order_not_allowed`, `arguments_not_an_object`, `sequence_devices_differ`,
`sequence_power_action_not_allowed`, each a `400`). Both steps go through the same validation as
`/api/call`. The power step is sent only if the boot step came back accepted. The reply is
`{"steps": [...]}` with one entry per step: `{tool, sent: true, reply}`,
`{tool, sent: false, skipped: "boot_step_not_accepted"}`, or a step that could not be made,
`{tool, sent: false | "unknown", error}` (`"unknown"` for an `amt_mcp_*` transport fault: the
request may or may not have arrived). HTTP status is 200 whatever the steps did.

## 5. Confirmation UX

Every write goes through a sheet built by `components.js` (`amtc.openWrite`, `amtc.bindWrite`).
The text a sheet shows as the call (`tools/call amt_power {device: "my-server-1", action:
"restart", confirmed: true}`) is the call that is sent. `confirmed: true` is added by the sheet
code, not by the page.

### 5.1 The one predicate

`amtc.destructiveCall(call, ctx)` (also exposed as `window.__destructiveCall` for the
verifier) decides whether a call gets the plain sheet or the force sheet. It reads the call's
**arguments**, never which button opened the sheet. A call with a `then` step is as destructive
as its worst step.

| Tool | Destructive when |
|------|------------------|
| `amt_power` | `action` is `hard_reset`, `hard_power_off`, `hard_power_cycle`, `immediate_shutdown`, `immediate_power_cycle` or `nmi` |
| `amt_set_next_boot` | `options.secure_erase`, `options.reflash_bios` or `options.configuration_data_reset` is `true` |
| `amt_ider` | `start` is `"now"` (a hard reset) |
| `amt_images` | `action` is `delete` |
| `amt_device_manage` | `action` is `remove`, or `repin` is `true` |
| `amt_identity_manage` | `action` is `remove` |
| `amt_wsman_invoke` | `method` is `Unprovision` |
| `amt_mirror_link`, `amt_serial_link` | `action` is `stop` **and** `ctx.startedByAgent` or `ctx.callInFlight` is true |

`ctx` carries what a call cannot say: for a stop, whether an agent started the session or a
call is using it now. No other tool is ever destructive; in particular no `amt_configure`
call is. `console/tests/test_console_components.py` checks the predicate against a table of
cases in a real browser, checks that every call that was sent and is destructive was preceded
by a force fire (a "call spy"), and checks that the spy itself would catch a mis-routed send.

### 5.2 The plain sheet

A `role="dialog"` `aria-modal` bottom sheet: title, a consequence line, the call, **Cancel**
and the confirm button.

- Focus goes to Cancel on open, never to a confirm button.
- Tab is trapped inside the sheet; Escape and a click on the scrim close it; focus returns to
  the control that opened it.
- A held key opens a sheet once (`event.repeat` is ignored) and a held key never re-fires
  Confirm.
- A click on any `aria-disabled="true"` element is swallowed before it reaches a handler.
- A plain sheet may carry **input fields** (rename an image, fetch a URL, edit a server). The
  call is rebuilt from the values on every input, and Confirm is `aria-disabled` with the
  reason visible next to it until the values make a call the tool would accept. A sheet with
  fields can never be the destructive one: if the rebuilt call is destructive, Confirm is
  disabled with "this call needs the hold, which a form cannot offer", and `openWrite` throws
  if a spec with fields is destructive at the outset.

### 5.3 The force sheet and the hold

For a destructive call the consequence line is styled as an error, and in place of Confirm the
sheet carries the **force control**, labelled "Hold to <verb>".

| Input | Behaviour |
|-------|-----------|
| Pointer hold | Press and hold 1200 ms. The control fills (a bar under the label) and counts 3, 2, 1 at 400 ms steps, then shows "release". Releasing after it armed fires the call (completion on the up event). Releasing early, leaving the control, moving outside its box or a pointer cancel resets it. The click that follows a fired hold is swallowed. |
| Click, tap, Enter or Space | Opens a **second sheet** with the same text and a "<verb> now" button. |
| Second sheet | The confirm is `aria-disabled` until 400 ms after a *release* (keyup of Enter or Space, or pointerup) that happened after the sheet opened. It never arms on a timer from the opening activation. A pointer click fires only if its own pointerdown landed while the button was armed. Focus starts on Cancel, and the action row sits above the consequence so the confirm is not under the point where the opener was. |
| Reduced motion | `[data-motion]` animations resolve to none and the fill is replaced by the countdown on the same fill colour. The 1200 ms delay is kept: it is a safety delay, not decoration. |

A combined entry is as destructive as its worst step, so one whose power step is `hard_reset`
("Reset to target") is a hold as a whole.

### 5.4 Disabled controls say why

A control that cannot act now is `aria-disabled="true"`, stays focusable, ignores activation,
and shows its reason as text beside it ("not offered by AMT right now", "host is already on",
"identity ... is missing", "the last server", "mounted", "paused: credential refused", "no tool
yet"). It is never a `disabled` attribute and never only a tooltip. A control also goes
`aria-disabled` with a reason while its own call is out (`S.busy`), so one activation is one
attempt. The verifier asserts this for every `aria-disabled` control on every page.

### 5.5 Results

A result row appears in the card of the action, newest first (five kept), with a timestamp in
US Eastern time and the tool's own words verbatim. The wording separates three outcomes:

- **Refused by the tool** (200 with `isError`): shown with the tool's text, plus only what that
  text proves about the host ("nothing sent" for a validation code, "the request was sent" for
  a ReturnValue failure, otherwise "the text does not say whether the host changed").
- **The console could not make the call** (4xx): "refused: <code> · nothing sent".
- **amt-mcp did not answer** (502): "it is not known whether the request was sent".

Text from a host or a tool is always inserted as a text node. No static script uses
`innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` or `new Function`.

## 6. Fleet and status polling

### 6.1 What the backend reads

For each server, `Fleet` makes four read-only calls: `amt_status`, then `amt_mirror_link`,
`amt_serial_link` and `amt_ider`, each with `action: "status"`, always naming the device.
The browser never triggers these; it only asks the console for the cache (`/api/fleet`,
`/api/server/<key>`).

- **Stagger.** For n servers, each new server's first read is due at `i * interval / n`
  after the list loads, so reads are spread across `AMT_CONSOLE_FLEET_SECONDS` (default 30)
  and never come as a burst. The poller takes the most overdue unpaused server one step at a
  time and sleeps `min(1 s, interval/4)` between steps. The device list itself is re-read at
  most once per interval.
- **Only while a page asks.** `fleet.touch()` is called by `GET /api/fleet`,
  `GET /api/server/<key>[/power|/captures]` and `POST /api/fleet/refresh`. The poller thread
  stops when nothing has asked for two intervals and restarts on the next request, so a closed
  browser costs the hosts nothing. `/api/call` does not keep it alive.
- **Pages poll the cache.** The Fleet page and the Status tab poll every 5 s; the cache itself
  refreshes on the schedule above.
- **Whitelist.** Only fields the status page shows are copied out of a tool result (sections
  `power`, `amt`, `provisioning`, `redirection`, `kvm`, `user_consent`, scalars of `next_boot`,
  and the `unavailable` / `truncated` coverage lists with reasons). Strings are masked and cut,
  so a one-time url in a session view's `error` or a `next_boot` field never reaches the
  browser. A viewer url or token in a session view is dropped.

### 6.2 Server states

| State | Meaning | Reads |
|-------|---------|-------|
| `loading` | In the list, not read yet | scheduled |
| `live` | Last `amt_status` succeeded | scheduled |
| `unreachable` | The read failed (transport error, a tool refusal that is not a pause, unreadable status, or `tls_leaf_unpinned_refused`) | still scheduled |
| `paused` | A refused credential or a changed TLS leaf | **none** until resumed |

An unreachable server shows the error text verbatim, the time of the next automatic read, and
a **Retry now** control; Power stays available because AMT can answer when the OS does not.
After a failed read a previously "matches" pin chip falls back to "pin not checked"; an
unpinned server shows "unpinned · every call refused". If the transport itself failed, the
session views are not read (they would fail the same way).

### 6.3 Pausing and resuming

A `wsman_auth_failed_401` is one failed Digest attempt; a second would count toward an AMT
account lockout. So:

- A `wsman_auth_failed_401` in the status read, **or in any call made through the console**
  (`Fleet.observe`), pauses the server with reason "credential refused".
- A `tls_leaf_pin_mismatch` in a status read pauses it with reason "pin differs".
- A paused server is never read automatically again: not by the schedule, not by "Refresh
  all", and not by the Power, Logs, Inventory, AMT settings or Advanced pages, which grey
  their read controls with "paused: <reason>".

Three ways to resume:

1. **The pin is replaced** (`amt_devices` shows a different `tls_leaf_sha256` than the one
   recorded when it paused).
2. **The identity is replaced**: the `updated_at` of the server's AMT identity changed from the
   value read at the pause. If no value could be read at pause time, there is nothing to
   compare and this path never resumes it.
3. **The operator presses Retry once** and that single read succeeds. If it is refused again,
   the server stays paused.

Paths 1 and 2 are checked every time the device list is re-read (each interval, after any
accepted `amt_device_manage`, and after an accepted identity value arrives).

### 6.4 Who holds a session

Each of KVM (mirror), SOL (terminal) and IDE-R has a holder:

| Holder | UI text | Rule |
|--------|---------|------|
| `console` | "KVM · you · 03:12" | The session is live and this console started it through `start` (a start that returned "already live; returning the existing link" does not count). |
| `agent` | "agent via mirror" or "agent via terminal" | Live, and not started by this console. |
| `other` | "another client · opens refused" | KVM only: a KVM-opening call (`amt_screenshot`, or a mirror `start`) was refused with "another session is open" or a non-zero `redir_start_status_N`, within the last 300 s. A later successful open clears it. |
| `free` | "KVM free" | Not live, no recent refusal. |
| `unknown` | "KVM unknown" | The session read failed; never shown as free. |

`AMT_CONSOLE_DATA/host-sessions.json` (0600) remembers which mirrors and terminals this console
started (`mirror:<device>`, `terminal:<device>`, `ider:<device>` to a start time), so "you"
survives a console restart. An entry is dropped when a successful read shows that session is
no longer live. The start mode of an IDE-R mount is kept in memory only, so after a restart a
mount shows "not recorded here". Which `N` a busy host really answers has not been read live;
any non-zero start status counts.

## 7. Page-by-page reference

Common behaviour: all times are shown in US Eastern with an `EST` / `EDT` label (the logs also
show the record's UTC time). Pages never poll AMT directly; they poll the console's cache or
read when asked. A page that needs a server that is not in the list shows "No server named
<key>".

### 7.1 Fleet (`/`)

| | |
|---|---|
| Reads | `GET /api/fleet` every 5 s. |
| Writes | **Shot** on a live card: `amt_screenshot`, plain sheet, sent without `confirmed`; the result is fetched once into the capture store and shown with its sha256 and a Save link. No other tool call. |
| Other posts | Refresh all (`POST /api/fleet/refresh` with no device); per-card **Retry now** (unreachable) or **Retry once** (paused). |

One card per server: power pill, address and AMT version, KVM / SOL / IDE-R chips, pin chip,
the age of the last read, and actions that depend on the state (live: KVM, Power, Shot, SOL;
unreachable: Retry now, Power, Edit server; paused: Retry once, Identities). A filter box
(`/` focuses it) matches key, address and version; the **Show** buttons are All, On, Held
(a KVM or SOL session held by you or an agent, or an IDE-R mount) and Problems (unreachable,
paused, pin differs or unpinned, or KVM held by another client). A banner summarizes sessions
held by this console, mounts and recordings. A device-list failure keeps the last good cards
and says so.

### 7.2 Manage: Servers (`/manage`)

| | |
|---|---|
| Reads | `amt_devices list` (open and Re-read), `amt_identities` (identity chips), `GET /api/fleet` (pin state). |
| Writes | `amt_device_manage` `add`, `edit` (plain sheets), `remove` and `edit` with `repin: true` (holds). `amt_devices pin_check` is a read, made only when **Check pin** is pressed; it needs no sheet. After an add, one `amt_status` read proves the server answers. |

The table shows key, address, ports, identity chips (`present`, `missing`, `no host logon`,
`status unknown`), the pin chip with the full SHA-256 in groups of four and the stored 16-hex
prefix in bold, and actions. Rules worth knowing:

- A **presented leaf that differs** puts the row in the error state, greys Edit and Remove with
  the reason, and keeps Check pin. **Re-pin** appears once a Check pin has read the presented
  leaf, and is a hold whose sheet shows the stored and the presented fingerprint. If the leaf
  changed again between the check and the re-pin, the result says so.
- The **last server's Remove** is greyed with "the last server: amt_device_manage refuses to
  remove it"; a stale-list remove that reaches the tool gets the tool's own refusal verbatim.
- **Add** names vault entries (a select over names `amt_identities` returns, or
  `<key>-amt` / `<key>-host`) and takes an optional expected pin; there is no password field.
  Without an expected pin the leaf presented during the add is pinned (trust on first use) and
  shown in the result for comparison with the AMT's own screen.
- **Edit** sends only the changed fields; an emptied host-logon field sends `clear_host`. It
  never sends `repin`.
- The address must be an IP address, not a host name.

### 7.3 Manage: Identities (`/manage/identities`)

| | |
|---|---|
| Reads | `amt_identities` (open, Re-read, after a value arrives), `amt_devices list` (for owners). |
| Writes | `amt_identity_manage` `intake` (plain sheet; "Mint the intake" or "Replace stored value"), `remove` (hold). The value itself is relayed through `/api/identities/intake/<id>` (section 9.2), not a tool call. |

Each entry is shown by **name and status only** (`present · synced`, `present · entered here`,
`present · unused`, `missing`), with kind and owner derived from the `used_by` fields of the
servers that name it. No value is ever shown. A missing entry offers **Enter**, which sets the
form to mint exactly that name. Remove is greyed while a server names the entry or when the entry
was copied from the main vault. After an AMT admin password arrives the page makes one
`amt_status` for the owner server and reports "succeeded N s after the value arrived". "Change
the AMT admin password" is shown as an unavailable control: amt-mcp has no tool that sets one.

At 1440 px and up the New identity form sits in a side panel beside the list (this page is laid out
as a split page, like Status, KVM and SOL).

The New identity form has no expiry and no kind argument to the tool (which takes only
`{action, name, confirmed}`); kind and owner are used to derive the vault entry name.

### 7.4 Images (`/images`) and the Media tab (`/server/<key>/media`)

One page, two modes: the Media tab has the server fixed; Images has a server picker.

| | |
|---|---|
| Reads | `amt_images list` (every 10 s, or every 2 s while a download or upload runs), `GET /api/fleet` every 5 s (IDE-R view per server), `amt_ider status` on **Status**. `Verify` is `amt_images verify` (a read, no sheet). |
| Writes | `amt_ider` `mount` and `unmount`; `amt_images` `fetch`, `upload`, `rename`, `set_root`, `delete`. |

Sheet kinds: mount with start `next_boot` or `graceful` is plain; mount with start `now` and
image delete are holds; unmount, rename, fetch, upload and set root are plain, the last four
with fields inside the sheet. Notable rules:

- The library lists `.iso` and `.img` files under the image root, at every depth; each shows
  whether it is 512-aligned (an unaligned image cannot be mounted), the newest sha256 the page
  can vouch for (finished upload or fetch, or Verify; otherwise "not verified yet"), progress of
  downloads and uploads, and where it is mounted.
- Rename and Delete are greyed with the reason (mounted, downloading, uploading) when amt-mcp's
  own view says the image is busy; amt-mcp's refusal decides and is shown verbatim with a gloss.
- Mount start modes: `next_boot` (the host sees the drive at its next boot; default), `graceful`
  (asks the OS to reset now), `now` (hard reset).
- With no image root, or one that is not usable, a banner says every mount is refused, and
  **Set root** opens a sheet. Names must be plain `.iso` / `.img` file names.
- Fetch always sends `overwrite: false`. An optional expected sha256 makes a mismatch delete
  the file.
- An upload mints a url through a plain sheet and then streams the file through the console
  without a second sheet (section 9.1).

### 7.5 Settings (`/settings`)

Console preferences and passkeys. Nothing here calls amt-mcp.

- **Theme:** System, Light or Dark, stored in the browser's `localStorage` key
  `amt-console-theme`. The theme button in the navigation rail cycles the same three values (a phone has no rail: use Settings). `theme-init.js`
  applies a saved light or dark choice before first paint; with storage blocked the page
  follows the system for that page view.
- **Keyboard shortcuts:** an on/off switch (`localStorage` key `amt-console-shortcuts`, this
  browser only) and a **Show the list** button that works whether the shortcuts are on or off.
- **Sign out.**
- **Passkeys:** a list (name, enrolled, last used) and **Add a passkey** (section 3.3).

### 7.6 The server page

`/server/<key>` is the server header (name, power pill, address and AMT version, session and pin
chips, and the section tabs) over the tab content. Under 600 px the tabs become a scrolling chip
row with the current section scrolled into view. The tabs, in order, from `SERVER_TABS`:

| Order | Label | Slug | Script |
|-------|-------|------|--------|
| 1 | Status | (none) | none of its own (`server.js`, below) |
| 2 | Power & boot | `power` | `power.js` |
| 3 | KVM | `console` | `console.js` + `embed.js` |
| 4 | SOL | `serial` | `serial.js` + `embed.js` |
| 5 | Media | `media` | `media.js` |
| 6 | Logs | `logs` | `logs.js` |
| 7 | Inventory | `inventory` | `inventory.js` |
| 8 | AMT settings | `settings` | `settings.js` |
| 9 | Advanced | `wsman` | `wsman.js` |

`server.js` loads on every server tab (it draws the header and, on Status, the cards); the
Script column shows each tab's own script on top of `status.js`, `server.js` and the shared
ones. `TAB_SCRIPTS` lists the slugs that have their own script; `SPLIT_TABS` (Status, KVM, SOL)
are laid out with a side column.

### 7.7 Status tab (`/server/<key>`)

| | |
|---|---|
| Reads | `GET /api/server/<key>` every 5 s; `GET /api/server/<key>/captures` on open and on Refresh. |
| Writes | **Take screenshot** (`amt_screenshot`, plain sheet, no `confirmed`). **Fetch** on a past capture is one `amt_captures fetch` through `/api/call`, with no sheet: it is read-only and mints a fresh one-time url that the backend fetches once. **Retry now / Retry once** post `/api/fleet/refresh`. |

Cards: Power, AMT (version, build, SKU, provisioning, zero-touch), Redirection (listener, KVM,
SOL, IDE-R), User consent, Coverage and Identity. The **Coverage** card is made of the read's own
`unavailable` list (dashed chips with reasons) and `truncated` list, so an empty section is
never mistaken for "nothing exists". When the user-consent state shows a code is on the host's
screen, the page points to Advanced and its "Send a consent code" template, because there is no
typed console control for it. The **Sessions on this host** panel shows the KVM, SOL and IDE-R
holders with Open or Start links and any recording. Stale values are marked "stale · last good
<time>" when the last read failed. Past captures list amt-mcp's screenshots, recordings and
casts for this server (the tool has no device filter, so the backend reads up to ten pages of
200 and filters), saying how many it listed of how many amt-mcp holds, and which folders it
could not find.

### 7.8 Power & boot (`power`)

| | |
|---|---|
| Reads | `GET /api/server/<key>/power` on open and **Re-read** (never on a timer, never for a paused server); `GET /api/server/<key>` every 5 s. |
| Writes | `amt_power`, `amt_set_next_boot`, and `/api/sequence` for the combined entries. |

The page opens with what AMT offers: one `amt_wsman_get` of
`CIM_AssociatedPowerManagementService`, whose `AvailableRequestedPowerStates` codes are mapped
to action names by `power.POWER_CODES` (a test pins that table to `amt_write.POWER_ACTIONS`).
Until it answers, every power control is `aria-disabled` ("reading what AMT offers"); then an
action AMT does not list is greyed ("not offered by AMT right now"). If the list cannot be
read, the banner says why and the actions stay available, because `amt_power` reads the list
itself and refuses by name with nothing sent. A paused server shows "paused" and offers
nothing.

The 15 power actions:

| Group | Actions | Sheet |
|-------|---------|-------|
| Graceful | `restart`, `shutdown`, `power_cycle`, `shutdown_hard_graceful`, `power_cycle_hard_graceful` | plain |
| Other | `power_on`, `sleep_light`, `sleep_deep`, `hibernate` | plain |
| Force tray | `hard_reset`, `hard_power_off`, `hard_power_cycle`, `immediate_shutdown`, `immediate_power_cycle`, `nmi` | hold |

The **Next boot** card has a target (`clear` for normal boot, `bios_setup`, `pxe`, `hard_disk`,
`cd_ider`, `floppy_ider`, `diagnostic`; `cd_ider` needs an image mounted first), 14 checkboxes
and two number fields (`firmware_verbosity` 0 to 3, `boot_media_index` 0 to 255), so 16 options.
`clear` sends no options. Three of the options (`secure_erase`, `reflash_bios`,
`configuration_data_reset`) make the call destructive. A value the tool would refuse greys the
three buttons with the reason. Buttons:

- **Set next boot only:** plain, or a hold when a destructive option is ticked.
- **Power on to target:** `amt_set_next_boot` then `amt_power` `power_on`; greyed when `power_on`
  is not offered or the host is already on.
- **Reset to target:** `amt_set_next_boot` then `amt_power` `hard_reset`; always a hold;
  greyed when `hard_reset` is not offered.

The chip next to the card title reads the `BIOSSetup` and `UseIDER` flags of AMT's boot
settings; a PXE or disk request lives in the boot order, which that read does not show. Results
show the tool's words: `ReturnValue`, graceful or not, the power-state readback or "readback
unavailable", the boot steps and flags read back. Platform Erase is not on this tab (see Advanced).

### 7.9 KVM (`console`) and SOL (`serial`)

Both tabs frame amt-mcp's own viewer page through the relay (section 8) and add the console's
own controls around it. Neither starts a session on page load.

| | KVM | SOL |
|---|---|---|
| Reads | `/api/server/<key>` every 5 s, `/api/embed/mirror/<key>` every 1 s while a session is live and the browser tab is visible, past recordings (`amt_captures`) | the same with `serial` |
| Start | `amt_mirror_link start` with `bind: "0.0.0.0"`, `port: 8766`, `fps: 15`, `quality: 70`, `record_on_start: false`; plain sheet | `amt_serial_link start` with `bind`, `port: 8766`, `record_on_start: false`; plain sheet |
| Stop | `stop`: plain, or a hold when an agent started the session or a call is in flight | the same |
| Record | `record_start` (plain sheet), `record_stop` (plain sheet); greyed with a reason when no session is live | the same |
| Input | `amt_console_input` macros and a text step (below) | **Send a line**: `amt_sol` with `read_seconds: 3`, up to 1023 printable ASCII characters, optional appended Enter |
| Host sign-in | `amt_remote_logon` / `amt_remote_logoff` with `console: "kvm"` | the same with `console: "serial"` |

**Session card states.** KVM has five: yours (`console`), an agent's, none (free), another
client (`held_other`, "opens refused"), and consent pending (a code is on the host's screen; the
card points to Advanced). SOL has three: yours, an agent's, none. Unknown (session status
unreadable) is never shown as free. When a session is held by an agent on amt-mcp's default bind
(`127.0.0.1`), the console cannot reach it: the card says "not reachable from here · bind
127.0.0.1". The console starts its own sessions on `0.0.0.0:8766` behind the viewer front, so a
session it starts is reachable; **Open in a tab** opens the keyed relay path in a new tab.

**AGENT TYPING strip.** When the viewer's status carries an `in_flight` call (an agent's tool is
using the session), the strip shows "AGENT TYPING · an agent's call holds this session for a
moment · your keys and mouse are paused until it returns", naming the tool, and the frame is
set `inert`. That takes focus out of the frame so the viewer releases control. Stop becomes a
hold in this state.

**KVM-only controls.**

- A 26-entry macro grid (Ctrl+Alt+Del, Win combinations, Alt-Tab, Alt-F4, F1 to F12, and so on).
  Each button is one `amt_console_input` action; the tests validate every entry against the live
  tool schema.
- A **screen guard**: a chip row (`any`, `desktop`, `windows-signin`, `linux-console`,
  `bios-setup`, `grub`, `text-installer`, `mok-manager`). A choice other than `any` is sent as
  `expect`, so the first frame is classified first and nothing is sent unless it matches. `any`
  omits `expect` (an empty list is refused by the tool).
- A **text step**: printable ASCII, at most 500 characters. There is no raw secret step; a
  credential is typed only by Host sign-in, and only into a positively identified sign-in.
- **Host sign-in / Sign out**: one attempt, no retry control. An abort is shown with its reason
  and what was typed.

Keys and mouse typed into the live frame go to the host through the viewer's own `input` route,
the one path that is not a tool call.

### 7.10 Logs (`logs`)

| | |
|---|---|
| Reads | `amt_logs` through `/api/call`, never `confirmed`: on open, **Read**, a switch of log, and **Newer / Older**. Never on a timer, never for a paused server. |
| Writes | None. |

Event log or Audit log; **Since** and **Until** in UTC (sent as typed, the tool judges them);
50 records a page, 20 on a phone (where each record is a card); newest first. The severity
filter (all, warning+, critical) applies on the page only, since `amt_logs` has no such
argument: it never changes a count and says how many rows it hid. The line under the table is
the result's own counts (`matched`, `fetched`, `fetch_complete`, `undated`, `undecodable`, rows
shown). The page distinguishes an empty log (nothing fetched), an empty window (records exist,
none match), a page past the end, and an incomplete fetch, and it reports a result that is
missing a count as unreadable rather than showing a zero.

### 7.11 Inventory (`inventory`)

Reads `amt_inventory` through `/api/call` on open and **Re-read**, naming all seven sections
(there is no section picker): chassis, baseboard, BIOS, processors, memory, storage media,
physical media. One card per section from the tool's own fields (CIM names, no relabelling), a
Coverage banner built from the result's `unavailable` (with reasons) and `truncated`, and
**Export JSON**, which saves the result exactly as returned (built in the browser; nothing is
sent anywhere). A result that neither returns a requested section nor lists its class as
unavailable is reported as unreadable. The section-to-class table in `inventory.js` is pinned to
`amt_tools.INVENTORY_CLASSES` by a test.

### 7.12 AMT settings (`settings`)

| | |
|---|---|
| Reads | `amt_settings {device, area}` on open (area `kvm`), on an area switch and on Re-read; `amt_identities` when the users area opens. |
| Writes | `amt_configure {device, area, changes, confirmed: true}` through a plain sheet. No `amt_configure` call is ever a hold. |

Ten area chips: six writable (`network`, `internet`, `security`, `users`, `kvm`, `features`) and
four dashed read-only ones (`agent_presence`, `system_defense`, `subscriptions`, `wake_alarms`)
whose cards show what was read and link to the guarded templates in Advanced.

A writable area shows its fields from the result (a switch per flag, number and text fields, one
line per string in a list), an old/new preview of every field, **Write** and **Discard**. Only
changed fields are sent. An input the tool would refuse (kind or length) is stopped before the
sheet, with the reason beside Write; a field the read did not report is not offered. The
consequence line names each change and, for the changes the tool itself calls risky (user
consent off, the plaintext VNC port, non-TLS connections, enabling IDE-R, SOL or KVM), what the
request does. After a write the result row shows what the tool read back and keeps `previous`,
with a **Revert** that writes those values back through its own sheet.

**Users** lists the AMT accounts (the admin account has no Remove), removes one, and adds one
(name 1 to 16 of `A-Za-z0-9_.@-`, `access_permission` 0 to 2, realm numbers 0 to 31). Add is
offered only while the vault identity `<device>-amt-user-<name>` is present in
`amt_identities`; otherwise it is greyed with "identity ... is missing" and a link to Manage.
No password is a field; only the digest of the vaulted password is sent. An add or remove has
no `previous`, so the opposite action is the revert.

A page that writes re-reads the area whenever the host may have changed. The page's tables
(writable fields and kinds, where each sits in the read, redirection states, risky changes, the
user-name rule) are pinned to `amt_write` and `amt_tools` by `test_console_settings.py`.

### 7.13 Advanced (`wsman`)

| | |
|---|---|
| Reads | `amt_wsman_get` (get or enumerate), when asked only. |
| Writes | `amt_wsman_invoke {device, operation, class_name, method, selectors, fields, confirmed: true}`: put, create, delete or invoke. Plain sheet, except method `Unprovision` (hold). |

A banner states what the tool states: no per-class safeguard beyond your confirmation, a Put
may replace a whole instance, credential-named fields are refused at any depth, replies are
redacted. Three parts:

- **WS-MAN browser.** A class (must match `AMT_`, `CIM_` or `IPS_` plus a name; the field
  suggests every class amt-mcp's code names and still accepts others), get or enumerate, and
  for a get the selectors as a JSON object of text values. The key names shown for each class
  (`CLASS_KEYS`) come from `console/tests/data/wsman_class_keys.json`, measured read-only against
  a live host with `deploy/wsman_class_probe.py` and pinned by a test. After an enumerate of a
  class with known keys, one chip per instance switches to get and fills the selectors; picking
  never reads. An enumerate shows its own `count` and `truncated`; a result missing either, or
  whose count is not its list, is unreadable and offers nothing.
- **Edit and Put** (from a get). Loads the editor with the full instance and **strips** every
  redacted or credential-named field at any depth, naming them in the editor and on the sheet.
- **Script editor.** The credential-name check runs in the page by the same rule as
  `amt_wsman.is_secret_field` (a parity test over a name corpus pins the two), plus the tool's
  own shape rules, with the tool's own codes. **Run** is `aria-disabled` with the code beside it
  when the tool would refuse; **Validate only** says the same without a call. `amt_wsman_invoke`
  reads nothing back, and the copy says so; a reply without a ReturnValue is "unknown", never
  success.
- **Guarded templates**: twelve actions with no typed tool (OS wake, OS power saving, three
  user-consent calls, two agent-presence watchdog rows, a system-defense filter and policy, an
  event-subscription delete, a wake alarm, and Unprovision). Load fills the editor; a
  `<placeholder>` must be replaced before Run is offered. Field names come from the AMT SDK and
  are not all confirmed by a live enumerate; a template whose class does not round-trip is to be
  dropped. **Platform Erase** is listed as unavailable ("no tool yet").

## 8. The embedded viewers

The KVM and SOL tabs show amt-mcp's own mirror page (`/m/<token>/`) or terminal page
(`/s/<token>/`) in embed mode (`?embed=1`: View and Control only; no Record, Power, Boot, Media,
Screenshot or Download). The viewer's token is its only key, so it never reaches the browser:
the console relays the page under its own path instead of redirecting.

### 8.1 Finding the session

`Embed.resolve` makes one server-side `amt_mirror_link` or `amt_serial_link` call with
`action: "status"` and the device named, reads the `urls` and `control_urls`, and keeps the
control url in memory for 30 s (`TARGET_TTL`). Only a control url whose scheme and host are
exactly the viewer front (`AMT_CONSOLE_VIEWER_ORIGIN`) with no query or fragment is relayed. An
agent's session on the tool's default bind (`127.0.0.1`) has no such url; the page then says
it is not reachable from here. The relay **never starts a session**: a GET that did would be a
write with no sheet. Start is the confirmed `tools/call` of section 7.9. A start or stop made
through the console forgets the cached target.

### 8.2 The opaque-origin frame and the embed key

The frame is `<iframe sandbox="allow-scripts allow-forms" allow="clipboard-write *"
referrerpolicy="no-referrer">`. There is no `allow-same-origin`: the relayed script cannot read
the console page's DOM, globals or cookie and cannot call `/api`. A test scans the static client
for any grant of `allow-same-origin`. The relayed response carries the same CSP `sandbox`, so
**Open in a tab** is no more privileged than the frame.

An opaque document cannot carry the `SameSite=Strict` cookie, so every `/embed/` request is
authenticated by an **embed key** in the path: `/embed/<kind>/<server>/<embed key>/<route>`.

| Property | Behaviour |
|----------|-----------|
| Minting | `POST /api/embed/key {kind, device}` with cookie and CSRF; `kind` is `mirror` or `serial`; the server must be known (`400 bad_embed_request`, `404 unknown_server`). The key is `secrets.token_urlsafe(32)` (43 characters) and appears in this reply only. |
| Binding | To the minting session (by `session_ref`, the SHA-256 the session record is filed under, never the cookie itself), one kind and one server. A key for another kind or server is refused. |
| Storage | In memory, as a SHA-256 digest. A presented key is compared against **every** kept digest with `hmac.compare_digest` (no early exit). |
| Lifetime | Ends at sign-out, when the session idles out, after 10 minutes unused (`KEY_TTL_IDLE`), or at a console restart. A request with the key, or the page's own `GET /api/embed/<kind>/<server>` poll (once a second while a session is live), restarts the clock. |
| Limit | At most 256 live keys (`KEYS_MAX`); the oldest unused goes first. |
| Open streams | A stream already open under the key (the mirror `stream`, the serial `events`) re-checks the key every 2 s (`KEY_RECHECK`), quiet or busy, and ends at the first no, so sign-out and session expiry cut it. An open stream counts as a use of the key. |
| Failure | A wrong, expired, revoked, other-kind or other-server key is `404 not_found`, with nothing sent upstream and no CORS header. A missing trailing slash is also a 404 (a redirect would repeat the key). |
| Page signal | The poll's `key_live` boolean tells the page when its frame's key is gone (idle limit, console restart) so it mounts a fresh frame. |
| Hygiene | The key is in no log line (`loggable()`), `Referer`, error body, upstream request or file. The frame's `src` and Open in a tab are the only places it is written. |

### 8.3 What the relay allows, rewrites and strips

**Allowed sub-routes** (`embed.GET_ROUTES`, `embed.POST_ROUTES`), pinned by
`test_the_allowlist_is_the_embed_page_s_routes_of_the_real_viewer` to the viewer's own route
tables minus the standalone-only ones:

| Kind | GET | POST |
|------|-----|------|
| `mirror` | page (empty), `stream`, `frame.jpg`, `status.json` | `input` |
| `serial` | page, `events`, `status.json`, `xterm.js`, `xterm.css`, `addon-fit.js` | `input` |

Everything else, including the standalone page's `record`, `media.json`, `power.json`, `ider`,
`power` and `boot`, is a 404 with nothing sent upstream. Every upstream request also carries
`embed=1`, so amt-mcp refuses those routes itself.

**Upstream request.** Built from the kept control path; the console's cookie, bearer and CSRF
token are never sent. Forwarded: `Accept` (if under 200 characters), `Content-Type` for a POST,
and `Last-Event-ID` only when it is all digits. Timeout 20 s. If the first attempt gets a 404
(the session restarted and its tokens changed), the relay does one fresh session lookup and
retries once.

**Response handling.**

- The viewer's `Location` and framing headers are never copied back. A 3xx from the viewer is
  `502 viewer_redirected`.
- The content type must look like a media type, else it is served as `application/octet-stream`.
- Text bodies (HTML, plain text, CSS, JavaScript, JSON) have every session token replaced by
  `[withheld]` and any one-time url masked. Non-text bodies pass through.
- A non-streaming body is read to at most 16 MiB; a status of 500 or above becomes 502; a
  non-2xx body is cut to 2000 bytes.
- Streams (`stream`, `events`) are copied chunk by chunk on a reader thread with
  `X-Accel-Buffering: no`; the upstream connection is cut when the browser goes away, when the
  key dies, or when upstream ends. The log line says which.
- Errors the relay makes are JSON with a fixed code: `404 not_found`, `404 unknown_server`,
  `409 session_not_live`, `409 viewer_not_reachable` (with the bind), `502 viewer_unreachable`,
  `502 viewer_redirected`, `502 status_unreadable`, `503 console_bearer_unavailable`,
  `502 amt_mcp_*`, `411`, `413` (over 64 KiB) and `415` (a POST whose `Content-Type` is neither `application/json` nor absent).

**CORS (Origin `null`).** The opaque frame sends `Origin: null`. Key-authenticated `/embed/`
paths answer `Access-Control-Allow-Origin: *`, never credentials; a preflight allows
`GET, POST, OPTIONS` with `Content-Type, Accept, Last-Event-ID, Cache-Control, Pragma`. No
other path answers CORS. A valid key is what the wildcard origin grants: a page with no key is
given nothing. A POST under `/embed/` additionally needs an `Origin` of exactly `null` or the
console's own origin (`403 cross_site_refused` otherwise); it needs neither the cookie nor the
console CSRF token, which the viewer's script cannot carry.

**CSP of relayed pages.** The viewer pages carry inline script and style, so they get their own
policy instead of the console's, with `<origin>` being `AMT_CONSOLE_ORIGIN`:

```
default-src 'none'; script-src <origin>/embed/ 'unsafe-inline'; style-src <origin>/embed/ 'unsafe-inline';
img-src <origin>/embed/ data: blob:; connect-src <origin>/embed/; font-src <origin>/embed/;
frame-ancestors 'self'; base-uri 'none'; form-action 'none'; object-src 'none';
sandbox allow-scripts allow-forms
```

with `X-Frame-Options: SAMEORIGIN`. The sources are absolute because an opaque document has no
`'self'`. The page can fetch, load and connect to nothing but the relay's own `/embed/` paths,
and cannot submit a form.

### 8.4 Start, stop, record, input

- **Start / Stop / Record** are tool calls from the console's own session card, each behind a
  sheet (section 7.9); Record is never a control of the framed page (a POST of `record` is a 404
  here, and amt-mcp refuses it in embed mode).
- **Live input** is the framed page's own `input` POST, relayed. It is the design's one named
  exception to "every write is a tool call behind a sheet".
- **AGENT TYPING** (section 7.9): the strip and the `inert` frame come from the viewer's
  `in_flight` field, which carries the tool name and start time and never its arguments.

## 9. Uploads and identity intake through the console

Both flows exist so that a one-time url never reaches the browser. They differ from the design
note, which has the browser PUT directly to the url; the console relays instead. Both keep the
url in memory only, hand the browser an opaque id, and accept at most 16 open offers (the
soonest to expire is evicted).

### 9.1 Image upload

1. The user picks a `.iso` or `.img` file in the Upload sheet (plain sheet with fields; an
   optional sha256). Confirm sends `amt_images upload {name, size_bytes, sha256?}` through
   `/api/call`.
2. In `_tool_call`, `Uploads.register` reads the minted url from the raw result. It is kept only
   if it is on amt-mcp's own origin (scheme and netloc, compared whole), has no query or
   fragment, and has a one-time path `/uploads/<43 chars>`. The browser receives `upload_id`,
   `name`, `size_bytes` and `expires_in_s` (at most 900) instead; a bad url gives
   `upload_refused`.
3. The page posts the raw file to `POST /api/images/upload/<upload_id>` with
   `Content-Type: application/octet-stream` and a `Content-Length` equal to the declared size
   (`415 octet_stream_required`, `411 length_required`, `400 size_not_the_declared_size`,
   `404 unknown_upload`).
4. The backend opens a connection to the url, then streams the body in 1 MiB chunks with a PUT.
   It holds none of the file and writes none of it; the console has no image root. The id is
   used up the moment the first byte goes; a refusal made before that keeps it.
5. The reply is amt-mcp's own: `{"ok": true, name, bytes, sha256}` for its 201, or
   `{"ok": false, status, text}` (first 600 characters, one-time urls masked) for a refusal, or
   `{"ok": false, "code": "browser_stream_ended_early" | "amt_mcp_unreachable:<Type>", ...}`.
   amt-mcp checks the exact size and the optional sha256 itself and deletes its part file on a
   mismatch. The console adds no size cap of its own.

The url, its token, the file name in the url and the id are in no response, header or log line
(the id is returned once, in the mint reply).

### 9.2 Identity intake

1. **Mint**: `amt_identity_manage intake {name}` (plain sheet). `Intakes.register` keeps the
   `/intake/<43 chars>` url (same origin and shape rules) and the page gets `intake_id`, `name`,
   `max_bytes` (at most 4096) and `expires_in_s` (at most 900).
2. **Send**: the page posts the field's text once to `POST /api/identities/intake/<intake_id>`
   with `Content-Type: text/plain` and clears the field before the answer arrives.
3. Before sending anything, the backend refuses (`400`, id kept) a value that is empty, longer
   than the offer's cap, short, not UTF-8, or contains a CR, LF or NUL
   (`value_size_out_of_range`, `value_incomplete`, `value_not_utf8`,
   `value_has_a_line_break_or_nul`). A host-logon value is one line of JSON
   (`{"user": ..., "password": ...}`).
4. It then PUTs the value once (30 s timeout). A `201` with `stored: true` returns
   `{"ok": true, "name"}` only; a refusal returns `{"ok": false, status, text}`, and if the
   answer text contains the value it is replaced by "[answer withheld: it contained the value]".
   An accepted intake re-reads the device list, so a server paused on its refused credential can
   resume (section 6.3).

The value exists in the console for the length of that request. The field is a text input
masked with `-webkit-text-security`, `autocomplete="off"`, outside any form, with no `value`
attribute. No value, url or id is stored, logged or returned (`test_console_secrets.py`,
`test_console_manage_browser.py`).

## 10. The captures store

A tool result that carries a one-time download (a `url` on `/handoffs/<43 chars>` and a
`sha256`, such as a screenshot or a finished recording) is **ingested by the backend**:

1. The url is accepted only from amt-mcp's own origin, with no query, fragment or userinfo, and
   a handoff path. Otherwise the record is `failed` with `handoff_url_not_from_amt_mcp` and
   nothing is fetched.
2. It is fetched **once**, immediately (60 s timeout, 1 GiB cap), streamed into a file created
   exclusively with mode 0600.
3. The body's SHA-256 must equal the tool's. A mismatch deletes the file and the record is
   `failed: sha256_mismatch`.
4. The record is `ready`, `expired` (the handoff returned 404 or 410: "not fetched within 15
   minutes"), or `failed` with a reason (`result_sha256_malformed`, `fetch_status_<n>`,
   `too_large`, `fetch_failed:<Type>`, or the transport error). An expired link is never
   silently missing.
5. Only the SHA-256 of the url is stored, so the same link is never fetched twice; a repeat
   returns the existing record.

Files live in `AMT_CONSOLE_DATA/captures` (0700 folder, 0600 files) as `<id>.bin` and
`<id>.json`, with a 22-character id. The browser sees the public record (id, name, status,
reason, sha256, bytes, taken and expiry time) and downloads from `GET /captures/<id>`
(a `ready` capture only; `Content-Disposition: attachment`; the name is sanitized to word
characters, dot, hyphen and space).

**Retention.** `AMT_CONSOLE_CAPTURE_HOURS` (default 24). There is no timer: records and files
older than the retention are swept whenever the store is listed, read or ingested.

`amt_captures fetch` (the Status tab's **Fetch** and the SOL tab's finished-cast save) mints a
fresh url per request, and the backend ingests it the same way. The SOL tab saves a finished
cast: after Stop recording, and after Stop terminal when a recording was running. A mirror
recording is encoded in the background and appears under Recordings after **Refresh**.

## 11. Theme and layout

### 11.1 Theme

`design/tokens.json` is the source of the colors (Material 3 roles plus three extended roles,
live, ok and hold) in light and dark. `console/make_theme.py` generates
`console/static/theme.css` from it:

```bash
python3 console/make_theme.py            # writes console/static/theme.css
python3 console/make_theme.py --check    # exit 1 if the committed file is not what the tokens produce
```

`test_theme_css_is_what_the_tokens_produce` runs the check, so a token edit without
regenerating fails the suite. The light theme is the default; dark applies under
`prefers-color-scheme: dark` unless the user chose light, and always under `data-theme="dark"`.
`base.css` is the mockups' own component layer, and a test fails on any color literal in the
built CSS that is not a token. `design/make_tokens.py` regenerates `tokens.json` (it needs
`material-color-utilities` from `design/requirements.txt`); the hue-band tests skip, and say so,
when that package is not importable (`AMT_MCU_PATH` can point at a `pip --target` copy).

The client makes no external request: no CDN, no web font (monospace text falls back to the
system stack), and a test asserts that every page load makes zero requests off the console's
origin.

### 11.2 Breakpoints

| Width | Layout |
|-------|--------|
| Under 600 px | Phone: bottom navigation bar, server sections as a scrolling chip row, 1-up cards, card-per-row tables, bottom sheets, 20 log records per page |
| 600 px and up | Navigation rail; server tabs; tables in a horizontal scroller |
| Under 840 px | 1-up cards |
| 840 to 1099 px | 2-up cards |
| 1100 px and up | 3-up cards |
| 1440 px and up | Status, KVM, SOL and Identities keep a 360 px side panel (under 1440 the panel stacks below) |

### 11.3 Keyboard shortcuts

| Keys | Action |
|------|--------|
| `g f` | Fleet |
| `g m` | Manage |
| `g c` | KVM of the server you are on |
| `g p` | Power & boot of the server you are on |
| `/` | Focus the fleet filter (when visible) |
| `?` | Show the list (a sheet) |
| `Esc` | Close the open sheet |

The second key of a `g` pair must follow within 1.5 s. Shortcuts are inert while focus is in an
input, textarea, select, iframe, `contenteditable` or `role="textbox"`; with Ctrl, Meta or Alt;
on a repeated key; and while any sheet is open. Settings holds the on/off switch (section 7.5).
Every shortcut has an on-screen control.

### 11.4 Accessibility

- Every state has a glyph and a word beside its color (pills, chips, results, severity).
- Disabled controls are focusable `aria-disabled` elements with visible reasons (section 5.4).
- Sheets are modal dialogs with a labelled title, focus management and a Tab trap (section 5.2).
- Hit areas are at least 48 by 48 CSS pixels for controls and 24 by 24 for inline chips (design
  note 5.6; the verifier measures them).
- Fingerprints are grouped by four characters.
- Reduced motion is honored on every page; everything that animates carries `data-motion`.
- axe-core 4.11.4 is run on every page in both themes and must report no violation. It is
  vendored for the tests only (section 13).

## 12. Configuration

`Config.from_env` in `server.py` (the backend reads nothing else from the environment).

| Variable | Default | Meaning |
|----------|---------|---------|
| `AMT_CONSOLE_ORIGIN` | `https://amt-console.example.com` | The console's public origin, `scheme://host[:port]` (anything else raises at startup). Used for the Host check, the exact-Origin check and the WebAuthn origin. |
| `AMT_CONSOLE_RP_ID` | `amt-console.example.com` | WebAuthn relying-party id. Must be the origin's host or a registrable suffix of it, as WebAuthn requires. |
| `AMT_CONSOLE_DATA` | `/console-data` | State folder: `passkeys.json`, `sessions.json`, `enroll.json`, `host-sessions.json`, `captures/`. Created 0700; must be writable. |
| `AMT_CONSOLE_MCP_URL` | `https://amt.example.com/mcp` | amt-mcp's MCP endpoint. Its origin is also the only origin handoff, upload and intake urls are accepted from. |
| `AMT_CONSOLE_VIEWER_ORIGIN` | `https://amt-viewer.example.com` | The viewer front the relay fetches from (`scheme://host[:port]`); only control urls on exactly this origin are relayed. |
| `AMT_CONSOLE_SECRETS_CLI` | none (unset) | Path to the vault CLI that returns the bearer (`<cli> get amt-console-token`, run with the current Python, 15 s timeout, empty stdin). Unset: every call fails with `console_bearer_unavailable`. |
| `AMT_CONSOLE_BIND` | `0.0.0.0` | Listen address. |
| `AMT_CONSOLE_PORT` | `8767` | Listen port. |
| `AMT_CONSOLE_IDLE_HOURS` | `12` | Session idle timeout, hours. |
| `AMT_CONSOLE_CAPTURE_HOURS` | `24` | Capture retention, hours. |
| `AMT_CONSOLE_MCP_TIMEOUT` | `60` | Seconds allowed for one `tools/call`. |
| `AMT_CONSOLE_FLEET_SECONDS` | `30` | The fleet read interval (section 6.1). |

The vault CLI reads its own `NVAULT_*` variables (for example the vault file and key file
paths) from the environment; the console passes the environment through and does not interpret
them. `mcp_client.from_env` reads `AMT_CONSOLE_MCP_URL`, `AMT_CONSOLE_SECRETS_CLI` and
`AMT_CONSOLE_MCP_TIMEOUT` and is not called by `server.py`, which builds its `Client` from
`Config`.

Run it directly with:

```bash
cd console && AMT_CONSOLE_DATA=/some/dir AMT_CONSOLE_SECRETS_CLI=/path/to/secrets.py python3 server.py
```

The container image runs the same `server.py` as a non-root user; see
[Install amt-console](install-console.md).

## 13. Testing

All console tests are in `console/tests/`. `conftest.py` puts the console modules, the test
helpers and the repository root on `sys.path`. Test doubles are in `console_fakes.py`: a software
passkey authenticator, a fake amt-mcp (`/mcp` and the one-time `/handoffs` route), a fake viewer
front that serves amt-mcp's real embed-mode pages, a fake vault CLI and a running console. No
test reaches a host: a call only ever goes to a fake or to amt-mcp's real code behind a fake.
All bearers and secrets in tests are throwaway sentinels.

| File | What it pins |
|------|--------------|
| `test_console_auth.py` | Enrollment, sign-in, counters, sessions and tombstones, CSRF, origin and Host checks, framing headers, static whitelist, passkey add |
| `test_console_webauthn.py` | Every refusal of the relying party names its check |
| `test_console_mcp_client.py` | The `TOOLS` table against live schemas, the per-call rules, the bearer lifecycle, no redirects |
| `test_console_components.py` | Sheets, the force matrix, the destructive predicate and call spy, framing refusal, theme, sign-in page, a full passkey ceremony in Chrome's virtual authenticator |
| `test_console_fleet.py`, `_fleet_browser.py` | The schedule and stagger, pause and resume, holders, coverage, captures list, routes, masking |
| `test_console_power.py` | Offered states, the action table, boot sheets, sequences |
| `test_console_embed.py`, `_embed_browser.py` | The relay, the allowlist, keys and their lifetime, CORS, streams, the KVM and SOL pages |
| `test_console_media.py` | Mounts, library, upload through the console, busy refusals |
| `test_console_logs_inventory.py`, `test_console_settings.py`, `test_console_wsman.py` | The read and write tabs; page tables pinned to the tools |
| `test_console_manage.py`, `_manage_browser.py` | Servers and identities against amt-mcp's real device and identity code |
| `test_console_captures.py` | One fetch, sha256, expiry, retention |
| `test_console_secrets.py` | No secret in any response, log, url, file or the client bundle; the markup scan |
| `test_console_theme.py` | `theme.css` equals the tokens; token coverage; no color literal outside tokens |
| `test_console_deploy.py` | The Dockerfile and compose service ship every module and mount nothing of amt-mcp's |
| `test_console_verifier.py` | The built-client verifier (below) and the mockup run |

About 800 test functions (a grep count of `def test_`); many are parametrized, and with Playwright installed pytest collected 1,354 cases from `console/tests` at the time of writing (the browser modules are skipped without it, so the count is lower there).

### 13.1 Running tests

The suite is configured in `pyproject.toml` to run on every core with work stealing
(`-n auto --dist worksteal`, needs `pytest-xdist`). Browser tests need Playwright and Chromium;
without them they skip with a message saying the browser immutables were **not** checked.

```bash
pip install -r console/requirements.txt 'mcp>=1.26,<2' pytest pytest-xdist httpx pillow playwright jsonschema
python3 -m playwright install chromium

python3 -m pytest console/tests                                   # the console, on every core
python3 -m pytest console/tests -n 0                              # one process
python3 -m pytest console/tests/test_console_power.py             # one file
python3 -m pytest console/tests -k "embed and not browser"        # a subset by name
python3 -m pytest console/tests/test_console_verifier.py -k shortcuts
```

### 13.2 The built-client verifier

`test_console_verifier.py` renders **every** console page (sign-in, Fleet, Manage, Identities,
Images, Settings and the nine server sections) in headless Chromium at 360, 600, 1024 and 1440
px in both themes, in front of the scripted amt-mcp, and walks each with the probes and the
failure builders of `design/check_mockups.py` (`layout_fails`, `contrast_fails`, `state_fails`;
shared with the mockup run, never copied). The aggregate prints `FAILS n` and asserts 0. It
checks: the layouts by width, no horizontal scroll and the 16 px gutter, hit areas, text and
ring contrast, that a state attribute paints its state's token, card-per-row tables and bottom
sheets on the phone, reduced motion, that every `aria-disabled` control is focusable with a
visible reason and ignores activation, zero console errors, **zero requests off the console's
origin**, and axe-core with no violation.

axe-core 4.11.4 (`console/tests/vendor/axe-core/`, MPL-2.0, its SHA-256 pinned by a test) is
**test-only**: never serve it from the console, never add it to the image, never fetch it. A
rule may be turned off only in `AXE_OFF` in that file, with a written reason; it is empty today,
and `color-contrast` may never be listed. A new page must be added to `PAGES` there.

### 13.3 The mockup verifier and the force-control pins

`design/check_mockups.py` verifies the 16 mockups in `design/*.html` (the same probes, plus the
force matrix, the confirm sheets, the call and secret scans and positive controls). Run it from
anywhere:

```bash
python3 design/check_mockups.py                        # everything
python3 design/check_mockups.py wsman.html             # one mockup
python3 design/check_mockups.py --part base wsman.html
python3 design/check_mockups.py --part force:1024:0 power-boot.html
python3 design/check_mockups.py --merge                # also merge new contrast pairs into tokens.json
```

`--part base` runs everything except the force matrices and prints how many force controls the
page has; `--part force:<width>:<index>` runs one force control's matrix at one width, so the
pieces can run side by side. Needs `playwright` with Chromium and `jsonschema`
(`design/requirements.txt`).

`test_console_verifier.py` wraps it, one piece per test. `FORCE_CONTROLS` there is the number of
force controls per mockup (`console.html` 1, `identities.html` 1, `media.html` 2,
`power-boot.html` 8, `serial.html` 1, `servers.html` 2, `wsman.html` 1 = 16), and each piece
asserts the verifier saw exactly that many; `STILL` lists the two mockups with no animated
element. `test_the_mockup_run_covers_all_sixteen_mockups` fails on a new or lost mockup, and
`test_a_force_piece_past_the_last_control_fails` is the split's own positive control.

## 14. Extending the console

### 14.1 Add a server tab or a page

1. Add `(slug, "Label")` to `SERVER_TABS` in `console/server.py` at the position you want. Add
   the slug to `TAB_SCRIPTS` if it has its own script, and to `SPLIT_TABS` if it has a side
   column.
2. Create `console/pages/content-server-<slug>.html` and `console/static/<slug>.js`. Without the
   page, the tab renders `content-unbuilt.html`.
3. In the script, take the server key from `.srvhead[data-server]`, wait for `amtc.ready`, and
   use `amtc.post` / `S.get`. Reads never poll AMT; follow the existing pattern of reading when
   opened and when asked, and greying controls for a paused server.
4. For a new top-level section, add it to `NAV` and to the section-to-scripts map in `_shell`,
   plus `content-<name>.html` and `appbar-<name>.html`, and the path to the `section` map in
   `_get`.
5. Add the page to the mockups (`design/<name>.html`) and to `PAGES` in
   `test_console_verifier.py`, and write the page's test module.

### 14.2 Add a tool to the console

1. Add the tool to amt-mcp first (its own tests and the tool-count pin there).
2. Add `"amt_new": (needs_device, read_only)` to `TOOLS` in `console/mcp_client.py`. If it is a
   write with actions that need no confirmation, add them to `UNCONFIRMED_ACTIONS`.
   `test_the_tool_table_matches_the_live_amt_mcp_schemas` fails until the table matches.
3. If a call with some arguments is destructive, add a case to `destructiveStep` in
   `components.js` and to the predicate test table.
4. If the result can carry a url, check it against `ONE_TIME_URL` in `captures.py`.

### 14.3 Rules a change must keep

- **No markup sinks for host or tool text.** Build with `amtc.h` (text nodes). Do not use
  `innerHTML`, `outerHTML`, `insertAdjacentHTML`, `document.write`, `eval` or `new Function`.
- **No external requests.** No CDN, font, script, image or `fetch` to another origin; the
  verifier fails on any.
- **Every write is behind a sheet** (`amtc.openWrite` / `amtc.bindWrite`), with the call shown
  being the call sent. The kind of sheet comes from the one predicate, never from the button.
  The exceptions are listed in this guide: embed input, the intake value relay, and the file
  upload stream (each follows a sheet or a keyed route).
- **The browser never holds a bearer, a one-time url, a viewer token or a secret value.** New
  routes that return tool output must go through `strip_one_time_urls` or a whitelist.
- **Disabled means `aria-disabled` plus visible text.** Never `disabled`, never a tooltip.
- **Name the device** on every call, and never send `confirmed` for a read.
- **Fail closed and keep reads off paused servers.** A page that reads a server must grey its
  control when the server is paused.
- **Keep the tables in sync with the tools** that the tests pin (power actions, inventory
  classes, settings fields, wsman class keys).
- **Update the mockups and the verifier pins** (`FORCE_CONTROLS`, `PAGES`, the mockup count)
  with any change to a page or a force control, and regenerate `theme.css` after a token edit.
- **Add a new module to the Dockerfile `COPY` list.**

### 14.4 Where the console departs from the design note

The built console follows the [UX design note](ux-design-2026-10-20.md) except in these places.
Read the note for intent and this guide for what runs.

| Design note | Built console |
|-------------|---------------|
| 2.7 (images) and 2.11 (identities): the browser PUTs the file or value straight to amt-mcp's one-time url | The console relays it (section 9), so the url never reaches the browser; the note's "two browser-direct paths" (its row 29) become one, the viewer's live input. |
| 2.9: Inventory has section chips | No picker; every read names all seven sections (designer ruling recorded in `inventory.js`). |
| 6.7: the console and serial views keep a 360 px side panel from 1440 px | The split layout also applies to Status and Identities (`SPLIT_TABS`, and `split=True` for `/manage/identities`). |
| Tool arguments such as an identity's kind, owner and expiry | `amt_identity_manage` takes only `{action, name, confirmed}`; the form derives the name from kind and owner and has no expiry. |

## 15. Keeping this guide current

Update this guide in the same change as any of the following. The anchor is the place to read.

| If you change | Update | Anchor in source |
|---------------|--------|------------------|
| A route, a status code or a header | sections 2.3 to 2.5, 3, 4 | `_get`, `_post`, `_embed`, `_headers`, `Handler` in `server.py` |
| An env var or default | section 12 | `Config.from_env` |
| The tool allowlist or confirmation rules | section 4 | `TOOLS`, `UNCONFIRMED_ACTIONS`, `validate_call` in `mcp_client.py` |
| The destructive set, hold timing or sheet rules | section 5 | `destructiveStep`, `wireForceControl`, `wireSecondSheet` in `components.js` |
| Polling, pause rules, holder rules | section 6 | `Fleet` in `fleet.py`, `POLL_MS` in the page scripts |
| A tab, its reads or its writes | section 7 | `SERVER_TABS` and the tab's script and `content-server-*.html` |
| The relay, embed keys, CORS or CSP | section 8 | `embed.py`, `embed_headers` and `EMBED_*` in `server.py` |
| Upload, intake or captures | sections 9 and 10 | `images.py`, `intake.py`, `captures.py` |
| Tokens, breakpoints, shortcuts | section 11 | `design/tokens.json`, `base.css`, `shortcuts.js` |
| Tests or the verifier | section 13 | `console/tests/`, `design/check_mockups.py`, `FORCE_CONTROLS` |

Check the guide against the source with these probes:

```bash
grep -n "SERVER_TABS" console/server.py                     # tab names and order
grep -n "environ\|env.get" console/server.py console/mcp_client.py   # configuration
grep -n "if (path\|re.fullmatch\|\"/auth\|\"/api" console/server.py   # routes
```

The repository's [agent guidance](../CLAUDE.md) also requires a change to a tool, a route, an env
var or a deploy step to update the matching guide in `docs/` in the same commit.
