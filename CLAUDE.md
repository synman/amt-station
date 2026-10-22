# amt-mcp

> Guidance for coding agents working in this repository.

Intel AMT MCP server (MeshCommander parity). Streamable-HTTP, stateless, behind the fleet
admin-token bearer gate; direct TLS to AMT (16993 WS-MAN, 16995 KVM). No MeshCommander, no
web relay, no browser. Currently the seven read tools, `amt_identities` (`amt_identity.py`), `amt_captures` (`amt_captures.py`), the server write tool `amt_device_manage` (`amt_fleet.py`, the device rules `deploy/amt_admin.py` shares), the identity write tool `amt_identity_manage` (`amt_identity.py`; its one-time `PUT /intake/<token>` route is in `amt_upload.py`), the display mirror `amt_mirror_link` (`amt_mirror.py`), the serial terminal `amt_serial_link` (`amt_serial.py`), the two composite write tools `amt_remote_logon` / `amt_remote_logoff` (`amt_tools.py`) and the eight write tools `amt_power`, `amt_set_next_boot`, `amt_console_input`, `amt_sol`, `amt_ider`, `amt_images`, `amt_configure`, `amt_wsman_invoke` (`amt_write.py`) on the gated skeleton. See `README.md` for the map and `docs/mcp-guide.md` / `docs/console-guide.md` for the deep dives; a change to a tool, a route, an env var or a deploy step updates the matching guide in `docs/` in the same commit.

## Guardrails

- **Bearer gate is mandatory.** Every tool call is gated (fully gated mount) in the dispatch
  wrapper (`amt_gate.py`). Refusals are MCP tool errors,
  never HTTP 401/403. Never pass `auth=`/`token_verifier=` to `FastMCP`. Never add a tool
  outside `GatedFastMCP`. Fail closed: unset hash, unknown transport, absent token all refuse.
- **Only the token's SHA-256 is ever configured** (`MCP_ADMIN_TOKEN_HASH`). The raw token is
  never stored, logged, put in env/argv/compose/image, or accepted in plaintext.
- **A second bearer for the management console** (`MCP_CONSOLE_TOKEN_HASH`, same form). Either
  valid bearer runs a call; every gated call is logged as `tool=<name> principal=<fleet|console>`
  (`amt_gate.call_log`), never a token or hash. Unset or malformed console hash: fleet only. The
  fleet hash unresolvable still refuses every token. Never add a principal check to a tool body.
- **One KVM session at a time.** AMT allows one KVM session per host. An IDE-R mount runs
  alongside KVM (verified live 2026-10-18), and a SOL session runs alongside KVM (verified live 2026-10-19: the serial terminal and the display mirror both live). Every open is paired
  with a close; a leaked session blocks the next connect. While `amt_mirror_link` runs, the
  console tools share its session through `amt_tools._kvm_session` instead of opening one.
- **Secrets stay in-process.** The AMT password and any typed host credential are resolved
  via `amt_vault` at call time. No secret is a tool argument, returned value, log line,
  exception text or file. Typed credentials go only through the vaulted-secret path, never
  the plain text-input tool.
- **TLS leaf pinning is enforced, and fails closed.** The chain is unverified, so the full leaf
  SHA-256 recorded per host in `amt_registry.py` is the identity check: WS-MAN verifies it on
  every connection, `amt_screenshot` verifies it in `connect` before the session is used, and
  a device with no pin is refused. Never register a device without its pin.
- **One authenticated WS-MAN attempt per call.** Manual Digest: one unauthenticated request,
  one authenticated request, no retry on a second 401 (repeated failures lock the account out). Never reintroduce urllib's `HTTPDigestAuthHandler`.
- **One logon attempt.** A wrong-password screen (or a Linux `Login incorrect`) stops the
  sequence; accounts can lock out (lockout prevention).
- **Composite tools type only into a POSITIVELY identified screen; anything else aborts
  (fail closed).** They target the Windows interactive sign-in (logon) and desktop (logoff),
  and logon also a Linux text console the FIRST frame shows (getty `login:` prompt only; see the
  console bullet below). Cheap structural pre-filters run first: power is on, geometry is Windows-class (not
  640x480 BIOS/POST), the taskbar detector (`taskbar_present`) agrees (logon aborts on a taskbar
  unless the classifier confirms a `desktop`, logoff on none), blank post-wake. Then OCR (`ocr_fragments`: `ocrmac`, else `tesseract` +
  Pillow) is the REQUIRED proceed gate: logon types only on the vaulted account's centred
  tile with a `Password` field below it and no foreign marker (`login`, GRUB, ...); logoff needs
  OCR to work and no foreign marker or sign-in furniture. A negative check alone is fail-open (a
  Linux console has no taskbar), so never reduce the gate to one. No usable OCR backend, a
  recognizer error, no text or an unrecognized screen all abort with `typed_nothing` and a
  `note`. Results carry the backend name and yes/no findings, never recognized text (the tile
  holds the account name). The first logon frame does not gate the Windows path (lock screen
  precedes the sign-in; the wake sends one click and Esc only), but it IS classified first, so a
  Linux console never receives that Esc. **`classify_screen` is the single
  source of truth for what the console shows** (`windows-signin`, `desktop`, `lock`, `bios-setup`,
  `linux-console`, `grub`, `text-installer`, `mok-manager`, `unknown`). The three boot labels are
  OCR text signatures calibrated on real 800x600 frames (`tests/real_frames/`, both recognizers),
  claimed only when exactly one signature matches and no taskbar is present; UEFI shells and firmware
  boot-device menus stay `unknown` (no real capture of one exists, never a fabricated signature). A
  sub-Windows frame (640x480 BIOS, 800x600 boot software) is now READ, and keeps the geometry label
  `bios-setup` unless a boot signature claims it; that fallback is geometry, not proof, and also
  covers 800x600 frames nothing recognizes (installer progress bars, a busybox shell). The gates
  derive from its label and hold no screen logic of their own (GRUB, the installer and MOK still
  abort both Windows tools: they fail the geometry gate, and the foreign-marker veto is unchanged). A logon on a classifier-confirmed `desktop` returns the no-op success
  `already_logged_in` (nothing typed, nothing cleared); every other non-sign-in context aborts.
  Thresholds and the OCR
  signature are calibrated on real frames (`tests/test_screen_context_real_frames.py`); retune
  only against real captures. The password-field clear is Ctrl+A, Delete, never the
  64-Backspace `clear_field` sweep.
- **Linux console logon (`_console_logon`).** Taken only when the first frame is `linux-console`.
  The last text line decides: getty's `login:` prompt proceeds (Ctrl+U, account name, Enter, then
  the password ONLY after a `Password:` prompt is read); a shell prompt is the `already_logged_in`
  no-op; anything else aborts with nothing sent. Prompts are matched on how the line ends, never
  on the hostname (ocrmac reads its `0` as `ø`, tesseract as `@`); `Last login:` is not a prompt
  and a shell-shaped line never is. Never Ctrl+A/Delete in a tty (Ctrl+A is a literal); never the
  blank check (a real tty is text on black). `Login incorrect` counts only after the last
  `Password:` line, so older text a `--noclear` getty keeps never counts. Logoff on a console
  types `exit` only at a shell prompt. Grounded on real Debian 13 tty1 frames; login and logoff
  live-verified 2026-10-19 (ocrmac) and 2026-10-20 in the NAS container (tesseract 5.3.0, through
  the shared mirror session). Tesseract reads a black console at `--psm 6`; sparse `--psm 11`
  dropped the colon of `login:` on stacked prompts.
- **Serial console logon (`console="serial"` on `amt_remote_logon` / `amt_remote_logoff`).**
  `amt_serial.console_logon` / `console_logoff` feed the serial text's lines to the same
  `console_prompt` / `console_login_incorrect`. Read first; one Enter only when nothing readable
  came back (a `Password:` prompt is never answered: login(1) drops it after 60 s, so an Enter
  into a silent fresh session is the one residual). Shares a live serial terminal, else its own
  SOL session. A parameter, not a tool. This replaced a client-side script that read
  the vault on the Mac and POSTed the password to the control page.
  Live-verified 2026-10-20 (clock read 10:24 EDT just after the run) through the NAS front and a live serial terminal: logon
  (`enter_sent_to_find_prompt: true` on a fresh terminal, then `command_prompt`) and logoff (`login_prompt`).
- **Boot and firmware input (`amt_console_input` `expect`).** `expect` is an optional list of
  classifier labels; when given, the FIRST frame is classified (`classify_screen`, after the session
  opens, before any step) and any other label, or a frame OCR could not read, aborts with
  `screen_not_expected:saw=<label>` / `screen_not_identified:<problem>` having sent no key, click or
  text. Omitted means the unguarded behaviour, byte for byte. `unknown` and an empty list are refused.
  A `secret` step beside any boot/firmware label (`amt_tools.BOOT_FIRMWARE_LABELS`: `bios-setup`,
  `grub`, `text-installer`, `mok-manager`) is refused before the session opens: no credential is ever
  typed into GRUB, BIOS setup, the installer or MOK. This is a parameter, never a new tool (the tool count
  is pinned in `tests/test_conformity.py`). Live-verified 2026-10-20 through the NAS front: `expect=["grub"]` on the
  Debian tty1 login refused with `screen_not_expected:saw=linux-console:expected=grub`. The
  proceed path (a matching label) has not been run live.
- **Identity intake (`amt_identity_manage`, `PUT /intake/<token>`).** The value of a vault entry reaches the vault only through a
  one-time url the tool mints (`amt_upload.intake_offer`: 900 s, 4096 bytes, claimed before the body is judged, outside the
  bearer gate), never as a tool argument. The body goes to `amt_vault.set_secret`, which hands it to the vault CLI on stdin
  (never argv or env) and drops the CLI's output; the entry's notes carry `source: console`, which `amt_identities` reads
  back. An unwritable vault answers 503 and keeps the url. `remove` deletes only a console-sourced entry no server names.
  The intake and upload routes answer CORS for `AMT_CONSOLE_ORIGIN` only. The container's vault mount must be writable
  (`deploy/compose.yaml` mounts it read-write; `amt_admin.py vault sync` leaves the folder 0700 and the files 0600). `vault sync` is merge-aware: it carries every `source: console` entry into
  the rebuilt vault (values in memory and on a child's stdin, never printed), keeps the console's entry when a name is in both
  vaults, and `vault status` reports each entry's source.
- **The management console (`console/`) has no write path into amt-mcp's state.** It mounts none of amt-mcp's vault, devices file or image
  root; every action is a `tools/call` with the console's own bearer, read in-process from the console's own vault (`AMT_CONSOLE_SECRETS_CLI`,
  no default, never the main vault) and never put in env, argv, a log line, an exception or a response. A call without a named `device`
  (tools that take one) or without `confirmed: true` (writes) is refused in `console/mcp_client.py` before it is sent, and its tool table is
  pinned to the live schemas by `console/tests/test_console_mcp_client.py`. Passkeys only; a POST needs the exact `Origin` and the session's
  CSRF token (the one exception is the relayed viewer's live `input` under `/embed/`, authenticated by its embed key; see the KVM and SOL tabs); the console sends `frame-ancestors 'none'` and `X-Frame-Options: DENY` on every response. A one-time handoff url is fetched once by
  the backend, only from amt-mcp's own origin, and never reaches the browser; a viewer, upload or intake url in a tool result is masked in `/api/call`
  replies (`captures.mask_one_time_urls`), so a page that needs one reads it server-side; the same mask is applied to a tool's error text before it is stored or
  sent on the status routes (`error`, `sessions_error` and `devices_error` of `/api/server/<key>` and `/api/fleet`, the captures list's `error`, the power route's `error`,
  and every string the fleet readers keep, such as a session view's own `error` and the `next_boot` fields, through `fleet._str` / `_scalars`;
  `fleet.clip` masks, then cuts, so a token the cut would land inside is withheld whole). Console modules are top-level (`server`, `auth`, ...), so the
  Dockerfile's COPY list must name each (a test checks it).
  **Power & boot (`console/power.py`, `static/power.js`).** What AMT offers is one `amt_wsman_get` of `CIM_AssociatedPowerManagementService` per page open
  or Re-read press (never on a timer, never for a paused server; its 401 pauses the server like any call). The combined boot entries run through
  `POST /api/sequence`: `amt_set_next_boot` then `amt_power` with `power_on` or `hard_reset` only, the power step sent only if the boot step was accepted.
  The sheet kind comes from the one predicate in `components.js` over the call's arguments (a `then` step counts); the page never decides it by button.
  **Console and Serial, the tabs labelled KVM and SOL (`console/embed.py`, `static/embed.js`, `console.js`, `serial.js`).** The viewer's token never reaches the browser, so the mirror and
  terminal pages are RELAYED under `/embed/mirror|serial/<server>/<embed key>/` (the backend's own `status` call finds the control url; only one on `AMT_CONSOLE_VIEWER_ORIGIN`
  is used), not redirected to. Only the embed page's routes are relayed (allowlist pinned to `amt_mirror`/`amt_serial` by a test; `record` is not one of them: it answers 404 here with nothing sent upstream), every upstream request says
  `embed=1`, nothing of the console's cookie, bearer or CSRF token goes upstream, and the token and any one-time url are replaced in text bodies. The route never starts
  a session (a GET that did would be a write with no sheet); Start is a confirmed `tools/call`. **The relayed page runs in an OPAQUE origin** (sprint review B1): the iframe is `sandbox="allow-scripts allow-forms"` (never `allow-same-origin`;
  a test scans the static client for it) and the relayed response carries the same CSP `sandbox` (an Open in a tab copy is opaque too), so it cannot reach the console page's DOM,
  globals or cookie or call `/api`. The SameSite=Strict cookie cannot ride it, so every `/embed/` GET, POST and OPTIONS is authenticated by the per-page-view
  EMBED KEY in the path (`embed.Keys`: `POST /api/embed/key {kind, device}` with cookie and CSRF mints `secrets.token_urlsafe(32)`; kept in memory as a digest, bound to the
  minting session and one (kind, server), compared in constant time against every kept digest, dead at sign-out, session expiry, `KEY_TTL_IDLE` (10 min) unused, or a restart; the
  open page's state poll keeps it alive and its `key_live` reply makes the page mount a fresh frame; a stream already open under the key (MJPEG `stream`, serial `events`) is re-checked every `KEY_RECHECK` (2 s), quiet or busy, and ends at the first no, so sign-out and session expiry cut it too, and an open stream counts as a use of the key). A wrong, expired, revoked or other-server key is a 404 with nothing sent upstream
  and no CORS header; a missing slash is a 404, not a redirect that would repeat the key. Key-authed `/embed/` paths answer CORS (`Access-Control-Allow-Origin: *`, never credentials,
  a preflight for the JSON `input` POST) and no other path does. The key is never in a log line (`loggable()`), `Referer`, error body, upstream request or file (the secrets scans cover it); the
  frame's `src` and Open in a tab are the only places it is written. The embed CSP names the absolute `<origin>/embed/` (an opaque document has no `'self'`). The one POST under `/embed/` is
  `input`, the viewer's own live keyboard and mouse (the one non-tool path): the embed key + an `Origin` of `null` or the console's own, no cookie, no console CSRF token (the viewer's script
  cannot carry it). Record is a tool action, not a relayed route: Start recording / Stop recording sit in the session
  card (`amt_mirror_link` / `amt_serial_link` `record_start` with `confirmed: true` behind a plain sheet, then `record_stop`; greyed with a visible reason when no session is live). Only these responses carry `frame-ancestors 'self'`; every other response still refuses a frame,
  and the shell's `frame-src` is `'self'`. The agent-typing strip sets the frame `inert` from the viewer's `in_flight`; Stop is the hold when an agent started the session
  or a call is in flight. There is no raw `secret` step in the console; a sign-in abort has no retry control. A start or stop through the console re-reads that server's
  session views at once (`Fleet.refresh_sessions`, no WS-MAN).
  **Media and images (`console/images.py`, `static/media.js`).** An image upload goes browser -> console -> amt-mcp, never browser -> amt-mcp: `_tool_call` makes the `amt_images`
  `upload` call itself, `images.Uploads.register` keeps the minted `/uploads/<token>` url in memory (only on amt-mcp's own origin, only a one-time path) and the browser
  gets an opaque `upload_id`; `POST /api/images/upload/<id>` streams the body on in chunks (nothing is stored here) and returns amt-mcp's own answer verbatim. The url and token are
  in no response, header or log line; the id is returned once, in the mint reply, and is in no other response, header or log line (the access log masks it). Everything else on the page is an ordinary `/api/call`. A sheet may carry input fields (`spec.fields`/`spec.build`
  in `components.js`) but only a plain one: a call the predicate calls destructive is never offered from a form. A mount, unmount or status through the console refreshes that server's session
  views at once, and the console records when it made a mount (`host-sessions.json`, key `ider:<device>`) and with which start mode (memory only).
  **Logs and Inventory (`static/logs.js`, `static/inventory.js`).** Plain reads through `/api/call` (`amt_logs`, `amt_inventory`; device named, no `confirmed`), no backend module and no sheet. A page reads when it opens, on its Read / Re-read control, on a log switch and on Newer / Older, never on a timer and never for a paused server (the control is `aria-disabled` with the reason; the page polls only the cached `/api/server/<key>`). The counts line is the result's own fields; a result missing one (or an inventory whose `unavailable` / `truncated` or a requested section is missing) is shown as unreadable, never as zero or "nothing unavailable". The severity filter is on the page only (`amt_logs` has no such argument) and never touches a count. A host's or a tool's text is a text node, never markup (a test bans `innerHTML` in these scripts). Inventory's section-to-class table is pinned to `amt_tools.INVENTORY_CLASSES`.
  **AMT settings (`static/settings.js`).** `amt_settings` reads (area chips: six writable, four dashed read-only) on open, on an area switch and on Re-read, never on a timer and never for a paused server; a result missing its area, sections or coverage lists is unreadable and offers no write. Writes are `amt_configure {device, area, changes, confirmed: true}` through a plain sheet (no `amt_configure` call is in the destructive predicate); `changes` holds only the fields that differ, typed as `amt_write._check_value` takes them, and an input the tool would refuse is stopped before the sheet. The page never says "nothing sent" unless the refusal text proves it (validation codes), and re-reads the area when the host may have changed. Revert writes `previous` back through its own sheet (users have none: the opposite action). Add user needs the vaulted identity `<device>-amt-user-<name>` in `amt_identities`; no password is a field or an argument. The page's tables (fields and kinds, sections, redirection states, risky changes, user-name rule) are pinned to `amt_write` and `amt_tools` by `console/tests/test_console_settings.py`.
  **Advanced (`static/wsman.js`).** The browser is `amt_wsman_get` (a get with its typed selectors, or an enumerate with none; the class field's suggestion list and each class's key names (`CLASS_KEYS`) are pinned to the live-measured `console/tests/data/wsman_class_keys.json`, re-measured with `deploy/wsman_class_probe.py`; picking a class or an enumerated instance fills fields and never reads; read when asked, never on a timer or for a paused server; an enumerate missing `count` / `truncated`, or whose count is not its list, is unreadable). Edit and Put (from a get only) strips every redacted or credential-named field at any depth and names them on the editor and the sheet. The editor mirrors the tool's refusals before anything is sent, with the tool's own codes, and the credential-name rule is `amt_wsman.is_secret_field` (a parity test over a name corpus pins the two); a credential-named field is never placed in a tool call from here. Run is a plain sheet unless the one predicate says otherwise, which is only the method `Unprovision` (the hold); the page has no Unprovision button of its own. `amt_wsman_invoke` reads nothing back, and the copy says so; a reply without a ReturnValue is "unknown". The twelve templates (`TEMPLATES` in the script, rows carrying `data-class` and `data-check-classes`) are each pinned to the design note's list and to the tool's pre-I/O validation; their field names are `[UNVERIFIED]` until a live enumerate of each class is run (a coordinator receipt), and one that does not round-trip is dropped. A `<placeholder>` blocks Run. Platform Erase is unavailable (`no tool yet`).
  **Servers and identities (`static/servers.js`, `static/identities.js`, `console/intake.py`).** Plain tool calls only: no `devices.py`, no `identities.py`, no console-side file or vault code. A pin check is one `amt_devices pin_check`, made only when pressed; a presented leaf that differs greys Edit and Remove (reason as text), keeps Check pin and offers Re-pin (`repin: true`, the hold) only after a check read the presented leaf; the last server's Remove is greyed with the tool's own reason, and amt-mcp's refusals (last server, vault entry missing, expected pin, in use) are shown verbatim. An entered value is relayed, not handed to the browser's own PUT: `_tool_call` makes the `intake` call, `intake.Intakes.register` keeps the `/intake/<token>` url in memory (amt-mcp's origin and a one-time path only) and the browser gets an `intake_id`; `POST /api/identities/intake/<id>` takes the value as plain text, refuses what amt-mcp would refuse before sending (keeping the id), PUTs it once, returns amt-mcp's answer with a one-time url masked and an answer that contains the value withheld. The value, the url and the id are in no log line, response, tool argument or file (a test scans all of them for the scripted value and token, with a deliberately broken route as the positive control). The value field is a `text-security` text input outside any form with no `value` attribute, cleared before the answer. Any accepted `amt_device_manage` or received value re-reads the fleet's device list (`Fleet.refresh_devices`).
  **Phone, accessibility and shortcuts (`static/shortcuts.js`, `console/tests/test_console_verifier.py`).** `test_console_verifier.py` renders EVERY console page at 360/600/1024/1440 in both themes and asserts `FAILS 0` with `design/check_mockups.py`'s own probes and its failure builders `layout_fails`, `contrast_fails` and `state_fails` (shared with the mockup run; never fork them): immutable 1 per page (text floors, 3:1 rings) and the DOM half of 3 (a state attribute paints its state's token; a table row's key is `data-pin-row`, never `data-pin`, which is the chip's), immutable 13 per page (navigation by width, section row, card-per-row tables, bottom sheets), 14, 15 (reduced motion per page, every animated element carries `data-motion`), 18 (every `aria-disabled` control focusable, with a visible reason, ignoring activation), 0 console errors, 0 request off the console's origin, and axe-core 4.11.4 with zero violations. axe is a TEST-ONLY vendored file (`console/tests/vendor/axe-core/`, hash pinned by a test): never serve it from the console, never add it to the Dockerfile, never fetch it; a rule may be turned off only in `AXE_OFF` with a written reason, and never `color-contrast`. A new page is added to `PAGES` there. The shortcuts (`g f`, `g m`, `g c`, `g p`, `/`, `?`) are inert in a field, a select, an iframe, with a modifier and while a sheet is open; Settings holds the switch (`localStorage` `amt-console-shortcuts`, this browser only).
  **Fleet status (`console/fleet.py`).** The backend reads each server (`amt_status` and the three session `status` views, device always named) on a
  staggered schedule that runs only while a page asks; the browser gets the cache. A `wsman_auth_failed_401` (in a read, or in any call through the
  console) or a `tls_leaf_pin_mismatch` (in a read) PAUSES that server: no automatic read at all, until its pin or identity `updated_at` changes (from a value read at the pause) or an operator's
  Retry once succeeds. Never add a path that reads a paused server on a timer. A viewer url or token in a session view is dropped by whitelist.
- **Tools:** every tool declares `title` + `readOnlyHint`; every write tool carries a
  `confirmed: StrictBool = False` guard (only the JSON boolean `true` proceeds; `"true"`/`1` fail schema validation) whose refusal names the consequence. Update
  `amt_parity.py` and `tests/test_conformity.py` `EXPECTED_TOOLS` in the same change.
- **The write path is separate from the read path.** Put/Create/Delete/Invoke live only in
  `amt_wsman_write.py` and are reached only from `amt_write.py`; `amt_wsman.py` keeps its
  `READ_METHODS` allowlist and no read module imports a write module (pinned by
  `tests/test_wsman_write.py`). A credential-named field is never a caller-supplied write value;
  vaulted credentials enter a request in-process only.
- **`amt_power` refuses a state AMT does not offer now** (`AvailableRequestedPowerStates`, read first;
  a boot menu offers only hard reset and NMI) with nothing sent. **`amt_remote_logon` re-reads, sending
  nothing, while the post-wake frame is still the lock screen, and re-reads after Enter until the
  sign-in is gone before judging `logged_in`.**
- **`amt_power` never defaults to a hard reset** (default `restart` is graceful state 14; state
  10 only when `hard_reset` is named; no silent downgrade). **`amt_set_next_boot` accepts only its
  allowlisted targets and never echoes a Get back** (read-only and secret fields are dropped; every boot option
  starts from its safe default each call, and `clear` resets them all). Every write tool is `destructiveHint: true`.
- **Most write tools are mocked-tested only.** Live-verified 2026-10-18: `amt_sol` (open, read,
  close) and `amt_ider` (`next_boot` mount and unmount). 2026-10-19: `amt_sol` reached the
  Debian `serial-getty@ttyS0` login prompt (the AMT SOL UART is the KT at 80:16.3, ttyS0, I/O
  port 0x4020). `amt_sol` sends its text verbatim: Enter is a real newline or carriage-return
  character, and a backslash-r pair reaches a getty as two typed characters. Do not run a write tool against a host
  without the operator's per-action approval; every class/method tagged `TODO verify-live` is
  unverified.
- `amt_ider` mounts images from the image root, which `amt_images` manages: set at runtime with `action=set_root` (persisted
  to `~/.amt-mcp/settings.json`, or `AMT_STATE_DIR`), else the `AMT_IMAGE_ROOT` env; unset is
  refused. `action=list` shows the root, its images, downloads and uploads, `action=fetch` downloads a URL into it in
  the background with an optional SHA-256 check, `verify` hashes one image, `rename`/`delete` change one,
  and `upload` mints a one-time `PUT /uploads/<token>` url (`amt_upload.py`; exact size, optional SHA-256,
  `AMT_UPLOAD_MAX_BYTES` cap). A mounted, downloading or uploading image is never renamed, deleted or overwritten
  (`_busy_reason` matches the mount's open descriptors by inode). A mount holds the host's IDE-R session
  until `unmount`; KVM keeps working beside it. AMT drops an IDE-R session after ~60 s of client silence,
  so the serve loop sends a KEEPALIVEPING (0x44) after `IDER_KEEPALIVE_SECONDS` idle (live-verified).
- `amt_kvm.py` is the proven engine; change it only with a test against the real host. Its
  2026-10-18 changes (`grab_update` incremental updates; an update completes when its last
  rectangle lands) were run live: shared screenshot 1.3 s. The mirror waits for updates in 30 ms
  slices under the socket lock so operator input is not held behind a frame period.
- **Captures (`amt_captures.py`).** `amt_captures` lists the screenshots, finished mirror MP4s and finished serial casts, newest
  first and paged, and `fetch` mints a fresh handoff url for ONE name from that list. It lists only regular files whose name has
  the shape a tool gives its own output in the two folders; a fetch looks the name up in the listing and never joins it onto a
  path, so a traversal or a symlink cannot name a file outside them. Read-only, not idempotent (each fetch mints a url).
- **Download handoffs (`amt_handoff.py`).** Over HTTP with `AMT_PUBLIC_BASE_URL` set, a file a
  tool writes (screenshot, finished mirror MP4, finished serial cast) also returns a one-time `url`
  (`GET /handoffs/<token>`, single fetch, 15-minute TTL). The token is the only key and is minted
  only into a gated result; the route is deliberately outside the bearer gate so a plain GET works.
  Handoffs are hard links, so a fetch never deletes the original. Live-verified 2026-10-20.
- **Behind an nginx reverse proxy** (for example `https://amt.example.com` for MCP and
  `https://amt-viewer.example.com` for the viewer pages, LAN-only names on 443), streams must send
  `X-Accel-Buffering: no` (the serial SSE and the mirror MJPEG both do), or nginx stalls them.
- **Serial terminal (`amt_serial.py`).** One SOL session per device, a reader thread under the
  socket lock (50 ms per read so input is not held), a 256 KiB scrollback and a token-gated xterm.js
  page at `/s/<token>/` on the mirror's server; `_stop_server_if_idle` keeps the server up while
  either a mirror or a terminal is live. View token watches, control token types (POST `input`).
  While a terminal is live, `amt_sol` uses it (`shared_terminal`) instead of opening a second SOL
  session. xterm.js is vendored; never load it from a CDN. Live-verified 2026-10-19.
- **Display mirror (`amt_mirror.py`).** One KVM session per device, a frame thread (one full
  frame, then incremental updates) and a token-gated HTTP viewer (`/m/<token>/`: page, MJPEG
  `stream`, `frame.jpg`, `status.json`, `record`). Every socket call is serialized on the
  mirror's lock (a TLS socket is not thread-safe). A shared session never sends its own
  full-frame request: AMT answers it only after the pending incremental one, which waits for a
  screen change. Two tokens per mirror: the view token never reaches `input`; only the
  control token's page can send keys and pointer events, each batch validated whole before any is sent. AMT ends a KVM session after `SessionTimeout`
  minutes (3 here) with no client input, so an idle mirror sends a no-op Shift_R release every
  `KVM_KEEPALIVE_SECONDS`; any input the agent or page sends resets that clock. The control page can
  mount an ISO only at `start=next_boot` and only one listed under the image root. Recordings encode to H.264 `.mp4` with `ffmpeg` on stop; the raw
  `.mjpeg`/`.times` pair is deleted only after the MP4 is written. The HTTP server never writes to stdout (stdout is the stdio MCP channel).

- **Viewer pages: embed, headers, in-flight, and the tool path.** `?embed=1` on a mirror or serial url
  renders the page without its `standalone` regions (Capture: Record and Screenshot or Download .txt, Media, Power, Boot):
  `amt_mirror.render_page` deletes the regions marked `standalone` from the page source, so nothing in the
  embed page reaches those routes, and a POST to `record`/`ider`/`power`/`boot` carrying `embed=1` is refused
  (403; recording is the tool's `record_start`/`record_stop`). Every viewer response sends `Referrer-Policy: no-referrer` and `Content-Security-Policy:
  frame-ancestors` set from `AMT_CONSOLE_ORIGIN` (unset or malformed: `'none'`; the value is validated, never
  copied raw). `status.json` reports `in_flight` (`{tool, started_at}` or null: name and start time, never
  arguments), set by `amt_tools.InFlight` around a tool call that uses the shared session. The standalone
  page's Power, Boot and ISO routes run the registered `amt_power` / `amt_set_next_boot` / `amt_ider`
  coroutines through `amt_mirror.run_tool`, on the loop `remember_tool_loop` recorded, never an `amt_write`
  function directly, so the session lock and refusals are the tools'.

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
| Fleet admin token | `mcp-admin-token` | Shared bearer; only its SHA-256 reaches this server (`MCP_ADMIN_TOKEN_HASH`) |
| Console token | `amt-console-token` | The management console's bearer, in a console-only vault; only its SHA-256 reaches this server (`MCP_CONSOLE_TOKEN_HASH`) |

## Deployment

Deployment is a separate, operator-authorized step: `deploy/compose.yaml`, with the site values in
`site.vars` (see `deploy/site.vars.example`).
