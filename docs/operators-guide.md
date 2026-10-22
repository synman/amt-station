# Operator's guide

This guide is for the person who runs amt-mcp and its management console after they are installed: adding and changing servers, keeping credentials in step with the AMT hosts, power and boot, the remote screen and serial console, installing an OS, updating the deployment, and fixing what goes wrong. It does not repeat installation. For that, see [install-mcp.md](install-mcp.md) and [install-console.md](install-console.md). For every tool, error and route in detail, see [mcp-guide.md](mcp-guide.md) and [console-guide.md](console-guide.md). The project overview is in [../README.md](../README.md).

Every value here is an example: device key `my-server-1`, AMT addresses `198.51.100.x`, host names `amt.example.com` (the MCP mount), `amt-viewer.example.com` (the viewer pages) and `amt-console.example.com` (the console), user `jdoe`, deploy directory `/srv/amt-mcp`. Replace them with your own.

## Contents

1. [The mental model](#1-the-mental-model)
2. [Daily checks](#2-daily-checks)
3. [Managing servers](#3-managing-servers)
4. [Managing identities (credentials)](#4-managing-identities-credentials)
5. [Power and boot](#5-power-and-boot)
6. [Remote screen (KVM)](#6-remote-screen-kvm)
7. [Serial console (SOL)](#7-serial-console-sol)
8. [Signing in to a host](#8-signing-in-to-a-host)
9. [Installing an OS or booting media](#9-installing-an-os-or-booting-media)
10. [Logs, inventory, AMT settings and Advanced WS-MAN](#10-logs-inventory-amt-settings-and-advanced-ws-man)
11. [Captures: screenshots and recordings](#11-captures-screenshots-and-recordings)
12. [Paused servers](#12-paused-servers)
13. [Deploying an update](#13-deploying-an-update)
14. [Monitoring and logs](#14-monitoring-and-logs)
15. [Backups](#15-backups)
16. [Incident playbook](#16-incident-playbook)
17. [Keeping this guide current](#17-keeping-this-guide-current)

## 0. Conventions used below

**Where things run.** Three places matter:

| Place | What you do there |
|---|---|
| The console (`https://amt-console.example.com`), in a browser | Almost everything: fleet status, power, KVM, SOL, media, logs, settings, servers and identities. Names in **bold** are labels you see in it. |
| Your own machine, with `deploy/amt_admin.py` | The things that need your main vault or the Docker host's shell: add a server with a brand-new credential, `vault sync`, `vault status`, mint a console enrollment code. |
| The Docker host, in the deploy directory `/srv/amt-mcp` | `docker compose`, `docker logs`, file rollbacks, backups. |

**The compose helper.** Every compose command is run from the deploy directory with the same three options. This guide writes them as `dc`:

```bash
cd /srv/amt-mcp
dc() { docker compose --env-file ./site.vars -f src/deploy/compose.yaml --project-directory . "$@"; }
dc ps
```

`site.vars` must exist in that directory. Without it, compose stops with `required variable <NAME> is missing a value: set in site.vars` before it does anything.

**`amt_admin.py`.** Run it from a checkout of the same version that is deployed, with the server's Python dependencies installed (it imports the same rules the server applies). It needs three environment variables, and a command that needs one that is unset stops before touching anything:

```bash
export AMT_SECRETS_CLI=/path/to/node-vault-mcp/services/secrets.py   # your main vault's CLI
export AMT_ADMIN_DEPLOY_DIR=/srv/amt-mcp                              # the deploy directory on the Docker host
export AMT_ADMIN_SSH_ENTRY=docker-host-ssh                            # main-vault entry holding ssh_cmd, user and host
python3 deploy/amt_admin.py device list
```

Its error messages say "NAS" where they mean the Docker host (for example `NAS command failed (rc 255): ...`). That is old wording in the source, not a second machine.

**Times.** The console shows US Eastern time labelled EST or EDT. AMT log filters (**Logs** tab) are UTC, and the container logs use the container's clock.

**"Hold".** A few console actions are destructive enough to need a hold: forced power actions, a next-boot request with `secure_erase`, `reflash_bios` or `configuration_data_reset`, removing a server or identity, re-pinning, deleting an image, mounting with start mode `now`, stopping a mirror or terminal an agent is using, and Unprovision. Press and hold the red control for 1.2 seconds and release, or press Enter and confirm on the second sheet (its button arms 400 ms after you release the key).

## 1. The mental model

- **Two kinds of client, one set of tools.** Agents call the tools over MCP with the fleet bearer. People use the console, which makes the same tool calls with its own bearer. The console holds no AMT state of its own and never mounts amt-mcp's vault, devices file or image folder; every button is a tool call. The pieces that exist only in the console are passkey sign-in, its capture store and the live keyboard and mouse in the viewer frame.
- **Every write needs confirmation.** A write tool does nothing unless called with the JSON boolean `confirmed: true` (the string `"true"` or `1` is refused). The console supplies it after you confirm in a sheet. A refusal reads `confirmation_required: this ... Nothing was done. Re-call with confirmed=true only on the operator's explicit approval.`
- **One KVM session per host.** AMT allows a single KVM (remote screen) session per host. While a **mirror** is running, it owns that session and the other console tools (`amt_screenshot`, `amt_console_input`, `amt_remote_logon`, `amt_remote_logoff`) reuse it, so you watch an agent work. With no mirror running, each of those tools opens the session, acts and closes it. A second client (for example another viewer program) is refused while one session is open. The console cannot take a session over.
- **How the mirror is shared.** The mirror page has a view link (watch only) and a control link (adds **Take control**: your keyboard and mouse then drive the host). When an agent's tool call is using the shared session, the console shows **AGENT TYPING** and freezes your keyboard and mouse until the call returns.
- **One SOL session.** Serial-over-LAN (the text console) is a separate single session. It runs alongside KVM. While a serial **terminal** is running, `amt_sol` (send text and read back) and the serial sign-in share it.
- **IDE-R beside KVM.** Mounting an image over IDE redirection (IDE-R) holds its own session until you unmount, and KVM keeps working alongside it. Whether SOL works beside an IDE-R mount is not established.
- **Calls to one host queue.** Screenshots, console input, sign-in, power, boot, mount, settings writes and the other write calls take a per-host lock inside amt-mcp, so two of them aimed at the same host run one at a time. Plain reads such as `amt_status` do not take it.
- **A stale password costs one attempt, and amt-mcp never retries it.** Each call makes one unauthenticated request and one Digest-authenticated request. A second 401 ends the call with `wsman_auth_failed_401`. AMT can lock the account after repeated failures (the lockout rules are in the AMT firmware, not in this repository), so the whole design avoids a second try.
- **A server pauses after an auth failure.** The console stops reading a server automatically when a call to it is refused for its credential (`wsman_auth_failed_401`) or when its TLS certificate no longer matches the pin (`tls_leaf_pin_mismatch`). It stays paused until the cause is fixed. See [12. Paused servers](#12-paused-servers).
- **Every host is pinned.** AMT hosts use self-signed certificates, so the full SHA-256 of each host's TLS leaf is stored and checked on every connection. An unpinned host, or a different certificate, is refused.
- **Nothing runs unattended.** The console reads the fleet only while someone has a console page open (it stops two intervals after the last request). There is no alerting. The daily check below is the monitoring.

## 2. Daily checks

### 2.1 The fleet page

**When.** Start of day, and after any change or incident.

**Steps.**

1. Open the console **Fleet** page (keyboard shortcut `g f`). The count chip shows the number of servers. The page reads each server in turn, spread over 30 seconds, then refreshes about every 30 seconds while it is open.
2. If the blue banner appears ("N sessions held by you"), someone started a mirror, a terminal or an IDE-R mount from the console. Open it and stop what is not needed.
3. Use **Show: Problems** to list servers that are unreachable, paused, have a pin that differs or is missing, or have their KVM held by another client.
4. For each card, read the power pill, the line under the name, the session chips, the pin chip and any message.
5. Open **Manage ▸ Identities** and check no entry says **missing**.
6. On the Docker host, `dc ps` should show `amt-mcp` and `amt-console` both `running`.

**Success looks like.** Every card has a power pill (not **Unreachable** or **Unknown**), the pin chip says **pin matches**, no card is paused, and `status read N s ago` is under about a minute.

**What each thing on a card means.**

| You see | It means | What to do |
|---|---|---|
| Pill **On**, **Sleep**, **Deep sleep**, **Hibernate**, **Off** | AMT answered and reported that power state. AMT answers on standby power, so **Off** does not mean unreachable. | Nothing. |
| Pill **Reading** with a progress bar | First read after the console or amt-mcp started. | Wait a few seconds. |
| Pill **Unreachable**, red message with an error such as `wsman_unreachable:TimeoutError`, **Retry now**, **Edit server** | The status read failed for a reason other than a refused credential or a changed certificate. Values on the server page are marked stale. A credential that cannot be read from the vault (`vault_miss:<name>`) lands here too. | Read the message. Network or wrong address: check the host, the cable and the address under **Manage**. Vault message: see [4](#4-managing-identities-credentials). The console retries by itself ("Next automatic read in N s"); **Retry now** is an ordinary read. Power actions stay available because AMT may answer when the OS does not. |
| Pill **Unknown**, chip **paused · credential refused** | The AMT rejected the stored password. Automatic reads have stopped. | [12. Paused servers](#12-paused-servers). Do not press **Retry once** until the vault is corrected. |
| Chip **paused · pin differs** | The host presents a different TLS certificate than the stored pin. | [12](#12-paused-servers), and the incident table in [16](#16-incident-playbook). |
| Pin chip **pin matches** | The last read verified the certificate against the pin. | Nothing. |
| Pin chip **pin differs · every call refused** | Same as paused for pin. | As above. |
| Pin chip **unpinned · every call refused** | The server has no stored pin (`tls_leaf_unpinned_refused`). A server added through the tools is always pinned, so this means the devices file was edited by hand. | Re-pin it ([3.4](#34-re-pin-after-a-certificate-change)). |
| Pin chip **pin not checked** | No read has verified it yet (just started, or the host is unreachable). | Wait, or press **Check pin** under **Manage**. |
| Chip **KVM free** (a **SOL** chip appears only when a terminal is held) | No session of that kind is open on the host (as far as amt-mcp and this console know). | Nothing. |
| Chip **KVM · you · mm:ss** / **SOL · you** | You started a mirror or terminal from this console. | Stop it when finished. |
| Chip **KVM · agent via mirror · mm:ss** / **SOL · agent via terminal** | An agent started it through the tools. | Leave it, or ask who is using it. Stopping it ends the session under the agent's call. |
| Chip **KVM · another client · opens refused** | An attempt to open KVM was refused because a session was already open and not amt-mcp's. The chip is based on a refused open the console saw in the last 5 minutes, not on a live probe. | [16](#16-incident-playbook), row "Mirror will not start". |
| Chip **IDE-R mounted** | An image is mounted on that host. | Unmount when the install is done ([9](#9-installing-an-os-or-booting-media)). |

### 2.2 The server page

Click a card name. The **Status** tab shows power, AMT version, provisioning state and mode, redirection (listener, KVM, SOL, IDE-R), user-consent state and the next-boot overrides, from `amt_status`. A class the host does not expose is listed as unavailable, not as an error. **Sessions on this host** shows who holds KVM, SOL and IDE-R. **Take screenshot** and **Past captures** are on the right ([11](#11-captures-screenshots-and-recordings)).

### 2.3 Signing in to the console

The console has no passwords: you sign in with a passkey (Touch ID, a phone or a security key). A session idles out after 12 hours (the sign-in page says "signed out after 12 hours idle"). Add another passkey from **Settings ▸ Passkeys ▸ Add a passkey** while signed in, so one lost device does not lock you out.

If every passkey is lost, mint a one-time enrollment code on your machine and enroll a new one:

```bash
python3 deploy/amt_admin.py console enroll-code
```

Expected output shape: a JSON line, then the code (shown once, only to this terminal; the code below is a placeholder):

```
{"enroll": {"delivered": "/srv/amt-mcp/console-data/enroll.json", "expires": <epoch seconds>, "valid_minutes": 10, "uses": 1}}
enrollment code (shown once): ABCD-EFGH-JKMN
```

Open the console sign-in page, choose **First time here? Enroll a passkey**, enter the code and a passkey name. The code is valid for 10 minutes and one use, and five wrong attempts withdraw it (mint a new one). Anyone who can run this command (the main vault plus ssh to the Docker host) can enroll a passkey, so protect those the way you protect the console.

## 3. Managing servers

A **server** is a key (`my-server-1`), the AMT address, the WS-MAN port (default 16993), the KVM/redirection port (default 16995), the names of up to two vault entries (the AMT admin password; optionally a host logon), and the stored TLS pin. The list lives in `config/devices.json` on the Docker host. Both the console (through `amt_device_manage`) and `amt_admin.py` write it under the same lock, keep the previous file as `config/.prev-devices.json`, and the running server re-reads it when it changes, so a change is live at the next call with no restart.

Quick reference:

| Task | Console | Command line |
|---|---|---|
| List | **Manage** page, or `amt_devices list` | `amt_admin.py device list` |
| Add | **Manage ▸ Add a server** | `amt_admin.py device add KEY --ip IP --amt-vault-key NAME [--host-vault-key NAME] [--wsman-port N] [--kvm-port N] [--pin SHA256]` |
| Edit | **Manage ▸ Edit** | `amt_admin.py device edit KEY [--ip IP] [--amt-vault-key NAME] [--host-vault-key NAME \| --no-host] [--wsman-port N] [--kvm-port N] [--repin]` |
| Check the pin | **Manage ▸ Check pin** | `amt_admin.py device pin KEY` |
| Re-pin | **Check pin**, then **Re-pin** (hold) | `amt_admin.py device edit KEY --repin` |
| Remove | **Manage ▸ Remove** (hold) | `amt_admin.py device remove KEY` |

### 3.1 Add a server

**When.** A new AMT host should be managed.

**Before you start.**

- The host's AMT must be provisioned with TLS enabled on 16993 and 16995, and the address must be reachable from amt-mcp's Docker host and from your machine. Preparing the host is in [install-mcp.md](install-mcp.md).
- The server needs a key: lowercase letters, digits and dashes, up to 63 characters (`my-server-2`). The address must be an IP address, never a host name (the pin is per address).
- Its **AMT admin password must already be in a vault** that amt-mcp can read (section 4.1). The entry is normally named `<key>-amt` (`my-server-2-amt`); a host logon, if you want host sign-in, is `<key>-os` holding `{"user": "...", "password": "..."}`.

**Steps (command line, the path that works on a stock deployment).**

1. Store the admin password in your main vault in your own terminal, as `my-server-2-amt` (use your vault's own instructions; never type it in a chat, ticket or shell argument).
2. Add the server:

   ```bash
   python3 deploy/amt_admin.py device add my-server-2 --ip 198.51.100.27 --amt-vault-key my-server-2-amt --host-vault-key my-server-2-os
   ```

   Add `--pin <64 hex>` if you already know the certificate fingerprint; the add then refuses any other certificate.
3. The command connects to the host's WS-MAN port (one TLS handshake, no credential), records the certificate it presents, rewrites the devices file, then copies the needed vault entries to the container's vault (`vault sync`).

**Success looks like.** Two JSON lines and exit status 0:

```
{"devices": ["my-server-1", "my-server-2"], "device": {"key": "my-server-2", "amt_ip": "198.51.100.27", "wsman_port": 16993, "kvm_port": 16995, "amt_vault_key": "my-server-2-amt", "host_vault_key": "my-server-2-os", "tls_leaf_sha256": "<64 hex>", "tls_leaf_observed_prefix": "<16 hex>"}}
{"vault": {"my-server-2-amt": {"source": "main", "on_nas": true, "matches": true}, ...}}
```

Then open the **Fleet** page: the new card reads and shows **pin matches**. Compare the printed fingerprint with an independent reading (3.2).

**What can go wrong.**

| Message | Meaning |
|---|---|
| `device my-server-2 exists; edit it instead` | The key is taken. |
| `vault my-server-2-amt in the main vault or the console's identities first` | The entry is not in the main vault (or a console-entered entry). Store it, then repeat. |
| `198.51.100.27:16993 presents leaf <hex>, not the given pin; nothing written` | You gave `--pin` and the host presents something else. Do not proceed until you know why. |
| a connection error from the handshake | Address, port or network. Nothing was written. |
| `devices.json changed since it was read, run the command again` (exit 3) | The console edited the file between your read and your write. Run it again. |
| `vault entry docker-host-ssh missing`, or `NAS command failed (rc N): ...` | The ssh entry named by `AMT_ADMIN_SSH_ENTRY` is missing, or the ssh step failed. |

**Adding from the console.** **Manage ▸ Add a server** takes the same fields and shows the sheet **Add the server my-server-2**. It works only when the identities it names already exist in amt-mcp's own vault, for example a second server that shares an existing entry (choose **use existing · ...** in the dropdown), or an entry you synced earlier. It refuses with `vault <name> in this server's vault (...) first` otherwise. A brand-new credential cannot be entered through the console first, because **the console's value entry only mints a one-time URL for an entry some server already names** (see 4.2). So for a server with a new password, use the command-line path above.

### 3.2 TOFU pinning, and comparing the fingerprint

"Trust on first use" means the pin is whatever certificate answered at the moment of the add. If something other than your host answered, you have pinned the wrong party. So after every add, and before every re-pin, compare the fingerprint with an independent reading of the host's certificate:

- The console's add form says to compare with what **MEBx** shows. This guide could not confirm that every firmware shows a certificate fingerprint in MEBx; if yours does not, use the next method.
- From a second machine on the same LAN, read the certificate and convert it to the form amt-mcp stores (lowercase hex, no colons). The pin is the SHA-256 of the certificate's DER encoding:

  ```bash
  openssl s_client -connect 198.51.100.27:16993 </dev/null 2>/dev/null \
    | openssl x509 -noout -fingerprint -sha256 | sed 's/.*=//; s/://g' | tr 'A-F' 'a-f'
  ```

  Expected: one line of 64 lowercase hex characters, equal to `tls_leaf_sha256` in `device list`. (The `x509 | sed | tr` half was checked against a local certificate; the `s_client` half was not run against an AMT host.)

`amt_admin.py device pin KEY` and the **Check pin** button are one TLS handshake with no credential. They print the certificate the host presents now beside the stored pin, and exit 1 / show a warning when they differ:

```
{"device": "my-server-1", "presented": "<64 hex>", "stored": "<64 hex>", "matches": true}
```

### 3.3 Edit a server's address, ports or identity names

**When.** The host moved to a new address, or you renamed its vault entries.

**Steps.** **Manage ▸ Edit** (fields: AMT address, WS-MAN port, KVM port, AMT identity, host logon identity; change at least one), or `amt_admin.py device edit my-server-1 --ip 198.51.100.40`.

If the address or WS-MAN port changes, the certificate is read again. A different certificate than the stored pin is refused: `198.51.100.40:16993 presents leaf <hex>, not the stored pin; pass repin to accept it; nothing written`. If the host kept its certificate (same machine, new address), the edit succeeds and the pin is unchanged. If it did not, find out why before re-pinning (3.4).

**Success looks like.** The sheet result says `saved · now 198.51.100.40 · ports 16993 / 16995 · live at the next tool call`; the Fleet card reads the host at its new address.

An edit that renames a vault entry needs the new entry to exist already: in the main vault for the command line, in amt-mcp's own vault for the console. From the command line the `vault sync` that follows drops the old entry from the container's vault when no server names it any more; from the console the old entry stays until you remove it.

### 3.4 Re-pin after a certificate change

**When.** The Fleet card says **paused · pin differs**, or a call fails with `tls_leaf_pin_mismatch`, and you have confirmed the change is legitimate (the host's AMT was re-provisioned, its TLS configuration was changed, or its certificate was regenerated).

**Steps.**

1. **Manage**: the row for the server shows **pin differs**. **Edit** and **Remove** are greyed ("re-pin first").
2. Press **Check pin**. The result shows the certificate presented now and the stored pin.
3. Compare the presented value with an independent reading (3.2).
4. Press **Re-pin**, read the sheet (it shows both values), then hold to confirm. Or `amt_admin.py device edit my-server-1 --repin`.

**Success looks like.** `the stored pin is now <value> · every call to it is allowed again`. If the new value is not the one you compared at the check, the console warns that the certificate changed between the check and the re-pin; compare again. The server resumes by itself.

**If you cannot explain the change, do not re-pin.** A changed certificate is either a re-provisioned AMT or another machine holding the address. Treat the second as an incident ([16](#16-incident-playbook)).

### 3.5 Remove a server

**Steps.** **Manage ▸ Remove** (hold) or `amt_admin.py device remove my-server-2`.

**Rules.**

- The last server cannot be removed (`refusing to remove the last device; the server would have nothing to serve`). The console greys **Remove** with that reason. Add the replacement first.
- Removing a server does not touch its vault entries when done from the console: they stay until you remove them (4.5). The command-line `device remove` runs `vault sync` afterwards, which rebuilds the container's vault from the entries the remaining servers name, so that server's copied entries drop out of the container's vault (entries you entered through the console are kept). Entries in your main vault are never touched.
- Every later tool call that names the removed server fails with `unknown_device:<key>`. End any mirror, terminal or mount on it before you remove it.

### 3.6 The devices file and its rollback

`config/devices.json` is `{"version": 1, "devices": {key: {...}}}`. Do not edit it by hand. Before each change amt-mcp or `amt_admin.py` copies the previous file to `config/.prev-devices.json`. That is one generation deep: the next change overwrites it, so restore before you change anything else.

To roll back the last change, on the Docker host:

```bash
cd /srv/amt-mcp/config
flock .devices.lock sh -c 'cp .prev-devices.json .devices.json.new && mv -f .devices.json.new devices.json'
```

The server re-reads the file at its next call. A restored file brings the old pins and entry names with it; if it names an entry that is not in the container's vault, run `amt_admin.py vault sync` afterwards. If the file is unreadable or malformed, every tool fails with `devices_file_unusable:<ErrorType>` (it never falls back to the built-in example registry), which is the signal to restore the previous file. This rollback command was read from the code's own write procedure, not run.

## 4. Managing identities (credentials)

An **identity** is a vault entry that a server uses. The container reads from its **own dedicated vault** (`vault/amt-mcp.vault` plus `vault/amt-mcp.key`), not from your main vault. Entries get into it by two routes, and every tool only ever shows names and status, never a value.

| Entry name | Used for | Read by |
|---|---|---|
| `my-server-1-amt` (the server's `amt_vault_key`) | The AMT `admin` password. Used by every call to the server. | All tools |
| `my-server-1-os` (the server's `host_vault_key`, optional) | Host logon, as one line of JSON `{"user": "jdoe", "password": "..."}` | Host sign-in, `secret` steps |
| `my-server-1-amt-rfb` | The KVM (RFB) password written into AMT's KVM settings | `amt_configure` area `kvm` |
| `my-server-1-amt-user-<name>` | The password of an AMT user you add | `amt_configure` area `users`, action `add` |

### 4.1 Route A: main vault and `vault sync` (works on a stock deployment)

**When.** First credential for a new server, rotation, or any time `Replace stored value` is unavailable.

**Steps.**

1. In your own terminal, store or replace the value in the main vault under the entry name (never in a chat, a ticket or a command argument you would be unhappy to see in a process list).
2. Copy it to the container:

   ```bash
   python3 deploy/amt_admin.py vault sync
   ```

   It builds a fresh vault in a private temporary directory, streams it over ssh, renames each file over the old one (the container sees the new files without a restart), and keeps the old pair as `.prev-amt-mcp.vault` and `.prev-amt-mcp.key`. It prints the status JSON and exits 0 only if every main entry matches.
3. Check:

   ```bash
   python3 deploy/amt_admin.py vault keys      # {"keys": ["my-server-1-amt", "my-server-1-os", ...]}
   python3 deploy/amt_admin.py vault status
   ```

   `vault status` sends the SHA-256 of each main-vault value over ssh stdin and the container answers yes or no; no value is printed:

   ```
   {"my-server-1-amt": {"source": "main", "on_nas": true, "matches": true}, "my-server-1-os": {"source": "main", "on_nas": true, "matches": true}, "extra": {}}
   ```

   `on_nas` means "present in the container's vault". `matches` is true when the container's value equals the main vault's. An entry entered through the console reports `"source": "console", "matches": null` and only has to be present. `extra` lists container entries no server names. Exit status 1 means some main entry is missing or differs.

`vault keys` lists the entries the registered servers need that exist in the main vault or were entered through the console: each server's `amt_vault_key`, `host_vault_key`, `<amt_vault_key>-rfb` and `<key>-amt-user-*`. A main-vault entry that no server names is not copied, and a sync drops it from the container's vault. Entries entered through the console are carried over by every sync whether or not a server names them.

**Sync when no intake is open.** An intake that lands between the sync's read and its rename is lost.

### 4.2 Route B: the console's value entry

**What it is.** **Manage ▸ Identities** lists every entry with its kind, owner, whether it is present, whether it was **synced** or **entered here**, and when it was updated. **Replace stored value** (or **Enter** for a missing entry, or **New identity**) mints a one-time URL in amt-mcp (15 minutes, one use, at most 4096 bytes). You type the value into the field once; the console relays it to that URL and clears the field before the answer arrives. The value is never shown again, never a tool argument, and not kept by the console. The entry's source becomes `console`.

**Two limits you will hit.**

1. **It needs a vault the container can write.** The shipped `deploy/compose.yaml` mounts `vault/` read-write and `vault sync` leaves it 0700 with 0600 files. A vault last synced by an older version (0500 and 0400) answers `503 vault_not_writable: nothing was stored` until you run `vault sync` again or `chmod 700 vault; chmod 600 vault/amt-mcp.*` as the deploy user.
2. **It only mints for an entry that a registered server already names**, `<amt_vault_key>-rfb`, or `<device>-amt-user-<name>` for a registered device. You cannot use it to create the first credential for a server you have not added.

**Success looks like.** `received · my-server-1-amt present · updated <time> · the field was cleared`, followed by an `amt_status` read that "succeeded N s after the value arrived". A refused one-time URL is used up: mint a new one.

### 4.3 Rotating the AMT admin password

**There is no tool that sets the AMT admin password**, and none may take a password as an argument. Verified in the source: `amt_configure` area `users` refuses the admin account (`users_username_invalid_or_admin: the admin account is never changed here`), `amt_wsman_invoke` refuses credential-named fields at any depth, and storing a value (`amt_identity_manage intake`, `vault sync`) only changes the vault, never the host (the tool's own consequence text says: "this does NOT change the password on the AMT"). The console page has a disabled **Change the AMT admin password** control that says "no tool: change it in MEBx".

**Steps.**

1. Change the password on the host itself: MEBx at the machine, or another AMT client you trust.
2. Immediately store the new value in the vault so it matches: Route A (main vault, then `vault sync`) or Route B (**Replace stored value**).
3. Confirm: `vault status` shows `matches: true`, and the Fleet card reads without a pause.

**The gap between steps 1 and 2 is the risk.** Until the vault and the host agree, every call to that server fails after one Digest attempt, and the console pauses the server. Do step 2 right after step 1, and do not poll or retry in between. Do the reverse order (vault first) and the same applies in the other direction: the vault then holds a password the host does not accept.

If a server pauses after a rotation, see [12](#12-paused-servers).

### 4.4 Host logon, KVM and AMT-user entries

- Host logon (`<key>-os`): one line of JSON with `user` and `password`. A wrong shape fails with `vault_bad_credential_shape:<name>`. Used by [8. Signing in to a host](#8-signing-in-to-a-host).
- `<amt_vault_key>-rfb` and `<key>-amt-user-<name>` are read by **AMT settings** writes ([10](#10-logs-inventory-amt-settings-and-advanced-ws-man)). An AMT user name is 1 to 16 characters (letters, digits and `_ . @ -`).

### 4.5 Removing an entry

- Console-entered entry that no server names: **Manage ▸ Identities ▸ Remove** (hold). The tool refuses an entry a server still names (`identity_in_use:<name>: named by my-server-1.amt_vault_key`) and an entry copied from the main vault (`identity_not_console_entry:<name>`).
- Main-vault entry: remove it from the main vault; the next `vault sync` drops it from the container's vault if no server names it.
- Removal cannot be undone from the console. Restoring needs a vault backup ([15](#15-backups)).

## 5. Power and boot

Open the server's **Power & boot** tab (shortcut `g p` from the server page).

**What AMT offers right now.** The banner at the top of the tab shows the power states the host will accept at this moment (read from `AvailableRequestedPowerStates`, once per page open or **Re-read**, never on a timer). Buttons for states AMT does not offer are greyed with "not offered by AMT right now". If you call `amt_power` with a state AMT does not offer, it refuses before sending anything: `power_state_not_available: AMT does not offer <action> now; it offers <list>. Nothing was sent.` At a boot menu or under an OS without the AMT agent, only the hard actions are offered.

**Graceful actions** ask the host's OS and do nothing if its AMT agent does not answer. They never fall back to a harder action.

| Button (tool action) | Effect |
|---|---|
| **Restart** (`restart`) | Graceful OS restart (power state 14). The default. |
| **Shut down** (`shutdown`) | Graceful OS shutdown (12); stays off until powered on. |
| **Power cycle** (`power_cycle`) | Graceful shutdown, then AMT powers it back on (15). |
| **Shut down, hard-graceful**, **Power cycle, hard-graceful** (`shutdown_hard_graceful`, `power_cycle_hard_graceful`) | Graceful to a hard-off state (13, 16). |
| **Power on** (`power_on`), **Sleep (light/deep)**, **Hibernate** | Other states (2, 3/4, 7). Wake a sleeping host with **Power on**. |

**Force** (the **Force** tray; each needs a hold): `hard_reset`, `hard_power_off`, `hard_power_cycle`, `immediate_shutdown`, `immediate_power_cycle`, `nmi`. The OS is not asked, so unsaved work is lost and a filesystem may need recovery. `hard_reset` is sent only when named; nothing defaults to it. `nmi` raises a non-maskable interrupt, which on most hosts crashes the kernel for a dump.

**Success looks like.** The result row shows the requested state, `applied: true` when the device's `ReturnValue` is 0, and a best-effort power state read afterwards (AMT applies the change asynchronously, so the readback can still show the old state). If the reply has no `ReturnValue`, the result says the request was sent and the outcome is unknown: check the host before sending again, because a retry can repeat the action.

### 5.1 Next boot (one time)

**Next boot (one time)** sets where the host boots **once**, at its next start or reset from any cause. It does not restart the host. Targets (the only seven accepted): `clear` (cancel a pending request), `bios_setup`, `pxe`, `hard_disk`, `cd_ider` (the mounted IDE-R ISO), `floppy_ider`, `diagnostic`. USB and arbitrary targets are refused.

- Every boot option starts from its safe default on each call; only what you tick applies. `clear` resets them all and sends no activation.
- Advanced options: 14 checkboxes (`lock_power_button`, `lock_reset_button`, `lock_sleep_button`, `lock_keyboard`, `user_password_bypass`, `forced_progress_events`, `configuration_data_reset`, `bios_pause`, `reflash_bios`, `use_safe_mode`, `use_sol`, `use_ider`, `secure_erase`, `enforce_secure_boot`) and two numbers (`firmware_verbosity` 0-3, `boot_media_index` 0-255). `secure_erase`, `reflash_bios` and `configuration_data_reset` are marked red and make the request destructive: the sheet becomes a hold. The tool's own description also names `lock_power_button` and `lock_reset_button` as options that act at that boot, but the console does not mark them red.
- The chip **AMT reports: ...** shows the BIOS-setup and IDE-R flags only. A PXE or disk request lives in the boot order, which that read does not show.

### 5.2 Combined entries and getting into BIOS setup

The three buttons under the next-boot form run two calls in order and send the second only if the first was accepted:

| Button | Calls |
|---|---|
| **Set next boot only** | `amt_set_next_boot` |
| **Power on → <target>** | `amt_set_next_boot`, then `amt_power power_on` (greyed with "host is already on" while the host is on) |
| **Reset → <target>** | `amt_set_next_boot`, then `amt_power hard_reset` (a hard reset: the OS is not asked, so this is a hold) |

**To enter BIOS setup on a running host without a hard reset:** choose **bios_setup**, press **Set next boot only**, then use graceful **Restart**. To enter it from off: choose **bios_setup** and press **Power on → BIOS setup**. Then open the **KVM** tab and watch it come up ([6](#6-remote-screen-kvm)). Clear the request afterwards with **normal boot (clear a pending request)** if the host did not consume it.

**What can go wrong.** `boot_readback_mismatch:<fields>:completed=<steps>` means the sequence was interrupted or AMT did not accept a field; the message names the steps that completed. Read the next-boot state on the **Status** tab and try again once.

## 6. Remote screen (KVM)

### 6.1 Start a mirror

**When.** You want to see or drive the host's screen.

**From the console.** Open the **KVM** tab and press **Start mirror**. The console starts every mirror itself with bind `0.0.0.0`, port 8766, 15 frames per second and JPEG quality 70, and shows the control page framed on the tab. If the host requires user consent, it shows a code on its own screen first: the **KVM** tab says "User consent is required on this host" and points to **Advanced ▸ Send a consent code** (enter it within 2 minutes; a wrong code counts against the attempts AMT allows).

**From an agent.** `amt_mirror_link` with `action: "start"`, `bind: "0.0.0.0"`, `port: 8766`, `confirmed: true`. The result lists `urls` (view only) and `control_urls` (adds **Take control**), the public viewer front first, for example `https://amt-viewer.example.com/m/<token>/`. **Pass `bind: "0.0.0.0"`.** The tool's default bind is `127.0.0.1`, which inside the container has no public address; the console then shows the session as "Held by an agent · not reachable from here" and will not frame it. The viewer server is shared between the mirror and the serial terminal, so a start on a different bind or port while one is live fails with `viewer_server_in_use: pages are live at <bind>:<port>; use that bind and port, or stop the live mirrors and terminals first`.

The tokens in those URLs are the only access key. Share a view URL only with people who may watch, and a control URL only with whoever may drive the host.

**Success looks like.** The **This KVM session** card shows **KVM · you · mm:ss**, resolution, frames per second, viewers and `last frame N s ago`. The mirror writes a new frame only when the screen changes, so a growing "last frame" age on a quiet screen is normal.

### 6.2 View, control, macros, text

- **View only** links never send input. **Take control** (on the control page) sends your keyboard and mouse to the host. That live input is the one path that is not a tool call.
- **Key macros and text** (below the screen) send one `amt_console_input` call: Ctrl+Alt+Del (the firmware sequence), the Windows key combinations, Alt-Tab, Alt-F4, function keys and more. **Act only when the screen is:** is a guard. Choose `desktop`, `windows-signin`, `linux-console`, `bios-setup`, `grub`, `text-installer` or `mok-manager` and the first frame is classified first; if the screen is anything else, nothing is sent and the result says `screen_not_expected:saw=<label>:expected=<label>` (or `screen_not_identified:<problem>`). With **any (no guard)**, the keys go to whatever is on screen.
- **Type text** sends up to 500 printable ASCII characters. Never type a credential here: use [host sign-in](#8-signing-in-to-a-host). A credential step is refused beside any boot or firmware screen guard.
- A call takes at most 50 steps, paced for AMT (it drops input that arrives faster than it can inject it).

### 6.3 Sharing the screen with agents

While a mirror runs, an agent's `amt_screenshot`, `amt_console_input` and sign-in calls use the mirror's session. The viewer's `status.json` reports `in_flight` (the tool name and start time of a call using the session, never its arguments). In the console that shows as the **AGENT TYPING** strip: your keys and mouse are paused until the call returns.

Stopping a mirror that an agent started, or while a call is in flight, takes a hold, because it ends the session under the agent's call and a sign-in can be left half-typed. Stop only if you know the agent is done.

### 6.4 The three-minute timeout and keepalive

AMT ends a KVM session when the client has sent no keyboard or mouse event for the KVM `SessionTimeout`. On the host this was measured on, that was 3 minutes (check yours in **AMT settings ▸ kvm**). A running mirror therefore sends a harmless no-op key release (Shift_R) every 60 seconds when you are idle; any input you or an agent sends resets that clock. Short tool calls that open their own session are not affected.

### 6.5 Record, screenshot, stop

- **Start recording** / **Stop recording** are on the session card (or `amt_mirror_link` `record_start` / `record_stop`). Everything on the screen, including what others type, is in the recording. On stop the raw frames are encoded to an H.264 `.mp4` in the background (this needs `ffmpeg`, which the image includes) and the raw pair is deleted only after the MP4 is written. The finished file appears under **Recordings** on the tab; **Refresh** it. A recording that is still encoding is not listed. If you update or restart amt-mcp during the encode, only the raw files remain.
- **Take screenshot** (Status tab, or **Shot** on the Fleet card) opens the KVM session for a moment (or shares your mirror's), captures a PNG, closes it, and sends no input. Where user consent is required it may show a consent prompt on the host.
- **Stop mirror** releases the session. Viewers lose the picture; a running recording is finished first.

### 6.6 "Another client holds the session"

AMT allows one KVM session. If amt-mcp's open is refused, the failure reads like `redir_start_status_N` (a non-zero start status; which number a busy host sends has not been read live) or "another session is open". The console shows **KVM · another client · opens refused** and the tab says "Another client holds this host's KVM session". This refusal comes from AMT's start reply, before any credential is sent, so retrying later does not risk a lockout.

1. Open the Fleet card. If the chip says **you** or **agent**, the session is amt-mcp's own: stop it from the **KVM** tab or ask the agent's owner.
2. Otherwise another program (a different management tool, a viewer left open) holds it. Close that program. If you cannot find it, wait for AMT to end an idle session after its `SessionTimeout`.
3. The console cannot take the session over. Only if amt-mcp itself still holds an orphaned session (`amt_mirror_link status` shows `live: false` but opens keep failing) is restarting `amt-mcp` a last resort, because it releases everything amt-mcp holds.

## 7. Serial console (SOL)

**When.** You want the host's text console (a Linux login on the serial port, GRUB, the kernel console) rather than its screen.

**Requirements on the host.** All three must be true, or the terminal shows nothing:

1. The serial port must be enabled in the BIOS.
2. SOL must be enabled in AMT: **AMT settings ▸ features** `sol_enabled` (the **Redirection** card on the Status tab shows SOL on or off).
3. Something on the host must talk on the AMT SOL serial port: a getty (for example `serial-getty@ttyS0` on Debian), or GRUB and the kernel console pointed at that port. On the Debian host this was verified on, the AMT SOL port was `ttyS0`; the port name depends on the board, so confirm it on your host.

**Steps.**

1. Open the **SOL** tab and press **Start terminal** (bind `0.0.0.0`, port 8766, shared with the mirror). Agents use `amt_serial_link` with `bind: "0.0.0.0"` for the same reason as in 6.1.
2. The terminal page shows the scrollback, then the live stream. **Take control** on the control page types into the host.
3. **Send a line** sends text through `amt_sol` (it asks confirmation even to read; **append Enter** adds a real newline; it reads for 3 seconds and shows up to 4 KiB). While a terminal is running it goes through the terminal's session, so the viewer shows it. Never send a credential: use [host sign-in on SOL](#8-signing-in-to-a-host).
4. **Start recording** / **Stop recording** write an asciinema v2 `.cast` file. On stop the console fetches the finished file once into its capture store so you can **Save** it.
5. **Stop terminal** releases the session. The page keeps what it printed.

Limits: a line is up to 1024 characters (`sol_text_must_be_ascii_up_to_1024_chars`; the console form stops at 1023 plus the Enter), ASCII only. A backslash followed by `r` or `n` is sent as those two characters, which a Linux getty takes as typed text.

**What can go wrong.** A blank terminal on a running host: check the three requirements above, then press Enter in the terminal (a getty prints its login prompt on a new line). SOL open fails with `auth_failed_status_N` or `auth_rejected_no_retry` when the AMT password is wrong: that is the paused case ([12](#12-paused-servers)).

## 8. Signing in to a host

**When.** The host is at a login prompt and you want amt-mcp to log it in with the vaulted host credential, once.

**Requirements.** The server has a `host_vault_key` entry holding `{"user": "...", "password": "..."}` (4.4). The host is powered on. For the KVM path the amt-mcp container needs an OCR engine (the image includes `tesseract`); for the serial path the host needs a getty on the SOL port.

**Steps.**

- KVM: **KVM** tab ▸ **Host sign-in ▸ Sign in to host** (the matching **Sign out** logs the user out). Agents call `amt_remote_logon` / `amt_remote_logoff` with `console: "kvm"`.
- Serial: **SOL** tab ▸ **Host sign-in on SOL ▸ Sign in (SOL)** / **Sign out (SOL)**, or the tools with `console: "serial"`.

**What it does.** It reads the screen (or the serial text) first. It types the credential only into a screen it positively identifies as a Windows sign-in (the vaulted account's tile with a **Password** field) or a Linux text login (getty's `login:` prompt; the password only after a `Password:` prompt has been read). A Linux shell prompt or a Windows desktop is the goal already met: `already_logged_in`, nothing typed. Anything else aborts with nothing typed. On serial it reads first, and sends one Enter only when nothing readable came back, and never at a `Password:` prompt. **It makes exactly one attempt and never retries**: a wrong password (`Login incorrect`) is reported as `logged_in: false`, because repeated wrong passwords can lock a host account.

**Success looks like.** `name and password typed once · logged_in: true` (or `already signed in: nothing was typed`).

### 8.1 Reading an abort

An abort result has `aborted: true`, a `reason`, `typed_nothing`, usually a `note`, and (KVM) a screenshot showing what the tool refused to type into. The console shows it as `aborted: <reason> · typed nothing · <note> · not retried: look at the console and try again yourself`. There is no retry button by design.

| `reason` | Meaning | Do |
|---|---|---|
| `host_not_powered_on` | AMT reports the host is not on. | Power it on, wait for the login screen. |
| `ocr_unavailable`, `ocr_failed`, `ocr_no_text` | No OCR engine, the engine failed, or it read no text. The screen could not be identified. | Check the container has `tesseract`; look at the screenshot; try again. |
| `not_windows_resolution`, `screen_unreadable`, `screen_blank` | The screen is a sub-Windows resolution (BIOS/boot software), unreadable, or blank. | Wake the screen or wait for the OS, then try again. |
| `no_desktop_taskbar`, `desktop_not_identified` (logoff) | Logoff needs a logged-in desktop and did not find one. | Look at the screen first. |
| `host_already_logged_in`, `signin_screen_detected` | A taskbar is showing where a sign-in was expected, or sign-in furniture where a desktop was expected. | Look at the screen. |
| `signin_not_identified` | Not the Windows sign-in for the vaulted account (no tile with a Password field below it). | Check the vaulted `user` matches the account tile as spelled, without a `DOMAIN\` prefix. |
| `foreign_console_detected` | A login prompt, boot loader, firmware or Linux console where Windows sign-in was expected. | Look at the screen. |
| `console_not_at_login_prompt` | The Linux console's last line is not a fresh getty `login:` prompt (a `Password:` prompt someone else started, or other text). | Clear the console yourself, then try again. |
| `password_prompt_not_identified` | The account name was typed but no `Password:` prompt followed; the password was **not** typed. | The console is now at a half-entered login. Look, then press Enter or Ctrl+U yourself. |
| `console_not_at_shell_prompt` (logoff) | Not at a shell prompt; typing `exit` would land elsewhere. | Look at the console. |
| `run_dialog_not_detected` (logoff) | The Run dialog (Win+R) did not appear. | Look at the screen; close any dialog. |

## 9. Installing an OS or booting media

Boot media (an ISO or a floppy image) is served from the **image library** on the Docker host (`iso/`, which the container sees as `/iso`) and mounted on the host over IDE-R. Everything about the library is on the **Images** page (**Images** in the navigation) and on each server's **Media** tab.

### 9.1 The image library

| Task | Console (**Images**, or **Media** tab) | Tool (`amt_images`) |
|---|---|---|
| See the library | opens with the page; **Re-read** | `list` (also shows downloads and uploads) |
| Set the image root | **Change root** | `set_root` (persisted in `data/state/settings.json`, used ahead of the `AMT_IMAGE_ROOT` environment value) |
| Download from a URL | **Fetch a URL** (optional SHA-256) | `fetch` (starts a background download; poll `list`) |
| Upload from your computer | **Upload a file** | `upload` (mints a one-time URL; the file never passes through MCP) |
| Check a file's hash | **Verify** | `verify` (SHA-256 of one image) |
| Rename / delete | **Rename**, **Delete** (hold) | `rename`, `delete` |

Rules:

- Images must be `.iso` or `.img`, a **multiple of 512 bytes** (**512-aligned**), plain names (no directory, no leading dot). Anything else is shown as **not 512-aligned · cannot be mounted** or refused by name.
- An image that is **mounted, downloading or uploading** is never renamed, deleted or overwritten (`ider_<action>_image_busy:<name>:mounted_on:<server>` / `being_downloaded` / `being_uploaded`).
- `fetch` runs in the amt-mcp container, so the container must be able to reach the URL. A wrong hash fails the download (`sha256_mismatch:got <hash>`) and removes the partial file. An existing name needs `overwrite`.
- `upload`: the URL lives 15 minutes and works once. The file must be exactly the declared size (`body_shorter_than_declared_size` / `body_larger_than_declared_size`), match the SHA-256 if one was given (`sha256_mismatch`), fit under `AMT_UPLOAD_MAX_BYTES` (default 16 GiB: `ider_upload_too_large`) and fit on the volume with room to spare (`ider_upload_no_room_on_the_image_volume`). Results, including failures, are listed by `list` under uploads. The proxies in front of the console and amt-mcp must allow a request body that large and not time out; see [16](#16-incident-playbook).
- Keep the image root on the mounted `/iso` volume. A root set to a path outside it exists only inside the container and is lost when the container is recreated.

### 9.2 Mount, boot and unmount

**When.** Installing an OS, booting a rescue image, or running a firmware update from media.

**Steps.**

1. **Media** tab ▸ **Mount an image**: choose the ISO and/or floppy image and the start mode:
   - **next boot** (default): the drive appears when the host next boots; the host is not reset.
   - **graceful**: asks the OS to reset now.
   - **now**: **hard resets the host at once** (a hold).
2. Press **Mount**. The mount belongs to amt-mcp: it holds the host's IDE-R session until you unmount, and KVM keeps working beside it. AMT drops an idle IDE-R session after about 60 seconds of client silence, so amt-mcp sends a keepalive every 10 seconds.
3. To boot from it: **Power & boot** tab ▸ target `cd_ider` (or `floppy_ider`) ▸ **Set next boot only**, then a graceful **Restart**. From off, use **Power on → the mounted IDE-R CD** instead (that button is greyed with "host is already on" while the host is on).
4. Watch it on the **KVM** tab.
5. When the install has finished, **Unmount** on the **Media** tab, and set next boot back to normal if it was not consumed.

**Success looks like.** The Fleet card shows **IDE-R mounted** (and the image name on the server page). `amt_ider status` shows `mounted: true` with the image names.

**What can go wrong.**

| Message | Meaning |
|---|---|
| `ider_image_root_unset: ...` | No image root is set. Set one (**Change root**). |
| `ider_already_mounted: unmount first (AMT permits one redirection session)` | A mount is already open on that host. Unmount it first. |
| `ider_image_not_a_512_aligned_regular_file:<name>` | The image's size is not a multiple of 512 bytes (often a truncated download). Verify it. |
| `ider_unmount_timeout: ... STILL HELD` | The serving thread did not stop. Call unmount again, or check `amt_ider status`. |
| The mount disappears | A mount lives in amt-mcp's memory. Restarting or recreating the container drops it ([13](#13-deploying-an-update)). |

## 10. Logs, inventory, AMT settings and Advanced WS-MAN

All four are on the server's tabs, are plain reads when they say so, and are never read on a timer or for a paused server (the **Read** control is greyed with the reason).

**Logs.** Choose **Event log** or **Audit log**, optional **Since (UTC)** and **Until (UTC)** (ISO-8601; no zone means UTC), a severity filter (the filter is on the page only), then **Read**; **Newer** / **Older** page through (1 to 500 records). Each page is a fresh read of the whole log. Event records carry a readable description, source and severity; audit records carry the application, event, the initiator and decoded extended data, with the raw codes beside them. The counts line separates "fetched", "undated" and "undecodable", so an empty page can be told from an empty log. A time filter drops records written before the AMT clock was set. **The audit log is the host-side record of who did what to AMT**; amt-mcp's own call log (section 14) names the tool and the caller but not the server or the outcome.

**Inventory.** **Read** gives chassis, baseboard, BIOS, processors, memory and storage media (`chassis`, `baseboard`, `bios`, `processors`, `memory`, `storage_media`, `physical_media`). A class the host does not expose is listed as unavailable rather than failing. **Export JSON** saves what you read.

**AMT settings.** Ten areas can be read; six can be written: `network`, `internet`, `security`, `users`, `kvm`, `features`. `agent_presence`, `system_defense`, `subscriptions` and `wake_alarms` are read-only here (change them through **Advanced**).

| Area | Writable fields |
|---|---|
| `network` | `HostName`, `DomainName`, `SharedFQDN`, `PingResponseEnabled`, `RmcpPingResponseEnabled`, `DDNSUpdateEnabled`, `DDNSPeriodicUpdateInterval`, `DDNSTTL`, `IdleWakeTimeout` |
| `internet` | `DetectionAlgorithm`, `DetectionStrings` |
| `security` | `AcceptNonSecureConnections` |
| `kvm` | `Is5900PortEnabled`, `OptInPolicy`, `SessionTimeout` |
| `features` | `ider_enabled`, `sol_enabled`, `kvm_enabled` |
| `users` | add or remove an AMT user (never the admin); an add reads the user's password from the vault entry `<key>-amt-user-<name>`, which you create first |

A write reads the whole instance, merges your change, writes it, reads it back and raises if the change or any other field differs (`configure_readback_mismatch:...`, `configure_collateral_change:...`). The result keeps `previous` (the old values), and **Revert** in the result row writes them back through its own sheet. **Revert is only on that result row**: copy `previous` if you may need it after leaving the page. The tool names these as risky: `kvm OptInPolicy=false` (turns off user consent), `kvm Is5900PortEnabled=true` (opens the plaintext VNC port 5900), `security AcceptNonSecureConnections=true` (accepts non-TLS connections) and enabling IDE-R, SOL or KVM.

**Advanced (WS-MAN).** Three parts:

- **WS-MAN browser** (`amt_wsman_get`): get or enumerate any `AMT_`, `CIM_` or `IPS_` class. Read-only; secret-named fields are redacted.
- **Edit and Put** (from a get): **a Put may whole-replace the instance and reset fields you omit.** Get the full instance, merge, then Put. The editor strips redacted and credential-named fields and says so; AMT may reset such a field, so prefer **AMT settings** for a class that carries one.
- **Script editor** (`amt_wsman_invoke`): put, create, delete or invoke on any class, **with no safeguard beyond your confirmation** and no readback. A non-zero `ReturnValue` or a SOAP fault raises; a reply without a `ReturnValue` is reported as unknown. **Validate only** checks the call inside the page (no credential-named field, nothing the tool would refuse on its shape, no leftover placeholder) and sends nothing. The guarded templates fill the editor without running: OS wake and power saving, user-consent request, send and cancel, watchdog, system-defense filter and policy, delete an event subscription, wake alarm, and **Unprovision AMT (factory reset)**. Unprovision takes the hold: it clears every setting, user and certificate and drops this console's access; re-provisioning is a hands-on MEBx step at the machine, and there is no undo. A name in `<angle brackets>` blocks Run until you replace it. Field names in the templates come from the AMT SDK and have not all been checked against a live read of each class.
- Platform Erase at next boot is listed as unavailable (no tool chains the required calls).

## 11. Captures: screenshots and recordings

| Kind | Made by | Where it is on the Docker host | Name |
|---|---|---|---|
| Screenshot (PNG) | `amt_screenshot`, **Take screenshot**, **Shot**, and the result frame of console and sign-in calls | `data/state/shots/` (`AMT_SHOT_DIR`) | `amt-<device>-<UTC time>-<hex>.png` |
| Mirror recording (MP4) | **Start recording** on a mirror | `data/amt-recordings/` (the container's `$HOME/amt-recordings`) | `amt-<device>-<UTC time>.mp4` |
| Serial recording (cast) | **Start recording** on a terminal | `data/amt-recordings/` | `<device>-serial-<UTC time>.cast` |

**Fetching one.** A tool that writes a file returns a one-time download URL (single use, 15 minutes) plus its SHA-256. In the console you never see that URL: the console fetches it once, checks the hash, and keeps the file in its own capture store; you get **Save**, **Copy sha256** and, on the KVM tab, **Open in console**. If the 15 minutes pass first, the result says "the one-time link expired ... Take a new screenshot". To get a file that is no longer in the console's store, use **Past captures** (Status tab) or **Recordings** (KVM and SOL tabs) and press **Fetch**: that is `amt_captures` with `action: "fetch"` and mints a fresh single-use URL each time. `amt_captures list` pages newest first and lists only finished files whose name has the shape above.

**Retention.**

- The console's own store deletes files after `AMT_CONSOLE_CAPTURE_HOURS` (24 in `deploy/compose.yaml`). **Save** what you need within that time, or fetch it again.
- Nothing in amt-mcp deletes the originals in `data/state/shots/` and `data/amt-recordings/`. They grow until you prune them by hand. Check the free space on `data/` in your daily check if you record often.

Captures show whatever was on the host's screen or serial port, including sign-in screens and account names. Treat them as sensitive ([15](#15-backups)).

## 12. Paused servers

**What it is.** The console stops reading a server automatically in two cases:

| Pause reason | Trigger | Meaning |
|---|---|---|
| **credential refused** | `wsman_auth_failed_401` in any call through the console (a read or a write) | The AMT rejected the `admin` password amt-mcp sent. One attempt was made and not repeated. |
| **pin differs** | `tls_leaf_pin_mismatch` in a status read | The certificate the host presents no longer matches the stored pin. No credential was sent. |

While paused, nothing reads that server on a timer. Logs, Inventory, AMT settings and Advanced show their **Read** controls greyed with "paused · credential refused" (or "pin differs"), and the power buttons are greyed too. A call you make yourself from an agent is not blocked by the pause, but it meets the same refusal and, for a credential pause, is one more failed attempt.

**What NOT to do.**

- **Do not press Retry once, or call anything against the server from an agent, until you know why it was refused.** A 401 means the vault holds a password the AMT does not accept. Each call is one more failed Digest authentication, and AMT can lock the admin account after repeated failures. The pause exists to stop exactly that.
- Do not "fix" it by re-pinning. A pin pause is about the certificate; a credential pause is about the password.
- Do not edit the vault by hand.

**Resuming after a credential refusal.**

1. Find out which side is stale. Did someone change the AMT password (MEBx, another tool)? Did the vault value change?
2. Make the vault match the host: [4.3](#43-rotating-the-amt-admin-password), Route A or B.
3. Run `vault status`: every main entry must show `matches: true`.
4. The server resumes by itself when its identity's `updated-at` changes (the console checks while a page is open) and takes one fresh read. If it did not resume (for example no `updated-at` could be read when it paused), press **Retry once** exactly once. It makes one real authentication attempt. If the read succeeds the server is live again; if it fails, it stays paused and you stop and re-check the password at the host.
5. A `vault sync` rebuilds the whole container vault, which may move every entry's `updated-at` and so resume other paused servers whose passwords are still wrong (not checked against the vault CLI's timestamps). Each such resume costs that server one attempt before it pauses again, so fix every stale password before you sync, or sync knowing that.

**Resuming after a pin difference.** Follow [3.4](#34-re-pin-after-a-certificate-change): **Check pin**, compare, **Re-pin**. The server resumes at once.

If the server is paused but reachable and you only need to look at it, the **Status** tab still shows the last good values marked stale, with the time of the last good read.

## 13. Deploying an update

Initial installation and the upgrade basics are in [install-mcp.md](install-mcp.md) (Upgrading) and [install-console.md](install-console.md). This section adds what a day-two update means for a running system.

**Before you start.**

- **Rebuilding `amt-mcp` restarts it, which ends everything it holds in memory:** running mirrors and terminals (and their recordings), IDE-R mounts, unused one-time upload and intake URLs, and background image downloads. Stop recordings and wait for their MP4 to appear, unmount images, and check the Fleet banner and the **Held** filter first. An in-flight tool call is cut off. Rebuilding only `amt-console` drops what the console keeps in memory (viewer-frame keys, so open frames remount; upload and intake handles not yet used). Passkeys, signed-in sessions and captures are on disk in `console-data/` and survive.
- `site.vars` must exist in the deploy directory, and should be compared with the new `deploy/site.vars.example` for lines added in the new version (compose refuses a missing one).
- Know your rollback target: the current `src/` is it, if you keep it.

**Steps.**

1. Put the new code beside the old one, from your checkout:

   ```bash
   # on your machine, in the repository, at the commit you mean to deploy
   git archive --format=tar --prefix=src.new/ HEAD | ssh jdoe@198.51.100.10 'tar -x -C /srv/amt-mcp -f -'
   ```

   A fresh directory plus a swap is needed because extracting over `src/` does not delete files that were removed.
2. On the Docker host, swap and rebuild only the service you changed:

   ```bash
   cd /srv/amt-mcp
   mv src src.prev && mv src.new src          # src.prev is the rollback copy
   dc up -d --build amt-mcp                   # or amt-console, or both service names
   ```

   A change to `amt-mcp.env` or `site.vars` also needs `dc up -d <service>`: they are read when the container is created, not on a signal. Add `--force-recreate` if compose reports nothing to do.
3. Verify:

   ```bash
   dc ps                                      # both services "running", not "restarting"
   docker logs --tail 30 amt-mcp 2>&1         # a Uvicorn line naming port 8765, no traceback
   docker logs --tail 30 amt-console 2>&1
   ```

   Then the checks in [2](#2-daily-checks): the Fleet page reads every server; `amt_devices list` returns your servers with `source: "file"`; a harmless read (`amt_status` on one server) succeeds; sign in to the console. A container that restarts in a loop with `refusing to start the HTTP mount: MCP_ADMIN_TOKEN_HASH is unset ...` has lost its `amt-mcp.env` hash (exit status 2).
4. Keep `src.prev` until you are satisfied, then remove it.

**Roll back.**

```bash
cd /srv/amt-mcp
mv src src.bad && mv src.prev src
dc up -d --build amt-mcp
```

Keep `src.bad` for diagnosis. That reverts code only. The other rollback files are one generation deep and belong to data changes, not to code:

| File | Holds | Put back with |
|---|---|---|
| `config/.prev-devices.json` | The devices file before the last change (both writers) | [3.6](#36-the-devices-file-and-its-rollback) |
| `vault/.prev-amt-mcp.vault`, `vault/.prev-amt-mcp.key` | The container vault pair before the last `vault sync` | Make the directory writable (`chmod 700`), rename both over the live pair together, then `chmod 500` again; this follows the sync's own rename procedure and was not run |

The image pins its base by tag (`python:3.12.7-slim-bookworm`) and does not version-pin its `apt` packages, so a rebuild can pick up newer `tesseract-ocr` and `ffmpeg`. Note any change in OCR behaviour (sign-in aborts with `ocr_*` reasons) after a rebuild.

## 14. Monitoring and logs

There is no built-in alerting, no health endpoint and no metric. What you have:

**amt-mcp's call log.** Every call that passes the bearer gate writes one line to the container's standard error:

```
2026-10-22 11:04:05,123 amt_mcp.calls tool=amt_status principal=console
```

The format is `<time> amt_mcp.calls tool=<name> principal=<fleet|console|stdio>`. `fleet` is an agent or script using the fleet bearer; `console` is the management console; `stdio` is a local stdio run with no bearer. A tool name that is not a plain identifier is logged as `<invalid-name>`. There is no token, hash, device, argument or outcome in it. A call refused for a bad bearer is not logged here (the refusal comes first). Uvicorn's own request lines (`POST /mcp ... 200`) appear in the same stream.

```bash
docker logs --since 1h amt-mcp 2>&1 | grep 'amt_mcp.calls'
docker logs --since 1h amt-mcp 2>&1 | grep -c 'principal=fleet'
```

The `2>&1` is required: the call log is on standard error, and `docker logs` keeps the two streams apart.

To see which host a power action hit and what AMT did, read that host's **audit log** (section 10), not the container log.

**The console's access log.** `docker logs amt-console 2>&1` shows lines like `2026-10-22 11:04:05,456 amt_console GET /api/fleet 200`. Embed keys, upload ids and intake ids in paths are replaced with `<key>` and `<id>`; no cookie, bearer, one-time URL or value is logged. Warnings (for example an enrollment code withdrawn after wrong attempts) go to the same stream.

**Health checks you can run.**

| Check | How | Healthy |
|---|---|---|
| Containers up | `dc ps` | `running`, no restart loop |
| amt-mcp answers and the devices file parses | `amt_devices` `list` (any MCP client, or the **Manage** page) | Your servers, `"source": "file"`. `source: "built-in"` means the file is not configured. |
| A host is reachable and credentials work | `amt_status` for one device (or the Fleet card) | A power state and AMT version |
| A host's certificate is as expected, no credential sent | `amt_devices` `pin_check` (**Check pin**), or `amt_admin.py device pin KEY` | `"matches": true` |
| The vault is in step | `amt_admin.py vault status` | Exit 0, every main entry `matches: true` |
| Identities present | `amt_identities` (**Manage ▸ Identities**) | No entry `missing` |
| Disk | `df -h /srv/amt-mcp/data /srv/amt-mcp/iso` | Room for recordings and images |

Without a bearer the HTTP mount refuses tool calls with an MCP error, not an HTTP status (`this call requires the mcp-admin-token bearer header ... the call was refused and nothing ran`), so an unauthenticated probe tells you the mount is up but nothing else.

## 15. Backups

| What | Where | Back up? | Notes |
|---|---|---|---|
| Servers | `config/devices.json` (and `.prev-devices.json`) | Yes | Small. It holds addresses, ports, entry names and pins, no secret. |
| Container vault and its key | `vault/amt-mcp.vault`, `vault/amt-mcp.key` | Yes, with care | Main-sourced entries are rebuildable from the main vault with `vault sync`. **Entries entered through the console exist only here.** The key file decrypts the vault: store them under the same protection as your main vault backup, not together in an unprotected place. |
| Console bearer vault | `console-vault/amt-console.vault`, `.key` | Yes, with care | The console's only credential. If lost, mint a new token and put its hash in `amt-mcp.env` as `MCP_CONSOLE_TOKEN_HASH` ([install-console.md](install-console.md)). |
| Console state | `console-data/` (`passkeys.json`, `sessions.json`, `host-sessions.json`, `captures/`) | Passkeys yes; the rest optional | Lost passkeys are recoverable with `console enroll-code` (2.3). Captures expire in 24 hours anyway. |
| Site values | `site.vars`, `amt-mcp.env` | Yes | `site.vars` holds no secret. `amt-mcp.env` holds the SHA-256 of each bearer, not a token. |
| Settings | `data/state/settings.json` | Yes | The image root and recording folder you set. |
| Captures | `data/state/shots/`, `data/amt-recordings/` | If you need them | Sensitive; nothing prunes them. |
| Images | `iso/` | Optional | Fetchable again by URL. |
| Main vault | on your machine | By its own procedure | The source of truth for main-sourced entries. Not covered here. |

**Never copy into a ticket, chat or email:** vault files or key files, the fleet or console token, enrollment codes, any one-time URL (download, upload, intake) or viewer URL (a mirror or terminal link is an access key; a control link lets the holder drive the host), screenshots and recordings (they may show account names and secrets on screen), or a value read out of any vault. Fingerprints, device keys, entry **names**, tool names and error codes are safe to share.

## 16. Incident playbook

First rule: **if a call was refused for a credential, stop calling that server until the vault and the host agree** ([12](#12-paused-servers)). Everything else is safe to look at.

| Symptom | Likely cause | First safe step |
|---|---|---|
| KVM frame is blank or black | The host's display is asleep or the host is off or asleep; or a user-consent code is waiting; or the console is a text console with no output yet (a real text console is a few lines on black). The mirror only writes a frame when the screen changes, so a quiet screen looks static. | **Status** tab: check power and **user consent**. Take a screenshot. If the host is on, send a harmless key from the control page to wake a display. If consent is pending, enter the code from the host screen in **Advanced ▸ Send a consent code** within 2 minutes. |
| Mirror will not start: "another session is open" / `redir_start_status_N` | Another client already holds the host's single KVM session (or amt-mcp's own earlier mirror does). This comes from AMT's start reply, before any credential. | Fleet chip and `amt_mirror_link status`: is it yours or an agent's? If neither, find and close the other client or wait for AMT's `SessionTimeout`. Do not loop; retrying is safe but pointless until it is released ([6.6](#66-another-client-holds-the-session)). |
| Mirror started by an agent shows "not reachable from here" | It was started with the default bind `127.0.0.1`, which the viewer front cannot reach. | Stop it and start it with `bind: "0.0.0.0"`, port 8766. |
| Start fails with `viewer_server_in_use` | A mirror or terminal is live on a different bind or port. | Use that bind and port, or stop the live ones first. |
| Pin mismatch after AMT was re-provisioned: **paused · pin differs**, `tls_leaf_pin_mismatch` | The host's certificate changed (re-provisioning, TLS reconfiguration), or another machine holds the address. | **Check pin**, compare with an independent reading (3.2). Re-pin only when you can explain the change ([3.4](#34-re-pin-after-a-certificate-change)). If you cannot, treat it as an incident and check the network. |
| 401 after a password change: **paused · credential refused**, `wsman_auth_failed_401` | The vault holds a password the AMT does not accept. | Do not retry. Make the vault match the host ([4.3](#43-rotating-the-amt-admin-password), [12](#12-paused-servers)). |
| Console shows a refusal "this call requires the mcp-admin-token bearer header ..." | The console's bearer does not hash to `MCP_CONSOLE_TOKEN_HASH` in amt-mcp's environment, or that line is missing, or `MCP_ADMIN_TOKEN_HASH` is unusable (which refuses every token, the console's too). The console forgets its cached token on this error and re-reads its vault on the next call. | Check that `MCP_CONSOLE_TOKEN_HASH` in `amt-mcp.env` is the SHA-256 of the token in the console's vault, without printing the token (how the hash is derived is in [install-console.md](install-console.md)). If you edited `amt-mcp.env`, recreate: `dc up -d amt-mcp`. |
| Console shows `console_bearer_unavailable` (HTTP 503) | The console could not read its bearer from its own vault (`vault_miss:amt-console-token`, wrong mount or key). | Check `console-vault/` is mounted and its files are readable by `DEPLOY_UID`. |
| Console shows `amt_mcp_unreachable:<Type>` (502) or `amt_mcp_http_NNN` | amt-mcp is down, or the console's URL (`AMT_CONSOLE_MCP_URL`, which is `AMT_PUBLIC_BASE_URL` plus `/mcp`) does not reach it through the proxy. `amt_mcp_http_421` is amt-mcp refusing the `Host` (not in `AMT_ALLOWED_HOSTS`). | `dc ps`; `docker logs amt-mcp`; check the proxy and `AMT_ALLOWED_HOSTS`. |
| Fleet shows "amt-mcp could not list its servers: ..." | `amt_devices` failed, or the devices file is unusable. | Read the message; `devices_file_unusable:<Type>` means restore `.prev-devices.json` ([3.6](#36-the-devices-file-and-its-rollback)). |
| Every tool fails with `vault_miss:<name>` | The entry is not in the container's vault. | **Manage ▸ Identities** shows it **missing**. Store it in the main vault and `vault sync`. |
| Power action refused: `power_state_not_available` | AMT does not offer that state now (a boot menu offers only hard reset and NMI). | Read the list in the message; use an offered action, or wait for the OS. |
| Power request sent but "unknown" outcome | The reply had no `ReturnValue`. | Check the host. Do not send it again until you know. |
| Host sign-in aborted with nothing typed | The screen was not a positively identified sign-in. | Read the `reason` ([8.1](#81-reading-an-abort)); look at the screen. It does not retry. |
| Image upload fails | One-time URL expired (15 minutes); size or hash differs from what was declared; over `AMT_UPLOAD_MAX_BYTES`; no room on the volume; or the name is mounted or being written. The browser-to-console and console-to-amt-mcp legs both pass through the TLS reverse proxy, and its body-size limit or timeout (for example nginx `client_max_body_size`) can cut a large file; that comes from how the path is built, not from a message in the source. | `amt_images list` shows `uploads` with each failure's error text. Mint a new upload. Check the proxy limits and `df -h /srv/amt-mcp/iso`. |
| A fetch fails | `sha256_mismatch:got <hash>`, the URL is unreachable from the container, or the name exists (`ider_fetch_exists`). | `amt_images list` shows the fetch's `state` and `error`. |
| Value entry (Identities) answers 503 `vault_not_writable: nothing was stored` | The container cannot write `vault/` (mounted `:ro`, or left 0500 and 0400 by an older `vault sync`). | Run `vault sync` from this version, or `chmod 700 vault; chmod 600 vault/amt-mcp.*`; meanwhile use Route A ([4.1](#41-route-a-main-vault-and-vault-sync-works-on-a-stock-deployment)). |
| KVM or SOL drops after a short time, or the picture freezes | The proxy is buffering or has a short read timeout for the stream (the mirror and serial streams send `X-Accel-Buffering: no`). If the mirror's session ended for any reason, `amt_mirror_link status` shows `live: false` with an `error`, and **Start mirror** opens a new one. | Check the proxy's buffering and read-timeout settings ([install-mcp.md](install-mcp.md), reverse proxy). |
| Viewer frame blank in the console | (a) The embed key expired (10 minutes unused) or the console restarted: the page mounts a fresh frame by itself. (b) The mirror is not reachable (agent-started on `127.0.0.1`). (c) The viewer origin differs between amt-mcp and the console (`AMT_VIEWER_PUBLIC_BASE_URL` vs `AMT_CONSOLE_VIEWER_ORIGIN`; compose takes both from `AMT_VIEWER_PUBLIC_BASE_URL`). (d) `viewer_unreachable` (502): the viewer origin did not answer. (e) A user-consent prompt is pending. | Read the text on the tab (it names the case); press **Open in a tab** to test the keyed page; check `AMT_VIEWER_PUBLIC_BASE_URL` and the viewer proxy name. |
| Console sign-in fails or all passkeys lost | Passkey not enrolled on this device, or the origin differs from `AMT_CONSOLE_ORIGIN` / `AMT_CONSOLE_RP_ID`. | Use another enrolled passkey; or mint a code with `amt_admin.py console enroll-code` (2.3). |
| `amt-mcp` restarts in a loop, exit status 2 | `MCP_ADMIN_TOKEN_HASH` is missing or not 64 hex characters in `amt-mcp.env`. | `docker logs amt-mcp`; fix the line; `dc up -d amt-mcp`. |
| A recording is missing after an update | The container was restarted during the encode; only the raw `.mjpeg` and `.times` remain in `data/amt-recordings/`, and an unfinished file is not listed. Nothing in the code re-encodes leftovers later. | The raw `.mjpeg` plays in VLC or ffplay (the viewer page says so). Stop recordings and wait for their MP4 before updating. |

## 17. Keeping this guide current

This guide was written from the source at the time of writing; the places that decide each claim are listed here so an update has somewhere to start. After any change in these files, re-read the sections named.

| Source | What it decides | Sections |
|---|---|---|
| `deploy/amt_admin.py` | Commands, flags, environment variables, output JSON, refusal text, vault sync/rollback procedure, enrollment code | 0, 2.3, 3, 4, 12, 13 |
| `deploy/compose.yaml`, `deploy/site.vars.example` | Services, mounts (notably the writable `./vault:/vault`), ports, `AMT_CONSOLE_CAPTURE_HOURS`, `AMT_CONSOLE_IDLE_HOURS`, directory layout | 0, 4.2, 11, 13, 15 |
| `amt_fleet.py`, `amt_registry.py` | Device rules (pin on add, repin on edit, last-server rule), devices file format, `.prev-devices.json` | 3, 16 |
| `amt_identity.py`, `amt_upload.py`, `amt_vault.py` | Which names an intake accepts, intake limits (900 s, 4096 bytes), the 503, remove rules | 4 |
| `amt_gate.py` | The bearer gate, the call-log format and principals, the refusal text | 1, 14, 16 |
| `amt_write.py` | Power actions and refusals, boot targets and options, console input macros and limits, SOL limits, IDE-R and the image library, `amt_configure` areas and risky changes | 5, 6, 7, 9, 10 |
| `amt_tools.py` | Reads, sign-in behaviour and abort reasons (`ABORT_NOTES` and the structural reasons) | 8, 10 |
| `amt_mirror.py`, `amt_serial.py` | Mirror and terminal behaviour, keepalive, recording, bind and port rules | 6, 7 |
| `amt_captures.py`, `amt_handoff.py` | Capture names, one-time handoffs, 15-minute lifetime | 11 |
| `console/fleet.py`, `console/static/fleet.js`, `status.js` | Fleet states, pause and resume rules, chip texts | 2, 12 |
| `console/static/*.js`, `console/pages/*.html` | Every label, button and sheet quoted in bold | all |
| `console/static/components.js` | The destructive predicate (which actions take a hold) | 0 |
| `console/auth.py`, `console/captures.py`, `console/mcp_client.py`, `console/embed.py` | Passkeys, enrollment attempts, capture retention, console error codes, viewer reachability | 2.3, 11, 16 |
| `CLAUDE.md` | The invariants the code must keep | 1 |

**Update triggers.** Re-check this guide when any of these change: a tool is added, removed or renamed (tool count is pinned in `tests/test_conformity.py`); a compose mount, port or environment value changes; a new `amt_admin.py` command appears; an error string quoted here is reworded; a console label changes; the intake's vault mount changes from read-only (sections 4.2 and 16 then lose their caveat); or a live check changes what is stated as unverified (the "not run" notes in 3.2, 3.6 and 13 above).

**Checks to run when you edit this guide.** Search the repository for each quoted error string before keeping it (`grep -rn 'power_state_not_available' *.py` and so on, using `command grep` if `grep` is a shell function that honours ignore files), and re-run any command you change.
