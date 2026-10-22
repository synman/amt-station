/* The Identities page (design/identities.html, note 2.11): the vault entries amt-mcp's servers use, by NAME and status only, and the
   one-time intake that stores a new value. Entries are read with amt_identities (when the page opens, on Re-read and after a value
   arrives), never on a timer, and never carry a value: present or missing, where it is used, its source and updated-at.
   Entering a value is two steps. Minting the intake is amt_identity_manage through a plain sheet; the console keeps the one-time url
   and gives this page an opaque intake id (the url never reaches the browser). Send the value then posts the field once to the
   console's own /api/identities/intake/<id> and clears the field BEFORE the answer arrives; the field is a text input masked by
   text-security, outside any form, with no value attribute. Remove is the hold and is greyed while a server names the entry. A tool's
   refusal is shown verbatim (text nodes only, never markup). */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var page = document.getElementById('ident-page');
  if (!page) return;
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;
  var KEY = /^[a-z0-9][a-z0-9-]{0,62}$/, USER = /^[A-Za-z0-9_.@-]{1,16}$/;

  // ---- what an entry is, from the fields of the servers that use it (amt_identities used_by) ----
  var KINDS = {
    amt_vault_key: { label: 'AMT admin password', use: 'used by every call to the server', select: 'amt_vault_key', icon: 'i-key' },
    host_vault_key: { label: 'host logon {user, password}', use: 'used by the host sign-in and the secret steps', select: 'host_vault_key', icon: 'i-person' },
    amt_configure_kvm: { label: 'KVM (RFB) password', use: 'written into the KVM settings by amt_configure', select: 'rfb', icon: 'i-key' },
    amt_configure_users: { label: 'AMT user password', use: 'read by amt_configure users add', select: 'user', icon: 'i-key' }
  };
  var kindBySelect = function (sel) { return Object.keys(KINDS).map(function (k) { return KINDS[k]; }).filter(function (k) { return k.select === sel; })[0] || null; };
  var FIELD_NAMES = { amt_vault_key: 'amt_vault_key', host_vault_key: 'host_vault_key', amt_configure_kvm: 'KVM settings', amt_configure_users: 'AMT users' };

  // ---- state ----
  var ids = { list: null, error: null, readAt: null };
  var devices = [];                                              // the servers (amt_devices list), for the owner select
  var intake = null;                                             // { id, name, max, until (ms), server } while a minted intake is waiting for its value
  var sending = false, dirty = false;

  var plain = function (v) { return typeof v === 'string' && v !== ''; };
  function rowOk(r) {
    return r && plain(r.name) && (r.status === 'present' || r.status === 'missing') && Array.isArray(r.used_by)
      && r.used_by.every(function (u) { return u && plain(u.device) && plain(u.field); })
      && (r.source === null || r.source === 'main' || r.source === 'console') && (r.updated_at === null || r.updated_at === undefined || typeof r.updated_at === 'string');
  }
  function readIdentities() {
    return amtc.post('/api/call', { tool: 'amt_identities', arguments: {} }).then(function (r) {
      var b = r.body || {}, s = b.structured;
      if (r.status !== 200) ids.error = 'the console could not ask amt-mcp (' + (b.error || 'no answer') + ')';
      else if (b.isError) ids.error = b.text;
      else if (!s || !Array.isArray(s.identities) || !s.identities.every(rowOk)) ids.error = 'amt-mcp\'s answer was not a readable list of identities';
      else ids = { list: s.identities, error: null, readAt: Date.now() / 1000 };
    });
  }
  function readDevices() {
    return amtc.post('/api/call', { tool: 'amt_devices', arguments: { action: 'list' } }).then(function (r) {
      var s = r.status === 200 && !r.body.isError ? r.body.structured : null;
      if (s && Array.isArray(s.devices)) devices = s.devices.filter(function (d) { return d && plain(d.key) && plain(d.amt_vault_key); });
    });
  }
  function readAll() { return Promise.all([readIdentities(), readDevices()]).then(renderAll); }
  var rowByName = function (n) { return (ids.list || []).filter(function (r) { return r.name === n; })[0] || null; };
  var deviceByKey = function (k) { return devices.filter(function (d) { return d.key === k; })[0] || null; };

  // ---- results (design 7.4): the tool's own words, in the card of the action ----
  var stamp = function () { return S.eastern(Date.now() / 1000, false); };
  function addResult(slot, node) { slot.insertBefore(node, slot.firstChild); while (slot.children.length > 5) slot.removeChild(slot.lastChild); }
  var lead = function (what) { return h('strong', {}, [stamp() + ' · ' + what]); };
  function failure(what, r) {                                  // the console could not make the call, or amt-mcp did not answer
    var code = (r.body && r.body.error) || 'no answer';
    if (r.status === 502) return S.result('live', 'i-help', [lead(what), ' · amt-mcp did not answer (' + code + ') · it is not known whether the request was made; Re-read the identities before trying again']);
    return S.result('error', 'i-block', [lead(what), ' · refused: ' + code + ' · nothing sent']);
  }
  function reply(what, r, tail, ok) {                          // 200 + isError is a refusal by the tool; anything but 200 never reached it
    if (r.status !== 200) return failure(what, r);
    if (r.body.isError) return S.result('error', 'i-block', [lead(what), ' · refused: ' + r.body.text + tail]);
    return ok(r.body.structured || {});
  }
  var when = function (iso) { var t = Date.parse(iso); return isNaN(t) ? iso : S.eastern(t / 1000); };

  // ---- the list ----
  function kindOf(row) { return row.used_by.length ? KINDS[row.used_by[0].field] || null : null; }
  function ownerList(row) { return row.used_by.map(function (u) { return u.device; }).filter(function (d, i, a) { return a.indexOf(d) === i; }); }
  function statusChip(row) {
    var owners = ownerList(row).join(', ');
    if (row.status === 'missing') return h('span', { class: 'chip small error', 'data-identity': 'missing' }, [icon('i-block'), 'missing · every call to ' + (owners || 'its server') + ' fails']);
    if (!row.used_by.length) return h('span', { class: 'chip small ok', 'data-identity': 'unused' }, [icon('i-check'), 'present · unused']);
    return h('span', { class: 'chip small ok', 'data-identity': row.source === 'console' ? 'entered' : 'synced' }, [icon('i-check'), 'present · ' + (row.source === 'console' ? 'entered here' : 'synced')]);
  }
  function subLine(row) {
    var k = kindOf(row), parts = [];
    parts.push(k ? k.label : 'no server names this entry');
    if (row.used_by.length) parts.push('owner ' + ownerList(row).join(', '));
    parts.push(row.used_by.length ? row.used_by.map(function (u) { return (KINDS[u.field] || { use: 'used by ' + u.field }).use; }).filter(function (x, i, a) { return a.indexOf(x) === i; }).join('; ') : 'used by nothing');
    if (row.status === 'present') {
      parts.push(row.source === 'console' ? 'entered here' : 'synced from the main vault');
      parts.push(row.updated_at ? 'updated ' + when(row.updated_at) : 'updated-at not recorded');
    }
    return parts.join(' · ');
  }
  function gated(label, reason, attrs) {                      // a button that may be aria-disabled, with its reason as visible text beside it
    var b = h('button', { type: 'button', class: 'btn text' }, [label]);
    Object.keys(attrs || {}).forEach(function (k) { b.setAttribute(k, attrs[k]); });
    if (!reason) return { node: b, btn: b };
    b.setAttribute('aria-disabled', 'true');
    return { node: h('div', { class: 'btn-wrap' }, [b, h('span', { class: 'reason' }, [reason])]), btn: b };
  }
  function removeReason(row) {
    if (row.used_by.length) return 'named by ' + row.used_by.map(function (u) { return u.device + '.' + (FIELD_NAMES[u.field] || u.field); }).join(', ') + ': amt_identity_manage refuses';
    if (row.source !== 'console') return 'copied from the main vault: remove it there';
    return null;
  }
  function renderRow(row) {
    var k = kindOf(row), li = h('li', { 'data-name': row.name }, [icon(row.status === 'missing' ? 'i-warning' : k ? k.icon : 'i-key'),
      h('span', { class: 'txt' }, [h('span', { class: 'data' }, [row.name]), h('span', { class: 'sub' }, [subLine(row)])]), statusChip(row)]);
    if (row.status === 'missing') {
      if (k) {                                                 // an entry no server names has nothing to derive its kind and owner from
        var enter = h('button', { type: 'button', class: 'btn text', 'aria-label': 'Enter ' + row.name }, ['Enter']);
        enter.addEventListener('click', function () { enterFor(row); });
        li.appendChild(enter);
      }
      return li;
    }
    var rep = gated('Replace stored value', null, { 'aria-label': 'Replace the stored value of ' + row.name });
    amtc.bindWrite(rep.btn, function () { return mintSpec(row.name, k, true); });
    li.appendChild(rep.node);
    var rm = gated('Remove', removeReason(row), { 'aria-label': 'Remove ' + row.name });
    amtc.bindWrite(rm.btn, function () { return removeSpec(row.name); });
    li.appendChild(rm.node);
    return li;
  }
  function renderList() {
    var list = $('id-list'), note = $('id-note');
    clear(list);
    if (!ids.list) {
      note.textContent = ids.error ? 'The identities could not be read: ' + ids.error + ' · this is not an empty list.' : 'Reading the identities…';
      return;
    }
    ids.list.forEach(function (row) { list.appendChild(renderRow(row)); });
    note.textContent = (ids.error ? 'The last re-read failed (' + ids.error + '); this is the list as read ' + S.eastern(ids.readAt, false) + '. ' : '')
      + (ids.list.length ? ids.list.length + (ids.list.length === 1 ? ' entry' : ' entries') + ' · read ' + S.eastern(ids.readAt, false) + '.' : 'amt-mcp names no identity yet.');
  }

  // ---- remove: the hold ----
  function removeSpec(name) {
    return { id: 'sheet-id-remove', title: 'Remove ' + name, verb: 'remove', nowLabel: 'Remove now', call: { tool: 'amt_identity_manage', arguments: { action: 'remove', name: name } },
      consequence: 'The entry is removed from amt-mcp\'s vault. An entry a server still names is refused. The operator can restore it only from a vault backup.',
      onResult: function (r) {
        addResult($('id-results'), reply('remove ' + name, r, ' · nothing changed', function () { return S.result('ok', 'i-check', [lead('remove ' + name), ' · removed']); }));
        readAll();
      } };
  }

  // ---- the new-identity form: the kind and owner derive the name the tool will accept ----
  function derivedName() {
    var kind = $('nid-kind').value, dev = deviceByKey($('nid-owner').value);
    if (!dev) return { name: '', help: 'no server is registered: an entry is named by a server' };
    if (kind === 'amt_vault_key') return { name: dev.amt_vault_key };
    if (kind === 'host_vault_key') return dev.host_vault_key ? { name: dev.host_vault_key } : { name: '', help: dev.key + ' names no host logon entry: amt-mcp mints an intake only for an entry a server names' };
    if (kind === 'rfb') return { name: dev.amt_vault_key + '-rfb' };
    var u = $('nid-user').value.trim();
    return USER.test(u) ? { name: dev.key + '-amt-user-' + u } : { name: '', help: 'the AMT user name is 1 to 16 characters: letters, digits and _ . @ -' };
  }
  function syncName() {
    var d = derivedName();
    $('nid-name').value = d.name;
    $('nid-help').textContent = d.help || 'the vault entry\'s name';
    $('nid-user-f').hidden = $('nid-kind').value !== 'user';
    renderMintButton();
  }
  function mintProblem() {
    return $('nid-name').value.trim() ? null : derivedName().help || 'enter the entry\'s name';
  }
  function renderMintButton() {
    var wrap = $('nid-wrap'), btn = $('nid-mint'), why = mintProblem(), old = wrap.querySelector('.reason');
    if (old) old.remove();
    if (why) { btn.setAttribute('aria-disabled', 'true'); wrap.appendChild(h('span', { class: 'reason' }, [why])); }
    else btn.removeAttribute('aria-disabled');
  }
  function renderOwners() {                                     // true when the options were rebuilt
    var sel = $('nid-owner'), was = sel.value, keys = devices.map(function (d) { return d.key; }).join('|');
    if (sel.getAttribute('data-keys') === keys) return false;
    clear(sel); sel.setAttribute('data-keys', keys);
    devices.forEach(function (d) { sel.appendChild(h('option', { value: d.key }, [d.key])); });
    if (was) sel.value = was;
    return true;
  }
  function enterFor(row) {                                     // a missing entry: the form is set to mint exactly that name
    var u = row.used_by[0];
    $('nid-kind').value = KINDS[u.field].select; $('nid-owner').value = u.device;
    syncName();
    $('new-panel').scrollIntoView({ block: 'start' });
    $('nid-mint').focus();
  }

  // ---- minting: a plain sheet; the console keeps the url and answers with an id ----
  function mintSpec(name, kind, replace) {
    var amtKind = kind && kind.select === 'amt_vault_key', host = kind && kind.select === 'host_vault_key';
    var tail = amtKind ? ' This does NOT change the password on the AMT: change it in MEBx first, then store the new value here. Until the two agree, every call to the server fails after one Digest attempt (no retries, so the account cannot lock).'
      : ' This does NOT change the password anywhere else: change it where it is used first, then store the new value here.';
    var base = replace ? 'Mints a one-time intake for the existing entry; the value you then send replaces the stored one.'
      : 'amt-mcp returns a one-time PUT url (15 minutes, one use) for this entry. Nothing is stored until you send the value; it then replaces any value now stored under the name, and the url dies.';
    return { id: 'sheet-id-mint', title: (replace ? 'Replace the stored value of ' : 'Mint a one-time intake for ') + name, verb: 'Mint', call: { tool: 'amt_identity_manage', arguments: { action: 'intake', name: name } },
      consequence: base + (host ? ' The value is one line of JSON: {"user": "...", "password": "..."}.' : '') + tail + ' This console relays the value to the url once and keeps no copy; no value is a tool argument.',
      onResult: function (r) { minted(r, name, kind); } };
  }
  function minted(r, name, kind) {
    var slot = $('nid-results'), s = (r.status === 200 && !r.body.isError && r.body.structured) || {};
    if (r.status === 200 && !r.body.isError && !s.intake_id) {
      addResult(slot, S.result('error', 'i-block', [lead('intake ' + name), ' · amt-mcp\'s answer carried no usable one-time url (' + (s.intake_refused || 'none') + ') · nothing is waiting for a value']));
      return;
    }
    if (r.status !== 200 || r.body.isError) { addResult(slot, reply('intake ' + name, r, ' · no one-time url was minted', function () { return null; })); return; }
    intake = { id: s.intake_id, name: s.name || name, max: s.max_bytes || 4096, until: Date.now() + (s.expires_in_s || 900) * 1000, server: adminOwner(name) };
    $('intake-value').value = '';
    renderIntake();
    $('intake-value').focus();
  }
  function adminOwner(name) {
    var d = devices.filter(function (x) { return x.amt_vault_key === name; })[0];
    return d ? d.key : null;
  }

  // ---- the minted intake: the countdown, the value field, Send ----
  var countdown = null;
  function mmss(ms) { var s = Math.max(0, Math.floor(ms / 1000)); return (s >= 600 ? '' : '0') + Math.floor(s / 60) + ':' + (s % 60 < 10 ? '0' : '') + (s % 60); }
  function renderIntake() {
    var block = $('intake-block'), status = $('intake-status');
    block.hidden = !intake;
    clear(status); countdown = null;
    if (!intake) return;
    var expired = Date.now() >= intake.until;
    if (expired) status.appendChild(S.result('error', 'i-timer', [h('strong', {}, ['intake expired']), ' for ', h('span', { class: 'data' }, [intake.name]), ' · mint a new one']));
    else {
      countdown = h('span', { class: 'data' }, [mmss(intake.until - Date.now())]);
      status.appendChild(S.result('live', 'i-timer', [h('strong', {}, ['intake minted']), ' for ', h('span', { class: 'data' }, [intake.name]), ' · one-time PUT url · expires in ', countdown,
        ' · at most ' + intake.max + ' bytes · the url is never shown']));
    }
    $('intake-value').disabled = expired;
    renderSendButton();
  }
  function valueProblem(v) {
    if (!intake) return 'mint an intake first';
    if (Date.now() >= intake.until) return 'the intake expired: mint a new one';
    if (!v) return 'enter the value';
    if (/[\r\n\u0000]/.test(v)) return 'one line only: no line break';
    if (new Blob([v]).size > intake.max) return 'larger than ' + intake.max + ' bytes';
    return null;
  }
  function renderSendButton() {
    var wrap = $('intake-wrap'), btn = $('intake-send'), old = wrap.querySelector('.reason'), why = sending ? 'sending…' : valueProblem($('intake-value').value);
    if (old) old.remove();
    if (why) { btn.setAttribute('aria-disabled', 'true'); wrap.appendChild(h('span', { class: 'reason' }, [why])); }
    else btn.removeAttribute('aria-disabled');
  }
  function tick() {
    if (!intake) return;
    if (Date.now() >= intake.until) { renderIntake(); return; }
    if (countdown) countdown.textContent = mmss(intake.until - Date.now());
  }
  function send() {
    var btn = $('intake-send'), input = $('intake-value');
    if (btn.getAttribute('aria-disabled') === 'true' || sending) return;
    var value = input.value;
    if (valueProblem(value)) { renderSendButton(); return; }
    var cur = intake;
    input.value = '';                                          // cleared before the answer: nothing of it stays in the page
    sending = true; renderSendButton();
    var headers = { 'Content-Type': 'text/plain; charset=utf-8' };
    if (amtc.csrf) headers['X-CSRF-Token'] = amtc.csrf;
    fetch('/api/identities/intake/' + cur.id, { method: 'POST', headers: headers, credentials: 'same-origin', body: value }).then(function (r) {
      return r.json().then(function (j) { return { status: r.status, body: j }; }, function () { return { status: r.status, body: {} }; });
    }, function () { return { status: 0, body: {} }; }).then(function (r) { sending = false; arrived(cur, r); });
    value = null;
  }
  function arrived(cur, r) {
    var slot = $('nid-results'), b = r.body || {}, what = 'intake ' + cur.name;
    if (r.status === 200 && b.ok === true) {
      intake = null; renderIntake();
      readIdentities().then(function () {
        var row = rowByName(cur.name), at = Date.now();
        renderAll();
        var present = row && row.status === 'present';
        addResult(slot, S.result(present ? 'ok' : 'live', present ? 'i-check' : 'i-help', [lead(what), ' · received · ', h('span', { class: 'data' }, [cur.name]),
          present ? ' present · ' + (row.updated_at ? 'updated ' + when(row.updated_at) : 'updated-at not recorded') : ' was stored, but amt_identities does not list it as present yet: Re-read',
          ' · the field was cleared']));
        if (cur.server) proveStatus(cur.server, at); else addResult(slot, S.result('ok', 'i-info', [lead(what), ' · amt_status does not use this entry, so no status was read']));
      });
      return;
    }
    if (r.status === 200 && b.ok === false && b.status) {      // amt-mcp refused: its url is used up (a 503 means it could not write its vault, nothing stored)
      intake = null; renderIntake();
      addResult(slot, S.result('error', 'i-block', [lead(what), ' · refused by the one-time url (' + b.status + '): ' + (b.text || 'no reason given') + ' · the url is used up · mint a new intake']));
      return;
    }
    if (r.status === 200 && b.ok === false) {
      intake = null; renderIntake();
      addResult(slot, S.result('live', 'i-help', [lead(what), ' · amt-mcp did not answer (' + (b.code || 'no answer') + ') · it is not known whether the value was stored; Re-read the identities before minting again']));
      return;
    }
    if (r.status === 404) intake = null;                       // the console no longer holds the url
    renderIntake();
    addResult(slot, r.status === 0 ? S.result('live', 'i-help', [lead(what), ' · the connection to the console ended before an answer · it is not known whether the value was sent; Re-read the identities before minting again'])
      : S.result('error', 'i-block', [lead(what), ' · refused: ' + (b.error || 'no answer') + ' · ' + (r.status === 404 ? 'the intake is gone: mint a new one' : 'nothing was sent to amt-mcp; the intake is still open')]));
  }
  function proveStatus(server, receivedAt) {
    amtc.post('/api/call', { tool: 'amt_status', arguments: { device: server } }).then(function (r) {
      var what = 'amt_status ' + server, slot = $('nid-results'), secs = Math.round((Date.now() - receivedAt) / 1000);
      if (r.status !== 200) addResult(slot, S.readFailure(what, r));
      else if (r.body.isError) addResult(slot, S.readRefusal(what, r.body.text));
      else addResult(slot, S.result('ok', 'i-verified', [lead(what), ' · succeeded ' + secs + ' s after the value arrived · the stored value is the one the AMT accepts']));
    });
  }

  // ---- the page ----
  function renderAll() {
    if (document.querySelector('.sheet.open')) { dirty = true; return; }   // a sheet's opener must not be replaced under it
    dirty = false;
    var f = document.activeElement, mark = f && f.closest && f.closest('#id-list') ? f.getAttribute('aria-label') : null;
    renderList();
    if (renderOwners() || !$('nid-name').value) syncName();
    if (mark) Array.prototype.some.call($('id-list').querySelectorAll('button[aria-label]'), function (b) {   // the list was rebuilt under the focus: put it back
      if (b.getAttribute('aria-label') !== mark) return false;
      b.focus(); return true;
    });
  }
  function bind() {
    $('nid-kind').addEventListener('change', syncName);
    $('nid-owner').addEventListener('change', syncName);
    $('nid-user').addEventListener('input', syncName);
    $('nid-name').addEventListener('input', renderMintButton);
    amtc.bindWrite($('nid-mint'), function () {
      var name = $('nid-name').value.trim(), row = rowByName(name);
      return mintSpec(name, kindBySelect($('nid-kind').value), !!(row && row.status === 'present'));
    });
    $('nid-cancel').addEventListener('click', function () { intake = null; $('intake-value').value = ''; renderIntake(); clear($('nid-results')); syncName(); });
    $('intake-value').addEventListener('input', renderSendButton);
    $('intake-send').addEventListener('click', send);
    $('id-reread').addEventListener('click', function () {
      var btn = $('id-reread');
      if (btn.getAttribute('aria-disabled') === 'true') return;
      var done = S.busy(btn, 'asking amt-mcp');
      readAll().then(done, done);
    });
    var focus = $('new-focus');
    if (focus) focus.addEventListener('click', function () { $('new-panel').scrollIntoView({ block: 'start' }); $('nid-name').focus(); });
  }
  bind();
  renderAll();
  setInterval(function () { if (dirty) renderAll(); tick(); }, 1000);
  amtc.ready.then(readAll);
}());
