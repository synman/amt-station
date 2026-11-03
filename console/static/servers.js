/* The Servers page (design/servers.html, note 2.10): the servers amt-mcp serves, each with its pin and its identities, and the add form.
   Reads are amt_devices list (when the page opens and on Re-read), amt_identities (the identity chips) and the console's cached fleet
   (the pin state a status read found); Check pin is one amt_devices pin_check, made only when asked. Every change is amt_device_manage
   through a sheet from components.js: add and edit are plain, re-pin (repin: true) and remove are the hold, decided by the one
   predicate there. A tool's refusal is shown verbatim (text nodes only, never markup); the last server's Remove is greyed with its
   reason, and so is every action on a server whose presented leaf differs (the way out is Re-pin, after a Check pin). No value of any
   credential is a field here: an identity is chosen by NAME. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var page = document.getElementById('servers-page');
  if (!page) return;
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;
  var KEY = /^[a-z0-9][a-z0-9-]{0,62}$/, HEX64 = /^[0-9a-f]{64}$/;
  var NEW = '__new__', NONE = '__none__';

  // ---- state ----
  var devs = { list: null, source: null, error: null, readAt: null };   // amt_devices list
  var ids = { byName: null, error: null };                              // amt_identities list: name -> row
  var fleet = {};                                                       // server key -> the console's cached entry (its pin state)
  var checks = {};                                                      // server key -> the last pin check made on this page
  var dirty = false;

  // ---- reading ----
  var plain = function (v) { return typeof v === 'string' && v !== ''; };
  var port = function (v) { return typeof v === 'number' && v > 0 && v < 65536 && Math.floor(v) === v; };
  function deviceOk(d) {
    return d && plain(d.key) && KEY.test(d.key) && plain(d.amt_ip) && port(d.wsman_port) && port(d.kvm_port) && plain(d.amt_vault_key)
      && (d.host_vault_key === null || d.host_vault_key === undefined || plain(d.host_vault_key))
      && (d.tls_leaf_sha256 === null || d.tls_leaf_sha256 === undefined || HEX64.test(d.tls_leaf_sha256));
  }
  function readDevices() {
    return amtc.post('/api/call', { tool: 'amt_devices', arguments: { action: 'list' } }).then(function (r) {
      var b = r.body || {}, s = b.structured;
      if (r.status !== 200) devs.error = 'the console could not ask amt-mcp (' + (b.error || 'no answer') + ')';
      else if (b.isError) devs.error = b.text;
      else if (!s || !Array.isArray(s.devices) || !s.devices.every(deviceOk)) devs.error = 'amt-mcp\'s answer was not a readable list of servers';
      else { devs = { list: s.devices, source: s.source || null, error: null, readAt: Date.now() / 1000 }; }
    });
  }
  function readIdentities() {
    return amtc.post('/api/call', { tool: 'amt_identities', arguments: {} }).then(function (r) {
      var b = r.body || {}, s = b.structured;
      if (r.status !== 200) ids = { byName: null, error: 'the console could not ask amt-mcp (' + (b.error || 'no answer') + ')' };
      else if (b.isError) ids = { byName: null, error: b.text };
      else if (!s || !Array.isArray(s.identities)) ids = { byName: null, error: 'amt-mcp\'s answer was not a list of identities' };
      else {
        var by = {};
        s.identities.forEach(function (row) { if (row && plain(row.name)) by[row.name] = row; });
        ids = { byName: by, error: null };
      }
    });
  }
  function readFleet() {
    return S.get('/api/fleet').then(function (r) {
      if (r.status !== 200) return;
      fleet = {};
      (r.body.servers || []).forEach(function (e) { fleet[e.key] = e; });
    });
  }
  function readAll() { return Promise.all([readDevices(), readIdentities(), readFleet()]).then(renderAll); }
  // amt_identities lists the entries servers already name (and those entered here), not every entry in the vault: a name for a server not yet
  // added is the operator's to give, and amt-mcp refuses one that is not in its vault, in its own words.
  var presentNames = function () { return ids.byName ? Object.keys(ids.byName).filter(function (n) { return ids.byName[n].status === 'present'; }) : []; };

  // ---- results (design 7.4): the tool's own words, in the card of the action ----
  var stamp = function () { return S.eastern(Date.now() / 1000, false); };
  function addResult(slot, node) { slot.insertBefore(node, slot.firstChild); while (slot.children.length > 5) slot.removeChild(slot.lastChild); }
  var lead = function (what) { return h('strong', {}, [stamp() + ' · ' + what]); };
  function failure(what, r) {                                  // the console could not make the call, or amt-mcp did not answer
    var code = (r.body && r.body.error) || 'no answer';
    if (r.status === 502) return S.result('live', 'i-help', [lead(what), ' · amt-mcp did not answer (' + code + ') · it is not known whether the change was made; Re-read the servers before trying again']);
    return S.result('error', 'i-block', [lead(what), ' · refused: ' + code + ' · nothing sent']);
  }
  function reply(what, r, tail, ok) {                          // 200 + isError is a refusal by the tool; anything but 200 never reached it
    if (r.status !== 200) return failure(what, r);
    if (r.body.isError) return S.result('error', 'i-block', [lead(what), ' · refused: ' + r.body.text + tail]);
    return ok(r.body.structured || {});
  }

  // ---- what a server's pin is: the last check made here, else what the console's own status read found ----
  function pinOf(d) {
    if (!d.tls_leaf_sha256) return { kind: 'unpinned' };
    var c = checks[d.key];
    if (c && c.stored === d.tls_leaf_sha256) return { kind: c.matches ? 'matches' : 'differs', at: c.at, check: c };
    var f = fleet[d.key];
    return { kind: f && (f.pin === 'matches' || f.pin === 'differs') ? f.pin : 'unchecked' };
  }
  function pinChip(d, pin) {
    var chip = S.pinChip({ pin: pin.kind });
    if (pin.at) chip.appendChild(document.createTextNode(' · checked ' + S.eastern(pin.at, false)));
    if (pin.kind === 'matches' && pin.check && pin.check.repinned) chip.appendChild(document.createTextNode(' · re-pinned'));
    return chip;
  }
  function identityChips(d) {
    var box = [];
    var one = function (name) {
      var row = ids.byName && ids.byName[name];
      if (!ids.byName) return h('span', { class: 'chip small dashed', 'data-identity': 'unknown' }, [icon('i-help'), name + ' · status unknown']);
      if (row && row.status === 'present') return h('span', { class: 'chip small ok', 'data-identity': 'present' }, [icon('i-key'), name]);
      return h('span', { class: 'chip small error', 'data-identity': 'missing' }, [icon('i-block'), name + ' · missing']);
    };
    box.push(one(d.amt_vault_key));
    box.push(d.host_vault_key ? one(d.host_vault_key) : h('span', { class: 'chip small dashed', 'data-identity': 'none' }, ['no host logon']));
    return box;
  }

  // ---- the table ----
  function gated(label, reason, extra) {                       // a button that may be aria-disabled, with its reason as visible text beside it
    var b = h('button', { type: 'button', class: 'btn text' }, [label]);
    if (extra) Object.keys(extra).forEach(function (k) { b.setAttribute(k, extra[k]); });
    if (!reason) return { node: b, btn: b };
    b.setAttribute('aria-disabled', 'true');
    return { node: h('div', { class: 'btn-wrap' }, [b, h('span', { class: 'reason' }, [reason])]), btn: b };
  }
  function actionsCell(d, pin) {
    var td = h('td', { class: 'acts', 'data-l': 'Actions' }), differs = pin.kind === 'differs', n = devs.list.length;
    var why = 'the leaf it presents differs from the stored pin: re-pin first';
    var edit = gated('Edit', differs ? why : null, { 'aria-label': 'Edit ' + d.key });
    amtc.bindWrite(edit.btn, function () { return editSpec(d); });
    var check = h('button', { type: 'button', class: 'btn text', 'aria-label': 'Check pin ' + d.key }, ['Check pin']);
    check.addEventListener('click', function () { checkPin(d, check); });
    td.appendChild(edit.node); td.appendChild(check);
    if (differs) {
      var known = pin.check && !pin.check.matches;
      var rp = gated('Re-pin', known ? null : 'run Check pin: the sheet compares the leaf it presents now', { 'aria-label': 'Re-pin ' + d.key, 'data-action': 'repin' });
      amtc.bindWrite(rp.btn, function () { return repinSpec(d, pin.check); });
      td.appendChild(rp.node);
    }
    var rm = gated('Remove', n === 1 ? 'the last server: amt_device_manage refuses to remove it' : differs ? why : null, { 'aria-label': 'Remove ' + d.key });
    amtc.bindWrite(rm.btn, function () { return removeSpec(d); });
    td.appendChild(rm.node);
    return td;
  }
  function rowFor(d) {
    var pin = pinOf(d);
    var pinCell = h('td', { 'data-l': 'TLS pin' }, [h('div', { class: 'pincell' }, [pinChip(d, pin)].concat(d.tls_leaf_sha256 ? [S.fp(d.tls_leaf_sha256, d.tls_leaf_sha256.slice(0, 16))] : []))]);
    return h('tr', { 'data-key': d.key, 'data-pin-row': pin.kind }, [h('td', { class: 'data', 'data-l': 'Key' }, [d.key]), h('td', { class: 'data', 'data-l': 'AMT address' }, [d.amt_ip]),
      h('td', { class: 'data', 'data-l': 'Ports' }, [d.wsman_port + ' / ' + d.kvm_port]), h('td', { class: 'ids', 'data-l': 'Identities' }, identityChips(d)), pinCell, actionsCell(d, pin)]);
  }
  function renderTable() {
    var body = $('srv-rows'), note = $('srv-note'), count = $('srv-count');
    clear(body);
    if (!devs.list) {
      count.textContent = devs.error ? 'unreadable' : 'reading';
      note.textContent = devs.error ? 'The servers could not be read: ' + devs.error + ' · this is not an empty list.' : 'Reading the servers…';
      return;
    }
    devs.list.forEach(function (d) { body.appendChild(rowFor(d)); });
    var n = devs.list.length;
    count.textContent = n + (n === 1 ? ' server' : ' servers') + ' · ' + (devs.source === 'file' ? 'the devices file' : devs.source === 'built-in' ? 'the built-in registry' : 'source not reported') + ' · amt_devices';
    note.textContent = (devs.error ? 'The last re-read failed (' + devs.error + '); this is the list as read ' + S.eastern(devs.readAt, false) + '. ' : '')
      + (ids.error ? 'The identities could not be read (' + ids.error + '), so their chips say "status unknown". ' : '')
      + (devs.source === 'built-in' ? 'These servers are the built-in registry: amt_device_manage changes a devices file, and refuses while the server reads none. ' : '')
      + (n === 0 ? 'amt-mcp serves no server.' : '');
  }

  // ---- Check pin: one TLS handshake, no credential, only when asked ----
  function checkPin(d, btn) {
    if (btn.getAttribute('aria-disabled') === 'true') return;
    var done = S.busy(btn, 'one TLS handshake');
    amtc.post('/api/call', { tool: 'amt_devices', arguments: { action: 'pin_check', device: d.key } }).then(function (r) {
      done();
      var slot = $('srv-results'), what = 'pin check ' + d.key;
      if (r.status !== 200) { addResult(slot, S.readFailure(what, r)); return; }
      if (r.body.isError) { addResult(slot, S.readRefusal(what, r.body.text)); return; }
      var s = r.body.structured || {};
      if (!HEX64.test(s.presented || '') || !HEX64.test(s.stored || '') || typeof s.matches !== 'boolean' || s.matches !== (s.presented === s.stored)) {
        addResult(slot, S.result('error', 'i-help', [lead(what), ' · the answer was not a readable pin check (presented leaf, stored pin and verdict) · nothing was concluded']));
        return;
      }
      checks[d.key] = { at: Date.now() / 1000, matches: s.matches, presented: s.presented, stored: s.stored };
      addResult(slot, s.matches
        ? S.result('ok', 'i-verified', [lead(what), ' · the leaf presented by ' + d.amt_ip + ':' + d.wsman_port + ' matches the stored pin · one TLS handshake, no credential sent'])
        : S.result('error', 'i-warning', [lead(what), ' · ', h('strong', {}, [d.key]), ' presents TLS leaf ', S.fp(s.presented), ', not the stored pin ', S.fp(s.stored, s.stored.slice(0, 16)),
          '. Every call to it is refused until you re-pin. Compare the new fingerprint with what MEBx shows before accepting it: a changed leaf is either a re-provisioned AMT or something between you and it.']));
      renderAll();
    }, done);
  }

  // ---- the sheets ----
  var looksLikeAddress = function (v) {
    var m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(v);
    if (m) return m.slice(1).every(function (o) { return +o <= 255; });
    return /^[0-9a-fA-F:.]+$/.test(v) && (v.match(/:/g) || []).length >= 2;
  };
  var portText = function (v) { return /^\d{1,5}$/.test(v) && +v >= 1 && +v <= 65535; };

  function editSpec(d) {
    return { id: 'sheet-srv-edit', title: 'Edit ' + d.key, verb: 'Save', call: { tool: 'amt_device_manage', arguments: { action: 'edit', device: d.key } },
      consequence: 'Changes the address, ports or identity names. A changed address or WS-MAN port re-reads the TLS leaf; a different one is refused unless you re-pin, which is a separate hold. amt-mcp keeps the previous devices file as .prev-devices.json.',
      fields: [{ name: 'ip', label: 'AMT address', value: d.amt_ip, mono: true }, { name: 'wsman_port', label: 'WS-MAN port', value: String(d.wsman_port), mono: true },
        { name: 'kvm_port', label: 'KVM port', value: String(d.kvm_port), mono: true }, { name: 'amt_vault_key', label: 'AMT identity (vault entry name)', value: d.amt_vault_key, mono: true },
        { name: 'host_vault_key', label: 'Host logon identity (vault entry name; empty for none)', value: d.host_vault_key || '', mono: true }],
      build: function (v) {
        var ip = (v.ip || '').trim(), ws = (v.wsman_port || '').trim(), kv = (v.kvm_port || '').trim(), amt = (v.amt_vault_key || '').trim(), host = (v.host_vault_key || '').trim();
        if (!looksLikeAddress(ip)) return { error: 'an IP address, never a host name' };
        if (!portText(ws) || !portText(kv)) return { error: 'ports are whole numbers 1 to 65535' };
        if (!KEY.test(amt)) return { error: 'the AMT identity is the name of a vault entry' };
        if (host && !KEY.test(host)) return { error: 'the host logon is the name of a vault entry, or empty for none' };
        var args = { action: 'edit', device: d.key }, changed = false, set = function (k, val) { args[k] = val; changed = true; };
        if (ip !== d.amt_ip) set('ip', ip);
        if (+ws !== d.wsman_port) set('wsman_port', +ws);
        if (+kv !== d.kvm_port) set('kvm_port', +kv);
        if (amt !== d.amt_vault_key) set('amt_vault_key', amt);
        if (host !== (d.host_vault_key || '')) { if (host) set('host_vault_key', host); else set('clear_host', true); }
        return changed ? { call: { tool: 'amt_device_manage', arguments: args } } : { error: 'change at least one field' };
      },
      onResult: function (r) {
        addResult($('srv-results'), reply('edit ' + d.key, r, ' · nothing was written', function (s) {
          var e = s.edited || {};
          return S.result('ok', 'i-check', [lead('edit ' + d.key), ' · saved · now ' + e.amt_ip + ' · ports ' + e.wsman_port + ' / ' + e.kvm_port + ' · live at the next tool call']);
        }));
        readAll();
      } };
  }
  function removeSpec(d) {
    return { id: 'sheet-srv-remove', title: 'Remove ' + d.key, verb: 'remove', nowLabel: 'Remove now', call: { tool: 'amt_device_manage', arguments: { action: 'remove', device: d.key } },
      consequence: 'Removes the server from amt-mcp\'s devices file; every tool then refuses it. Its vault entries stay until you remove them in Identities. amt-mcp refuses to remove the last server.',
      onResult: function (r) {
        addResult($('srv-results'), reply('remove ' + d.key, r, ' · nothing was removed', function (s) {
          return S.result('ok', 'i-check', [lead('remove ' + d.key), ' · removed · servers now: ' + ((s.devices || []).join(', ') || 'none')]);
        }));
        readAll();
      } };
  }
  function repinSpec(d, check) {
    var presented = check.presented;
    return { id: 'sheet-srv-repin', title: 'Accept the new TLS leaf of ' + d.key, verb: 're-pin', nowLabel: 'Re-pin now', call: { tool: 'amt_device_manage', arguments: { action: 'edit', device: d.key, repin: true } },
      consequence: 'Replaces the stored pin with the leaf the server presents when the request is made. If the leaf changed because something sits between the console and the server, you are pinning the wrong party: compare with MEBx first.',
      detail: function () {
        var dl = h('dl', { class: 'kv' });
        dl.appendChild(h('dt', {}, ['Stored'])); dl.appendChild(h('dd', {}, [S.fp(check.stored, check.stored.slice(0, 16))]));
        dl.appendChild(h('dt', {}, ['Presented at the check'])); dl.appendChild(h('dd', {}, [S.fp(presented)]));
        return dl;
      },
      onResult: function (r) {
        addResult($('srv-results'), reply('re-pin ' + d.key, r, ' · the stored pin is unchanged', function (s) {
          var e = s.edited || {}, pinned = e.tls_leaf_sha256;
          if (!HEX64.test(pinned || '')) return S.result('live', 'i-help', [lead('re-pin ' + d.key), ' · accepted, but the answer did not name the pin now stored; Check pin to read it']);
          checks[d.key] = { at: Date.now() / 1000, matches: true, presented: pinned, stored: pinned, repinned: true };
          var parts = [lead('re-pin ' + d.key), ' · the stored pin is now ', S.fp(pinned, pinned.slice(0, 16)), ' · every call to it is allowed again'];
          if (pinned !== presented) parts.push(' · this is NOT the leaf you compared at the check (', S.fp(presented), '): it changed between the check and the re-pin; compare the stored pin with MEBx');
          return S.result(pinned === presented ? 'ok' : 'error', pinned === presented ? 'i-verified' : 'i-warning', parts);
        }));
        readAll();
      } };
  }

  // ---- the add panel ----
  function fillIdentitySelect(sel, key, optional) {
    var names = presentNames(), want = sel.getAttribute('data-want') || sel.value;
    clear(sel);
    if (optional) sel.appendChild(h('option', { value: NONE }, ['none']));
    sel.appendChild(h('option', { value: NEW }, ['new entry: ' + (key || '<key>') + (optional ? '-host' : '-amt') + ' (must exist in the vault first)']));
    names.forEach(function (n) { sel.appendChild(h('option', { value: n }, ['use existing · ' + n])); });
    sel.value = Array.prototype.some.call(sel.options, function (o) { return o.value === want; }) ? want : (optional ? NONE : NEW);
    sel.removeAttribute('data-want');
  }
  function addValues() {
    var key = $('add-key').value.trim();
    return { key: key, ip: $('add-ip').value.trim(), ws: $('add-wsman').value.trim(), kvm: $('add-kvm').value.trim(), amt: $('add-amt').value, host: $('add-host').value, pin: $('add-pin').value.trim() };
  }
  function entryName(choice, key, suffix) { return choice === NEW ? key + suffix : choice; }
  function addProblem(v) {
    if (!KEY.test(v.key)) return 'a key is lowercase letters, digits and dashes';
    if (devs.list && devs.list.some(function (d) { return d.key === v.key; })) return 'a server with this key exists: edit it';
    if (!looksLikeAddress(v.ip)) return 'an IP address, never a host name';
    if (!portText(v.ws) || !portText(v.kvm)) return 'ports are whole numbers 1 to 65535';
    if (v.pin && !HEX64.test(v.pin.toLowerCase())) return 'the expected pin is 64 hex characters';
    return null;
  }
  function addSpec() {
    var v = addValues(), args = { action: 'add', device: v.key, ip: v.ip, wsman_port: +v.ws, kvm_port: +v.kvm, amt_vault_key: entryName(v.amt, v.key, '-amt') };
    if (v.host !== NONE) args.host_vault_key = entryName(v.host, v.key, '-host');
    if (v.pin) args.expected_pin = v.pin.toLowerCase();
    return { id: 'sheet-srv-add', title: 'Add the server ' + v.key, verb: 'Add server', call: { tool: 'amt_device_manage', arguments: args },
      callNote: 'then amt_status {device: "' + v.key + '"}',
      consequence: 'Records the TLS leaf the server presents now as its pin' + (v.pin ? ' (or refuses when it is not the expected pin)' : ' (trust on first use)') + ', writes the devices file through amt-mcp, and reads the server\'s status once. Every later call to this server is refused if its leaf changes. The named identities must already exist in amt-mcp\'s vault.',
      onResult: function (r) { addResult($('add-results'), reply('add ' + v.key, r, ' · nothing was written', function (s) { return added(v, s); })); readAll().then(function () { if (r.status === 200 && !r.body.isError) proveStatus(v.key); }); } };
  }
  function added(v, s) {
    var d = s.added || {}, pin = d.tls_leaf_sha256;
    var how = v.pin ? 'the expected pin you gave' : 'the leaf the server presented during the add (trust on first use)';
    var parts = [lead('add ' + v.key), ' · added · ' + (d.amt_ip || v.ip) + ' · pinned to '];
    if (HEX64.test(pin || '')) parts.push(S.fp(pin, pin.slice(0, 16)), ' (' + how + '): compare it with what MEBx shows');
    else parts.push('a leaf the answer did not name');
    resetAdd();
    return S.result('ok', 'i-check', parts);
  }
  function proveStatus(key) {
    amtc.post('/api/call', { tool: 'amt_status', arguments: { device: key } }).then(function (r) {
      var what = 'amt_status ' + key, slot = $('add-results');
      if (r.status !== 200) addResult(slot, S.readFailure(what, r));
      else if (r.body.isError) addResult(slot, S.readRefusal(what, r.body.text));
      else addResult(slot, S.result('ok', 'i-verified', [lead(what), ' · succeeded · the server answers with the identities it names']));
    });
  }
  function resetAdd() {
    ['add-key', 'add-ip', 'add-pin'].forEach(function (id) { $(id).value = ''; });
    $('add-wsman').value = '16993'; $('add-kvm').value = '16995';
    $('add-amt').setAttribute('data-want', NEW); $('add-host').setAttribute('data-want', NONE);
  }
  function renderAdd() {
    var v = addValues();
    fillIdentitySelect($('add-amt'), v.key, false); fillIdentitySelect($('add-host'), v.key, true);
    var wrap = $('add-wrap'), btn = $('add-go'), why = addProblem(addValues()), old = wrap.querySelector('.reason');
    if (old) old.remove();
    if (why) { btn.setAttribute('aria-disabled', 'true'); wrap.appendChild(h('span', { class: 'reason' }, [why])); }
    else btn.removeAttribute('aria-disabled');
  }

  // ---- the page ----
  function renderAll() {
    if (document.querySelector('.sheet.open')) { dirty = true; return; }   // a sheet's opener must not be replaced under it
    dirty = false;
    var f = document.activeElement, mark = f && f.closest && f.closest('#srv-rows') ? f.getAttribute('aria-label') : null;
    renderTable();
    renderAdd();
    if (mark) Array.prototype.some.call($('srv-rows').querySelectorAll('button[aria-label]'), function (b) {   // the table was rebuilt under the focus: put it back
      if (b.getAttribute('aria-label') !== mark) return false;
      b.focus(); return true;
    });
  }
  function bind() {
    amtc.bindWrite($('add-go'), addSpec);
    ['add-key', 'add-ip', 'add-wsman', 'add-kvm', 'add-pin'].forEach(function (id) { $(id).addEventListener('input', renderAdd); });
    ['add-amt', 'add-host'].forEach(function (id) { $(id).addEventListener('change', renderAdd); });
    $('add-cancel').addEventListener('click', function () { resetAdd(); clear($('add-results')); renderAdd(); });
    var focus = document.getElementById('add-focus');
    if (focus) focus.addEventListener('click', function () { $('add-panel').scrollIntoView({ block: 'start' }); $('add-key').focus(); });
    $('srv-reread').addEventListener('click', function () {
      var btn = $('srv-reread');
      if (btn.getAttribute('aria-disabled') === 'true') return;
      var done = S.busy(btn, 'asking amt-mcp');
      readAll().then(done, done);
    });
  }
  bind();
  renderAll();
  setInterval(function () { if (dirty) renderAll(); }, 1000);
  amtc.ready.then(readAll);
}());
