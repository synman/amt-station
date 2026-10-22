/* The AMT settings tab (design/settings.html, note 2.12): the ten settings areas through amt_settings, the six that amt_configure writes with an
   old / new preview, the write sheet and Revert, the AMT accounts with vaulted passwords, and the four read-only areas pointing at Advanced.
   A read happens when the page opens, on an area switch and on Re-read, never on a timer and never for a paused server. A write is a sheet from
   components.js (the call shown is the call sent, with confirmed: true); no password is a field here, and a credential-named field the tool
   refuses is shown as the tool said it. Everything from the host or the tool is set as text nodes only. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var head = document.querySelector('.srvhead[data-server]'), page = document.getElementById('settings-page');
  if (!head || !page) return;
  var key = head.getAttribute('data-server'), POLL_MS = 5000;
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;

  // ---- the tables the page shares with the tools (console/tests pins each to amt_write and amt_tools) ----
  // The six areas amt_configure writes: where the fields sit in the amt_settings read, and each field's kind (bool, int, str, strlist).
  var AREAS = {
    network: { section: 'general', fields: [{ n: 'HostName', t: 'str' }, { n: 'DomainName', t: 'str' }, { n: 'SharedFQDN', t: 'bool' }, { n: 'PingResponseEnabled', t: 'bool' },
      { n: 'RmcpPingResponseEnabled', t: 'bool' }, { n: 'DDNSUpdateEnabled', t: 'bool' }, { n: 'DDNSPeriodicUpdateInterval', t: 'int' }, { n: 'DDNSTTL', t: 'int' }, { n: 'IdleWakeTimeout', t: 'int' }] },
    internet: { section: 'environment_detection', fields: [{ n: 'DetectionAlgorithm', t: 'int' }, { n: 'DetectionStrings', t: 'strlist' }] },
    security: { section: 'tls', pick: 'Intel(r) AMT 802.3 TLS Settings', fields: [{ n: 'AcceptNonSecureConnections', t: 'bool' }] },
    kvm: { section: 'settings', fields: [{ n: 'Is5900PortEnabled', t: 'bool' }, { n: 'OptInPolicy', t: 'bool' }, { n: 'SessionTimeout', t: 'int' }] },
    features: { fields: [{ n: 'ider_enabled', t: 'bool' }, { n: 'sol_enabled', t: 'bool' }, { n: 'kvm_enabled', t: 'bool' }] }
  };
  var READ_ONLY = ['agent_presence', 'system_defense', 'subscriptions', 'wake_alarms'];
  var SECTIONS = {                                   // what a read of each area returns, in the tool's order
    network: ['ethernet_ports', 'general'], internet: ['mps_servers', 'remote_access_policy_rules', 'environment_detection'],
    security: ['tls', 'certificates', 'authorization'], agent_presence: ['watchdogs', 'capabilities'], system_defense: ['policies', 'service'],
    subscriptions: ['filter_subscriptions', 'indication_filters'], wake_alarms: ['service', 'occurrences'],
    kvm: ['redirection_sap', 'settings', 'opt_in'], features: ['redirection_service', 'kvm_sap', 'opt_in', 'setup'], users: ['users']
  };
  var REDIRECTION = { 32768: [false, false], 32769: [true, false], 32770: [false, true], 32771: [true, true] };   // AMT_RedirectionService.EnabledState -> [ider, sol]
  var KVM_ENABLED = [2, 6];                                                                                     // CIM_KVMRedirectionSAP.EnabledState values that mean enabled
  var RISKY = [['kvm', 'OptInPolicy', false, 'turns OFF user consent for remote KVM sessions'], ['kvm', 'Is5900PortEnabled', true, 'opens the unencrypted VNC port 5900'],
    ['security', 'AcceptNonSecureConnections', true, 'accepts non-TLS (plaintext) connections to AMT'], ['features', 'ider_enabled', true, 'enables IDE redirection'],
    ['features', 'sol_enabled', true, 'enables Serial-over-LAN'], ['features', 'kvm_enabled', true, 'enables KVM redirection']];
  var USER_NAME = /^[A-Za-z0-9_.@-]{1,16}$/;
  var U32 = 4294967295;
  var KIND_SAY = { bool: 'on or off', int: 'a whole number from 0 to ' + U32, str: '1 to 256 printable characters', strlist: '1 to 16 lines, each 1 to 256 printable characters' };

  amtc.settings = { AREAS: AREAS, READ_ONLY: READ_ONLY, SECTIONS: SECTIONS, RISKY: RISKY, REDIRECTION: REDIRECTION, KVM_ENABLED: KVM_ENABLED };   // read by the tests that pin these to the tools

  var st = { area: 'kvm', busy: false, writing: false, again: false, deferred: false, paused: null, gone: false, view: null, raw: {}, idents: null, results: {} };
  var ctl = { reread: { btn: $('set-reread'), wrap: $('set-reread-wrap'), reason: null } };
  var gates = [];                       // { btn, wrap, reason, why() } for the controls of the drawn card
  var revertGates = [];                 // the Revert buttons in the results, which outlive a redraw
  var chips = {};
  document.querySelectorAll('#set-areas [data-area]').forEach(function (c) { chips[c.getAttribute('data-area')] = c; });
  var isObj = function (v) { return v !== null && typeof v === 'object' && !Array.isArray(v); };
  var writable = function (area) { return !!AREAS[area] || area === 'users'; };

  function gate(btn, why) {
    var wrap = h('div', { class: 'btn-wrap' }, []);
    btn.parentNode.insertBefore(wrap, btn); wrap.appendChild(btn);
    var g = { btn: btn, wrap: wrap, reason: null, why: why };
    gates.push(g);
    return g;
  }
  function pausedWhy() { return st.paused ? 'paused · ' + (st.paused.reason || 'refused') : st.writing ? 'waiting for amt-mcp' : null; }
  function controls() {
    S.setReason(ctl.reread, st.paused ? 'paused · ' + (st.paused.reason || 'refused') : st.busy || st.writing ? 'waiting for amt-mcp' : null);
    gates.concat(revertGates).forEach(function (g) { S.setReason(g, g.why()); });
    Object.keys(chips).forEach(function (a) {
      chips[a].setAttribute('aria-pressed', String(a === st.area));
      chips[a].classList.toggle('selected', a === st.area);
    });
  }
  function banner() {
    var box = $('set-paused'), text = $('set-paused-text');
    clear(text);
    box.hidden = !st.paused;
    if (st.paused) S.pausedNote('the AMT settings', key, st.paused).forEach(function (n) { text.appendChild(typeof n === 'string' ? document.createTextNode(n) : n); });
  }

  // ---- a result the page can trust: the area it asked for, its sections and the coverage lists are all there ----
  function unreadable(s, area) {
    if (!isObj(s)) return 'no result object';
    var bad = [];
    if (s.area !== area) bad.push('area');
    if (!isObj(s.sections)) bad.push('sections');
    if (!isObj(s.classes)) bad.push('classes');
    if (!Array.isArray(s.unavailable)) bad.push('unavailable');
    if (!Array.isArray(s.truncated)) bad.push('truncated');
    if (bad.length) return 'missing or wrong: ' + bad.join(', ');
    var lost = SECTIONS[area].filter(function (n) { return s.sections[n] === undefined; });
    if (lost.length) bad.push('sections not returned: ' + lost.join(', '));
    if (area === 'users' && !Array.isArray(s.sections.users)) bad.push('users is not a list');
    return bad.length ? bad.join('; ') : null;
  }

  // ---- the current value of each writable field, as the tool read it (undefined = not reported, or not the kind the field has) ----
  function ofKind(t, v) {
    if (t === 'bool') return typeof v === 'boolean' ? v : undefined;
    if (t === 'int') return typeof v === 'number' && isFinite(v) && Math.floor(v) === v ? v : undefined;
    if (t === 'str') return typeof v === 'string' ? v : undefined;
    if (typeof v === 'string') return [v];                                     // one repeated element comes back as a bare string
    return Array.isArray(v) && v.every(function (x) { return typeof x === 'string'; }) ? v : undefined;
  }
  function currents(area, s) {
    var spec = AREAS[area], out = {};
    if (area === 'features') {
      var rs = s.sections.redirection_service, sap = s.sections.kvm_sap, pair = isObj(rs) ? REDIRECTION[rs.EnabledState] : undefined;
      out.ider_enabled = pair ? pair[0] : undefined; out.sol_enabled = pair ? pair[1] : undefined;
      out.kvm_enabled = isObj(sap) && typeof sap.EnabledState === 'number' ? KVM_ENABLED.indexOf(sap.EnabledState) !== -1 : undefined;
      return out;
    }
    var sec = s.sections[spec.section];
    if (spec.pick) sec = (Array.isArray(sec) ? sec : []).filter(function (i) { return isObj(i) && i.InstanceID === spec.pick; })[0];
    spec.fields.forEach(function (f) { out[f.n] = isObj(sec) ? ofKind(f.t, sec[f.n]) : undefined; });
    return out;
  }

  // ---- what the form holds: parsed per kind with the tool's own limits (amt_write._check_value) ----
  function show(v) { return Array.isArray(v) ? v.join(', ') : v === '' ? 'empty' : String(v); }
  // str.isprintable() is false for every Other and Separator character except the ASCII space, and the length is in code points, not UTF-16 units
  function printable(x) { var n = Array.from(x).length; return n > 0 && n <= 256 && !/[\p{C}\p{Z}]/u.test(x.replace(/ /g, '')); }
  function parse(f, raw) {
    if (f.t === 'bool') return { ok: true, value: raw === true };
    var text = String(raw);
    if (f.t === 'int') return /^\d{1,10}$/.test(text.trim()) && Number(text.trim()) <= U32 ? { ok: true, value: Number(text.trim()) } : { ok: false, why: 'must be ' + KIND_SAY.int };
    if (f.t === 'str') return printable(text) ? { ok: true, value: text } : { ok: false, why: 'must be ' + KIND_SAY.str };
    var lines = text.split('\n').map(function (l) { return l.replace(/\r$/, ''); }).filter(function (l) { return l !== ''; });
    return lines.length >= 1 && lines.length <= 16 && lines.every(printable) ? { ok: true, value: lines } : { ok: false, why: 'must be ' + KIND_SAY.strlist };
  }
  function same(a, b) { return Array.isArray(a) ? Array.isArray(b) && a.length === b.length && a.every(function (x, i) { return x === b[i]; }) : a === b; }
  function form() {                                    // { changes, invalid: [field: why], rows: [{ f, cur, after, changed, bad }] }
    var v = st.view, area = st.area, out = { changes: {}, invalid: [], rows: [] };
    AREAS[area].fields.forEach(function (f) {
      var cur = v.cur[f.n], raw = st.raw[f.n], p = cur === undefined || raw === undefined ? { ok: true, value: cur } : parse(f, raw);   // a field nobody touched is not judged
      var changed = cur !== undefined && raw !== undefined && p.ok && !same(p.value, cur);
      if (!p.ok) out.invalid.push(f.n + ' ' + p.why);
      if (changed) out.changes[f.n] = p.value;
      out.rows.push({ f: f, cur: cur, after: p, changed: changed });
    });
    return out;
  }
  function seed(f, cur) { return f.t === 'bool' ? cur : f.t === 'strlist' ? cur.join('\n') : String(cur); }

  // ---- reading ----
  function read() {
    if (st.busy) { st.again = true; return Promise.resolve(); }
    if (st.writing) { st.deferred = true; return Promise.resolve(); }                // asked for while a write is out: the write's end reads it (settled)
    if (st.paused || st.gone) return Promise.resolve();
    var area = st.area, args = { device: key, area: area };
    st.busy = true; st.view = null; st.raw = {}; st.idents = null; gates = [];
    clear($('set-state')); $('set-banner').hidden = true;
    $('set-state').appendChild(h('div', { class: 'progress', role: 'progressbar', 'aria-label': 'Reading the ' + area + ' settings' }, [h('i', { 'data-motion': 'progress' })]));
    controls();
    return amtc.post('/api/call', { tool: 'amt_settings', arguments: args }).catch(function () { return { status: 0, body: {} }; })
      .then(function (r) {
        if (area !== st.area) { st.busy = false; return null; }                    // the operator moved on while it was out
        return outcome(r, args).then(function () { st.busy = false; draw(); return loadEntry(); });
      }).then(function () { if (st.again) { st.again = false; read(); } });
  }
  function outcome(r, args) {                                                         // resolves once the identity read of the users area (if any) is in
    var slot = $('set-state'), b = r.body || {}, what = 'read the ' + args.area + ' settings';
    clear(slot);
    if (r.status !== 200) slot.appendChild(S.readFailure(what, r));
    else if (b.isError) slot.appendChild(S.readRefusal(what, b.text));
    else {
      var bad = unreadable(b.structured, args.area);
      if (bad) slot.appendChild(S.result('error', 'i-block', [S.stamp() + ' · ' + what + ' · amt-mcp returned a result this page cannot read (' + bad + '), so no coverage is claimed and nothing is offered to write']));
      else {
        st.view = { s: b.structured, args: args, at: Date.now() / 1000, cur: AREAS[args.area] ? currents(args.area, b.structured) : {} };
        if (args.area === 'users') return readIdentities();
      }
    }
    return Promise.resolve();
  }
  function readIdentities() {                                                         // which vault entries exist, so a missing password identity is said before Add is offered
    return amtc.post('/api/call', { tool: 'amt_identities', arguments: { device: key } }).catch(function () { return { status: 0, body: {} }; }).then(function (r) {
      var b = r.body || {}, rows = b.structured && b.structured.identities;
      if (r.status !== 200 || b.isError || !Array.isArray(rows)) { st.idents = { error: r.status !== 200 ? ((b.error) || 'no answer') : b.isError ? b.text : 'no list reported' }; return; }
      st.idents = { present: rows.filter(function (x) { return x && x.status === 'present' && typeof x.name === 'string'; }).map(function (x) { return x.name; }) };
    });
  }

  // ---- drawing ----
  function coverage(s, area) {                                                         // immutable 19: from the result's own lists
    var why = isObj(s.unavailable_reasons) ? s.unavailable_reasons : {}, parts = [], live = false, n = SECTIONS[area].length;
    s.unavailable.forEach(function (cls) { parts.push(cls + ' is unavailable: ' + (typeof why[cls] === 'string' ? why[cls] : 'the tool gave no reason') + ', so its section is empty.'); });
    if (s.truncated.length) { live = true; parts.push(s.truncated.join(', ') + ' was cut at the item cap: more exist than were read.'); }
    else parts.push('Nothing was truncated.');
    if (!s.unavailable.length) parts.unshift(n === 1 ? 'The 1 section of this area was read.' : 'All ' + n + ' sections of this area were read.');
    return { text: parts.join(' '), live: live };
  }
  function draw() {
    gates = [];
    controls();
    var v = st.view, cards = $('set-cards'), box = $('set-banner');
    clear(cards); box.hidden = true; $('set-call').textContent = '';
    $('set-note').textContent = v ? 'amt_settings · read ' + S.eastern(v.at, false) : 'amt_settings · not read yet';
    if (!v) return;
    var cov = coverage(v.s, st.area), text = $('set-banner-text');
    clear(text);
    text.appendChild(h('strong', {}, ['Coverage:']));
    text.appendChild(document.createTextNode(' ' + cov.text));
    box.className = 'banner' + (cov.live ? ' live' : '');
    box.hidden = false;
    if (st.area === 'users') cards.appendChild(usersCard());
    else if (AREAS[st.area]) { cards.appendChild(areaCard()); cards.appendChild(sectionsCard()); }
    else cards.appendChild(readOnlyCard());
    $('set-call').textContent = amtc.fmtCall({ tool: 'amt_settings', arguments: v.args }) + ' · read-only · amt_configure {device, area, changes, confirmed: true} writes: the whole instance is read, merged, written and read back; a collateral change raises and `previous` is kept';
    controls();
  }
  function resultsSlot(area) {
    var slot = h('div', { class: 'col gap8', 'data-results': area, 'aria-live': 'polite' }, []);
    (st.results[area] || []).forEach(function (n) { slot.appendChild(n); });
    return slot;
  }
  function addResult(area, node) {
    var list = st.results[area] = st.results[area] || [];
    list.unshift(node);
    while (list.length > 5) { var old = list.pop(); if (old.parentNode) old.parentNode.removeChild(old); }
    var slot = document.querySelector('[data-results="' + area + '"]');
    if (slot) slot.insertBefore(node, slot.firstChild);
  }

  // ---- the writable area ----
  function areaCard() {
    var area = st.area, spec = AREAS[area], v = st.view;
    var card = h('div', { class: 'card', id: 'set-card', 'data-area': area }, []);
    card.appendChild(h('h2', {}, [icon('i-settings'), area]));
    card.appendChild(h('p', { class: 'body-s muted m0' }, [Object.keys(v.s.classes).map(function (n) { return v.s.classes[n]; }).join(' + ')]));
    var list = h('div', { class: 'list' }, []), inputs = {}, helps = {}, boxes = {};
    spec.fields.forEach(function (f) {
      var cur = v.cur[f.n], risk = RISKY.filter(function (x) { return x[0] === area && x[1] === f.n; })[0];
      if (f.t === 'bool') {
        var sw = h('span', { class: 'switch', role: 'switch', tabindex: '0', 'aria-checked': String(cur === true), 'data-field': f.n }, [h('span', { class: 'trk' }),
          h('span', { class: 'txt' }, [h('span', {}, [f.n]), h('span', { class: 'sub' + (risk ? ' warn' : '') }, [cur === undefined ? 'not reported by AMT, so it is not offered' : risk ? 'weakens access when ' + risk[2] + ': ' + risk[3] : 'on or off'])])]);
        if (cur === undefined) sw.setAttribute('aria-disabled', 'true');
        inputs[f.n] = sw;
        var flip = function () { if (sw.getAttribute('aria-disabled') === 'true') return; st.raw[f.n] = sw.getAttribute('aria-checked') !== 'true'; sw.setAttribute('aria-checked', String(st.raw[f.n])); update(); };
        sw.addEventListener('click', flip);
        sw.addEventListener('keydown', function (e) { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); if (!e.repeat) flip(); } });
        list.appendChild(sw);
        return;
      }
      var id = 'set-f-' + f.n, input = f.t === 'strlist' ? h('textarea', { id: id, class: 'mono', 'data-field': f.n, spellcheck: 'false', autocomplete: 'off' }, [])
        : h('input', { id: id, class: 'mono', 'data-field': f.n, spellcheck: 'false', autocomplete: 'off', inputmode: f.t === 'int' ? 'numeric' : null }, []);
      input.value = cur === undefined ? '' : seed(f, cur);
      var help = h('span', { class: 'help' }, [cur === undefined ? 'not reported by AMT, so it is not offered' : 'must be ' + KIND_SAY[f.t]]);
      if (cur === undefined) { input.readOnly = true; input.setAttribute('aria-disabled', 'true'); }
      inputs[f.n] = input; helps[f.n] = help;
      input.addEventListener('input', function () { if (cur !== undefined) { st.raw[f.n] = input.value; update(); } });
      boxes[f.n] = h('div', { class: 'field', id: 'set-field-' + f.n }, [h('label', { for: id }, [f.n]), input, help]);
      list.appendChild(boxes[f.n]);
    });
    card.appendChild(list);
    var diff = h('div', { class: 'diff', 'aria-label': 'Preview of the write' }, [h('span', { class: 'h' }, ['Field']), h('span', { class: 'h' }, ['Current']), h('span', { class: 'h' }, ['After'])]), cells = {};
    spec.fields.forEach(function (f) {
      var a = h('span', { class: 'data' }, []), b = h('span', { class: 'data' }, []);
      cells[f.n] = { cur: a, after: b };
      diff.appendChild(h('span', { class: 'data' }, [f.n])); diff.appendChild(a); diff.appendChild(b);
    });
    card.appendChild(diff);
    var write = h('button', { type: 'button', class: 'btn filled', id: 'set-write' }, ['Write ' + area]), discard = h('button', { type: 'button', class: 'btn text', id: 'set-discard' }, ['Discard']);
    card.appendChild(h('div', { class: 'row' }, [write, discard]));
    var slot = resultsSlot(area);
    card.appendChild(slot);
    card.appendChild(h('p', { class: 'body-s muted m0' }, [area === 'features'
      ? 'amt_configure {area: features, changes} requests the redirection and KVM states, then reads them back; `previous` is kept for revert.'
      : 'amt_configure {area, changes}: the whole instance is read, merged, written and read back; a collateral change raises and `previous` is kept for revert. No password is sent from this form.']));
    var gw = gate(write, function () {
      var f = form();
      return pausedWhy() || (f.invalid.length ? f.invalid[0] : !Object.keys(f.changes).length ? 'nothing changed' : null);
    });
    var gd = gate(discard, function () { return Object.keys(st.raw).length ? null : 'nothing to discard'; });
    amtc.bindWrite(write, writeSpec);
    discard.addEventListener('click', function () { if (discard.getAttribute('aria-disabled') === 'true') return; st.raw = {}; draw(); });
    function update() {
      var f = form();
      f.rows.forEach(function (row) {
        var n = row.f.n, c = cells[n];
        c.cur.textContent = row.cur === undefined ? 'not reported' : show(row.cur);
        c.after.textContent = row.cur === undefined ? 'not offered' : !row.after.ok ? 'invalid' : row.changed ? show(row.after.value) : show(row.cur) + ' (unchanged)';
        c.after.classList.toggle('new', row.changed);
        if (boxes[n]) { boxes[n].classList.toggle('err', row.cur !== undefined && !row.after.ok); helps[n].textContent = row.cur === undefined ? 'not reported by AMT, so it is not offered' : row.after.ok ? 'must be ' + KIND_SAY[row.f.t] : row.f.n + ' ' + row.after.why; }
      });
      controls();
    }
    update();
    return card;
  }
  function riskLines(area, changes) {
    return RISKY.filter(function (x) { return x[0] === area && Object.prototype.hasOwnProperty.call(changes, x[1]) && changes[x[1]] === x[2]; })
      .map(function (x) { return 'THIS REQUEST ' + x[3] + '.'; });
  }
  function writeSpec() {
    var area = st.area, f = form(), ch = f.changes;
    var said = f.rows.filter(function (r) { return r.changed; }).map(function (r) { return r.f.n + ' changes from ' + show(r.cur) + ' to ' + show(r.after.value); }).join('; ') + '.';
    var how = area === 'features'
      ? 'The current redirection and KVM states are read, the change is requested, and the states are read back; the previous values are kept for revert.'
      : 'The whole instance is read, merged, written and read back; if anything else changed, the call raises and the previous values are kept for revert.';
    return { id: 'set-write-sheet', title: 'Write ' + area + ' settings of ' + key, verb: 'Write',
      consequence: [said].concat(riskLines(area, ch), [how + ' No password is sent from this form.']).join(' '),
      call: { tool: 'amt_configure', arguments: { device: key, area: area, changes: ch } }, onResult: function (r) { wrote(area, ch, r); } };
  }

  // ---- results (design 7.4): the tool's own words, in the card of the area ----
  var NOT_SENT = /secret_field_refused|unknown_field|invalid_value|unknown_settings_area|area_not_writable_by_this_tool|changes_must_be_a_nonempty_object|users_changes_need|users_username_invalid_or_admin|users_add_needs|users_no_such_user|users_user_exists|configure_instance_not_round_trippable/;
  var SENT = /configure_(readback_mismatch|collateral_change)/;
  function lead(what) { return h('strong', {}, [S.stamp() + ' · ' + what]); }
  function lit(o) { return '{' + Object.keys(o).map(function (k) { return k + ': ' + (Array.isArray(o[k]) ? '[' + o[k].join(', ') + ']' : JSON.stringify(o[k])); }).join(', ') + '}'; }
  function failure(what, r) {                                       // the console could not make the call, or amt-mcp did not answer
    var code = (r.body && r.body.error) || 'no answer';
    if (r.status === 502) return S.result('live', 'i-help', [lead(what), ' · amt-mcp did not answer (' + code + ') · it is not known whether the request was sent; the area is re-read below']);
    return S.result('error', 'i-block', [lead(what), ' · refused: ' + code + ' · nothing sent']);
  }
  function refusal(what, text) {                                    // a tool refusal, verbatim, with only what its text lets the page say about the host
    var tail = NOT_SENT.test(text) ? ' · nothing sent' : SENT.test(text) ? ' · the write was sent and AMT\'s readback did not match: the area is re-read below'
      : ' · the text does not say whether the host changed: the area is re-read below';
    var parts = [lead(what), ' · refused: ' + text + tail];
    if (/secret_field_refused/.test(text)) parts.push(' Passwords come from Identities, never from a form here.');
    return S.result('error', 'i-block', parts);
  }
  function sentButUnclear(text) { return !NOT_SENT.test(text); }
  function revertable(prev) { return isObj(prev) && Object.keys(prev).length > 0 && Object.keys(prev).every(function (k) { return prev[k] !== null && (typeof prev[k] !== 'object' || Array.isArray(prev[k])); }); }
  function settled(reread) {                                         // the end of a write: one re-read when the host may have changed, else the read it held back (an area chosen meanwhile)
    var held = st.deferred;
    st.deferred = false;
    if (reread) loadEntry().then(read);
    else if (held) read();
  }
  function wrote(area, ch, r) {
    var b = r.body || {}, what = 'write ' + area, row, reread = false;
    if (r.status !== 200) { row = failure(what, r); reread = r.status === 502; }
    else if (b.isError) { row = refusal(what, b.text); reread = sentButUnclear(b.text); }
    else {
      var s = b.structured || {}, prev = s.previous, back = s.readback;
      row = S.result('ok', 'i-check', [lead(area), ' · written and read back' + (isObj(back) ? ': ' + lit(back) : '') + (isObj(prev) ? ' · previous values kept for revert: ' + lit(prev) : '')
        + (Array.isArray(s.verified_unchanged) && s.verified_unchanged.length ? ' · ' + s.verified_unchanged.length + ' other field(s) verified unchanged' : '')]);
      if (revertable(prev)) addRevert(row, area, prev);
      reread = true;
    }
    addResult(area, row);
    settled(reread);
  }
  function addRevert(row, area, prev) {
    var btn = h('button', { type: 'button', class: 'btn text', 'data-revert': area }, [icon('i-refresh'), 'Revert']), wrap = h('div', { class: 'btn-wrap' }, [btn]);
    row.appendChild(wrap);
    var g = { btn: btn, wrap: wrap, reason: null, why: pausedWhy };
    revertGates.push(g);
    amtc.bindWrite(btn, function () {
      return { id: 'set-revert-sheet', title: 'Revert ' + area + ' settings of ' + key, verb: 'Revert',
        consequence: 'Writes the previous values back: ' + lit(prev) + '. The whole instance is read, merged, written and read back, as for any write here.',
        call: { tool: 'amt_configure', arguments: { device: key, area: area, changes: prev } },
        onResult: function (r) {
          var ok = r.status === 200 && !(r.body || {}).isError;
          var out = r.status !== 200 ? failure('revert ' + area, r) : r.body.isError ? refusal('revert ' + area, r.body.text)
            : S.result('ok', 'i-check', [lead('revert ' + area), ' · written and read back: ' + lit((r.body.structured || {}).readback || prev)]);
          addResult(area, out);
          if (ok) { g.btn.setAttribute('aria-disabled', 'true'); g.why = function () { return 'already reverted'; }; }
          settled(!ok ? (r.status === 502 || (r.body && r.body.isError && sentButUnclear(r.body.text))) : true);
          controls();
        } };
    });
  }

  // ---- the AMT accounts ----
  function usersCard() {
    var v = st.view, users = v.s.sections.users;
    var card = h('div', { class: 'card', id: 'users-card' }, []);
    card.appendChild(h('h2', {}, [icon('i-person'), 'users · AMT accounts']));
    var list = h('ul', { class: 'list' }, []);
    if (!users.length) list.appendChild(h('li', {}, [h('span', { class: 'txt' }, [h('span', { class: 'muted' }, ['no accounts reported'])])]));
    users.forEach(function (u) {
      var entry = isObj(u) ? u : {}, name = typeof entry.DigestUsername === 'string' ? entry.DigestUsername : null;
      var admin = name !== null && name.toLowerCase() === 'admin';
      var bits = [];
      if (entry.AccessPermission !== undefined) bits.push('access ' + show(entry.AccessPermission));
      if (entry.Realms !== undefined) bits.push('realms ' + show(entry.Realms));
      if (admin) bits.push('the admin account is never changed here');
      var li = h('li', { 'data-user': name || '' }, [icon('i-person'), h('span', { class: 'txt' }, [h('span', { class: 'data' }, [name || 'account without a digest user name']),
        h('span', { class: 'sub' }, [bits.join(' · ') || 'no access fields reported'])])]);
      if (name !== null && !admin) {
        var rm = h('button', { type: 'button', class: 'btn text', 'data-remove': name, 'aria-label': 'Remove ' + name }, ['Remove']);
        li.appendChild(rm);
        gate(rm, pausedWhy);
        amtc.bindWrite(rm, function () { return removeSpec(name); });
      }
      list.appendChild(li);
    });
    card.appendChild(list);
    var uname = h('input', { id: 'user-name', class: 'mono', autocomplete: 'off', spellcheck: 'false' }, []);
    var perm = h('select', { id: 'user-perm' }, [h('option', { value: '0' }, ['0']), h('option', { value: '1' }, ['1']), h('option', { value: '2', selected: 'selected' }, ['2'])]);
    var realms = h('input', { id: 'user-realms', class: 'mono', autocomplete: 'off', spellcheck: 'false', placeholder: 'e.g. 3, 4' }, []);
    var entryName = h('span', { class: 'data', id: 'user-entry' }, [key + '-amt-user-<name>']);
    var form_ = h('div', { class: 'form' }, [
      h('div', { class: 'field' }, [h('label', { for: 'user-name' }, ['New user name']), uname, h('span', { class: 'help' }, ['1 to 16 of A-Z a-z 0-9 _ . @ -; not admin'])]),
      h('div', { class: 'field' }, [h('label', { for: 'user-perm' }, ['access_permission']), perm, h('span', { class: 'help' }, ['0 to 2, as AMT defines AccessPermission'])]),
      h('div', { class: 'field' }, [h('label', { for: 'user-realms' }, ['Realms (numbers)']), realms, h('span', { class: 'help' }, ['realm numbers 0 to 31, comma separated'])])]);
    card.appendChild(form_);
    card.appendChild(h('div', { class: 'result' }, [icon('i-key'), h('span', {}, ['The new user\'s password is read from the identity ', entryName, ', which must exist first. It is never typed here.']),
      h('a', { class: 'btn text', href: '/manage' }, ['Create it'])]));
    var add = h('button', { type: 'button', class: 'btn tonal', id: 'user-add' }, ['Add user']);
    card.appendChild(h('div', { class: 'row' }, [add]));
    card.appendChild(resultsSlot('users'));
    card.appendChild(h('p', { class: 'body-s muted m0' }, ['amt_configure {area: users, changes: {action: add|remove, username, ...}}: add sends only the digest of the vaulted password; the result has no `previous` to restore, so the opposite action is the revert (Remove for an added user, Add user for a removed one).']));
    function entered() {                                                                // the form's values, or why it cannot be sent
      var name = uname.value.trim(), nums = realms.value.split(',').map(function (x) { return x.trim(); }).filter(function (x) { return x !== ''; });
      entryName.textContent = key + '-amt-user-' + (name || '<name>');
      if (!USER_NAME.test(name)) return { why: name ? 'user name must be 1 to 16 of A-Z a-z 0-9 _ . @ -' : 'enter a user name' };
      if (name.toLowerCase() === 'admin') return { why: 'the admin account is never changed here' };
      if (!nums.length || nums.some(function (x) { return !/^\d{1,2}$/.test(x) || Number(x) > 31; })) return { why: 'realms are numbers 0 to 31' };
      return { name: name, access: Number(perm.value), realms: nums.map(Number) };
    }
    var ga = gate(add, function () {
      var e = entered(), idents = st.idents;
      if (pausedWhy()) return pausedWhy();
      if (e.why) return e.why;
      if (!idents || idents.error) return 'identities could not be read' + (idents ? ' (' + idents.error + ')' : '');
      return idents.present.indexOf(key + '-amt-user-' + e.name) === -1 ? 'identity ' + key + '-amt-user-' + e.name + ' is missing' : null;
    });
    [uname, perm, realms].forEach(function (el) { el.addEventListener('input', controls); el.addEventListener('change', controls); });
    amtc.bindWrite(add, function () { return addSpec(entered()); });
    return card;
  }
  function removeSpec(name) {
    return { id: 'set-user-remove', title: 'Remove the AMT user ' + name + ' from ' + key, verb: 'Remove user',
      consequence: 'The account is deleted from AMT. Anything authenticating as ' + name + ' is refused from now on. The vault entry ' + key + '-amt-user-' + name + ' stays until deleted in Identities.',
      call: { tool: 'amt_configure', arguments: { device: key, area: 'users', changes: { action: 'remove', username: name } } }, onResult: function (r) { userResult('remove ' + name, r); } };
  }
  function addSpec(e) {
    return { id: 'set-user-add', title: 'Add the AMT user ' + e.name + ' to ' + key, verb: 'Add user',
      consequence: 'Adds the AMT account ' + e.name + ' with access_permission ' + e.access + ' and realms ' + e.realms.join(', ') + '. Its password is the vaulted identity ' + key + '-amt-user-' + e.name
        + ': only the digest is sent to AMT, and no password is typed here. If the user already exists the call raises.',
      call: { tool: 'amt_configure', arguments: { device: key, area: 'users', changes: { action: 'add', username: e.name, access_permission: e.access, realms: e.realms } } },
      onResult: function (r) { userResult('add ' + e.name, r); } };
  }
  function userResult(what, r) {
    var b = r.body || {}, row, reread = false;
    if (r.status !== 200) { row = failure(what, r); reread = r.status === 502; }
    else if (b.isError) { row = refusal(what, b.text); reread = sentButUnclear(b.text); }
    else {
      var s = b.structured || {};
      row = S.result('ok', 'i-check', [lead(what), ' · done and read back' + (isObj(s.readback) ? ': ' + lit(s.readback) : '') + ' · revert: ' + (typeof s.revert === 'string' ? s.revert : 'the opposite action')]);
      reread = true;
    }
    addResult('users', row);
    settled(reread);
  }

  // ---- the read-only areas, and every section of the area as the tool returned it ----
  function sectionDump(s, names) {
    var kids = [];
    names.forEach(function (n) {
      var sec = s.sections[n];
      kids.push(h('h3', { class: 'title-s muted' }, [n + (s.classes[n] ? ' · ' + s.classes[n] : '')]));
      if (Array.isArray(sec)) {
        if (!sec.length) kids.push(h('p', { class: 'muted m0' }, ['none reported']));
        sec.forEach(function (it, i) { kids.push(S.instance(isObj(it) ? it : { value: it }, i + 1, sec.length)); });
      } else kids.push(S.instance(isObj(sec) ? sec : { value: sec }, 1, 1));
    });
    return kids;
  }
  function readOnlyCard() {
    var v = st.view, card = h('div', { class: 'card', id: 'set-card', 'data-area': st.area }, [h('h2', {}, [icon('i-list'), st.area + ' · read-only here'])]);
    card.appendChild(h('p', { class: 'body-s muted m0' }, ['amt_configure has no ' + st.area + ' area. It is written with amt_wsman_invoke: ',
      h('a', { href: '/server/' + key + '/wsman' }, ['the guarded templates in Advanced']), '.']));
    sectionDump(v.s, SECTIONS[st.area]).forEach(function (n) { card.appendChild(n); });
    return card;
  }
  function sectionsCard() {
    var v = st.view, card = h('div', { class: 'card', id: 'sections-card' }, [h('h2', {}, [icon('i-list'), 'What was read · ' + st.area])]);
    card.appendChild(h('p', { class: 'body-s muted m0' }, ['Every section the read returned, as the tool returned it. Credentials are redacted and certificate blobs reduced to a size note by the tool.']));
    sectionDump(v.s, SECTIONS[st.area]).forEach(function (n) { card.appendChild(n); });
    return card;
  }

  function loadEntry() {
    return S.get('/api/server/' + key).then(function (r) {
      if (r.status === 404) { st.gone = true; return; }
      if (r.status !== 200) return;
      var e = r.body.server;
      st.paused = e.state === 'paused' ? (e.paused || { reason: 'refused' }) : null;
      banner(); controls();
    });
  }

  // ---- wiring ----
  Object.keys(chips).forEach(function (a) {
    chips[a].addEventListener('click', function () {
      if (a === st.area) return;
      st.area = a; st.view = null; st.raw = {};
      draw(); read();
    });
  });
  ctl.reread.btn.addEventListener('click', function () { if (ctl.reread.btn.getAttribute('aria-disabled') !== 'true') read(); });
  document.addEventListener('tools-call', function (e) { if (/^set-/.test(e.detail.sheet || '')) { st.writing = true; controls(); } });
  document.addEventListener('tools-result', function (e) { if (/^set-/.test(e.detail.sheet || '')) { st.writing = false; controls(); } });
  controls();
  amtc.ready.then(function () {
    loadEntry().then(function () { read(); });
    setInterval(loadEntry, POLL_MS);                                // the cached state only: a pause or a resume shows; nothing is read
  });
}());
