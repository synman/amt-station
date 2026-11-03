/* The Inventory tab (design/inventory.html, note 2.9): every hardware section through amt_inventory, one card each, the coverage banner
   made of the result's own `unavailable` and `truncated`, and an Export of the result as JSON. A read happens when the page opens and
   on Re-read, never on a timer, and never for a paused server. Every read names all seven sections: there is no section picker
   (designer ruling 2026-10-21: a picker that only narrowed the next call did nothing a user could see). The fields of an instance are shown as the tool returned them (their
   CIM names), not renamed. A result missing a field the banner is made of is reported as unreadable, never as "nothing unavailable".
   Everything from the host is set as text nodes only. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var head = document.querySelector('.srvhead[data-server]'), page = document.getElementById('inventory-page');
  if (!head || !page) return;
  var key = head.getAttribute('data-server'), POLL_MS = 5000;
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;

  // section -> the CIM class behind it. `unavailable` names classes; console/tests pins this table to amt_tools.INVENTORY_CLASSES.
  var CLASSES = { chassis: 'CIM_Chassis', baseboard: 'CIM_Card', bios: 'CIM_BIOSElement', processors: 'CIM_Processor', memory: 'CIM_PhysicalMemory',
    storage_media: 'CIM_MediaAccessDevice', physical_media: 'CIM_PhysicalMedia' };
  var SECTIONS = Object.keys(CLASSES);
  var CARDS = [{ id: 'chassis', icon: 'i-dns', title: 'Chassis', parts: ['chassis'] }, { id: 'baseboard', icon: 'i-memory', title: 'Baseboard', parts: ['baseboard'] },
    { id: 'bios', icon: 'i-settings', title: 'BIOS', parts: ['bios'] }, { id: 'processors', icon: 'i-memory', title: 'Processors', parts: ['processors'] },
    { id: 'memory', icon: 'i-memory', title: 'Memory', parts: ['memory'] }, { id: 'storage', icon: 'i-disc', title: 'Storage media', parts: ['storage_media', 'physical_media'] }];
  var PART_LABEL = { storage_media: 'Storage media', physical_media: 'Physical media' };

  var st = { busy: false, paused: null, view: null, gone: false };   // view: { s, args, at }
  var ctl = { reread: { btn: $('inv-reread'), wrap: $('inv-reread-wrap'), reason: null }, exp: { btn: $('inv-export'), wrap: $('inv-export-wrap'), reason: null } };
  function controls() {
    S.setReason(ctl.reread, st.paused ? 'paused · ' + (st.paused.reason || 'refused') : st.busy ? 'waiting for amt-mcp' : null);
    S.setReason(ctl.exp, st.busy ? 'waiting for amt-mcp' : !st.view ? 'read first' : null);
  }
  function banner() {
    var box = $('inv-paused'), text = $('inv-paused-text');
    clear(text);
    box.hidden = !st.paused;
    if (st.paused) S.pausedNote('the inventory', key, st.paused).forEach(function (n) { text.appendChild(typeof n === 'string' ? document.createTextNode(n) : n); });
  }

  // ---- a result the page can trust: the coverage lists are present and every section asked for is accounted for ----
  function unreadable(s, args) {
    if (!s || typeof s !== 'object' || Array.isArray(s)) return 'no result object';
    var bad = [];
    if (!s.sections || typeof s.sections !== 'object' || Array.isArray(s.sections)) bad.push('sections');
    if (!Array.isArray(s.unavailable)) bad.push('unavailable');
    if (!Array.isArray(s.truncated)) bad.push('truncated');
    if (bad.length) return 'missing or wrong: ' + bad.join(', ');
    var lost = args.sections.filter(function (n) { return s.sections[n] === undefined && s.unavailable.indexOf(CLASSES[n]) === -1; });
    var odd = args.sections.filter(function (n) { return s.sections[n] !== undefined && !Array.isArray(s.sections[n]); });
    if (lost.length) bad.push('neither returned nor reported unavailable: ' + lost.join(', '));
    if (odd.length) bad.push('not a list: ' + odd.join(', '));
    return bad.length ? bad.join('; ') : null;
  }

  // ---- reading ----
  function read() {
    if (st.busy || st.paused || st.gone) return Promise.resolve();
    var args = { device: key, sections: SECTIONS.slice() };
    st.busy = true;
    clear($('inv-state')); $('inv-banner').hidden = true;
    $('inv-state').appendChild(h('div', { class: 'progress', role: 'progressbar', 'aria-label': 'Reading the inventory' }, [h('i', { 'data-motion': 'progress' })]));
    controls();
    return amtc.post('/api/call', { tool: 'amt_inventory', arguments: args }).catch(function () { return { status: 0, body: {} }; })
      .then(function (r) { st.busy = false; outcome(r, args); return loadEntry(); });
  }
  function outcome(r, args) {
    var slot = $('inv-state'), b = r.body || {}, what = 'read the inventory';
    clear(slot);
    st.view = null;
    if (r.status !== 200) slot.appendChild(S.readFailure(what, r));
    else if (b.isError) slot.appendChild(S.readRefusal(what, b.text));
    else {
      var bad = unreadable(b.structured, args);
      if (bad) slot.appendChild(S.result('error', 'i-block', [S.stamp() + ' · ' + what + ' · amt-mcp returned a result this page cannot read (' + bad + '), so no coverage is claimed: none can be trusted']));
      else st.view = { s: b.structured, args: args, at: Date.now() / 1000 };
    }
    draw();
  }

  // ---- drawing ----
  var instance = S.instance;
  function part(name, s, args) {                          // one section inside a card: its instances, or why there are none
    var cls = CLASSES[name], out = [];
    if (s.unavailable.indexOf(cls) !== -1) return [h('span', { class: 'chip small dashed', 'data-part': name }, [icon('i-help'), 'unavailable on this AMT'])];
    var items = s.sections[name];
    if (!items.length) return [h('p', { class: 'muted m0', 'data-part': name }, ['none reported'])];
    items.forEach(function (it, i) { out.push(instance(it && typeof it === 'object' && !Array.isArray(it) ? it : { value: it }, i + 1, items.length)); });
    return out;
  }
  function card(c, s, args) {
    var first = c.parts[0], count = Array.isArray(s.sections[first]) ? s.sections[first].length : null;
    var kids = [h('h2', {}, [icon(c.icon), c.title + (count === null ? '' : ' (' + count + ')')])];
    c.parts.forEach(function (name) {
      if (c.parts.length > 1) kids.push(h('h3', { class: 'title-s muted' }, [PART_LABEL[name]]));
      part(name, s, args).forEach(function (n) { kids.push(n); });
    });
    return h('div', { class: 'card', 'data-card': c.id }, kids);
  }
  function coverage(s, args) {                                   // immutable 19: from the result's own lists
    var name = function (cls) { return SECTIONS.filter(function (n) { return CLASSES[n] === cls; })[0] || cls; };
    var why = s.unavailable_reasons && typeof s.unavailable_reasons === 'object' ? s.unavailable_reasons : {}, parts = [], live = false;
    s.unavailable.forEach(function (cls) {
      parts.push(name(cls) + ' is unavailable: ' + (typeof why[cls] === 'string' ? why[cls] : 'the tool gave no reason') + ', so that section is empty and the rest was read.');
    });
    if (s.truncated.length) {
      live = true;
      parts.push(s.truncated.map(name).join(', ') + ' was cut at the item cap: more exist than were read.');
    } else parts.push('Nothing was truncated.');
    if (!s.unavailable.length) parts.unshift('All ' + args.sections.length + ' sections were read.');
    return { text: parts.join(' '), live: live };
  }
  function draw() {
    controls();
    var v = st.view, cards = $('inv-cards'), box = $('inv-banner');
    clear(cards); box.hidden = true; $('inv-call').textContent = ''; $('inv-note').textContent = v ? 'amt_inventory · read ' + S.eastern(v.at, false) : 'amt_inventory · not read yet';
    if (!v) return;
    var s = v.s, args = v.args, cov = coverage(s, args), text = $('inv-banner-text');
    clear(text);
    text.appendChild(h('strong', {}, ['Coverage:']));
    text.appendChild(document.createTextNode(' ' + cov.text));
    box.className = 'banner' + (cov.live ? ' live' : '');
    box.hidden = false;
    CARDS.forEach(function (c) { cards.appendChild(card(c, s, args)); });
    $('inv-call').textContent = amtc.fmtCall({ tool: 'amt_inventory', arguments: args }) + ' · read-only';
  }

  // ---- Export JSON: the result as the tool returned it, built in the browser; nothing is sent anywhere ----
  function exportJson() {
    if (!st.view) return;
    var blob = new Blob([JSON.stringify(st.view.s, null, 2) + '\n'], { type: 'application/json' });
    var url = URL.createObjectURL(blob), a = h('a', { href: url, download: key + '-inventory.json' });
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
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
  ctl.reread.btn.addEventListener('click', function () { if (ctl.reread.btn.getAttribute('aria-disabled') !== 'true') read(); });
  ctl.exp.btn.addEventListener('click', function () { if (ctl.exp.btn.getAttribute('aria-disabled') !== 'true') exportJson(); });
  controls();
  amtc.ready.then(function () {
    loadEntry().then(function () { read(); });
    setInterval(loadEntry, POLL_MS);                                // the cached state only: a pause or a resume shows; nothing is read
  });
}());
