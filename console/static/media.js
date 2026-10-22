/* The Media tab and the Images section (design/media.html, note 2.7): what is mounted on a server, the mount form with its start
   mode, and the image library (fetch, upload, verify, rename, delete, set root). One page serves both: on a server tab the server is
   fixed, on /images it is chosen. Every write is a sheet from components.js; the sheet kind comes from the one predicate there
   (a mount with start "now" and a delete take the hold). A tool's refusal is shown verbatim (text nodes only, never markup).
   The library is read with amt_images list: the server's own answer decides what is busy, this page only greys what it already knows.
   An upload's one-time url never reaches this page: the console keeps it and hands back an upload_id, and the file goes to the
   console's own route (note 2.7 / packet C5 token rule). */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var page = document.getElementById('media-page');
  if (!page) return;
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;
  var fixed = page.getAttribute('data-server') || '';
  var key = fixed, POLL_MS = 5000, BUSY_MS = 2000, IDLE_MS = 10000;

  // ---- state ----
  var lib = { phase: 'loading', error: null, root: null, source: null, rootError: null, images: [], fetches: [], uploads: { open: [], finished: [] }, readAt: null };
  var servers = [], fleetLoaded = false;
  var verified = {};                                         // image name -> { sha, at }, from Verify on this page
  var sending = {};                                          // image name -> { loaded, total }, an upload this browser is sending now
  var start = 'next_boot', dirty = false;

  var base = function (p) { return String(p).split('/').pop(); };
  var lower = function (s) { return String(s).toLowerCase(); };
  var isIso = function (n) { return /\.iso$/.test(lower(n)); };
  var isImg = function (n) { return /\.img$/.test(lower(n)); };
  var plainName = function (n) { return !!n && n.indexOf('/') === -1 && n.indexOf('\\') === -1 && n.charAt(0) !== '.' && (isIso(n) || isImg(n)); };
  var num = function (n) { return typeof n === 'number' && isFinite(n) ? n.toLocaleString('en-US') : 'unknown'; };
  var entryFor = function (k) { for (var i = 0; i < servers.length; i++) if (servers[i].key === k) return servers[i]; return null; };
  var shaOk = function (v) { return /^[0-9a-fA-F]{64}$/.test(v); };

  // ---- results (design 7.4): the tool's own words, in the card of the action ----
  function stamp() { return S.eastern(Date.now() / 1000, false); }
  function addResult(slot, node) { slot.insertBefore(node, slot.firstChild); while (slot.children.length > 5) slot.removeChild(slot.lastChild); }
  function lead(what) { return h('strong', {}, [stamp() + ' · ' + what]); }
  function failure(what, r) {                                  // the console could not make the call, or amt-mcp did not answer
    var code = (r.body && r.body.error) || 'no answer';
    if (r.status === 502) return S.result('live', 'i-help', [lead(what), ' · amt-mcp did not answer (' + code + ') · it is not known whether the request was sent; read the library or the mount status before trying again']);
    return S.result('error', 'i-block', [lead(what), ' · refused: ' + code + ' · nothing sent']);
  }
  function busyWords(text) {                                   // the tool's busy code, in plain words beside it
    var m = /image_busy:[^:\s]+:(mounted_on:([\w.-]+)|being_downloaded|being_uploaded)/.exec(text || '');
    if (!m) return '';
    return ' · ' + (m[2] ? 'the image is mounted on ' + m[2] : m[1] === 'being_downloaded' ? 'the image is being downloaded' : 'the image is being uploaded');
  }
  function refusal(what, text, tail) { return S.result('error', 'i-block', [lead(what), ' · refused: ' + text + busyWords(text) + tail]); }
  function reply(what, r, tail, ok) {                          // 200 + isError is a refusal by the tool; anything but 200 never reached it
    if (r.status !== 200) return failure(what, r);
    if (r.body.isError) return refusal(what, r.body.text, tail);
    return ok(r.body.structured || {});
  }

  // ---- reading the library ----
  function readLibrary() {
    return amtc.post('/api/call', { tool: 'amt_images', arguments: { action: 'list' } }).then(function (r) {
      var b = r.body || {}, s = b.structured;
      if (r.status !== 200) lib.error = 'the console could not ask amt-mcp (' + (b.error || 'no answer') + ')';
      else if (b.isError) lib.error = b.text;
      else if (!s || !Array.isArray(s.images)) lib.error = 'amt-mcp\'s library answer was not readable';
      else {
        lib = { phase: 'ok', error: null, root: s.image_root || null, source: s.source || null, rootError: s.error || null, images: s.images,
          fetches: Array.isArray(s.fetches) ? s.fetches : [], uploads: s.uploads && typeof s.uploads === 'object' ? { open: s.uploads.open || [], finished: s.uploads.finished || [] } : { open: [], finished: [] },
          readAt: Date.now() / 1000 };
      }
      if (lib.error) lib.phase = 'error';
      renderAll();
    });
  }
  function loadFleet() {
    return S.get('/api/fleet').then(function (r) {
      if (r.status !== 200) return;
      servers = r.body.servers || []; fleetLoaded = true;
      if (!fixed && (!key || !entryFor(key)) && servers.length) key = servers[0].key;
      renderAll();
    });
  }

  // ---- what each image is: a file, a download, an upload; what holds it; what is known of its hash ----
  function mountsOf(name) {                                   // the servers this console knows to have the image mounted
    var out = [];
    servers.forEach(function (e) {
      var im = e.sessions && e.sessions.ider;
      if (im && im.mounted === true && Object.keys(im.images || {}).some(function (k) { return im.images[k] === base(name); })) out.push(e.key);
    });
    return out;
  }
  function rowsModel() {
    var rows = {}, order = [];
    var get = function (name) { if (!rows[name]) { rows[name] = { name: name }; order.push(name); } return rows[name]; };
    lib.images.forEach(function (im) { var r = get(im.path); r.bytes = im.bytes; r.mountable = im.mountable; r.file = true; });
    lib.fetches.forEach(function (f) { if (f.state === 'running') { var r = get(f.name); r.fetch = f; } });
    lib.uploads.open.forEach(function (u) { var r = get(u.name); r.upload = u; });
    Object.keys(sending).forEach(function (n) { var r = get(n); r.sending = sending[n]; });
    order.forEach(function (n) { rows[n].mounted = mountsOf(n); });
    return order.map(function (n) { return rows[n]; });
  }
  function shaFor(name, size) {                               // the newest hash this page can vouch for, and how it was learned; an arrival hash only for a file of the size that arrived
    var best = verified[name] ? { sha: verified[name].sha, at: verified[name].at, how: 'verified' } : null;
    var consider = function (sha, at, how) { if (typeof sha === 'string' && shaOk(sha) && (!best || at > best.at)) best = { sha: sha, at: at, how: how }; };
    lib.uploads.finished.forEach(function (u) { if (u.state === 'done' && u.name === name && typeof size === 'number' && u.bytes === size) consider(u.sha256, u.at || 0, 'checked on arrival'); });
    return best;
  }
  function busyReason(row) {
    if (row.mounted.length) return 'mounted';
    if (row.fetch) return 'downloading';
    if (row.upload || row.sending) return 'uploading';
    return null;
  }

  // ---- the library table ----
  function progress(pct, label) {
    var bar = h('i', pct === null ? { 'data-motion': 'progress' } : {});
    if (pct !== null) bar.style.width = Math.max(0, Math.min(100, pct)) + '%';
    var box = h('div', { class: 'progress', role: 'progressbar', 'aria-label': label }, [bar]);
    if (pct !== null) box.setAttribute('aria-valuenow', String(Math.round(pct)));
    box.style.width = '140px';
    return box;
  }
  function stateCell(row) {
    var td = h('td', { 'data-l': 'State' });
    if (row.fetch) {
      var f = row.fetch, pct = f.total_bytes ? 100 * f.bytes / f.total_bytes : null;
      td.appendChild(progress(pct, 'download ' + (pct === null ? 'size unknown' : Math.round(pct) + '%')));
      td.appendChild(h('span', { class: 'body-s muted' }, [' ' + (pct === null ? S.bytes(f.bytes) + ' so far' : Math.round(pct) + '%') + ' · ' + (f.sha256_expected ? 'sha256 checked on completion' : 'no sha256 given')]));
    } else if (row.upload || row.sending) {
      var u = row.upload || {}, sent = row.sending, size = u.size_bytes || (sent && sent.total), got = Math.max(u.bytes || 0, 0);
      if (sent && !(got > sent.loaded)) got = sent.loaded;      // the browser's own count leads until amt-mcp's catches up
      var pctU = size ? 100 * got / size : null;
      td.appendChild(progress(pctU, 'upload ' + (pctU === null ? 'size unknown' : Math.round(pctU) + '%')));
      td.appendChild(h('span', { class: 'body-s muted' }, [' ' + (got > 0 ? 'uploading from this browser · ' + S.bytes(got) + ' of ' + S.bytes(size) : 'upload url minted · waiting for the file · ' + S.bytes(size) + ' declared') + ' · exact size and sha256 checked when the PUT ends']));
    } else {
      td.appendChild(row.mountable ? h('span', { class: 'chip small ok' }, [icon('i-check'), '512-aligned']) : h('span', { class: 'chip small error' }, [icon('i-block'), 'not 512-aligned · cannot be mounted']));
      row.mounted.forEach(function (k) { td.appendChild(document.createTextNode(' ')); td.appendChild(h('span', { class: 'chip small live' }, ['mounted on ' + k])); });
    }
    return td;
  }
  function shaCell(row) {
    var td = h('td', { 'data-l': 'SHA-256' });
    if (row.fetch) { td.appendChild(h('span', { class: 'fp' }, ['downloading…'])); return td; }
    if (row.upload || row.sending) {
      var want = (row.upload || {}).sha256_expected;
      td.appendChild(h('span', { class: 'fp' }, [want ? 'expected ' + want.slice(0, 4) + '…' : 'no sha256 given']));
      return td;
    }
    var known = shaFor(row.name, row.bytes);
    if (!known) { td.appendChild(h('span', { class: 'chip small dashed' }, ['not verified yet'])); return td; }
    td.appendChild(h('span', { class: 'fp' }, [known.sha.slice(0, 16).match(/.{4}/g).join(' ') + ' …']));
    td.appendChild(document.createTextNode(' '));
    td.appendChild(h('span', { class: 'chip small ok' }, [icon('i-verified'), known.how + (known.at ? ' ' + S.eastern(known.at, false) : '')]));
    return td;
  }
  function gated(label, reason) {                    // a button that may be aria-disabled, with its reason as visible text beside it
    var b = h('button', { type: 'button', class: 'btn text' }, [label]);
    if (!reason) return { node: b, btn: b };
    b.setAttribute('aria-disabled', 'true');
    return { node: h('div', { class: 'btn-wrap' }, [b, h('span', { class: 'reason' }, [reason])]), btn: b };
  }
  function actionsCell(row) {
    var td = h('td', { class: 'acts', 'data-l': 'Actions' }), busy = busyReason(row), name = row.name;
    if (!row.fetch && !row.upload && !row.sending) {
      var m = gated('Mount', mountReason(row)); m.btn.setAttribute('aria-label', 'Mount ' + name);
      amtc.bindWrite(m.btn, function () { choose(name); return mountSpec(); });
      td.appendChild(m.node);
      var v = h('button', { type: 'button', class: 'btn text', 'aria-label': 'Verify ' + name }, ['Verify']);
      v.addEventListener('click', function () { verify(name, v); });
      td.appendChild(v);
    }
    var rn = gated('Rename', busy), dl = gated('Delete', busy);
    rn.btn.setAttribute('aria-label', 'Rename ' + name); dl.btn.setAttribute('aria-label', 'Delete ' + name);
    amtc.bindWrite(rn.btn, function () { return renameSpec(name); });
    amtc.bindWrite(dl.btn, function () { return deleteSpec(name); });
    td.appendChild(rn.node); td.appendChild(dl.node);
    return td;
  }
  function renderLibrary() {
    var body = $('lib-rows'), rows = rowsModel();
    clear(body);
    rows.forEach(function (row) {
      var tr = h('tr', { 'data-name': row.name }, [h('td', { class: 'data', 'data-l': 'Name' }, [row.name]),
        h('td', { class: 'data', 'data-l': 'Size' }, [row.upload || row.sending ? S.bytes((row.upload || {}).size_bytes || (row.sending || {}).total) + ' declared' : S.bytes(row.bytes)]),
        shaCell(row), stateCell(row), actionsCell(row)]);
      body.appendChild(tr);
    });
    var note = $('lib-note'), empty = $('lib-empty');
    var rootText = lib.root ? lib.root + (lib.source ? ' (' + lib.source + ')' : '') : 'not set';
    if (lib.phase === 'loading') { note.textContent = 'Reading the library…'; }
    else if (lib.error) { note.textContent = 'The library could not be read: ' + lib.error + ' · this is not an empty library' + (lib.readAt ? '; the table shows the last good read at ' + S.eastern(lib.readAt, false) : '') + '.'; }
    else if (lib.rootError) { note.textContent = 'Listed 0 images: ' + lib.rootError; }
    else {
      var down = lib.fetches.filter(function (f) { return f.state === 'running'; }).length, up = lib.uploads.open.length;
      note.textContent = 'Listed ' + lib.images.length + ' .iso/.img file' + (lib.images.length === 1 ? '' : 's') + ' under ' + rootText + ' (every depth; other file types are not listed) · ' + down + ' download' + (down === 1 ? '' : 's') + ' and ' + up + ' upload' + (up === 1 ? '' : 's') + ' in progress · read ' + S.ago(Date.now() / 1000 - lib.readAt) + '.';
    }
    var none = lib.phase === 'ok' && !lib.rootError && rows.length === 0;
    empty.hidden = !none;
    if (none) empty.textContent = 'No images under the root: nothing is in the library yet. Fetch a URL or upload a file to fill it.';
    $('lib-root-chip').textContent = 'image root · ' + (lib.root ? lib.root : lib.phase === 'loading' ? 'reading' : 'not set');
    renderFailures();
  }
  function renderFailures() {                                 // a download or upload amt-mcp recorded as failed, until a later attempt of that name succeeds
    var slot = $('lib-failures');
    if (!slot) return;
    clear(slot);
    var later = function (name, at) { return lib.uploads.finished.some(function (u) { return u.name === name && u.state === 'done' && (u.at || 0) > at; }); };
    lib.fetches.forEach(function (f) {
      if (f.state === 'failed') slot.appendChild(S.result('error', 'i-block', [h('strong', {}, ['fetch ' + f.name]), ' · failed: ' + (f.error || 'no reason reported') + ' · nothing was kept (amt-mcp deletes the part file)']));
    });
    lib.uploads.finished.slice(0, 5).forEach(function (u) {
      if (u.state === 'failed' && !later(u.name, u.at || 0)) slot.appendChild(S.result('error', 'i-block', [h('strong', {}, [(u.at ? S.eastern(u.at, false) + ' · ' : '') + 'upload ' + u.name]), ' · refused by the one-time url: ' + (u.error || 'no reason reported') + ' · amt-mcp deleted the part file · mint a new upload']));
    });
  }

  // ---- the server picker (Images section) and the Mounted card ----
  function renderPicker() {
    var pick = $('media-pick');
    if (!pick || pick.hidden) return;
    var sel = $('media-server'), want = (fleetLoaded ? 'loaded:' : 'reading:') + servers.map(function (e) { return e.key; }).join('|');
    if (sel.getAttribute('data-keys') === want) { sel.value = key; return; }
    clear(sel); sel.setAttribute('data-keys', want);
    if (!servers.length) sel.appendChild(h('option', { value: '' }, [fleetLoaded ? 'no servers are registered' : 'reading the servers…']));
    servers.forEach(function (e) { sel.appendChild(h('option', { value: e.key }, [e.key])); });
    sel.value = key;
  }
  var STARTS = {
    next_boot: 'next_boot · the host sees the drive at its next boot; it was not reset',
    graceful: 'graceful · the host was asked to reset when the image was mounted',
    now: 'now · the host was hard reset when the image was mounted'
  };
  function kvRows(rows) {
    var dl = h('dl', { class: 'kv' });
    rows.forEach(function (r) { dl.appendChild(h('dt', {}, [r[0]])); dl.appendChild(h('dd', {}, r[1])); });
    return dl;
  }
  function renderMounted() {
    var e = entryFor(key), body = $('mounted-body'), chip = $('mounted-chip'), um = $('unmount');
    $('mounted-key').textContent = key || 'no server';
    clear(body); clear(chip);
    var im = e && e.sessions ? e.sessions.ider : null, reason = null;
    if (!key) { body.appendChild(h('p', { class: 'muted m0' }, [fleetLoaded ? 'No server is registered, so nothing can be mounted.' : 'Reading the servers…'])); reason = 'no server'; }
    else if (!e || !im || im.mounted === null || im.mounted === undefined) {
      chip.appendChild(h('span', { class: 'chip small dashed' }, [icon('i-help'), 'unknown']));
      body.appendChild(h('p', { class: 'muted m0' }, ['IDE-R state unknown: ' + ((e && (e.sessions_error || e.error)) || 'amt-mcp\'s mount status has not been read yet') + '. Status asks amt-mcp now.']));
    } else if (im.mounted === true) {
      chip.appendChild(h('span', { class: 'chip small live', 'data-session': 'ider' }, [h('span', { class: 'dot', 'data-motion': 'live-pulse' }), icon('i-disc'), 'IDE-R held']));
      var names = Object.keys(im.images || {}).map(function (k) { return im.images[k]; });
      var sized = names.map(function (n) { var f = lib.images.filter(function (x) { return base(x.path) === n; })[0]; return f ? n + ' · ' + S.bytes(f.bytes) : n; });
      var cd = names.some(isIso);
      body.appendChild(kvRows([['Image', [h('span', { class: 'data' }, [sized.join(', ') || 'not reported'])]],
        ['Start', [im.start ? STARTS[im.start] || im.start : 'not recorded here: this console did not start the mount, or restarted since']],
        ['Since', [im.since ? S.eastern(im.since, false) + ' · session held until unmount · KVM works beside it' : 'not recorded here · session held until unmount · KVM works beside it']],
        ['To boot from it', [h('a', { href: '/server/' + key + '/power' }, ['set next boot ' + (cd ? 'cd_ider' : 'floppy_ider') + ', then reset'])]]]));
      if (im.error) body.appendChild(S.result('error', 'i-block', ['The serving thread ended with an error: ' + im.error]));
    } else {
      chip.appendChild(h('span', { class: 'chip small' }, ['not mounted']));
      body.appendChild(h('p', { class: 'muted m0' }, ['Nothing is mounted on ' + key + '. A mount holds the host\'s IDE-R session until you unmount it.']));
      reason = 'nothing mounted';
    }
    setReason(um, reason);
  }
  var reasons = {};                                           // element id -> its reason node
  function setReason(btn, reason) {                           // an aria-disabled button with its reason beside it (immutable 18)
    var wrap = btn.parentNode, node = reasons[btn.id];
    if (!btn.id) return;
    if (!wrap.classList.contains('btn-wrap')) { var w = h('div', { class: 'btn-wrap' }, []); wrap.insertBefore(w, btn); w.appendChild(btn); wrap = w; }
    if (reason) {
      btn.setAttribute('aria-disabled', 'true');
      if (!node) { node = reasons[btn.id] = h('span', { class: 'reason' }, [reason]); wrap.appendChild(node); } else node.textContent = reason;
    } else {
      btn.removeAttribute('aria-disabled');
      if (node) { node.remove(); delete reasons[btn.id]; }
    }
  }

  // ---- the mount form ----
  function fillSelect(sel, names) {
    var keep = sel.value;
    clear(sel); sel.appendChild(h('option', { value: '' }, ['none']));
    names.forEach(function (n) { sel.appendChild(h('option', { value: n }, [n])); });
    sel.value = names.indexOf(keep) !== -1 ? keep : '';
  }
  function renderMountForm() {
    var ok = lib.images.filter(function (i) { return i.mountable; }).map(function (i) { return i.path; });
    fillSelect($('mount-iso'), ok.filter(isIso));
    fillSelect($('mount-floppy'), ok.filter(isImg));
    document.querySelectorAll('#mount-start [data-start]').forEach(function (c) { c.setAttribute('aria-checked', String(c.getAttribute('data-start') === start)); });
    setReason($('mount-go'), mountFormReason());
  }
  function mountFormReason() {
    var e = entryFor(key), im = e && e.sessions ? e.sessions.ider : null;
    if (!key) return 'no server';
    if (lib.phase === 'loading') return 'reading the library';
    if (!lib.root) return 'no image root';
    if (!$('mount-iso').value && !$('mount-floppy').value) return 'pick an image';
    if (im && im.mounted === true) return 'unmount first';
    return null;
  }
  function mountReason(row) {                                 // a row's own Mount button
    var e = entryFor(key), im = e && e.sessions ? e.sessions.ider : null;
    if (!key) return 'no server';
    if (!lib.root) return 'no image root';
    if (!row.mountable) return 'not 512-aligned';
    if (im && im.mounted === true) return 'unmount first';
    return null;
  }
  function choose(name) { var sel = isImg(name) ? $('mount-floppy') : $('mount-iso'); sel.value = name; renderMountForm(); }
  function mountSpec() {
    var iso = $('mount-iso').value, fl = $('mount-floppy').value, args = { device: key, action: 'mount' };
    if (iso) args.iso_path = iso;
    if (fl) args.floppy_path = fl;
    args.start = start;
    var names = [iso, fl].filter(Boolean).join(' and '), drive = iso && fl ? 'a CD and a floppy drive' : iso ? 'a CD drive' : 'a floppy drive';
    var held = 'The host\'s IDE-R session is opened and held until you unmount. KVM keeps working beside it.';
    var spec = { id: 'sheet-mount', call: { tool: 'amt_ider', arguments: args }, onResult: mountResult };
    if (start === 'now') return Object.assign(spec, { title: 'Mount ' + names + ' and HARD reset ' + key + ' now', verb: 'mount and reset', nowLabel: 'Mount and reset now',
      consequence: 'The image is attached and the host is reset at once without asking the OS: unsaved work is lost. The IDE-R session is held until unmount.' });
    if (start === 'graceful') return Object.assign(spec, { title: 'Mount ' + names + ' on ' + key + ' and reset it', verb: 'Mount',
      consequence: held + ' The host is asked to reset now (graceful: the same act as Restart), so open applications may prompt to save.' });
    return Object.assign(spec, { title: 'Mount ' + names + ' on ' + key, verb: 'Mount', consequence: held + ' The host sees ' + drive + ' at its next boot and is not reset.' });
  }
  function mountResult(r) {
    var slot = $('mount-results');
    addResult(slot, reply('mount', r, ' · nothing was mounted', function (s) {
      var names = Object.keys(s.images || {}).map(function (k) { return s.images[k]; }).join(', ');
      return S.result('ok', 'i-check', [lead('mount ' + names), ' · mounted on ' + s.device + ' · start ' + s.start + ' · the host\'s IDE-R session is held until unmount' + (s.note ? ' · ' + s.note : '')]);
    }));
    if (r.status === 200 && !r.body.isError) loadFleet();
  }
  function bindStartRadios() {
    var radios = Array.prototype.slice.call(document.querySelectorAll('#mount-start [data-start]'));
    function pick(c) { start = c.getAttribute('data-start'); renderMountForm(); }
    radios.forEach(function (c, i) {
      c.addEventListener('click', function () { pick(c); });
      c.addEventListener('keydown', function (e) {
        if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); if (!e.repeat) pick(c); }
        else if (/^Arrow(Down|Right|Up|Left)$/.test(e.key)) {
          e.preventDefault();
          var n = radios[(i + (/Down|Right/.test(e.key) ? 1 : radios.length - 1)) % radios.length];
          n.focus(); pick(n);
        }
      });
    });
  }

  // ---- unmount and status ----
  function unmountSpec() {
    return { id: 'sheet-unmount', title: 'Unmount the image from ' + key, verb: 'Unmount', call: { tool: 'amt_ider', arguments: { device: key, action: 'unmount' } },
      consequence: 'Ends the IDE-R session. If the host is reading the drive, that read fails. If the serving thread will not stop, the session is reported as still held.',
      onResult: function (r) {
        var slot = $('mounted-results');
        if (r.status === 200 && r.body.isError && /STILL HELD|ider_unmount_timeout/.test(r.body.text)) {
          addResult(slot, h('div', { class: 'result live', 'data-session': 'unmount_held' }, [icon('i-timer'), h('span', {}, [lead('unmount'),
            ' · Unmount requested; the serving thread has not stopped yet, so the session is still held. Check status again in a few seconds. · amt-mcp says: ' + r.body.text])]));
        } else addResult(slot, reply('unmount', r, ' · nothing changed', function (s) {
          return S.result('ok', 'i-check', [lead('unmount'), ' · unmounted · ' + num(s.bytes_to_host) + ' bytes were served to the host' + (s.ended_with_error ? ' · the serving thread had ended with: ' + s.ended_with_error : '')]);
        }));
        if (r.status === 200 && !r.body.isError) loadFleet();
      } };
  }
  function checkStatus(btn) {
    if (btn.getAttribute('aria-disabled') === 'true' || !key) return;
    var done = S.busy(btn, 'asking amt-mcp');
    amtc.post('/api/call', { tool: 'amt_ider', arguments: { device: key, action: 'status' } }).then(function (r) {
      done();
      addResult($('mounted-results'), reply('status', r, ' · nothing changed', function (s) {
        var names = Object.keys(s.images || {}).map(function (k) { return s.images[k]; }).join(', ');
        return S.result(s.mounted ? 'live' : 'ok', 'i-disc', [lead('status of ' + key), s.mounted ? ' · mounted: ' + names + ' · ' + num(s.bytes_to_host) + ' bytes served to the host so far' : ' · not mounted']);
      }));
      loadFleet();
    }, done);
  }

  // ---- library actions ----
  function verify(name, btn) {
    if (btn.getAttribute('aria-disabled') === 'true') return;
    var done = S.busy(btn, 'hashing the image');
    amtc.post('/api/call', { tool: 'amt_images', arguments: { action: 'verify', path: name } }).then(function (r) {
      done();
      addResult($('lib-results'), reply('verify ' + name, r, ' · nothing changed', function (s) {
        if (typeof s.sha256 === 'string') verified[name] = { sha: s.sha256, at: Date.now() / 1000 };
        renderLibrary();
        return S.result('ok', 'i-verified', [lead('verify ' + name), ' · sha256 recomputed ', S.fp(s.sha256 || ''), ' · ' + (s.mountable ? '512-byte aligned' : 'not 512-byte aligned: it cannot be mounted')]);
      }));
    }, done);
  }
  function deleteSpec(name) {
    return { id: 'sheet-img-delete', title: 'Delete ' + name, verb: 'delete', nowLabel: 'Delete now', call: { tool: 'amt_images', arguments: { action: 'delete', path: name } },
      consequence: 'The file is deleted from the image root. There is no undo; fetch or upload it again if you need it. Refused if it is mounted, downloading or uploading.',
      onResult: function (r) {
        addResult($('lib-results'), reply('delete ' + name, r, ' · nothing changed', function (s) { return S.result('ok', 'i-check', [lead('delete ' + name), ' · deleted · ' + S.bytes(s.bytes)]); }));
        readLibrary();
      } };
  }
  function renameSpec(name) {
    return { id: 'sheet-img-rename', title: 'Rename ' + name, verb: 'Rename', call: { tool: 'amt_images', arguments: { action: 'rename', path: name } },
      consequence: 'Renames the file in the image root. Refused if it is mounted, downloading or uploading. No host is touched.',
      fields: [{ name: 'new_name', label: 'New name', value: name, mono: true }],
      build: function (v) {
        var n = (v.new_name || '').trim();
        if (!plainName(n)) return { error: 'a plain .iso or .img file name' };
        if (n === name) return { error: 'enter a different name' };
        return { call: { tool: 'amt_images', arguments: { action: 'rename', path: name, new_name: n } } };
      },
      onResult: function (r) {
        addResult($('lib-results'), reply('rename ' + name, r, ' · nothing changed', function (s) { return S.result('ok', 'i-check', [lead('rename ' + name), ' · renamed to ' + s.to]); }));
        readLibrary();
      } };
  }
  function fetchSpec() {
    return { id: 'sheet-img-fetch', title: 'Fetch an image into the root', verb: 'Fetch', call: { tool: 'amt_images', arguments: { action: 'fetch' } },
      consequence: 'Downloads the URL into the image root on the server in the background; with a SHA-256 given, a mismatch deletes the file and reports failure. No host is touched.',
      fields: [{ name: 'url', label: 'URL', placeholder: 'https://…/image.iso' }, { name: 'name', label: 'Save as (optional)', mono: true, placeholder: 'taken from the URL' },
        { name: 'sha256', label: 'Expected SHA-256 (optional)', mono: true, placeholder: '64 hex characters' }],
      build: function (v) {
        var url = (v.url || '').trim(), name = (v.name || '').trim(), sha = (v.sha256 || '').trim();
        if (!/^https?:\/\/\S+$/i.test(url)) return { error: 'enter an http(s) URL' };
        if (name && !plainName(name)) return { error: 'save-as must be a plain .iso or .img name' };
        if (sha && !shaOk(sha)) return { error: 'the SHA-256 is 64 hex characters' };
        var args = { action: 'fetch', url: url };
        if (name) args.name = name;
        if (sha) args.sha256 = lower(sha);
        args.overwrite = false;
        return { call: { tool: 'amt_images', arguments: args } };
      },
      onResult: function (r, v) {
        addResult($('lib-results'), reply('fetch', r, ' · nothing was fetched', function (s) {
          return S.result('live', 'i-timer', [lead('fetch ' + s.name), ' · downloading in the background · progress is in the table' + (s.sha256_expected ? ' · sha256 is checked on completion' : '')]);
        }));
        readLibrary();
      } };
  }
  function uploadSpec() {
    return { id: 'sheet-img-upload', title: 'Upload a file from this computer', verb: 'Mint the upload and send', call: { tool: 'amt_images', arguments: { action: 'upload' } },
      consequence: 'amt-mcp mints a one-time url for exactly this size (and this SHA-256 if you give one); this console sends the file to it once, streaming it straight through to the image root, with progress in the library. A wrong size or hash is refused at the end and amt-mcp deletes the part file. The console keeps nothing of the file and the url never reaches this page.',
      fields: [{ name: 'file', label: 'File', type: 'file', accept: '.iso,.img' }, { name: 'sha256', label: 'Expected SHA-256 (optional)', mono: true, placeholder: '64 hex characters' }],
      build: function (v) {
        var f = v.file, sha = (v.sha256 || '').trim();
        if (!f) return { error: 'choose a file' };
        if (!plainName(f.name)) return { error: 'the file must be a plain .iso or .img', title: 'Upload ' + f.name + ' from this computer' };
        if (!f.size) return { error: 'the file is empty' };
        if (sha && !shaOk(sha)) return { error: 'the SHA-256 is 64 hex characters', notes: { file: f.name + ' · ' + num(f.size) + ' bytes' } };
        var args = { action: 'upload', name: f.name, size_bytes: f.size };
        if (sha) args.sha256 = lower(sha);
        return { call: { tool: 'amt_images', arguments: args }, title: 'Upload ' + f.name + ' from this computer',
          notes: { file: f.name + ' · ' + num(f.size) + ' bytes (read from the file; the url accepts exactly this many)' } };
      },
      onResult: function (r, v) {
        var slot = $('lib-results'), s = r.body && r.body.structured || {};
        if (r.status !== 200 || r.body.isError) { addResult(slot, reply('upload', r, ' · no upload url was minted', function () { return null; })); return; }
        if (!s.upload_id) {
          addResult(slot, S.result('error', 'i-block', [lead('upload ' + (s.name || '')), ' · amt-mcp\'s answer carried no usable upload url (' + (s.upload_refused || 'none') + ') · nothing is waiting for the file']));
          return;
        }
        send(v.file, s.upload_id);
      } };
  }
  function rootSpec() {
    return { id: 'sheet-img-root', title: 'Change the image root', verb: 'Set root', call: { tool: 'amt_images', arguments: { action: 'set_root' } },
      consequence: 'Points the library at another directory on the server (created if missing) and persists it ahead of the AMT_IMAGE_ROOT env. Mounted images keep serving.',
      fields: [{ name: 'root', label: 'Directory on the server', value: lib.root || '', mono: true }],
      build: function (v) {
        var root = (v.root || '').trim();
        return root ? { call: { tool: 'amt_images', arguments: { action: 'set_root', root: root } } } : { error: 'enter a directory' };
      },
      onResult: function (r) {
        addResult($('lib-results'), reply('set root', r, ' · nothing changed', function (s) {
          return S.result('ok', 'i-check', [lead('set root'), ' · image root is now ' + s.image_root + (s.previous ? ' (was ' + s.previous + ', set by ' + (s.previous_source || 'unknown') + ')' : ' (none was set)') + ' · persisted']);
        }));
        readLibrary();
      } };
  }

  // ---- sending an upload: the file goes to the console's route; the console streams it to amt-mcp ----
  function send(file, uploadId) {
    var name = file.name, slot = $('lib-results'), xhr = new XMLHttpRequest();
    sending[name] = { loaded: 0, total: file.size };
    xhr.open('POST', '/api/images/upload/' + uploadId);
    xhr.setRequestHeader('Content-Type', 'application/octet-stream');
    if (amtc.csrf) xhr.setRequestHeader('X-CSRF-Token', amtc.csrf);
    xhr.upload.onprogress = function (e) { sending[name] = { loaded: e.loaded, total: file.size }; renderAll(); };
    function end(node) { delete sending[name]; addResult(slot, node); readLibrary(); }
    xhr.onload = function () {
      var j = {};
      try { j = JSON.parse(xhr.responseText); } catch (e) { /* not JSON: shown as no answer */ }
      if (xhr.status === 200 && j.ok === true) end(S.result('ok', 'i-verified', [lead('upload ' + name), ' · received ' + num(j.bytes) + ' bytes (the declared size) · sha256 ', S.fp(j.sha256 || ''), ' recorded by amt-mcp · it is in the library']));
      else if (xhr.status === 200 && j.code === 'browser_stream_ended_early') end(S.result('error', 'i-block', [lead('upload ' + name), ' · the browser stopped after ' + num(j.sent) + ' of ' + num(j.size_bytes) + ' bytes; amt-mcp refuses a short body and deletes the part file · mint a new upload']));
      else if (xhr.status === 200 && j.status === 404) end(S.result('error', 'i-block', [lead('upload ' + name), ' · refused by the one-time url: ' + (j.text || 'not found') + ' · the url was used already or expired · mint a new upload']));
      else if (xhr.status === 200 && j.status) end(S.result('error', 'i-block', [lead('upload ' + name), ' · refused by the one-time url: ' + (j.text || 'no reason given') + ' · amt-mcp deleted the part file · mint a new upload']));
      else if (xhr.status === 200 && j.code) end(S.result('live', 'i-help', [lead('upload ' + name), ' · amt-mcp did not answer (' + j.code + ') · it is not known how much arrived; read the library before minting a new upload']));
      else end(S.result('error', 'i-block', [lead('upload ' + name), ' · refused: ' + (j.error || 'no answer') + ' · nothing was sent to amt-mcp · mint a new upload']));
    };
    xhr.onerror = function () { end(S.result('live', 'i-help', [lead('upload ' + name), ' · the connection to the console ended before an answer · it is not known how much arrived; read the library for the result, then mint a new upload'])); };
    xhr.send(file);
  }

  // ---- the page ----
  function renderAll() {
    if (document.querySelector('.sheet.open')) { dirty = true; return; }   // a sheet's opener must not be replaced under it
    dirty = false;
    var f = document.activeElement, mark = f && f.closest && f.closest('#lib-rows') ? f.getAttribute('aria-label') : null;
    renderPicker(); renderMounted(); renderLibrary(); renderMountForm(); renderRoot();
    if (mark) Array.prototype.some.call($('lib-rows').querySelectorAll('button[aria-label]'), function (b) {   // the table was rebuilt under the focus: put it back
      if (b.getAttribute('aria-label') !== mark) return false;
      b.focus(); return true;
    });
  }
  function renderRoot() {
    var bad = lib.phase === 'ok' && (!lib.root || lib.rootError), box = $('noroot');
    box.hidden = !bad;
    if (bad) $('noroot-text').textContent = (lib.root ? 'The image root is not usable, so every mount is refused until it is. ' : 'No image root is set: every mount is refused until one is. Set it here (persisted) or with AMT_IMAGE_ROOT on the server. ') + 'amt-mcp says: ' + (lib.rootError || 'no root');
  }
  function bind() {
    bindStartRadios();
    amtc.bindWrite($('mount-go'), mountSpec);
    amtc.bindWrite($('unmount'), unmountSpec);
    amtc.bindWrite($('lib-fetch'), fetchSpec);
    amtc.bindWrite($('lib-upload'), uploadSpec);
    amtc.bindWrite($('lib-root-change'), rootSpec);
    amtc.bindWrite($('noroot-set'), rootSpec);
    $('mounted-status').addEventListener('click', function () { checkStatus($('mounted-status')); });
    ['mount-iso', 'mount-floppy'].forEach(function (id) { $(id).addEventListener('change', renderMountForm); });
    var sel = $('media-server');
    if (sel) sel.addEventListener('change', function () { key = sel.value; renderAll(); });
  }
  function poll() {
    loadFleet();
    setTimeout(poll, POLL_MS);
  }
  function libPoll() {
    var busy = lib.fetches.some(function (f) { return f.state === 'running'; }) || lib.uploads.open.length > 0 || Object.keys(sending).length > 0;
    readLibrary().then(function () { setTimeout(libPoll, busy ? BUSY_MS : IDLE_MS); }, function () { setTimeout(libPoll, IDLE_MS); });
  }
  bind();
  renderAll();
  setInterval(function () { if (dirty) renderAll(); }, 1000);
  amtc.ready.then(function () { poll(); libPoll(); });
}());
