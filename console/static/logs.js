/* The Logs tab (design/logs.html, note 2.8): the event log or the audit log through amt_logs, newest first, with a time window, a
   severity filter on the page, the tool's own counts and paging. A read happens when the page opens, on Read, on a switch of log and on
   Newer / Older, never on a timer, and never for a paused server (a refused credential gets no second attempt from here). The counts
   under the table are the result's own fields; a result missing one is reported as unreadable, never as a zero. A tool's text and a
   record's text are data and are set as text nodes only. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var head = document.querySelector('.srvhead[data-server]'), page = document.getElementById('logs-page');
  if (!head || !page) return;
  var key = head.getAttribute('data-server'), POLL_MS = 5000;
  var LIMIT = window.matchMedia('(max-width: 599px)').matches ? 20 : 50;    // a phone page is card-per-row: 20 of them stay under the phone height ceiling
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;

  var st = { kind: 'event', sev: 'all', busy: false, paused: null, view: null, gone: false };   // view: the last readable result { s, args, kind, at }
  var ctl = {};
  ['read', 'newer', 'older'].forEach(function (n) { ctl[n] = { btn: $('log-' + n), wrap: $('log-' + n + '-wrap'), reason: null }; });
  var KINDS = { event: 'Event log', audit: 'Audit log' };
  var LEVEL_ICON = { critical: 'i-warning', warning: 'i-warning', info: 'i-info' };

  // ---- what the controls may do now ----
  function pagerTargets() {
    var v = st.view;
    if (!v) return { newer: null, older: null };
    var s = v.s, past = s.returned === 0 && s.matched > 0 && s.offset >= s.matched;
    return {
      newer: past ? Math.floor((s.matched - 1) / LIMIT) * LIMIT : s.offset > 0 ? Math.max(0, s.offset - LIMIT) : null,
      older: s.offset + s.returned < s.matched ? s.offset + LIMIT : null
    };
  }
  function controls() {
    var why = st.paused ? 'paused · ' + (st.paused.reason || 'refused') : st.busy ? 'waiting for amt-mcp' : null, t = pagerTargets();
    S.setReason(ctl.read, why);
    S.setReason(ctl.newer, why || (!st.view ? 'read first' : t.newer === null ? 'newest page' : null));
    S.setReason(ctl.older, why || (!st.view ? 'read first' : t.older === null ? 'oldest page' : null));
    ['event', 'audit'].forEach(function (k) {
      var b = $('log-' + k);
      b.setAttribute('aria-pressed', String(st.kind === k));
      if (st.busy) b.setAttribute('aria-disabled', 'true'); else b.removeAttribute('aria-disabled');
    });
    document.querySelectorAll('#sev-seg button').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-sev') === st.sev)); });
    $('sev-seg').hidden = st.kind !== 'event';                 // an audit record has no severity
    $('log-title').textContent = KINDS[st.kind];
  }
  function banner() {
    var box = $('logs-paused'), text = $('logs-paused-text');
    clear(text);
    box.hidden = !st.paused;
    if (st.paused) S.pausedNote('the log', key, st.paused).forEach(function (n) { text.appendChild(typeof n === 'string' ? document.createTextNode(n) : n); });
  }

  // ---- the arguments of the next read, exactly as the tool takes them ----
  function readArgs(offset, win) {                              // win: the displayed result's own args, when paging (the fields may have been edited since)
    var a = { device: key, kind: st.kind, offset: offset, limit: LIMIT }, since = win ? win.since : $('since').value.trim(), until = win ? win.until : $('until').value.trim();
    if (since) a.since = since;
    if (until) a.until = until;
    return a;
  }

  // ---- a result the page can trust: every field the footer is made of is present and of the right type ----
  function unreadable(s, args) {
    if (!s || typeof s !== 'object' || Array.isArray(s)) return 'no result object';
    var missing = ['fetched', 'matched', 'undated', 'undecodable', 'offset', 'returned'].filter(function (k) { return !(Number.isInteger(s[k]) && s[k] >= 0); });
    if (typeof s.fetch_complete !== 'boolean') missing.push('fetch_complete');
    if (!Array.isArray(s.records)) missing.push('records');
    else if (s.records.length !== s.returned || s.records.some(function (r) { return !r || typeof r !== 'object'; })) missing.push('records_vs_returned');
    if (s.kind !== undefined && s.kind !== args.kind) missing.push('kind');
    return missing.length ? 'missing or wrong: ' + missing.join(', ') : null;
  }

  // ---- reading ----
  function read(offset, win) {
    if (st.busy || st.paused || st.gone) return Promise.resolve();
    var args = readArgs(offset, win), kind = st.kind;
    st.busy = true; st.view = null;
    clear($('log-state')); clear($('log-table')); $('log-counts').textContent = ''; $('log-sevnote').hidden = true;
    $('log-state').appendChild(h('div', { class: 'progress', role: 'progressbar', 'aria-label': 'Reading the ' + kind + ' log' }, [h('i', { 'data-motion': 'progress' })]));
    controls();
    return amtc.post('/api/call', { tool: 'amt_logs', arguments: args }).catch(function () { return { status: 0, body: {} }; })
      .then(function (r) { st.busy = false; outcome(r, args, kind); return loadEntry(); });
  }
  function outcome(r, args, kind) {
    var slot = $('log-state'), b = r.body || {}, what = 'read the ' + kind + ' log';
    clear(slot);
    st.view = null;
    if (r.status !== 200) slot.appendChild(S.readFailure(what, r));
    else if (b.isError) slot.appendChild(S.readRefusal(what, b.text));
    else {
      var bad = unreadable(b.structured, args);
      if (bad) slot.appendChild(S.result('error', 'i-block', [S.stamp() + ' · ' + what + ' · amt-mcp returned a result this page cannot read (' + bad + '), so no count is shown: none can be trusted']));
      else st.view = { s: b.structured, args: args, kind: kind, at: Date.now() / 1000 };
    }
    draw();
  }

  // ---- drawing ----
  function td(label, kids, cls) { return h('td', { 'data-l': label, class: cls || null }, kids); }
  function hex(n) { return Number.isInteger(n) && n >= 0 ? '0x' + (n < 16 ? '0' : '') + n.toString(16) : null; }
  function nr(s) { return h('span', { class: 'muted' }, [s || 'not reported']); }
  function stamps(r) {                                          // the record's UTC time, with US Eastern beside it
    var m = typeof r.timestamp === 'string' && /^(\d{4}-\d\d-\d\d)T(\d\d:\d\d:\d\d)Z$/.exec(r.timestamp);
    if (!m) return [r.timestamp ? String(r.timestamp) : 'no time'];
    var out = [m[1] + ' ' + m[2] + ' UTC'];
    if (Number.isInteger(r.epoch)) out.push(h('span', { class: 'loc body-s muted' }, [S.eastern(r.epoch)]));
    return out;
  }
  function sevCell(r) {
    var lvl = typeof r.level === 'string' ? r.level : null, known = lvl && LEVEL_ICON[lvl];
    var kids = [h('span', { class: 'sev' + (known ? ' ' + lvl : '') }, [icon(known ? LEVEL_ICON[lvl] : 'i-help'), lvl || 'level not reported'])];
    if (typeof r.severity === 'string' && r.severity.toLowerCase() !== lvl) kids.push(h('span', { class: 'loc body-s muted' }, [r.severity]));
    return kids;
  }
  function eventRow(r) {
    if (r.decoded === false) return h('tr', { 'data-decoded': 'false' }, [td('Level', [h('span', { class: 'sev' }, [icon('i-help'), 'undecodable'])]), td('Time', ['no time'], 't data'),
      td('Source', [nr('unknown')]), td('Description', ['could not be decoded']), td('Raw sensor / type / data', [r.raw_hex ? 'raw hex ' + r.raw_hex : 'raw not available'], 'data muted')]);
    var raw = [hex(r.sensor_type), hex(r.event_type), typeof r.event_data_hex === 'string' ? '0x' + r.event_data_hex : null].map(function (x) { return x === null ? 'not reported' : x; }).join(' / ');
    return h('tr', { 'data-level': typeof r.level === 'string' ? r.level : null }, [td('Level', sevCell(r)), td('Time', stamps(r), 't data'),
      td('Source', [typeof r.source === 'string' ? r.source : nr()]), td('Description', [typeof r.description === 'string' ? r.description : nr()]),
      td('Raw sensor / type / data', [raw], 'data muted')]);
  }
  function auditInitiator(r) {
    var kind = typeof r.initiator_kind === 'string' ? r.initiator_kind.replace(/_/g, ' ') : null, who = typeof r.initiator === 'string' ? r.initiator : null;
    if (!kind && !who) return [nr()];
    if (kind && who && who.toLowerCase() === kind) return [kind];
    return [(kind || 'kind not reported') + (who ? ' · ' + who : '')];
  }
  function auditExtra(r) {
    var parts = [];
    if (typeof r.net_address === 'string' && r.net_address) parts.push('address ' + r.net_address);
    if (typeof r.extended_data === 'string' && r.extended_data) parts.push(r.extended_data);
    var raw = typeof r.extended_data_hex === 'string' ? r.extended_data_hex : '', kids = [];
    if (parts.length) kids.push(parts.join(' · '));
    if (raw) kids.push(h('span', { class: 'muted' }, [(parts.length ? ' · ' : '') + 'hex ' + raw.replace(/(.{4})(?=.)/g, '$1 ')]));
    return kids.length ? kids : ['—'];
  }
  function auditRow(r) {
    if (r.decoded === false) return h('tr', { 'data-decoded': 'false' }, [td('Time', ['no time'], 't data'), td('App', [nr('unknown')]), td('Event', ['could not be decoded']),
      td('Initiator', [nr('unknown')]), td('Extended data', [r.raw_hex ? 'raw hex ' + r.raw_hex : 'raw not available'], 'data muted')]);
    return h('tr', {}, [td('Time', stamps(r), 't data'), td('App', [typeof r.app === 'string' ? r.app : nr()]), td('Event', [typeof r.event === 'string' ? r.event : nr()]),
      td('Initiator', auditInitiator(r)), td('Extended data', auditExtra(r), 'data')]);
  }
  function keepRow(r) {                                         // the severity filter hides only a record known to be below it
    if (st.kind !== 'event' || st.sev === 'all' || r.decoded === false) return true;
    if (r.level === 'info') return false;
    return !(st.sev === 'critical' && r.level === 'warning');
  }

  function span(args) {
    if (args.since && args.until) return 'between ' + args.since + ' and ' + args.until;
    if (args.since) return 'at or after ' + args.since;
    if (args.until) return 'at or before ' + args.until;
    return 'in the window';
  }
  function countsText(s, args) {
    var filtered = !!(args.since || args.until);
    var undated = s.undated + ' undated' + (s.undated ? ' (no AMT clock time on the record: ' + (filtered ? 'dropped by the time filter)' : 'listed last)') : '');
    var undec = s.undecodable + ' undecodable' + (s.undecodable ? (filtered ? ' (no time, so the time filter drops them)' : ' (shown with their raw hex)') : '');
    return 'matched ' + s.matched + ' of ' + s.fetched + ' fetched · ' + (s.fetch_complete ? 'fetch complete' : 'fetch incomplete: more records may exist than were read') + ' · '
      + undated + ' · ' + undec + ' · ' + (s.returned ? 'showing ' + (s.offset + 1) + '–' + (s.offset + s.returned) + ' newest first' : 'showing none');
  }
  function note(kind, iconId, text, state) {
    var n = S.result(kind, iconId, [text]);
    n.setAttribute('data-state', state);
    return n;
  }
  function draw() {
    controls();
    var slot = $('log-state'), tbl = $('log-table'), v = st.view, sevnote = $('log-sevnote');
    clear(tbl); $('log-counts').textContent = ''; sevnote.hidden = true; $('log-call').textContent = '';
    if (!v) return;
    clear(slot);
    var s = v.s, args = v.args, kind = v.kind;
    $('log-counts').textContent = countsText(s, args);
    $('log-call').textContent = amtc.fmtCall({ tool: 'amt_logs', arguments: args }) + ' · read-only · read ' + S.eastern(v.at, false);
    if (!s.fetch_complete) slot.appendChild(note('live', 'i-timer', 'The fetch did not complete: the counts cover the ' + s.fetched + ' record' + (s.fetched === 1 ? '' : 's') + ' read, and older records may exist.', 'incomplete'));
    if (s.fetched === 0) {                                      // nothing was read: an empty log, or a read that did not finish
      slot.appendChild(s.fetch_complete
        ? note('live', 'i-info', 'The ' + kind + ' log is empty: ' + s.fetched + ' fetched, ' + s.undated + ' undated, ' + s.undecodable + ' undecodable. A cleared or never-written log looks like this; a filter that matched nothing does not.', 'emptylog')
        : note('live', 'i-help', 'Nothing was read and the fetch did not finish, so it is not known whether the ' + kind + ' log is empty.', 'unread'));
      return;
    }
    if (s.returned === 0) {                                     // records exist, but none is on this page
      slot.appendChild(s.matched === 0
        ? note('live', 'i-info', 'No records in this window: ' + s.fetched + ' were fetched and none is ' + span(args) + '. The ' + kind + ' log itself is not empty (it holds ' + (s.fetch_complete ? '' : 'at least ') + s.fetched + '). Widen the window.', 'emptypage')
        : note('live', 'i-info', 'This page is past the end: ' + s.matched + ' records match and offset ' + s.offset + ' is beyond them. Press Newer.', 'pastend'));
      return;
    }
    var shown = s.records.filter(keepRow);
    if (st.kind === 'event' && st.sev !== 'all') {
      sevnote.hidden = false;
      sevnote.textContent = 'Severity filter ' + (st.sev === 'warning' ? 'warning+' : 'critical') + ': ' + shown.length + ' of the ' + s.returned + ' records on this page shown, ' + (s.returned - shown.length)
        + ' hidden. The counts above are for the whole log, before the filter; other pages may hold more.';
    }
    if (!shown.length) {
      slot.appendChild(note('live', 'i-info', 'All ' + s.returned + ' records on this page are below the severity filter. Other pages may hold more.', 'sevhidden'));
      return;
    }
    var cols = st.kind === 'event' ? ['Level', 'Time', 'Source', 'Description', 'Raw sensor / type / data'] : ['Time', 'App', 'Event', 'Initiator', 'Extended data'];
    var table = h('table', { class: 'tbl ' + (st.kind === 'event' ? 'logs' : 'audit'), 'data-kind': st.kind }, [
      h('thead', {}, [h('tr', {}, cols.map(function (c) { return h('th', { scope: 'col' }, [c]); }))]),
      h('tbody', {}, shown.map(st.kind === 'event' ? eventRow : auditRow))]);
    tbl.appendChild(h('div', { class: 'tbl-wrap' }, [table]));
  }

  // ---- the server's cached state: paused or not (the console's own route, no AMT contact) ----
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
  ctl.read.btn.addEventListener('click', function () { if (ctl.read.btn.getAttribute('aria-disabled') !== 'true') read(0); });
  ctl.newer.btn.addEventListener('click', function () { var t = pagerTargets().newer; if (t !== null) read(t, st.view.args); });     // no view, no target: a busy, paused or unread page has none
  ctl.older.btn.addEventListener('click', function () { var t = pagerTargets().older; if (t !== null) read(t, st.view.args); });
  ['event', 'audit'].forEach(function (k) {
    $('log-' + k).addEventListener('click', function () {
      if (st.busy || st.kind === k) return;
      st.kind = k; st.view = null; clear($('log-state')); clear($('log-table')); $('log-counts').textContent = ''; $('log-sevnote').hidden = true; $('log-call').textContent = '';
      controls();
      read(0);
    });
  });
  document.querySelectorAll('#sev-seg button').forEach(function (b) {
    b.addEventListener('click', function () { st.sev = b.getAttribute('data-sev'); draw(); });      // on the page: no new read
  });
  ['since', 'until'].forEach(function (id) {
    $(id).addEventListener('keydown', function (e) { if (e.key === 'Enter' && !e.repeat && ctl.read.btn.getAttribute('aria-disabled') !== 'true') read(0); });
  });
  controls();
  amtc.ready.then(function () {
    loadEntry().then(function () { read(0); });
    setInterval(loadEntry, POLL_MS);                                // the cached state only: a pause or a resume shows; no log is read
  });
}());
