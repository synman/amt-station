/* The fleet page: one card per server from the console's own /api/fleet (the backend reads amt_status and the session
   views on its schedule; this page only asks for the cached result), the filters, Retry, and the screenshot sheet. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var POLL_MS = 5000, grid = document.getElementById('fleet-grid'), cards = {}, snap = null, show = 'all', query = '';
  if (!grid) return;
  var $ = function (id) { return document.getElementById(id); };

  function line(e) {
    var bits = [e.address || 'address unknown', e.version ? 'AMT ' + e.version : 'AMT version not read'];
    var text = bits.join(' · ');
    if ((e.state === 'unreachable' || e.state === 'paused') && e.read_at) text += ' (last read ' + S.eastern(e.read_at, false) + ')';
    return text;
  }
  function modeOf(e) { return e.state === 'paused' ? 'paused' : e.state === 'unreachable' ? 'unreachable' : 'live'; }
  function problem(e) {
    return e.state === 'unreachable' || e.state === 'paused' || e.pin === 'differs' || e.pin === 'unpinned' || (e.sessions && e.sessions.kvm.holder === 'other');
  }
  function held(e) {
    var s = e.sessions; return !!s && (s.kvm.holder === 'console' || s.kvm.holder === 'agent' || s.sol.holder === 'console' || s.sol.holder === 'agent' || s.ider.mounted === true);
  }
  function visible(e) {
    if (query) {
      var hay = [e.key, e.address, e.version].join(' ').toLowerCase();
      if (hay.indexOf(query.toLowerCase()) === -1) return false;
    }
    return show === 'all' || (show === 'on' && e.power.kind === 'on') || (show === 'held' && held(e)) || (show === 'problems' && problem(e));
  }

  // ---- one card ----
  function link(cls, href, iconId, label) { return h('a', { class: 'btn ' + cls, href: href }, [icon(iconId), label]); }
  function retryButton(e, label, card) {
    var b = h('button', { type: 'button', class: 'btn tonal' }, [icon('i-refresh'), label]);
    b.addEventListener('click', function () {
      if (b.getAttribute('aria-disabled') === 'true') return;
      var done = S.busy(b, 'waiting for amt-mcp');
      amtc.post('/api/fleet/refresh', { device: e.key }).then(function (r) {
        done();
        if (r.status === 200 && r.body.server) { replace(r.body.server); render(); }
      });
    });
    return b;
  }
  function buildActions(e, card) {
    var key = e.key, mode = modeOf(e), acts = h('div', { class: mode === 'live' ? 'acts' : 'row' });
    if (mode === 'live') {
      acts.appendChild(link('tonal', '/server/' + key + '/console', 'i-monitor', 'KVM'));
      acts.appendChild(link('outlined', '/server/' + key + '/power', 'i-power', 'Power'));
      var shot = h('button', { type: 'button', class: 'btn text', 'aria-label': 'Screenshot of ' + key }, [icon('i-camera'), 'Shot']);
      amtc.bindWrite(shot, function () {                      // the sheet for amt_screenshot, built by the shared component
        return { id: 'shot-' + key, title: 'Take a screenshot of ' + key, verb: 'Take screenshot', readOnly: true,
          consequence: 'Opens the host\'s single KVM session for a moment (or shares your mirror\'s), grabs the screen and closes it. Where user consent is required this may show a consent prompt on the host. It sends no input.',
          call: { tool: 'amt_screenshot', arguments: { device: key } },
          callNote: 'read-only · the result\'s one-time url is fetched once by the console, its sha256 checked, then kept in the capture store',
          onResult: function (r) { var slot = card.querySelector('.shot'); S.clear(slot); slot.appendChild(S.shotResult(key, r, true)); } };
      });
      acts.appendChild(shot);
      acts.appendChild(link('text', '/server/' + key + '/serial', 'i-terminal', 'SOL'));
    } else if (mode === 'unreachable') {
      acts.appendChild(retryButton(e, 'Retry now', card));
      acts.appendChild(link('text', '/server/' + key + '/power', 'i-power', 'Power'));
      acts.appendChild(link('text', '/manage', 'i-edit', 'Edit server'));
    } else {
      acts.appendChild(retryButton(e, 'Retry once', card));
      acts.appendChild(link('text', '/manage/identities', 'i-key', 'Identities'));
    }
    return acts;
  }
  function newCard(e) {
    var card = h('article', { class: 'card high scard', 'aria-labelledby': 'c-' + e.key, 'data-key': e.key }, [
      h('div', { class: 'row' }, [h('h2', { id: 'c-' + e.key }, [h('a', { class: 'tlink', href: '/server/' + e.key }, [e.key])]), h('span', { class: 'spacer' }), h('span', { class: 'slot-pill' })]),
      h('div', { class: 'data muted slot-line' }), h('div', { class: 'row slot-sess' }), h('div', { class: 'row slot-pin' }), h('div', { class: 'slot-state' }),
      h('div', { class: 'slot-acts' }), h('div', { class: 'shot' })]);
    return card;
  }
  function fill(card, e) {
    card.setAttribute('data-fleet-state', e.state);
    var set = function (sel, kids) { var el = card.querySelector(sel); S.clear(el); kids.forEach(function (k) { if (k) el.appendChild(typeof k === 'string' ? document.createTextNode(k) : k); }); };
    set('.slot-pill', [S.pill(e.power)]);
    set('.slot-line', [line(e)]);
    var sess = [];
    if (e.state === 'paused') sess.push(S.pausedChip(e, true));
    else if (e.sessions) { sess.push(S.kvmChip(e.sessions.kvm, true)); if (e.sessions.sol.holder !== 'free') sess.push(S.solChip(e.sessions.sol, true)); sess.push(S.iderChip(e.sessions.ider, true)); }
    else sess.push(S.kvmChip({ holder: 'unknown' }, true));
    set('.slot-sess', sess);
    var note = e.state === 'live' ? 'status read ' + S.ago(e.age_s) : e.state === 'paused' ? 'no automatic reads' : '';
    set('.slot-pin', [S.pinChip(e, true), note ? h('span', { class: 'body-s muted' }, [note]) : null]);
    var state = [];
    if (e.state === 'loading') state.push(h('div', { class: 'progress', role: 'progressbar', 'aria-label': 'Reading ' + e.key }, [h('i', { 'data-motion': 'progress' })]));
    else if (e.state === 'unreachable') {
      state.push(S.result('error', 'i-cloud-off', [(e.error || 'no answer') + ' Next automatic read in ' + Math.round(e.next_in_s || 0) + ' s; power actions stay available (AMT may answer when the OS does not).']));
    } else if (e.state === 'paused') {
      var why = e.paused && e.paused.reason === 'pin differs'
        ? 'The TLS leaf differs from the pin: every call to this server is refused until it is re-pinned in Manage.'
        : 'One Digest attempt, no further attempts: the account can lock.';
      state.push(S.result('error', 'i-block', [(e.error || '') + ' · ' + why + ' Polling of this server is paused until its identity is replaced, it is re-pinned, or you retry once.']));
    }
    set('.slot-state', state);
    var acts = card.querySelector('.slot-acts');
    if (acts.getAttribute('data-mode') !== modeOf(e)) { S.clear(acts); acts.appendChild(buildActions(e, card)); acts.setAttribute('data-mode', modeOf(e)); }
  }

  // ---- the page ----
  function replace(entry) {
    if (!snap) return;
    snap.servers = snap.servers.map(function (s) { return s.key === entry.key ? entry : s; });
  }
  function banner() {
    var parts = [], n = 0, first = null, mounts = [], recording = [];
    snap.servers.forEach(function (e) {
      var s = e.sessions; if (!s) return;
      if (s.kvm.holder === 'console') { n += 1; first = first || e.key; parts.push('KVM on ' + e.key + ', control, ' + S.elapsed(s.kvm.elapsed_s)); }
      if (s.sol.holder === 'console') { n += 1; first = first || e.key; parts.push('serial terminal on ' + e.key + ', ' + S.elapsed(s.sol.elapsed_s)); }
      if (s.ider.mounted === true) mounts.push(e.key + (Object.keys(s.ider.images || {}).length ? ', ' + Object.keys(s.ider.images).map(function (k) { return s.ider.images[k]; }).join(', ') : ''));
      if (s.kvm.recording || s.sol.recording) recording.push(e.key);
    });
    var box = $('fleet-banner');
    if (!n) { box.hidden = true; return; }
    var text = $('fleet-banner-text'); S.clear(text);
    text.appendChild(h('strong', {}, [n + (n === 1 ? ' session held by you:' : ' sessions held by you:')]));
    text.appendChild(document.createTextNode(' ' + parts.join(' · ') + (mounts.length ? ' · ' + mounts.length + ' IDE-R mount' + (mounts.length === 1 ? '' : 's') + ' (' + mounts.join('; ') + ')' : '') +
      ' · ' + (recording.length ? 'recording on ' + recording.join(', ') : 'no recording')));
    $('fleet-banner-open').setAttribute('href', '/server/' + first + '/console');
    box.hidden = false;
  }
  function render() {
    if (!snap) return;
    $('fleet-loading').hidden = snap.loaded || snap.servers.length > 0;
    var err = $('fleet-error'); err.hidden = !snap.devices_error;
    if (snap.devices_error) $('fleet-error-text').textContent = 'amt-mcp could not list its servers: ' + snap.devices_error + ' · the cards below are from the last good read.';
    $('fleet-count').textContent = snap.servers.length + (snap.servers.length === 1 ? ' server' : ' servers');
    $('fleet-note').textContent = 'auto-refresh ' + Math.round(snap.interval) + ' s · amt_status per server · pauses on a refused credential';
    banner();
    var seen = {}, shown = 0;
    snap.servers.forEach(function (e) {
      seen[e.key] = true;
      var card = cards[e.key];
      if (!card) { card = cards[e.key] = newCard(e); }
      fill(card, e);
      var ok = visible(e);
      card.hidden = !ok; if (ok) shown += 1;
      grid.appendChild(card);                                   // keeps the server order; moves, never rebuilds
    });
    Object.keys(cards).forEach(function (k) { if (!seen[k]) { cards[k].remove(); delete cards[k]; } });
    $('fleet-empty').hidden = !(snap.loaded && snap.servers.length === 0 && !snap.devices_error);
    $('fleet-nomatch').hidden = !(snap.servers.length > 0 && shown === 0);
  }
  function poll() {
    S.get('/api/fleet').then(function (r) { if (r.status === 200) { snap = r.body; render(); } });
  }

  $('q').addEventListener('input', function (ev) { query = ev.target.value.trim(); render(); });
  document.querySelectorAll('[data-show]').forEach(function (b) {
    b.addEventListener('click', function () {
      show = b.getAttribute('data-show');
      document.querySelectorAll('[data-show]').forEach(function (o) { o.setAttribute('aria-pressed', String(o === b)); });
      render();
    });
  });
  $('fleet-refresh').addEventListener('click', function () { amtc.post('/api/fleet/refresh', {}).then(function () { poll(); }); });
  amtc.ready.then(function () { poll(); setInterval(poll, POLL_MS); });
}());
