/* The server page: the persistent header (name, power pill, address, session and pin chips, tabs) on every tab, and on
   the Status tab the cards from amt_status with their coverage, the sessions panel, the capture card and the past
   captures. Data comes from the console's own /api/server/<key> routes; a value the tool did not report says so. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var head = document.querySelector('.srvhead[data-server]');
  if (!head) return;
  var key = head.getAttribute('data-server'), POLL_MS = 5000, entry = null, gone = false, interval = 30;
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;

  // ---- small builders ----
  var nr = function () { return h('span', { class: 'muted' }, ['not reported']); };
  var words = function (v) { return typeof v === 'string' ? v.replace(/_/g, ' ') : v; };
  function val(v, withCode) {                                 // a label with its code beside it
    if (v === null || v === undefined) return [nr()];
    return [String(words(v))].concat(withCode === undefined || withCode === null ? [] : [' ', h('span', { class: 'data muted' }, ['code ' + withCode])]);
  }
  function onoff(v) {
    return v === true ? h('span', { class: 'chip small ok' }, [icon('i-check'), 'enabled']) : v === false ? h('span', { class: 'chip small' }, ['disabled']) : nr();
  }
  function kv(rows) {
    var dl = h('dl', { class: 'kv' });
    rows.forEach(function (r) { dl.appendChild(h('dt', {}, [r[0]])); dl.appendChild(h('dd', {}, r[1])); });
    return dl;
  }
  function card(iconId, title, rows, extra, stale) {
    var h2 = h('h2', {}, [icon(iconId), title, h('span', { class: 'spacer' })]);
    if (stale) h2.appendChild(h('span', { class: 'chip small dashed' }, ['stale · ' + (entry.read_at ? 'last good ' + S.eastern(entry.read_at, false) : 'never read')]));
    if (extra) h2.appendChild(extra);
    return h('div', { class: 'card' }, [h2, kv(rows)]);
  }
  var textLink = function (href, label) { return h('a', { class: 'btn text', href: href }, [label]); };

  // ---- the header ----
  function renderHeader() {
    var e = entry, pill = $('srv-pill'), line = $('srv-line'), chips = $('srv-chips');
    clear(pill); pill.appendChild(S.pill(e.power));
    var read = e.state === 'live' ? ' · read ' + S.ago(e.age_s) : e.read_at ? ' · last read ' + S.eastern(e.read_at, false) : '';
    line.textContent = (e.address || 'address unknown') + (e.version ? ' · AMT ' + e.version : '') + read;
    clear(chips);
    if (e.state === 'paused') chips.appendChild(S.pausedChip(e, false));
    else if (e.sessions) {
      chips.appendChild(S.kvmChip(e.sessions.kvm, false, true));
      chips.appendChild(S.solChip(e.sessions.sol, false, true));
      var ider = S.iderChip(e.sessions.ider, false, true); if (ider) chips.appendChild(ider);
    } else chips.appendChild(S.kvmChip({ holder: 'unknown' }, false, true));
    chips.appendChild(S.pinChip(e, false, true));
  }
  function revealCurrentTab() {                               // the current section is inside the viewport at every width
    document.querySelectorAll('.srvhead .tabs, .srvhead .chips-scroll').forEach(function (bar) {
      var cur = bar.querySelector('[aria-current="page"]');
      if (!cur || bar.offsetParent === null) return;
      var left = cur.offsetLeft, right = left + cur.offsetWidth;
      if (left < bar.scrollLeft || right > bar.scrollLeft + bar.clientWidth) bar.scrollLeft = Math.max(0, left - (bar.clientWidth - cur.offsetWidth) / 2);
    });
  }

  // ---- the state card ----
  function renderState() {
    var box = $('srv-state'); if (!box) return;
    clear(box);
    var e = entry;
    if (e.state === 'loading') {
      box.appendChild(h('div', { class: 'card outlined' }, [h('h2', {}, ['Reading ' + e.key]), h('div', { class: 'progress', role: 'progressbar', 'aria-label': 'Reading ' + e.key }, [h('i', { 'data-motion': 'progress' })])]));
    } else if (e.state === 'unreachable') {
      var retry = h('button', { type: 'button', class: 'btn tonal' }, [icon('i-refresh'), 'Retry now']);
      retry.addEventListener('click', function () { guarded(retry); });
      box.appendChild(h('div', { class: 'card outlined', 'data-state': 'unreachable' }, [h('h2', {}, [icon('i-cloud-off'), 'Host unreachable']),
        h('p', { class: 'm0' }, ['The last status read failed: ', h('span', { class: 'data' }, [e.error || 'no answer']), '. ',
          e.read_at ? 'Values below are from ' + S.eastern(e.read_at) + ' and are marked stale. ' : 'No earlier read exists, so nothing below is known. ',
          'Power actions stay available: AMT may answer when the OS does not. Next automatic read in ' + Math.round(e.next_in_s || 0) + ' s.']), h('div', { class: 'row' }, [retry])]));
    } else if (e.state === 'paused') {
      var once = h('button', { type: 'button', class: 'btn tonal' }, [icon('i-refresh'), 'Retry once']);
      once.addEventListener('click', function () { guarded(once); });
      var pin = e.paused && e.paused.reason === 'pin differs';
      box.appendChild(h('div', { class: 'card outlined', 'data-state': 'paused' }, [h('h2', {}, [icon('i-block'), 'Paused · ' + (e.paused ? e.paused.reason : 'refused')]),
        h('p', { class: 'm0' }, [h('span', { class: 'data' }, [e.error || '']), ' · ', pin ? 'The TLS leaf differs from the pin: every call to this server is refused until it is re-pinned in Manage. '
          : 'One Digest attempt, no further attempts: the account can lock. ', 'Automatic reads of this server stopped at ' + S.eastern(e.paused.at, false) + ' and resume when its identity is replaced, it is re-pinned, or you retry once and the read succeeds.']),
        h('div', { class: 'row' }, [once, textLink('/manage/identities', 'Identities')])]));
    }
  }

  // ---- the status cards ----
  function nextBoot(nb) {
    var set = Object.keys(nb || {}).filter(function (k) { var v = nb[k]; return v === true || (typeof v === 'number' && v !== 0); });
    return set.length ? set.map(function (k) { return h('span', { class: 'chip small' }, [k + (nb[k] === true ? '' : ' ' + nb[k])]); }) : ['normal ', h('span', { class: 'muted' }, ['(no override reported)'])];
  }
  function renderCards() {
    var box = $('status-cards'); if (!box) return;
    clear(box);
    var e = entry, st = e.status; if (!st) return;
    var stale = e.state !== 'live';
    var p = st.power || {}, a = st.amt || {}, pr = st.provisioning || {}, rd = st.redirection || {}, kvm = rd.kvm || {}, uc = st.user_consent || {};
    $('read-note').textContent = 'amt_status · read-only WS-MAN reads · ' + (stale ? 'last good read ' + (e.read_at ? S.eastern(e.read_at) : 'never') : 'read ' + S.ago(e.age_s)) + ' · auto ' + Math.round(interval) + ' s';
    box.appendChild(card('i-power', 'Power', [['State', [S.pill(e.power), ' ', h('span', { class: 'data muted' }, ['code ' + (p.code === undefined ? 'not reported' : p.code)])]],
      ['Next boot', nextBoot(st.next_boot)]], textLink('/server/' + key + '/power', 'Actions'), stale));
    var build = [a.version ? 'version ' + a.version : null, a.build_number ? 'build ' + a.build_number : null, a.sku ? 'sku ' + a.sku : null].filter(Boolean);
    box.appendChild(card('i-memory', 'AMT', [['Version', build.length ? [h('span', { class: 'data' }, [build.join(' · ')])] : [nr()]],
      ['Provisioning', [pr.mode === undefined && pr.state === undefined && pr.control_mode === undefined ? nr() : [pr.mode, pr.state, pr.control_mode].map(words).filter(Boolean).join(' · ')]],
      ['Zero-touch', [pr.zero_touch_enabled === true ? 'enabled' : pr.zero_touch_enabled === false ? 'disabled' : nr()]]], null, stale));
    var kvmText = kvm.state === undefined && kvm.port_5900_enabled === undefined ? [nr()] : [words(kvm.state) + (kvm.state_code === undefined ? '' : ' (state ' + kvm.state_code + ')') + ' · port 5900 ',
      h('strong', {}, [kvm.port_5900_enabled === true ? 'open' : kvm.port_5900_enabled === false ? 'closed' : 'not reported']),
      kvm.session_timeout === undefined ? '' : ' · session timeout ' + kvm.session_timeout + ' min'];
    box.appendChild(card('i-cast', 'Redirection', [['Listener', [onoff(rd.listener_enabled)]], ['KVM', kvmText], ['SOL', [onoff(rd.sol_enabled)]], ['IDE-R', [onoff(rd.ider_enabled)]]], null, stale));
    var ucCard = card('i-person', 'User consent', [['Required for', val(uc.required_for, uc.required_code)], ['State', val(uc.state, uc.state_code)],
      ['Policy', uc.can_modify_policy === true ? ['can be changed · ', h('a', { href: '/server/' + key + '/settings' }, ['AMT settings · kvm'])] : uc.can_modify_policy === false ? ['cannot be changed from here'] : [nr()]]], null, stale);
    if (uc.state_code === 1 || uc.state_code === 2) {
      ucCard.appendChild(S.result('live', 'i-pin', ['A consent code is showing on the host\'s screen. Read it from the console and enter it in ', h('a', { href: '/server/' + key + '/wsman' }, ['Advanced → Send a consent code']),
        ' (IPS_OptInService.SendOptInCode); there is no typed console control for it yet.']));
    }
    box.appendChild(ucCard);
    var un = (st.unavailable || []).map(function (c) { return [h('span', { class: 'chip small dashed' }, [c]), ' ', h('span', { class: 'body-s muted' }, [(st.unavailable_reasons || {})[c] || 'this AMT does not expose it'])]; });
    var unDd = un.length ? [].concat.apply([], un).concat([h('span', { class: 'body-s muted' }, ['its section is empty, the rest was read'])]) : ['none'];
    var tr = (st.truncated || []).length ? (st.truncated.map(function (c) { return h('span', { class: 'chip small' }, [c]); })).concat([h('span', { class: 'body-s muted' }, ['cut at the item cap: more exist than were read'])]) : ['none'];
    box.appendChild(card('i-list', 'Coverage', [['Unavailable', unDd], ['Truncated', tr]], h('span', { class: 'chip small' }, ['this read']), stale));
    box.appendChild(card('i-fingerprint', 'Identity', [['TLS leaf', [S.fp(e.leaf, e.prefix)]],
      ['Pinned', [e.pin === 'matches' ? h('span', { class: 'chip small ok' }, [icon('i-verified'), 'matches on every connection']) : e.pin === 'differs' || e.pin === 'unpinned' ? h('span', { class: 'chip small error' }, [icon('i-block'), e.pin === 'differs' ? 'differs · every call refused' : 'unpinned · every call refused'])
        : h('span', { class: 'chip small dashed' }, [icon('i-help'), 'not checked by a read yet'])]],
      ['Compare', [h('span', { class: 'muted' }, ['against the fingerprint MEBx shows; the console never shows an AMT password'])]]], null, false));
  }

  // ---- the sessions panel ----
  function row(iconId, lead, sub, action) {
    var li = h('li', {}, [icon(iconId), h('span', { class: 'txt' }, [h('span', {}, lead), h('span', { class: 'sub' }, sub)])]);
    if (action) li.appendChild(action);
    return li;
  }
  function holderRow(kind, view) {
    var label = kind === 'kvm' ? 'KVM' : 'SOL', icn = kind === 'kvm' ? 'i-cast' : 'i-terminal', page = kind === 'kvm' ? 'console' : 'serial';
    if (!view || view.holder === 'unknown') return row(icn, [label + ' · unknown'], [entry.sessions_error || 'amt-mcp\'s session status could not be read']);
    var since = view.since ? (kind === 'kvm' ? 'mirror' : 'terminal') + ' started ' + S.eastern(view.since, false) : '';
    var facts = [since, kind === 'kvm' && view.fps ? view.fps + ' fps' : '', typeof view.viewers === 'number' ? view.viewers + (view.viewers === 1 ? ' viewer' : ' viewers') : ''].filter(Boolean).join(' · ');
    var flight = view.in_flight ? ' · an agent\'s call (' + view.in_flight.tool + ') is using this session' + (view.in_flight.started_at ? ' since ' + S.eastern(view.in_flight.started_at, false) : '') : '';
    var open = textLink('/server/' + key + '/' + page, 'Open');
    if (view.holder === 'console') return row(icn, [label + ' · ', h('strong', {}, ['held by you']), kind === 'kvm' ? ' (console, control token)' : ' (console)'], [facts + ' · agents share this session while it runs' + flight], open);
    if (view.holder === 'agent') return row(icn, [label + ' · ', h('strong', {}, ['held by an agent via the ' + (kind === 'kvm' ? 'mirror' : 'terminal')])], [facts + ' · the console attaches to it, it did not start it' + flight], open);
    if (view.holder === 'other') return row('i-lock', [label + ' · ', h('strong', {}, ['held by another client'])], ['amt-mcp could not open it and the console cannot take it over · opens refused (refusal seen ' + S.ago(view.refused_age_s) + ')']);
    return row(icn, [label + ' · free'], [kind === 'kvm' ? 'no mirror is running; starting one opens the host\'s single KVM session' : 'a serial terminal or amt_sol opens it; it runs beside KVM (verified live)'], textLink('/server/' + key + '/' + page, 'Start'));
  }
  function renderSessions() {
    var box = $('sessions-body'); if (!box) return;
    clear(box);
    var s = entry.sessions, ul = h('ul', { class: 'list' });
    if (!s) { box.appendChild(S.result('error', 'i-cloud-off', ['Session status was not read: ' + (entry.sessions_error || entry.error || 'amt-mcp did not answer') + '.'])); return; }
    ul.appendChild(holderRow('kvm', s.kvm));
    ul.appendChild(holderRow('sol', s.sol));
    var im = s.ider || {};
    if (im.mounted === true) {
      var names = Object.keys(im.images || {}).map(function (k) { return im.images[k]; });
      ul.appendChild(row('i-disc', ['IDE-R · ', h('strong', {}, [names.join(', ') || 'image']), ' mounted'], ['held until unmount; KVM keeps working beside it'], textLink('/server/' + key + '/media', 'Media')));
    } else if (im.mounted === false) ul.appendChild(row('i-disc', ['IDE-R · not mounted'], ['a mount holds the host\'s IDE-R session until unmount'], textLink('/server/' + key + '/media', 'Media')));
    else ul.appendChild(row('i-disc', ['IDE-R · unknown'], [entry.sessions_error || 'amt-mcp\'s mount status could not be read']));
    var rec = (s.kvm && s.kvm.recording) ? { who: 'mirror', r: s.kvm.recording, dir: s.kvm.recording_dir } : (s.sol && s.sol.recording) ? { who: 'serial terminal', r: s.sol.recording, dir: s.sol.recording_dir } : null;
    var dir = (s.kvm && s.kvm.recording_dir) || (s.sol && s.sol.recording_dir);
    ul.appendChild(rec ? row('i-record', ['Recording · ' + rec.who], [Math.round(rec.r.seconds || 0) + ' s · ' + (rec.r.frames || 0) + ' frames · ' + S.bytes(rec.r.bytes) + ' · goes to the NAS folder' + (rec.dir ? ' ' + rec.dir : ''), ' · not to the browser'])
      : row('i-record', ['Recording · none'], ['recordings go to the NAS folder ' + (dir || 'amt-mcp reports') + ', not to the browser']));
    box.appendChild(ul);
    box.appendChild(h('p', { class: 'body-s muted m0' }, ['AMT allows one KVM session per host. While it is held, another client\'s open is refused; an idle mirror keeps it alive with a no-op key every 60 s.']));
  }

  // ---- the capture card and the past captures ----
  function loadPast() {
    var box = $('past-captures'); if (!box) return;
    S.get('/api/server/' + key + '/captures').then(function (r) {
      clear(box);
      if (r.status !== 200) { box.appendChild(S.result('error', 'i-cloud-off', ['Captures were not listed: ' + (r.body.error || 'no answer') + ' · amt-mcp did not answer, so this is not an empty list.'])); return; }
      var b = r.body, ul = h('ul', { class: 'list' });
      b.captures.forEach(function (c) { ul.appendChild(S.pastRow(c, ul)); });
      var missing = b.searched.filter(function (s) { return !s.found; });
      if (!b.captures.length) box.appendChild(h('p', { class: 'muted m0' }, [missing.length ? 'amt-mcp lists no captures for ' + key + ' and could not read its ' + missing.map(function (s) { return s.kinds.join(' and '); }).join(' or ') + ' folder, so this list may be missing files.' : 'amt-mcp lists no screenshots, recordings or casts for ' + key + ' (it searched ' + b.searched.length + ' folders).']));
      else box.appendChild(ul);
      box.appendChild(h('p', { class: 'body-s muted m0' }, ['Listed ' + b.captures.length + ' for ' + key + ' of ' + b.listed + ' that amt-mcp holds' + (b.complete ? '' : ' (the newest only: the list was cut)') + (b.captures.length && missing.length ? ' · a folder was not found: ' + missing.map(function (s) { return s.kinds.join(' and '); }).join(', ') : '') + '.']));
    });
  }
  function bindShot() {
    var shot = $('srv-shot'); if (!shot) return;
    amtc.bindWrite(shot, function () {
      return { id: 'shot-' + key, title: 'Take a screenshot of ' + key, verb: 'Take screenshot', readOnly: true,
        consequence: 'Opens the host\'s single KVM session for a moment (or shares your mirror\'s), grabs the screen and closes it. Where user consent is required this may show a consent prompt on the host. It sends no input.',
        call: { tool: 'amt_screenshot', arguments: { device: key } },
        callNote: 'read-only · the result\'s one-time url is fetched once by the console, its sha256 checked, then kept in the capture store',
        onResult: function (r) { var slot = $('capture-results'); clear(slot); slot.appendChild(S.shotResult(key, r, true)); if (r.status === 200 && !r.body.isError) loadPast(); } };
    });
  }

  // ---- the page ----
  function render() {
    renderHeader(); renderState(); renderCards(); renderSessions();
  }
  function missing() {
    gone = true;
    var box = $('srv-state') || document.querySelector('.content');
    clear(box);
    box.appendChild(h('div', { class: 'card outlined' }, [h('h2', {}, ['No server named ' + key]), h('p', { class: 'm0' }, ['amt-mcp does not list it. ', h('a', { href: '/' }, ['Back to the fleet'])])]));
  }
  function poll() {
    if (gone) return;
    S.get('/api/server/' + key).then(function (r) {
      if (r.status === 404) return missing();
      if (r.status === 200) { entry = r.body.server; interval = r.body.interval || interval; render(); }
    });
  }
  function refresh() {
    return amtc.post('/api/fleet/refresh', { device: key }).then(function (r) { if (r.status === 200 && r.body.server) { entry = r.body.server; render(); } });
  }
  function guarded(button) {                                  // one attempt per activation: the control ignores the next while the call is out
    if (button.getAttribute('aria-disabled') === 'true') return;
    var done = S.busy(button, 'waiting for amt-mcp');
    refresh().then(done, done);
  }
  var btn = $('srv-refresh'); if (btn) btn.addEventListener('click', function () { guarded(btn); loadPast(); });
  bindShot();
  revealCurrentTab();
  amtc.ready.then(function () { poll(); loadPast(); setInterval(poll, POLL_MS); });
}());
