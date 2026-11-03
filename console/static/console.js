/* The Console tab (design/console.html, note 2.5): amt-mcp's own mirror page in embed mode, framed through the console's relay, and what
   only the console adds around it: the session card with its five states, the agent-typing strip, Start and Stop, the key macros and text
   with the screen guard, and host sign-in. Every write is a sheet from components.js (the sheet kind comes from the one predicate there);
   there is no raw secret step anywhere in this file. The live keyboard and mouse are the viewer page's own input route, not a tool call; Record is
   a confirmed tool call from the session card, never a control of the framed page. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status, E = amtc.embed;
  var head = document.querySelector('.srvhead[data-server]'), page = document.getElementById('console-page');
  if (!head || !page) return;
  var key = head.getAttribute('data-server');
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;

  // ---- the macro grid (note 2.5): each entry is one amt_console_input action, validated against the live schema by the tests ----
  var key_ = function (k, mods) { var a = { kind: 'key', key: k }; if (mods) a.modifiers = mods; return a; };
  var macro = function (m) { return { kind: 'macro', macro: m }; };
  var MACROS = [
    ['Ctrl+Alt+Del', macro('ctrl_alt_del')], ['Win', macro('win')], ['Win+Down', key_('down', ['win'])], ['Win+Up', key_('up', ['win'])],
    ['Win+L', macro('win_l')], ['Win+M', key_('m', ['win'])], ['Win+R', macro('win_r')], ['Win+Left', key_('left', ['win'])],
    ['Win+Right', key_('right', ['win'])], ['Shift+Win+M', key_('m', ['shift', 'win'])], ['Alt-Tab', macro('alt_tab')], ['Alt-F4', macro('alt_f4')],
    ['Ctrl-W', key_('w', ['ctrl'])], ['F1', key_('f1')], ['F2', macro('f2')], ['F3', key_('f3')], ['F4', key_('f4')], ['F5', key_('f5')],
    ['F6', key_('f6')], ['F7', key_('f7')], ['F8', key_('f8')], ['F9', key_('f9')], ['F10', macro('f10')], ['F11', key_('f11')],
    ['F12', macro('f12')], ['LS+LA+PrtSc', key_('print_screen', ['shift', 'alt'])]
  ];
  var GUARDS = ['any', 'desktop', 'windows-signin', 'linux-console', 'bios-setup', 'grub', 'text-installer', 'mok-manager'];
  var guard = 'any';
  amtc.macros = MACROS.map(function (m) { return { label: m[0], action: m[1] }; });

  // ---- the session controller ----
  var ses = E.session({ kind: 'mirror', key: key, holderKey: 'kvm', label: 'KVM', noun: 'mirror', viewerPath: 'm',
    screen: $('kvm-screen'), foot: $('kvm-foot'), strip: $('agent-strip'), onChange: renderSession });
  var loadRecordings = E.recordings(key, 'recording', $('rec-list'), $('rec-refresh'));

  // ---- Start and Stop ----
  var START_ARGS = { device: key, action: 'start', bind: '0.0.0.0', port: 8766, fps: 15, quality: 70, record_on_start: false };
  function startSpec() {
    return { id: 'start-mirror', title: 'Start a mirror of ' + key, verb: 'Start mirror',
      consequence: 'Opens the host\'s single KVM session and serves a live view behind the viewer front. You get the control page framed here; viewers get a view link; agents\' calls share the session while it runs. Where user consent is required the host shows a code first.',
      call: { tool: 'amt_mirror_link', arguments: Object.assign({}, START_ARGS) }, onResult: function (r) { E.attemptDone('start-mirror'); startResult(r); } };
  }
  function stopSpec() {
    var ctx = ses.ctx(), call = { tool: 'amt_mirror_link', arguments: { device: key, action: 'stop' } };
    var forced = amtc.destructiveCall(call, ctx), spec = { id: 'stop-mirror', ctx: ctx, call: call, onResult: stopResult };
    if (!forced) return Object.assign(spec, { title: 'Stop the mirror of ' + key, verb: 'Stop mirror',
      consequence: 'Releases the host\'s KVM session. Viewers lose the picture; a running recording is finished and encoded first. Agents that were sharing this session will open their own next time.' });
    var tail = 'stopping it ends the session under that agent\'s call, which then fails mid-sequence (a logon can be left half-typed). Stop only if you know the agent is done.';
    return Object.assign(spec, { verb: 'stop', nowLabel: 'Stop now',
      title: ctx.startedByAgent ? 'Stop the mirror an agent started on ' + key : 'Stop the mirror on ' + key + ' while an agent\'s call is using it',
      consequence: ctx.startedByAgent ? 'An agent started this mirror and may be driving the host through it right now: ' + tail
        : 'An agent\'s call is using this mirror right now: ' + tail });
  }
  function startResult(r) {
    var slot = $('session-results'), bad = E.problem('start mirror', r);
    if (bad) E.add(slot, bad);
    else {
      var s = r.body.structured || {}, already = /already live/.test(s.note || '');
      E.add(slot, S.result('ok', 'i-check', [E.lead('start mirror'), already ? ' · a mirror was already running; the console attached to it (it did not start it)'
        : ' · started' + (s.fps ? ' · ' + s.fps + ' fps' : '') + (s.width && s.height ? ' · ' + s.width + '×' + s.height : '') + ' · the control page is framed above']));
    }
    ses.refresh();
  }
  function stopResult(r) {
    var slot = $('session-results'), bad = E.problem('stop mirror', r);
    if (bad) E.add(slot, bad);
    else {
      var s = r.body.structured || {};
      E.add(slot, S.result('ok', 'i-check', [E.lead('stop mirror'), s.stopped === false ? ' · no mirror was live' : ' · stopped' + (s.session_released === false ? ' · the session is still releasing' : ' · KVM session released'),
        s.recording ? ' · a recording was running: it is finished and encoded in the background and is listed under Recordings when ready' : '']));
    }
    ses.refresh().then(loadRecordings);
  }

  // ---- Record start and stop: a confirmed amt_mirror_link tools/call from here, not a route of the framed page (which has no Record in embed mode) ----
  var record = E.recordControl({ ses: ses, tool: 'amt_mirror_link', key: key, noun: 'mirror', slot: $('session-results'), startTitle: 'Record this mirror',
    startConsequence: 'Writes the live view to a file in the NAS recordings folder until you stop it. Everything on the host\'s screen, including what others type, is in the recording.',
    stopConsequence: 'Closes the recording. It is then encoded to an H.264 .mp4 in the background (this needs ffmpeg on amt-mcp) and is listed under Recordings when ready.',
    stopped: function (s) {
      E.add($('session-results'), S.result('ok', 'i-check', [E.lead('stop recording'), s.recording ? ' · stopped · it is finished and encoded in the background and is listed under Recordings when ready' : ' · no recording was running']));
      return loadRecordings();
    } });

  // ---- the session card: one of the five states (design 2.5) ----
  function note(text) { return h('p', { class: 'body-s muted m0' }, [text]); }
  function renderSession(api) {
    var box = $('kvm-session'), st = api.state(), e = api.entry(), v = e && e.sessions && e.sessions.kvm, l = api.live();
    clear(box);
    box.setAttribute('data-mirror-state', st);
    if (st === 'console' || st === 'agent') {
      var who = h('div', { class: 'who' }, [S.kvmChip(v, false, true)]);
      if (v.since) who.appendChild(h('span', { class: 'chip small' }, ['since ' + S.eastern(v.since, false)]));
      if (typeof v.viewers === 'number') who.appendChild(h('span', { class: 'chip small' }, [v.viewers + (v.viewers === 1 ? ' viewer' : ' viewers')]));
      who.appendChild(h('span', { class: 'chip small' }, [icon('i-robot'), st === 'console' ? 'agents share this session while it runs' : (l && !l.reachable ? 'not reachable from here' : 'the console attached to it: watch, take control')]));
      if (l && l.recording) who.appendChild(h('span', { class: 'chip small live' }, [icon('i-record'), 'recording · ' + Math.round(l.recording.seconds || 0) + ' s']));
      box.appendChild(who);
      box.appendChild(note('AMT allows one KVM session per host. Another client\'s open is refused while this runs; if the console is signed out the mirror keeps running on amt-mcp. The console starts every mirror itself (bind 0.0.0.0, port 8766, behind the viewer front), so an agent\'s mirror is reachable here too.'));
      var row = h('div', { class: 'row' }, []);
      row.appendChild(record());
      if ((!l || l.reachable) && api.embedPath()) row.appendChild(h('a', { class: 'btn tonal', href: api.embedPath(), target: '_blank', rel: 'noopener' }, [icon('i-open'), 'Open in a tab']));   // the frame's own keyed path: shown once a key is minted
      var stop = h('button', { type: 'button', class: 'btn danger-outlined', 'data-stop': 'mirror' }, [st === 'agent' ? 'Stop the agent\'s mirror' : 'Stop mirror']);
      amtc.bindWrite(stop, stopSpec);
      row.appendChild(stop);
      box.appendChild(row);
    } else if (st === 'stopped') {
      var go = h('button', { type: 'button', class: 'btn filled', id: 'start-mirror-btn' }, [icon('i-cast'), 'Start mirror']);
      amtc.bindWrite(go, startSpec);
      box.appendChild(h('div', { class: 'row' }, [h('span', { class: 'chip small dashed', 'data-session': 'free' }, [icon('i-lock-open'), 'no mirror running · KVM free']), go]));
      box.appendChild(note('Starting a mirror opens the host\'s single KVM session until it is stopped; agents\' console tools then share it.'));
    } else if (st === 'other') {
      box.appendChild(S.result('error', 'i-lock', ['Another client holds this host\'s KVM session: the mirror could not open it (', h('span', { class: 'data' }, ['another session is open']), '). Wait for it to end or ask who holds it; the console cannot take it over. Opens refused.']));
      box.lastChild.setAttribute('data-session', 'held_other');
    } else if (st === 'consent') {
      box.appendChild(S.result('live', 'i-pin', ['User consent is required on this host: a code is on its screen. Enter it within 2 minutes in ', h('a', { href: '/server/' + key + '/wsman' }, ['Advanced → Send a consent code']),
        ' (IPS_OptInService.SendOptInCode); the console has no typed control for it yet.']));
      box.lastChild.setAttribute('data-session', 'consent_pending');
    } else {
      box.appendChild(S.result('live', 'i-help', [st === 'loading' ? 'Reading the session…' : 'The KVM session status could not be read (' + ((e && e.sessions_error) || 'amt-mcp did not answer') + '); it is not shown as free.']));
    }
    if (st !== 'console' && st !== 'agent') box.appendChild(h('div', { class: 'row' }, [record(E.noRecordReason(st, 'mirror'))]));   // no session is live: Record is greyed, with the reason
  }

  // ---- the macro grid, the guard and the text step ----
  function buildGuards() {
    var row = $('guards');
    GUARDS.forEach(function (g) {
      var b = h('button', { type: 'button', class: 'chip small' + (g === guard ? ' selected' : ''), 'aria-pressed': String(g === guard), 'data-guard': g }, [g === 'any' ? 'any (no guard)' : g]);
      b.addEventListener('click', function () {
        guard = g;
        row.querySelectorAll('[data-guard]').forEach(function (c) { var on = c.getAttribute('data-guard') === g; c.classList.toggle('selected', on); c.setAttribute('aria-pressed', String(on)); });
      });
      row.appendChild(b);
    });
  }
  function inputArgs(actions) {
    var args = { device: key, actions: actions };
    if (guard !== 'any') args.expect = [guard];                  // "any" omits expect: an empty list is refused by the tool
    return args;
  }
  function inputSpec(id, title, verb, consequence, actions, what) {
    return { id: id, title: title, verb: verb, call: { tool: 'amt_console_input', arguments: inputArgs(actions) },
      consequence: consequence + (guard === 'any' ? ' No screen guard is set, so it acts on whatever is on the screen.' : ' The first frame is classified first: unless the screen is ' + guard + ', nothing is sent.'),
      onResult: function (r) { E.add($('input-results'), E.inputResult(what + (guard === 'any' ? '' : ' with guard ' + guard), r)); } };
  }
  function buildMacros() {
    var grid = $('macro-grid');
    MACROS.forEach(function (m) {
      var b = h('button', { type: 'button', 'aria-label': 'Send ' + m[0], 'data-json': JSON.stringify(m[1]) }, [m[0]]);
      amtc.bindWrite(b, function () {
        return inputSpec('macro-sheet', 'Send ' + m[0] + ' to ' + key, 'Send',
          'The key chord is sent to whatever has focus on the host\'s screen, through the shared KVM session.', [m[1]], m[0]);
      });
      grid.appendChild(b);
    });
  }
  var TEXT_RULE = /^[\x20-\x7e]*$/, TEXT_MAX = 500;
  function textProblem(v) {
    if (v === '') return 'type the text to send';
    if (!TEXT_RULE.test(v)) return 'printable ASCII only (no tabs, newlines or other characters)';
    if (v.length > TEXT_MAX) return 'at most ' + TEXT_MAX + ' characters (this is ' + v.length + ')';
    return null;
  }
  function buildText() {
    var input = $('txt'), btn = $('type-text'), box = $('field-text'), help = box.querySelector('.help');
    var wrap = h('div', { class: 'btn-wrap' }, []), reason = null;
    btn.parentNode.insertBefore(wrap, btn); wrap.appendChild(btn);
    function check() {
      var bad = textProblem(input.value);
      box.classList.toggle('err', !!bad && input.value !== '');
      help.textContent = bad && input.value !== '' ? bad : '';
      if (bad) { btn.setAttribute('aria-disabled', 'true'); if (!reason) { reason = h('span', { class: 'reason' }, []); wrap.appendChild(reason); } reason.textContent = bad; }
      else { btn.removeAttribute('aria-disabled'); if (reason) { reason.remove(); reason = null; } }
    }
    input.addEventListener('input', check);
    amtc.bindWrite(btn, function () {
      return inputSpec('text-sheet', 'Type text into ' + key, 'Type',
        'The text is typed into whatever has focus on the host\'s screen, paced for AMT, through the shared KVM session. Never a credential: that is Host sign-in.',
        [{ kind: 'text', text: input.value }], 'type text');
    });
    check();
  }

  // ---- host sign-in (one attempt, no retry control) ----
  function signSpec(kind) {
    var logon = kind === 'logon', what = logon ? 'sign in' : 'sign out', id = 'sign-' + kind;
    return { id: id, title: logon ? 'Sign in to ' + key + '\'s console' : 'Sign out of ' + key + '\'s console', verb: logon ? 'Sign in' : 'Sign out',
      consequence: logon ? 'The host\'s screen is read first. Only a positively identified Windows sign-in or a Linux login: prompt gets the vaulted account and password, once. A wrong password is reported, never retried; any other screen aborts with nothing typed.'
        : 'Windows: Win+R, logoff, Enter after the Run dialog is seen. Linux: exit at a shell prompt. Unsaved work in the host session can be lost.',
      call: { tool: logon ? 'amt_remote_logon' : 'amt_remote_logoff', arguments: { device: key, console: 'kvm' } },
      onResult: function (r) { E.attemptDone(id); E.add($('signin-results'), E.signResult(what, r)); } };
  }
  E.oneAttempt('sign-logon', '#signin-btn', 'one attempt: waiting for amt-mcp');
  E.oneAttempt('sign-logoff', '#signout-btn', 'one attempt: waiting for amt-mcp');
  E.oneAttempt('start-mirror', '#start-mirror-btn', 'waiting for amt-mcp');
  amtc.bindWrite($('signin-btn'), function () { return signSpec('logon'); });
  amtc.bindWrite($('signout-btn'), function () { return signSpec('logoff'); });

  buildGuards(); buildMacros(); buildText();
  renderSession(ses);
  ses.start();
  amtc.ready.then(loadRecordings);
}());
