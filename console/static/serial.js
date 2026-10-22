/* The Serial tab (design/serial.html, note 2.6): amt-mcp's own terminal page in embed mode, framed through the console's relay, and the
   console's part around it: the session card with its states (yours, an agent's, none), Start and Stop, recording as a capture, Send a line
   through amt_sol and host sign-in on the serial getty. Every write is a sheet from components.js. The live typing is the viewer page's own
   input route, not a tool call. A line sent here is never a credential: the page says so, and Host sign-in is the only path that types one. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status, E = amtc.embed;
  var head = document.querySelector('.srvhead[data-server]'), page = document.getElementById('serial-page');
  if (!head || !page) return;
  var key = head.getAttribute('data-server');
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;

  var ses = E.session({ kind: 'serial', key: key, holderKey: 'sol', label: 'SOL', noun: 'terminal', viewerPath: 's',
    screen: $('sol-screen'), foot: $('sol-foot'), strip: $('agent-strip'), onChange: renderSession });
  var loadRecordings = E.recordings(key, 'serial_cast', $('rec-list'), $('rec-refresh'));

  // ---- a finished recording becomes a capture: fetched once by the backend through amt_captures, then Save ----
  function saveRecording(recording) {
    var slot = $('session-results'), path = recording && typeof recording.path === 'string' ? recording.path : null;
    if (!path) return Promise.resolve();
    var name = path.split('/').pop();
    return amtc.post('/api/call', { tool: 'amt_captures', arguments: { action: 'fetch', name: name } }).then(function (r) {
      var b = r.body || {}, cap = b.structured && b.structured.capture;
      if (r.status === 200 && !b.isError && cap && cap.status === 'ready') {
        var res = S.result('ok', 'i-verified', [E.lead('recording'), ' · ' + name + ' · ' + S.bytes(cap.bytes) + ' · sha256 ', S.fp(cap.sha256), ' verified · listed by amt_captures · fetched once, kept in the capture store']);
        E.add(slot, h('div', { class: 'col gap8' }, [res, S.captureActions(cap, key, false)]));
      } else {
        E.add(slot, S.result('live', 'i-timer', [E.lead('recording'), ' · ' + name + ' was written, but is not kept as a capture yet: ' + (r.status !== 200 ? (b.error || 'no answer') : b.isError ? b.text : cap && cap.reason ? cap.reason : 'amt-mcp offered no download')
          + '. It is listed under Recordings when amt-mcp lists it; Refresh there.']));
      }
      return loadRecordings();
    });
  }

  // ---- Start, Stop, Record ----
  E.oneAttempt('start-terminal', '#start-terminal-btn', 'waiting for amt-mcp');
  function startSpec() {
    return { id: 'start-terminal', title: 'Start a serial terminal of ' + key, verb: 'Start terminal',
      consequence: 'Opens the host\'s SOL session and serves the terminal page behind the viewer front. You get the control page framed here; viewers get a view link; amt_sol shares the session while it runs.',
      call: { tool: 'amt_serial_link', arguments: { device: key, action: 'start', bind: '0.0.0.0', port: 8766, record_on_start: false } },
      onResult: function (r) {
        E.attemptDone('start-terminal');
        var bad = E.problem('start terminal', r);
        if (bad) E.add($('session-results'), bad);
        else {
          var already = /already live/.test((r.body.structured || {}).note || '');
          E.add($('session-results'), S.result('ok', 'i-check', [E.lead('start terminal'), already ? ' · a terminal was already running; the console attached to it (it did not start it)' : ' · started · the control page is framed above']));
        }
        ses.refresh();
      } };
  }
  function stopSpec() {
    var ctx = ses.ctx(), call = { tool: 'amt_serial_link', arguments: { device: key, action: 'stop' } };
    var forced = amtc.destructiveCall(call, ctx), spec = { id: 'stop-terminal', ctx: ctx, call: call, onResult: stopResult };
    if (!forced) return Object.assign(spec, { title: 'Stop the serial terminal of ' + key, verb: 'Stop terminal',
      consequence: 'Releases the host\'s SOL session. The page keeps what it printed; a running recording is closed first.' });
    var tail = 'stopping it ends the session under that agent\'s call, which then fails mid-sequence. Stop only if you know the agent is done.';
    return Object.assign(spec, { verb: 'stop', nowLabel: 'Stop now',
      title: ctx.startedByAgent ? 'Stop the terminal an agent started on ' + key : 'Stop the terminal on ' + key + ' while an agent\'s call is using it',
      consequence: ctx.startedByAgent ? 'An agent started this terminal and may be typing through it right now: ' + tail : 'An agent\'s call is using this terminal right now: ' + tail });
  }
  // amt_serial keeps the last finished recording in a stop's result for as long as the terminal lives, so Stop terminal saves one only if it
  // closed it just now (ses.recording() says whether one runs).
  function stopResult(r) {
    var wasRecording = ses.recording(), slot = $('session-results'), bad = E.problem('stop terminal', r), s = (r.body && r.body.structured) || {};
    if (bad) E.add(slot, bad);
    else E.add(slot, S.result('ok', 'i-check', [E.lead('stop terminal'), s.stopped === false ? ' · no terminal was live' : ' · stopped' + (s.session_released === false ? ' · the session is still releasing' : ' · SOL session released')]));
    ses.refresh().then(function () { return bad || !wasRecording ? null : saveRecording(s.recording); });
  }
  // Record start and stop: a confirmed amt_serial_link tools/call from here, not a route of the framed page (which has no Record in embed mode).
  var record = E.recordControl({ ses: ses, tool: 'amt_serial_link', key: key, noun: 'terminal', slot: $('session-results'), startTitle: 'Record this terminal',
    startConsequence: 'Writes an asciinema .cast file to the NAS recordings folder until you stop it. Everything printed, including what others type, is in the recording.',
    stopConsequence: 'Closes the .cast file. It is then fetched once into the capture store so it can be saved from here.',
    stopped: function (s) { return saveRecording(s.recording); } });

  // ---- the session card: yours, an agent's, none ----
  function note(text) { return h('p', { class: 'body-s muted m0' }, [text]); }
  function renderSession(api) {
    var box = $('sol-session'), st = api.state(), e = api.entry(), v = e && e.sessions && e.sessions.sol, l = api.live();
    clear(box);
    box.setAttribute('data-serial-state', st);
    if (st === 'console' || st === 'agent') {
      var who = h('div', { class: 'who' }, [S.solChip(v, false, true)]);
      if (v.since) who.appendChild(h('span', { class: 'chip small' }, ['since ' + S.eastern(v.since, false)]));
      if (typeof v.viewers === 'number') who.appendChild(h('span', { class: 'chip small' }, [v.viewers + (v.viewers === 1 ? ' viewer' : ' viewers')]));
      who.appendChild(h('span', { class: 'chip small' }, [icon('i-robot'), st === 'console' ? 'amt_sol shares this session while it runs' : (l && !l.reachable ? 'not reachable from here' : 'the console attached to it')]));
      if (l && l.recording) who.appendChild(h('span', { class: 'chip small live' }, [icon('i-record'), 'recording · ' + Math.round(l.recording.seconds || 0) + ' s']));
      box.appendChild(who);
      var row = h('div', { class: 'row' }, []);
      row.appendChild(record());
      if ((!l || l.reachable) && api.embedPath()) row.appendChild(h('a', { class: 'btn tonal', href: api.embedPath(), target: '_blank', rel: 'noopener' }, [icon('i-open'), 'Open in a tab']));   // the frame's own keyed path: shown once a key is minted
      var stop = h('button', { type: 'button', class: 'btn danger-outlined', 'data-stop': 'terminal' }, [st === 'agent' ? 'Stop the agent\'s terminal' : 'Stop terminal']);
      amtc.bindWrite(stop, stopSpec);
      row.appendChild(stop);
      box.appendChild(row);
    } else if (st === 'stopped') {
      var go = h('button', { type: 'button', class: 'btn filled', id: 'start-terminal-btn' }, [icon('i-terminal'), 'Start terminal']);
      amtc.bindWrite(go, startSpec);
      box.appendChild(h('div', { class: 'row' }, [h('span', { class: 'chip small dashed', 'data-session': 'sol_free' }, [icon('i-lock-open'), 'no terminal running · SOL free']), go]));
      box.appendChild(note('Starting a terminal opens the host\'s SOL session until it is stopped; amt_sol then shares it. SOL runs beside KVM.'));
    } else {
      box.appendChild(S.result('live', 'i-help', [st === 'loading' ? 'Reading the session…' : 'The SOL session status could not be read (' + ((e && e.sessions_error) || 'amt-mcp did not answer') + '); it is not shown as free.']));
    }
    if (st !== 'console' && st !== 'agent') box.appendChild(h('div', { class: 'row' }, [record(E.noRecordReason(st, 'terminal'))]));   // no session is live: Record is greyed, with the reason
  }

  // ---- Send a line (amt_sol: confirmed even to read; through the live terminal's session when one runs) ----
  var LINE_RULE = /^[\x20-\x7e]*$/, LINE_MAX = 1023;
  function lineProblem(v) {
    if (!LINE_RULE.test(v)) return 'printable ASCII only (Enter is the checkbox below)';
    if (v.length > LINE_MAX) return 'at most ' + LINE_MAX + ' characters (this is ' + v.length + ')';
    return null;
  }
  function enterOn() { return $('append-enter').getAttribute('aria-checked') === 'true'; }
  function lineSpec() {
    var text = $('sl').value + (enterOn() ? '\n' : '');
    return { id: 'sol-sheet', title: 'Send a line to ' + key + '\'s serial console', verb: 'Send',
      consequence: 'The text is typed into the serial console exactly as shown, through this terminal\'s session if one is running, and up to 3 s of output is read back. It runs as whatever is logged in there. Never a credential.',
      call: { tool: 'amt_sol', arguments: { device: key, text: text, read_seconds: 3 } },
      onResult: function (r) {
        E.attemptDone('sol-sheet');
        var bad = E.problem('send a line', r);
        if (bad) return E.add($('line-results'), bad);
        var s = r.body.structured || {}, box = h('div', { class: 'col gap8' }, []);
        box.appendChild(S.result(s.error ? 'live' : 'ok', s.error ? 'i-timer' : 'i-check', [E.lead('send a line'), ' · ' + s.sent_chars + ' chars sent · ' + s.bytes + ' bytes read in ' + s.window_seconds + ' s'
          + (s.truncated ? ' · more arrived than was kept' : '') + (s.shared_terminal ? ' · through the live terminal: the viewer shows it' : '') + (s.error ? ' · ' + s.error : '')]));
        if (typeof s.output === 'string' && s.output) box.appendChild(h('pre', { class: 'data out', tabindex: '0', 'aria-label': 'SOL output read back' }, [s.output]));
        E.add($('line-results'), box);
      } };
  }
  function buildLine() {
    var input = $('sl'), btn = $('send-line'), box = $('field-line'), help = box.querySelector('.help'), original = help.textContent;
    var wrap = h('div', { class: 'btn-wrap' }, []), reason = null;
    btn.parentNode.insertBefore(wrap, btn); wrap.appendChild(btn);
    function check() {
      var bad = lineProblem(input.value);
      box.classList.toggle('err', !!bad);
      help.textContent = bad || original;
      if (bad) { btn.setAttribute('aria-disabled', 'true'); if (!reason) { reason = h('span', { class: 'reason' }, []); wrap.appendChild(reason); } reason.textContent = bad; }
      else { btn.removeAttribute('aria-disabled'); if (reason) { reason.remove(); reason = null; } }
    }
    input.addEventListener('input', check);
    var chk = $('append-enter');
    function flip() { chk.setAttribute('aria-checked', String(chk.getAttribute('aria-checked') !== 'true')); }
    chk.addEventListener('click', flip);
    chk.addEventListener('keydown', function (e) { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); if (!e.repeat) flip(); } });
    E.oneAttempt('sol-sheet', '#send-line', 'waiting for amt-mcp');
    amtc.bindWrite(btn, lineSpec);
    check();
  }

  // ---- host sign-in on the serial getty (one attempt, no retry control) ----
  function signSpec(kind) {
    var logon = kind === 'logon', id = 'sign-' + kind;
    return { id: id, title: logon ? 'Sign in to ' + key + ' over serial' : 'Sign out of ' + key + ' over serial', verb: logon ? 'Sign in' : 'Sign out',
      consequence: logon ? 'Reads the serial text first. Only getty\'s login: prompt gets the vaulted account and, after a Password: prompt, the password, once. No screenshot; nothing is echoed.'
        : 'Sends exit only at a shell prompt and checks the login prompt is back.',
      call: { tool: logon ? 'amt_remote_logon' : 'amt_remote_logoff', arguments: { device: key, console: 'serial' } },
      onResult: function (r) { E.attemptDone(id); E.add($('signin-results'), E.signResult(logon ? 'sign in (SOL)' : 'sign out (SOL)', r)); } };
  }
  E.oneAttempt('sign-logon', '#signin-btn', 'one attempt: waiting for amt-mcp');
  E.oneAttempt('sign-logoff', '#signout-btn', 'one attempt: waiting for amt-mcp');
  amtc.bindWrite($('signin-btn'), function () { return signSpec('logon'); });
  amtc.bindWrite($('signout-btn'), function () { return signSpec('logoff'); });

  buildLine();
  renderSession(ses);
  ses.start();
  amtc.ready.then(loadRecordings);
}());
