/* Shared by the KVM and SOL tabs (packet C4): the embedded viewer page and its states, the agent-typing strip, the results of
   the tools these tabs call, host sign-in and the recordings list. The viewer page is amt-mcp's own, relayed under /embed/<kind>/<server>/
   by the console backend; this script never sees its url or token (the backend answers /api/embed/<kind>/<server> without them). The page runs in
   a sandboxed frame with an OPAQUE origin (no allow-same-origin): it cannot reach this page's DOM, globals or cookie, so its requests carry a
   per-page-view embed key in the path instead (POST /api/embed/key mints it; the frame's src is /embed/<kind>/<server>/<key>/).
   Every tool refusal is shown verbatim, as text nodes only. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var E = amtc.embed = {};
  var clear = S.clear;

  // ---- results (design 7.4): the tool's own words, where the action was ----
  function stamp() { return S.eastern(Date.now() / 1000, false); }
  E.lead = function (what) { return h('strong', {}, [stamp() + ' · ' + what]); };
  E.add = function (slot, node) {
    slot.insertBefore(node, slot.firstChild);
    while (slot.children.length > 5) slot.removeChild(slot.lastChild);
  };
  E.failure = function (what, r) {                              // the console could not make the call, or amt-mcp did not answer
    var code = (r.body && r.body.error) || 'no answer';
    if (r.status === 502) return S.result('live', 'i-help', [E.lead(what), ' · amt-mcp did not answer (' + code + ') · it is not known whether the request was sent; read the session state before trying again']);
    return S.result('error', 'i-block', [E.lead(what), ' · refused: ' + code + ' · nothing sent']);
  };
  E.GUARD = /screen_not_expected|screen_not_identified/;
  E.HELD_OTHER = /another (?:redirection )?session (?:is )?open|redir_start_status_[1-9]/i;
  E.refusal = function (what, text) {
    var tail = E.GUARD.test(text) ? ' · no key, click or text was sent' : E.HELD_OTHER.test(text) ? ' · another client holds this host\'s session: opens refused' : '';
    return S.result('error', 'i-block', [E.lead(what), ' · refused: ' + text + tail]);
  };
  // One reply from /api/call: null when it is a plain success the caller renders itself.
  E.problem = function (what, r) {
    if (r.status !== 200) return E.failure(what, r);
    if (r.body.isError) return E.refusal(what, r.body.text);
    return null;
  };
  function kept(cap) {                                          // a capture record the backend kept from a result's one-time link
    return cap && cap.status === 'ready' ? [' · result screenshot kept: sha256 ', S.fp(cap.sha256), ' verified'] : [];
  }

  // amt_console_input: a success names the steps; an abort of the screen guard is an error with its reason and nothing sent.
  E.inputResult = function (what, r) {
    var bad = E.problem(what, r);
    if (bad) return bad;
    var s = r.body.structured || {}, kinds = (s.kinds || []).join(', ');
    var parts = [E.lead(what), ' · sent ' + (s.steps_run === undefined ? 'its' : s.steps_run) + ' step' + (s.steps_run === 1 ? '' : 's') + (kinds ? ' (' + kinds + ')' : '')];
    if (s.screen_label) parts.push(' · screen was ' + s.screen_label);
    return S.result('ok', 'i-check', parts.concat(kept(s.screenshot && s.screenshot.capture)));
  };

  // amt_remote_logon / amt_remote_logoff. An abort is structured (aborted, reason, typed_nothing, note) and carries no retry control.
  function findings(s) {
    var bits = [];
    if (s.screen_label) bits.push('screen ' + s.screen_label);
    if (s.console_prompt) bits.push('last line ' + s.console_prompt);
    if (s.ocr_backend) bits.push('ocr ' + s.ocr_backend);
    if (s.enter_sent_to_find_prompt === true) bits.push('one Enter sent to find the prompt');
    if (s.shared_terminal === true) bits.push('through the live terminal');
    return bits;
  }
  E.signResult = function (what, r) {
    var bad = E.problem(what, r);
    if (bad) return bad;
    var s = r.body.structured || {}, facts = findings(s).join(' · ');
    if (s.aborted === true) {
      var typed = s.typed_nothing === true ? 'typed nothing' : (s.account_typed ? 'the account was typed, the password was not' : 'typed nothing known');
      return S.result('error', 'i-block', [E.lead(what), ' · aborted: ' + s.reason + ' · ' + typed + (s.note ? ' · ' + s.note : '') + (facts ? ' · ' + facts : '') + ' · not retried: look at the console and try again yourself']);
    }
    var ok = s.logged_in === true || s.logged_off === true, parts = [E.lead(what)];
    if (s.already_logged_in === true) parts.push(' · already signed in: nothing was typed');
    else if (s.logoff_submitted === true) parts.push(' · exit sent' + (s.logged_off === true ? ' · logged_off: true' : s.logged_off === false ? ' · logged_off: false (a shell prompt is still showing)' : ' · logged_off: not judged'));
    else {
      parts.push(' · name and password typed once' + (s.logged_in === true ? ' · logged_in: true' : s.logged_in === false ? ' · logged_in: false' + (s.login_incorrect ? ' (Login incorrect)' : '') + ' · not retried' : ' · logged_in: not judged'));
    }
    if (facts) parts.push(' · ' + facts);
    if (s.logged_in_basis || s.logged_off_basis) parts.push(' · ' + (s.logged_in_basis || s.logged_off_basis));
    return S.result(ok || s.already_logged_in === true ? 'ok' : s.logged_in === false ? 'error' : 'live', ok ? 'i-check' : s.logged_in === false ? 'i-block' : 'i-timer', parts.concat(kept(s.screenshot && s.screenshot.capture)));
  };

  // A control that sends one call: it ignores activation (aria-disabled, still focusable, the reason as visible text) from the moment its
  // sheet's call is sent until the result is rendered, so one activation is one attempt.
  var attempts = {}, pending = {};
  E.oneAttempt = function (sheetId, selector, why) { attempts[sheetId] = { selector: selector, why: why }; };
  E.attemptDone = function (sheetId) { if (pending[sheetId]) { pending[sheetId](); delete pending[sheetId]; } };
  document.addEventListener('tools-call', function (e) {
    var a = attempts[e.detail.sheet], btn = a && document.querySelector(a.selector);
    if (btn && !pending[e.detail.sheet]) pending[e.detail.sheet] = S.busy(btn, a.why);
  });

  // ---- the session controller: the server's entry, amt-mcp's live view of the session, the frame and the strip ----
  var POLL_ENTRY_MS = 5000, POLL_LIVE_MS = 1000;
  /* cfg = { kind: 'mirror' | 'serial', key, holderKey: 'kvm' | 'sol', label: 'KVM' | 'SOL', noun: 'mirror' | 'terminal', viewerPath: 'm' | 's',
             screen, foot, strip: elements, onChange(state) } */
  E.session = function (cfg) {
    var entry = null, live = null, frame = null, gone = false, busy = false, sig = null, none = null;
    var framePath = null, minting = false, mintFailed = null, mintRetryAt = 0;
    var api = { cfg: cfg };

    function view() { return entry && entry.sessions ? entry.sessions[cfg.holderKey] : null; }
    function consent() {
      var uc = entry && entry.status && entry.status.user_consent;
      return !!uc && (uc.state_code === 1 || uc.state_code === 2);
    }
    // The five states of design 2.5 (three for the terminal): yours, an agent's, none, another client, consent pending.
    api.state = function () {
      if (!entry) return 'loading';
      var v = view();
      if (!v || v.holder === 'unknown') return 'unknown';
      if (v.holder === 'console') return 'console';
      if (v.holder === 'agent') return 'agent';
      if (v.holder === 'other') return 'other';
      return cfg.kind === 'mirror' && consent() ? 'consent' : 'stopped';
    };
    api.entry = function () { return entry; };
    api.recording = function () {                                // whether a recording runs: amt-mcp's live view, else the cached read
      var l = api.live(), v = view();
      return l ? !!l.recording : !!(v && v.recording);
    };
    api.live = function () { return live && live.live ? live : null; };
    api.inFlight = function () {                                 // the freshest in-flight call: amt-mcp's live view, else the cached read
      var l = api.live(), v = view();
      return (l && l.in_flight) || (!l && v && v.in_flight) || null;
    };
    api.ctx = function () {                                      // what the stop predicate needs and a call cannot say
      return { startedByAgent: api.state() === 'agent', callInFlight: !!api.inFlight() };
    };

    // ---- the frame, the strip and the footer ----
    function say(kind, text) {
      dropFrame();
      if (!none) { none = h('p', { class: 'none muted' }, []); cfg.screen.appendChild(none); }
      none.textContent = text;
      none.setAttribute('data-screen-state', kind);
    }
    // The frame is opaque-origin: it gets a key minted for this page view, in its path, and nothing else of this session. The page's own relative
    // urls (stream, status.json, input ...) resolve under that path.
    api.embedPath = function () { return framePath; };
    function dropFrame() { if (frame) { frame.remove(); frame = null; } framePath = null; }
    function ensureFrame() {
      if (frame || minting) return;
      if (mintFailed && Date.now() < mintRetryAt) return say('error', 'The ' + cfg.noun + ' could not be framed: ' + mintFailed + ' · trying again shortly.');
      if (!none) say('connecting', 'Connecting to the ' + cfg.noun + '…');
      minting = true;
      amtc.post('/api/embed/key', { kind: cfg.kind, device: cfg.key }).then(function (r) {
        minting = false;
        var st = api.state();
        if (r.status !== 200 || !r.body || !r.body.key) { mintFailed = (r.body && r.body.error) || 'no answer'; mintRetryAt = Date.now() + 5000; return render(); }
        mintFailed = null;
        if (frame || (st !== 'console' && st !== 'agent')) return render();      // the session ended while the key was minted: the key idles out unused
        if (none) { none.remove(); none = null; }
        framePath = '/embed/' + cfg.kind + '/' + cfg.key + '/' + r.body.key + '/';
        frame = h('iframe', { src: framePath, title: (cfg.kind === 'mirror' ? 'KVM display' : 'SOL terminal') + ' of ' + cfg.key,
          sandbox: 'allow-scripts allow-forms', allow: 'clipboard-write *', referrerpolicy: 'no-referrer', 'data-embed': cfg.kind });   // allow: the terminal's Copy button wrote to the clipboard as a same-origin frame; an opaque one needs it delegated
        cfg.screen.appendChild(frame);
        render();
      }, function () { minting = false; mintFailed = 'no answer'; mintRetryAt = Date.now() + 5000; render(); });
    }
    function renderScreen() {
      var st = api.state(), l = api.live();
      if ((st === 'console' || st === 'agent') && l && !l.reachable) {
        return say('unreachable', 'Held by an agent · not reachable from here · bind ' + (l.bind || 'unknown') + '. It was started with the tool\'s default address, which the console\'s viewer front cannot reach; the console frames only a ' + cfg.noun + ' it can reach.');
      }
      if (st === 'console' || st === 'agent') {
        if (live && live.error && live.live === undefined) return say('error', 'The ' + cfg.noun + ' could not be read: ' + live.error);
        if (l || frame) return ensureFrame();
        return say('connecting', 'Connecting to the ' + cfg.noun + '…');
      }
      var text = { loading: 'Reading the session…', unknown: 'The session status could not be read, so the ' + cfg.noun + ' is not shown (' + ((entry && entry.sessions_error) || 'amt-mcp did not answer') + ').',
        other: 'Another client holds this host\'s ' + cfg.label + ' session: the ' + cfg.noun + ' could not open it. The console cannot take it over.',
        consent: 'User consent is required on this host: a code is on its screen. Enter it in Advanced → Send a consent code; there is no ' + cfg.noun + ' until the session opens.',
        stopped: 'No ' + cfg.noun + ' is running · ' + cfg.label + ' free. Start one to see and drive the host.' }[st];
      say(st, text);
    }
    function renderStrip() {
      var f = api.inFlight(), strip = cfg.strip;
      strip.hidden = !f;
      if (f && f.tool) {
        var tool = strip.querySelector('.tool');
        if (!tool) { tool = h('span', { class: 'data tool' }, []); strip.appendChild(tool); }
        tool.textContent = ' · ' + f.tool;
      }
      if (frame) {
        var was = frame.inert;
        frame.inert = !!f;                                      // pointer and keys cannot reach a frame that is inert; the viewer releases control on blur
        if (f && !was && (document.activeElement === frame || frame.contains(document.activeElement))) strip.focus();
      }
    }
    function renderFoot() {
      var l = api.live(), foot = cfg.foot;
      clear(foot);
      if (frame && cfg.kind === 'mirror' && l && l.width && l.height) frame.setAttribute('title', 'Live console of ' + cfg.key + ', ' + l.width + ' by ' + l.height);   // the geometry in the frame's name (5.6)
      var host = (l && l.viewer_host) || 'the viewer front';
      foot.appendChild(h('span', {}, ['amt-mcp viewer · ', h('span', { class: 'data' }, [host + ' · /' + cfg.viewerPath + '/…/']), ' · embed mode: no Power, Boot or Media rows, no downloads']));
      if (l && l.reachable) {
        var bits = [];
        if (l.width && l.height) bits.push(l.width + '×' + l.height);
        if (l.fps) bits.push(l.fps + ' fps');
        if (typeof l.last_frame_age_s === 'number') bits.push('last frame ' + l.last_frame_age_s + ' s ago');
        if (typeof l.viewers === 'number') bits.push(l.viewers + (l.viewers === 1 ? ' viewer' : ' viewers'));
        if (bits.length) foot.appendChild(h('span', {}, [bits.join(' · ')]));
      }
      var dir = (l && l.recording_dir) || (view() && view().recording_dir);
      foot.appendChild(h('span', {}, ['Recordings go to the NAS folder' + (dir ? ' ' + dir : '')]));
    }
    function signature() {
      var l = api.live();
      return JSON.stringify([api.state(), !!framePath, !!api.inFlight(), l && l.reachable, l && l.bind, l && l.viewers, l && l.recording && true, view() && view().viewers, entry && entry.sessions_error]);
    }
    function render() {
      renderScreen(); renderStrip(); renderFoot();
      var now = signature();
      if (now !== sig) { sig = now; cfg.onChange(api); }
    }

    // ---- polling ----
    function loadEntry() {
      return S.get('/api/server/' + cfg.key).then(function (r) { if (r.status === 200) { entry = r.body.server; render(); } else if (r.status === 404) gone = true; });
    }
    function loadLive() {
      var st = api.state();
      if (document.hidden || gone || (st !== 'console' && st !== 'agent')) { if (live) { live = null; render(); } return Promise.resolve(); }
      var mounted = framePath;                                           // a reply to a poll sent before this frame existed says nothing about its key
      return S.get('/api/embed/' + cfg.kind + '/' + cfg.key).then(function (r) {
        live = r.status === 200 ? r.body : { error: (r.body && r.body.error) || 'no answer' };
        if (frame && mounted && mounted === framePath && live.key_live === false) dropFrame();                 // the frame's key is gone (idle limit, console restarted): mount a fresh one
        render();
      });
    }
    // After a start or stop: the fleet entry (a server-side read of the session views) and the live view, now.
    api.refresh = function () { return loadEntry().then(loadLive); };
    api.start = function () {
      amtc.ready.then(function () {
        api.refresh();
        setInterval(loadEntry, POLL_ENTRY_MS);
        setInterval(function () { if (!busy) { busy = true; loadLive().then(function () { busy = false; }, function () { busy = false; }); } }, POLL_LIVE_MS);
      });
    };
    return api;
  };

  // ---- Record: a confirmed tools/call from the console's own chrome, never a route of the framed viewer page (sprint review M1) ----
  /* cfg = { ses, tool: 'amt_mirror_link' | 'amt_serial_link', key, noun: 'mirror' | 'terminal', slot (the results list), startTitle, startConsequence,
             stopConsequence, stopped(structured): what the page does with a recording it just closed (a promise, or nothing) }
     Returns build(reason): the button for the session card. With no reason it is Start recording, or Stop recording while one runs; with a
     reason (no session is live) it is Start recording greyed, the reason beside it as text. */
  E.noRecordReason = function (state, noun) {
    return state === 'loading' ? 'reading the session' : state === 'unknown' ? 'the session status could not be read' : 'no ' + noun + ' is running';
  };
  E.recordControl = function (cfg) {
    E.oneAttempt('rec-start', '#rec-start-btn', 'waiting for amt-mcp');
    E.oneAttempt('rec-stop', '#rec-stop-btn', 'waiting for amt-mcp');
    function spec(on) {
      var id = on ? 'rec-start' : 'rec-stop';
      return { id: id, title: on ? cfg.startTitle : 'Stop recording the ' + cfg.noun + ' of ' + cfg.key, verb: on ? 'Start recording' : 'Stop recording',
        consequence: on ? cfg.startConsequence : cfg.stopConsequence,
        call: { tool: cfg.tool, arguments: { device: cfg.key, action: on ? 'record_start' : 'record_stop' } },
        onResult: function (r) {
          E.attemptDone(id);
          var bad = E.problem(on ? 'start recording' : 'stop recording', r);
          if (bad) E.add(cfg.slot, bad);
          else if (on) E.add(cfg.slot, S.result('live', 'i-record', [E.lead('start recording'), ' · recording to the NAS recordings folder until stopped']));
          cfg.ses.refresh().then(function () { return !bad && !on ? cfg.stopped(r.body.structured || {}) : null; });
        } };
    }
    return function build(reason) {
      if (reason) {
        return h('div', { class: 'btn-wrap', 'data-record': 'unavailable' }, [h('button', { type: 'button', class: 'btn tonal', 'aria-disabled': 'true' }, [icon('i-record'), 'Start recording']),
          h('span', { class: 'reason' }, [reason])]);
      }
      var on = !cfg.ses.recording(), btn = h('button', { type: 'button', class: 'btn tonal', id: on ? 'rec-start-btn' : 'rec-stop-btn' }, [icon('i-record'), on ? 'Start recording' : 'Stop recording']);
      amtc.bindWrite(btn, function () { return spec(on); });
      return btn;
    };
  };

  // ---- the Recordings list: this server's finished MP4s or casts, as the capture store keeps them ----
  E.recordings = function (key, kind, box, refreshBtn) {
    function load() {
      return S.get('/api/server/' + key + '/captures').then(function (r) {
        clear(box);
        if (r.status !== 200) { box.appendChild(S.result('error', 'i-cloud-off', ['Captures were not listed: ' + ((r.body && r.body.error) || 'no answer') + ' · amt-mcp did not answer, so this is not an empty list.'])); return; }
        var mine = r.body.captures.filter(function (c) { return c.kind === kind; }), ul = h('ul', { class: 'list' });
        mine.forEach(function (c) { ul.appendChild(S.pastRow(c, ul)); });
        if (mine.length) box.appendChild(ul);
        else box.appendChild(h('p', { class: 'muted m0' }, ['amt-mcp lists no ' + (kind === 'recording' ? 'mirror recordings' : 'serial casts') + ' for ' + key + ' (it searched ' + r.body.searched.length + ' folders). A recording that is still being encoded is not listed yet; Refresh when it is done.']));
      });
    }
    if (refreshBtn) refreshBtn.addEventListener('click', function () {
      if (refreshBtn.getAttribute('aria-disabled') === 'true') return;
      var done = S.busy(refreshBtn, 'listing');
      load().then(done, done);
    });
    return load;
  };
}());
