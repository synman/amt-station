/* The Power & boot tab (design/power-boot.html, note 2.4): what AMT offers right now first, then the power actions (the
   Force tray holds the six that never ask the OS), the one-time next boot with its 14 checkboxes and two number fields,
   the combined entries, and the results with their readback. Every write is a sheet from components.js; the sheet kind is
   computed from the call's arguments there. A tool's refusal is shown verbatim (text nodes only, never markup). */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon, S = amtc.status;
  var head = document.querySelector('.srvhead[data-server]'), page = document.getElementById('power-page');
  if (!head || !page) return;
  var key = head.getAttribute('data-server'), POLL_MS = 5000;
  var $ = function (id) { return document.getElementById(id); };
  var clear = S.clear;

  // ---- the copy: the title, the confirm verb and the consequence line of each power action (from the tools' descriptions) ----
  var OS_NOT_ASKED = 'The OS is NOT asked. ';
  var POWER = {
    restart: { group: 'graceful', label: 'Restart', title: 'Restart @ (graceful)', verb: 'Restart',
      say: 'The host\'s OS is asked to restart (power state 14). Open applications may prompt to save; if the AMT agent in the OS does not answer, nothing happens and this is reported, never downgraded to a hard reset.' },
    shutdown: { group: 'graceful', label: 'Shut down', title: 'Shut down @ (graceful)', verb: 'Shut down',
      say: 'The host\'s OS is asked to shut down (power state 12). It stays off until powered on from here or at the button.' },
    power_cycle: { group: 'graceful', label: 'Power cycle', title: 'Power cycle @ (graceful)', verb: 'Power cycle',
      say: 'The host\'s OS is asked to shut down and AMT powers it back on.' },
    shutdown_hard_graceful: { group: 'graceful', label: 'Shut down, hard-graceful', title: 'Shut down @ (hard-graceful)', verb: 'Shut down',
      say: 'The host is asked to shut down gracefully to a hard-off state (power state 13).' },
    power_cycle_hard_graceful: { group: 'graceful', label: 'Power cycle, hard-graceful', title: 'Power cycle @ (hard-graceful)', verb: 'Power cycle',
      say: 'The host is power-cycled gracefully through a hard-off cycle (power state 16).' },
    power_on: { group: 'other', label: 'Power on', title: 'Power on @', verb: 'Power on', say: 'The host is powered on (power state 2).' },
    sleep_light: { group: 'other', label: 'Sleep (light)', title: 'Put @ to light sleep', verb: 'Sleep', say: 'The host enters light sleep (power state 3). Wake it with Power on.' },
    sleep_deep: { group: 'other', label: 'Sleep (deep)', title: 'Put @ to sleep', verb: 'Sleep', say: 'The host enters deep sleep (S3). Wake it with Power on.' },
    hibernate: { group: 'other', label: 'Hibernate', title: 'Hibernate @', verb: 'Hibernate', say: 'The host hibernates (S4).' },
    hard_reset: { group: 'force', label: 'Hard reset', title: 'Hard reset @', verb: 'hard reset', now: 'Hard reset now',
      say: OS_NOT_ASKED + 'The host resets at once as if the reset button were pressed: unsaved work is lost and a filesystem may need recovery.' },
    hard_power_off: { group: 'force', label: 'Hard power off', title: 'Hard power off @', verb: 'power off', now: 'Hard power off now',
      say: OS_NOT_ASKED + 'Power is cut at once: unsaved work is lost.' },
    hard_power_cycle: { group: 'force', label: 'Hard power cycle', title: 'Hard power cycle @', verb: 'power cycle', now: 'Hard power cycle now',
      say: OS_NOT_ASKED + 'Power is cut and restored at once, as if the plug were pulled: unsaved work is lost and a filesystem may need recovery.' },
    immediate_shutdown: { group: 'force', label: 'Immediate shutdown', title: 'Immediate shutdown of @', verb: 'shut down', now: 'Shut down now',
      say: OS_NOT_ASKED + 'The host is powered off at once: unsaved work is lost.' },
    immediate_power_cycle: { group: 'force', label: 'Immediate power cycle', title: 'Immediate power cycle of @', verb: 'power cycle', now: 'Power cycle now',
      say: OS_NOT_ASKED + 'The host is powered off and on at once: unsaved work is lost.' },
    nmi: { group: 'force', label: 'NMI', title: 'Send NMI to @', verb: 'send NMI', now: 'Send NMI now',
      say: 'A non-maskable interrupt is raised in the OS. On most hosts this crashes the kernel for a dump: unsaved work is lost.' }
  };
  var GROUPS = { graceful: 'power-graceful', other: 'power-other', force: 'power-force' };
  var BTN_CLASS = { graceful: 'btn tonal', other: 'btn outlined', force: 'btn text' };
  var DANGER = { secure_erase: 'the host\'s storage is erased', reflash_bios: 'the BIOS is reflashed', configuration_data_reset: 'the firmware configuration is reset' };
  var NUMBERS = [['firmware_verbosity', 0, 3], ['boot_media_index', 0, 255]];

  // ---- state: what AMT offers (phase loading | ok | error | paused) and the cached status entry ----
  var st = { phase: 'loading', offered: null, error: null, paused: null, readAtLocal: null, age0: 0 };
  var entry = null;
  var rec = {};                                              // action name -> { btn, wrap, reason }

  // ---- disabled controls say why, as visible text beside them (immutable 18 and 20) ----
  function setReason(r, reason) {
    if (reason) {
      r.btn.setAttribute('aria-disabled', 'true');
      if (!r.reason) { r.reason = h('span', { class: 'reason' }, [reason]); r.wrap.appendChild(r.reason); } else r.reason.textContent = reason;
    } else {
      r.btn.removeAttribute('aria-disabled');
      if (r.reason) { r.reason.remove(); r.reason = null; }
    }
  }
  function offeredReason(name) {
    if (st.phase === 'paused') return 'paused · ' + (st.paused.reason || 'refused');
    if (st.phase === 'loading') return 'reading what AMT offers';
    if (st.phase === 'ok' && st.offered.indexOf(name) === -1) return 'not offered by AMT right now';
    return null;
  }

  // ---- the target and the options the form would send ----
  function target() { var o = $('boot-target').options[$('boot-target').selectedIndex]; return { id: o.value, label: o.getAttribute('data-label') }; }
  function readOptions() {
    var o = {}, err = null;
    if (target().id === 'clear') return { options: o, error: null };      // normal boot sends no options: clear resets them all
    document.querySelectorAll('#boot-options .check[role=checkbox][aria-checked="true"]').forEach(function (c) { o[c.getAttribute('data-opt')] = true; });
    NUMBERS.forEach(function (n) {
      var input = $('opt-' + n[0]), box = $('field-' + n[0]), raw = input.value.trim(), v = Number(raw), bad = (input.validity && input.validity.badInput) || raw !== '' && (!isFinite(v) || Math.floor(v) !== v || v < n[1] || v > n[2]);
      box.classList.toggle('err', !!bad);
      box.querySelector('.help').textContent = bad ? n[0] + ' must be a whole number from ' + n[1] + ' to ' + n[2] : '';
      if (bad) err = err || n[0] + ' must be ' + n[1] + '-' + n[2];
      else if (raw !== '' && v > 0) o[n[0]] = v;
    });
    return { options: o, error: err };
  }
  function dangers(o) { return Object.keys(DANGER).filter(function (k) { return o[k] === true; }); }
  function atBoot(d) { return d.map(function (k) { return DANGER[k]; }).join('; '); }
  function bootCall(o) {
    var args = { device: key, target: target().id };
    if (Object.keys(o).length) args.options = o;
    return { tool: 'amt_set_next_boot', arguments: args };
  }
  var T = function (s) { return s.replace('@', key); };

  // ---- the specs the sheets are made from ----
  function powerSpec(name) {
    var t = POWER[name];
    return { id: 'pw-' + name, title: T(t.title), verb: t.verb, nowLabel: t.now, consequence: t.say,
      call: { tool: 'amt_power', arguments: { device: key, action: name } }, onResult: function (r) { addResult($('power-results'), powerResult(name, r)); } };
  }
  function bootSpec(kind) {
    var tg = target(), opts = readOptions().options, d = dangers(opts), call = bootCall(opts);
    var into = tg.label + (d.length ? ' with ' + d.join(', ') : '');
    var spec = { id: 'sheet-boot-' + kind, onResult: function (r) { bootResult(r, kind); } };
    if (kind === 'set') {
      if (tg.id === 'clear') return Object.assign(spec, { title: 'Clear the pending next boot of ' + key, verb: 'Clear next boot', call: call,
        consequence: 'Cancels a pending one-time boot request and resets every boot option to its safe default; the host is not touched now.' });
      var forced = amtc.destructiveCall(call);
      return Object.assign(spec, { title: 'Set the next boot of ' + key + ' to ' + into, call: call,
        verb: forced ? 'set next boot' : 'Set next boot', nowLabel: forced ? 'Set next boot now' : undefined,
        consequence: forced ? 'Only the boot request is written now; at the next start or reset, from any cause, ' + atBoot(d) + '. The host is not touched now, but what happens at that boot cannot be undone.'
          : 'Only the one-time boot target changes; the host is not touched now. It takes effect at the next start or reset, from any cause, and then clears.' });
    }
    var reset = kind === 'reset', tail = ' Two calls, in order; if the first is refused the second is not sent.';
    call.then = { tool: 'amt_power', arguments: { device: key, action: reset ? 'hard_reset' : 'power_on' } };
    var lead = 'Sets the one-time boot target' + (d.length ? ' (' + atBoot(d) + ' at that boot)' : '');
    return Object.assign(spec, { call: call, title: (reset ? 'Reset ' + key + ' into ' : 'Power on ' + key + ' into ') + into,
      verb: reset ? 'reset' : amtc.destructiveCall(call) ? 'power on' : 'Power on', nowLabel: reset ? 'Reset now' : 'Power on now',
      consequence: reset ? lead + ', then HARD resets the host: the OS is NOT asked and unsaved work is lost.' + tail
        : lead + ', then powers the host on.' + tail + (d.length ? ' What happens at that boot cannot be undone.' : '') });
  }

  // ---- results (design 7.4): the tool's own words, with the readback, in the card of the action ----
  function stamp() { return S.eastern(Date.now() / 1000, false); }
  function addResult(slot, node) {
    slot.insertBefore(node, slot.firstChild);
    while (slot.children.length > 5) slot.removeChild(slot.lastChild);
  }
  function lead(what) { return h('strong', {}, [stamp() + ' · ' + what]); }
  function failure(what, r) {                                  // the console could not make the call, or amt-mcp did not answer
    var code = (r.body && r.body.error) || 'no answer';
    if (r.status === 502) return S.result('live', 'i-help', [lead(what), ' · amt-mcp did not answer (' + code + ') · it is not known whether the request was sent; read the power state before trying again']);
    return S.result('error', 'i-block', [lead(what), ' · refused: ' + code + ' · nothing sent']);
  }
  function refusal(what, text, partial) {                     // a tool refusal, verbatim
    var tail = partial ? ' · part of the sequence ran before it stopped' : /nothing was sent/i.test(text) ? '' : ' · nothing sent';
    return S.result('error', 'i-block', [lead(what), ' · refused: ' + text + tail]);
  }
  function powerOk(name, s) {
    var parts = [lead(name)], rv = s.return_value;
    if (s.applied === true) parts.push(' · accepted, ReturnValue ' + rv);
    else if (rv !== undefined && rv !== 'unknown') parts.push(' · sent; ReturnValue ' + rv + ' (not 0): AMT did not confirm it');
    else parts.push(' · sent; the device replied without a ReturnValue: the outcome is unknown');
    if (s.graceful === true) parts.push(' · graceful'); else if (s.graceful === false) parts.push(' · ungraceful: the OS was not asked');
    var read = s.readback === 'ok';
    if (read) parts.push(' · power state read back: ' + s.power_state_after + (s.power_state_after_code === undefined ? '' : ' (code ' + s.power_state_after_code + ')'));
    else if (s.readback === 'unavailable') parts.push(' · readback unavailable (' + (s.readback_error || 'the read failed') + ')');
    if (s.note) parts.push(' · ' + s.note);
    return S.result(s.applied === true && read ? 'ok' : 'live', s.applied === true && read ? 'i-check' : 'i-timer', parts);
  }
  function powerResult(name, r) {
    var b = r.body || {};
    if (r.status !== 200) return failure(name, r);
    if (b.isError) return refusal(name, b.text, false);
    return powerOk(name, b.structured || {});
  }
  function bootOk(s) {
    var o = s.options && s.options.length ? ' with ' + s.options.join(', ') : '', n = Object.keys(s.readback || {}).length;
    var parts = [lead('set next boot ' + s.target + o), ' · ' + (s.steps || []).join(', ') + ' accepted · readback: ' + n + ' BootSettingData flags as sent'];
    if (s.note) parts.push(' · ' + s.note);
    return S.result('ok', 'i-check', parts);
  }
  function bootReply(reply) {                                  // one boot step's tool result
    if (reply.isError) return refusal('set next boot', reply.text, /completed=(?!none)/.test(reply.text));
    return bootOk(reply.structured || {});
  }
  function bootResult(r, kind) {
    var slot = $('boot-results'), b = r.body || {};
    if (kind === 'set') {
      addResult(slot, r.status !== 200 ? failure('set next boot', r) : bootReply(b));
      if (r.status === 200 && !b.isError) refreshEntry();
      return;
    }
    if (r.status !== 200) return addResult(slot, failure(kind === 'reset' ? 'reset into target' : 'power on into target', r));
    var steps = b.steps || [], first = steps[0] || {}, second = steps[1] || {}, action = kind === 'reset' ? 'hard_reset' : 'power_on', rows = [];
    rows.push(first.reply ? bootReply(first.reply) : first.error ? failure('set next boot', { status: first.sent === 'unknown' ? 502 : 400, body: { error: first.error } }) : failure('set next boot', { status: 400, body: {} }));
    if (second.reply) rows.push(powerReply(action, second.reply));
    else if (second.skipped) rows.push(S.result('live', 'i-timer', [lead(action), ' · not sent: the boot step was not accepted, so the host was not touched']));
    else if (second.error) rows.push(failure(action, { status: second.sent === 'unknown' ? 502 : 400, body: { error: second.error } }));
    rows.forEach(function (row) { addResult(slot, row); });          // newest on top: the power step, then the boot step
    if (first.reply && !first.reply.isError) refreshEntry();
  }
  function powerReply(action, reply) { return reply.isError ? refusal(action, reply.text, false) : powerOk(action, reply.structured || {}); }

  // ---- the power card ----
  function buildPowerButtons() {
    Object.keys(POWER).forEach(function (name) {
      var t = POWER[name], b = h('button', { type: 'button', class: BTN_CLASS[t.group], 'data-action': name }, [t.label]), wrap = h('div', { class: 'btn-wrap' }, [b]);
      rec[name] = { btn: b, wrap: wrap, reason: null };
      amtc.bindWrite(b, function () { return powerSpec(name); });
      $(GROUPS[t.group]).appendChild(wrap);
    });
  }
  function hostOn() { return !!(entry && entry.power && entry.power.kind === 'on'); }
  function apply() {
    Object.keys(rec).forEach(function (name) { setReason(rec[name], offeredReason(name)); });
    var opts = readOptions(), paused = st.phase === 'paused' ? 'paused · ' + (st.paused.reason || 'refused') : null;
    var setOnly = paused || opts.error, on = offeredReason('power_on') || (hostOn() ? 'host is already on' : null), reset = offeredReason('hard_reset');
    setReason(rec['boot-set'], setOnly);
    setReason(rec['boot-poweron'], setOnly || on);
    setReason(rec['boot-reset'], setOnly || reset);
    rec['boot-poweron'].btn.lastChild.textContent = 'Power on → ' + target().label;
    renderBanner(); renderEntry();
  }
  function renderEntry() {
    var pill = $('power-pill'), chip = $('boot-chip');
    clear(pill);
    if (entry) pill.appendChild(S.pill(entry.power));
    var nb = entry && entry.status && entry.status.next_boot, yes = function (v) { return v === true || v === 'true'; };
    var text = 'AMT reports: not read', cls = 'chip small dashed';
    if (nb && Object.keys(nb).length) {
      if (yes(nb.BIOSSetup)) { text = 'AMT reports: BIOS setup pending'; cls = 'chip small live'; }
      else if (yes(nb.UseIDER)) { text = 'AMT reports: IDE-R ' + (String(nb.IDERBootDevice) === '1' ? 'CD' : 'floppy') + ' boot pending'; cls = 'chip small live'; }
      else { text = 'AMT reports: normal'; cls = 'chip small'; }
    }
    chip.className = cls; chip.textContent = text;
  }

  // ---- the offered-set banner ----
  function renderBanner() {
    var box = $('offered-banner'), text = $('offered-text'), data = function (v) { return h('span', { class: 'data' }, [v]); };
    clear(text);
    box.className = 'banner' + (st.phase === 'ok' || st.phase === 'loading' ? '' : ' error');
    if (st.phase === 'loading') text.appendChild(document.createTextNode('Reading what AMT offers right now…'));
    else if (st.phase === 'paused') text.appendChild(document.createTextNode('Reading is paused for this server (' + (st.paused.reason || 'refused') + '): no power or boot action is offered from here until it resumes. Retry once from the Status tab.'));
    else if (st.phase === 'error') text.appendChild(document.createTextNode('What AMT offers could not be read (' + st.error + '). Every action stays available: amt_power reads the list itself and refuses one AMT does not offer, naming the ones it does, with nothing sent.'));
    else {
      var age = S.ago(st.age0 + (Date.now() - st.readAtLocal) / 1000);
      [h('strong', {}, ['AMT offers right now:']), ' ', data(st.offered.length ? st.offered.join(' ') : 'nothing'), ' · read ' + age + ' from ', data('AvailableRequestedPowerStates'),
        '. An action it does not offer is greyed with the reason; amt_power refuses it by name and sends nothing.'].forEach(function (n) { text.appendChild(typeof n === 'string' ? document.createTextNode(n) : n); });
    }
  }
  function readOffered() {
    return S.get('/api/server/' + key + '/power').then(function (r) {
      if (r.status !== 200) { st = { phase: 'error', offered: null, error: r.body.error || 'no answer', paused: null }; return apply(); }
      var b = r.body;
      if (b.paused) st = { phase: 'paused', offered: null, error: null, paused: b.paused };
      else if (Array.isArray(b.offered)) st = { phase: 'ok', offered: b.offered, error: null, paused: null, readAtLocal: Date.now(), age0: Math.max(0, b.now - b.read_at) };
      else st = { phase: 'error', offered: null, error: b.error || 'no list reported', paused: null };
      apply();
    });
  }
  function loadEntry() {
    return S.get('/api/server/' + key).then(function (r) { if (r.status === 200) { entry = r.body.server; apply(); } });
  }
  function refreshEntry() {                                    // after a boot write: one status read, so the chip shows what AMT now holds
    return amtc.post('/api/fleet/refresh', { device: key }).then(function (r) { if (r.status === 200 && r.body.server) { entry = r.body.server; apply(); } });
  }

  // ---- the next boot card ----
  function buildBoot() {
    document.querySelectorAll('#boot-options .check[role=checkbox]').forEach(function (c) {
      function flip() { if (c.getAttribute('aria-disabled') === 'true') return; c.setAttribute('aria-checked', String(c.getAttribute('aria-checked') !== 'true')); apply(); }
      c.addEventListener('click', flip);
      c.addEventListener('keydown', function (e) { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); if (!e.repeat) flip(); } });
    });
    NUMBERS.forEach(function (n) { $('opt-' + n[0]).addEventListener('input', apply); });
    $('boot-target').addEventListener('change', apply);
    [['boot-set', 'set'], ['boot-poweron', 'poweron'], ['boot-reset', 'reset']].forEach(function (p) {
      var b = $(p[0]), wrap = h('div', { class: 'btn-wrap' }, []);
      b.parentNode.insertBefore(wrap, b); wrap.appendChild(b);
      rec[p[0]] = { btn: b, wrap: wrap, reason: null };
      amtc.bindWrite(b, function () { return bootSpec(p[1]); });
    });
  }

  buildPowerButtons();
  buildBoot();
  var again = $('offered-reread');
  again.addEventListener('click', function () {
    if (again.getAttribute('aria-disabled') === 'true') return;
    var done = S.busy(again, 'reading');
    readOffered().then(done, done);
  });
  apply();
  amtc.ready.then(function () {
    loadEntry(); readOffered();
    setInterval(loadEntry, POLL_MS);
    setInterval(function () { if (st.phase === 'ok') renderBanner(); }, POLL_MS);
  });
}());
