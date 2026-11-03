/* amt-console component layer: sheets with focus management, the write confirmation, the force control with its
   state machine, and the one destructive-call predicate (design note 5.1, 5.2, immutables 4, 5 and 6).
   Public surface: window.amtc. The verifier hooks keep the mockups' names (window.__openSheet, __closeSheets,
   __calls, __callCount, __forceFireCount, __destructiveCall) so the same matrix runs against this code. */
(function () {
  'use strict';
  var ICONS = '/static/icons.svg';
  var amtc = window.amtc = window.amtc || { csrf: null };

  // ---- small DOM helpers ----
  function h(tag, attrs, kids) {
    var el = document.createElement(tag);
    Object.keys(attrs || {}).forEach(function (k) { if (attrs[k] !== null && attrs[k] !== undefined) el.setAttribute(k, attrs[k]); });
    (kids || []).forEach(function (c) { el.appendChild(typeof c === 'string' ? document.createTextNode(c) : c); });
    return el;
  }
  function icon(id) {
    var NS = 'http://www.w3.org/2000/svg', svg = document.createElementNS(NS, 'svg'), use = document.createElementNS(NS, 'use');
    svg.setAttribute('class', 'i'); svg.setAttribute('aria-hidden', 'true');
    use.setAttribute('href', ICONS + '#' + id); svg.appendChild(use);
    return svg;
  }
  amtc.h = h; amtc.icon = icon;

  // ---- talking to the console backend ----
  amtc.post = function (path, body) {
    var headers = { 'Content-Type': 'application/json' };
    if (amtc.csrf) headers['X-CSRF-Token'] = amtc.csrf;
    return fetch(path, { method: 'POST', headers: headers, credentials: 'same-origin', body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }, function () { return { status: r.status, body: {} }; }); });
  };

  // ---- sheets: role=dialog, focus to Cancel on open (never a confirm), Tab trapped inside, focus restored to the opener ----
  var scrim = null, openerStack = [];
  function scrimEl() {
    if (!scrim) {
      scrim = document.getElementById('scrim');
      if (!scrim) { scrim = h('div', { id: 'scrim', class: 'scrim' }); document.body.appendChild(scrim); }
      scrim.addEventListener('click', closeSheets);
    }
    return scrim;
  }
  function topSheet() { var o = document.querySelectorAll('.sheet.open:not(.inline)'); return o.length ? o[o.length - 1] : null; }
  function openSheet(id, opts) {
    var s = document.getElementById(id); if (!s) return null;
    opts = opts || {};
    var opener = opts.opener || document.activeElement;
    if (opener && opener !== document.body && !opener.closest('.sheet')) openerStack.push(opener);
    s.classList.add('open'); scrimEl().classList.add('open');
    s.setAttribute('data-opened-by', opts.byKey ? 'key' : 'pointer');
    s.dispatchEvent(new CustomEvent('sheet-open', { detail: opts }));
    var first = s.querySelector('[data-autofocus]') || s.querySelector('[data-close]'); if (first) first.focus();
    return s;
  }
  function closeSheets() {
    var was = false;
    document.querySelectorAll('.sheet.open:not(.inline)').forEach(function (s) { was = true; s.classList.remove('open'); s.dispatchEvent(new CustomEvent('sheet-close')); });
    scrimEl().classList.remove('open');
    if (was) { var back = openerStack.length ? openerStack[0] : null; openerStack = []; if (back && document.contains(back)) { try { back.focus(); } catch (e) { /* gone */ } } }
  }
  amtc.openSheet = openSheet; amtc.closeSheets = closeSheets;
  window.__openSheet = openSheet; window.__closeSheets = closeSheets;

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape') { closeSheets(); return; }
    if (e.key !== 'Tab') return;
    var s = topSheet(); if (!s) return;
    var f = Array.prototype.filter.call(s.querySelectorAll('button, a[href], input, select, textarea, [tabindex="0"]'), function (el) { return el.offsetParent !== null; });
    if (!f.length) return;
    var i = f.indexOf(document.activeElement);
    if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus(); }
    else if (!e.shiftKey && (i === -1 || i === f.length - 1)) { e.preventDefault(); f[0].focus(); }
  });
  document.addEventListener('keydown', function (e) {       // a held key opens a sheet once, never again
    if (e.repeat && e.target.closest && e.target.closest('[data-open]')) { e.preventDefault(); e.stopImmediatePropagation(); }
  }, true);
  document.addEventListener('click', function (e) {
    var dis = e.target.closest('[aria-disabled="true"]');
    if (dis) { e.preventDefault(); e.stopImmediatePropagation(); return; }
    var op = e.target.closest('[data-open]');
    if (op) { openSheet(op.getAttribute('data-open'), { byKey: e.detail === 0, opener: op }); return; }
    if (e.target.closest('[data-close]')) closeSheets();
  }, true);

  // ---- the call spy: every call sent lands here with whether a force fire preceded it ----
  var calls = [], fireCount = 0;
  window.__calls = function () { return calls.slice(); };
  window.__callCount = function () { return calls.length; };
  window.__forceFireCount = function () { return fireCount; };

  // The destructive predicate, computed from the call's ARGUMENTS (never from which button opened the sheet).
  // `ctx` carries what a call cannot: for stopping a mirror or terminal, whether an agent started it or a call is in flight.
  var FORCED_POWER = ['hard_reset', 'hard_power_off', 'hard_power_cycle', 'immediate_shutdown', 'immediate_power_cycle', 'nmi'];
  var BOOT_DESTRUCTIVE = ['secure_erase', 'reflash_bios', 'configuration_data_reset'];
  function destructiveCall(call, ctx) {
    return destructiveStep(call, ctx) || (!!call && !!call.then && destructiveStep(call.then, ctx));   // a sequence is as destructive as its worst step
  }
  function destructiveStep(call, ctx) {
    var a = (call && call.arguments) || {}, ctxt = ctx || {};
    switch (call && call.tool) {
      case 'amt_power': return FORCED_POWER.indexOf(a.action) !== -1;
      case 'amt_set_next_boot': return !!a.options && typeof a.options === 'object' && BOOT_DESTRUCTIVE.some(function (k) { return a.options[k] === true; });
      case 'amt_ider': return a.start === 'now';
      case 'amt_images': return a.action === 'delete';
      case 'amt_device_manage': return a.action === 'remove' || a.repin === true;
      case 'amt_identity_manage': return a.action === 'remove';
      case 'amt_wsman_invoke': return a.method === 'Unprovision';
      case 'amt_mirror_link': case 'amt_serial_link': return a.action === 'stop' && (ctxt.startedByAgent === true || ctxt.callInFlight === true);
      default: return false;
    }
  }
  amtc.destructiveCall = destructiveCall; window.__destructiveCall = destructiveCall;

  // `tools/call amt_power {device: "x", action: "restart", confirmed: true}`: the text a sheet shows is the call it sends.
  function lit(v) {
    if (v === null || typeof v !== 'object') return JSON.stringify(v);
    if (Array.isArray(v)) return '[' + v.map(lit).join(', ') + ']';
    return '{' + Object.keys(v).map(function (k) { return (/^[A-Za-z_][A-Za-z0-9_]*$/.test(k) ? k : JSON.stringify(k)) + ': ' + lit(v[k]); }).join(', ') + '}';
  }
  // A call may carry `then`: a second call the backend sends only if the first was accepted (the combined boot entries).
  function fmtCall(call) { return 'tools/call ' + call.tool + ' ' + lit(call.arguments) + (call.then ? ' · then ' + call.then.tool + ' ' + lit(call.then.arguments) : ''); }
  amtc.fmtCall = fmtCall;

  function sendCall(spec, forced) {
    var call = spec.call;
    calls.push({ sheet: spec.sheetId, tool: call.tool, arguments: call.arguments, then: call.then || null, ctx: spec.ctx || {}, text: fmtCall(call), forced: !!forced });
    document.dispatchEvent(new CustomEvent('tools-call', { detail: { sheet: spec.sheetId, count: calls.length, forced: !!forced } }));
    var sent = call.then ? amtc.post('/api/sequence', { steps: [{ tool: call.tool, arguments: call.arguments }, { tool: call.then.tool, arguments: call.then.arguments }] })
      : amtc.post('/api/call', { tool: call.tool, arguments: call.arguments });
    sent.then(function (r) {
      document.dispatchEvent(new CustomEvent('tools-result', { detail: { sheet: spec.sheetId, status: r.status, body: r.body } }));
      if (spec.onResult) spec.onResult(r, spec.values);
    });
    return sent;
  }

  // ---- the write confirmation (design 5.1): a plain sheet, or the force sheet when the predicate says so ----
  var sheetSeq = 0;
  function consequenceLine(text, destructive) {
    return h('p', { class: 'consequence' + (destructive ? ' destructive' : '') }, [icon(destructive ? 'i-warning' : 'i-info'), h('span', {}, [text])]);
  }
  // A call with confirmed: true (a read-only call is sent as it is); a sequence's second step is a write too.
  function confirmedCall(call, readOnly) {
    var c = { tool: call.tool, arguments: Object.assign({}, call.arguments, readOnly ? {} : { confirmed: true }) };
    if (call.then) c.then = { tool: call.then.tool, arguments: Object.assign({}, call.then.arguments, { confirmed: true }) };
    return c;
  }
  function plainSheet(id, spec) {
    var confirm = h('button', { class: 'btn filled', 'data-confirm': '', 'data-autofocus-never': '' }, [spec.verb]);
    var title = h('h2', { id: id + '-t' }, [spec.title]), callEl = h('p', { class: 'call' }, [fmtCall(spec.call) + (spec.callNote ? ' · ' + spec.callNote : '')]);
    var fields = spec.fields ? fieldRows(id, spec, title, callEl, confirm) : null;
    var s = h('div', { id: id, class: 'sheet', 'data-motion': 'sheet-open', 'data-confirm-sheet': '', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': id + '-t' }, [
      h('div', { class: 'handle', 'aria-hidden': 'true' }), title, consequenceLine(spec.consequence, false)].concat(fields ? fields.rows : [], [callEl,
      h('div', { class: 'acts' }, [h('button', { class: 'btn text', 'data-close': '' }, ['Cancel']), fields ? fields.wrap : confirm])]));
    confirm.addEventListener('keydown', function (e) { if (e.repeat) { e.preventDefault(); e.stopImmediatePropagation(); } });
    confirm.addEventListener('click', function (e) {
      e.preventDefault();
      var sent = spec;
      if (fields) {
        sent = Object.assign({}, spec, { call: fields.current(), values: fields.values() });   // Confirm is aria-disabled while there is no call, and never gets here
      }
      closeSheets(); sendCall(sent, false);
    });
    return [s];
  }
  /* Input fields on a plain sheet (rename, fetch, upload, set root). spec.fields = [{ name, label, value?, placeholder?, mono?, type?: 'file', accept? }]
     and spec.build(values) -> { call, title?, notes? } or { error, title?, notes? }, where values maps a field name to its text (or the chosen File).
     The call shown is rebuilt from the values on every input and is the call sent; while build reports an error, Confirm is aria-disabled with the
     error as its visible reason. A form sheet can only be plain: a call the predicate calls destructive is shown as an error, never offered, so
     typing into a field cannot take the place of the hold. */
  function fieldRows(id, spec, title, callEl, confirm) {
    var inputs = {}, helps = {}, rows = [], reason = h('span', { class: 'reason' }, ['']), wrap = h('div', { class: 'btn-wrap' }, [confirm, reason]), cur = null;
    spec.fields.forEach(function (f) {
      var fid = id + '-f-' + f.name;
      var input = f.type === 'file' ? h('input', { id: fid, type: 'file', accept: f.accept })
        : h('input', { id: fid, class: f.mono ? 'mono' : null, value: f.value, placeholder: f.placeholder, autocomplete: 'off', spellcheck: 'false', 'data-field': f.name });
      var help = h('span', { class: 'help' });
      inputs[f.name] = input; helps[f.name] = help;
      input.addEventListener('input', recompute); input.addEventListener('change', recompute);
      rows.push(h('div', { class: 'field' }, [h('label', { for: fid }, [f.label]), input, help]));
    });
    function values() {
      var v = {};
      spec.fields.forEach(function (f) { v[f.name] = f.type === 'file' ? (inputs[f.name].files && inputs[f.name].files[0]) || null : inputs[f.name].value; });
      return v;
    }
    function recompute() {
      var r = spec.build(values()), why = r.error || null;
      if (r.title) title.textContent = r.title;
      spec.fields.forEach(function (f) { helps[f.name].textContent = (r.notes && r.notes[f.name]) || ''; });
      if (!why && destructiveCall(r.call, spec.ctx)) why = 'this call needs the hold, which a form cannot offer';
      cur = why ? null : confirmedCall(r.call);
      callEl.textContent = fmtCall(cur || spec.call) + (spec.callNote ? ' · ' + spec.callNote : '');
      if (why) { confirm.setAttribute('aria-disabled', 'true'); reason.textContent = why; reason.hidden = false; }
      else { confirm.removeAttribute('aria-disabled'); reason.textContent = ''; reason.hidden = true; }
    }
    recompute();
    return { rows: rows, wrap: wrap, current: function () { return cur; }, values: values };
  }
  function forceSheets(id, spec) {
    var id2 = id + '-sheet2', text = fmtCall(spec.call);
    var ctl = h('button', { class: 'force-control', 'data-hold': '', 'data-sheet': id2, 'aria-describedby': id + '-help' }, [
      h('span', { class: 'fill', 'data-motion': 'force-hold' }), icon('i-warning'), h('span', { class: 'lbl' }, ['Hold to ' + spec.verb]), h('span', { class: 'count', 'aria-hidden': 'true' }, ['3'])]);
    var host = h('div', { id: id, class: 'sheet', 'data-motion': 'sheet-open', 'data-force-sheet': '', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': id + '-t' }, [
      h('div', { class: 'handle', 'aria-hidden': 'true' }), h('h2', { id: id + '-t' }, [spec.title]),
      consequenceLine(spec.consequence, true)].concat(spec.detail ? [spec.detail()] : [], [h('p', { class: 'call' }, [text]),
      h('div', { class: 'acts' }, [h('button', { class: 'btn text', 'data-close': '' }, ['Cancel']), ctl,
        h('span', { id: id + '-help', class: 'body-s muted' }, ['Hold 1.2 s and release, or press Enter and confirm on the next sheet'])])]));
    var confirm = h('button', { class: 'btn danger', 'data-confirm': '', 'data-armed': 'false', 'aria-disabled': 'true' }, [spec.nowLabel || spec.verb + ' now']);
    var second = h('div', { id: id2, class: 'sheet', 'data-motion': 'sheet-open', 'data-force-sheet2': '', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': id2 + '-t' }, [
      h('div', { class: 'handle', 'aria-hidden': 'true' }), h('h2', { id: id2 + '-t' }, [spec.title]),
      h('div', { class: 'acts' }, [h('button', { class: 'btn text', 'data-close': '', 'data-autofocus': '' }, ['Cancel']),
        h('div', { class: 'btn-wrap' }, [confirm, h('span', { class: 'reason' }, ['arms 400 ms after you release the key or the pointer'])])]),
      consequenceLine(spec.consequence, true), h('p', { class: 'call' }, [text])]);
    wireForceControl(ctl, spec);
    wireSecondSheet(second, confirm, spec);
    return [host, second];
  }
  function fire(spec) {
    fireCount += 1; closeSheets();
    document.dispatchEvent(new CustomEvent('force-fired', { detail: { count: fireCount } }));
    sendCall(spec, true);
  }

  // The force control. Pointer: a hold of 1200 ms arms it (the bar is full) and the RELEASE fires (up-event completion, SC 2.5.2);
  // leaving the control, a swipe or an early release cancels; the click that follows a fired hold is swallowed.
  // A click, a tap, a key press or an assistive-technology activation opens the SECOND sheet instead. event.repeat is ignored.
  function wireForceControl(k, spec) {
    var timer = null, tick = null, armed = false, suppressClick = false, n = 3, cnt = k.querySelector('.count');
    function reset() { clearTimeout(timer); clearInterval(tick); timer = tick = null; armed = false; k.classList.remove('holding', 'armed'); }
    k.addEventListener('pointerdown', function (e) {
      if (e.button !== 0) return;
      reset(); k.classList.add('holding'); n = 3; cnt.textContent = n;
      tick = setInterval(function () { n = Math.max(0, n - 1); cnt.textContent = n; }, 400);
      timer = setTimeout(function () { armed = true; k.classList.add('armed'); cnt.textContent = 'release'; }, 1200);
    });
    k.addEventListener('pointerup', function () { var was = armed; reset(); if (was) { suppressClick = true; fire(spec); } });
    ['pointerleave', 'pointercancel'].forEach(function (ev) { k.addEventListener(ev, reset); });
    k.addEventListener('pointermove', function (e) {
      var r = k.getBoundingClientRect(); if (e.clientX < r.left || e.clientX > r.right || e.clientY < r.top || e.clientY > r.bottom) reset();
    });
    k.addEventListener('click', function (e) {
      e.preventDefault();
      if (suppressClick) { suppressClick = false; return; }
      openSheet(k.getAttribute('data-sheet'), { byKey: e.detail === 0, opener: k });
    });
    k.addEventListener('keydown', function (e) {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      e.preventDefault(); if (e.repeat) return;
      openSheet(k.getAttribute('data-sheet'), { byKey: true, key: e.key, opener: k });
    });
  }

  // The second sheet's confirm arms only 400 ms after a RELEASE (keyup or pointerup) that happened after the sheet opened,
  // never on a timer from the opening activation; a pointer click fires only if its own pointerdown landed while armed.
  var releaseHooks = [];
  function released() { releaseHooks = releaseHooks.filter(function (f) { return f(); }); }   // a hook returns false once its sheet is gone
  document.addEventListener('keyup', function (e) { if (e.key === 'Enter' || e.key === ' ') released(); });
  document.addEventListener('pointerup', released);
  function wireSecondSheet(s, btn, spec) {
    var armTimer = null, releaseSeen = false, armedSheet = false, downWhileArmed = false;
    function disarm() { armedSheet = false; btn.setAttribute('aria-disabled', 'true'); btn.setAttribute('data-armed', 'false'); }
    function arm() { if (!s.classList.contains('open')) return; armedSheet = true; btn.removeAttribute('aria-disabled'); btn.setAttribute('data-armed', 'true'); }
    function release() { if (!s.classList.contains('open') || releaseSeen) return; releaseSeen = true; clearTimeout(armTimer); armTimer = setTimeout(arm, 400); }
    s.__release = release;
    releaseHooks.push(function () { if (!document.contains(s)) return false; release(); return true; });
    s.addEventListener('sheet-open', function () { clearTimeout(armTimer); disarm(); releaseSeen = false; downWhileArmed = false; var c = s.querySelector('[data-close]'); if (c) c.focus(); });
    s.addEventListener('sheet-close', function () { clearTimeout(armTimer); disarm(); releaseSeen = false; });
    btn.addEventListener('pointerdown', function () { downWhileArmed = armedSheet; });
    btn.addEventListener('keydown', function (e) { if (e.repeat) { e.preventDefault(); e.stopImmediatePropagation(); } });
    btn.addEventListener('click', function (e) {
      e.preventDefault();
      var byPointer = e.detail > 0;
      if (!armedSheet || (byPointer && !downWhileArmed)) return;
      fire(spec);
    });
  }

  /* amtc.openWrite(spec, opener): spec = { id?, title, verb, nowLabel?, consequence, call: {tool, arguments, then?}, ctx?, readOnly?, detail?, onResult? }.
     `detail` is a function returning a node a FORCE sheet shows between the consequence and the call (the re-pin sheet's two fingerprints).
     `then` is a second write sent after the first only if the backend accepted it (POST /api/sequence); `nowLabel` is the force
     sheet's confirm text when "<verb> now" does not read well. `fields` and `build` add input fields to a PLAIN sheet (see fieldRows);
     onResult(r, values) then also gets what the fields held when Confirm was pressed.
     The call that is shown is the call that is sent, with confirmed: true. The sheet kind comes from the one predicate
     over that call's arguments; the same predicate decided the consequence line's style. */
  amtc.openWrite = function (spec, opener) {
    var id = spec.id || 'w' + (++sheetSeq);
    // A read-only call (amt_screenshot: it opens a session but writes nothing) is confirmed by the sheet and sent as it is;
    // a write always carries confirmed: true, and a call the predicate calls destructive can never be sent as a read.
    var readOnly = spec.readOnly === true && !destructiveCall(spec.call);
    var call = confirmedCall(spec.call, readOnly);                            // both steps of a sequence are writes
    if (spec.fields && destructiveCall(call, spec.ctx)) throw new Error('a sheet with fields cannot be a force sheet');
    var full = Object.assign({}, spec, { call: call, sheetId: id });
    [id, id + '-sheet2'].forEach(function (old) { var el = document.getElementById(old); if (el) el.remove(); });
    var made = destructiveCall(call, spec.ctx) ? forceSheets(id, full) : plainSheet(id, full);
    made.forEach(function (el) { document.body.appendChild(el); });
    return openSheet(id, { byKey: false, opener: opener });
  };

  /* amtc.bindWrite(button, specFn): one deliberate activation opens the sheet; a held key opens it once (event.repeat ignored). */
  amtc.bindWrite = function (button, specFn) {
    button.addEventListener('keydown', function (e) { if (e.repeat) { e.preventDefault(); e.stopImmediatePropagation(); } });
    button.addEventListener('click', function (e) {
      if (button.getAttribute('aria-disabled') === 'true') return;
      amtc.openWrite(specFn(), button);
    });
  };
}());
