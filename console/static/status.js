/* Shared pieces of the fleet and server pages: the power pill, the session and pin chips, the fingerprint, times.
   Everything is built with text nodes (amtc.h), never markup: a tool's refusal text is shown verbatim and is data. */
(function () {
  'use strict';
  var amtc = window.amtc, h = amtc.h, icon = amtc.icon;
  var S = amtc.status = {};

  // ---- times (operator-facing times are US Eastern, labelled EST or EDT) ----
  var EASTERN = new Intl.DateTimeFormat('en-CA', { timeZone: 'America/New_York', year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23', timeZoneName: 'short' });
  S.eastern = function (epoch, withDate) {
    var p = {};
    EASTERN.formatToParts(new Date(epoch * 1000)).forEach(function (x) { p[x.type] = x.value; });
    return (withDate === false ? '' : p.year + '-' + p.month + '-' + p.day + ' ') + p.hour + ':' + p.minute + ':' + p.second + ' ' + p.timeZoneName;
  };
  S.ago = function (s) {
    if (s === null || s === undefined) return 'never';
    s = Math.max(0, Math.round(s));
    return s < 60 ? s + ' s ago' : s < 3600 ? Math.floor(s / 60) + ' min ago' : Math.floor(s / 3600) + ' h ago';
  };
  S.elapsed = function (s) {
    s = Math.max(0, Math.round(s || 0));
    var hh = Math.floor(s / 3600), mm = Math.floor((s % 3600) / 60), ss = s % 60, two = function (n) { return (n < 10 ? '0' : '') + n; };
    return (hh ? hh + ':' : '') + two(mm) + ':' + two(ss);
  };
  S.bytes = function (n) {
    if (typeof n !== 'number') return 'size unknown';
    return n < 1024 ? n + ' B' : n < 1048576 ? Math.round(n / 1024) + ' KB' : n < 1073741824 ? (n / 1048576).toFixed(1) + ' MB' : (n / 1073741824).toFixed(2) + ' GB';
  };

  // ---- a TLS fingerprint: in full, grouped by 4, the stored prefix in bold ----
  S.fp = function (hex, prefix) {
    var span = h('span', { class: 'fp' });
    if (!hex) { span.appendChild(document.createTextNode('not pinned')); return span; }
    var groups = hex.match(/.{1,4}/g) || [], bold = prefix && hex.indexOf(prefix) === 0 ? Math.ceil(prefix.length / 4) : 0;
    groups.forEach(function (g, i) {
      if (i) span.appendChild(document.createTextNode(' '));
      span.appendChild(i < bold ? h('b', {}, [g]) : document.createTextNode(g));
    });
    return span;
  };
  S.shortFp = function (hex, prefix) {                      // the stored 16-hex prefix, grouped by 4
    var p = prefix || (hex || '').slice(0, 16), span = h('span', { class: 'fp' }, [(p.match(/.{1,4}/g) || []).join(' ')]);
    return span;
  };

  // ---- pills and chips ----
  S.pill = function (power, withCode) {
    var p = h('span', { class: 'pill ' + power.kind, 'data-power': power.kind }, [icon(power.kind === 'unknown' ? 'i-help' : 'i-power'), power.label]);
    return p;
  };
  function chip(cls, attrs, iconId, parts, live) {
    var a = { class: 'chip ' + cls };
    Object.keys(attrs).forEach(function (k) { a[k] = attrs[k]; });
    var kids = [];
    if (live) kids.push(h('span', { class: 'dot', 'data-motion': 'live-pulse' }));
    if (iconId) kids.push(icon(iconId));
    return h('span', a, kids.concat(parts));
  }
  var sz = function (small) { return small ? ' small' : ''; };

  function sessionChip(kind, label, view, small, long) {
    if (!view || view.holder === 'unknown') return chip('dashed' + sz(small), { 'data-session': 'unknown' }, 'i-help', [label + ' unknown']);
    var icn = kind === 'kvm' ? 'i-cast' : 'i-terminal', t = S.elapsed(view.elapsed_s);
    switch (view.holder) {
      case 'console': return chip('live' + sz(small), { 'data-session': 'held_console' }, icn, [label + ' · you' + (long ? ' (console)' : '') + ' · ' + t], true);
      case 'agent': return chip('live' + sz(small), { 'data-session': 'held_agent' }, icn, [label + ' · agent via ' + (kind === 'kvm' ? 'mirror' : 'terminal') + ' · ' + t], true);
      case 'other': return chip('error' + sz(small), { 'data-session': 'held_other' }, 'i-lock', [label + ' · another client · opens refused']);
      default: return chip(sz(small).trim(), { 'data-session': kind === 'kvm' ? 'free' : 'sol_free' }, icn, [label + ' free']);
    }
  }
  S.kvmChip = function (view, small, long) { return sessionChip('kvm', 'KVM', view, small, long); };
  S.solChip = function (view, small, long) { return sessionChip('sol', 'SOL', view, small, long); };
  S.iderChip = function (ider, small, long) {
    if (!ider || ider.mounted !== true) return null;
    var names = Object.keys(ider.images || {}).map(function (k) { return ider.images[k]; });
    return chip('live' + sz(small), { 'data-session': 'ider' }, 'i-disc', [long && names.length ? 'IDE-R · ' + names.join(', ') : 'IDE-R mounted'], true);
  };
  S.pinChip = function (e, small, withFp) {
    var cls = sz(small);
    switch (e.pin) {
      case 'matches': return chip('ok' + cls, { 'data-pin': 'matches' }, 'i-verified', ['pin matches'].concat(withFp && e.leaf ? [' · ', S.shortFp(e.leaf, e.prefix)] : []));
      case 'differs': return chip('error' + cls, { 'data-pin': 'differs' }, 'i-block', ['pin differs · every call refused']);
      case 'unpinned': return chip('error' + cls, { 'data-pin': 'unpinned' }, 'i-block', ['unpinned · every call refused']);
      default: return chip('dashed' + cls, { 'data-pin': 'unchecked' }, 'i-help', ['pin not checked']);
    }
  };
  S.pausedChip = function (e, small) {
    return chip('error' + sz(small), { 'data-session': 'paused' }, 'i-block', ['paused · ' + (e.paused ? e.paused.reason : 'refused')]);
  };

  // ---- a result row (design 7.4): the tool's text verbatim, where the action was ----
  S.result = function (kind, iconId, parts) {
    return h('div', { class: 'result ' + kind }, [icon(iconId), h('span', {}, parts)]);
  };

  // ---- a screenshot's outcome (design 5.4): verified and kept, expired, or refused, with the tool's text verbatim ----
  function copyButton(text) {
    var b = h('button', { type: 'button', class: 'btn text' }, [icon('i-copy'), 'Copy sha256']);
    b.addEventListener('click', function () {
      var done = function (ok) { b.lastChild.textContent = ok ? 'Copied' : 'Could not copy'; };
      try { navigator.clipboard.writeText(text).then(function () { done(true); }, function () { done(false); }); } catch (e) { done(false); }
    });
    return b;
  }
  S.captureActions = function (rec, key, openLink) {
    var row = h('div', { class: 'row' }, [h('a', { class: 'btn outlined', href: '/captures/' + rec.id }, [icon('i-download'), 'Save'])]);
    row.appendChild(copyButton(rec.sha256));
    if (openLink) row.appendChild(h('a', { class: 'btn text', href: '/server/' + key + '/console' }, [icon('i-open'), 'Open in console']));
    return row;
  };
  S.shotResult = function (key, r, openLink) {
    var box = h('div', { class: 'col gap8' }), at = S.eastern(Date.now() / 1000, false), body = r.body || {};
    if (r.status !== 200) { box.appendChild(S.result('error', 'i-block', [at + ' · screenshot · refused: ' + (body.error || 'no answer') + ' · nothing sent'])); return box; }
    if (body.isError) { box.appendChild(S.result('error', 'i-block', [at + ' · screenshot · refused: ' + body.text + ' · no input was sent'])); return box; }
    var s = body.structured || {}, rec = s.capture;
    if (!rec) { box.appendChild(S.result('live', 'i-info', [at + ' · screenshot taken; amt-mcp offered no one-time link' + (s.path_note ? ': ' + s.path_note : '') + '.'])); return box; }
    if (rec.status === 'expired') { box.appendChild(S.result('error', 'i-timer', [h('strong', {}, [at]), ' · the one-time link expired: it was not fetched within 15 minutes. Take a new screenshot.'])); return box; }
    if (rec.status !== 'ready') { box.appendChild(S.result('error', 'i-block', [h('strong', {}, [at]), ' · not kept: ' + (rec.reason || 'the fetch failed') + '. Take a new screenshot.'])); return box; }
    var bits = [h('strong', {}, [key + ' · ' + S.eastern(rec.taken_at)])];
    if (s.width && s.height) bits.push(' · ' + s.width + '×' + s.height);
    bits.push(' · ' + S.bytes(rec.bytes));
    if (typeof s.iterations === 'number') bits.push(s.stable === true ? ' · stable after ' + s.iterations + ' frames' : ' · still changing after ' + s.iterations + ' frames');
    bits.push(' · sha256 ', S.fp(rec.sha256), ' verified · fetched once from amt-mcp and kept in the capture store for 24 h');
    box.appendChild(S.result('ok', 'i-verified', bits));
    box.appendChild(S.captureActions(rec, key, openLink));
    return box;
  };

  // ---- a past capture's row (design 5.4): Save when kept, Fetch when not; the fetch is one read-only amt_captures call ----
  var KIND = { screenshot: ['i-camera', 'screenshot'], recording: ['i-record', 'mirror recording'], serial_cast: ['i-terminal', 'serial cast'] };
  S.pastRow = function (c, listBox) {
    var k = KIND[c.kind] || ['i-info', c.kind || 'capture'], rec = c.capture;
    var when = c.modified ? S.eastern(Date.parse(c.modified) / 1000) : 'time unknown';
    var sub = rec && rec.status === 'ready' ? ['sha256 ', S.fp(rec.sha256), ' verified · kept in the capture store']
      : rec && rec.status === 'expired' ? ['expired · the one-time link was not fetched within 15 minutes; fetch again for a fresh one']
      : rec ? ['not kept: ' + (rec.reason || 'the fetch failed') + '; fetch again']
      : ['sha256 is shown once fetched · a fresh one-time url per item, fetched once into the capture store'];
    var li = h('li', {}, [icon(k[0]), h('span', { class: 'txt' }, [h('span', {}, [k[1] + ' · ' + when + ' · ' + S.bytes(c.bytes)]), h('span', { class: 'sub' }, sub)])]);
    if (rec && rec.status === 'ready') li.appendChild(h('a', { class: 'btn text', href: '/captures/' + rec.id }, [icon('i-download'), 'Save']));
    else {
      var btn = h('button', { type: 'button', class: 'btn text', 'aria-label': 'Fetch ' + c.name }, ['Fetch']);
      btn.addEventListener('click', function () {
        if (btn.getAttribute('aria-disabled') === 'true') return;
        var done = S.busy(btn, 'fetching from amt-mcp');
        amtc.post('/api/call', { tool: 'amt_captures', arguments: { action: 'fetch', name: c.name } }).then(function (r) {
          var b = r.body || {}, got = b.structured && b.structured.capture;
          if (r.status === 200 && !b.isError && got) { c.capture = got; listBox.replaceChild(S.pastRow(c, listBox), li); return; }
          done();
          S.clear(li.querySelector('.sub'));
          li.querySelector('.sub').textContent = 'refused: ' + (r.status !== 200 ? (b.error || 'no answer') : b.isError ? b.text : 'no download was offered') + ' · nothing was fetched';
        });
      });
      li.appendChild(btn);
    }
    return li;
  };

  // ---- the console's own JSON routes ----
  S.get = function (path) {
    return fetch(path, { credentials: 'same-origin' }).then(function (r) {
      if (r.status === 401) { location.replace('/signin?expired=1'); return new Promise(function () {}); }
      return r.json().then(function (j) { return { status: r.status, body: j }; }, function () { return { status: r.status, body: {} }; });
    });
  };
  // A control that ignores activation while its call is out: aria-disabled, still focusable, with the reason as visible text (immutable 18).
  S.busy = function (btn, reason) {
    btn.setAttribute('aria-disabled', 'true');
    var why = h('span', { class: 'body-s muted reason' }, [reason]);
    if (btn.parentNode) btn.parentNode.insertBefore(why, btn.nextSibling);
    return function () { btn.removeAttribute('aria-disabled'); why.remove(); };
  };
  S.clear = function (el) { while (el.firstChild) el.removeChild(el.firstChild); };

  // ---- one instance's fields as a key/value list, the tool's own names and values (Inventory, AMT settings): text nodes only ----
  S.value = function (v) {
    if (v === null || v === undefined) return h('span', { class: 'muted' }, ['not reported']);
    if (typeof v === 'boolean') return v ? h('span', { class: 'chip small ok' }, [icon('i-check'), 'true']) : h('span', { class: 'chip small' }, ['false']);
    if (typeof v === 'number') return h('span', { class: 'data' }, [String(v)]);
    if (typeof v === 'string') return v === '' ? h('span', { class: 'muted' }, ['empty']) : h('span', {}, [v]);
    if (Array.isArray(v)) return h('span', { class: 'data' }, [v.map(function (x) { return x !== null && typeof x === 'object' ? JSON.stringify(x) : String(x); }).join(', ') || 'empty']);
    return h('span', { class: 'data' }, [JSON.stringify(v)]);
  };
  // A CIM name has no space to wrap at (SystemCreationClassName), so it may break before each word inside it; the text is unchanged.
  S.key = function (k) {
    var out = [];
    String(k).split(/(?=[A-Z][a-z])/).forEach(function (w, i) { if (i) out.push(h('wbr')); out.push(w); });
    return out;
  };
  S.instance = function (item, n, of) {
    var dl = h('dl', { class: 'kv' });
    Object.keys(item).forEach(function (k) { dl.appendChild(h('dt', {}, S.key(k))); dl.appendChild(h('dd', {}, [S.value(item[k])])); });
    if (!Object.keys(item).length) dl.appendChild(h('dd', {}, [h('span', { class: 'muted' }, ['no properties reported'])]));
    return h('div', { class: 'inst' }, (of > 1 ? [h('h3', { class: 'title-s muted' }, [n + ' of ' + of])] : []).concat([dl]));
  };

  // ---- the read pages (Logs, Inventory): a disabled control that says why, and the rows for a read that did not come back ----
  S.stamp = function () { return S.eastern(Date.now() / 1000, false); };
  // r = { btn, wrap, reason }: aria-disabled with the reason as visible text beside the control (immutable 18), or enabled again.
  S.setReason = function (r, reason) {
    if (reason) {
      r.btn.setAttribute('aria-disabled', 'true');
      if (!r.reason) { r.reason = h('span', { class: 'reason' }, [reason]); r.wrap.appendChild(r.reason); } else r.reason.textContent = reason;
    } else {
      r.btn.removeAttribute('aria-disabled');
      if (r.reason) { r.reason.remove(); r.reason = null; }
    }
  };
  // The console could not make the call, or amt-mcp did not answer (immutable 7): never reported as a refusal by the tool.
  S.readFailure = function (what, r) {
    var code = (r.body && r.body.error) || 'no answer', lead = h('strong', {}, [S.stamp() + ' · ' + what]);
    if (r.status === 502 || r.status === 0) return S.result('live', 'i-help', [lead, ' · amt-mcp did not answer (' + code + ') · the read may or may not have reached the host; nothing was changed']);
    return S.result('error', 'i-block', [lead, ' · refused: ' + code + ' · nothing sent']);
  };
  // A tool's refusal, verbatim, in the card of the read that was refused (immutable 7). A read changes nothing, and says so.
  S.readRefusal = function (what, text) {
    return S.result('error', 'i-block', [h('strong', {}, [S.stamp() + ' · ' + what]), ' · refused: ' + text + ' · read-only: nothing on the host was changed']);
  };
  // What a paused server's page says in place of reading: a refused credential gets no second attempt from here.
  S.pausedNote = function (noun, key, paused) {
    return ['Reading is paused for this server (' + ((paused && paused.reason) || 'refused') + '): ' + noun + ' is not read from here until it resumes. Retry once from the ',
      h('a', { href: '/server/' + key }, ['Status tab']), '.'];
  };
}());
