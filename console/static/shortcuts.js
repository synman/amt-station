/* Keyboard shortcuts (design note 5.5): g f fleet, g m manage, g c console and g p power (of the current server), / the filter, ? this list,
   Esc closes a sheet (components.js). Never active while focus is in a text field, a select or the embedded viewer (which takes every key while
   it controls), nor while a sheet is open; switched off in Settings (this browser). Every shortcut has an on-screen control: the rail and bottom
   bar links, the server's section tabs, the filter field itself, and the list button in Settings. */
(function () {
  'use strict';
  var amtc = window.amtc, KEY = 'amt-console-shortcuts', PAIR_MS = 1500, pending = 0, mem = null;
  var ROWS = [['g f', 'Fleet', 'Fleet in the navigation'], ['g m', 'Manage', 'Manage in the navigation'],
              ['g c', 'KVM of the server you are on', 'the KVM section of the server'], ['g p', 'Power and boot of the server you are on', 'the Power & boot section of the server'],
              ['/', 'Filter the fleet', 'the filter field on Fleet'], ['?', 'This list', 'Show the list in Settings'], ['Esc', 'Close the open sheet', 'Cancel on the sheet']];

  function on() { try { return localStorage.getItem(KEY) !== 'off'; } catch (e) { return mem !== 'off'; } }
  function set(v) { mem = v ? 'on' : 'off'; try { localStorage.setItem(KEY, mem); } catch (e) { /* storage blocked: mem keeps the choice for this page only */ } paint(v); }
  function paint(v) { document.querySelectorAll('[data-pref-shortcuts]').forEach(function (s) { s.setAttribute('aria-checked', String(v)); }); }

  function server() { var h = document.querySelector('.srvhead[data-server]'); return h ? h.getAttribute('data-server') : null; }
  function typing(t) {
    if (!t || !t.tagName) return false;
    var tag = t.tagName;
    return tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT' || tag === 'IFRAME' || t.isContentEditable || t.getAttribute('role') === 'textbox';
  }

  function list(opener, byKey) {
    var id = 'shortcuts-sheet', s = document.getElementById(id), h = amtc.h;
    if (!s) {
      var rows = ROWS.map(function (r) { return h('tr', {}, [h('th', { scope: 'row', class: 'data' }, [r[0]]), h('td', {}, [r[1]]), h('td', { class: 'muted' }, [r[2]])]); });
      s = h('div', { id: id, class: 'sheet', 'data-motion': 'sheet-open', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': id + '-t' }, [
        h('div', { class: 'handle', 'aria-hidden': 'true' }), h('h2', { id: id + '-t' }, ['Keyboard shortcuts']),
        h('p', { class: 'body-s muted' }, ['Never active while you type in a field or work in the console or serial view. Switch them off in Settings.']),
        h('table', { class: 'tbl' }, [h('thead', {}, [h('tr', {}, [h('th', { scope: 'col' }, ['Keys']), h('th', { scope: 'col' }, ['Does']), h('th', { scope: 'col' }, ['Also on screen'])])]), h('tbody', {}, rows)]),
        h('div', { class: 'acts' }, [h('button', { type: 'button', class: 'btn text', 'data-close': '', 'data-autofocus': '' }, ['Close'])])]);
      Array.prototype.forEach.call(s.querySelectorAll('tbody td, tbody th'), function (c, i) { c.setAttribute('data-l', ['Keys', 'Does', 'Also on screen'][i % 3]); });
      document.body.appendChild(s);
    }
    amtc.openSheet(id, { byKey: !!byKey, opener: opener });
  }

  document.addEventListener('keydown', function (e) {
    if (!on() || e.repeat || e.ctrlKey || e.metaKey || e.altKey || e.defaultPrevented) return;
    if (typing(e.target) || typing(document.activeElement) || document.querySelector('.sheet.open:not(.inline)')) return;
    var now = Date.now(), k = e.key, go = null;
    if (pending && now - pending < PAIR_MS) {
      pending = 0;
      var key = server();
      if (k === 'f') go = '/';
      else if (k === 'm') go = '/manage';
      else if (k === 'c' && key) go = '/server/' + key + '/console';
      else if (k === 'p' && key) go = '/server/' + key + '/power';
      if (go) { e.preventDefault(); location.assign(go); }
      return;
    }
    pending = 0;
    if (k === 'g') { pending = now; return; }
    if (k === '/') {
      var q = document.querySelector('[data-shortcut-filter]');
      if (q && q.offsetParent !== null) { e.preventDefault(); q.focus(); }
    } else if (k === '?') { e.preventDefault(); list(document.activeElement, true); }
  });

  document.querySelectorAll('[data-shortcuts-list]').forEach(function (b) { b.addEventListener('click', function () { list(b, false); }); });
  document.querySelectorAll('[data-pref-shortcuts]').forEach(function (s) {
    var flip = function () { set(s.getAttribute('aria-checked') !== 'true'); };
    s.addEventListener('click', flip);
    s.addEventListener('keydown', function (e) { if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); if (!e.repeat) flip(); } });
  });
  paint(on());
}());
