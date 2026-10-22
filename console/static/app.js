/* The app shell: the theme override, the session (CSRF token for this page) and sign-out. */
(function () {
  'use strict';
  var root = document.documentElement, amtc = window.amtc;
  var THEMES = ['system', 'light', 'dark'];
  var LABELS = { system: 'Theme: follows the system', light: 'Theme: light', dark: 'Theme: dark' };

  function saved() { try { return localStorage.getItem('amt-console-theme') || 'system'; } catch (e) { return 'system'; } }
  function setTheme(v) {
    if (v === 'system') root.removeAttribute('data-theme'); else root.setAttribute('data-theme', v);
    try { localStorage.setItem('amt-console-theme', v); } catch (e) { /* storage blocked: applies for this page only */ }
    document.querySelectorAll('[data-theme-set]').forEach(function (b) { b.setAttribute('aria-pressed', String(b.getAttribute('data-theme-set') === v)); });
    var t = document.getElementById('theme-toggle');
    if (t) { t.setAttribute('aria-label', LABELS[v]); t.setAttribute('title', LABELS[v]); t.setAttribute('data-theme-now', v); }
  }
  document.querySelectorAll('[data-theme-set]').forEach(function (b) { b.addEventListener('click', function () { setTheme(b.getAttribute('data-theme-set')); }); });
  var toggle = document.getElementById('theme-toggle');
  if (toggle) toggle.addEventListener('click', function () { setTheme(THEMES[(THEMES.indexOf(saved()) + 1) % THEMES.length]); });
  setTheme(saved());

  // The session: a 401 means signed out (or idled out); the CSRF token for every state-changing call comes from here.
  amtc.ready = fetch('/api/session', { credentials: 'same-origin' }).then(function (r) {
    if (r.status === 401) { location.replace('/signin?expired=1'); return new Promise(function () {}); }
    return r.json();
  }).then(function (j) { amtc.csrf = j.csrf; });

  function signOut() { amtc.ready.then(function () { return amtc.post('/auth/signout'); }).then(function () { location.replace('/signin'); }); }
  document.querySelectorAll('[data-signout]').forEach(function (b) { b.addEventListener('click', signOut); });
}());
