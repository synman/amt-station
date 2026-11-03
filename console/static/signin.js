/* Sign-in, first-passkey enrollment and the five card states of design/sign-in.html. */
(function () {
  'use strict';
  var root = document.documentElement, abort = null;
  function show(state) { root.setAttribute('data-auth', state); }
  function post(path, body) {
    return fetch(path, { method: 'POST', headers: { 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json().then(function (j) { return { status: r.status, body: j }; }, function () { return { status: r.status, body: {} }; }); });
  }
  function fail(id, text) { var b = document.getElementById(id); b.querySelector('.txt').textContent = text; b.hidden = false; }
  function clearErrors() { document.querySelectorAll('.banner.error[data-error]').forEach(function (b) { b.hidden = true; }); }

  if (new URLSearchParams(location.search).get('expired') === '1') show('expired');
  document.querySelectorAll('[data-state-set]').forEach(function (b) {
    b.addEventListener('click', function (e) {
      if (b.tagName === 'A') e.preventDefault();
      if (abort) abort.abort();
      clearErrors(); show(b.getAttribute('data-state-set'));
    });
  });

  function signIn() {
    clearErrors(); show('waiting'); abort = new AbortController();
    post('/auth/signin/options').then(function (o) {
      if (o.status !== 200) throw new Error(o.body.error || 'sign_in_unavailable');
      return window.amtWebAuthn.get(o.body, abort.signal);
    }).then(function (assertion) { return post('/auth/signin/verify', assertion); }).then(function (v) {
      if (v.status === 200) { location.replace('/'); return; }
      if (v.body.error === 'passkey_not_enrolled') { show('refused'); return; }
      throw new Error(v.body.error || 'sign_in_refused');
    }).catch(function (err) {
      if (err && err.name === 'AbortError') return;
      show('signin'); fail('signin-error', err && err.name === 'NotAllowedError' ? 'The passkey prompt was dismissed. Nothing was sent to any host.' : 'Sign-in failed: ' + (err && err.message ? err.message : 'unknown') + '. Nothing was sent to any host.');
    });
  }
  document.querySelectorAll('[data-signin]').forEach(function (b) { b.addEventListener('click', signIn); });

  document.getElementById('enroll-go').addEventListener('click', function () {
    clearErrors();
    var code = Array.prototype.map.call(document.querySelectorAll('#enroll-code input'), function (i) { return i.value; }).join('');
    var name = document.getElementById('pkname').value;
    post('/auth/enroll/options', { code: code, name: name }).then(function (o) {
      if (o.status !== 200) throw new Error(o.body.error || 'enroll_unavailable');
      return window.amtWebAuthn.create(o.body);
    }).then(function (cred) { return post('/auth/enroll/verify', cred); }).then(function (v) {
      if (v.status !== 200) throw new Error(v.body.error || 'enroll_refused');
      location.replace('/');
    }).catch(function (err) {
      fail('enroll-error', 'Enrollment failed: ' + (err && err.name === 'NotAllowedError' ? 'the passkey prompt was dismissed' : (err && err.message) || 'unknown') + '.');
    });
  });
}());
