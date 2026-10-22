/* Settings: list the enrolled passkeys and add one from this signed-in session. */
(function () {
  'use strict';
  var amtc = window.amtc, list = document.getElementById('passkey-list');
  if (!list) return;
  var result = document.getElementById('passkey-result');

  function when(epoch) { return epoch ? new Date(epoch * 1000).toLocaleString() : 'never'; }
  function render(passkeys) {
    list.textContent = '';
    passkeys.forEach(function (p) {
      var li = amtc.h('li', {}, [amtc.icon('i-fingerprint'), amtc.h('span', { class: 'txt' }, [
        amtc.h('span', {}, [p.name]), amtc.h('span', { class: 'sub' }, ['enrolled ' + when(p.created) + ' · last used ' + when(p.last_used)])])]);
      list.appendChild(li);
    });
  }
  function load() { return fetch('/api/passkeys', { credentials: 'same-origin' }).then(function (r) { return r.json(); }).then(function (j) { render(j.passkeys); }); }
  function say(ok, text) {
    result.hidden = false; result.className = 'result ' + (ok ? 'ok' : 'error');
    result.querySelector('span').textContent = text;
  }

  var go = document.getElementById('pk-add-go');
  go.addEventListener('keydown', function (e) { if (e.repeat) { e.preventDefault(); e.stopImmediatePropagation(); } });
  go.addEventListener('click', function () {
    var name = document.getElementById('pkn').value;
    amtc.closeSheets();
    amtc.ready.then(function () { return amtc.post('/api/passkeys/options', { name: name }); }).then(function (o) {
      if (o.status !== 200) throw new Error(o.body.error || 'unavailable');
      return window.amtWebAuthn.create(o.body);
    }).then(function (cred) { return amtc.post('/api/passkeys/verify', cred); }).then(function (v) {
      if (v.status !== 200) throw new Error(v.body.error || 'refused');
      say(true, 'Passkey added: ' + v.body.passkey.name + '.'); return load();
    }).catch(function (err) { say(false, 'Passkey not added: ' + (err && err.name === 'NotAllowedError' ? 'the prompt was dismissed' : (err && err.message) || 'unknown') + '.'); });
  });
  load();
}());
