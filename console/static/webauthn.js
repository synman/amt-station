/* The browser half of the passkey ceremonies: base64url, and the two navigator.credentials calls.
   The server verifies everything; this only converts between JSON and the buffers the browser wants. */
(function () {
  'use strict';
  function b64u(buf) {
    var s = '', bytes = new Uint8Array(buf);
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  function unb64u(text) {
    var s = atob(text.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((text.length + 3) % 4));
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
    return out.buffer;
  }
  window.amtWebAuthn = {
    create: function (options, signal) {
      var pk = options.publicKey;
      pk.challenge = unb64u(pk.challenge); pk.user.id = unb64u(pk.user.id);
      pk.excludeCredentials = (pk.excludeCredentials || []).map(function (c) { return { type: c.type, id: unb64u(c.id) }; });
      return navigator.credentials.create({ publicKey: pk, signal: signal }).then(function (cred) {
        return { id: cred.id, clientDataJSON: b64u(cred.response.clientDataJSON), attestationObject: b64u(cred.response.attestationObject) };
      });
    },
    get: function (options, signal) {
      var pk = options.publicKey;
      pk.challenge = unb64u(pk.challenge);
      return navigator.credentials.get({ publicKey: pk, signal: signal }).then(function (cred) {
        var r = cred.response;
        return { id: cred.id, clientDataJSON: b64u(r.clientDataJSON), authenticatorData: b64u(r.authenticatorData), signature: b64u(r.signature) };
      });
    }
  };
}());
