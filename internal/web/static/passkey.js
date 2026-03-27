// passkey.js — WebAuthn passkey registration and login helpers.
// Requires the browser WebAuthn API (navigator.credentials).
// Gracefully degrades: buttons are hidden if WebAuthn is unsupported.

(function () {
  'use strict';

  // ── Utility ──────────────────────────────────────────────────────────────

  /** Convert a base64url string to a Uint8Array. */
  function base64urlToBytes(b64) {
    var padded = b64.replace(/-/g, '+').replace(/_/g, '/');
    while (padded.length % 4) padded += '=';
    var binary = atob(padded);
    var bytes = new Uint8Array(binary.length);
    for (var i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  /** Convert a Uint8Array (or ArrayBuffer) to a base64url string. */
  function bytesToBase64url(buf) {
    var bytes = new Uint8Array(buf);
    var binary = '';
    for (var i = 0; i < bytes.byteLength; i++) {
      binary += String.fromCharCode(bytes[i]);
    }
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  /**
   * Decode the base64url-encoded binary fields in a PublicKeyCredential
   * options object (creation or assertion) to Uint8Arrays, as required by
   * the WebAuthn browser API.
   *
   * Only the four field paths the WebAuthn spec defines as BufferSource are
   * decoded; everything else (including rp.id, which is a plain domain string)
   * is left untouched.
   */
  function preparePublicKeyOptions(opts) {
    if (opts.challenge) {
      opts.challenge = base64urlToBytes(opts.challenge);
    }
    if (opts.user && opts.user.id) {
      opts.user.id = base64urlToBytes(opts.user.id);
    }
    if (Array.isArray(opts.excludeCredentials)) {
      opts.excludeCredentials = opts.excludeCredentials.map(function (c) {
        return Object.assign({}, c, { id: base64urlToBytes(c.id) });
      });
    }
    if (Array.isArray(opts.allowCredentials)) {
      opts.allowCredentials = opts.allowCredentials.map(function (c) {
        return Object.assign({}, c, { id: base64urlToBytes(c.id) });
      });
    }
    return opts;
  }

  /**
   * Convert a PublicKeyCredential returned by navigator.credentials.create/get
   * to a plain JSON-serialisable object for posting to the server.
   */
  function credentialToJSON(cred) {
    var obj = {
      id: cred.id,
      rawId: bytesToBase64url(cred.rawId),
      type: cred.type,
      response: {}
    };

    var r = cred.response;
    if (r.attestationObject) {
      obj.response.attestationObject = bytesToBase64url(r.attestationObject);
    }
    if (r.clientDataJSON) {
      obj.response.clientDataJSON = bytesToBase64url(r.clientDataJSON);
    }
    if (r.authenticatorData) {
      obj.response.authenticatorData = bytesToBase64url(r.authenticatorData);
    }
    if (r.signature) {
      obj.response.signature = bytesToBase64url(r.signature);
    }
    if (r.userHandle) {
      obj.response.userHandle = bytesToBase64url(r.userHandle);
    }
    return obj;
  }

  // ── Registration ─────────────────────────────────────────────────────────

  function initRegistration() {
    var btn = document.getElementById('register-passkey-btn');
    if (!btn) return;

    if (!window.PublicKeyCredential) {
      btn.style.display = 'none';
      return;
    }

    var status = document.getElementById('passkey-register-status');

    btn.addEventListener('click', async function () {
      btn.disabled = true;
      if (status) status.textContent = 'Starting registration…';

      try {
        // 1. Fetch the creation options from the server.
        var beginResp = await fetch('/passkeys/register/begin', { credentials: 'same-origin' });
        if (!beginResp.ok) {
          var err = await beginResp.json();
          throw new Error(err.error || 'Failed to begin registration');
        }
        var optionsJSON = await beginResp.json();

        // 2. Convert base64url fields to ArrayBuffers.
        var publicKey = preparePublicKeyOptions(optionsJSON.publicKey || optionsJSON);

        // 3. Ask the authenticator to create a credential.
        var credential = await navigator.credentials.create({ publicKey: publicKey });

        // 4. Post the result to the server.
        var nameInput = document.getElementById('passkey-name');
        var nameVal = nameInput ? nameInput.value.trim() : '';
        var finishURL = '/passkeys/register/finish';
        if (nameVal) {
          finishURL += '?name=' + encodeURIComponent(nameVal);
        }
        var finishResp = await fetch(finishURL, {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(credentialToJSON(credential))
        });

        if (!finishResp.ok) {
          var ferr = await finishResp.json();
          throw new Error(ferr.error || 'Registration failed');
        }

        if (status) status.textContent = 'Passkey registered! Reloading…';
        window.location.reload();

      } catch (e) {
        if (status) status.textContent = 'Error: ' + e.message;
        btn.disabled = false;
      }
    });
  }

  // ── Login ─────────────────────────────────────────────────────────────────

  function initLogin() {
    var btn = document.getElementById('passkey-login-btn');
    if (!btn) return;

    if (!window.PublicKeyCredential) {
      btn.style.display = 'none';
      return;
    }

    var status = document.getElementById('passkey-login-status');

    btn.addEventListener('click', async function () {
      btn.disabled = true;
      if (status) status.textContent = 'Waiting for passkey…';

      try {
        // 1. Fetch the assertion options from the server.
        var beginResp = await fetch('/login/passkey/begin', { credentials: 'same-origin' });
        if (!beginResp.ok) {
          var err = await beginResp.json();
          throw new Error(err.error || 'Failed to begin login');
        }
        var optionsJSON = await beginResp.json();
        var publicKey = preparePublicKeyOptions(optionsJSON.publicKey || optionsJSON);

        // 2. Ask the authenticator to sign the challenge.
        var assertion = await navigator.credentials.get({ publicKey: publicKey });

        // 3. Post the signed assertion to the server.
        var finishResp = await fetch('/login/passkey/finish', {
          method: 'POST',
          credentials: 'same-origin',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(credentialToJSON(assertion))
        });

        if (!finishResp.ok) {
          var ferr = await finishResp.json();
          throw new Error(ferr.error || 'Login failed');
        }

        var result = await finishResp.json();
        window.location.href = result.redirect || '/';

      } catch (e) {
        if (status) status.textContent = 'Error: ' + e.message;
        btn.disabled = false;
      }
    });
  }

  // ── Boot ──────────────────────────────────────────────────────────────────

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', function () {
      initRegistration();
      initLogin();
    });
  } else {
    initRegistration();
    initLogin();
  }
}());
