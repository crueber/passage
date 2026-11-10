// theme.js — per-browser theme preference for Passage.
//
// External file because the strict CSP (script-src 'self') blocks inline
// scripts. Loaded synchronously (NOT deferred) so a stored theme is applied to
// <html> before first paint, avoiding a flash of the server default.
//
// The picker is cosmetic and client-only: the server-rendered data-theme value
// from ui.theme remains authoritative whenever localStorage is empty or
// unavailable (private mode, disabled storage, JS disabled).
(function () {
  "use strict";

  var KEY = "passage.theme";
  var SLUG = /^[a-z0-9-]{1,32}$/;

  function readStored() {
    try {
      var value = window.localStorage.getItem(KEY);
      return value && SLUG.test(value) ? value : null;
    } catch (e) {
      return null; // Storage disabled or blocked — use the server default.
    }
  }

  function writeStored(value) {
    try {
      if (value) {
        window.localStorage.setItem(KEY, value);
      } else {
        window.localStorage.removeItem(KEY);
      }
    } catch (e) {
      // Private mode / quota errors: the preference simply does not persist.
    }
  }

  function apply(name) {
    if (name) {
      document.documentElement.dataset.theme = name;
    }
  }

  var stored = readStored();
  if (stored) apply(stored);

  function hasOption(select, value) {
    for (var i = 0; i < select.options.length; i++) {
      if (select.options[i].value === value) return true;
    }
    return false;
  }

  document.addEventListener("DOMContentLoaded", function () {
    var select = document.getElementById("theme-select");
    if (!select) return;

    var serverDefault = select.getAttribute("data-default") || "";
    var live = document.documentElement.getAttribute("data-theme") || serverDefault;

    // Empty value means "follow the server default".
    if (live === serverDefault || !hasOption(select, live)) {
      select.value = "";
    } else {
      select.value = live;
    }

    select.addEventListener("change", function () {
      var value = select.value;
      if (!value) {
        writeStored(null);
        apply(serverDefault);
        return;
      }
      writeStored(value);
      apply(value);
    });
  });
})();
