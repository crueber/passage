// app.js — progressive enhancement for Passage pages, kept external so the
// strict CSP (script-src 'self') allows it. Templates mark interactive
// elements with data- attributes; this file wires them via delegation.
(function () {
  "use strict";

  // [data-copy="<selector>"]: copy the target element's text to the clipboard.
  document.addEventListener("click", function (e) {
    var btn = e.target.closest("[data-copy]");
    if (!btn) return;
    var target = document.querySelector(btn.getAttribute("data-copy"));
    if (!target) return;
    var done = function () {
      var original = btn.textContent;
      btn.textContent = "Copied!";
      setTimeout(function () { btn.textContent = original; }, 1500);
    };
    if (navigator.clipboard && navigator.clipboard.writeText) {
      navigator.clipboard.writeText(target.textContent).then(done, done);
    } else {
      done();
    }
  });

  // [data-confirm="<message>"]: ask before submitting the owning form.
  document.addEventListener("submit", function (e) {
    var el = e.target.querySelector("[data-confirm]");
    if (el && !window.confirm(el.getAttribute("data-confirm"))) {
      e.preventDefault();
    }
  });

  // View switch (dashboard): Comfortable vs Iconized. The server renders the
  // effective mode from the browser cookie -> account default -> Comfortable.
  // Clicking a switch option updates the attribute and cookie in place; without
  // JavaScript the same links hit GetDashboard, which sets the cookie and
  // redirects.
  var viewOptions = document.querySelectorAll("[data-view-option]");
  if (viewOptions.length) {
    var applyView = function (mode) {
      document.body.setAttribute("data-app-view", mode);
      Array.prototype.forEach.call(viewOptions, function (option) {
        var active = option.getAttribute("data-view-option") === mode;
        option.classList.toggle("is-active", active);
        if (active) option.setAttribute("aria-current", "page");
        else option.removeAttribute("aria-current");
      });
      var secure = window.location.protocol === "https:" ? "; secure" : "";
      document.cookie =
        "passage_app_view=" + mode + "; path=/; max-age=31536000; samesite=lax" + secure;
    };
    // Preserve the old per-browser density choice from before this redesign.
    // If there is no new cookie yet, map standard/condensed to comfortable/
    // iconized, apply it, and drop the old key so clearing the cookie falls back
    // to the account default rather than resurrecting the old value.
    if (!/(^|;\s*)passage_app_view=/.test(document.cookie)) {
      var legacyDensity = null;
      try {
        legacyDensity = window.localStorage.getItem("passage.density");
      } catch (err) {
        legacyDensity = null;
      }
      if (legacyDensity === "condensed" || legacyDensity === "standard") {
        applyView(legacyDensity === "condensed" ? "iconized" : "comfortable");
        try {
          window.localStorage.removeItem("passage.density");
        } catch (err) {
          /* storage unavailable: the cookie is still set */
        }
      }
    }

    Array.prototype.forEach.call(viewOptions, function (option) {
      option.addEventListener("click", function (e) {
        var mode = option.getAttribute("data-view-option");
        if (mode !== "comfortable" && mode !== "iconized") return;
        e.preventDefault();
        applyView(mode);
      });
    });
  }

  // Command launcher (dashboard): Ctrl/Cmd+K on desktop, floating button on
  // mobile. The result rows are rendered server-side so type-ahead only filters
  // existing links; no JSON or extra request is involved.
  var commandLayer = document.getElementById("command-layer");
  if (commandLayer) {
    var commandInput = document.getElementById("command-input");
    var commandEmpty = document.getElementById("command-empty");
    var commandOpen = document.getElementById("command-open");
    var commandItems = Array.prototype.slice.call(
      commandLayer.querySelectorAll(".command-item")
    );
    var selectedItem = null;
    var lastFocus = null;

    var visibleItems = function () {
      return commandItems.filter(function (item) {
        return !item.hidden;
      });
    };

    var selectItem = function (item) {
      Array.prototype.forEach.call(commandItems, function (candidate) {
        candidate.classList.remove("is-selected");
        candidate.setAttribute("aria-selected", "false");
      });
      selectedItem = item || null;
      if (!selectedItem) {
        commandInput.removeAttribute("aria-activedescendant");
        return;
      }
      selectedItem.classList.add("is-selected");
      selectedItem.setAttribute("aria-selected", "true");
      commandInput.setAttribute("aria-activedescendant", selectedItem.id);
      selectedItem.scrollIntoView({ block: "nearest" });
    };

    var filterCommand = function () {
      var query = commandInput.value.trim().toLowerCase();
      var terms = query ? query.split(/\s+/) : [];
      commandItems.forEach(function (item) {
        var haystack = item.getAttribute("data-search") || "";
        var match = terms.every(function (term) {
          return haystack.indexOf(term) !== -1;
        });
        item.hidden = !match;
        item.setAttribute("aria-selected", "false");
        item.classList.remove("is-selected");
      });
      var visible = visibleItems();
      commandEmpty.hidden = visible.length > 0;
      commandInput.setAttribute("aria-expanded", visible.length > 0 ? "true" : "false");
      selectItem(visible.length ? visible[0] : null);
    };

    var openCommand = function () {
      lastFocus = document.activeElement;
      commandLayer.hidden = false;
      document.body.style.overflow = "hidden";
      commandInput.value = "";
      filterCommand();
      commandInput.focus();
    };

    var closeCommand = function () {
      commandLayer.hidden = true;
      document.body.style.overflow = "";
      if (lastFocus && typeof lastFocus.focus === "function") lastFocus.focus();
    };

    var moveSelection = function (delta) {
      var visible = visibleItems();
      if (!visible.length) return;
      var index = visible.indexOf(selectedItem);
      if (index === -1) index = delta > 0 ? -1 : 0;
      selectItem(visible[(index + delta + visible.length) % visible.length]);
    };

    commandInput.addEventListener("input", filterCommand);
    commandInput.addEventListener("keydown", function (e) {
      if (e.key === "ArrowDown") {
        e.preventDefault();
        moveSelection(1);
      } else if (e.key === "ArrowUp") {
        e.preventDefault();
        moveSelection(-1);
      } else if (e.key === "Enter") {
        if (!selectedItem) return;
        e.preventDefault();
        selectedItem.click();
      }
    });

    commandLayer.addEventListener("keydown", function (e) {
      if (e.key !== "Tab") return;
      var focusables = [commandInput].concat(visibleItems());
      var first = focusables[0];
      var last = focusables[focusables.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    });

    Array.prototype.forEach.call(
      commandLayer.querySelectorAll("[data-command-close]"),
      function (el) {
        el.addEventListener("click", closeCommand);
      }
    );
    if (commandOpen) commandOpen.addEventListener("click", openCommand);

    document.addEventListener("keydown", function (e) {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        if (commandLayer.hidden) openCommand();
        else commandInput.focus();
        return;
      }
      if (!commandLayer.hidden && e.key === "Escape") {
        e.preventDefault();
        closeCommand();
      }
    });
  }

  // #select-all-btn (user manage-access page): toggle every app_id checkbox.
  var selectAll = document.getElementById("select-all-btn");
  if (selectAll) {
    var boxes = function () {
      return Array.prototype.slice.call(document.querySelectorAll('input[name="app_id"]'));
    };
    var allChecked = function (list) {
      return list.length > 0 && list.every(function (cb) { return cb.checked; });
    };
    var updateLabel = function () {
      selectAll.textContent = allChecked(boxes()) ? "Deselect All" : "Select All";
    };
    selectAll.addEventListener("click", function () {
      var check = !allChecked(boxes());
      boxes().forEach(function (cb) { cb.checked = check; });
      updateLabel();
    });
    updateLabel();
  }
})();
