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
