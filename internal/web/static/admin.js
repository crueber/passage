/* admin.js — progressive enhancement for the admin navbar burger toggle */
(function () {
  var burger = document.querySelector('.navbar-burger[data-target="admin-navbar-menu"]');
  if (!burger) return;
  burger.addEventListener('click', function () {
    var target = document.getElementById(burger.dataset.target);
    var active = burger.classList.toggle('is-active');
    target.classList.toggle('is-active', active);
    burger.setAttribute('aria-expanded', String(active));
  });
}());
