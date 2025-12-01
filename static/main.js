// Small UI helpers: fade-in and delete confirmation
document.addEventListener('DOMContentLoaded', function () {
  // Animate content container
  const container = document.querySelector('.container');
  if (container) container.classList.add('animate__animated', 'animate__fadeInUp');

  // Confirm deletes
  document.querySelectorAll('form.delete-form').forEach(function (form) {
    form.addEventListener('submit', function (e) {
      const ok = confirm('Delete this employee? This action cannot be undone.');
      if (!ok) e.preventDefault();
    });
  });

  // Theme handling: three color themes (blue, green, dark)
  function applyTheme(name) {
    document.body.classList.remove('theme-blue', 'theme-green', 'theme-dark');
    const cls = 'theme-' + name;
    document.body.classList.add(cls);
    // mark active button
    document.querySelectorAll('.btn-theme').forEach(b => b.classList.remove('active'));
    const active = document.querySelector('.btn-theme[data-theme="' + name + '"]');
    if (active) active.classList.add('active');
  }

  // load saved theme
  const saved = localStorage.getItem('site-theme') || 'blue';
  applyTheme(saved);

  // theme button listeners
  document.querySelectorAll('.btn-theme').forEach(function (btn) {
    btn.addEventListener('click', function () {
      const t = btn.getAttribute('data-theme');
      if (!t) return;
      applyTheme(t);
      localStorage.setItem('site-theme', t);
    });
  });
});
