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
});
