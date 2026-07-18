// Theme + brightness, persisted in localStorage.
(function () {
  const root = document.documentElement;
  const sel = document.getElementById('theme-select');
  const bright = document.getElementById('brightness');

  const savedTheme = localStorage.getItem('thoth-theme') || 'dark';
  const savedBright = localStorage.getItem('thoth-brightness') || '100';
  root.setAttribute('data-theme', savedTheme);
  root.style.setProperty('--brightness', savedBright + '%');
  if (sel) sel.value = savedTheme;
  if (bright) bright.value = savedBright;

  if (sel) sel.addEventListener('change', () => {
    root.setAttribute('data-theme', sel.value);
    localStorage.setItem('thoth-theme', sel.value);
  });
  if (bright) bright.addEventListener('input', () => {
    root.style.setProperty('--brightness', bright.value + '%');
    localStorage.setItem('thoth-brightness', bright.value);
  });
})();
