// Directory Fuzzing tab: subdomain selection helpers + live console.
(function () {
  const items = () => [...document.querySelectorAll('.fz-item input[type=checkbox]')];
  const on = (id, fn) => { const b = document.getElementById(id); if (b) b.addEventListener('click', fn); };

  on('fz-all', () => items().forEach(c => (c.checked = true)));
  on('fz-clear', () => items().forEach(c => (c.checked = false)));
  on('fz-alive', () => items().forEach(c => {
    c.checked = c.closest('.fz-item').dataset.live === 'up';
  }));

  // Require at least one target before submitting.
  const form = document.getElementById('fuzz-form');
  if (form) form.addEventListener('submit', (e) => {
    if (!items().some(c => c.checked)) {
      e.preventDefault();
      alert('Select at least one subdomain to fuzz.');
    }
  });

  // Live console — fed by stream.js via a global hook.
  const consoleEl = document.getElementById('fuzz-console');
  let cleared = false;
  window.fuzzLog = function (line) {
    if (!consoleEl) return;
    if (!cleared) { consoleEl.textContent = ''; cleared = true; }
    consoleEl.textContent += line + '\n';
    consoleEl.scrollTop = consoleEl.scrollHeight;
  };
})();
