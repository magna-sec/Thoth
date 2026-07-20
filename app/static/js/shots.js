// Screenshots tab: subdomain selection helpers + gallery filter.
(function () {
  const items = () => [...document.querySelectorAll('#shot-form .fz-item input[type=checkbox]')];
  const on = (id, fn) => { const b = document.getElementById(id); if (b) b.addEventListener('click', fn); };

  on('sh-all', () => items().forEach(c => (c.checked = true)));
  on('sh-clear', () => items().forEach(c => (c.checked = false)));
  on('sh-alive', () => items().forEach(c => {
    c.checked = c.closest('.fz-item').dataset.live === 'up';
  }));
  on('sh-missing', () => items().forEach(c => {
    c.checked = c.closest('.fz-item').dataset.shot === '0';
  }));

  // No selection is meaningful here: it means "every subdomain".
  const filter = document.getElementById('shot-filter');
  if (filter) {
    const apply = () => {
      const q = filter.value.trim().toLowerCase();
      document.querySelectorAll('#shot-grid .shot').forEach((fig) => {
        fig.hidden = q !== '' && !fig.dataset.host.toLowerCase().includes(q);
      });
    };
    filter.addEventListener('input', apply);
    window.Thoth.persist('shot-filter', [filter], apply);
  }
})();
