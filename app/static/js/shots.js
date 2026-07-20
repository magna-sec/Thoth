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
  const kind = document.getElementById('shot-default');
  if (filter || kind) {
    const apply = () => {
      const q = (filter?.value || '').trim().toLowerCase();
      const want = kind?.value || '';
      let shown = 0;
      document.querySelectorAll('#shot-grid .shot').forEach((fig) => {
        // data-text covers host, page title and the default-page label, so you can
        // search "IIS" and find every server splash page.
        const okText = !q || (fig.dataset.text || '').toLowerCase().includes(q);
        const isDefault = fig.dataset.default === '1';
        const okKind = !want || (want === 'default' ? isDefault : !isDefault);
        fig.hidden = !(okText && okKind);
        if (!fig.hidden) shown++;
      });
      const count = document.getElementById('shot-count');
      if (count) count.textContent = shown;
    };
    [filter, kind].forEach(el => el?.addEventListener('input', apply));
    kind?.addEventListener('change', apply);
    window.Thoth.persist('shot-filter', [filter, kind], apply,
                         document.getElementById('sh-reset'));
  }
})();
