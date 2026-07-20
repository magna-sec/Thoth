// Domain detail page: path filter, copy buttons, standalone live check.
(function () {
  const meta = document.querySelector('meta[name=csrf-token]');
  const csrf = meta ? meta.content : '';

  // Copy buttons
  document.addEventListener('click', (e) => {
    const b = e.target.closest('.copy');
    if (!b) return;
    navigator.clipboard.writeText(b.dataset.copy).then(() => {
      const t = b.textContent; b.textContent = '✓';
      setTimeout(() => (b.textContent = t), 900);
    });
  });

  // Filter page groups by the paths they contain
  const pf = document.getElementById('page-filter');
  if (pf) {
    const applyPathFilter = () => {
      const q = pf.value.toLowerCase();
      document.querySelectorAll('#page-groups .group-row').forEach(tr => {
        const hay = (tr.dataset.paths || '').toLowerCase();
        tr.style.display = hay.includes(q) ? '' : 'none';
      });
    };
    pf.addEventListener('input', applyPathFilter);
    window.Thoth.persist('page-filter', [pf], applyPathFilter,
                         document.getElementById('pg-reset'));
  }

  // Filter the interesting-URLs table (path, params and labels all searchable)
  const uf = document.getElementById('url-filter');
  if (uf) {
    const applyUrlFilter = () => {
      const q = uf.value.trim().toLowerCase();
      document.querySelectorAll('#url-rows tr[data-url]').forEach(tr => {
        tr.style.display = !q || tr.textContent.toLowerCase().includes(q) ? '' : 'none';
      });
    };
    uf.addEventListener('input', applyUrlFilter);
    window.Thoth.persist('url-filter', [uf], applyUrlFilter);
  }

  // Site tree: bulk expand/collapse
  const setTree = (open) => document.querySelectorAll('.tree-dir')
    .forEach(d => { d.open = open; });
  document.getElementById('tree-expand')?.addEventListener('click', () => setTree(true));
  document.getElementById('tree-collapse')?.addEventListener('click', () => setTree(false));

  // Standalone "Check live" on the header
  const btn = document.querySelector('.check-one[data-standalone]');
  if (btn) btn.addEventListener('click', async () => {
    btn.disabled = true;
    const label = btn.textContent; btn.textContent = 'Checking…';
    try {
      const r = await fetch(btn.dataset.checkUrl, {
        method: 'POST', headers: { 'X-CSRFToken': csrf },
      });
      const d = await r.json();
      const badge = document.querySelector('.page-head .badge');
      if (badge) {
        badge.className = 'badge ' + (d.status_code ? 's' + Math.floor(d.status_code / 100) + 'xx' : 'dead');
        badge.textContent = d.status_code != null ? d.status_code : 'dead';
      }
    } finally {
      btn.disabled = false; btn.textContent = label;
    }
  });
})();
