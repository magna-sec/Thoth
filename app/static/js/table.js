// Sortable/filterable tables, copy buttons, per-module config toggle, analysis bars.
// (Tabs live in tabs.js — the subdomain page needs those without the rest of this.)
(function () {
  // --- Module config toggle ---
  const modSel = document.getElementById('module-select');
  function syncMod() {
    document.querySelectorAll('.mod-config').forEach(c => {
      c.hidden = c.dataset.mod !== modSel.value;
    });
  }
  if (modSel) { modSel.addEventListener('change', syncMod); syncMod(); }

  // --- Copy buttons ---
  document.addEventListener('click', (e) => {
    const b = e.target.closest('.copy');
    if (!b) return;
    navigator.clipboard.writeText(b.dataset.copy).then(() => {
      b.textContent = '✓'; setTimeout(() => (b.textContent = '⧉'), 900);
    });
  });

  // Results filtering lives in results.js (multi-criteria). --- Sort ---
  document.querySelectorAll('table.sortable th[data-sort]').forEach((th, idx) => {
    th.addEventListener('click', () => {
      const tbody = th.closest('table').querySelector('tbody');
      const rows = [...tbody.rows];
      const asc = th.dataset.dir !== 'asc';
      th.dataset.dir = asc ? 'asc' : 'desc';
      rows.sort((a, b) => {
        const x = a.cells[idx].textContent.trim(), y = b.cells[idx].textContent.trim();
        const nx = parseFloat(x), ny = parseFloat(y);
        if (!isNaN(nx) && !isNaN(ny)) return asc ? nx - ny : ny - nx;
        return asc ? x.localeCompare(y) : y.localeCompare(x);
      });
      rows.forEach(r => tbody.appendChild(r));
    });
  });
  // Analysis is rendered server-side (see detail.html) so it's correct on load
  // and never blank after a run; it refreshes on the next page load.
})();
