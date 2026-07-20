// Tab bar, shared by the workspace and subdomain pages. Kept out of table.js so the
// subdomain page can have tabs without pulling in the table/copy/module wiring too.
(function () {
  const tabWrap = document.querySelector('[data-tabs]');
  if (!tabWrap) return;

  tabWrap.addEventListener('click', (e) => {
    const btn = e.target.closest('.tab');
    if (!btn) return;
    // Resolve the pane BEFORE deactivating anything: if a tab ever loses its pane, the
    // old code threw here having already cleared every .active, leaving no pane visible
    // and every later click throwing too — the whole tab bar looking dead.
    const pane = document.querySelector(`[data-pane="${btn.dataset.tab}"]`);
    if (!pane) return;
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    document.querySelectorAll('.tabpane').forEach(p => p.classList.remove('active'));
    btn.classList.add('active');
    pane.classList.add('active');
  });

  if (location.hash) {
    const b = document.querySelector(`.tab[data-tab="${location.hash.slice(1)}"]`);
    if (b) b.click();
  }
  // Buttons elsewhere on the page that jump to a tab (e.g. Overview quick actions).
  document.querySelectorAll('.tab-jump').forEach(btn => {
    btn.addEventListener('click', () => {
      const t = document.querySelector(`.tab[data-tab="${btn.dataset.goto}"]`);
      if (t) t.click();
    });
  });
  // Come back to the tab you were on after a refresh (a #hash still wins).
  if (window.Thoth) window.Thoth.persistTab();
})();
