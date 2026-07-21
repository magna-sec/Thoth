// Bulk actions on the Subdomains tab. Cards carry a .dc-check box; the bar gathers the
// checked ids and either POSTs them to runs.start (as a module run over target_ids) or
// scopes the nuclei import to them.
(function () {
  const bar = document.getElementById('bulk-bar');
  if (!bar) return;
  const meta = document.querySelector('meta[name=csrf-token]');
  const csrf = meta ? meta.content : '';
  const runUrl = bar.dataset.runUrl;
  const wsId = bar.dataset.ws;

  const boxes = () => [...document.querySelectorAll('.dc-check')];
  const checked = () => boxes().filter(b => b.checked);
  const visible = () => boxes().filter(b => {
    const card = b.closest('.domain-card');
    return card && card.style.display !== 'none';
  });

  const countEl = document.getElementById('bulk-count');
  const actions = document.getElementById('bulk-actions');
  const scopeNote = document.getElementById('nuclei-scope');

  function refresh() {
    const n = checked().length;
    if (countEl) countEl.textContent = `${n} selected`;
    if (actions) actions.hidden = n === 0;
    boxes().forEach(b => b.closest('.domain-card')?.classList.toggle('selected', b.checked));
    if (scopeNote) {
      scopeNote.textContent = n
        ? `restricting to ${n} selected subdomain${n === 1 ? '' : 's'}`
        : 'matching across all subdomains';
    }
  }

  const on = (id, fn) => { const el = document.getElementById(id); if (el) el.addEventListener('click', fn); };

  document.addEventListener('change', (e) => { if (e.target.classList.contains('dc-check')) refresh(); });
  on('bulk-clear', () => { boxes().forEach(b => (b.checked = false)); refresh(); });
  on('bulk-alive-sel', () => {
    boxes().forEach(b => (b.checked = b.closest('.domain-card')?.dataset.live === 'up'));
    refresh();
  });
  on('bulk-iis-sel', () => {
    boxes().forEach(b => (b.checked = b.closest('.domain-card')?.dataset.iis === '1'));
    refresh();
  });
  const allVisible = document.getElementById('bulk-all-visible');
  if (allVisible) allVisible.addEventListener('change', () => {
    visible().forEach(b => (b.checked = allVisible.checked));
    refresh();
  });

  // Run a module over the checked hosts by building and submitting a form to runs.start.
  function runModule(module, force) {
    const ids = checked().map(b => b.value);
    if (!ids.length) return;
    if (module === 'dirsearch' && !confirm(`Fuzz ${ids.length} subdomain(s)?`)) return;
    const form = document.createElement('form');
    form.method = 'post';
    form.action = runUrl;
    const add = (name, value) => {
      const i = document.createElement('input');
      i.type = 'hidden'; i.name = name; i.value = value; form.appendChild(i);
    };
    add('csrf_token', csrf);
    add('workspace_id', wsId);
    add('module', module);
    if (force) { add('cfg__bools', 'force'); add('cfg_force', 'on'); }
    ids.forEach(id => add('target_ids', id));
    document.body.appendChild(form);
    form.submit();
  }

  bar.querySelectorAll('[data-bulk-module]').forEach(btn => {
    btn.addEventListener('click', () => runModule(btn.dataset.bulkModule, btn.dataset.bulkForce));
  });

  // "Nuclei import" jumps to the import card, carrying the selection as its scope.
  on('bulk-nuclei', () => {
    document.getElementById('nuclei')?.scrollIntoView({ behavior: 'smooth' });
    document.querySelector('#nuclei textarea')?.focus();
  });

  // Copy the current selection into the nuclei form as it submits.
  const nucleiForm = document.getElementById('nuclei-form');
  if (nucleiForm) nucleiForm.addEventListener('submit', () => {
    nucleiForm.querySelectorAll('input[name=target_ids]').forEach(i => i.remove());
    checked().forEach(b => {
      const i = document.createElement('input');
      i.type = 'hidden'; i.name = 'target_ids'; i.value = b.value;
      nucleiForm.appendChild(i);
    });
  });

  refresh();
})();
