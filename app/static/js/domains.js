// Per-domain live checks: colour-code cards by response.
(function () {
  const meta = document.querySelector('meta[name=csrf-token]');
  const csrf = meta ? meta.content : '';

  function colour(card, code, alive, checkedAt, waf) {
    const live = alive ? 'up' : 'down';
    card.classList.remove('status-up', 'status-down', 'status-na');
    card.classList.add('status-' + live);
    card.dataset.live = live;
    card.dataset.code = code != null ? code : '';
    const badge = card.querySelector('.dc-status');
    if (badge) {
      badge.className = 'dc-status badge ' + (code ? 's' + Math.floor(code / 100) + 'xx' : 'dead');
      badge.textContent = code != null ? code : 'dead';
    }
    const chk = card.querySelector('.dc-checked');
    if (chk && checkedAt) chk.textContent = 'checked ' + checkedAt;
    const wafBox = card.querySelector('.dc-waf');
    if (wafBox) wafBox.innerHTML = waf ? `<span class="chip waf">🛡 ${waf}</span>` : '';
    applyFilters();
  }

  function esc(s) {
    const d = document.createElement('div'); d.textContent = s || ''; return d.innerHTML;
  }

  async function checkOne(card) {
    const tid = card.dataset.tid;
    card.classList.add('checking');
    try {
      const r = await fetch(`${window.THOTH.baseUrl}/domains/${tid}/check`, {
        method: 'POST', headers: { 'X-CSRFToken': csrf },
      });
      if (!r.ok) return;
      const d = await r.json();
      colour(card, d.status_code, d.alive, d.checked_at, d.waf);
      const srv = card.querySelector('.dc-server');
      if (srv) srv.innerHTML = d.server ? `<span class="dc-srv">${esc(d.server)}</span>` : '';
      const ttl = card.querySelector('.dc-title');
      if (ttl) ttl.textContent = d.title || '';
    } finally {
      card.classList.remove('checking');
    }
  }

  document.addEventListener('click', (e) => {
    const btn = e.target.closest('.check-one');
    if (btn) checkOne(btn.closest('.domain-card'));
  });

  // --- Filtering (host search + liveness + status bucket) ---
  const search = document.getElementById('domain-search');
  const fLive = document.getElementById('filter-live');
  const fStatus = document.getElementById('filter-status');
  const count = document.getElementById('domain-count');

  function applyFilters() {
    const q = (search && search.value || '').toLowerCase();
    const live = fLive && fLive.value;
    const status = fStatus && fStatus.value;
    let shown = 0;
    document.querySelectorAll('.domain-card').forEach(card => {
      const okHost = !q || (card.dataset.host || '').toLowerCase().includes(q);
      const okLive = !live || card.dataset.live === live;
      const okStatus = !status || (card.dataset.code || '').charAt(0) === status;
      const show = okHost && okLive && okStatus;
      card.style.display = show ? '' : 'none';
      if (show) shown++;
    });
    if (count) count.textContent = shown;
  }
  window.applyFilters = applyFilters;
  [search, fLive, fStatus].forEach(el => {
    if (el) el.addEventListener('input', applyFilters);
    if (el) el.addEventListener('change', applyFilters);
  });

  // "Check all live" is now a real alive run (see the form in detail.html) so it is
  // recorded as a run and feeds Analysis. Per-card "Check live" stays an instant probe.
})();
