// Results tab: multi-criteria filtering (text, host, status bucket, exclude status,
// exclude size, WAF, hide 3xx, hide dead).
(function () {
  const body = document.getElementById('findings-body');
  if (!body) return;
  const q = document.getElementById('finding-filter');
  const host = document.getElementById('rf-host');
  const status = document.getElementById('rf-status');
  const exStatus = document.getElementById('rf-exstatus');
  const exSize = document.getElementById('rf-exsize');
  const waf = document.getElementById('rf-waf');
  const hideRedir = document.getElementById('rf-hideredir');
  const hideDead = document.getElementById('rf-hidedead');
  const count = document.getElementById('results-count');

  function nums(str) {
    return new Set((str || '').split(',').map(s => s.trim()).filter(Boolean));
  }

  // Populate the host dropdown from whatever hosts are present.
  function refreshHosts() {
    if (!host) return;
    const seen = new Set([...host.options].map(o => o.value));
    document.querySelectorAll('#findings-body tr').forEach(tr => {
      const h = tr.dataset.host;
      if (h && !seen.has(h)) {
        seen.add(h);
        const o = document.createElement('option'); o.value = o.textContent = h;
        host.appendChild(o);
      }
    });
  }

  function apply() {
    const text = (q && q.value || '').toLowerCase();
    const h = host && host.value;
    const s = status && status.value;
    const exS = nums(exStatus && exStatus.value);
    const exZ = nums(exSize && exSize.value);
    const w = waf && waf.value;
    const hr = hideRedir && hideRedir.checked;
    const hd = hideDead && hideDead.checked;
    let shown = 0, total = 0;
    document.querySelectorAll('#findings-body tr').forEach(tr => {
      if (!tr.dataset.host && tr.children.length < 3) return;  // skip "empty" row
      total++;
      const d = tr.dataset;
      const code = d.code || '';
      const dead = d.dead === '1';
      const ok =
        (!text || (d.host || '').toLowerCase().includes(text) || (d.path || '').toLowerCase().includes(text)) &&
        (!h || d.host === h) &&
        (!s || code.charAt(0) === s) &&
        (!exS.size || !exS.has(code)) &&
        (!exZ.size || !exZ.has(d.len || '')) &&
        (!w || (d.waf || '0') === w) &&
        (!hr || code.charAt(0) !== '3') &&
        (!hd || !dead);
      tr.style.display = ok ? '' : 'none';
      if (ok) shown++;
    });
    if (count) count.textContent = total ? `${shown}/${total}` : '';
  }

  window.applyResultsFilter = function () { refreshHosts(); apply(); };
  [q, host, status, exStatus, exSize, waf, hideRedir, hideDead].forEach(el => {
    if (!el) return;
    el.addEventListener('input', apply);
    el.addEventListener('change', apply);
  });
  refreshHosts();
  apply();
})();
