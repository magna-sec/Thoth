// Full-response viewer modal. Fetches a URL on demand (through the workspace proxy).
(function () {
  const modal = document.getElementById('resp-modal');
  if (!modal) return;
  const titleEl = document.getElementById('resp-title');
  const headersEl = document.getElementById('resp-headers');
  const bodyEl = document.getElementById('resp-body');
  const metaEl = document.getElementById('resp-meta');

  function open() { modal.hidden = false; }
  function close() { modal.hidden = true; }
  document.getElementById('resp-close').addEventListener('click', close);
  modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape') close(); });

  document.addEventListener('click', async (e) => {
    const btn = e.target.closest('.resp-btn');
    if (!btn) return;
    const tid = btn.dataset.tid, path = btn.dataset.path || '/';
    titleEl.textContent = 'Loading ' + path + ' …';
    headersEl.textContent = ''; bodyEl.textContent = ''; metaEl.textContent = '';
    open();
    try {
      const u = `${window.THOTH.baseUrl}/response?target_id=${encodeURIComponent(tid)}&path=${encodeURIComponent(path)}`;
      const d = await (await fetch(u)).json();
      if (d.error) { titleEl.textContent = d.url; bodyEl.textContent = d.error; return; }
      titleEl.textContent = `${d.status} ${d.reason}  ·  ${d.url}`;
      headersEl.textContent = Object.entries(d.headers).map(([k, v]) => `${k}: ${v}`).join('\n');
      bodyEl.textContent = d.body || '(empty)';
      metaEl.textContent = `${d.length} bytes` + (d.truncated ? ' · truncated to 200KB' : '');
    } catch (err) {
      titleEl.textContent = 'Request failed';
      bodyEl.textContent = String(err);
    }
  });
})();
