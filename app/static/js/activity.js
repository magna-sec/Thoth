// Run-activity indicator: shows a "running" banner while runs are in flight and
// auto-reloads the page when they all finish, so cards/stats/results refresh.
(function () {
  if (!window.THOTH || !window.THOTH.baseUrl) return;

  const banner = document.createElement('div');
  banner.id = 'run-banner';
  banner.hidden = true;
  banner.innerHTML = '<span class="spinner"></span> <span id="run-banner-text">Running…</span>';
  document.body.appendChild(banner);

  let sawActive = false;
  let timer = null;

  async function poll() {
    let d;
    try {
      d = await (await fetch(window.THOTH.baseUrl + '/activity')).json();
    } catch { schedule(4000); return; }

    if (d.active > 0) {
      sawActive = true;
      banner.hidden = false;
      const names = d.running.map(r => r.pct ? `${r.module} ${r.pct}%` : r.module).join(', ');
      document.getElementById('run-banner-text').textContent =
        `${d.active} task(s) in progress — ${names}`;
      schedule(1500);
    } else if (sawActive) {
      // Everything just finished — refresh so all views reflect final state.
      document.getElementById('run-banner-text').textContent = 'Done — refreshing…';
      location.reload();
    } else {
      banner.hidden = true;
      schedule(4000);
    }
  }
  function schedule(ms) { clearTimeout(timer); timer = setTimeout(poll, ms); }

  // Immediate feedback when a run button is clicked (before the redirect lands).
  document.addEventListener('submit', (e) => {
    const form = e.target;
    if (form.matches('#fuzz-form') || form.querySelector('[value="alive"], [value="dirsearch"]')
        || form.action.includes('/checkall')) {
      const btn = form.querySelector('button[type=submit]');
      if (btn) { btn.disabled = true; btn.dataset.orig = btn.textContent; btn.textContent = 'Starting…'; }
    }
  });

  poll();
})();
