// Run detail page: live-stream the verbose log + result count while the run is active,
// then reload once it finishes so the full results table renders.
(function () {
  const T = window.THOTH;
  if (!T || !T.runId) return;
  if (T.runStatus === 'done' || T.runStatus === 'error') return;  // static snapshot

  const logEl = document.getElementById('run-log');
  const countEl = document.getElementById('run-count');

  async function poll() {
    let d;
    try {
      d = await (await fetch(`${T.baseUrl}/runs/${T.runId}/status`)).json();
    } catch { setTimeout(poll, 2500); return; }

    if (logEl && d.log) { logEl.textContent = d.log; logEl.scrollTop = logEl.scrollHeight; }
    if (countEl) countEl.textContent = d.findings;

    const fill = document.getElementById('progress-fill');
    const ptext = document.getElementById('progress-text');
    if (fill) fill.style.width = d.progress_pct + '%';
    if (ptext) ptext.textContent = `${d.progress_done}/${d.progress_total} (${d.progress_pct}%)`;

    if (d.status === 'done' || d.status === 'error') {
      location.reload();  // render config + results table in final state
      return;
    }
    setTimeout(poll, 2000);
  }
  poll();
})();
