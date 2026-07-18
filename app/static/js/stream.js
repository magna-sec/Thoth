// Live findings via SSE. Appends rows, bumps stats, updates run status.
(function () {
  if (!window.THOTH || !window.THOTH.streamUrl) return;
  const body = document.getElementById('findings-body');

  // Resume from the highest finding id already rendered (DB-poll fallback needs it).
  let maxId = 0;
  document.querySelectorAll('#findings-body tr[data-fid]').forEach(tr => {
    maxId = Math.max(maxId, parseInt(tr.dataset.fid, 10) || 0);
  });

  const url = window.THOTH.streamUrl + '?last_id=' + maxId;
  const es = new EventSource(url);

  es.onmessage = (e) => {
    let msg;
    try { msg = JSON.parse(e.data); } catch { return; }
    if (msg.type === 'finding') addFinding(msg.finding);
    else if (msg.type === 'run_status') {
      updateRun(msg.run_id, msg.status);
      if (window.fuzzLog) window.fuzzLog(`— run #${msg.run_id} ${msg.status} —`);
    } else if (msg.type === 'log') {
      if (window.fuzzLog) window.fuzzLog(msg.msg);
    }
  };

  function badge(code) {
    if (code == null) return '<span class="badge dead">dead</span>';
    return `<span class="badge s${Math.floor(code / 100)}xx">${code}</span>`;
  }

  function esc(s) { const d = document.createElement('div'); d.textContent = s == null ? '' : s; return d.innerHTML; }

  function addFinding(f) {
    if (f.id && f.id <= maxId) return;
    if (f.id) maxId = f.id;
    const extra = f.extra || {};
    const copyUrl = (f.base_url || '') + (f.path || '');
    const tr = document.createElement('tr');
    tr.className = 'new-row';
    tr.dataset.fid = f.id || '';
    tr.dataset.host = f.host || '';
    tr.dataset.path = f.path || '';
    tr.dataset.code = f.status_code != null ? f.status_code : '';
    tr.dataset.dead = f.status_code == null ? '1' : '0';
    tr.dataset.waf = f.waf ? '1' : '0';
    tr.dataset.len = f.content_length != null ? f.content_length : '';
    tr.dataset.tid = f.target_id || '';
    const hostCell = f.target_id
      ? `<a href="${window.THOTH.baseUrl}/domains/${f.target_id}">${esc(f.host)}</a>`
      : esc(f.host);
    const fullUrl = (f.base_url || '') + (f.path || '');
    tr.innerHTML =
      `<td class="sensitive">${hostCell}</td>` +
      `<td class="sensitive mono"><a href="${esc(fullUrl)}" target="_blank" rel="noopener">${esc(f.path)}</a></td>` +
      `<td>${badge(f.status_code)}</td>` +
      `<td class="mono">${f.content_length ?? ''}</td>` +
      `<td class="muted">${esc(extra.server)}</td>` +
      `<td class="muted sensitive">${esc(extra.title)}</td>` +
      `<td class="row-actions"><button class="btn small resp-btn" data-tid="${f.target_id || ''}" data-path="${esc(f.path)}">Response</button>` +
      `<button class="copy" data-copy="${esc(copyUrl)}">⧉</button></td>`;
    body.insertBefore(tr, body.firstChild);
    bumpStat('stat-findings');
    if (extra.alive) bumpStat('stat-alive');
    if (window.applyResultsFilter) applyResultsFilter();
    // Live-recolour the matching subdomain card from an alive-module finding.
    if (extra.alive !== undefined) recolourCard(f);
    // Mirror dirsearch hits into the fuzz console.
    if (window.fuzzLog && extra.module === 'dirsearch') {
      window.fuzzLog(`  [${f.status_code}] ${f.host}${f.path}  (${f.content_length ?? '?'}b)`);
    }
  }

  function bumpStat(id) {
    const el = document.getElementById(id);
    if (el) el.textContent = (parseInt(el.textContent, 10) || 0) + 1;
  }

  function recolourCard(f) {
    const card = document.querySelector(`.domain-card[data-tid="${f.target_id}"]`);
    if (!card) return;
    const extra = f.extra || {};
    const live = f.status_code != null ? 'up' : 'down';
    card.classList.remove('status-up', 'status-down', 'status-na');
    card.classList.add('status-' + live);
    card.dataset.live = live;
    card.dataset.code = f.status_code != null ? f.status_code : '';
    const b = card.querySelector('.dc-status');
    if (b) {
      b.className = 'dc-status badge ' + (f.status_code ? 's' + Math.floor(f.status_code / 100) + 'xx' : 'dead');
      b.textContent = f.status_code != null ? f.status_code : 'dead';
    }
    const waf = card.querySelector('.dc-waf');
    if (waf) waf.innerHTML = f.waf ? `<span class="chip waf">🛡 ${esc(f.waf)}</span>` : '';
    const srv = card.querySelector('.dc-server');
    if (srv) srv.innerHTML = extra.server ? `<span class="dc-srv">${esc(extra.server)}</span>` : '';
    const ttl = card.querySelector('.dc-title');
    if (ttl) ttl.textContent = extra.title || '';
    if (window.applyFilters) applyFilters();
  }

  function updateRun(runId, status) {
    const row = document.querySelector(`#runs-body tr[data-run="${runId}"] .badge`);
    if (row) { row.textContent = status; row.className = 'badge run-' + status; }
  }
})();
