/**
 * threats.js — Threat Feed page
 * MailGuard AI v2.0
 */
'use strict';

(function () {
  const { API, toast, verdictClass, verdictColour, scoreColour, actionClass,
          formatTimestamp, escHtml, truncate, registerPage, navigate } = window.APP;

  async function loadThreats(root, filter) {
    root.innerHTML = `
<div class="page-header mb-2">
  <div>
    <h1 class="page-title">Threat Feed</h1>
    <p class="page-subtitle">Real-time stream of threats detected by the MailGuard gateway</p>
  </div>
  <div style="display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap">
    <span class="intel-source-badge">📡 LOCAL FEED</span>
    <select class="form-control" id="verdict-filter" style="width:160px">
      <option value="">All Threats</option>
      <option value="CRITICAL" ${filter==='CRITICAL'?'selected':''}>CRITICAL</option>
      <option value="HIGH_RISK" ${filter==='HIGH_RISK'?'selected':''}>HIGH_RISK</option>
      <option value="SUSPICIOUS" ${filter==='SUSPICIOUS'?'selected':''}>SUSPICIOUS</option>
    </select>
    <button class="btn btn-secondary btn-sm" id="refresh-btn">↻ Refresh</button>
    <button class="btn btn-primary btn-sm" onclick="window.APP.navigate('#analyze')">+ Scan Email</button>
  </div>
</div>
<div id="feed-content">
  <div class="loading-splash"><div class="spinner-ring"></div><p>Loading threat feed…</p></div>
</div>`;

    document.getElementById('verdict-filter')?.addEventListener('change', (e) => {
      loadThreats(root, e.target.value);
    });
    document.getElementById('refresh-btn')?.addEventListener('click', () => {
      loadThreats(root, filter);
    });

    try {
      const url = '/api/threats?limit=100' + (filter ? `&verdict=${filter}` : '');
      const data = await API.get(url);
      const threats = data.threats || [];
      const feedEl = document.getElementById('feed-content');
      if (!feedEl) return;

      if (!threats.length) {
        feedEl.innerHTML = `
          <div class="card">
            <div class="empty-state">
              <div class="empty-state-icon">🛡</div>
              <div class="empty-state-text">No threats detected</div>
              <p class="text-muted text-small">All emails appear safe${filter ? ` with verdict: ${filter}` : ''}</p>
              <button class="btn btn-secondary btn-sm mt-1" onclick="window.APP.navigate('#analyze')">Scan an Email</button>
            </div>
          </div>`;
        return;
      }

      const noteEl = document.createElement('div');
      noteEl.className = 'card mb-2';
      noteEl.innerHTML = `
        <div class="sandbox-note" style="margin:0">
          ⚠ <strong>LOCAL INTELLIGENCE ONLY</strong> — ${data.note}
        </div>`;
      feedEl.innerHTML = '';
      feedEl.appendChild(noteEl);

      const tableCard = document.createElement('div');
      tableCard.className = 'card';
      tableCard.innerHTML = `
        <div class="card-header">
          <span class="card-title">🚨 Active Threats (${threats.length})</span>
          <span class="text-muted text-small">Click a row to investigate</span>
        </div>
        <div style="overflow-x:auto">
          <table class="reports-table" id="threats-table">
            <thead>
              <tr>
                <th>Time</th>
                <th>From / Subject</th>
                <th>Category</th>
                <th>Verdict</th>
                <th>Score</th>
                <th>Action</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              ${threats.map(e => {
                const vc = verdictClass(e.verdict);
                const sc = scoreColour(e.score);
                const icon = { SAFE:'✅', SUSPICIOUS:'⚠️', HIGH_RISK:'🔴', CRITICAL:'💀' }[e.verdict] || '📧';
                let action = 'DELIVER';
                if (e.score >= 80) action = 'BLOCK';
                else if (e.score >= 60) action = 'QUARANTINE';
                else if (e.score >= 30) action = 'FLAG';
                const ac = actionClass(action);
                return `
                  <tr class="clickable" data-id="${escHtml(e.id)}">
                    <td><span class="text-xs text-muted font-mono">${formatTimestamp(e.timestamp)}</span></td>
                    <td>
                      <div style="font-size:0.8rem;font-weight:600;max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(e.from_address||'—',50))}</div>
                      <div class="text-xs text-muted" style="max-width:220px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(e.subject||'(no subject)',50))}</div>
                    </td>
                    <td><span class="text-xs text-muted">${escHtml((e.category||'—').replace(/_/g,' '))}</span></td>
                    <td><span class="badge badge-${vc}">${icon} ${e.verdict.replace('_',' ')}</span></td>
                    <td><span style="font-size:0.85rem;font-weight:700;color:${sc};font-family:'JetBrains Mono',monospace">${e.score}</span></td>
                    <td><span class="badge ${ac}">${action}</span></td>
                    <td><span class="text-xs text-muted">${escHtml(e.status||'new')}</span></td>
                  </tr>`;
              }).join('')}
            </tbody>
          </table>
        </div>`;
      feedEl.appendChild(tableCard);

      feedEl.querySelectorAll('tr.clickable').forEach(row => {
        row.addEventListener('click', () => navigate(`#report/${row.dataset.id}`));
      });
    } catch (err) {
      const feedEl = document.getElementById('feed-content');
      if (feedEl) feedEl.innerHTML = `<div class="card"><div class="error-state"><div>⚠</div><strong>Failed to load threat feed</strong><p class="text-small">${escHtml(err.message)}</p></div></div>`;
      toast(`Error: ${err.message}`, 'error');
    }
  }

  registerPage('threats', {
    mount(root) {
      loadThreats(root, '');
    },
  });
})();
