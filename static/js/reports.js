/**
 * reports.js — Email Investigation list
 * MailGuard AI v2.0
 */
'use strict';

(function () {
  const { API, toast, verdictClass, verdictColour, scoreColour, actionClass,
          formatTimestamp, escHtml, truncate, registerPage, navigate } = window.APP;

  registerPage('reports', {
    mount(root) {
      root.innerHTML = `
<div class="page-header mb-2">
  <div>
    <h1 class="page-title">Email Investigation</h1>
    <p class="page-subtitle">All analysed emails — click any row to open the forensic investigation</p>
  </div>
  <div style="display:flex;gap:0.75rem;align-items:center;flex-wrap:wrap">
    <input type="text" id="search-box" class="form-control" placeholder="Search subject, sender…" style="width:220px" />
    <select id="filter-verdict" class="form-control" style="width:150px">
      <option value="">All Verdicts</option>
      <option value="SAFE">SAFE</option>
      <option value="SUSPICIOUS">SUSPICIOUS</option>
      <option value="HIGH_RISK">HIGH RISK</option>
      <option value="CRITICAL">CRITICAL</option>
    </select>
    <button class="btn btn-primary btn-sm" onclick="window.APP.navigate('#analyze')">+ Scan Email</button>
  </div>
</div>

<div class="card">
  <div class="card-header">
    <span class="card-title">📋 All Cases</span>
    <span class="text-muted text-small" id="report-count"></span>
  </div>
  <div id="reports-table-wrap">
    <div class="loading-splash"><div class="spinner-ring"></div><p>Loading investigations…</p></div>
  </div>
</div>`;

      let allEmails = [];

      function renderTable(emails) {
        const wrap = document.getElementById('reports-table-wrap');
        const countEl = document.getElementById('report-count');
        if (!wrap) return;
        if (countEl) countEl.textContent = `${emails.length} case${emails.length !== 1 ? 's' : ''}`;
        if (!emails.length) {
          wrap.innerHTML = `<div class="empty-state" style="min-height:120px"><div class="empty-state-icon">📭</div><div class="empty-state-text">No cases found</div></div>`;
          return;
        }
        wrap.innerHTML = `
          <div style="overflow-x:auto">
            <table class="reports-table">
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
                ${emails.map(e => {
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
                      <td class="text-xs text-muted font-mono" style="white-space:nowrap">${formatTimestamp(e.timestamp)}</td>
                      <td>
                        <div style="font-size:0.8rem;font-weight:600;max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(e.from_address||'—', 50))}</div>
                        <div class="text-xs text-muted" style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(e.subject||'(no subject)', 50))}</div>
                      </td>
                      <td class="text-xs text-muted">${escHtml((e.category||'—').replace(/_/g,' '))}</td>
                      <td><span class="badge badge-${vc}">${icon} ${e.verdict.replace('_',' ')}</span></td>
                      <td><span style="font-size:0.85rem;font-weight:700;color:${sc};font-family:'JetBrains Mono',monospace">${e.score}</span></td>
                      <td><span class="badge ${ac}">${action}</span></td>
                      <td class="text-xs text-muted">${escHtml(e.status||'new')}</td>
                    </tr>`;
                }).join('')}
              </tbody>
            </table>
          </div>`;

        wrap.querySelectorAll('tr.clickable').forEach(row => {
          row.addEventListener('click', () => navigate(`#report/${row.dataset.id}`));
        });
      }

      function applyFilters() {
        const search  = (document.getElementById('search-box')?.value || '').toLowerCase();
        const verdict = document.getElementById('filter-verdict')?.value || '';
        let filtered  = allEmails;
        if (search) {
          filtered = filtered.filter(e =>
            (e.subject || '').toLowerCase().includes(search) ||
            (e.from_address || '').toLowerCase().includes(search) ||
            (e.category || '').toLowerCase().includes(search)
          );
        }
        if (verdict) {
          filtered = filtered.filter(e => e.verdict === verdict);
        }
        renderTable(filtered);
      }

      document.getElementById('search-box')?.addEventListener('input', applyFilters);
      document.getElementById('filter-verdict')?.addEventListener('change', applyFilters);

      API.get('/api/reports?limit=100').then(emails => {
        allEmails = emails || [];
        renderTable(allEmails);
      }).catch(err => {
        const wrap = document.getElementById('reports-table-wrap');
        if (wrap) wrap.innerHTML = `<div class="error-state"><div>⚠</div><strong>Failed to load reports</strong><p>${escHtml(err.message)}</p></div>`;
        toast(`Error: ${err.message}`, 'error');
      });
    },
  });
})();
