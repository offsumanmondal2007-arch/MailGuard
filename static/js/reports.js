/**
 * reports.js — Email case list / reports page
 * MailGuard AI
 */
'use strict';

(function () {
  const { API, toast, verdictClass, verdictColour, scoreColour,
          formatTimestamp, escHtml, registerPage, navigate } = window.APP;

  function truncate(str, max) {
    if (!str) return '—';
    return str.length > max ? str.slice(0, max) + '…' : str;
  }
  function scoreColourLocal(score) {
    if (score >= 80) return '#dc2626';
    if (score >= 60) return '#ef4444';
    if (score >= 30) return '#f59e0b';
    return '#22c55e';
  }

  let _allEmails = [];
  let _filterVerdict = '';
  let _filterCategory = '';
  let _searchQuery = '';

  function renderPage() {
    return `
<div class="page-header">
  <div>
    <h1 class="page-title">📋 Case Reports</h1>
    <p class="page-subtitle">Complete analysis history — click any row to view the full forensic report</p>
  </div>
  <button class="btn btn-secondary btn-sm" id="reports-refresh">↻ Refresh</button>
</div>

<!-- Filters -->
<div class="card mb-2" style="padding:0.85rem 1.1rem">
  <div style="display:flex;gap:0.75rem;flex-wrap:wrap;align-items:center">
    <input type="text" id="reports-search" class="form-control" placeholder="Search subject or sender…" style="max-width:280px;margin-bottom:0" />
    <select id="filter-verdict" class="form-control" style="max-width:160px;margin-bottom:0">
      <option value="">All Verdicts</option>
      <option value="SAFE">Safe</option>
      <option value="SUSPICIOUS">Suspicious</option>
      <option value="HIGH_RISK">High Risk</option>
      <option value="CRITICAL">Critical</option>
    </select>
    <select id="filter-category" class="form-control" style="max-width:240px;margin-bottom:0">
      <option value="">All Categories</option>
      <option value="SAFE">Safe</option>
      <option value="PHISHING">Phishing</option>
      <option value="CREDENTIAL_THEFT">Credential Theft</option>
      <option value="PAYMENT_FRAUD">Payment Fraud</option>
      <option value="BUSINESS_EMAIL_COMPROMISE">BEC</option>
      <option value="EXECUTIVE_IMPERSONATION">Executive Impersonation</option>
      <option value="SOCIAL_ENGINEERING">Social Engineering</option>
      <option value="SPAM">Spam</option>
    </select>
    <span id="reports-count" class="text-muted text-small"></span>
  </div>
</div>

<!-- Table -->
<div class="card">
  <div class="data-table-wrapper">
    <table class="data-table">
      <thead>
        <tr>
          <th>Score</th>
          <th>Verdict</th>
          <th>Category</th>
          <th>Sender</th>
          <th>Subject</th>
          <th>Confidence</th>
          <th>Status</th>
          <th>Time</th>
        </tr>
      </thead>
      <tbody id="reports-tbody">
        <tr><td colspan="8" style="text-align:center;color:var(--text-muted)">Loading…</td></tr>
      </tbody>
    </table>
  </div>
</div>`;
  }

  function renderTable(emails) {
    const tbody = document.getElementById('reports-tbody');
    const count = document.getElementById('reports-count');
    if (!tbody) return;

    if (count) count.textContent = `${emails.length} record${emails.length !== 1 ? 's' : ''}`;

    if (!emails.length) {
      tbody.innerHTML = `
        <tr>
          <td colspan="8">
            <div class="empty-state">
              <div class="empty-state-icon">📭</div>
              <div class="empty-state-text">No emails match your filters</div>
            </div>
          </td>
        </tr>`;
      return;
    }

    tbody.innerHTML = emails.map(e => {
      const vc = verdictClass(e.verdict);
      const sc = scoreColourLocal(e.score);
      return `
        <tr class="clickable" data-id="${escHtml(e.id)}">
          <td class="col-score" style="color:${sc};font-weight:700">${e.score}</td>
          <td><span class="badge badge-${vc}">${e.verdict.replace('_',' ')}</span></td>
          <td style="font-size:0.78rem">${escHtml(e.category.replace(/_/g,' '))}</td>
          <td style="font-family:monospace;font-size:0.75rem">${escHtml(truncate(e.from_address, 35))}</td>
          <td>${escHtml(truncate(e.subject, 50))}</td>
          <td style="font-size:0.78rem">${Math.round((e.confidence||0)*100)}%</td>
          <td><span class="status-pill status-${e.status}">${e.status}</span></td>
          <td class="text-muted" style="font-size:0.75rem;white-space:nowrap">${formatTimestamp(e.timestamp)}</td>
        </tr>`;
    }).join('');

    tbody.querySelectorAll('tr.clickable').forEach(row => {
      row.addEventListener('click', () => navigate(`#report/${row.dataset.id}`));
    });
  }

  function applyFilters() {
    let filtered = _allEmails.slice();
    if (_filterVerdict) filtered = filtered.filter(e => e.verdict === _filterVerdict);
    if (_filterCategory) filtered = filtered.filter(e => e.category === _filterCategory);
    if (_searchQuery) {
      const q = _searchQuery.toLowerCase();
      filtered = filtered.filter(e =>
        (e.subject||'').toLowerCase().includes(q) ||
        (e.from_address||'').toLowerCase().includes(q)
      );
    }
    renderTable(filtered);
  }

  async function loadReports() {
    try {
      _allEmails = await API.get('/api/emails?limit=200');
      applyFilters();
    } catch (err) {
      const tbody = document.getElementById('reports-tbody');
      if (tbody) tbody.innerHTML = `
        <tr><td colspan="8"><div class="error-state">
          <strong>Failed to load reports</strong>
          <p class="text-small">${escHtml(err.message)}</p>
        </div></td></tr>`;
      toast(`Error: ${err.message}`, 'error');
    }
  }

  registerPage('reports', {
    mount(root) {
      root.innerHTML = renderPage();
      loadReports();

      document.getElementById('reports-refresh').addEventListener('click', () => {
        toast('Refreshing…', 'success', 1500);
        loadReports();
      });
      document.getElementById('reports-search').addEventListener('input', e => {
        _searchQuery = e.target.value.trim();
        applyFilters();
      });
      document.getElementById('filter-verdict').addEventListener('change', e => {
        _filterVerdict = e.target.value;
        applyFilters();
      });
      document.getElementById('filter-category').addEventListener('change', e => {
        _filterCategory = e.target.value;
        applyFilters();
      });

      return () => { _allEmails = []; _filterVerdict = ''; _filterCategory = ''; _searchQuery = ''; };
    },
  });
})();
