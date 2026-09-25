/**
 * policies.js — Security Policy Engine page
 * MailGuard AI v2.0
 */
'use strict';

(function () {
  const { API, toast, escHtml, registerPage } = window.APP;

  function actionBadge(action) {
    const map = {
      BLOCK:      'badge-block',
      QUARANTINE: 'badge-quarantine',
      FLAG:       'badge-flag',
      DELIVER:    'badge-deliver',
    };
    return `<span class="badge ${map[action] || 'badge-safe'}">${action}</span>`;
  }

  async function loadPolicies(root) {
    root.innerHTML = `
<div class="page-header mb-2">
  <div>
    <h1 class="page-title">Security Policies</h1>
    <p class="page-subtitle">Configure email security rules — Block, Quarantine, Flag, or Deliver decisions</p>
  </div>
  <div style="display:flex;align-items:center;gap:0.75rem">
    <span class="intel-source-badge" style="color:var(--warn);border-color:rgba(245,158,11,0.3);background:rgba(245,158,11,0.06)">⚠ IN-MEMORY</span>
    <button class="btn btn-secondary btn-sm" id="refresh-pol">↻ Refresh</button>
  </div>
</div>
<div class="disclaimer-box mb-2">
  <div class="disclaimer-title">⚠ Prototype Policy Engine</div>
  Policies are stored in-memory and reset on server restart. In a production deployment, policies would be
  persisted to a database and evaluated in real-time as emails arrive at the gateway.
</div>
<div class="card mb-2">
  <div class="card-header">
    <span class="card-title">⚙ Active Security Policies</span>
    <span class="text-muted text-small" id="pol-count">Loading…</span>
  </div>
  <div id="policies-list">
    <div class="loading-splash" style="min-height:80px"><div class="spinner-ring"></div></div>
  </div>
</div>

<!-- Policy actions legend -->
<div class="card">
  <div class="card-header"><span class="card-title">📖 Policy Action Reference</span></div>
  <div class="info-grid" style="grid-template-columns:repeat(auto-fill,minmax(200px,1fr))">
    ${[
      { action: 'BLOCK',      col: 'var(--block-color)',      desc: 'Email is rejected and not delivered. Sender receives an NDR.' },
      { action: 'QUARANTINE', col: 'var(--quarantine-color)', desc: 'Email is held for analyst review. Not delivered to recipient.' },
      { action: 'FLAG',       col: 'var(--flag-color)',       desc: 'Email is delivered with a warning banner added to the subject.' },
      { action: 'DELIVER',    col: 'var(--deliver-color)',    desc: 'Email passes all checks and is delivered normally.' },
    ].map(a => `
      <div class="info-item" style="gap:0.4rem">
        <span class="badge" style="background:rgba(0,0,0,0.2);border-color:${a.col};color:${a.col};width:100px">${a.action}</span>
        <span class="text-xs text-muted">${escHtml(a.desc)}</span>
      </div>`).join('')}
  </div>
</div>`;

    document.getElementById('refresh-pol')?.addEventListener('click', () => loadPolicies(root));

    try {
      const data = await API.get('/api/policies');
      const policies = data.policies || [];
      const countEl = document.getElementById('pol-count');
      if (countEl) countEl.textContent = `${policies.length} policies`;
      const listEl = document.getElementById('policies-list');
      if (!listEl) return;
      listEl.innerHTML = policies.map(pol => `
        <div class="policy-row ${pol.enabled ? '' : 'disabled'}" id="pol-${pol.id}">
          <div class="policy-priority">#${pol.priority}</div>
          <div class="policy-body">
            <div class="policy-name">${escHtml(pol.name)}</div>
            <div class="policy-desc">${escHtml(pol.description)}</div>
            <div class="policy-cond">IF: ${escHtml(pol.condition)}</div>
          </div>
          <div class="policy-meta">
            ${actionBadge(pol.action)}
            <label class="toggle-switch" title="${pol.enabled ? 'Disable' : 'Enable'} policy">
              <input type="checkbox" ${pol.enabled ? 'checked' : ''} data-pol-id="${pol.id}">
              <span class="toggle-slider"></span>
            </label>
          </div>
        </div>`).join('');

      listEl.querySelectorAll('input[data-pol-id]').forEach(toggle => {
        toggle.addEventListener('change', async () => {
          const polId = toggle.dataset.polId;
          const enabled = toggle.checked;
          try {
            await API.patch(`/api/policies/${polId}`, { enabled });
            const rowEl = document.getElementById(`pol-${polId}`);
            if (rowEl) rowEl.classList.toggle('disabled', !enabled);
            toast(`Policy ${enabled ? 'enabled' : 'disabled'}`, 'success');
          } catch (err) {
            toggle.checked = !enabled; // Revert
            toast(`Failed: ${err.message}`, 'error');
          }
        });
      });
    } catch (err) {
      const listEl = document.getElementById('policies-list');
      if (listEl) listEl.innerHTML = `<div class="error-state"><p>${escHtml(err.message)}</p></div>`;
      toast(`Error: ${err.message}`, 'error');
    }
  }

  registerPage('policies', {
    mount(root) {
      loadPolicies(root);
    },
  });
})();
