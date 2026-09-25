/**
 * system_status.js — System Status page
 * MailGuard AI v2.0
 */
'use strict';

(function () {
  const { API, toast, escHtml, registerPage } = window.APP;

  registerPage('status', {
    mount(root) {
      root.innerHTML = `
<div class="page-header mb-2">
  <div>
    <h1 class="page-title">System Status</h1>
    <p class="page-subtitle">Component health, pipeline architecture, and capability overview</p>
  </div>
  <button class="btn btn-secondary btn-sm" id="refresh-status">↻ Refresh</button>
</div>
<div id="status-content">
  <div class="loading-splash"><div class="spinner-ring"></div><p>Loading system status…</p></div>
</div>`;

      document.getElementById('refresh-status')?.addEventListener('click', () => loadStatus(root));
      loadStatus(root);
    },
  });

  async function loadStatus(root) {
    try {
      const data = await API.get('/api/system/status');
      const statusEl = document.getElementById('status-content');
      if (!statusEl) return;

      const components = data.components || {};
      const pipeline   = data.analysis_pipeline || [];
      const notes      = data.notes || [];

      const statusDot = (s) => {
        const cls = { active: 'cs-active', prototype: 'cs-prototype', local: 'cs-local', error: 'cs-error' }[s] || 'cs-local';
        return `<div class="component-status-dot ${cls}"></div>`;
      };
      const statusBadge = (s) => {
        const map = {
          active:    { cls: 'cb-active',    label: 'ACTIVE' },
          prototype: { cls: 'cb-prototype', label: 'PROTOTYPE' },
          local:     { cls: 'cb-local',     label: 'LOCAL' },
          error:     { cls: 'cb-error',     label: 'ERROR' },
        };
        const { cls, label } = map[s] || map.local;
        return `<span class="component-badge ${cls}">${label}</span>`;
      };

      statusEl.innerHTML = `
<!-- Overall status -->
<div class="threat-banner threat-banner-safe mb-2" style="background:rgba(34,197,94,0.04);border-color:rgba(34,197,94,0.25)">
  <div style="font-size:1.5rem">🟢</div>
  <div>
    <div style="font-size:1rem;font-weight:700;color:var(--safe)">System Operational</div>
    <div style="font-size:0.78rem;color:var(--text-secondary)">MailGuard AI v${data.version} — All core components active</div>
  </div>
</div>

<!-- Component grid -->
<div class="card mb-2">
  <div class="card-header"><span class="card-title">🔧 Component Status</span></div>
  <div class="component-grid">
    ${Object.entries(components).map(([name, comp]) => `
      <div class="component-card">
        ${statusDot(comp.status)}
        <div class="component-info">
          <div class="component-name">${escHtml(name.replace(/_/g,' ').toUpperCase())}</div>
          <div class="component-desc">${escHtml(comp.description)}</div>
          ${statusBadge(comp.status)}
        </div>
      </div>`).join('')}
  </div>
</div>

<!-- Analysis pipeline -->
<div class="card mb-2">
  <div class="card-header"><span class="card-title">⚙ Pre-Delivery Analysis Pipeline</span></div>
  <p class="text-xs text-muted mb-1" style="margin-bottom:0.75rem">Every email is processed through this pipeline before delivery decision.</p>
  <div class="pipeline-display" style="flex-wrap:wrap;gap:0.5rem">
    ${pipeline.map((step, i) => `
      <div style="display:flex;align-items:center;gap:0.3rem">
        <div class="pipeline-display-box" style="background:var(--bg-surface)">${escHtml(step)}</div>
        ${i < pipeline.length - 1 ? '<span style="color:var(--text-muted);font-size:0.75rem">→</span>' : ''}
      </div>`).join('')}
  </div>
</div>

<!-- Notes / Disclaimers -->
<div class="card mb-2">
  <div class="card-header"><span class="card-title">⚠ Implementation Notes</span></div>
  ${notes.map(n => `
    <div style="display:flex;gap:0.65rem;align-items:flex-start;padding:0.45rem 0;border-bottom:1px solid rgba(255,255,255,0.04)">
      <span style="color:var(--warn);flex-shrink:0">▶</span>
      <span style="font-size:0.8rem;color:var(--text-secondary)">${escHtml(n)}</span>
    </div>`).join('')}
</div>

<!-- Health check live -->
<div class="card">
  <div class="card-header"><span class="card-title">💊 Live Health Check</span></div>
  <div id="live-health">
    <div class="loading-splash" style="min-height:60px"><div class="spinner-ring"></div></div>
  </div>
</div>`;

      // Health check
      API.get('/api/health').then(h => {
        const el = document.getElementById('live-health');
        if (!el) return;
        el.innerHTML = `
          <div class="info-grid">
            <div class="info-item"><span class="info-item-label">Service</span><span class="info-item-value">${escHtml(h.service)}</span></div>
            <div class="info-item"><span class="info-item-label">Status</span><span class="info-item-value" style="color:var(--safe)">${escHtml(h.status)}</span></div>
            <div class="info-item"><span class="info-item-label">Database</span><span class="info-item-value" style="color:${h.database==='connected'?'var(--safe)':'var(--fail)'}">${escHtml(h.database)}</span></div>
            <div class="info-item"><span class="info-item-label">Detector</span><span class="info-item-value" style="color:var(--safe)">${escHtml(h.detector)}</span></div>
            <div class="info-item"><span class="info-item-label">Checked at</span><span class="info-item-value text-small">${new Date().toLocaleString('en-IN')}</span></div>
          </div>`;
      }).catch(() => {
        const el = document.getElementById('live-health');
        if (el) el.innerHTML = '<p class="text-fail">Health check failed — backend may be offline.</p>';
      });

    } catch (err) {
      const statusEl = document.getElementById('status-content');
      if (statusEl) statusEl.innerHTML = `<div class="card"><div class="error-state"><div>⚠</div><strong>Failed to load status</strong><p class="text-small">${escHtml(err.message)}</p></div></div>`;
      toast(`Error: ${err.message}`, 'error');
    }
  }
})();
