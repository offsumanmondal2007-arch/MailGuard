/**
 * timeline.js — Forensic Timeline browser page
 * MailGuard AI v2.0
 */
'use strict';

(function () {
  const { API, toast, escHtml, truncate, formatTimestamp, formatTime, registerPage, navigate } = window.APP;

  function renderTimelineView(email) {
    const timeline = email.timeline || [];
    if (!timeline.length) {
      return '<p class="text-muted text-small">No timeline data for this email.</p>';
    }
    return `
      <div class="timeline-list">
        ${timeline.map(evt => {
          const level = evt.level || 'info';
          const dotCls = level === 'critical' ? 'timeline-dot-critical' :
                         level === 'warning'  ? 'timeline-dot-warning'  : 'timeline-dot-info';
          const icon = level === 'critical' ? '✗' : level === 'warning' ? '⚠' : '●';
          const timeStr = formatTime(evt.timestamp);
          return `
            <div class="timeline-item">
              <div class="timeline-dot ${dotCls}">${icon}</div>
              <div class="timeline-time">${timeStr}</div>
              <div class="timeline-event">${escHtml(evt.event || '')}</div>
              <div class="timeline-detail">${escHtml(evt.detail || '')}</div>
            </div>`;
        }).join('')}
      </div>`;
  }

  registerPage('timeline', {
    mount(root, params) {
      root.innerHTML = `
<div class="page-header mb-2">
  <div>
    <h1 class="page-title">Forensic Timeline</h1>
    <p class="page-subtitle">Step-by-step processing timeline for each email through the security pipeline</p>
  </div>
</div>
<div style="display:grid;grid-template-columns:320px 1fr;gap:var(--gap);align-items:start">
  <div class="card">
    <div class="card-header"><span class="card-title">📋 Select Email</span></div>
    <div id="email-picker">
      <div class="loading-splash" style="min-height:80px"><div class="spinner-ring"></div></div>
    </div>
  </div>
  <div class="card" id="timeline-view">
    <div class="empty-state" style="min-height:200px">
      <div class="empty-state-icon">⏱</div>
      <div class="empty-state-text">Select an email to view its forensic timeline</div>
      <p class="text-muted text-small">The timeline shows every step the email went through during analysis</p>
    </div>
  </div>
</div>`;

      API.get('/api/emails?limit=30').then(emails => {
        const pickerEl = document.getElementById('email-picker');
        if (!pickerEl) return;
        if (!emails.length) {
          pickerEl.innerHTML = `<div class="empty-state" style="min-height:80px"><div class="empty-state-text">No emails yet</div></div>`;
          return;
        }
        pickerEl.innerHTML = emails.map(e => {
          const icon = { SAFE:'✅', SUSPICIOUS:'⚠️', HIGH_RISK:'🔴', CRITICAL:'💀' }[e.verdict] || '📧';
          return `
            <div class="email-picker-row clickable" data-id="${escHtml(e.id)}"
                 style="display:flex;align-items:center;gap:0.65rem;padding:0.5rem;border-bottom:1px solid var(--border);cursor:pointer;transition:background .15s;border-radius:var(--radius)">
              <span>${icon}</span>
              <div style="flex:1;min-width:0">
                <div style="font-size:0.78rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(e.subject||'(no subject)',40))}</div>
                <div class="text-xs text-muted">${escHtml(truncate(e.from_address||'—',35))}</div>
              </div>
            </div>`;
        }).join('');

        pickerEl.querySelectorAll('.email-picker-row').forEach(row => {
          row.addEventListener('click', async () => {
            // Highlight selection
            pickerEl.querySelectorAll('.email-picker-row').forEach(r => r.style.background = '');
            row.style.background = 'rgba(0,212,255,0.06)';

            const viewEl = document.getElementById('timeline-view');
            if (!viewEl) return;
            viewEl.innerHTML = `<div class="loading-splash" style="min-height:100px"><div class="spinner-ring"></div></div>`;

            try {
              const data = await API.get(`/api/emails/${row.dataset.id}/timeline`);
              const emailData = await API.get(`/api/emails/${row.dataset.id}`);
              viewEl.innerHTML = `
                <div class="card-header">
                  <span class="card-title">⏱ Forensic Timeline</span>
                  <span class="text-muted text-small">${(data.timeline||[]).length} events</span>
                </div>
                <div style="margin-bottom:0.75rem;padding:0.65rem;background:var(--bg-surface);border-radius:var(--radius)">
                  <div style="font-size:0.78rem;font-weight:600">${escHtml(emailData.subject||'(no subject)')}</div>
                  <div class="text-xs text-muted">${escHtml(emailData.from_address||'—')}</div>
                  <div class="text-xs text-muted">${formatTimestamp(emailData.timestamp)}</div>
                </div>
                ${renderTimelineView({ timeline: data.timeline })}
                <div style="margin-top:0.75rem">
                  <a href="#report/${row.dataset.id}" class="btn btn-secondary btn-sm">📋 Full Investigation →</a>
                </div>`;
            } catch (err) {
              const viewEl = document.getElementById('timeline-view');
              if (viewEl) viewEl.innerHTML = `<div class="error-state"><div>⚠</div><p>${escHtml(err.message)}</p></div>`;
            }
          });
        });

        // Auto-select target email or first email
        const targetId = params && params[0] ? params[0] : null;
        let selectedRow = targetId ? pickerEl.querySelector(`.email-picker-row[data-id="${targetId}"]`) : null;
        if (!selectedRow) selectedRow = pickerEl.querySelector('.email-picker-row');
        if (selectedRow) setTimeout(() => selectedRow.click(), 100);
      }).catch(err => {
        const pickerEl = document.getElementById('email-picker');
        if (pickerEl) pickerEl.innerHTML = `<p class="text-muted text-small">${escHtml(err.message)}</p>`;
      });
    },
  });
})();
