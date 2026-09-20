/**
 * report.js — Single email forensic case view
 * MailGuard AI
 *
 * Route: #report/{id}
 */
'use strict';

(function () {
  const { API, toast, verdictClass, verdictColour, scoreColour, checkIcon,
          formatTimestamp, escHtml, registerPage, navigate } = window.APP;

  function scoreColourLocal(score) {
    if (score >= 80) return '#dc2626';
    if (score >= 60) return '#ef4444';
    if (score >= 30) return '#f59e0b';
    return '#22c55e';
  }

  function truncate(str, max) {
    if (!str) return '—';
    return str.length > max ? str.slice(0, max) + '…' : str;
  }

  function renderReport(r) {
    const vc   = verdictClass(r.verdict);
    const col  = verdictColour(r.verdict);
    const sc   = scoreColourLocal(r.score);
    const bd   = r.breakdown || {};
    const geo  = r.geo || {};
    const for_ = r.forensics || {};

    const pillars = [
      { key: 'header_forensics', label: 'Header Forensics', icon: '📨' },
      { key: 'content_analysis', label: 'Content Analysis', icon: '📝' },
      { key: 'url_intelligence', label: 'URL Intelligence', icon: '🔗' },
      { key: 'behavioural',      label: 'Behaviour Analysis', icon: '🧠' },
      { key: 'ml_heuristic',     label: 'Heuristic ML Layer', icon: '🤖' },
    ];

    const breakdownRows = pillars.map(p => {
      const pil = bd[p.key] || { score: 0, max: 25 };
      const pct = pil.max ? Math.round(pil.score / pil.max * 100) : 0;
      const barCol = pct >= 70 ? '#dc2626' : pct >= 40 ? '#f59e0b' : '#22c55e';
      return `
        <div class="breakdown-row">
          <span class="breakdown-label">${p.icon} ${escHtml(p.label)}</span>
          <div class="breakdown-bar-track">
            <div class="breakdown-bar-fill" style="width:${pct}%;background:${barCol}"></div>
          </div>
          <span class="breakdown-score">${pil.score}/${pil.max}</span>
        </div>`;
    }).join('');

    // Pillar-level check details (grouped)
    const pillarChecksSections = pillars.map(p => {
      const pil = bd[p.key] || { checks: [] };
      if (!pil.checks || !pil.checks.length) return '';
      const items = pil.checks.map(c => `
        <div class="check-item">
          <span class="check-icon check-${c.result}">${checkIcon(c.result)}</span>
          <div class="check-body">
            <div class="check-name">${escHtml(c.name)}</div>
            <div class="check-detail">${escHtml(c.detail)}</div>
          </div>
        </div>`).join('');
      return `
        <details class="mb-1" style="border:1px solid var(--border);border-radius:var(--radius);padding:0.6rem 0.85rem;margin-bottom:0.5rem">
          <summary>${p.icon} ${escHtml(p.label)} — ${pil.score||0}/${pil.max||15} pts</summary>
          <div style="margin-top:0.5rem">${items}</div>
        </details>`;
    }).join('');

    const reasonsHtml = (r.reasons || []).length
      ? `<ul class="reasons-list">${r.reasons.map(re => `<li>${escHtml(re)}</li>`).join('')}</ul>`
      : `<p class="text-muted text-small">No significant signals detected.</p>`;

    const geoHtml = geo.available ? `
      <div class="info-grid">
        <div class="info-item"><span class="info-item-label">IP Address</span><span class="info-item-value font-mono">${escHtml(geo.ip)}</span></div>
        <div class="info-item"><span class="info-item-label">Country</span><span class="info-item-value">${escHtml(geo.country)}</span></div>
        <div class="info-item"><span class="info-item-label">Region</span><span class="info-item-value">${escHtml(geo.region)}</span></div>
        <div class="info-item"><span class="info-item-label">City</span><span class="info-item-value">${escHtml(geo.city)}</span></div>
        <div class="info-item"><span class="info-item-label">ISP</span><span class="info-item-value">${escHtml(geo.isp)}</span></div>
        <div class="info-item"><span class="info-item-label">ASN</span><span class="info-item-value">${escHtml(geo.asn)}</span></div>
      </div>` :
      `<p class="text-muted text-small">${escHtml(geo.note || 'IP Geolocation not available')}</p>`;

    const statusOptions = ['new','reviewed','quarantined','cleared'];

    return `
<span class="back-link" id="back-btn">← Back to Reports</span>

<div class="report-layout">

  <!-- SIDEBAR -->
  <div class="report-sidebar">

    <!-- Case identity -->
    <div class="card">
      <div class="case-id-badge">CASE-${r.id.split('-')[0].toUpperCase()}</div>
      <div class="score-gauge" style="margin-top:0.75rem">
        <div class="score-circle ${vc}">
          <span class="score-number" style="color:${sc}">${r.score}</span>
          <span class="score-max">/ 100</span>
        </div>
        <span class="score-label" style="color:${col}">${r.verdict.replace('_',' ')}</span>
      </div>
      <div style="margin-top:1rem">
        <div class="info-item mb-1">
          <span class="info-item-label">Category</span>
          <span class="info-item-value">${escHtml(r.category.replace(/_/g,' '))}</span>
        </div>
        <div class="info-item mb-1">
          <span class="info-item-label">Confidence</span>
          <span class="info-item-value">${Math.round(r.confidence*100)}%
            <div class="confidence-bar mt-1">
              <div class="confidence-fill" style="width:${Math.round(r.confidence*100)}%;background:${col}"></div>
            </div>
          </span>
        </div>
        <div class="info-item mb-1">
          <span class="info-item-label">Analyzed</span>
          <span class="info-item-value text-small">${formatTimestamp(r.timestamp)}</span>
        </div>
        <div class="info-item">
          <span class="info-item-label">Status</span>
          <div style="display:flex;gap:0.4rem;flex-wrap:wrap;margin-top:0.3rem" id="status-buttons">
            ${statusOptions.map(s => `
              <button class="btn btn-sm ${s===r.status?'btn-primary':'btn-secondary'}" 
                      data-status="${s}" id="status-${s}">
                ${s}
              </button>`).join('')}
          </div>
        </div>
      </div>
    </div>

    <!-- Recommended action -->
    <div class="action-box ${vc}">
      <strong>Recommended Action</strong><br>
      <span style="font-size:0.8rem">${escHtml(r.recommended_action)}</span>
    </div>

    <!-- Email metadata -->
    <div class="card">
      <div class="card-header"><span class="card-title">📧 Email Info</span></div>
      <div class="info-item mb-1">
        <span class="info-item-label">From</span>
        <span class="info-item-value text-small font-mono">${escHtml(r.from_address || '—')}</span>
      </div>
      <div class="info-item mb-1">
        <span class="info-item-label">Reply-To</span>
        <span class="info-item-value text-small font-mono">${escHtml(r.reply_to || '—')}</span>
      </div>
      <div class="info-item mb-1">
        <span class="info-item-label">Subject</span>
        <span class="info-item-value text-small">${escHtml(r.subject || '—')}</span>
      </div>
      <div class="info-item">
        <span class="info-item-label">Sender IP</span>
        <span class="info-item-value font-mono text-small">${escHtml(r.sender_ip || '—')}</span>
      </div>
    </div>

  </div>

  <!-- MAIN -->
  <div class="report-main">

    <!-- Detection reasons -->
    <div class="card">
      <div class="card-header"><span class="card-title">🚨 Threat Detection Reasons</span></div>
      ${reasonsHtml}
    </div>

    <!-- Score breakdown -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">📊 Score Breakdown</span>
        <span class="text-muted text-small">Total: ${r.score}/100</span>
      </div>
      ${breakdownRows}
    </div>

    <!-- Per-pillar detailed checks -->
    <div class="card">
      <div class="card-header"><span class="card-title">🔬 Forensic Check Details</span></div>
      ${pillarChecksSections || '<p class="text-muted text-small">No check details available.</p>'}
    </div>

    <!-- Header forensics -->
    <div class="card">
      <div class="card-header"><span class="card-title">📨 Header Forensics</span></div>
      <div class="info-grid mb-1">
        <div class="info-item"><span class="info-item-label">From Domain</span><span class="info-item-value font-mono">${escHtml(for_.from_domain||'—')}</span></div>
        <div class="info-item"><span class="info-item-label">Reply-To Domain</span><span class="info-item-value font-mono">${escHtml(for_.reply_to_domain||'—')}</span></div>
        <div class="info-item"><span class="info-item-label">Domain Mismatch</span><span class="info-item-value" style="color:${for_.domain_mismatch?'var(--fail)':'var(--safe)'}">${for_.domain_mismatch?'⚠ Yes':'✓ No'}</span></div>
        <div class="info-item"><span class="info-item-label">SPF</span><span class="info-item-value" style="color:${for_.spf==='pass'?'var(--safe)':for_.spf==='fail'?'var(--fail)':'var(--warn)'}">${escHtml(for_.spf||'unknown')}</span></div>
        <div class="info-item"><span class="info-item-label">DKIM</span><span class="info-item-value" style="color:${for_.dkim==='pass'?'var(--safe)':for_.dkim==='fail'?'var(--fail)':'var(--warn)'}">${escHtml(for_.dkim||'unknown')}</span></div>
        <div class="info-item"><span class="info-item-label">DMARC</span><span class="info-item-value" style="color:${for_.dmarc==='pass'?'var(--safe)':for_.dmarc==='fail'?'var(--fail)':'var(--warn)'}">${escHtml(for_.dmarc||'unknown')}</span></div>
        <div class="info-item"><span class="info-item-label">Display-Name Spoofing</span><span class="info-item-value" style="color:${for_.display_name_spoofing?'var(--fail)':'var(--safe)'}">${for_.display_name_spoofing?'⚠ Detected':'✓ None'}</span></div>
        <div class="info-item"><span class="info-item-label">Typosquatting</span><span class="info-item-value" style="color:${for_.typosquatting?'var(--fail)':'var(--safe)'}">${for_.typosquatting?'⚠ Detected':'✓ None'}</span></div>
        <div class="info-item"><span class="info-item-label">Mail Hops</span><span class="info-item-value">${for_.received_hops||0}</span></div>
      </div>
      ${(for_.urls_found||[]).length ? `
        <div class="divider"></div>
        <div class="section-title">URLs Detected (${for_.urls_found.length})</div>
        <div style="display:flex;flex-wrap:wrap;gap:0.4rem">
          ${for_.urls_found.map(u => {
            const susp = (for_.suspicious_urls||[]).includes(u);
            return `<span class="tag" style="${susp?'color:var(--fail);border-color:rgba(239,68,68,0.4)':''}" title="${escHtml(u)}">${escHtml(truncate(u,60))}</span>`;
          }).join('')}
        </div>` : ''}
    </div>

    <!-- Geolocation -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">🌍 IP Geolocation</span>
        ${geo.available ? '<span class="badge badge-safe">Live Data</span>' : '<span class="text-muted text-small">Unavailable</span>'}
      </div>
      ${geoHtml}
    </div>

    <!-- Raw body (collapsible) -->
    ${r.body ? `
    <div class="card">
      <details>
        <summary>📄 Email Body (raw)</summary>
        <pre style="margin-top:0.75rem;font-size:0.75rem;color:var(--text-secondary);white-space:pre-wrap;word-break:break-all;max-height:400px;overflow-y:auto;background:var(--bg-input);padding:0.75rem;border-radius:var(--radius)">${escHtml(r.body)}</pre>
      </details>
    </div>` : ''}

  </div>
</div>`;
  }

  async function loadAndRender(root, emailId) {
    root.innerHTML = `<div class="loading-splash"><div class="spinner-ring"></div><p>Loading case…</p></div>`;
    try {
      const record = await API.get(`/api/emails/${emailId}`);
      root.innerHTML = renderReport(record);

      // Back button
      document.getElementById('back-btn').addEventListener('click', () => navigate('#reports'));

      // Status update buttons
      const statusBtns = document.querySelectorAll('#status-buttons button');
      statusBtns.forEach(btn => {
        btn.addEventListener('click', async () => {
          const newStatus = btn.dataset.status;
          try {
            await API.patch(`/api/emails/${emailId}/status`, { status: newStatus });
            // Update button styles
            statusBtns.forEach(b => {
              b.className = `btn btn-sm ${b.dataset.status === newStatus ? 'btn-primary' : 'btn-secondary'}`;
            });
            toast(`Status updated to: ${newStatus}`, 'success');
          } catch (err) {
            toast(`Failed: ${err.message}`, 'error');
          }
        });
      });
    } catch (err) {
      root.innerHTML = `
        <span class="back-link" id="back-btn2">← Back to Reports</span>
        <div class="error-state" style="margin-top:2rem">
          <div style="font-size:2rem">⚠</div>
          <strong>Failed to load case</strong>
          <p class="text-small">${escHtml(err.message)}</p>
          <button class="btn btn-secondary btn-sm mt-1" onclick="window.APP.navigate('#reports')">Back to Reports</button>
        </div>`;
      document.getElementById('back-btn2')?.addEventListener('click', () => navigate('#reports'));
      toast(`Error: ${err.message}`, 'error');
    }
  }

  registerPage('report', {
    mount(root, params) {
      const emailId = params[0];
      if (!emailId) {
        root.innerHTML = `<div class="empty-state"><div class="empty-state-icon">🔍</div><div>No case ID provided</div></div>`;
        return;
      }
      loadAndRender(root, emailId);
    },
  });
})();
