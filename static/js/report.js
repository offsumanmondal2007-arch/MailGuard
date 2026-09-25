/**
 * report.js — Full Email Forensic Investigation Page
 * MailGuard AI v2.0
 * Route: #report/{id}
 */
'use strict';

(function () {
  const { API, toast, verdictClass, verdictColour, scoreColour, actionClass, actionColour,
          checkIcon, formatTimestamp, formatTime, escHtml, registerPage, navigate, buildAuthCards } = window.APP;

  function truncate(str, max) {
    max = max || 60;
    if (!str) return '—';
    return str.length > max ? str.slice(0, max) + '…' : str;
  }

  // ── Build forensic timeline ────────────────────────────────────
  function renderTimeline(timeline) {
    if (!timeline || !timeline.length) {
      return `<p class="text-muted text-small">No timeline data available.</p>`;
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

  // ── Build full investigation report ────────────────────────────
  function renderReport(r) {
    const vc  = verdictClass(r.verdict);
    const col = verdictColour(r.verdict);
    const sc  = scoreColour(r.score);
    const bd  = r.breakdown || {};
    const geo = r.geo || {};
    const forensics = r.forensics || {};
    const decision = r.decision || {};
    const timeline = r.timeline || [];

    const action = decision.action || (r.score >= 80 ? 'BLOCK' : r.score >= 60 ? 'QUARANTINE' : r.score >= 30 ? 'FLAG' : 'DELIVER');
    const ac  = actionClass(action);
    const aCol = actionColour(action);

    const pillars = [
      { key: 'header_forensics', label: 'Header Forensics',    icon: '📨', max: 25 },
      { key: 'content_analysis', label: 'Content Analysis',    icon: '📝', max: 25 },
      { key: 'url_intelligence', label: 'URL Intelligence',    icon: '🔗', max: 20 },
      { key: 'behavioural',      label: 'Behavioural Signals', icon: '🧠', max: 15 },
      { key: 'ml_heuristic',     label: 'Heuristic Layer',     icon: '⚙',  max: 15 },
    ];

    const breakdownRows = pillars.map(p => {
      const pil = bd[p.key] || { score: 0, max: p.max };
      const pct = pil.max ? Math.round(pil.score / pil.max * 100) : 0;
      const barCol = pct >= 70 ? '#dc2626' : pct >= 40 ? '#f59e0b' : '#22c55e';
      return `
        <div class="breakdown-row">
          <span class="breakdown-label">${p.icon} ${escHtml(p.label)}</span>
          <div class="breakdown-bar-track"><div class="breakdown-bar-fill" style="width:${pct}%;background:${barCol}"></div></div>
          <span class="breakdown-score" style="color:${barCol}">${pil.score}/${pil.max}</span>
        </div>`;
    }).join('');

    // Exact score math
    const p1 = (bd.header_forensics || {}).score || 0;
    const p2 = (bd.content_analysis || {}).score || 0;
    const p3 = (bd.url_intelligence || {}).score || 0;
    const p4 = (bd.behavioural || {}).score || 0;
    const p5 = (bd.ml_heuristic || {}).score || 0;

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
        <details style="border:1px solid var(--border);border-radius:var(--radius);padding:0.6rem 0.85rem;margin-bottom:0.5rem">
          <summary style="cursor:pointer;font-size:0.82rem;font-weight:600">${p.icon} ${p.label} — ${pil.score || 0}/${pil.max || 15} pts</summary>
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
        <div class="info-item"><span class="info-item-label">ASN/Org</span><span class="info-item-value">${escHtml(geo.asn)}</span></div>
      </div>
      <p class="text-xs text-muted mt-1">⚠ IP geolocation is approximate — this is NOT the physical location of the attacker.</p>` :
      `<p class="text-muted text-small">${escHtml(geo.note || 'IP Geolocation not available')}</p>`;

    const statusOptions = ['new', 'reviewed', 'quarantined', 'cleared'];

    const urlsHtml = (forensics.urls_found || []).length ? `
      <div>
        <div class="section-title">URLs Found (${forensics.urls_found.length})</div>
        <div style="display:flex;flex-wrap:wrap;gap:0.4rem">
          ${forensics.urls_found.map(u => {
            const susp = (forensics.suspicious_urls || []).includes(u);
            return `<span class="tag" style="${susp ? 'color:var(--fail);border-color:rgba(239,68,68,0.4)' : ''}" title="${escHtml(u)}">${escHtml(truncate(u, 65))}</span>`;
          }).join('')}
        </div>
      </div>` : '<p class="text-muted text-small">No URLs found.</p>';

    return `
<span class="back-link" id="back-btn">← Back to Investigation List</span>

<div class="report-layout">

  <!-- SIDEBAR -->
  <div class="report-sidebar">

    <!-- Case ID + Score -->
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
          <span class="info-item-label">Decision</span>
          <span class="info-item-value"><span class="badge ${ac}">${action}</span></span>
        </div>
        <div class="info-item mb-1">
          <span class="info-item-label">Confidence</span>
          <span class="info-item-value">${Math.round(r.confidence*100)}%
            <div class="confidence-bar mt-1"><div class="confidence-fill" style="width:${Math.round(r.confidence*100)}%;background:${col}"></div></div>
          </span>
        </div>
        <div class="info-item mb-1">
          <span class="info-item-label">Analyzed</span>
          <span class="info-item-value text-small">${formatTimestamp(r.timestamp)}</span>
        </div>
        <div class="info-item">
          <span class="info-item-label">Analyst Status</span>
          <div class="status-btn-group" id="status-buttons" style="margin-top:0.4rem">
            ${statusOptions.map(s => `
              <button class="btn btn-sm ${s===r.status?'btn-primary':'btn-secondary'}" data-status="${s}" id="status-${s}">${s}</button>`).join('')}
          </div>
        </div>
      </div>
    </div>

    <!-- Recommended action -->
    <div class="action-box ${vc}">
      <strong>Recommended Action</strong><br>
      <span style="font-size:0.78rem">${escHtml(r.recommended_action)}</span>
    </div>

    <!-- Email metadata -->
    <div class="card">
      <div class="card-header"><span class="card-title">📧 Email Metadata</span></div>
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
      <div class="info-item mb-1">
        <span class="info-item-label">Sender IP</span>
        <span class="info-item-value font-mono text-small">${escHtml(r.sender_ip || '—')}</span>
      </div>
      <div class="info-item">
        <span class="info-item-label">From Domain</span>
        <span class="info-item-value font-mono">${escHtml(forensics.from_domain || '—')}</span>
      </div>
    </div>

    <!-- Quick flags -->
    <div class="card">
      <div class="card-header"><span class="card-title">🚩 Detection Flags</span></div>
      <div style="display:flex;flex-direction:column;gap:0.4rem">
        ${[
          { label: 'Domain Mismatch',      val: forensics.domain_mismatch },
          { label: 'Display-Name Spoofing',val: forensics.display_name_spoofing },
          { label: 'Typosquatting',        val: forensics.typosquatting },
          { label: 'Suspicious TLD',       val: forensics.suspicious_tld },
          { label: 'SPF Failed',           val: forensics.spf === 'fail' },
          { label: 'DKIM Failed',          val: forensics.dkim === 'fail' },
          { label: 'DMARC Failed',         val: forensics.dmarc === 'fail' },
          { label: 'Malicious URLs',       val: (forensics.suspicious_urls || []).length > 0 },
        ].map(f => `
          <div style="display:flex;align-items:center;justify-content:space-between;font-size:0.78rem">
            <span class="text-secondary">${f.label}</span>
            <span style="color:${f.val ? 'var(--fail)' : 'var(--safe)'};font-weight:700">${f.val ? '✗ YES' : '✓ NO'}</span>
          </div>`).join('')}
      </div>
    </div>

  </div>

  <!-- MAIN CONTENT -->
  <div class="report-main">

    <!-- WHY this was blocked -->
    <div class="verdict-decision-box ${action.toLowerCase()}-box">
      <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem">
        <div>
          <div class="verdict-decision-title" style="color:${aCol}">
            WHY THIS EMAIL WAS ${action}
          </div>
          <div class="verdict-decision-reasons">
            ${(decision.justifications || []).map(j => `• ${escHtml(j)}`).join('<br>') || '• Score-based decision applied'}
          </div>
        </div>
        <span class="badge ${ac}" style="font-size:0.85rem;padding:0.3rem 0.85rem">${action}</span>
      </div>
    </div>

    <!-- Detection reasons -->
    <div class="card">
      <div class="card-header"><span class="card-title">🚨 Threat Detection Reasons</span></div>
      ${reasonsHtml}
    </div>

    <!-- Score breakdown (exact math) -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">📊 Risk Score Breakdown</span>
        <span class="text-muted text-small">
          <span class="font-mono" style="color:var(--text-secondary)">${p1}+${p2}+${p3}+${p4}+${p5} = </span>
          <strong style="color:${sc}">${r.score}/100</strong>
        </span>
      </div>
      ${breakdownRows}
      <p class="text-xs text-muted mt-1">Pillars: Header Forensics (25) + Content (25) + URL (20) + Behaviour (15) + Heuristic (15) = 100</p>
    </div>

    <!-- Email Authentication -->
    <div class="card">
      <div class="card-header"><span class="card-title">🔐 Email Authentication (SPF / DKIM / DMARC)</span></div>
      ${buildAuthCards(forensics)}
    </div>

    <!-- Header forensics detail -->
    <div class="card">
      <div class="card-header"><span class="card-title">📨 Header Forensics</span></div>
      <div class="info-grid mb-1">
        <div class="info-item"><span class="info-item-label">From Domain</span><span class="info-item-value font-mono">${escHtml(forensics.from_domain||'—')}</span></div>
        <div class="info-item"><span class="info-item-label">Reply-To Domain</span><span class="info-item-value font-mono">${escHtml(forensics.reply_to_domain||'—')}</span></div>
        <div class="info-item"><span class="info-item-label">Domain Mismatch</span><span class="info-item-value" style="color:${forensics.domain_mismatch?'var(--fail)':'var(--safe)'}">${forensics.domain_mismatch?'⚠ YES':'✓ NO'}</span></div>
        <div class="info-item"><span class="info-item-label">Display Name</span><span class="info-item-value">${escHtml(forensics.display_name||'—')}</span></div>
        <div class="info-item"><span class="info-item-label">Display-Name Spoof</span><span class="info-item-value" style="color:${forensics.display_name_spoofing?'var(--fail)':'var(--safe)'}">${forensics.display_name_spoofing?'⚠ YES':'✓ NO'}</span></div>
        <div class="info-item"><span class="info-item-label">Typosquatting</span><span class="info-item-value" style="color:${forensics.typosquatting?'var(--fail)':'var(--safe)'}">${forensics.typosquatting?'⚠ YES':'✓ NO'}</span></div>
        <div class="info-item"><span class="info-item-label">Suspicious TLD</span><span class="info-item-value" style="color:${forensics.suspicious_tld?'var(--fail)':'var(--safe)'}">${forensics.suspicious_tld?'⚠ YES':'✓ NO'}</span></div>
        <div class="info-item"><span class="info-item-label">Mail Relay Hops</span><span class="info-item-value">${forensics.received_hops||0}</span></div>
      </div>
      <div class="divider"></div>
      ${urlsHtml}
    </div>

    <!-- Per-pillar forensic checks (collapsible) -->
    <div class="card">
      <div class="card-header"><span class="card-title">🔬 Detailed Forensic Checks</span></div>
      ${pillarChecksSections || '<p class="text-muted text-small">No detailed check data available.</p>'}
    </div>

    <!-- Geolocation -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">🌍 Sender IP Geolocation</span>
        ${geo.available ? '<span class="badge badge-safe">Live Data</span>' : '<span class="text-muted text-small">Unavailable</span>'}
      </div>
      ${geoHtml}
    </div>

    <!-- Forensic Timeline -->
    <div class="card">
      <div class="card-header">
        <span class="card-title">⏱ Forensic Processing Timeline</span>
        <span class="text-muted text-small">${timeline.length} events</span>
      </div>
      ${renderTimeline(timeline)}
    </div>

    <!-- Raw email body (collapsible) -->
    ${r.body ? `
    <div class="card">
      <details>
        <summary style="cursor:pointer;font-size:0.82rem;font-weight:600">📄 Raw Email Body</summary>
        <pre style="margin-top:0.75rem;font-size:0.75rem;color:var(--text-secondary);white-space:pre-wrap;word-break:break-all;max-height:350px;overflow-y:auto;background:var(--bg-input);padding:0.75rem;border-radius:var(--radius);font-family:'JetBrains Mono',monospace">${escHtml(r.body)}</pre>
      </details>
    </div>` : ''}

    <!-- Raw headers (collapsible) -->
    ${r.headers ? `
    <div class="card">
      <details>
        <summary style="cursor:pointer;font-size:0.82rem;font-weight:600">📋 Raw Email Headers</summary>
        <pre style="margin-top:0.75rem;font-size:0.72rem;color:var(--text-secondary);white-space:pre-wrap;word-break:break-all;max-height:250px;overflow-y:auto;background:var(--bg-input);padding:0.75rem;border-radius:var(--radius);font-family:'JetBrains Mono',monospace">${escHtml(r.headers)}</pre>
      </details>
    </div>` : ''}

  </div>
</div>`;
  }

  // ── Load and display report ────────────────────────────────────
  async function loadAndRender(root, emailId) {
    root.innerHTML = `<div class="loading-splash"><div class="spinner-ring"></div><p>Loading investigation…</p></div>`;
    try {
      const record = await API.get(`/api/emails/${emailId}`);
      root.innerHTML = renderReport(record);

      document.getElementById('back-btn').addEventListener('click', () => navigate('#reports'));

      // Status update buttons
      const statusBtns = document.querySelectorAll('#status-buttons button');
      statusBtns.forEach(btn => {
        btn.addEventListener('click', async () => {
          const newStatus = btn.dataset.status;
          try {
            await API.patch(`/api/emails/${emailId}/status`, { status: newStatus });
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
        <div class="card" style="margin-top:1rem">
          <div class="error-state">
            <div style="font-size:2rem">⚠</div>
            <strong>Failed to load investigation</strong>
            <p class="text-small">${escHtml(err.message)}</p>
            <button class="btn btn-secondary btn-sm mt-1" onclick="window.APP.navigate('#reports')">Back to Reports</button>
          </div>
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
