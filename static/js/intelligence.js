/**
 * intelligence.js — Threat Intelligence page
 * MailGuard AI v2.0
 */
'use strict';

(function () {
  const { API, toast, verdictClass, verdictColour, escHtml, truncate, registerPage, navigate } = window.APP;

  registerPage('intelligence', {
    mount(root) {
      root.innerHTML = `
<div class="page-header mb-2">
  <div>
    <h1 class="page-title">Threat Intelligence</h1>
    <p class="page-subtitle">IOC analysis, threat actor profiling, and intelligence artifacts</p>
  </div>
  <span class="intel-source-badge">🧠 LOCAL INTELLIGENCE</span>
</div>

<div class="card mb-2">
  <div class="sandbox-note" style="margin:0">
    ⚠ <strong>LOCAL INTELLIGENCE ONLY</strong> — This platform uses locally-derived threat intelligence from analysed emails.
    No external threat feeds (VirusTotal, MISP, AlienVault OTX, etc.) are currently connected.
    Real-world deployments should integrate live threat intelligence APIs.
  </div>
</div>

<div class="dash-grid-2 mb-2">
  <!-- IOC Summary -->
  <div class="card">
    <div class="card-header"><span class="card-title">📊 Intelligence Overview</span></div>
    <div id="intel-overview">
      <div class="loading-splash" style="min-height:100px"><div class="spinner-ring"></div></div>
    </div>
  </div>
  <!-- Threat actor categories -->
  <div class="card">
    <div class="card-header"><span class="card-title">🎭 Threat Actor Techniques</span></div>
    <div style="display:flex;flex-direction:column;gap:0.5rem">
      ${[
        { name: 'Display Name Spoofing', desc: 'Impersonate trusted contacts by spoofing the display name', mitre: 'T1566.002', icon: '👤' },
        { name: 'Domain Lookalike', desc: 'Register domains that visually resemble legitimate domains (typosquatting)', mitre: 'T1583.001', icon: '🌐' },
        { name: 'Business Email Compromise', desc: 'Compromise or impersonate executive accounts to authorize fraud', mitre: 'T1534', icon: '💸' },
        { name: 'Credential Harvesting', desc: 'Fake login pages to capture user credentials', mitre: 'T1056.003', icon: '🔑' },
        { name: 'URL Obfuscation', desc: 'Shorten, encode or redirect URLs to hide malicious destinations', mitre: 'T1027', icon: '🔗' },
        { name: 'QR Code Phishing', desc: 'Embed malicious URLs in QR codes to bypass URL filters', mitre: 'T1566.001', icon: '📲' },
        { name: 'Malicious Attachments', desc: 'Deliver malware via macro-enabled documents or executables', mitre: 'T1566.001', icon: '📎' },
        { name: 'Reply-To Hijacking', desc: 'Set Reply-To to attacker-controlled address to intercept responses', mitre: 'T1534', icon: '✉' },
      ].map(t => `
        <div style="display:flex;align-items:flex-start;gap:0.75rem;padding:0.5rem 0;border-bottom:1px solid var(--border)">
          <span style="font-size:1.1rem;flex-shrink:0">${t.icon}</span>
          <div style="flex:1;min-width:0">
            <div style="font-size:0.82rem;font-weight:600;color:var(--text-primary)">${escHtml(t.name)}</div>
            <div style="font-size:0.72rem;color:var(--text-secondary)">${escHtml(t.desc)}</div>
          </div>
          <span class="text-xs font-mono" style="background:var(--bg-surface);border:1px solid var(--border);padding:0.1rem 0.4rem;border-radius:3px;color:var(--text-muted);flex-shrink:0">${t.mitre}</span>
        </div>`).join('')}
    </div>
  </div>
</div>

<!-- Recent threat samples -->
<div class="card">
  <div class="card-header">
    <span class="card-title">🚨 Recent Threat Samples</span>
    <span class="text-muted text-small">Click to investigate</span>
  </div>
  <div id="intel-threats">
    <div class="loading-splash" style="min-height:100px"><div class="spinner-ring"></div></div>
  </div>
</div>`;

      // Load dashboard for overview
      API.get('/api/dashboard').then(data => {
        const overviewEl = document.getElementById('intel-overview');
        if (!overviewEl) return;
        const total = data.total || 0;
        const threats = (data.suspicious||0) + (data.high_risk||0) + (data.critical||0);
        const bycat = data.by_category || {};
        overviewEl.innerHTML = `
          <div class="info-grid">
            <div class="info-item"><span class="info-item-label">Total Analyzed</span><span class="info-item-value">${total}</span></div>
            <div class="info-item"><span class="info-item-label">Threats Found</span><span class="info-item-value" style="color:var(--fail)">${threats}</span></div>
            <div class="info-item"><span class="info-item-label">Threat Rate</span><span class="info-item-value">${total ? Math.round(threats/total*100) : 0}%</span></div>
            <div class="info-item"><span class="info-item-label">CRITICAL</span><span class="info-item-value" style="color:var(--critical)">${data.critical||0}</span></div>
            <div class="info-item"><span class="info-item-label">HIGH_RISK</span><span class="info-item-value" style="color:var(--high)">${data.high_risk||0}</span></div>
            <div class="info-item"><span class="info-item-label">SUSPICIOUS</span><span class="info-item-value" style="color:var(--suspicious)">${data.suspicious||0}</span></div>
            <div class="info-item"><span class="info-item-label">BEC</span><span class="info-item-value">${(bycat['BUSINESS_EMAIL_COMPROMISE']||0)+(bycat['PAYMENT_FRAUD']||0)}</span></div>
            <div class="info-item"><span class="info-item-label">Credential Theft</span><span class="info-item-value">${bycat['CREDENTIAL_THEFT']||0}</span></div>
          </div>
          <div class="disclaimer-box" style="margin-top:0.75rem">
            <div class="disclaimer-title">🔌 External Integrations (Not Connected)</div>
            VirusTotal API, AlienVault OTX, MISP, GreyNoise, AbuseIPDB — integrate these for real-world deployment.
          </div>`;
      }).catch(() => {
        const overviewEl = document.getElementById('intel-overview');
        if (overviewEl) overviewEl.innerHTML = '<p class="text-muted text-small">Failed to load overview.</p>';
      });

      // Load threats
      API.get('/api/threats?limit=20').then(data => {
        const el = document.getElementById('intel-threats');
        if (!el) return;
        const threats = (data.threats || []).slice(0, 15);
        if (!threats.length) {
          el.innerHTML = `<div class="empty-state" style="min-height:80px"><div class="empty-state-text">No threats found</div></div>`;
          return;
        }
        el.innerHTML = threats.map(t => {
          const col = verdictColour(t.verdict);
          const icon = { SAFE:'✅', SUSPICIOUS:'⚠️', HIGH_RISK:'🔴', CRITICAL:'💀' }[t.verdict] || '📧';
          return `
            <div class="intel-threat-row" data-id="${escHtml(t.id)}">
              <span style="font-size:1.2rem;flex-shrink:0">${icon}</span>
              <div style="flex:1;min-width:0">
                <div style="font-size:0.8rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(t.from_address||'—',50))}</div>
                <div class="text-xs text-muted" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(t.subject||'(no subject)',60))}</div>
              </div>
              <div style="text-align:right;flex-shrink:0">
                <span class="badge badge-${verdictClass(t.verdict)}">${t.verdict.replace('_',' ')}</span>
                <div class="text-xs text-muted">${escHtml(t.category.replace(/_/g,' '))}</div>
              </div>
            </div>`;
        }).join('');
        el.querySelectorAll('.intel-threat-row').forEach(row => {
          row.addEventListener('click', () => navigate(`#report/${row.dataset.id}`));
        });
      }).catch(() => {});
    },
  });
})();
