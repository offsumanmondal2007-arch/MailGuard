/**
 * about.js — About page
 * MailGuard AI v2.0 — SIH 2026 Project
 */
'use strict';

(function () {
  const { registerPage, escHtml } = window.APP;

  registerPage('about', {
    mount(root) {
      root.innerHTML = `
<div class="about-hero">
  <div class="about-hero-icon">🛡</div>
  <h1 class="about-hero-title">MailGuard AI</h1>
  <div class="about-hero-sub">AI-Powered Pre-Delivery Email Security Gateway &amp; Forensic Intelligence Platform</div>
  <div style="display:flex;align-items:center;justify-content:center;gap:0.75rem;margin-top:1rem;flex-wrap:wrap">
    <span class="badge badge-safe">v2.0.0</span>
    <span class="badge badge-safe">SIH 2026 Project</span>
    <span class="badge badge-suspicious">Academic / Research Use</span>
  </div>
</div>

<div class="card mb-2">
  <div class="card-header"><span class="card-title">🎯 Project Mission</span></div>
  <p style="font-size:0.85rem;color:var(--text-secondary);line-height:1.7">
    MailGuard AI is a Smart India Hackathon 2026 project that demonstrates a modern pre-delivery email security gateway
    with explainable AI-powered threat detection, IP geolocation, forensic investigation capabilities, and a SOC-grade dashboard.
    The platform analyses every email <strong>before delivery</strong> and provides a transparent, explainable security decision
    with full forensic evidence — not just a score.
  </p>
</div>

<div class="feature-grid mb-2">
  ${[
    { icon:'⚙', title:'Pre-Delivery Security Gateway', desc:'Emails are inspected before reaching the recipient. No post-delivery cleanup.', proto: false },
    { icon:'🔬', title:'5-Pillar Heuristic Engine', desc:'Header Forensics, Content Analysis, URL Intelligence, Behavioural Analysis, Heuristic ML.', proto: false },
    { icon:'🔐', title:'SPF / DKIM / DMARC Analysis', desc:'Parses all three email authentication protocols with detailed fail reasoning.', proto: false },
    { icon:'💸', title:'BEC Detection', desc:'Multi-signal detection: display name spoofing, urgency, payment keywords, executive impersonation.', proto: false },
    { icon:'🔑', title:'Credential Phishing Detection', desc:'Identifies login-harvesting attempts, lookalike domains, and fake password reset flows.', proto: false },
    { icon:'🌐', title:'IP Geolocation', desc:'Real sender IP location via ip-api.com with ISP, ASN, and country data.', proto: false },
    { icon:'📊', title:'Explainable Scoring', desc:'Every score shows exact pillar contributions: P1+P2+P3+P4+P5 = Total/100.', proto: false },
    { icon:'⏱', title:'Forensic Timeline', desc:'Step-by-step processing record showing every check and its result with timestamps.', proto: false },
    { icon:'🔗', title:'URL Analysis', desc:'Static heuristic URL analysis: IP-URLs, typosquatting, shortened URLs, suspicious TLDs.', proto: false },
    { icon:'📎', title:'Attachment Analysis', desc:'Static file type analysis: executable detection, double extensions, macro-enabled files.', proto: true },
    { icon:'📲', title:'QR Code Phishing', desc:'Architecture ready for QR code URL extraction from images. Library integration pending.', proto: true },
    { icon:'⚙', title:'Security Policy Engine', desc:'10 configurable BLOCK/QUARANTINE/FLAG/DELIVER policies with toggle controls.', proto: true },
  ].map(f => `
    <div class="feature-card">
      <div class="feature-icon">${f.icon}</div>
      <div class="feature-title">
        ${f.title}
        ${f.proto ? '<span class="prototype-tag">PROTOTYPE</span>' : ''}
      </div>
      <div class="feature-desc">${escHtml(f.desc)}</div>
    </div>`).join('')}
</div>

<!-- Technology stack -->
<div class="dash-grid-2 mb-2">
  <div class="card">
    <div class="card-header"><span class="card-title">🛠 Technology Stack</span></div>
    ${[
      { name: 'FastAPI (Python)', role: 'Backend API server and email analysis engine', icon: '🐍' },
      { name: 'SQLite + WAL', role: 'Persistent email storage with thread-safe access', icon: '🗄' },
      { name: 'Vanilla JS SPA', role: 'Hash-based routing without a framework', icon: '⚡' },
      { name: 'Chart.js 4', role: 'Dashboard visualization and data charts', icon: '📈' },
      { name: 'Inter + JetBrains Mono', role: 'Typography (Google Fonts)', icon: '🔤' },
      { name: 'ip-api.com', role: 'Real-time IP geolocation API', icon: '🌍' },
      { name: 'Regex Heuristics', role: 'Pattern matching for threats, URLs, BEC signals', icon: '🔎' },
    ].map(t => `
      <div style="display:flex;align-items:center;gap:0.75rem;padding:0.45rem 0;border-bottom:1px solid rgba(255,255,255,0.04)">
        <span style="font-size:1rem;flex-shrink:0">${t.icon}</span>
        <div>
          <div style="font-size:0.82rem;font-weight:600">${escHtml(t.name)}</div>
          <div class="text-xs text-muted">${escHtml(t.role)}</div>
        </div>
      </div>`).join('')}
  </div>

  <div class="card">
    <div class="card-header"><span class="card-title">📋 Score Calculation</span></div>
    <p class="text-xs text-muted mb-1">Total threat score = sum of 5 independent pillars, capped at 100.</p>
    ${[
      { pillar: 'Header Forensics',    max: 25, checks: 'SPF, DKIM, DMARC, reply-to mismatch, display-name spoofing, typosquatting, routing anomalies' },
      { pillar: 'Content Analysis',    max: 25, checks: 'Urgency keywords, phishing phrases, financial demands, credential requests, lottery spam' },
      { pillar: 'URL Intelligence',    max: 20, checks: 'Malicious URL patterns, IP-based URLs, shortened URLs, suspicious TLDs, redirects' },
      { pillar: 'Behavioural Signals', max: 15, checks: 'BEC patterns, executive impersonation, wire transfer requests, gift card scams' },
      { pillar: 'Heuristic ML Layer', max: 15, checks: 'Combined feature scoring, cross-pillar correlation, anomaly detection' },
    ].map(p => `
      <div style="margin-bottom:0.65rem">
        <div style="display:flex;justify-content:space-between;font-size:0.8rem;font-weight:600;margin-bottom:0.25rem">
          <span>${p.pillar}</span>
          <span style="color:var(--text-muted)">max ${p.max} pts</span>
        </div>
        <div class="text-xs text-muted">${escHtml(p.checks)}</div>
      </div>`).join('')}
    <div class="divider"></div>
    <div class="font-mono text-xs" style="color:var(--text-secondary)">
      Score = Header(25) + Content(25) + URL(20) + Behaviour(15) + Heuristic(15) = 100
    </div>
  </div>
</div>

<!-- Disclaimer -->
<div class="disclaimer-box" role="note" aria-label="Project disclaimer">
  <div class="disclaimer-title">&#9888; Academic Research Prototype — Disclaimer</div>
  <ul style="list-style:none;display:flex;flex-direction:column;gap:0.4rem">
    <li>&#128300; This is an <strong>academic research project</strong> for SIH 2026. Not a production security product.</li>
    <li>&#9888; <strong>No file sandbox</strong> — attachment analysis is static metadata inspection only. Files are not executed.</li>
    <li>&#128225; <strong>No live threat feeds</strong> — threat intelligence is derived from locally analysed emails only.</li>
    <li>&#127758; <strong>IP geolocation is approximate</strong> — it shows the ISP location, NOT the attacker's physical location.</li>
    <li>&#129302; <strong>No real ML model</strong> — threat scoring uses expert-designed heuristic rules, labelled as "Heuristic ML Layer".</li>
    <li>&#128274; <strong>No link following</strong> — URL analysis checks patterns and heuristics only; URLs are not fetched or browsed.</li>
    <li>&#9881; <strong>Policy engine is in-memory</strong> — policy changes reset on server restart.</li>
    <li>&#128683; <strong>No cookies or tracking</strong> — this platform sets no first-party cookies. See <a href="#cookies">Cookie Policy</a>.</li>
    <li>&#128683; <strong>No fake reviews or unsupported claims</strong> — all stated capabilities reflect the actual prototype implementation.</li>
  </ul>
  <div style="margin-top:1rem;padding-top:0.75rem;border-top:1px solid rgba(245,158,11,0.2);font-size:0.76rem;color:var(--text-muted);display:flex;flex-wrap:wrap;gap:0.75rem">
    <strong style="color:var(--text-secondary)">Legal:</strong>
    <a href="#privacy">Privacy Policy</a>
    <a href="#terms">Terms &amp; Conditions</a>
    <a href="#cookies">Cookie Policy</a>
    <a href="#refund">Refund Policy</a>
  </div>
</div>`;
    },
  });
})();
