/**
 * about.js — About page for MailGuard AI
 */
'use strict';

(function () {
  const { registerPage } = window.APP;

  registerPage('about', {
    mount(root) {
      root.innerHTML = `
<div class="page-header">
  <div>
    <h1 class="page-title">ℹ About MailGuard AI</h1>
    <p class="page-subtitle">AI-Powered Email Threat Detection, Geolocation & Forensic Intelligence Platform</p>
  </div>
  <span class="badge badge-suspicious">SIH 2026 Prototype</span>
</div>

<!-- Hero -->
<div class="card mb-2" style="text-align:center;padding:2rem">
  <div style="font-size:3rem;margin-bottom:0.5rem">🛡</div>
  <h2 style="font-size:1.6rem;font-weight:800;margin-bottom:0.5rem">MailGuard <span style="color:var(--brand)">AI</span></h2>
  <p style="color:var(--text-secondary);max-width:600px;margin:0 auto;font-size:0.9rem;line-height:1.8">
    A professional SOC-grade email forensics platform that combines multi-pillar heuristic analysis, 
    header forensics, URL intelligence, and IP geolocation to deliver explainable threat scores.
    Built for <strong>Smart India Hackathon 2026</strong>.
  </p>
  <div style="margin-top:1rem;display:flex;justify-content:center;gap:0.75rem;flex-wrap:wrap">
    <span class="badge badge-safe">v1.0.0</span>
    <span class="badge badge-suspicious">SIH 2026</span>
    <span class="badge" style="background:rgba(59,158,218,0.12);color:var(--info);border:1px solid rgba(59,158,218,0.3)">FastAPI + SQLite</span>
    <span class="badge" style="background:rgba(59,158,218,0.12);color:var(--info);border:1px solid rgba(59,158,218,0.3)">Vanilla JS SPA</span>
  </div>
</div>

<!-- Feature cards -->
<div class="about-grid mb-2">
  <div class="feature-card">
    <div class="feature-icon">📨</div>
    <div class="feature-title">Header Forensics</div>
    <div class="feature-desc">
      Analyses From vs Reply-To domain mismatch, display-name spoofing, 
      SPF/DKIM/DMARC authentication results, typosquatting detection, 
      and suspicious TLD identification. Max 25 pts.
    </div>
  </div>
  <div class="feature-card">
    <div class="feature-icon">📝</div>
    <div class="feature-title">Content Analysis</div>
    <div class="feature-desc">
      Detects urgency language, credential/password requests, financial/payment patterns, 
      threatening language, generic greetings, and sensitive information solicitation 
      using a curated regex pattern bank. Max 25 pts.
    </div>
  </div>
  <div class="feature-card">
    <div class="feature-icon">🔗</div>
    <div class="feature-title">URL Intelligence</div>
    <div class="feature-desc">
      Extracts and classifies all URLs in the email. Detects IP-based URLs, 
      shortened URLs, suspicious TLDs, lookalike/typosquatting domains, 
      and URL obfuscation techniques. Max 20 pts.
    </div>
  </div>
  <div class="feature-card">
    <div class="feature-icon">🧠</div>
    <div class="feature-title">Behavioural Signals</div>
    <div class="feature-desc">
      Identifies new bank account requests (primary BEC indicator), executive impersonation, 
      confidentiality pressure tactics, and unusual sending patterns 
      (missing To: header). Max 15 pts.
    </div>
  </div>
  <div class="feature-card">
    <div class="feature-icon">🤖</div>
    <div class="feature-title">Heuristic ML Layer</div>
    <div class="feature-desc">
      A transparent weighted multi-pillar combination with non-linear corroboration 
      scoring. Rewards emails that trigger multiple pillars simultaneously.
      <em>Not a pre-trained neural network — clearly documented.</em> Max 15 pts.
    </div>
  </div>
  <div class="feature-card">
    <div class="feature-icon">🌍</div>
    <div class="feature-title">IP Geolocation</div>
    <div class="feature-desc">
      Live IP geolocation via ip-api.com (free, no API key required). 
      Returns country, region, city, ISP, and ASN. 
      Graceful fallback if the service is unreachable — analysis never blocks.
    </div>
  </div>
  <div class="feature-card">
    <div class="feature-icon">📊</div>
    <div class="feature-title">SOC Dashboard</div>
    <div class="feature-desc">
      Real-time threat statistics, 14-day activity timeline, verdict distribution doughnut, 
      category bar chart, and top sender domain analysis. 
      Auto-refreshes every 60 seconds.
    </div>
  </div>
  <div class="feature-card">
    <div class="feature-icon">📋</div>
    <div class="feature-title">Case Management</div>
    <div class="feature-desc">
      Every analysis is persisted to SQLite with a unique case ID. 
      Analysts can update status (New / Reviewed / Quarantined / Cleared) 
      and filter the full case history.
    </div>
  </div>
</div>

<!-- Transparency notice -->
<div class="card mb-2" style="border-left:3px solid var(--suspicious)">
  <div class="card-header">
    <span class="card-title">⚠ Transparency & Honest Capabilities</span>
  </div>
  <div style="font-size:0.85rem;line-height:1.8;color:var(--text-secondary)">
    <p class="mb-1"><strong style="color:var(--text-primary)">What is real:</strong><br>
    Header forensics, content pattern matching, URL extraction and classification, 
    IP geolocation via ip-api.com, SQLite persistence, and the multi-pillar scoring system 
    all perform genuine operations on the submitted email content.
    </p>
    <p class="mb-1"><strong style="color:var(--text-primary)">What is heuristic:</strong><br>
    The "Heuristic ML Layer" is a weighted, non-linear combination of the four other pillars. 
    It is <em>not</em> a pre-trained neural network or deep learning model. 
    This is clearly labelled in every report.
    </p>
    <p class="mb-1"><strong style="color:var(--text-primary)">What is demo:</strong><br>
    The six seed emails inserted at startup are sample/demo data. 
    The geolocation data for those IPs reflects real lookups at the time of seeding.
    </p>
    <p><strong style="color:var(--text-primary)">External dependencies:</strong><br>
    Only ip-api.com is used (free, 45 req/min). No API keys required for core functionality. 
    All analysis works offline if geolocation is unavailable.
    </p>
  </div>
</div>

<!-- Tech stack -->
<div class="card">
  <div class="card-header"><span class="card-title">🛠 Technology Stack</span></div>
  <div class="info-grid">
    <div class="info-item"><span class="info-item-label">Backend</span><span class="info-item-value">Python 3.10+ / FastAPI</span></div>
    <div class="info-item"><span class="info-item-label">Database</span><span class="info-item-value">SQLite 3 (WAL mode)</span></div>
    <div class="info-item"><span class="info-item-label">Frontend</span><span class="info-item-value">Vanilla JS SPA (no framework)</span></div>
    <div class="info-item"><span class="info-item-label">Charts</span><span class="info-item-value">Chart.js 4.4</span></div>
    <div class="info-item"><span class="info-item-label">Geolocation</span><span class="info-item-value">ip-api.com (free tier)</span></div>
    <div class="info-item"><span class="info-item-label">Detection</span><span class="info-item-value">Multi-pillar heuristic engine</span></div>
    <div class="info-item"><span class="info-item-label">Server</span><span class="info-item-value">Uvicorn ASGI</span></div>
    <div class="info-item"><span class="info-item-label">Routing</span><span class="info-item-value">Single-origin (no CORS)</span></div>
  </div>
</div>`;
    },
  });
})();
