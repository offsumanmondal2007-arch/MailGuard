/**
 * urls.js — Standalone URL Analysis page
 * MailGuard AI v2.0
 */
'use strict';

(function () {
  const { API, toast, escHtml, registerPage } = window.APP;

  const DEMO_URLS = [
    { label: '✅ Safe Google',    url: 'https://www.google.com/search?q=mailguard' },
    { label: '🔴 IP-based URL',  url: 'http://185.220.101.45/paypal/verify' },
    { label: '🎣 Phishing',      url: 'https://paypa1-secure.tk/verify-account' },
    { label: '🔗 Shortened',     url: 'http://bit.ly/3xR9pQZ' },
    { label: '⚠ Typosquat',     url: 'https://micros0ft-365.top/login' },
    { label: '💀 Malicious TLD', url: 'https://login-verify.hdfc-bank-secure.ml/account' },
    { label: '🔑 Credential',    url: 'https://aws-account-verify.tk/signin?redirect=root' },
    { label: '📦 Redirect',      url: 'https://tracking-portal.xyz/?redirect=http://evil.ml' },
  ];

  function renderVerdictBadge(verdict, score) {
    const map = {
      MALICIOUS:  { cls: 'badge-critical', icon: '💀' },
      SUSPICIOUS: { cls: 'badge-suspicious', icon: '⚠️' },
      LOW_RISK:   { cls: 'badge-high', icon: '🟡' },
      SAFE:       { cls: 'badge-safe', icon: '✅' },
      UNKNOWN:    { cls: 'badge-suspicious', icon: '❓' },
    };
    const { cls, icon } = map[verdict] || map.UNKNOWN;
    return `<span class="badge ${cls}">${icon} ${verdict.replace('_',' ')}</span>`;
  }

  function renderIndicators(indicators) {
    if (!indicators || !indicators.length) {
      return '<p class="text-muted text-small">No threat indicators detected.</p>';
    }
    return indicators.map(ind => `
      <div class="url-indicator-row">
        <span class="url-indicator-type">${escHtml(ind.type)}</span>
        <span class="url-indicator-detail">${escHtml(ind.detail)}</span>
        <span class="url-indicator-risk">+${ind.risk || 0}</span>
      </div>`).join('');
  }

  function renderResult(data) {
    const score = data.risk_score || 0;
    const scoreCol = score >= 70 ? '#dc2626' : score >= 40 ? '#f59e0b' : score >= 15 ? '#ef4444' : '#22c55e';
    const resultEl = document.getElementById('url-result');
    if (!resultEl) return;

    resultEl.innerHTML = `
      <div class="url-result-card">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;margin-bottom:0.75rem">
          <div>
            <div style="font-size:0.72rem;color:var(--text-muted);margin-bottom:0.25rem">ANALYZED URL</div>
            <div class="font-mono" style="font-size:0.82rem;color:var(--text-primary);word-break:break-all;max-width:400px">${escHtml(data.url)}</div>
          </div>
          <div style="display:flex;flex-direction:column;align-items:flex-end;gap:0.4rem">
            ${renderVerdictBadge(data.verdict, score)}
            <div style="font-size:0.68rem;color:var(--text-muted)">Risk: <strong style="color:${scoreCol}">${score}/100</strong></div>
          </div>
        </div>
        <div class="divider"></div>
        <div style="font-size:0.8rem;font-weight:600;color:var(--text-secondary);margin-bottom:0.5rem">Threat Indicators (${(data.indicators||[]).length})</div>
        ${renderIndicators(data.indicators)}
        <div class="divider"></div>
        <div class="sandbox-note">
          ⚠ ${escHtml(data.note || 'Static analysis only')}
        </div>
      </div>`;
  }

  registerPage('urls', {
    mount(root) {
      root.innerHTML = `
<div class="page-header mb-2">
  <div>
    <h1 class="page-title">URL Analysis</h1>
    <p class="page-subtitle">Analyze individual URLs for phishing, malware distribution, or suspicious patterns</p>
  </div>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--gap);align-items:start">
  <div>
    <div class="card mb-2">
      <div class="card-header"><span class="card-title">🔗 Demo URLs</span><span class="text-muted text-small">Click to load</span></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.4rem">
        ${DEMO_URLS.map((d, i) => `
          <button class="demo-btn" data-i="${i}" type="button" style="font-size:0.75rem">
            <span class="demo-btn-label">${escHtml(d.label)}</span>
            <span class="demo-btn-sub" style="font-size:0.65rem;font-family:'JetBrains Mono',monospace">${escHtml(d.url.slice(0,40))}…</span>
          </button>`).join('')}
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="card-title">🔍 Analyze URL</span></div>
      <div class="form-group">
        <label class="form-label" for="url-input">URL to Analyze</label>
        <input type="text" id="url-input" class="form-control font-mono" placeholder="https://example.com/path?query=value" />
      </div>
      <button class="btn btn-primary" id="url-analyze-btn">
        <span id="url-btn-icon">🔍</span>
        <span id="url-btn-text">Analyze URL</span>
      </button>
    </div>
    <div class="card mt-1" style="margin-top:0.85rem">
      <div class="card-header"><span class="card-title">ℹ About URL Analysis</span></div>
      <ul style="font-size:0.78rem;color:var(--text-secondary);display:flex;flex-direction:column;gap:0.4rem;list-style:none">
        <li>🔬 <strong>Static heuristic analysis</strong> — No live browsing or link following</li>
        <li>⚠ <strong>No sandbox</strong> — URL destination is not fetched or executed</li>
        <li>🎯 Checks: IP-based URLs, shortened URLs, suspicious TLDs, typosquatting, credential keywords, obfuscation</li>
        <li>📊 Risk score: 0 (safe) → 100 (critical)</li>
        <li>🌐 For real URL safety: use VirusTotal or Google Safe Browsing</li>
      </ul>
    </div>
  </div>
  <div>
    <div id="url-result">
      <div class="empty-state" style="min-height:200px;border:1px dashed var(--border);border-radius:var(--radius-lg)">
        <div class="empty-state-icon">🔗</div>
        <div class="empty-state-text">URL analysis results will appear here</div>
        <p class="text-muted text-small">Enter a URL or select a demo to analyze</p>
      </div>
    </div>
  </div>
</div>`;

      // Demo buttons
      const demoUrls = DEMO_URLS;
      root.querySelectorAll('.demo-btn[data-i]').forEach(btn => {
        btn.addEventListener('click', () => {
          const url = demoUrls[parseInt(btn.dataset.i)].url;
          document.getElementById('url-input').value = url;
          toast('Demo URL loaded', 'success', 1500);
        });
      });

      // Analyze button
      document.getElementById('url-analyze-btn')?.addEventListener('click', async () => {
        const url = document.getElementById('url-input').value.trim();
        if (!url) { toast('Please enter a URL', 'warn'); return; }
        const btn  = document.getElementById('url-analyze-btn');
        const icon = document.getElementById('url-btn-icon');
        const text = document.getElementById('url-btn-text');
        btn.disabled = true;
        icon.textContent = '⏳';
        text.textContent = 'Analyzing…';
        try {
          const data = await API.post('/api/url/analyze', { url });
          renderResult(data);
          toast('URL analysis complete', 'success');
        } catch (err) {
          toast(`Error: ${err.message}`, 'error');
        } finally {
          btn.disabled = false;
          icon.textContent = '🔍';
          text.textContent = 'Analyze URL';
        }
      });

      // Allow Enter key
      document.getElementById('url-input')?.addEventListener('keydown', e => {
        if (e.key === 'Enter') document.getElementById('url-analyze-btn')?.click();
      });
    },
  });
})();
