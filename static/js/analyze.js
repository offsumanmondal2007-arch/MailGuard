/**
 * analyze.js — Email submission and result display page
 * MailGuard AI
 */
'use strict';

(function () {
  const { API, toast, verdictClass, verdictColour, scoreColour, checkIcon,
          formatTimestamp, escHtml, registerPage, navigate } = window.APP;

  // ── Demo email presets ──────────────────────────────────────
  const DEMOS = [
    {
      label:    '✅ Safe Internal',
      sub:      'Low-risk corporate email',
      subject:  'Q3 Team Lunch — Friday 12pm',
      from:     'Alice Johnson <alice.johnson@acme-corp.com>',
      replyTo:  'alice.johnson@acme-corp.com',
      ip:       '',
      headers:  'Received: from mail.acme-corp.com ([10.0.0.5])\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass\nTo: team@acme-corp.com',
      body:     'Hi team,\n\nJust a reminder that we have our Q3 team lunch this Friday at 12pm in the main conference room. Please RSVP by Thursday EOD.\n\nBest,\nAlice',
    },
    {
      label:    '🎣 Phishing',
      sub:      'PayPal account suspension spoof',
      subject:  'Your PayPal account has been SUSPENDED - Verify Immediately',
      from:     'PayPal Security <security@paypa1-secure.tk>',
      replyTo:  'noreply@paypal-helpdesk.ml',
      ip:       '185.220.101.45',
      headers:  'Received: from unknown ([185.220.101.45])\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail',
      body:     'Dear Customer,\n\nURGENT: Your PayPal account has been suspended. Verify immediately or your account will be permanently terminated.\n\nClick here to verify your account and enter your username and password:\nhttp://185.220.101.45/paypal/verify\n\nFailure to act within 24 hours will result in legal action.',
    },
    {
      label:    '💸 BEC Fraud',
      sub:      'CEO wire transfer request',
      subject:  'Confidential — Urgent Wire Transfer Required',
      from:     '"Robert Chen - CEO" <robert.chen.ceo@acme-corp-hq.xyz>',
      replyTo:  'rchen.payments@gmail.com',
      ip:       '91.108.4.1',
      headers:  'Received: from smtp.gmail.com ([91.108.4.1])\nAuthentication-Results: spf=softfail; dkim=pass; dmarc=fail',
      body:     'Hi Sarah,\n\nI need you to process a confidential wire transfer today. Transfer $87,500 to our new partner:\nBank: First National Trust\nRouting Number: 021000021\nAccount Number: 7829301847\n\nPlease keep this confidential — do not discuss with anyone. I am in a board meeting. Confirm once completed.\n\nRobert Chen\nChief Executive Officer',
    },
    {
      label:    '🔑 Credential Theft',
      sub:      'Microsoft 365 password expiry',
      subject:  'Action Required: Your Microsoft 365 Password Expires Today',
      from:     'Microsoft IT Support <support@micros0ft-365.top>',
      replyTo:  'support@micros0ft-365.top',
      ip:       '103.224.182.9',
      headers:  'Received: from smtp.micros0ft-365.top ([103.224.182.9])\nAuthentication-Results: spf=fail; dkim=fail',
      body:     'Dear User,\n\nYour Microsoft 365 account password expires today. Sign in immediately to update your credentials:\nhttps://micros0ft-365.top/m365/login\n\nFailure to update within 24 hours will disable your account and you will lose all access.',
    },
    {
      label:    '⚠ Suspicious Reset',
      sub:      'Unknown password reset link',
      subject:  'Password Reset Request for Your Account',
      from:     'noreply@accounts-reset-portal.download',
      replyTo:  '',
      ip:       '78.46.113.7',
      headers:  'Received: from mail.accounts-reset-portal.download ([78.46.113.7])\nAuthentication-Results: spf=softfail; dkim=fail',
      body:     'Hello,\n\nWe received a request to reset your account password.\nClick the link below:\nhttp://bit.ly/3xR9pQZ\n\nIf you did not request this, ignore this email.',
    },
    {
      label:    '👤 Exec Impersonation',
      sub:      'Gift card social engineering',
      subject:  'Personal Request — Need Your Help Urgently',
      from:     '"Dr. Meena Sharma - Managing Director" <md@globaltech-inc.cf>',
      replyTo:  'meena.sharma.md2026@gmail.com',
      ip:       '162.158.102.10',
      headers:  'Received: from smtp.outbound.cf ([162.158.102.10])\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail',
      body:     'Hi,\n\nI need your immediate and confidential assistance. I am in a board meeting — please keep this strictly between us.\n\nPurchase 10 Amazon gift cards worth INR 5,000 each and share the redemption codes via this email immediately. I will reimburse from petty cash. Do not mention this to HR or Finance — this is a confidential executive matter.',
    },
    {
      label:    '🎰 Lottery Spam',
      sub:      'Sweepstakes prize winner claim',
      subject:  'CONGRATULATIONS!!! YOU WON $1,000,000!!!',
      from:     'Lucky Rewards <rewards@promotions-direct.top>',
      replyTo:  'claim@promotions-direct.top',
      ip:       '194.26.29.11',
      headers:  'Received: from mail.promotions-direct.top ([194.26.29.11])\nAuthentication-Results: spf=fail; dkim=fail',
      body:     'You have been selected as our lucky winner!\nClaim your prize immediately.\nLimited time offer!!!\nClick now to receive your reward:\nhttp://promotions-direct.top/claim-prize',
    },
    {
      label:    '📄 Normal Invoice',
      sub:      'Legitimate portal billing notice',
      subject:  'Your Monthly Invoice',
      from:     'Billing Department <billing@acme-services.com>',
      replyTo:  'billing@acme-services.com',
      ip:       '',
      headers:  'Received: from mail.acme-services.com ([10.0.0.8])\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass',
      body:     'Your monthly invoice is now available in your normal customer portal.\nYou can log in through the company website to view your billing information.',
    },
  ];

  // ── Build the page HTML ──────────────────────────────────────
  function renderPage() {
    return `
<div class="page-header">
  <div>
    <h1 class="page-title">🔍 Email Analysis</h1>
    <p class="page-subtitle">Submit an email for AI-powered threat detection and forensic analysis</p>
  </div>
</div>

<div class="analyze-layout">
  <!-- LEFT: Input form -->
  <div>
    <div class="card mb-2">
      <div class="card-header">
        <span class="card-title">📧 Demo Emails</span>
        <span class="text-muted text-small">Click to pre-fill form</span>
      </div>
      <div class="demo-grid" id="demo-grid"></div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">📝 Email Details</span>
      </div>
      <form id="analyze-form" novalidate>
        <div class="form-group">
          <label class="form-label" for="inp-subject">Subject</label>
          <input type="text" id="inp-subject" class="form-control" placeholder="Email subject line" />
        </div>
        <div class="form-group">
          <label class="form-label" for="inp-from">From Address</label>
          <input type="text" id="inp-from" class="form-control" placeholder='e.g. "John Doe <john@example.com>"' />
        </div>
        <div class="form-group">
          <label class="form-label" for="inp-replyto">Reply-To</label>
          <input type="text" id="inp-replyto" class="form-control" placeholder="Reply-To header value (optional)" />
        </div>
        <div class="form-group">
          <label class="form-label" for="inp-ip">Sender IP</label>
          <input type="text" id="inp-ip" class="form-control" placeholder="e.g. 185.220.101.45 (optional)" />
          <span class="form-error" id="ip-error">Invalid IP address format</span>
        </div>
        <div class="form-group">
          <label class="form-label" for="inp-headers">Raw Email Headers <span class="text-muted">(optional)</span></label>
          <textarea id="inp-headers" class="form-control" rows="4" placeholder="Paste raw email headers here (Received:, Authentication-Results:, etc.)"></textarea>
        </div>
        <div class="form-group">
          <label class="form-label" for="inp-body">Email Body <span style="color:var(--fail)">*</span></label>
          <textarea id="inp-body" class="form-control" rows="8" placeholder="Paste the email body here…" style="min-height:200px"></textarea>
          <span class="form-hint">Paste the full text of the email body. HTML not required — plain text is sufficient.</span>
          <span class="form-error" id="body-error">Email body is required for analysis</span>
        </div>

        <div style="display:flex;gap:0.75rem;flex-wrap:wrap">
          <button type="submit" class="btn btn-primary btn-lg" id="analyze-btn">
            <span id="analyze-btn-icon">🔍</span>
            <span id="analyze-btn-text">Analyze Email</span>
          </button>
          <button type="button" class="btn btn-secondary" id="clear-btn">🗑 Clear</button>
        </div>
      </form>
    </div>
  </div>

  <!-- RIGHT: Result panel -->
  <div id="result-area">
    <div class="empty-state" style="min-height:300px; border:1px dashed var(--border); border-radius:var(--radius-lg);">
      <div class="empty-state-icon">📊</div>
      <div class="empty-state-text">Analysis results will appear here</div>
      <p class="text-muted text-small">Submit an email or load a demo to see the threat report</p>
    </div>
  </div>
</div>`;
  }

  // ── Render demo buttons ──────────────────────────────────────
  function renderDemoGrid() {
    const grid = document.getElementById('demo-grid');
    if (!grid) return;
    grid.innerHTML = DEMOS.map((d, i) => `
      <button class="demo-btn" data-demo="${i}" type="button">
        <span class="demo-btn-label">${escHtml(d.label)}</span>
        <span class="demo-btn-sub">${escHtml(d.sub)}</span>
      </button>
    `).join('');
    grid.querySelectorAll('.demo-btn').forEach(btn => {
      btn.addEventListener('click', () => loadDemo(parseInt(btn.dataset.demo)));
    });
  }

  function loadDemo(i) {
    const d = DEMOS[i];
    if (!d) return;
    document.getElementById('inp-subject').value = d.subject;
    document.getElementById('inp-from').value    = d.from;
    document.getElementById('inp-replyto').value = d.replyTo;
    document.getElementById('inp-ip').value      = d.ip;
    document.getElementById('inp-headers').value = d.headers;
    document.getElementById('inp-body').value    = d.body;
    clearErrors();
    toast(`Demo loaded: ${d.label}`, 'success', 2000);
  }

  function clearErrors() {
    document.querySelectorAll('.form-group.has-error').forEach(g => g.classList.remove('has-error'));
  }

  // ── Analyse form submit ──────────────────────────────────────
  async function handleSubmit(e) {
    e.preventDefault();
    clearErrors();

    const subject    = document.getElementById('inp-subject').value.trim();
    const from_address = document.getElementById('inp-from').value.trim();
    const reply_to   = document.getElementById('inp-replyto').value.trim();
    const sender_ip  = document.getElementById('inp-ip').value.trim();
    const headers    = document.getElementById('inp-headers').value.trim();
    const body       = document.getElementById('inp-body').value.trim();

    // Basic validation
    let valid = true;
    if (!body && !headers && !from_address) {
      document.getElementById('inp-body').closest('.form-group').classList.add('has-error');
      document.getElementById('body-error').textContent = 'Provide at least an email body, headers, or sender address.';
      valid = false;
    }
    if (sender_ip) {
      const ipRe = /^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+$/;
      if (!ipRe.test(sender_ip)) {
        document.getElementById('inp-ip').closest('.form-group').classList.add('has-error');
        valid = false;
      }
    }
    if (!valid) return;

    // Show loading state
    const btn     = document.getElementById('analyze-btn');
    const btnIcon = document.getElementById('analyze-btn-icon');
    const btnText = document.getElementById('analyze-btn-text');
    btn.disabled  = true;
    btnIcon.textContent = '';
    btnText.textContent = 'Analyzing…';

    const resultArea = document.getElementById('result-area');
    resultArea.innerHTML = `
      <div class="loading-splash" style="min-height:200px">
        <div class="spinner-ring"></div>
        <p>Running threat analysis…</p>
      </div>`;

    try {
      const result = await API.post('/api/analyze', { subject, from_address, reply_to, sender_ip, headers, body });
      renderResult(result);
      toast('Analysis complete', 'success');
    } catch (err) {
      resultArea.innerHTML = `
        <div class="error-state">
          <div style="font-size:2rem">⚠</div>
          <strong>Analysis failed</strong>
          <p class="text-small">${escHtml(err.message)}</p>
          <button class="btn btn-secondary btn-sm mt-1" onclick="document.getElementById('analyze-form').dispatchEvent(new Event('submit'))">Retry</button>
        </div>`;
      toast(`Error: ${err.message}`, 'error', 6000);
    } finally {
      btn.disabled = false;
      btnIcon.textContent = '🔍';
      btnText.textContent = 'Analyze Email';
    }
  }

  // ── Render analysis result ───────────────────────────────────
  function renderResult(r) {
    const vc   = verdictClass(r.verdict);
    const col  = verdictColour(r.verdict);
    const sc   = scoreColour(r.score);
    const bd   = r.breakdown || {};
    const geo  = r.geo || {};
    const for_ = r.forensics || {};

    const pillars = [
      { key: 'header_forensics', label: 'Header Forensics' },
      { key: 'content_analysis', label: 'Content Analysis' },
      { key: 'url_intelligence', label: 'URL Intelligence' },
      { key: 'behavioural',      label: 'Behaviour Analysis' },
      { key: 'ml_heuristic',     label: 'Heuristic ML Layer' },
    ];

    const breakdownHtml = pillars.map(p => {
      const pil = bd[p.key] || { score: 0, max: 25 };
      const pct = pil.max ? Math.round(pil.score / pil.max * 100) : 0;
      const barCol = pct >= 70 ? '#dc2626' : pct >= 40 ? '#f59e0b' : '#22c55e';
      return `
        <div class="breakdown-row">
          <span class="breakdown-label">${escHtml(p.label)}</span>
          <div class="breakdown-bar-track">
            <div class="breakdown-bar-fill" style="width:${pct}%;background:${barCol}"></div>
          </div>
          <span class="breakdown-score">${pil.score}/${pil.max}</span>
        </div>`;
    }).join('');

    const reasonsHtml = (r.reasons || []).length
      ? `<ul class="reasons-list">${r.reasons.map(re => `<li>${escHtml(re)}</li>`).join('')}</ul>`
      : `<p class="text-muted text-small">No significant threat signals detected.</p>`;

    const checksHtml = (r.checks || []).map(c => `
      <div class="check-item">
        <span class="check-icon check-${c.result}">${checkIcon(c.result)}</span>
        <div class="check-body">
          <div class="check-name">${escHtml(c.name)}</div>
          <div class="check-detail">${escHtml(c.detail)}</div>
        </div>
      </div>`).join('');

    const urlsHtml = (for_.urls_found || []).length ? `
      <div class="mt-1">
        <div class="section-title">URLs Detected</div>
        <div style="display:flex;flex-wrap:wrap;gap:0.4rem">
          ${for_.urls_found.map(u => {
            const susp = (for_.suspicious_urls || []).includes(u);
            return `<span class="tag" style="${susp ? 'color:var(--fail);border-color:rgba(239,68,68,0.4)' : ''}">${escHtml(truncate(u, 60))}</span>`;
          }).join('')}
        </div>
      </div>` : '';

    const geoHtml = geo.available ? `
      <div class="info-grid">
        <div class="info-item"><span class="info-item-label">Country</span><span class="info-item-value">${escHtml(geo.country)}</span></div>
        <div class="info-item"><span class="info-item-label">Region</span><span class="info-item-value">${escHtml(geo.region)}</span></div>
        <div class="info-item"><span class="info-item-label">City</span><span class="info-item-value">${escHtml(geo.city)}</span></div>
        <div class="info-item"><span class="info-item-label">ISP</span><span class="info-item-value">${escHtml(geo.isp)}</span></div>
        <div class="info-item"><span class="info-item-label">ASN</span><span class="info-item-value">${escHtml(geo.asn)}</span></div>
        <div class="info-item"><span class="info-item-label">IP Address</span><span class="info-item-value font-mono">${escHtml(geo.ip)}</span></div>
      </div>` : `<p class="text-muted text-small">${escHtml(geo.note || 'Geolocation not available')}</p>`;

    const forHtml = `
      <div class="info-grid">
        <div class="info-item"><span class="info-item-label">From Domain</span><span class="info-item-value font-mono">${escHtml(for_.from_domain || '—')}</span></div>
        <div class="info-item"><span class="info-item-label">Reply-To Domain</span><span class="info-item-value font-mono">${escHtml(for_.reply_to_domain || '—')}</span></div>
        <div class="info-item"><span class="info-item-label">Domain Mismatch</span><span class="info-item-value" style="color:${for_.domain_mismatch?'var(--fail)':'var(--safe)'}">${for_.domain_mismatch ? '⚠ Yes' : '✓ No'}</span></div>
        <div class="info-item"><span class="info-item-label">SPF</span><span class="info-item-value" style="color:${for_.spf==='pass'?'var(--safe)':'var(--warn)'}">${escHtml(for_.spf || 'unknown')}</span></div>
        <div class="info-item"><span class="info-item-label">DKIM</span><span class="info-item-value" style="color:${for_.dkim==='pass'?'var(--safe)':'var(--warn)'}">${escHtml(for_.dkim || 'unknown')}</span></div>
        <div class="info-item"><span class="info-item-label">DMARC</span><span class="info-item-value" style="color:${for_.dmarc==='pass'?'var(--safe)':'var(--warn)'}">${escHtml(for_.dmarc || 'unknown')}</span></div>
        <div class="info-item"><span class="info-item-label">Display-Name Spoofing</span><span class="info-item-value" style="color:${for_.display_name_spoofing?'var(--fail)':'var(--safe)'}">${for_.display_name_spoofing ? '⚠ Detected' : '✓ None'}</span></div>
        <div class="info-item"><span class="info-item-label">Typosquatting</span><span class="info-item-value" style="color:${for_.typosquatting?'var(--fail)':'var(--safe)'}">${for_.typosquatting ? '⚠ Detected' : '✓ None'}</span></div>
      </div>`;

    const actionClass = vc;

    document.getElementById('result-area').innerHTML = `
<div class="result-panel">

  <!-- Score hero -->
  <div class="card">
    <div class="result-hero">
      <div class="score-gauge">
        <div class="score-circle ${vc}">
          <span class="score-number" style="color:${sc}">${r.score}</span>
          <span class="score-max">/ 100</span>
        </div>
        <span class="score-label" style="color:${col}">${r.verdict.replace('_',' ')}</span>
      </div>
      <div class="result-meta">
        <div class="result-verdict-label" style="color:${col}">${r.verdict.replace('_',' ')}</div>
        <div class="result-category">📂 ${escHtml(r.category)}</div>
        <div class="result-confidence">
          Confidence: ${Math.round(r.confidence * 100)}%
          <div class="confidence-bar mt-1">
            <div class="confidence-fill" style="width:${Math.round(r.confidence*100)}%;background:${col}"></div>
          </div>
        </div>
        <div class="mt-1 flex gap-1 items-center flex-wrap">
          <a href="#report/${r.id}" class="btn btn-secondary btn-sm">📋 Full Report</a>
          <a href="#reports" class="btn btn-secondary btn-sm">📊 All Reports</a>
        </div>
      </div>
    </div>
  </div>

  <!-- Recommended action -->
  <div class="action-box ${actionClass}">
    <strong>Recommended Action</strong><br>${escHtml(r.recommended_action)}
  </div>

  <!-- Detection reasons -->
  <div class="card">
    <div class="card-header"><span class="card-title">🚨 Detection Reasons</span></div>
    ${reasonsHtml}
  </div>

  <!-- Score breakdown -->
  <div class="card">
    <div class="card-header">
      <span class="card-title">📊 Score Breakdown</span>
      <span class="text-muted text-small">Total: ${r.score}/100</span>
    </div>
    ${breakdownHtml}
  </div>

  <!-- All checks (collapsible) -->
  <div class="card">
    <details>
      <summary>🔬 Detailed Forensic Checks (${(r.checks||[]).length})</summary>
      <div style="margin-top:0.75rem">${checksHtml || '<p class="text-muted text-small">No checks performed.</p>'}</div>
    </details>
  </div>

  <!-- Header forensics -->
  <div class="card">
    <div class="card-header"><span class="card-title">📨 Header Forensics</span></div>
    ${forHtml}
    ${urlsHtml}
  </div>

  <!-- Geolocation -->
  <div class="card">
    <div class="card-header">
      <span class="card-title">🌍 IP Geolocation</span>
      ${geo.available ? '' : '<span class="text-muted text-small">Unavailable</span>'}
    </div>
    ${geoHtml}
  </div>

</div>`;
  }

  // ── Page registration ────────────────────────────────────────
  registerPage('analyze', {
    mount(root) {
      root.innerHTML = renderPage();
      renderDemoGrid();

      document.getElementById('analyze-form').addEventListener('submit', handleSubmit);
      document.getElementById('clear-btn').addEventListener('click', () => {
        document.getElementById('analyze-form').reset();
        document.getElementById('result-area').innerHTML = `
          <div class="empty-state" style="min-height:300px;border:1px dashed var(--border);border-radius:var(--radius-lg)">
            <div class="empty-state-icon">📊</div>
            <div class="empty-state-text">Analysis results will appear here</div>
          </div>`;
        clearErrors();
      });
    },
  });

  // Helper exported for report.js
  window._renderAnalyzeResult = renderResult;
})();

// Helper to truncate (used in renderResult)
function truncate(str, max) {
  max = max || 60;
  if (!str) return '—';
  return str.length > max ? str.slice(0, max) + '…' : str;
}
