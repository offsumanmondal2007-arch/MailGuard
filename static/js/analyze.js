/**
 * analyze.js — Email Scanner with pipeline progress
 * MailGuard AI v2.0
 */
'use strict';

(function () {
  const { API, toast, verdictClass, verdictColour, scoreColour, actionClass, actionColour,
          checkIcon, formatTimestamp, escHtml, registerPage, navigate, buildAuthCards } = window.APP;

  // ── Demo email presets ─────────────────────────────────────────
  const DEMOS = [
    {
      label: '✅ Safe Internal',    sub: 'Internal corporate email',
      subject: '[DEMO] Q3 Team Lunch — Friday 12pm',
      from: 'Alice Johnson <alice.johnson@acme-corp.com>', replyTo: 'alice.johnson@acme-corp.com', ip: '',
      headers: 'Received: from mail.acme-corp.com ([10.0.0.5])\nAuthentication-Results: spf=pass; dkim=pass; dmarc=pass\nTo: team@acme-corp.com',
      body: 'Hi team,\n\nJust a reminder — Q3 team lunch this Friday at 12pm in the main conference room. RSVP by Thursday EOD.\n\nBest,\nAlice Johnson\nSenior Project Manager, Acme Corp',
    },
    {
      label: '🎣 Credential Phishing', sub: 'PayPal account suspension',
      subject: '[DEMO] Your PayPal account has been SUSPENDED - Verify Immediately',
      from: 'PayPal Security <security@paypa1-secure.tk>', replyTo: 'noreply@paypal-helpdesk.ml', ip: '185.220.101.45',
      headers: 'Received: from unknown ([185.220.101.45])\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail',
      body: 'Dear Customer,\n\nURGENT: Your PayPal account has been suspended. Verify immediately or your account will be permanently terminated.\n\nClick here to verify your account and enter your username and password:\nhttp://185.220.101.45/paypal/verify\n\nFailure to act within 24 hours will result in legal action.\n\nPayPal Security Team',
    },
    {
      label: '💸 BEC / Wire Fraud', sub: 'CEO urgent wire transfer',
      subject: '[DEMO] Confidential — Urgent Wire Transfer Required',
      from: '"Robert Chen - CEO" <robert.chen.ceo@acme-corp-hq.xyz>', replyTo: 'rchen.payments@gmail.com', ip: '91.108.4.1',
      headers: 'Received: from smtp.gmail.com ([91.108.4.1])\nAuthentication-Results: spf=softfail; dkim=pass; dmarc=fail',
      body: 'Hi Sarah,\n\nI need you to process a confidential wire transfer today.\nTransfer $87,500 to:\nBank: First National Trust\nRouting: 021000021\nAccount: 7829301847\n\nKeep this confidential — do not discuss with anyone. I am in a board meeting.\n\nRobert Chen\nChief Executive Officer',
    },
    {
      label: '🔑 Password Phishing', sub: 'Microsoft 365 expiry',
      subject: '[DEMO] Action Required: Your Microsoft 365 Password Expires Today',
      from: 'Microsoft IT Support <support@micros0ft-365.top>', replyTo: 'support@micros0ft-365.top', ip: '103.224.182.9',
      headers: 'Received: from smtp.micros0ft-365.top ([103.224.182.9])\nAuthentication-Results: spf=fail; dkim=fail',
      body: 'Dear User,\n\nYour Microsoft 365 password expires today. Sign in immediately to update your credentials:\nhttps://micros0ft-365.top/m365/login?redirect=portal\n\nFailure to update within 24 hours will disable your account.',
    },
    {
      label: '👤 Exec Impersonation', sub: 'Gift card social engineering',
      subject: '[DEMO] Personal Request — Need Your Help Urgently',
      from: '"Dr. Meena Sharma - Managing Director" <md@globaltech-inc.cf>', replyTo: 'meena.sharma.md2026@gmail.com', ip: '162.158.102.10',
      headers: 'Received: from smtp.outbound.cf ([162.158.102.10])\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail',
      body: 'Hi,\n\nI need immediate and confidential assistance. I am in a board meeting — keep this strictly between us.\n\nPurchase 10 Amazon gift cards worth INR 5,000 each and share the codes via this email immediately. I will reimburse from petty cash. Do not mention this to HR or Finance.',
    },
    {
      label: '⚠ Suspicious Reset', sub: 'Unknown shortened URL',
      subject: '[DEMO] Password Reset Request for Your Account',
      from: 'noreply@accounts-reset-portal.download', replyTo: '', ip: '78.46.113.7',
      headers: 'Received: from mail.accounts-reset-portal.download ([78.46.113.7])\nAuthentication-Results: spf=softfail; dkim=fail',
      body: 'Hello,\n\nWe received a request to reset your account password.\nClick the link to reset:\nhttp://bit.ly/3xR9pQZ\n\nIf you did not request this, ignore this email.',
    },
    {
      label: '📲 QR Phishing', sub: 'Bank QR code scam',
      subject: '[DEMO] Verify Your Bank Account via QR Code',
      from: 'HDFC NetBanking <noreply@hdfc-bank-secure.ml>', replyTo: '', ip: '139.59.48.5',
      headers: 'Received: from mail.hdfc-bank-secure.ml ([139.59.48.5])\nAuthentication-Results: spf=fail; dkim=fail',
      body: 'Dear Customer,\n\nYour HDFC account requires verification.\nPlease scan the QR code below:\n[QR CODE - Destination: https://hdfc-verify-account.xyz/login]\n\nFailure to verify will result in account suspension within 24 hours.\n\nHDFC Bank Security Team',
    },
    {
      label: '📎 Malicious Attachment', sub: 'Fake invoice .exe',
      subject: '[DEMO] Invoice #INV-2026-0934 Attached',
      from: 'Billing <billing@supplier-invoices-global.download>', replyTo: '', ip: '94.102.49.190',
      headers: 'Received: from mail.supplier-invoices-global.download ([94.102.49.190])\nAuthentication-Results: spf=softfail; dkim=fail',
      body: 'Dear Accounts Team,\n\nPlease find the attached Invoice #INV-2026-0934.\nAttached: Invoice_INV-2026-0934.pdf.exe\nAmount: $4,250.00\n\nProcess this payment urgently to avoid late fees.\n\nSupplier Accounts Team',
    },
  ];

  // ── Pipeline steps ─────────────────────────────────────────────
  const PIPELINE_STEPS = [
    'EMAIL RECEIVED',
    'HEADER PARSING',
    'SPF / DKIM / DMARC CHECK',
    'SENDER ANALYSIS',
    'DOMAIN ANALYSIS',
    'URL ANALYSIS',
    'ATTACHMENT CHECK',
    'BEC DETECTION',
    'CREDENTIAL PHISHING',
    'BEHAVIOURAL ANALYSIS',
    'THREAT INTELLIGENCE',
    'RISK CALCULATION',
    'SECURITY DECISION',
  ];

  // ── Build page HTML ────────────────────────────────────────────
  function renderPage() {
    return `
<div class="page-header">
  <div>
    <h1 class="page-title">Email Scanner</h1>
    <p class="page-subtitle">Submit an email for pre-delivery security inspection and forensic analysis</p>
  </div>
</div>

<div class="analyze-layout">
  <!-- LEFT: Form -->
  <div>
    <div class="card mb-2">
      <div class="card-header">
        <span class="card-title">🎯 Demo Threat Scenarios</span>
        <span class="text-muted text-small">Select to pre-fill the form</span>
      </div>
      <div class="demo-grid" id="demo-grid"></div>
    </div>

    <div class="card">
      <div class="card-header">
        <span class="card-title">📧 Email Details</span>
        <span class="text-xs text-muted">Fields marked * are required</span>
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
          <textarea id="inp-headers" class="form-control" rows="3" placeholder="Received: from...&#10;Authentication-Results: spf=fail; dkim=fail; dmarc=fail"></textarea>
        </div>
        <div class="form-group">
          <label class="form-label" for="inp-body">Email Body <span style="color:var(--fail)">*</span></label>
          <textarea id="inp-body" class="form-control" rows="7" placeholder="Paste the full email body here…" style="min-height:160px"></textarea>
          <span class="form-error" id="body-error">Provide at least a body, headers, or sender address.</span>
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

  <!-- RIGHT: Analysis pipeline + result -->
  <div>
    <!-- Analysis pipeline progress panel -->
    <div class="card mb-2" id="pipeline-panel">
      <div class="card-header">
        <span class="card-title">⚙ Security Analysis Pipeline</span>
        <span class="text-xs text-muted" id="pipeline-status">Ready</span>
      </div>
      <div class="pipeline-steps" id="pipeline-steps">
        ${PIPELINE_STEPS.map((step, i) => `
          <div class="pipeline-step" id="pstep-${i}">
            <div class="pipeline-step-dot" id="pdot-${i}">
              <span id="pdot-icon-${i}">○</span>
            </div>
            <div class="pipeline-step-label">${step}</div>
          </div>`).join('')}
      </div>
    </div>

    <!-- Result area -->
    <div id="result-area">
      <div class="empty-state" style="min-height:200px;border:1px dashed var(--border);border-radius:var(--radius-lg)">
        <div class="empty-state-icon">🛡</div>
        <div class="empty-state-text">Analysis results will appear here</div>
        <p class="text-muted text-small">Submit an email or load a demo scenario</p>
      </div>
    </div>
  </div>
</div>`;
  }

  // ── Demo grid ──────────────────────────────────────────────────
  function renderDemoGrid() {
    const grid = document.getElementById('demo-grid');
    if (!grid) return;
    grid.innerHTML = DEMOS.map((d, i) => `
      <button class="demo-btn" data-demo="${i}" type="button">
        <span class="demo-btn-label">${escHtml(d.label)}</span>
        <span class="demo-btn-sub">${escHtml(d.sub)}</span>
      </button>`).join('');
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
    // Reset pipeline
    resetPipeline();
    toast(`Demo loaded: ${d.label}`, 'success', 2000);
  }

  function clearErrors() {
    document.querySelectorAll('.form-group.has-error').forEach(g => g.classList.remove('has-error'));
  }

  // ── Pipeline animation ─────────────────────────────────────────
  function resetPipeline() {
    PIPELINE_STEPS.forEach((_, i) => {
      const step = document.getElementById(`pstep-${i}`);
      const dot  = document.getElementById(`pdot-${i}`);
      const icon = document.getElementById(`pdot-icon-${i}`);
      if (step) { step.className = 'pipeline-step'; }
      if (dot)  { dot.className = 'pipeline-step-dot'; }
      if (icon) icon.textContent = '○';
    });
    const statusEl = document.getElementById('pipeline-status');
    if (statusEl) statusEl.textContent = 'Ready';
  }

  async function runPipelineAnimation(totalMs) {
    const statusEl = document.getElementById('pipeline-status');
    if (statusEl) statusEl.textContent = 'Analyzing…';

    const stepDelay = totalMs / PIPELINE_STEPS.length;

    for (let i = 0; i < PIPELINE_STEPS.length; i++) {
      const step = document.getElementById(`pstep-${i}`);
      const dot  = document.getElementById(`pdot-${i}`);
      const icon = document.getElementById(`pdot-icon-${i}`);

      if (step) step.className = 'pipeline-step active';
      if (dot)  dot.className  = 'pipeline-step-dot';
      if (icon) icon.textContent = '●';

      await new Promise(res => setTimeout(res, stepDelay));

      if (step) step.className = 'pipeline-step completed';
      if (dot)  dot.className  = 'pipeline-step-dot';
      if (icon) icon.textContent = '✓';
    }

    if (statusEl) statusEl.textContent = 'Complete ✓';
  }

  // ── Form submit ────────────────────────────────────────────────
  async function handleSubmit(e) {
    e.preventDefault();
    clearErrors();

    const subject      = document.getElementById('inp-subject').value.trim();
    const from_address = document.getElementById('inp-from').value.trim();
    const reply_to     = document.getElementById('inp-replyto').value.trim();
    const sender_ip    = document.getElementById('inp-ip').value.trim();
    const headers      = document.getElementById('inp-headers').value.trim();
    const body         = document.getElementById('inp-body').value.trim();

    let valid = true;
    if (!body && !headers && !from_address) {
      document.getElementById('inp-body').closest('.form-group').classList.add('has-error');
      valid = false;
    }
    if (sender_ip) {
      if (!/^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-fA-F:]+$/.test(sender_ip)) {
        document.getElementById('inp-ip').closest('.form-group').classList.add('has-error');
        valid = false;
      }
    }
    if (!valid) return;

    const btn     = document.getElementById('analyze-btn');
    const btnIcon = document.getElementById('analyze-btn-icon');
    const btnText = document.getElementById('analyze-btn-text');
    btn.disabled  = true;
    btnIcon.textContent = '⏳';
    btnText.textContent = 'Analyzing…';

    // Clear result
    document.getElementById('result-area').innerHTML = '';
    resetPipeline();

    // Run pipeline animation concurrently with real API call
    const pipelinePromise = runPipelineAnimation(1800);
    const apiPromise      = API.post('/api/analyze', { subject, from_address, reply_to, sender_ip, headers, body });

    try {
      const [_, result] = await Promise.all([pipelinePromise, apiPromise]);
      renderResult(result);
      toast('Analysis complete', 'success');
    } catch (err) {
      // Ensure pipeline shows failure
      const lastStep = document.getElementById(`pstep-${PIPELINE_STEPS.length - 1}`);
      if (lastStep) lastStep.className = 'pipeline-step failed';

      document.getElementById('result-area').innerHTML = `
        <div class="card">
          <div class="error-state">
            <div style="font-size:2rem">⚠</div>
            <strong>Analysis failed</strong>
            <p class="text-small">${escHtml(err.message)}</p>
            <button class="btn btn-secondary btn-sm mt-1" id="retry-btn">Retry</button>
          </div>
        </div>`;
      document.getElementById('retry-btn')?.addEventListener('click', () => handleSubmit(e));
      toast(`Error: ${err.message}`, 'error', 6000);
    } finally {
      btn.disabled = false;
      btnIcon.textContent = '🔍';
      btnText.textContent = 'Analyze Email';
    }
  }

  // ── Render analysis result ─────────────────────────────────────
  function renderResult(r) {
    const vc  = verdictClass(r.verdict);
    const col = verdictColour(r.verdict);
    const sc  = scoreColour(r.score);
    const bd  = r.breakdown || {};
    const geo = r.geo || {};
    const forensics = r.forensics || {};
    const decision = r.decision || {};

    const action = decision.action || (r.score >= 80 ? 'BLOCK' : r.score >= 60 ? 'QUARANTINE' : r.score >= 30 ? 'FLAG' : 'DELIVER');
    const ac = actionClass(action);
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

    // Score detail: show exact components
    const p1 = (bd.header_forensics || {}).score || 0;
    const p2 = (bd.content_analysis || {}).score || 0;
    const p3 = (bd.url_intelligence || {}).score || 0;
    const p4 = (bd.behavioural || {}).score || 0;
    const p5 = (bd.ml_heuristic || {}).score || 0;
    const scoreDetail = `
      <div class="text-xs text-muted" style="font-family:'JetBrains Mono',monospace;margin-top:0.3rem">
        ${p1} + ${p2} + ${p3} + ${p4} + ${p5} = <strong style="color:${sc}">${r.score}</strong>/100
      </div>`;

    const reasonsHtml = (r.reasons || []).length
      ? `<ul class="reasons-list">${r.reasons.map(re => `<li>${escHtml(re)}</li>`).join('')}</ul>`
      : `<p class="text-muted text-small">No significant threat signals detected.</p>`;

    const urlsHtml = (forensics.urls_found || []).length ? `
      <div class="mt-1">
        <div class="section-title">URLs Found (${forensics.urls_found.length})</div>
        <div style="display:flex;flex-wrap:wrap;gap:0.4rem">
          ${forensics.urls_found.map(u => {
            const susp = (forensics.suspicious_urls || []).includes(u);
            return `<span class="tag" style="${susp ? 'color:var(--fail);border-color:rgba(239,68,68,0.4)' : ''}" title="${escHtml(u)}">${escHtml(truncate(u, 65))}</span>`;
          }).join('')}
        </div>
      </div>` : '';

    const geoHtml = geo.available ? `
      <div class="info-grid">
        <div class="info-item"><span class="info-item-label">IP</span><span class="info-item-value font-mono">${escHtml(geo.ip)}</span></div>
        <div class="info-item"><span class="info-item-label">Country</span><span class="info-item-value">${escHtml(geo.country)}</span></div>
        <div class="info-item"><span class="info-item-label">Region</span><span class="info-item-value">${escHtml(geo.region)}</span></div>
        <div class="info-item"><span class="info-item-label">City</span><span class="info-item-value">${escHtml(geo.city)}</span></div>
        <div class="info-item"><span class="info-item-label">ISP</span><span class="info-item-value">${escHtml(geo.isp)}</span></div>
        <div class="info-item"><span class="info-item-label">ASN</span><span class="info-item-value">${escHtml(geo.asn)}</span></div>
      </div>
      <p class="text-xs text-muted mt-1">⚠ IP geolocation is approximate — this is NOT the physical attacker location.</p>` :
      `<p class="text-muted text-small">${escHtml(geo.note || 'Geolocation not available')}</p>`;

    document.getElementById('result-area').innerHTML = `
<div class="result-panel">

  <!-- Security decision -->
  <div class="verdict-decision-box ${action.toLowerCase()}-box">
    <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:0.5rem">
      <div>
        <div class="verdict-decision-title" style="color:${aCol}">
          SECURITY DECISION: ${action}
        </div>
        <div class="verdict-decision-reasons">
          ${(decision.justifications || ['Score-based decision']).map(j => `• ${escHtml(j)}`).join('<br>')}
        </div>
      </div>
      <div style="text-align:right">
        <span class="badge ${ac}" style="font-size:0.85rem;padding:0.3rem 0.85rem">${action}</span>
      </div>
    </div>
  </div>

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
        <div class="result-verdict-label" style="color:${col}">${r.verdict.replace('_', ' ')}</div>
        <div class="result-category">📂 ${escHtml(r.category.replace(/_/g,' '))}</div>
        <div class="result-confidence">
          Confidence: ${Math.round(r.confidence * 100)}%
          <div class="confidence-bar mt-1"><div class="confidence-fill" style="width:${Math.round(r.confidence*100)}%;background:${col}"></div></div>
        </div>
        ${scoreDetail}
        <div class="mt-1 flex gap-1 flex-wrap" style="gap:0.5rem">
          <a href="#report/${r.id}" class="btn btn-secondary btn-sm">📋 Full Investigation</a>
          <a href="#reports" class="btn btn-secondary btn-sm">📊 All Cases</a>
        </div>
      </div>
    </div>
  </div>

  <!-- WHY this was blocked/quarantined -->
  <div class="card">
    <div class="card-header"><span class="card-title">🚨 Why This Email Was ${action}</span></div>
    ${reasonsHtml}
  </div>

  <!-- Score breakdown with exact math -->
  <div class="card">
    <div class="card-header">
      <span class="card-title">📊 Risk Score Breakdown</span>
      <span class="text-muted text-small">Total: ${r.score}/100</span>
    </div>
    ${breakdownRows}
  </div>

  <!-- SPF / DKIM / DMARC -->
  <div class="card">
    <div class="card-header"><span class="card-title">🔐 Email Authentication</span></div>
    ${buildAuthCards(forensics)}
    <p class="text-xs text-muted mt-1">Authentication failures contribute to the threat score.</p>
  </div>

  <!-- Header forensics + URLs -->
  <div class="card">
    <div class="card-header"><span class="card-title">📨 Header Forensics</span></div>
    <div class="info-grid mb-1">
      <div class="info-item"><span class="info-item-label">From Domain</span><span class="info-item-value font-mono">${escHtml(forensics.from_domain || '—')}</span></div>
      <div class="info-item"><span class="info-item-label">Reply-To Domain</span><span class="info-item-value font-mono">${escHtml(forensics.reply_to_domain || '—')}</span></div>
      <div class="info-item"><span class="info-item-label">Domain Mismatch</span><span class="info-item-value" style="color:${forensics.domain_mismatch?'var(--fail)':'var(--safe)'}">${forensics.domain_mismatch ? '⚠ DETECTED' : '✓ None'}</span></div>
      <div class="info-item"><span class="info-item-label">Display-Name Spoof</span><span class="info-item-value" style="color:${forensics.display_name_spoofing?'var(--fail)':'var(--safe)'}">${forensics.display_name_spoofing ? '⚠ DETECTED' : '✓ None'}</span></div>
      <div class="info-item"><span class="info-item-label">Typosquatting</span><span class="info-item-value" style="color:${forensics.typosquatting?'var(--fail)':'var(--safe)'}">${forensics.typosquatting ? '⚠ DETECTED' : '✓ None'}</span></div>
      <div class="info-item"><span class="info-item-label">Mail Hops</span><span class="info-item-value">${forensics.received_hops || 0}</span></div>
    </div>
    ${urlsHtml}
  </div>

  <!-- Geolocation -->
  <div class="card">
    <div class="card-header">
      <span class="card-title">🌍 Sender IP Geolocation</span>
      ${geo.available ? '<span class="badge badge-safe">Live Data</span>' : '<span class="text-muted text-small">Unavailable</span>'}
    </div>
    ${geoHtml}
  </div>

</div>`;
  }

  // ── Register ───────────────────────────────────────────────────
  registerPage('analyze', {
    mount(root) {
      root.innerHTML = renderPage();
      renderDemoGrid();
      document.getElementById('analyze-form').addEventListener('submit', handleSubmit);
      document.getElementById('clear-btn').addEventListener('click', () => {
        document.getElementById('analyze-form').reset();
        document.getElementById('result-area').innerHTML = `
          <div class="empty-state" style="min-height:200px;border:1px dashed var(--border);border-radius:var(--radius-lg)">
            <div class="empty-state-icon">🛡</div>
            <div class="empty-state-text">Analysis results will appear here</div>
          </div>`;
        clearErrors();
        resetPipeline();
      });
    },
  });

  window._renderAnalyzeResult = renderResult;
})();
