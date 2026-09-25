/**
 * attachments.js — Attachment Analysis page
 * MailGuard AI v2.0
 */
'use strict';

(function () {
  const { API, toast, escHtml, registerPage } = window.APP;

  const DEMO_FILES = [
    { label: '✅ Normal PDF',        filename: 'invoice.pdf',              size: 256000, mime: 'application/pdf' },
    { label: '💀 Malware (.exe)',     filename: 'setup.exe',                size: 1024000, mime: 'application/x-msdownload' },
    { label: '⚠ Double Extension',   filename: 'invoice.pdf.exe',          size: 512000, mime: 'application/x-msdownload' },
    { label: '🦠 Macro Word Doc',    filename: 'Quotation_Q3.docm',        size: 128000, mime: 'application/vnd.ms-word.document.macroEnabled.12' },
    { label: '📦 Suspicious Zip',    filename: 'Documents.zip',            size: 4096000, mime: 'application/zip' },
    { label: '🔴 PowerShell Script', filename: 'update.ps1',               size: 8000, mime: 'text/plain' },
    { label: '💡 MIME Mismatch',     filename: 'resume.docx',              size: 32000, mime: 'application/x-msdownload' },
    { label: '📋 Normal Excel',      filename: 'budget_2026.xlsx',         size: 64000, mime: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet' },
  ];

  function riskColour(score) {
    if (score >= 70) return '#dc2626';
    if (score >= 40) return '#ef4444';
    if (score >= 15) return '#f59e0b';
    return '#22c55e';
  }

  function verdictLabel(verdict) {
    const map = {
      CRITICAL: { cls: 'badge-critical', icon: '💀' },
      HIGH_RISK: { cls: 'badge-high_risk', icon: '🔴' },
      SUSPICIOUS: { cls: 'badge-suspicious', icon: '⚠️' },
      LOW_RISK: { cls: 'badge-safe', icon: '🟡' },
    };
    const { cls, icon } = map[verdict] || { cls: 'badge-safe', icon: '✅' };
    return `<span class="badge ${cls}">${icon} ${verdict.replace('_', ' ')}</span>`;
  }

  function renderResult(data) {
    const el = document.getElementById('attach-result');
    if (!el) return;
    const col = riskColour(data.risk_score || 0);
    el.innerHTML = `
      <div class="url-result-card">
        <div style="display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:1rem;margin-bottom:0.75rem">
          <div>
            <div style="font-size:0.72rem;color:var(--text-muted)">FILENAME</div>
            <div class="font-mono" style="font-size:0.88rem;color:var(--text-primary)">${escHtml(data.filename)}</div>
          </div>
          <div style="text-align:right">
            ${verdictLabel(data.verdict)}
            <div style="font-size:0.68rem;color:var(--text-muted);margin-top:0.25rem">Risk: <strong style="color:${col}">${data.risk_score}/100</strong></div>
          </div>
        </div>

        <div class="attachment-meta-grid">
          <div class="attachment-meta-item"><span class="attachment-meta-label">Extension</span><span class="attachment-meta-value">.${escHtml(data.extension) || 'none'}</span></div>
          <div class="attachment-meta-item"><span class="attachment-meta-label">MIME Type</span><span class="attachment-meta-value">${escHtml(data.mime_type)}</span></div>
          <div class="attachment-meta-item"><span class="attachment-meta-label">File Size</span><span class="attachment-meta-value">${data.size_bytes ? (data.size_bytes / 1024).toFixed(1) + ' KB' : '—'}</span></div>
          <div class="attachment-meta-item"><span class="attachment-meta-label">SHA256</span><span class="attachment-meta-value">${escHtml(data.sha256 || 'Not provided')}</span></div>
          <div class="attachment-meta-item"><span class="attachment-meta-label">Analysis Type</span><span class="attachment-meta-value">${escHtml(data.analysis_type)}</span></div>
          <div class="attachment-meta-item"><span class="attachment-meta-label">Sandbox</span><span class="attachment-meta-value" style="color:var(--warn)">${escHtml(data.sandbox_status)}</span></div>
        </div>

        <div class="divider"></div>
        <div style="font-size:0.8rem;font-weight:600;color:var(--text-secondary);margin-bottom:0.5rem">
          Risk Indicators (${(data.indicators || []).length})
        </div>
        ${(data.indicators || []).map(ind => `
          <div class="url-indicator-row">
            <span class="url-indicator-type">${escHtml(ind.type)}</span>
            <span class="url-indicator-detail">${escHtml(ind.detail)}</span>
            <span class="url-indicator-risk">+${ind.risk || 0}</span>
          </div>`).join('') || '<p class="text-muted text-small">No threat indicators.</p>'}
        <div class="divider"></div>
        <div class="sandbox-note">⚠ ${escHtml(data.note)}</div>
      </div>`;
  }

  registerPage('attachments', {
    mount(root) {
      root.innerHTML = `
<div class="page-header mb-2">
  <div>
    <h1 class="page-title">Attachment Analysis</h1>
    <p class="page-subtitle">Static analysis of email attachment metadata and file types</p>
  </div>
  <span class="intel-source-badge" style="color:var(--warn);border-color:rgba(245,158,11,0.3);background:rgba(245,158,11,0.06)">⚠ STATIC ANALYSIS</span>
</div>

<div style="display:grid;grid-template-columns:1fr 1fr;gap:var(--gap);align-items:start">
  <div>
    <div class="card mb-2">
      <div class="card-header"><span class="card-title">📎 Demo Files</span><span class="text-muted text-small">Click to load</span></div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.4rem">
        ${DEMO_FILES.map((d, i) => `
          <button class="demo-btn" data-i="${i}" type="button" style="font-size:0.75rem">
            <span class="demo-btn-label">${escHtml(d.label)}</span>
            <span class="demo-btn-sub" style="font-family:'JetBrains Mono',monospace;font-size:0.65rem">${escHtml(d.filename)}</span>
          </button>`).join('')}
      </div>
    </div>
    <div class="card">
      <div class="card-header"><span class="card-title">🔍 Analyze Attachment</span></div>
      <div class="form-group">
        <label class="form-label" for="file-name">Filename</label>
        <input type="text" id="file-name" class="form-control font-mono" placeholder="e.g. invoice.pdf.exe" />
      </div>
      <div style="display:grid;grid-template-columns:1fr 1fr;gap:0.75rem">
        <div class="form-group">
          <label class="form-label" for="file-size">File Size (bytes)</label>
          <input type="number" id="file-size" class="form-control" placeholder="1024" />
        </div>
        <div class="form-group">
          <label class="form-label" for="file-mime">MIME Type</label>
          <input type="text" id="file-mime" class="form-control font-mono" placeholder="application/pdf" />
        </div>
      </div>
      <div class="form-group">
        <label class="form-label" for="file-sha">SHA256 Hash <span class="text-muted">(optional)</span></label>
        <input type="text" id="file-sha" class="form-control font-mono" placeholder="e.g. a3c3f8d…" />
      </div>
      <button class="btn btn-primary" id="attach-analyze-btn">
        <span id="attach-btn-icon">🔍</span>
        <span id="attach-btn-text">Analyze Attachment</span>
      </button>
    </div>
    <div class="card" style="margin-top:0.85rem">
      <div class="card-header"><span class="card-title">ℹ About Attachment Analysis</span></div>
      <ul style="font-size:0.78rem;color:var(--text-secondary);display:flex;flex-direction:column;gap:0.4rem;list-style:none">
        <li>📂 <strong>Static metadata analysis</strong> — extension, MIME type, double extensions</li>
        <li>⚠ <strong>No file execution</strong> — file content is NOT read or detonated</li>
        <li>🦠 Detects: executables, macro-enabled docs, archives, scripts, MIME mismatches</li>
        <li>🔒 SHA256: For IOC matching against known malware hashes (manual lookup)</li>
        <li>🧪 For real analysis: Use Cuckoo Sandbox, ANY.RUN, or VirusTotal</li>
      </ul>
    </div>
  </div>
  <div>
    <div id="attach-result">
      <div class="empty-state" style="min-height:200px;border:1px dashed var(--border);border-radius:var(--radius-lg)">
        <div class="empty-state-icon">📎</div>
        <div class="empty-state-text">Attachment analysis results will appear here</div>
        <p class="text-muted text-small">Enter file details or select a demo to analyze</p>
      </div>
    </div>
  </div>
</div>`;

      const demoFiles = DEMO_FILES;
      root.querySelectorAll('.demo-btn[data-i]').forEach(btn => {
        btn.addEventListener('click', () => {
          const d = demoFiles[parseInt(btn.dataset.i)];
          document.getElementById('file-name').value = d.filename;
          document.getElementById('file-size').value = d.size;
          document.getElementById('file-mime').value = d.mime;
          toast(`Demo loaded: ${d.label}`, 'success', 1500);
        });
      });

      document.getElementById('attach-analyze-btn')?.addEventListener('click', async () => {
        const filename  = document.getElementById('file-name').value.trim();
        const size      = parseInt(document.getElementById('file-size').value) || 0;
        const mime_type = document.getElementById('file-mime').value.trim();
        const sha256    = document.getElementById('file-sha').value.trim();

        if (!filename) { toast('Please enter a filename', 'warn'); return; }

        const btn  = document.getElementById('attach-analyze-btn');
        const icon = document.getElementById('attach-btn-icon');
        const text = document.getElementById('attach-btn-text');
        btn.disabled = true; icon.textContent = '⏳'; text.textContent = 'Analyzing…';
        try {
          const data = await API.post('/api/attachment/analyze', { filename, size, mime_type, sha256 });
          renderResult(data);
          toast('Attachment analysis complete', 'success');
        } catch (err) {
          toast(`Error: ${err.message}`, 'error');
        } finally {
          btn.disabled = false; icon.textContent = '🔍'; text.textContent = 'Analyze Attachment';
        }
      });
    },
  });
})();
