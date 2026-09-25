/**
 * dashboard.js — SOC Dashboard v2
 * MailGuard AI — Pre-Delivery Email Security Gateway
 */
'use strict';

(function () {
  const { API, toast, verdictClass, verdictColour, scoreColour, actionClass,
          formatTimestamp, escHtml, truncate, registerPage, navigate } = window.APP;

  let _charts = [];
  let _prevData = null;

  function destroyCharts() {
    _charts.forEach(c => { try { c.destroy(); } catch (_) {} });
    _charts = [];
  }

  function applyChartDefaults() {
    if (!window.Chart) return;
    Chart.defaults.color       = '#7a96b8';
    Chart.defaults.borderColor = '#1a2a40';
    Chart.defaults.font.family = "'Inter', 'Segoe UI', system-ui";
    Chart.defaults.font.size   = 11;
    Chart.defaults.animation   = { duration: 500, easing: 'easeOutQuart' };
  }

  // ── Page skeleton ──────────────────────────────────────────────
  function renderPage() {
    return `
<div class="dash-toprow">
  <div>
    <h1 class="page-title">SOC Dashboard</h1>
    <p class="page-subtitle">Pre-delivery email security gateway — real-time threat monitoring</p>
  </div>
  <div class="dash-actions">
    <span id="dash-last-refresh" class="text-muted text-small"></span>
    <button class="btn btn-secondary btn-sm" id="dash-refresh">↻ Refresh</button>
    <button class="btn btn-primary btn-sm" onclick="window.APP.navigate('#analyze')">+ Scan Email</button>
  </div>
</div>

<!-- Threat level banner -->
<div class="threat-banner" id="threat-banner">
  <div class="threat-banner-left">
    <div class="threat-ring-wrap">
      <canvas id="gauge-canvas" width="100" height="100"></canvas>
      <div class="threat-ring-centre">
        <span class="gauge-pct" id="gauge-pct">—</span>
        <span class="gauge-label">THREAT<br>RATE</span>
      </div>
    </div>
  </div>
  <div class="threat-banner-right">
    <div class="threat-level-label" id="threat-level-label">Loading…</div>
    <p class="threat-level-desc" id="threat-level-desc">Fetching threat intelligence…</p>
    <div class="threat-bar-wrap">
      <div class="threat-bar-track">
        <div class="threat-bar-fill" id="threat-bar-fill" style="width:0%"></div>
      </div>
    </div>
  </div>
</div>

<!-- KPI stat cards -->
<div class="kpi-grid" id="kpi-grid">
  ${Array(9).fill(0).map(() => `
    <div class="kpi-card">
      <div class="kpi-label text-muted">Loading…</div>
      <div class="kpi-value" style="color:var(--text-muted)">—</div>
    </div>`).join('')}
</div>

<!-- Charts row -->
<div class="dash-grid-2">
  <div class="chart-card dash-card-tall">
    <div class="card-header">
      <span class="card-title">📈 Email Volume — Last 14 Days</span>
      <span class="text-muted text-small" id="timeline-total"></span>
    </div>
    <canvas id="chart-timeline"></canvas>
  </div>
  <div class="chart-card">
    <div class="card-header">
      <span class="card-title">🎯 Threat Distribution</span>
    </div>
    <div class="doughnut-wrap">
      <canvas id="chart-verdict"></canvas>
      <div class="doughnut-centre">
        <span class="doughnut-big" id="doughnut-big">—</span>
        <span class="doughnut-sub">Total</span>
      </div>
    </div>
    <div class="verdict-legend" id="verdict-legend"></div>
  </div>
</div>

<!-- Category + Domains -->
<div class="dash-grid-2">
  <div class="chart-card">
    <div class="card-header">
      <span class="card-title">📂 Threat Categories</span>
    </div>
    <div id="category-bars">
      <div class="loading-splash" style="min-height:100px"><div class="spinner-ring"></div></div>
    </div>
  </div>
  <div class="chart-card">
    <div class="card-header">
      <span class="card-title">🌐 Top Sender Domains</span>
    </div>
    <div id="domain-bars">
      <div class="loading-splash" style="min-height:100px"><div class="spinner-ring"></div></div>
    </div>
  </div>
</div>

<!-- Recent threat activity table -->
<div class="card">
  <div class="card-header">
    <span class="card-title">🚨 Recent Threat Activity</span>
    <div style="display:flex;gap:0.5rem;align-items:center">
      <span id="alerts-count" class="text-muted text-small"></span>
      <a href="#reports" class="btn btn-secondary btn-sm">View All →</a>
    </div>
  </div>
  <div id="alerts-feed">
    <div class="loading-splash" style="min-height:100px"><div class="spinner-ring"></div></div>
  </div>
</div>`;
  }

  // ── Animate counter ────────────────────────────────────────────
  function animateCount(el, target, suffix = '') {
    if (!el) return;
    const dur = 700, steps = 25;
    let i = 0;
    const iv = setInterval(() => {
      i++;
      el.textContent = Math.round(target * (i / steps)) + suffix;
      if (i >= steps) { el.textContent = target + suffix; clearInterval(iv); }
    }, dur / steps);
  }

  // ── KPI Cards ──────────────────────────────────────────────────
  function populateKpis(data) {
    const grid = document.getElementById('kpi-grid');
    if (!grid) return;

    const prev = _prevData || {};
    const delta = (key) => {
      if (!prev[key] && prev[key] !== 0) return '';
      const d = data[key] - prev[key];
      if (d === 0) return '';
      return d > 0
        ? `<span class="kpi-delta kpi-delta-up">▲ ${d}</span>`
        : `<span class="kpi-delta kpi-delta-dn">▼ ${Math.abs(d)}</span>`;
    };

    // Derive extra stats from the data
    const total    = data.total || 0;
    const blocked  = data.blocked !== undefined ? data.blocked : (data.critical || 0);
    const quarant  = data.quarantined || 0;
    const susp     = data.suspicious || 0;
    const high     = data.high_risk || 0;
    const crit     = data.critical || 0;

    // BEC/phishing from category breakdown
    const bycat = data.by_category || {};
    const bec   = (bycat['BUSINESS_EMAIL_COMPROMISE'] || 0) + (bycat['PAYMENT_FRAUD'] || 0);
    const cred  = bycat['CREDENTIAL_THEFT'] || 0;
    const spam  = bycat['SPAM'] || 0;

    const cards = [
      { label: 'Total Analyzed', value: total,    icon: '📧', color: 'var(--brand)',      accent: 'accent-brand',      sub: 'All time',             delta: delta('total') },
      { label: 'Threats Blocked',value: blocked,  icon: '🚫', color: 'var(--critical)',   accent: 'accent-critical',   sub: 'Score ≥ 80 or Policy', delta: delta('blocked') },
      { label: 'Quarantined',    value: quarant,  icon: '🔒', color: '#a855f7',           accent: 'accent-purple',     sub: 'Analyst / Policy hold',delta: delta('quarantined') },
      { label: 'Suspicious',     value: susp,     icon: '⚠️', color: 'var(--suspicious)', accent: 'accent-suspicious', sub: 'Score 30–59',          delta: delta('suspicious') },
      { label: 'High Risk',      value: high,     icon: '🔴', color: 'var(--high)',       accent: 'accent-high',       sub: 'Score 60–79',          delta: delta('high_risk') },
      { label: 'Critical',       value: crit,     icon: '💀', color: 'var(--critical)',   accent: 'accent-critical',   sub: 'Score ≥ 80',           delta: delta('critical') },
      { label: 'BEC Detected',   value: bec,      icon: '💸', color: '#14b8a6',           accent: 'accent-teal',       sub: 'Wire fraud + BEC',     delta: '' },
      { label: 'Credential Theft',value: cred,    icon: '🔑', color: '#3b82f6',           accent: 'accent-blue',       sub: 'Password phishing',    delta: '' },
      { label: 'Safe Delivered', value: data.safe||0, icon: '✅', color: 'var(--safe)', accent: 'accent-safe',       sub: 'No threat found',      delta: delta('safe') },
    ];

    grid.innerHTML = cards.map(c => `
      <div class="kpi-card ${c.accent}">
        <div class="kpi-top-row">
          <span class="kpi-icon">${c.icon}</span>
          ${c.delta}
        </div>
        <div class="kpi-value" style="color:${c.color}" id="kv-${c.label.replace(/\s/g,'_')}">${c.value}</div>
        <div class="kpi-label">${c.label}</div>
        <div class="kpi-sub">${c.sub}</div>
      </div>`).join('');

    cards.forEach(c => {
      const el = document.getElementById(`kv-${c.label.replace(/\s/g,'_')}`);
      if (el) animateCount(el, c.value);
    });
  }

  // ── Threat gauge ───────────────────────────────────────────────
  function drawGauge(pct) {
    const canvas = document.getElementById('gauge-canvas');
    if (!canvas) return;
    const ctx = canvas.getContext('2d');
    const cx = 50, cy = 50, r = 40;
    const start = Math.PI * 0.75, sweep = Math.PI * 1.5;

    ctx.clearRect(0, 0, 100, 100);
    ctx.beginPath();
    ctx.arc(cx, cy, r, start, start + sweep);
    ctx.strokeStyle = '#1a2a40';
    ctx.lineWidth   = 8;
    ctx.lineCap     = 'round';
    ctx.stroke();

    const fillAngle = start + sweep * (pct / 100);
    const col = pct >= 60 ? '#dc2626' : pct >= 30 ? '#f59e0b' : '#22c55e';
    const grad = ctx.createLinearGradient(0, 0, 100, 100);
    grad.addColorStop(0, col + 'cc');
    grad.addColorStop(1, col);
    ctx.beginPath();
    ctx.arc(cx, cy, r, start, fillAngle);
    ctx.strokeStyle = grad;
    ctx.lineWidth   = 8;
    ctx.lineCap     = 'round';
    ctx.stroke();

    const pctEl    = document.getElementById('gauge-pct');
    const labelEl  = document.getElementById('threat-level-label');
    const descEl   = document.getElementById('threat-level-desc');
    const barEl    = document.getElementById('threat-bar-fill');
    const banner   = document.getElementById('threat-banner');

    if (pctEl) pctEl.textContent = pct + '%';
    if (barEl) barEl.style.width = pct + '%';

    let level, desc, bannerClass;
    if (pct >= 60) {
      level = '🔴 CRITICAL THREAT LEVEL';
      desc  = 'More than half of analysed emails are threats. Immediate SOC response required.';
      bannerClass = 'threat-banner-critical';
      if (barEl) barEl.style.background = 'var(--critical)';
    } else if (pct >= 30) {
      level = '🟠 ELEVATED THREAT LEVEL';
      desc  = 'Significant threat activity detected. Active monitoring recommended.';
      bannerClass = 'threat-banner-high';
      if (barEl) barEl.style.background = 'var(--suspicious)';
    } else if (pct > 0) {
      level = '🟡 MODERATE THREAT LEVEL';
      desc  = 'Low-to-moderate threat activity. Standard protocols in place.';
      bannerClass = 'threat-banner-moderate';
      if (barEl) barEl.style.background = 'var(--suspicious)';
    } else {
      level = '🟢 CLEAR — No Active Threats';
      desc  = 'All analysed emails appear safe. System operating normally.';
      bannerClass = 'threat-banner-safe';
      if (barEl) barEl.style.background = 'var(--safe)';
    }

    if (labelEl) labelEl.textContent = level;
    if (descEl)  descEl.textContent  = desc;
    if (banner)  banner.className    = `threat-banner ${bannerClass}`;
  }

  // ── Timeline chart ─────────────────────────────────────────────
  function buildTimeline(data) {
    const ctx = document.getElementById('chart-timeline');
    if (!ctx || !window.Chart) return;

    const days   = Object.keys(data.by_day || {}).sort();
    const counts = days.map(d => data.by_day[d]);
    const total  = counts.reduce((a, b) => a + b, 0);
    const tEl = document.getElementById('timeline-total');
    if (tEl) tEl.textContent = `${total} emails in period`;

    const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 250);
    gradient.addColorStop(0,   'rgba(0,212,255,0.2)');
    gradient.addColorStop(0.7, 'rgba(0,212,255,0.03)');
    gradient.addColorStop(1,   'rgba(0,212,255,0)');

    _charts.push(new Chart(ctx, {
      type: 'line',
      data: {
        labels: days.map(d => new Date(d).toLocaleDateString('en-IN', { day: 'numeric', month: 'short' })),
        datasets: [{
          label: 'Emails',
          data: counts,
          borderColor: '#00d4ff',
          backgroundColor: gradient,
          fill: true,
          tension: 0.45,
          pointBackgroundColor: '#00d4ff',
          pointBorderColor: '#0d1421',
          pointBorderWidth: 2,
          pointRadius: 4,
          pointHoverRadius: 6,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: item => ` ${item.raw} email${item.raw !== 1 ? 's' : ''}`,
            },
          },
        },
        scales: {
          x: { grid: { color: '#1a2a40' }, ticks: { maxTicksLimit: 7 } },
          y: { grid: { color: '#1a2a40' }, beginAtZero: true, ticks: { stepSize: 1 } },
        },
      },
    }));
  }

  // ── Verdict doughnut ───────────────────────────────────────────
  function buildVerdictDoughnut(data) {
    const ctx = document.getElementById('chart-verdict');
    if (!ctx || !window.Chart) return;

    const labels  = Object.keys(data.by_verdict || {});
    const vals    = labels.map(l => data.by_verdict[l]);
    const colours = labels.map(l => verdictColour(l));
    const total   = vals.reduce((a, b) => a + b, 0);

    const centreEl = document.getElementById('doughnut-big');
    if (centreEl) centreEl.textContent = total;

    const legendEl = document.getElementById('verdict-legend');
    if (legendEl) {
      legendEl.innerHTML = labels.map((l, i) => `
        <div class="vleg-item">
          <span class="vleg-dot" style="background:${colours[i]}"></span>
          <span class="vleg-name">${l.replace('_', ' ')}</span>
          <span class="vleg-count">${vals[i]}</span>
        </div>`).join('');
    }

    _charts.push(new Chart(ctx, {
      type: 'doughnut',
      data: {
        labels,
        datasets: [{
          data: vals,
          backgroundColor: colours,
          borderColor: '#0a1220',
          borderWidth: 4,
          hoverOffset: 6,
        }],
      },
      options: {
        responsive: true,
        cutout: '70%',
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: item => ` ${item.label.replace('_', ' ')}: ${item.raw} (${Math.round(item.raw / total * 100)}%)`,
            },
          },
        },
      },
    }));
  }

  // ── Category bars ──────────────────────────────────────────────
  function buildCategoryBars(data) {
    const el = document.getElementById('category-bars');
    if (!el) return;
    const cats   = Object.entries(data.by_category || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const maxVal = cats.length ? cats[0][1] : 1;
    const palette = ['#dc2626','#ef4444','#f59e0b','#22c55e','#3b9eda','#8b5cf6','#ec4899','#14b8a6'];

    if (!cats.length) {
      el.innerHTML = `<p class="text-muted text-small" style="text-align:center;padding:1rem">No category data yet</p>`;
      return;
    }

    el.innerHTML = cats.map(([cat, cnt], i) => {
      const pct = Math.round(cnt / maxVal * 100);
      const col = palette[i % palette.length];
      return `
        <div class="catbar-row">
          <div class="catbar-label">${escHtml(cat.replace(/_/g, ' '))}</div>
          <div class="catbar-track"><div class="catbar-fill" style="width:${pct}%;background:${col}"></div></div>
          <div class="catbar-count" style="color:${col}">${cnt}</div>
        </div>`;
    }).join('');
  }

  // ── Domain bars ────────────────────────────────────────────────
  function buildDomainBars(data) {
    const el = document.getElementById('domain-bars');
    if (!el) return;
    const doms   = (data.top_domains || []).slice(0, 8);
    const maxVal = doms.length ? doms[0][1] : 1;

    if (!doms.length) {
      el.innerHTML = `<p class="text-muted text-small" style="text-align:center;padding:1rem">No domain data yet</p>`;
      return;
    }

    el.innerHTML = doms.map(([domain, cnt]) => {
      const pct = Math.round(cnt / maxVal * 100);
      const cleaned = (domain || '(unknown)').replace(/["><]/g, '').slice(0, 40);
      return `
        <div class="catbar-row">
          <div class="catbar-label font-mono" title="${escHtml(domain)}">${escHtml(cleaned)}</div>
          <div class="catbar-track"><div class="catbar-fill" style="width:${pct}%;background:rgba(0,212,255,0.6)"></div></div>
          <div class="catbar-count" style="color:var(--brand)">${cnt}</div>
        </div>`;
    }).join('');
  }

  // ── Recent alerts table ────────────────────────────────────────
  function buildAlertsFeed(recent) {
    const el = document.getElementById('alerts-feed');
    const countEl = document.getElementById('alerts-count');
    if (!el) return;

    if (!recent || !recent.length) {
      el.innerHTML = `<div class="empty-state" style="min-height:80px"><div class="empty-state-icon">📭</div><div class="empty-state-text">No emails analysed yet</div></div>`;
      return;
    }

    if (countEl) countEl.textContent = `${recent.length} recent`;

    // Table header
    const header = `
      <div style="display:grid;grid-template-columns:80px 1fr 160px 120px 70px 110px;gap:0.5rem;padding:0.4rem 1rem;border-bottom:1px solid var(--border);">
        <span class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.06em">Time</span>
        <span class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.06em">Sender / Subject</span>
        <span class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.06em">Category</span>
        <span class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.06em">Verdict</span>
        <span class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.06em">Score</span>
        <span class="text-xs text-muted" style="text-transform:uppercase;letter-spacing:.06em">Action</span>
      </div>`;

    const rows = recent.map(e => {
      const vc  = verdictClass(e.verdict);
      const sc  = scoreColour(e.score);
      const icon = { SAFE:'✅', SUSPICIOUS:'⚠️', HIGH_RISK:'🔴', CRITICAL:'💀' }[e.verdict] || '📧';
      const timeStr = e.timestamp ? new Date(e.timestamp).toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit' }) : '—';

      // Determine action from decision or score/verdict
      let action = 'DELIVER';
      if (e.decision && e.decision.action) {
        action = e.decision.action;
      } else if (e.score >= 80) {
        action = 'BLOCK';
      } else if (e.score >= 60) {
        action = 'QUARANTINE';
      } else if (e.score >= 30) {
        action = 'FLAG';
      }

      const ac = actionClass(action);

      return `
        <div class="alert-row alert-row-${vc} clickable" data-id="${escHtml(e.id)}"
             style="display:grid;grid-template-columns:80px 1fr 160px 120px 70px 110px;gap:0.5rem;padding:0.65rem 1rem;border-radius:0;border-bottom:1px solid rgba(255,255,255,0.03)">
          <div class="text-small font-mono text-muted">${timeStr}</div>
          <div style="min-width:0">
            <div style="font-size:0.78rem;font-weight:600;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(e.from_address || '—', 50))}</div>
            <div class="text-xs text-muted" style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${escHtml(truncate(e.subject || '(no subject)', 50))}</div>
          </div>
          <div><span class="text-xs text-muted">${escHtml((e.category || '—').replace(/_/g,' '))}</span></div>
          <div><span class="badge badge-${vc}">${icon} ${e.verdict.replace('_',' ')}</span></div>
          <div><span style="font-size:0.85rem;font-weight:700;font-family:'JetBrains Mono',monospace;color:${sc}">${e.score}</span></div>
          <div><span class="badge ${ac}">${action}</span></div>
        </div>`;
    }).join('');

    el.innerHTML = header + rows;

    el.querySelectorAll('.alert-row.clickable').forEach(row => {
      row.addEventListener('click', () => navigate(`#report/${row.dataset.id}`));
    });
  }

  function setRefreshTime() {
    const el = document.getElementById('dash-last-refresh');
    if (el) el.textContent = `Updated ${new Date().toLocaleTimeString('en-IN')}`;
  }

  // ── Master load ────────────────────────────────────────────────
  async function loadDashboard() {
    try {
      const data = await API.get('/api/dashboard');
      populateKpis(data);
      drawGauge(data.threat_percentage || 0);
      destroyCharts();
      buildTimeline(data);
      buildVerdictDoughnut(data);
      buildCategoryBars(data);
      buildDomainBars(data);
      buildAlertsFeed(data.recent);
      setRefreshTime();
      _prevData = data;
    } catch (err) {
      toast(`Dashboard error: ${err.message}`, 'error', 6000);
    }
  }

  // ── Register page ──────────────────────────────────────────────
  registerPage('dashboard', {
    mount(root) {
      applyChartDefaults();
      root.innerHTML = renderPage();
      loadDashboard();

      document.getElementById('dash-refresh')?.addEventListener('click', () => {
        toast('Refreshing…', 'success', 1500);
        destroyCharts();
        loadDashboard();
      });

      const interval = setInterval(loadDashboard, 60_000);
      return () => { clearInterval(interval); destroyCharts(); };
    },
  });

})();
