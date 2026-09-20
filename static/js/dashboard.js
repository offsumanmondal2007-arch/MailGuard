/**
 * dashboard.js — Premium SOC Dashboard v2
 * MailGuard AI
 *
 * Features:
 *  • Animated KPI stat cards with delta indicators
 *  • Threat-level radial gauge
 *  • Email volume timeline (line + gradient fill)
 *  • Verdict doughnut with centre KPI
 *  • Category horizontal bars
 *  • Top sender domains
 *  • Live recent-alerts feed with severity rows
 *  • Auto-refresh every 60 s
 */
'use strict';

(function () {
  const { API, toast, verdictClass, verdictColour, scoreColour,
          formatTimestamp, escHtml, truncate, registerPage, navigate } = window.APP;

  let _charts = [];
  let _prevData = null;   // for delta arrows

  // ── Destroy all Chart.js instances ────────────────────────────
  function destroyCharts() {
    _charts.forEach(c => { try { c.destroy(); } catch (_) {} });
    _charts = [];
  }

  // ── Chart.js global defaults ───────────────────────────────────
  function applyChartDefaults() {
    if (!window.Chart) return;
    Chart.defaults.color          = '#8ca0b8';
    Chart.defaults.borderColor    = '#1e2d42';
    Chart.defaults.font.family    = "'Segoe UI', 'Inter', system-ui";
    Chart.defaults.font.size      = 12;
    Chart.defaults.animation      = { duration: 600, easing: 'easeOutQuart' };
  }

  // ── Page HTML skeleton ─────────────────────────────────────────
  function renderPage() {
    return `
<!-- ══ DASHBOARD HEADER ══════════════════════════════════════ -->
<div class="dash-toprow">
  <div>
    <h1 class="page-title">📊 SOC Dashboard</h1>
    <p class="page-subtitle">Real-time email threat intelligence — MailGuard AI</p>
  </div>
  <div class="dash-actions">
    <span id="dash-last-refresh" class="text-muted text-small"></span>
    <button class="btn btn-secondary btn-sm" id="dash-refresh">↻ Refresh</button>
  </div>
</div>

<!-- ══ THREAT LEVEL BANNER ════════════════════════════════════ -->
<div class="threat-banner" id="threat-banner">
  <div class="threat-banner-left">
    <div class="threat-ring-wrap">
      <canvas id="gauge-canvas" width="120" height="120"></canvas>
      <div class="threat-ring-centre" id="gauge-centre">
        <span class="gauge-pct" id="gauge-pct">—</span>
        <span class="gauge-label">THREAT<br>RATE</span>
      </div>
    </div>
  </div>
  <div class="threat-banner-right">
    <div class="threat-level-label" id="threat-level-label">Loading…</div>
    <p class="threat-level-desc" id="threat-level-desc">Fetching current threat intelligence…</p>
    <div class="threat-bar-wrap">
      <div class="threat-bar-track">
        <div class="threat-bar-fill" id="threat-bar-fill" style="width:0%"></div>
      </div>
    </div>
  </div>
</div>

<!-- ══ KPI STAT CARDS ═════════════════════════════════════════ -->
<div class="kpi-grid" id="kpi-grid">
  ${buildKpiSkeleton()}
</div>

<!-- ══ CHARTS ROW 1 ══════════════════════════════════════════ -->
<div class="dash-grid-2">

  <!-- Timeline -->
  <div class="chart-card dash-card-tall">
    <div class="card-header">
      <span class="card-title">📈 Email Volume — Last 14 Days</span>
      <span class="text-muted text-small" id="timeline-total"></span>
    </div>
    <canvas id="chart-timeline"></canvas>
  </div>

  <!-- Verdict doughnut -->
  <div class="chart-card">
    <div class="card-header">
      <span class="card-title">🥧 Threat Distribution</span>
    </div>
    <div class="doughnut-wrap">
      <canvas id="chart-verdict"></canvas>
      <div class="doughnut-centre" id="doughnut-centre">
        <span class="doughnut-big" id="doughnut-big">—</span>
        <span class="doughnut-sub">Total</span>
      </div>
    </div>
    <div class="verdict-legend" id="verdict-legend"></div>
  </div>

</div>

<!-- ══ CHARTS ROW 2 ══════════════════════════════════════════ -->
<div class="dash-grid-2">

  <!-- Category bars -->
  <div class="chart-card">
    <div class="card-header">
      <span class="card-title">📂 Threat Categories</span>
    </div>
    <div id="category-bars">
      <div class="loading-splash" style="min-height:120px"><div class="spinner-ring"></div></div>
    </div>
  </div>

  <!-- Top domains -->
  <div class="chart-card">
    <div class="card-header">
      <span class="card-title">🌐 Top Sender Domains</span>
    </div>
    <div id="domain-bars">
      <div class="loading-splash" style="min-height:120px"><div class="spinner-ring"></div></div>
    </div>
  </div>

</div>

<!-- ══ RECENT ALERTS FEED ═════════════════════════════════════ -->
<div class="card">
  <div class="card-header">
    <span class="card-title">🚨 Recent Alerts Feed</span>
    <div style="display:flex;gap:0.5rem;align-items:center">
      <span id="alerts-count" class="text-muted text-small"></span>
      <a href="#reports" class="btn btn-secondary btn-sm">View All →</a>
    </div>
  </div>
  <div id="alerts-feed">
    <div class="loading-splash" style="min-height:120px"><div class="spinner-ring"></div></div>
  </div>
</div>`;
  }

  // ── KPI skeleton placeholders ──────────────────────────────────
  function buildKpiSkeleton() {
    return Array(6).fill(0).map(() => `
      <div class="kpi-card">
        <div class="kpi-label text-muted">Loading…</div>
        <div class="kpi-value" style="color:var(--text-muted)">—</div>
      </div>`).join('');
  }

  // ── Animate a counter from 0 ──────────────────────────────────
  function animateCount(el, target, suffix = '') {
    const dur = 800, steps = 30;
    let i = 0;
    const iv = setInterval(() => {
      i++;
      el.textContent = Math.round(target * (i / steps)) + suffix;
      if (i >= steps) { el.textContent = target + suffix; clearInterval(iv); }
    }, dur / steps);
  }

  // ── KPI Cards ─────────────────────────────────────────────────
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

    const cards = [
      {
        label: 'Total Analysed',
        value: data.total,
        sub:   'All time',
        color: 'var(--brand)',
        accent:'accent-brand',
        icon:  '📧',
        delta: delta('total'),
      },
      {
        label: 'Safe',
        value: data.safe,
        sub:   data.total ? `${Math.round(data.safe / data.total * 100)}% of total` : '0%',
        color: 'var(--safe)',
        accent:'accent-safe',
        icon:  '✅',
        delta: delta('safe'),
      },
      {
        label: 'Suspicious',
        value: data.suspicious,
        sub:   data.total ? `${Math.round(data.suspicious / data.total * 100)}% of total` : '0%',
        color: 'var(--suspicious)',
        accent:'accent-suspicious',
        icon:  '⚠️',
        delta: delta('suspicious'),
      },
      {
        label: 'High Risk',
        value: data.high_risk,
        sub:   data.total ? `${Math.round(data.high_risk / data.total * 100)}% of total` : '0%',
        color: 'var(--high)',
        accent:'accent-high',
        icon:  '🔴',
        delta: delta('high_risk'),
      },
      {
        label: 'Critical',
        value: data.critical,
        sub:   data.total ? `${Math.round(data.critical / data.total * 100)}% of total` : '0%',
        color: 'var(--critical)',
        accent:'accent-critical',
        icon:  '💀',
        delta: delta('critical'),
      },
      {
        label: 'Quarantined',
        value: data.quarantined || 0,
        sub:   'Analyst-flagged',
        color: '#a855f7',
        accent:'accent-purple',
        icon:  '🔒',
        delta: delta('quarantined'),
      },
    ];

    grid.innerHTML = cards.map(c => `
      <div class="kpi-card ${c.accent}">
        <div class="kpi-top-row">
          <span class="kpi-icon">${c.icon}</span>
          ${c.delta}
        </div>
        <div class="kpi-value" style="color:${c.color}" id="kpi-val-${c.label.replace(/\s/g,'')}">0</div>
        <div class="kpi-label">${c.label}</div>
        <div class="kpi-sub">${c.sub}</div>
      </div>`).join('');

    // Animate counters
    cards.forEach(c => {
      const el = document.getElementById(`kpi-val-${c.label.replace(/\s/g,'')}`);
      if (el) animateCount(el, c.value);
    });
  }

  // ── Threat gauge (custom canvas) ──────────────────────────────
  function drawGauge(pct) {
    const canvas = document.getElementById('gauge-canvas');
    if (!canvas) return;
    const ctx    = canvas.getContext('2d');
    const cx = 60, cy = 60, r = 48;
    const start = Math.PI * 0.75, sweep = Math.PI * 1.5;

    ctx.clearRect(0, 0, 120, 120);

    // Track
    ctx.beginPath();
    ctx.arc(cx, cy, r, start, start + sweep);
    ctx.strokeStyle = '#1e2d42';
    ctx.lineWidth   = 10;
    ctx.lineCap     = 'round';
    ctx.stroke();

    // Fill
    const fillAngle = start + sweep * (pct / 100);
    const col = pct >= 60 ? '#dc2626' : pct >= 30 ? '#f59e0b' : '#22c55e';

    const grad = ctx.createLinearGradient(0, 0, 120, 120);
    grad.addColorStop(0, col + 'cc');
    grad.addColorStop(1, col);

    ctx.beginPath();
    ctx.arc(cx, cy, r, start, fillAngle);
    ctx.strokeStyle = grad;
    ctx.lineWidth   = 10;
    ctx.lineCap     = 'round';
    ctx.stroke();

    // Update centre text
    const pctEl   = document.getElementById('gauge-pct');
    const labelEl = document.getElementById('threat-level-label');
    const descEl  = document.getElementById('threat-level-desc');
    const barEl   = document.getElementById('threat-bar-fill');
    const banner  = document.getElementById('threat-banner');

    if (pctEl) pctEl.textContent = pct + '%';
    if (barEl) barEl.style.width = pct + '%';

    let level, desc, bannerClass;
    if (pct >= 60) {
      level      = '🔴 CRITICAL THREAT LEVEL';
      desc       = 'More than half of analysed emails are threats. Immediate SOC response required.';
      bannerClass= 'threat-banner-critical';
      if (barEl) barEl.style.background = 'var(--critical)';
    } else if (pct >= 30) {
      level      = '🟠 ELEVATED THREAT LEVEL';
      desc       = 'Significant threat activity detected. Active monitoring recommended.';
      bannerClass= 'threat-banner-high';
      if (barEl) barEl.style.background = 'var(--suspicious)';
    } else if (pct > 0) {
      level      = '🟡 MODERATE THREAT LEVEL';
      desc       = 'Low-to-moderate threat activity. Standard protocols in place.';
      bannerClass= 'threat-banner-moderate';
      if (barEl) barEl.style.background = 'var(--suspicious)';
    } else {
      level      = '🟢 CLEAR — No Threats Detected';
      desc       = 'All analysed emails appear safe. System operating normally.';
      bannerClass= 'threat-banner-safe';
      if (barEl) barEl.style.background = 'var(--safe)';
    }

    if (labelEl) labelEl.textContent = level;
    if (descEl)  descEl.textContent  = desc;
    if (banner) {
      banner.className = `threat-banner ${bannerClass}`;
    }
  }

  // ── Timeline chart ─────────────────────────────────────────────
  function buildTimeline(data) {
    const ctx = document.getElementById('chart-timeline');
    if (!ctx || !window.Chart) return;

    const days   = Object.keys(data.by_day || {}).sort();
    const counts = days.map(d => data.by_day[d]);
    const total  = counts.reduce((a, b) => a + b, 0);

    const totalEl = document.getElementById('timeline-total');
    if (totalEl) totalEl.textContent = `${total} emails in period`;

    const gradient = ctx.getContext('2d').createLinearGradient(0, 0, 0, 280);
    gradient.addColorStop(0,   'rgba(0,212,255,0.25)');
    gradient.addColorStop(0.6, 'rgba(0,212,255,0.05)');
    gradient.addColorStop(1,   'rgba(0,212,255,0)');

    _charts.push(new Chart(ctx, {
      type: 'line',
      data: {
        labels: days.map(d => {
          const dt = new Date(d);
          return dt.toLocaleDateString('en-IN', { day: 'numeric', month: 'short' });
        }),
        datasets: [{
          label:            'Emails',
          data:             counts,
          borderColor:      '#00d4ff',
          backgroundColor:  gradient,
          fill:             true,
          tension:          0.45,
          pointBackgroundColor: '#00d4ff',
          pointBorderColor:     '#0d1421',
          pointBorderWidth:     2,
          pointRadius:          5,
          pointHoverRadius:     7,
        }],
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              title: items => items[0].label,
              label: item  => ` ${item.raw} email${item.raw !== 1 ? 's' : ''}`,
            },
          },
        },
        scales: {
          x: { grid: { color: '#1e2d42' }, ticks: { maxTicksLimit: 7 } },
          y: { grid: { color: '#1e2d42' }, beginAtZero: true, ticks: { stepSize: 1 } },
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

    // Legend
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
          data:            vals,
          backgroundColor: colours,
          borderColor:     '#111927',
          borderWidth:     4,
          hoverOffset:     8,
        }],
      },
      options: {
        responsive: true,
        cutout: '68%',
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

  // ── Category progress bars ─────────────────────────────────────
  function buildCategoryBars(data) {
    const el = document.getElementById('category-bars');
    if (!el) return;

    const cats    = Object.entries(data.by_category || {}).sort((a, b) => b[1] - a[1]).slice(0, 8);
    const maxVal  = cats.length ? cats[0][1] : 1;
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
          <div class="catbar-track">
            <div class="catbar-fill" style="width:${pct}%;background:${col}"></div>
          </div>
          <div class="catbar-count" style="color:${col}">${cnt}</div>
        </div>`;
    }).join('');

    // Animate bars in
    requestAnimationFrame(() => {
      el.querySelectorAll('.catbar-fill').forEach(b => {
        b.style.transition = 'width 0.7s cubic-bezier(0.4,0,0.2,1)';
      });
    });
  }

  // ── Domain progress bars ───────────────────────────────────────
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
      const pct      = Math.round(cnt / maxVal * 100);
      const cleaned  = (domain || '(unknown)').replace(/[">]/g, '').slice(0, 40);
      return `
        <div class="catbar-row">
          <div class="catbar-label font-mono" title="${escHtml(domain)}">${escHtml(cleaned)}</div>
          <div class="catbar-track">
            <div class="catbar-fill" style="width:${pct}%;background:rgba(0,212,255,0.7)"></div>
          </div>
          <div class="catbar-count" style="color:var(--brand)">${cnt}</div>
        </div>`;
    }).join('');
  }

  // ── Recent alerts feed ─────────────────────────────────────────
  function buildAlertsFeed(recent) {
    const el = document.getElementById('alerts-feed');
    const countEl = document.getElementById('alerts-count');
    if (!el) return;

    if (!recent || !recent.length) {
      el.innerHTML = `
        <div class="empty-state" style="min-height:100px">
          <div class="empty-state-icon">📭</div>
          <div class="empty-state-text">No emails analysed yet</div>
        </div>`;
      return;
    }

    if (countEl) countEl.textContent = `${recent.length} recent`;

    el.innerHTML = recent.map(e => {
      const vc  = verdictClass(e.verdict);
      const sc  = scoreColour(e.score);
      const icon = { SAFE:'✅', SUSPICIOUS:'⚠️', HIGH_RISK:'🔴', CRITICAL:'💀' }[e.verdict] || '📧';
      return `
        <div class="alert-row alert-row-${vc} clickable" data-id="${escHtml(e.id)}">
          <div class="alert-icon">${icon}</div>
          <div class="alert-body">
            <div class="alert-subject">${escHtml(truncate(e.subject || '(no subject)', 55))}</div>
            <div class="alert-from text-muted">${escHtml(truncate(e.from_address || '—', 45))}</div>
          </div>
          <div class="alert-meta">
            <span class="badge badge-${vc}">${e.verdict.replace('_', ' ')}</span>
            <span class="alert-score" style="color:${sc}">${e.score}/100</span>
            <span class="alert-time text-muted">${formatTimestamp(e.timestamp)}</span>
          </div>
        </div>`;
    }).join('');

    el.querySelectorAll('.alert-row.clickable').forEach(row => {
      row.addEventListener('click', () => navigate(`#report/${row.dataset.id}`));
    });
  }

  // ── Last-refresh timestamp ─────────────────────────────────────
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
        loadDashboard();
      });

      const interval = setInterval(loadDashboard, 60_000);
      return () => { clearInterval(interval); destroyCharts(); };
    },
  });

})();
