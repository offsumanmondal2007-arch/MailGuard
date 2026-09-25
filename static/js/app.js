/**
 * app.js — SPA Router, shared utilities, health check
 * MailGuard AI v2.0 — Pre-Delivery Email Security Gateway
 *
 * Hash-based routing: #dashboard | #analyze | #reports | #report/{id}
 *   | #threats | #urls | #attachments | #intelligence | #timeline
 *   | #policies | #status | #about
 */

'use strict';

// ═══════════════════════════════════════════════════════════
// API helpers
// ═══════════════════════════════════════════════════════════
const API = {
  async get(path) {
    const res = await fetch(path);
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.detail || err.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  async post(path, body) {
    const res = await fetch(path, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.detail || err.error || `HTTP ${res.status}`);
    }
    return res.json();
  },

  async patch(path, body) {
    const res = await fetch(path, {
      method:  'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });
    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: res.statusText }));
      throw new Error(err.detail || err.error || `HTTP ${res.status}`);
    }
    return res.json();
  },
};

// ═══════════════════════════════════════════════════════════
// Toast notifications
// ═══════════════════════════════════════════════════════════
function toast(message, type = 'success', duration = 4000) {
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.textContent = message;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transition = 'opacity 0.3s';
    setTimeout(() => el.remove(), 300);
  }, duration);
}

// ═══════════════════════════════════════════════════════════
// Verdict / score helpers
// ═══════════════════════════════════════════════════════════
function verdictClass(verdict) {
  return (verdict || 'safe').toLowerCase();
}

function verdictColour(verdict) {
  const map = {
    SAFE:       '#22c55e',
    SUSPICIOUS: '#f59e0b',
    HIGH_RISK:  '#ef4444',
    CRITICAL:   '#dc2626',
  };
  return map[verdict] || '#8ca0b8';
}

function scoreColour(score) {
  if (score >= 80) return '#dc2626';
  if (score >= 60) return '#ef4444';
  if (score >= 30) return '#f59e0b';
  return '#22c55e';
}

function actionColour(action) {
  const map = {
    BLOCK:      '#ef4444',
    QUARANTINE: '#f59e0b',
    FLAG:       '#a855f7',
    DELIVER:    '#22c55e',
  };
  return map[(action||'').toUpperCase()] || '#8ca0b8';
}

function actionClass(action) {
  const map = {
    BLOCK:      'badge-block',
    QUARANTINE: 'badge-quarantine',
    FLAG:       'badge-flag',
    DELIVER:    'badge-deliver',
  };
  return map[(action||'').toUpperCase()] || 'badge-safe';
}

function checkIcon(result) {
  const map = { pass: '✓', fail: '✗', warn: '⚠', info: 'ℹ' };
  return map[result] || '•';
}

function formatTimestamp(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
}

function formatTime(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleTimeString('en-IN', { hour: '2-digit', minute: '2-digit', second: '2-digit' });
}

function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = str || '';
  return d.innerHTML;
}

function truncate(str, max = 60) {
  if (!str) return '—';
  return str.length > max ? str.slice(0, max) + '…' : str;
}

// ═══════════════════════════════════════════════════════════
// Router
// ═══════════════════════════════════════════════════════════
const PAGES = {};

function registerPage(name, handlers) {
  PAGES[name] = handlers;
}

let _currentPage = null;
let _currentCleanup = null;

// Page title map
const PAGE_TITLES = {
  dashboard:    'Dashboard',
  analyze:      'Email Scanner',
  reports:      'Email Investigation',
  report:       'Case Investigation',
  threats:      'Threat Feed',
  urls:         'URL Analysis',
  attachments:  'Attachment Analysis',
  intelligence: 'Threat Intelligence',
  timeline:     'Forensic Timeline',
  policies:     'Security Policies',
  status:       'System Status',
  about:        'About',
};

function getInitialRoute() {
  if (window.location.hash && window.location.hash.length > 1) {
    return window.location.hash;
  }
  const path = (window.location.pathname || '').replace(/^\/+/, '').split('/')[0];
  if (path && PAGE_TITLES[path]) {
    return '#' + (window.location.pathname || '').replace(/^\/+/, '');
  }
  return '#dashboard';
}

function navigate(hash) {
  const raw = (hash || '').replace(/^#/, '') || 'dashboard';
  const [page, ...params] = raw.split('/');

  // Update sidebar nav active state (including child views like report -> reports)
  document.querySelectorAll('.nav-link').forEach(a => {
    const isTarget = a.dataset.page === page || (page === 'report' && a.dataset.page === 'reports');
    a.classList.toggle('active', Boolean(isTarget));
  });

  // Update breadcrumb
  const breadEl = document.getElementById('breadcrumb-page');
  if (breadEl) {
    if (page === 'report' && params[0]) {
      const shortId = params[0].length > 8 ? params[0].slice(0, 8).toUpperCase() : params[0];
      breadEl.innerHTML = `<a href="#reports" style="color:var(--text-muted);text-decoration:none">Investigation</a> <span class="breadcrumb-sep">›</span> Case-${escHtml(shortId)}`;
    } else if (page === 'timeline' && params[0]) {
      const shortId = params[0].length > 8 ? params[0].slice(0, 8).toUpperCase() : params[0];
      breadEl.innerHTML = `<a href="#timeline" style="color:var(--text-muted);text-decoration:none">Forensic Timeline</a> <span class="breadcrumb-sep">›</span> Case-${escHtml(shortId)}`;
    } else {
      breadEl.textContent = PAGE_TITLES[page] || page;
    }
  }

  // Close sidebar on mobile after selecting a destination
  if (window.innerWidth <= 768) {
    const sidebar = document.getElementById('sidebar');
    if (sidebar && !sidebar.classList.contains('collapsed')) {
      sidebar.classList.add('collapsed');
    }
  }

  // Unmount current page
  if (_currentCleanup) { try { _currentCleanup(); } catch (_) {} }
  _currentCleanup = null;
  _currentPage = null;

  const root = document.getElementById('app-root');

  const handler = PAGES[page];
  if (handler) {
    _currentPage = page;
    try {
      const cleanup = handler.mount(root, params);
      _currentCleanup = cleanup || null;
    } catch (err) {
      console.error('Page mount error:', err);
      root.innerHTML = `<div class="empty-state"><div class="empty-state-icon">⚠</div><div class="empty-state-text">Page error: ${escHtml(err.message)}</div></div>`;
    }
  } else {
    root.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🔍</div>
        <div class="empty-state-text">Page not found: <code>#${escHtml(raw)}</code></div>
        <a href="#dashboard" class="btn btn-secondary btn-sm mt-1">Go to Dashboard</a>
      </div>`;
  }
}

window.addEventListener('hashchange', () => navigate(location.hash));

// ═══════════════════════════════════════════════════════════
// Sidebar toggle
// ═══════════════════════════════════════════════════════════
function initSidebarToggle() {
  const toggleBtn = document.getElementById('sidebar-toggle');
  const sidebar   = document.getElementById('sidebar');
  if (!toggleBtn || !sidebar) return;

  toggleBtn.addEventListener('click', () => {
    sidebar.classList.toggle('collapsed');
  });
}

// ═══════════════════════════════════════════════════════════
// Health check
// ═══════════════════════════════════════════════════════════
async function checkHealth() {
  const dot  = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  try {
    const h = await API.get('/api/health');
    if (dot) dot.className  = 'status-dot online';
    if (text) text.textContent = `${h.service} Online`;
  } catch (_) {
    if (dot) dot.className  = 'status-dot offline';
    if (text) text.textContent = 'Backend offline';
  }
}

// ═══════════════════════════════════════════════════════════
// Threat badge updater
// ═══════════════════════════════════════════════════════════
async function updateThreatBadge() {
  try {
    const data = await API.get('/api/dashboard');
    const threats = (data.suspicious || 0) + (data.high_risk || 0) + (data.critical || 0);
    const badge = document.getElementById('threat-badge');
    if (badge) {
      if (threats > 0) {
        badge.textContent = threats > 99 ? '99+' : threats;
        badge.style.display = 'inline-block';
      } else {
        badge.style.display = 'none';
      }
    }
  } catch (_) {}
}

// ═══════════════════════════════════════════════════════════
// Auth status helpers (shared across pages)
// ═══════════════════════════════════════════════════════════
function buildAuthCards(forensics) {
  const items = [
    {
      protocol: 'SPF',
      status: forensics.spf || 'unknown',
      pass: 'Sending server authorized for this domain.',
      fail: 'Sending IP is NOT authorized for this domain.',
      softfail: 'Sending server has soft-fail — partial authorization.',
      unknown: 'SPF record not found in headers.',
      risk_pass: '+0',
      risk_fail: '+20',
      risk_softfail: '+10',
    },
    {
      protocol: 'DKIM',
      status: forensics.dkim || 'unknown',
      pass: 'DKIM signature is valid — message integrity confirmed.',
      fail: 'DKIM signature FAILED — message may have been altered.',
      softfail: 'DKIM result inconclusive.',
      unknown: 'DKIM signature not found in headers.',
      risk_pass: '+0',
      risk_fail: '+15',
      risk_softfail: '+5',
    },
    {
      protocol: 'DMARC',
      status: forensics.dmarc || 'unknown',
      pass: 'DMARC policy satisfied — domain alignment confirmed.',
      fail: 'DMARC policy FAILED — domain alignment not satisfied.',
      softfail: 'DMARC result inconclusive.',
      unknown: 'DMARC record not found in headers.',
      risk_pass: '+0',
      risk_fail: '+15',
      risk_softfail: '+5',
    },
  ];

  return `<div class="auth-cards">` + items.map(item => {
    const s = item.status;
    const cls = s === 'pass' ? 'auth-pass' : s === 'fail' ? 'auth-fail' : s === 'softfail' ? 'auth-warn' : 'auth-unknown';
    const detail = item[s] || item.unknown;
    const risk = item[`risk_${s}`] || '—';
    return `
      <div class="auth-card ${cls}">
        <div class="auth-card-protocol">${item.protocol}</div>
        <div class="auth-card-status">${s.toUpperCase()}</div>
        <div class="auth-card-detail">${escHtml(detail)}</div>
        <div class="auth-card-risk text-muted">Risk contribution: ${risk}</div>
      </div>`;
  }).join('') + `</div>`;
}

// ═══════════════════════════════════════════════════════════
// Boot — run after all scripts load
// ═══════════════════════════════════════════════════════════
window.addEventListener('load', () => {
  initSidebarToggle();
  checkHealth();
  setInterval(checkHealth, 30_000);
  updateThreatBadge();
  setInterval(updateThreatBadge, 60_000);
  navigate(getInitialRoute());
});

// Export globals for page scripts
window.APP = {
  API, toast,
  verdictClass, verdictColour, scoreColour, actionColour, actionClass,
  checkIcon, formatTimestamp, formatTime,
  escHtml, truncate,
  registerPage, navigate,
  buildAuthCards,
};
