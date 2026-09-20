/**
 * app.js — SPA Router, shared utilities, health check
 * MailGuard AI
 *
 * Hash-based routing:  #analyze | #dashboard | #reports | #about | #report/{id}
 * All API calls use relative paths → works from any port.
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

function checkIcon(result) {
  const map = { pass: '✓', fail: '✗', warn: '⚠', info: 'ℹ' };
  return map[result] || '•';
}

function formatTimestamp(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleString('en-IN', { dateStyle: 'medium', timeStyle: 'short' });
}

function escHtml(str) {
  const d = document.createElement('div');
  d.textContent = str;
  return d.innerHTML;
}

function truncate(str, max = 60) {
  if (!str) return '—';
  return str.length > max ? str.slice(0, max) + '…' : str;
}

// ═══════════════════════════════════════════════════════════
// Router
// ═══════════════════════════════════════════════════════════
const PAGES = {};  // Filled by page scripts: PAGES['analyze'] = { mount, unmount }

function registerPage(name, handlers) {
  PAGES[name] = handlers;
}

let _currentPage = null;
let _currentCleanup = null;

function navigate(hash) {
  const raw = hash.replace(/^#/, '') || 'analyze';
  const [page, ...params] = raw.split('/');

  // Update nav active state
  document.querySelectorAll('.nav-link').forEach(a => {
    a.classList.toggle('active', a.dataset.page === page);
  });

  // Unmount current page
  if (_currentCleanup) { try { _currentCleanup(); } catch (_) {} }
  _currentCleanup = null;
  _currentPage = null;

  const root = document.getElementById('app-root');

  const handler = PAGES[page];
  if (handler) {
    _currentPage = page;
    const cleanup = handler.mount(root, params);
    _currentCleanup = cleanup || null;
  } else {
    root.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🔍</div>
        <div class="empty-state-text">Page not found: <code>#${raw}</code></div>
        <a href="#analyze" class="btn btn-secondary btn-sm mt-1">Go to Analyze</a>
      </div>`;
  }
}

window.addEventListener('hashchange', () => navigate(location.hash));

// ═══════════════════════════════════════════════════════════
// Health check
// ═══════════════════════════════════════════════════════════
async function checkHealth() {
  const dot  = document.getElementById('status-dot');
  const text = document.getElementById('status-text');
  try {
    const h = await API.get('/api/health');
    dot.className  = 'status-dot online';
    text.textContent = `${h.service} — Online`;
  } catch (_) {
    dot.className  = 'status-dot offline';
    text.textContent = 'Backend offline';
  }
}

// ═══════════════════════════════════════════════════════════
// Boot — run after all scripts load
// ═══════════════════════════════════════════════════════════
window.addEventListener('load', () => {
  checkHealth();
  setInterval(checkHealth, 30_000);
  navigate(location.hash || '#analyze');
});

// Export globals for page scripts
window.APP = { API, toast, verdictClass, verdictColour, scoreColour, checkIcon, formatTimestamp, escHtml, truncate, registerPage, navigate };
