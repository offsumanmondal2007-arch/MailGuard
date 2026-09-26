/**
 * cookie-consent.js — Cookie consent banner
 * MailGuard AI v2.0
 *
 * NOTE: This platform sets NO first-party cookies.
 * The banner simply informs users of the third-party
 * network requests (Google Fonts, jsDelivr CDN) and
 * is shown once, storing acknowledgement in sessionStorage
 * (not a cookie) so it does not reappear in the same session.
 */
'use strict';

(function () {
  // Use sessionStorage (not a cookie) to track dismissal within the session.
  // This avoids setting a cookie just to remember cookie consent — which would
  // be self-defeating and potentially non-compliant.
  const STORAGE_KEY = 'mg_cookie_notice_dismissed';

  function dismiss() {
    try { sessionStorage.setItem(STORAGE_KEY, '1'); } catch (_) {}
    const banner = document.getElementById('cookie-consent-banner');
    if (banner) {
      banner.style.opacity = '0';
      banner.style.transform = 'translateY(20px)';
      setTimeout(() => banner.remove(), 300);
    }
  }

  function show() {
    if (sessionStorage.getItem(STORAGE_KEY) === '1') return;

    const banner = document.createElement('div');
    banner.id = 'cookie-consent-banner';
    banner.setAttribute('role', 'dialog');
    banner.setAttribute('aria-modal', 'false');
    banner.setAttribute('aria-label', 'Cookie and tracking notice');
    banner.setAttribute('aria-live', 'polite');
    banner.innerHTML = `
<div class="cookie-banner-content">
  <div class="cookie-banner-icon" aria-hidden="true">&#127850;</div>
  <div class="cookie-banner-text">
    <strong>No Cookies — Just a Heads Up</strong>
    <p>This platform sets <strong>no cookies</strong>. However, third-party services like
    <a href="https://policies.google.com/privacy" target="_blank" rel="noopener noreferrer">Google Fonts</a>
    and <a href="https://www.jsdelivr.com/privacy-policy-jsdelivr-net" target="_blank" rel="noopener noreferrer">jsDelivr CDN</a>
    may log network requests.
    <a href="#cookies" id="cookie-learn-more">Learn more</a>.</p>
  </div>
  <div class="cookie-banner-actions">
    <button class="btn btn-primary btn-sm" id="cookie-accept-btn" type="button" aria-label="Acknowledge and dismiss this notice">
      Got it
    </button>
  </div>
</div>`;

    document.body.appendChild(banner);

    // Animate in
    requestAnimationFrame(() => {
      requestAnimationFrame(() => {
        banner.style.opacity = '1';
        banner.style.transform = 'translateY(0)';
      });
    });

    document.getElementById('cookie-accept-btn').addEventListener('click', dismiss);
    document.getElementById('cookie-learn-more').addEventListener('click', (e) => {
      dismiss();
    });

    // Keyboard accessibility: Escape to dismiss
    document.addEventListener('keydown', function onEsc(e) {
      if (e.key === 'Escape') { dismiss(); document.removeEventListener('keydown', onEsc); }
    });
  }

  // Show after a short delay so page renders first
  window.addEventListener('load', () => setTimeout(show, 1500));
})();
