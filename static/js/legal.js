/**
 * legal.js — Legal & Compliance Pages
 * MailGuard AI v2.0 — SIH 2026 Project
 *
 * Pages: privacy | terms | cookies | refund
 *
 * Compliance scope:
 *   * India Digital Personal Data Protection (DPDP) Act, 2023
 *   * India IT Act, 2000 (Sec 43A & 72A)
 *   * India Consumer Protection Act, 2019
 *   * WCAG 2.1 AA accessibility
 */
'use strict';

(function () {
  const { registerPage, escHtml } = window.APP;

  // Shared constants
  const EFFECTIVE_DATE = 'September 26, 2026';
  const LAST_UPDATED   = 'September 26, 2026';
  const PROJECT_NAME   = 'MailGuard AI';
  const PROJECT_FULL   = 'MailGuard AI — Email Security Gateway';
  const TEAM_NAME      = 'Team MailGuard (SIH 2026)';
  const CONTACT_EMAIL  = 'offsumanmondal2007@gmail.com';
  const JURISDICTION   = 'India';

  // Shared render helpers
  function legalHeader(title, icon, subtitle) {
    return `
<div class="legal-hero" role="banner">
  <div class="legal-hero-icon" aria-hidden="true">${icon}</div>
  <h1 class="legal-hero-title">${escHtml(title)}</h1>
  <p class="legal-hero-sub">${escHtml(subtitle)}</p>
  <div class="legal-meta">
    <span class="legal-badge">Effective: ${escHtml(EFFECTIVE_DATE)}</span>
    <span class="legal-badge">Last Updated: ${escHtml(LAST_UPDATED)}</span>
    <span class="legal-badge badge-warn-legal">Academic Research Project</span>
  </div>
</div>`;
  }

  function legalSection(id, icon, title, content) {
    return `
<section class="legal-section card mb-2" id="${escHtml(id)}" aria-labelledby="${escHtml(id)}-heading">
  <div class="card-header">
    <h2 class="card-title" id="${escHtml(id)}-heading"><span aria-hidden="true">${icon}</span> ${escHtml(title)}</h2>
  </div>
  <div class="legal-body">${content}</div>
</section>`;
  }

  function disclaimer() {
    return `
<div class="disclaimer-box" role="note" aria-label="Important disclaimer">
  <div class="disclaimer-title">&#9888; Academic Research Prototype</div>
  <p>This is an academic research prototype developed for Smart India Hackathon 2026. It is NOT a commercial product or service. No commercial transactions occur. No real user payment data, financial data, or sensitive personal data is collected. Email content submitted is used solely for threat detection and stored locally on the server.</p>
</div>`;
  }

  function legalNav(activePage) {
    const links = [
      { page: 'privacy', label: 'Privacy Policy',    icon: '&#128274;' },
      { page: 'terms',   label: 'Terms & Conditions', icon: '&#128203;' },
      { page: 'cookies', label: 'Cookie Policy',     icon: '&#127850;' },
      { page: 'refund',  label: 'Refund Policy',     icon: '&#128176;' },
    ];
    return `
<nav class="legal-nav-tabs" aria-label="Legal pages navigation">
  ${links.map(l => `
    <a href="#${l.page}"
       class="legal-tab${activePage === l.page ? ' active' : ''}"
       aria-current="${activePage === l.page ? 'page' : 'false'}">
      <span aria-hidden="true">${l.icon}</span> ${l.label}
    </a>`).join('')}
</nav>`;
  }

  // ================================================================
  // PRIVACY POLICY
  // ================================================================
  registerPage('privacy', {
    mount(root) {
      root.innerHTML = legalHeader('Privacy Policy', '&#128274;', 'How ' + PROJECT_NAME + ' handles your data — DPDP Act 2023 compliant')
      + legalNav('privacy')
      + legalSection('who-we-are', '&#8505;', 'Who We Are',
        '<p>This Privacy Policy applies to <strong>' + escHtml(PROJECT_FULL) + '</strong>, developed by <strong>' + escHtml(TEAM_NAME) + '</strong> as an academic research prototype for Smart India Hackathon (SIH) 2026.</p>'
        + '<p class="mt-1">We are <strong>not</strong> a registered company or commercial entity. This tool is intended solely for academic demonstration, research, and evaluation purposes.</p>'
        + '<div class="legal-contact-box mt-1"><strong>Data Point of Contact (Grievance Officer):</strong><br>'
        + '<a href="mailto:' + escHtml(CONTACT_EMAIL) + '" aria-label="Send email to data controller">' + escHtml(CONTACT_EMAIL) + '</a></div>'
      )
      + legalSection('data-we-collect', '&#128230;', 'Data We Collect and Why',
        '<p>We follow the principle of <strong>data minimisation</strong> under the DPDP Act 2023: we collect only what is strictly necessary for the email security analysis service to function.</p>'
        + '<table class="legal-table" role="table" aria-label="Data collection summary">'
        + '<thead><tr><th scope="col">Data Type</th><th scope="col">What We Collect</th><th scope="col">Purpose</th><th scope="col">Legal Basis (DPDP)</th></tr></thead>'
        + '<tbody>'
        + '<tr><td>Email Content</td><td>Subject, from address, reply-to, headers, body — submitted by you voluntarily</td><td>Core threat detection and forensic analysis</td><td>Consent (you submit it voluntarily)</td></tr>'
        + '<tr><td>Sender IP Address</td><td>IP address you optionally provide in the form</td><td>IP geolocation for threat context</td><td>Consent (optional field)</td></tr>'
        + '<tr><td>Analysis Results</td><td>Threat score, verdict, forensic breakdown</td><td>Dashboard, investigation, audit trail</td><td>Legitimate purpose (security research)</td></tr>'
        + '<tr><td>Server Logs</td><td>HTTP request method, path, timestamp, status code</td><td>Error diagnostics and server health</td><td>Legitimate purpose (operational necessity)</td></tr>'
        + '</tbody></table>'
        + '<div class="legal-highlight mt-1"><strong>We do NOT collect:</strong> names, government IDs, biometric data, financial data, passwords, location data, device fingerprints, advertising identifiers, or any personal data beyond what you voluntarily submit in the analysis form.</div>'
      )
      + legalSection('no-tracking', '&#128683;', 'Analytics and Tracking',
        '<p>This platform does <strong>not</strong> use any third-party analytics, advertising trackers, or behavioural tracking scripts.</p>'
        + '<ul class="legal-list">'
        + '<li><strong>No Google Analytics, Google Tag Manager, or Firebase</strong></li>'
        + '<li><strong>No Facebook/Meta Pixel or social media trackers</strong></li>'
        + '<li><strong>No advertising networks of any kind</strong></li>'
        + '<li><strong>No session recording tools (Hotjar, FullStory, etc.)</strong></li>'
        + '</ul>'
        + '<p class="mt-1"><strong>Third-party libraries that make network requests:</strong></p>'
        + '<ul class="legal-list">'
        + '<li><strong>Chart.js 4.4.3</strong> (jsDelivr CDN) — used for dashboard charts only. No tracking data sent.</li>'
        + '<li><strong>Google Fonts</strong> (Inter, JetBrains Mono) — typography only. Google may log font requests (IP, user-agent) per their privacy policy.</li>'
        + '<li><strong>ip-api.com</strong> — the backend server calls this API to geolocate sender IPs you submit. The IP you enter in the form is sent to ip-api.com. See <a href="https://ip-api.com/docs/legal" target="_blank" rel="noopener noreferrer">ip-api.com legal terms</a>.</li>'
        + '</ul>'
      )
      + legalSection('data-storage', '&#128452;', 'Data Storage and Security',
        '<ul class="legal-list">'
        + '<li>All analysis data is stored in a local <strong>SQLite database</strong> on the server running this application.</li>'
        + '<li>Data is <strong>not</strong> transmitted to any cloud, third-party SaaS, or remote database.</li>'
        + '<li>The application typically runs locally (<code>127.0.0.1:8000</code>) or via a temporary Cloudflare tunnel for demonstration.</li>'
        + '<li>We do not implement encryption-at-rest for the SQLite database in this prototype. <strong>Do not submit real confidential emails.</strong></li>'
        + '</ul>'
        + '<div class="legal-highlight mt-1"><strong>Recommendation:</strong> Use only the built-in Demo Scenarios. Do not paste real personal or confidential email content.</div>'
      )
      + legalSection('your-rights', '&#9878;', 'Your Rights Under DPDP Act 2023',
        '<p>The Digital Personal Data Protection Act, 2023 grants you the following rights as a Data Principal:</p>'
        + '<div class="legal-rights-grid">'
        + '<div class="legal-right-card"><div class="legal-right-title">Right to Access (Sec 11)</div><p>Request a summary of personal data we hold.</p></div>'
        + '<div class="legal-right-card"><div class="legal-right-title">Right to Correction (Sec 12)</div><p>Request correction of inaccurate personal data.</p></div>'
        + '<div class="legal-right-card"><div class="legal-right-title">Right to Erasure (Sec 12)</div><p>Request deletion of submitted email data from our local database.</p></div>'
        + '<div class="legal-right-card"><div class="legal-right-title">Right to Grievance Redressal (Sec 13)</div><p>Raise a data-related complaint. We respond within 48 hours.</p></div>'
        + '<div class="legal-right-card"><div class="legal-right-title">Right to Nominate (Sec 14)</div><p>Nominate another person to exercise your rights in case of death or incapacity.</p></div>'
        + '</div>'
        + '<p class="mt-1">To exercise any right, contact: <a href="mailto:' + escHtml(CONTACT_EMAIL) + '">' + escHtml(CONTACT_EMAIL) + '</a></p>'
      )
      + legalSection('data-retention', '&#8987;', 'Data Retention',
        '<ul class="legal-list">'
        + '<li>Submitted email data is retained in the local SQLite database for the duration of the server session.</li>'
        + '<li>There is no automatic deletion schedule in this prototype. In a production deployment, a retention policy of 90 days would apply with automated purge.</li>'
        + '<li>Server access logs follow standard OS log rotation policies (typically 7-30 days).</li>'
        + '</ul>'
      )
      + legalSection('minors', '&#128118;', 'Protection of Minors',
        '<p>This platform is intended for security professionals, researchers, and students aged 18 and above. As per DPDP Act 2023 Section 9, we do not knowingly process personal data of children under 18 without verifiable parental consent. If you believe a minor has submitted data without consent, contact us immediately at <a href="mailto:' + escHtml(CONTACT_EMAIL) + '">' + escHtml(CONTACT_EMAIL) + '</a>.</p>'
      )
      + legalSection('changes-privacy', '&#128260;', 'Changes to This Policy',
        '<p>We may update this Privacy Policy as the project evolves. The "Last Updated" date at the top reflects the most recent revision. We will make reasonable efforts to notify users of significant changes.</p>'
      )
      + disclaimer();
    },
  });

  // ================================================================
  // TERMS & CONDITIONS
  // ================================================================
  registerPage('terms', {
    mount(root) {
      root.innerHTML = legalHeader('Terms & Conditions', '&#128203;', 'Terms of use for ' + PROJECT_NAME + ' — please read before using')
      + legalNav('terms')
      + legalSection('acceptance', '&#10003;', 'Acceptance of Terms',
        '<p>By accessing or using <strong>' + escHtml(PROJECT_FULL) + '</strong>, you agree to these Terms. If you do not agree, do not use this platform.</p>'
        + '<p class="mt-1">This platform is made available exclusively as an <strong>academic research prototype</strong> for evaluation and demonstration during Smart India Hackathon 2026. It is not a commercial product.</p>'
      )
      + legalSection('permitted-use', '&#9989;', 'Permitted Use',
        '<p>You may use this platform only for:</p>'
        + '<ul class="legal-list">'
        + '<li>Evaluating the email threat detection capabilities of this prototype.</li>'
        + '<li>Academic research, security demonstrations, and educational purposes.</li>'
        + '<li>Testing with the provided demo scenarios or with email content you own or have explicit permission to use.</li>'
        + '</ul>'
      )
      + legalSection('prohibited-use', '&#128683;', 'Prohibited Use',
        '<p>You must <strong>not</strong>:</p>'
        + '<ul class="legal-list">'
        + '<li>Submit other individuals&#39; private emails without their explicit written consent.</li>'
        + '<li>Attempt to reverse-engineer, scrape, or abuse the API endpoints maliciously.</li>'
        + '<li>Use this platform to process real production email traffic without proper legal authorisation.</li>'
        + '<li>Submit content containing malware, illegal material, or content violating Indian law.</li>'
        + '<li>Represent this prototype as a production-ready commercial security product.</li>'
        + '<li>Use automated tools or bots to flood the API with requests.</li>'
        + '</ul>'
      )
      + legalSection('no-warranty', '&#9888;', 'No Warranty — Research Prototype',
        '<p>This software is provided <strong>"AS IS"</strong> without warranty of any kind, express or implied. We make <strong>no representations</strong> that:</p>'
        + '<ul class="legal-list">'
        + '<li>The threat detection is accurate, complete, or fit for any production security purpose.</li>'
        + '<li>The platform will be available without interruption, errors, or data loss.</li>'
        + '<li>The scoring or verdicts constitute legal, professional, or certified security advice.</li>'
        + '</ul>'
        + '<div class="legal-highlight mt-1"><strong>Critical Warning:</strong> Do NOT use this prototype to make real security decisions on production email infrastructure. False positives and false negatives are expected. This is a research demonstration only.</div>'
      )
      + legalSection('accuracy-claims', '&#127919;', 'Accuracy — No Unsupported Claims',
        '<p>We have taken care to ensure all claims about capabilities are accurate and evidence-based:</p>'
        + '<ul class="legal-list">'
        + '<li>Features that are incomplete are clearly marked with a PROTOTYPE label.</li>'
        + '<li>The "Heuristic ML Layer" uses rule-based expert scoring — not a trained machine learning model. This is clearly stated.</li>'
        + '<li>IP geolocation shows ISP/datacenter location, not the attacker&#39;s physical address. This is clearly disclosed.</li>'
        + '<li>We make <strong>no claims</strong> of "100% detection rate", "zero false positives", or any unverified performance guarantees.</li>'
        + '<li>Dashboard statistics reflect only locally seeded demo data, not independently verified benchmarks.</li>'
        + '<li>There are <strong>no fake reviews, testimonials, or fabricated user endorsements</strong> on this platform.</li>'
        + '</ul>'
      )
      + legalSection('ip-rights', '&#169;', 'Intellectual Property',
        '<ul class="legal-list">'
        + '<li>Source code, design, and documentation are the intellectual property of <strong>' + escHtml(TEAM_NAME) + '</strong>.</li>'
        + '<li><strong>FastAPI</strong> — MIT License</li>'
        + '<li><strong>Chart.js 4</strong> — MIT License</li>'
        + '<li><strong>SQLite</strong> — Public Domain</li>'
        + '<li><strong>Google Fonts (Inter, JetBrains Mono)</strong> — Open Font License (OFL)</li>'
        + '<li>Emoji characters are part of the Unicode Standard (Unicode Consortium).</li>'
        + '<li><strong>No third-party images, stock photos, or proprietary assets</strong> are used in this project. All visual elements are CSS/emoji-based.</li>'
        + '</ul>'
      )
      + legalSection('liability', '&#9878;', 'Limitation of Liability',
        '<p>To the maximum extent permitted by applicable Indian law, ' + escHtml(TEAM_NAME) + ' shall not be liable for any direct, indirect, incidental, special, or consequential damages arising from use of this platform, incorrect threat verdicts, data loss, or unauthorised access.</p>'
        + '<p class="mt-1">This platform is not covered by any SLA, service guarantee, or commercial support agreement.</p>'
      )
      + legalSection('governing-law', '&#127963;', 'Governing Law &amp; Jurisdiction',
        '<p>These Terms are governed by the laws of <strong>' + escHtml(JURISDICTION) + '</strong>. Any disputes shall be subject to the exclusive jurisdiction of courts in India. Applicable laws include:</p>'
        + '<ul class="legal-list">'
        + '<li>Digital Personal Data Protection (DPDP) Act, 2023</li>'
        + '<li>Information Technology Act, 2000 (and its amendments)</li>'
        + '<li>Consumer Protection Act, 2019 (for any future commercial deployment)</li>'
        + '</ul>'
      )
      + legalSection('contact-terms', '&#128231;', 'Contact',
        '<p>For questions about these Terms:<br>'
        + '<a href="mailto:' + escHtml(CONTACT_EMAIL) + '">' + escHtml(CONTACT_EMAIL) + '</a></p>'
        + '<p class="mt-1"><strong>Project:</strong> ' + escHtml(PROJECT_FULL) + '<br>'
        + '<strong>Team:</strong> ' + escHtml(TEAM_NAME) + '<br>'
        + '<strong>Jurisdiction:</strong> ' + escHtml(JURISDICTION) + '</p>'
      )
      + disclaimer();
    },
  });

  // ================================================================
  // COOKIE POLICY
  // ================================================================
  registerPage('cookies', {
    mount(root) {
      root.innerHTML = legalHeader('Cookie Policy', '&#127850;', 'How ' + PROJECT_NAME + ' uses (or does not use) cookies')
      + legalNav('cookies')
      + legalSection('cookie-summary', '&#128203;', 'Summary',
        '<div class="legal-highlight"><strong>Short answer:</strong> ' + escHtml(PROJECT_NAME) + ' does <strong>not</strong> set any first-party cookies, tracking cookies, or persistent cookies. You do not need to accept or consent to any cookies to use this platform.</div>'
      )
      + legalSection('what-are-cookies', '&#10067;', 'What Are Cookies?',
        '<p>Cookies are small text files stored in your browser. They are used for session management, analytics, personalisation, and advertising tracking. Many websites require you to consent to non-essential cookies under privacy regulations.</p>'
      )
      + legalSection('our-cookies', '&#128269;', 'Cookies We Set',
        '<p>This platform sets <strong>zero first-party cookies</strong>. There is no login system, no user session cookie, no preference cookie, and no tracking cookie.</p>'
        + '<table class="legal-table" role="table" aria-label="First-party cookie table">'
        + '<thead><tr><th scope="col">Cookie Name</th><th scope="col">Type</th><th scope="col">Purpose</th><th scope="col">Duration</th></tr></thead>'
        + '<tbody><tr><td colspan="4" style="text-align:center;color:var(--text-muted);font-style:italic">No cookies are set by this application.</td></tr></tbody>'
        + '</table>'
      )
      + legalSection('third-party-cookies', '&#127760;', 'Third-Party Resources That May Set Cookies',
        '<p>Some third-party resources may make network requests that could set cookies in your browser. We have no control over these:</p>'
        + '<table class="legal-table" role="table" aria-label="Third-party resources and cookie risk">'
        + '<thead><tr><th scope="col">Service</th><th scope="col">Purpose</th><th scope="col">Cookie Risk</th><th scope="col">Privacy Policy</th></tr></thead>'
        + '<tbody>'
        + '<tr><td>Google Fonts</td><td>Typography (Inter, JetBrains Mono)</td><td>Low — Google may log font requests. No persistent tracking cookie typically set.</td><td><a href="https://policies.google.com/privacy" target="_blank" rel="noopener noreferrer">Google Privacy Policy</a></td></tr>'
        + '<tr><td>jsDelivr CDN</td><td>Chart.js library</td><td>Low — CDN logs request metadata. No tracking cookie.</td><td><a href="https://www.jsdelivr.com/privacy-policy-jsdelivr-net" target="_blank" rel="noopener noreferrer">jsDelivr Privacy</a></td></tr>'
        + '<tr><td>ip-api.com</td><td>Backend IP geolocation (server-to-server)</td><td>None — your browser does not contact ip-api.com directly. The server makes this call.</td><td><a href="https://ip-api.com/docs/legal" target="_blank" rel="noopener noreferrer">ip-api Legal</a></td></tr>'
        + '</tbody></table>'
      )
      + legalSection('local-storage', '&#128190;', 'Local Storage and Session Storage',
        '<p>This application uses <strong>hash-based routing</strong> (e.g. <code>#dashboard</code>) for navigation. No data is written to <code>localStorage</code> or <code>sessionStorage</code>. All application state is held in JavaScript memory and is discarded when you close the tab.</p>'
      )
      + legalSection('cookie-consent', '&#10003;', 'Cookie Consent — Is It Required?',
        '<div class="legal-highlight"><strong>No cookie consent banner is required</strong> because this platform sets no cookies. Under India\'s DPDP Act 2023 and IT Act 2000, consent is required for processing personal data — not for applications that set no cookies at all.</div>'
        + '<p class="mt-1">If you wish to block even the third-party font/CDN requests, you may use browser extensions such as uBlock Origin or Privacy Badger. The application will still function correctly with system fonts as fallback.</p>'
      )
      + legalSection('cookie-control', '&#9881;', 'Managing Cookies in Your Browser',
        '<p>You can manage or delete cookies through your browser settings:</p>'
        + '<ul class="legal-list">'
        + '<li><strong>Chrome:</strong> Settings &rarr; Privacy and Security &rarr; Cookies and other site data</li>'
        + '<li><strong>Firefox:</strong> Settings &rarr; Privacy &amp; Security &rarr; Cookies and Site Data</li>'
        + '<li><strong>Edge:</strong> Settings &rarr; Cookies and site permissions</li>'
        + '<li><strong>Safari:</strong> Preferences &rarr; Privacy &rarr; Manage Website Data</li>'
        + '</ul>'
      )
      + disclaimer();
    },
  });

  // ================================================================
  // REFUND POLICY
  // ================================================================
  registerPage('refund', {
    mount(root) {
      root.innerHTML = legalHeader('Refund Policy', '&#128176;', PROJECT_NAME + ' refund and payment policy')
      + legalNav('refund')
      + legalSection('no-payment', '&#127358;', 'This Platform Is Free — No Payments Accepted',
        '<div class="legal-highlight"><strong>' + escHtml(PROJECT_NAME) + '</strong> is a <strong>free, open-source academic research prototype</strong>. We do not accept payments, subscriptions, in-app purchases, donations, or any other form of monetary transaction. No refunds can be or need to be issued.</div>'
      )
      + legalSection('no-charges', '&#10003;', 'What This Means for You',
        '<ul class="legal-list">'
        + '<li>There is <strong>no registration fee</strong>.</li>'
        + '<li>There is <strong>no subscription or premium tier</strong>.</li>'
        + '<li>There are <strong>no in-app purchases</strong>.</li>'
        + '<li>There is <strong>no trial that converts to a paid plan</strong>.</li>'
        + '<li>There are <strong>no hidden charges</strong> of any kind.</li>'
        + '</ul>'
      )
      + legalSection('future-commercial', '&#128302;', 'Future Commercial Use',
        '<p>If ' + escHtml(PROJECT_NAME) + ' is ever developed into a commercial product, this Refund Policy will be updated with a revised effective date before any payments are collected. Any future policy would comply with:</p>'
        + '<ul class="legal-list">'
        + '<li>India Consumer Protection Act, 2019</li>'
        + '<li>RBI payment gateway guidelines</li>'
        + '<li>Applicable SaaS consumer protection norms</li>'
        + '</ul>'
      )
      + legalSection('contact-refund', '&#128231;', 'Contact',
        '<p>For any enquiries (even though no billing should exist), contact:<br>'
        + '<a href="mailto:' + escHtml(CONTACT_EMAIL) + '">' + escHtml(CONTACT_EMAIL) + '</a></p>'
        + '<p class="mt-1"><strong>Project:</strong> ' + escHtml(PROJECT_FULL) + '<br>'
        + '<strong>Team:</strong> ' + escHtml(TEAM_NAME) + '</p>'
      )
      + disclaimer();
    },
  });

})();
