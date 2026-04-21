/**
 * UI Injector - Shared Module
 * Injects verdict badge and explainability card into email view
 */

const UIInjector = {

  /** Helper: find sender insertion point */
  _insertionPoint() {
    if (window.location.hostname.includes('mail.google.com')) {
      return document.querySelector('.gD') || document.querySelector('h2.hP');
    }
    if (window.location.hostname.includes('outlook')) {
      return document.querySelector('[aria-label*="From"]');
    }
    return null;
  },

  /** Helper: color for score value */
  _scoreColor(s) {
    return s >= 70 ? '#cf222e' : s >= 40 ? '#d29922' : '#2da44e';
  },

  /** Inject verdict badge near sender name */
  injectBadge(verdict, score) {
    document.getElementById('phishguard-badge')?.remove();

    const v = verdict.toUpperCase();
    const labels = { SAFE: 'Safe', SUSPICIOUS: `Suspicious · ${score}`, PHISHING: `Phishing · ${score}` };

    const badge = document.createElement('span');
    badge.id        = 'phishguard-badge';
    badge.className = `phishguard-badge phishguard-badge-${v.toLowerCase()}`;
    badge.title     = 'PhishGuard AI — click for details';
    badge.textContent = labels[v] || v;

    const pt = this._insertionPoint();
    if (pt) {
      pt.parentNode.insertBefore(badge, pt.nextSibling);
      badge.addEventListener('click', () => this.toggleCard());
    }
    return badge;
  },

  /** Loading badge while analysis runs */
  showLoadingBadge() {
    document.getElementById('phishguard-badge')?.remove();

    const badge = document.createElement('span');
    badge.id        = 'phishguard-badge';
    badge.className = 'phishguard-badge phishguard-badge-loading';
    badge.textContent = 'Analyzing…';

    const pt = this._insertionPoint();
    if (pt) pt.parentNode.insertBefore(badge, pt.nextSibling);
  },

  /** Build and inject the expandable detail card */
  injectCard(result) {
    document.getElementById('phishguard-card')?.remove();

    const v      = (result.verdict || 'UNKNOWN').toUpperCase();
    const score  = result.final_score || 0;
    const conf   = Math.round((result.confidence || 0) * 100);
    const color  = this._scoreColor(score);
    const agents = result.agent_scores || {};

    // ── Card header ──────────────────────────────────────
    let html = `
      <div class="phishguard-card-header">
        <div class="pg-header-left">
          <div class="pg-score-ring"
               style="--pg-ring-color:${color};--pg-ring-pct:${score}%">
            <span class="pg-score-num" style="color:${color}">${score}</span>
          </div>
          <div>
            <div class="pg-verdict-text v-${v.toLowerCase()}">${v}</div>
            <div class="pg-confidence">${conf}% confidence</div>
          </div>
        </div>
        <button class="phishguard-card-close" id="phishguard-close" title="Close">✕</button>
      </div>
      <div class="phishguard-card-body">
    `;

    // ── Spear phishing alert ─────────────────────────────
    if (result.spear_phishing_detected) {
      html += `
        <div class="phishguard-spear-alert">
          <svg width="14" height="14" viewBox="0 0 16 16" fill="currentColor">
            <path d="M8.22 1.754a.25.25 0 00-.44 0L1.698 13.132a.25.25 0 00.22.368h12.164a.25.25 0 00.22-.368L8.22 1.754zm-1.763-.707c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0114.082 15H1.918a1.75 1.75 0 01-1.543-2.575L6.457 1.047zM9 11a1 1 0 11-2 0 1 1 0 012 0zm-.25-5.25a.75.75 0 00-1.5 0v2.5a.75.75 0 001.5 0v-2.5z"/>
          </svg>
          <span><strong>Targeted attack detected</strong> — this email was crafted to target you specifically.</span>
        </div>
      `;
    }

    // ── Agent breakdown ──────────────────────────────────
    const agentLabels = { url_agent: 'URL', content_agent: 'Content',
                          header_agent: 'Header', reputation_agent: 'Reputation' };
    html += `<div class="pg-section"><p class="pg-section-title">Agent Analysis</p>`;

    for (const [key, data] of Object.entries(agents)) {
      const s     = data.score || 0;
      const fill  = this._scoreColor(s);
      const name  = agentLabels[key] || key.replace('_agent', '');
      html += `
        <div class="phishguard-agent-row">
          <div class="phishguard-agent-name">${name}</div>
          <div class="phishguard-score-bar">
            <div class="phishguard-score-fill" style="width:${s}%;background:${fill}"></div>
          </div>
          <div class="phishguard-agent-score" style="color:${fill}">${s}</div>
        </div>
      `;
      if (data.signals?.length) {
        html += '<div class="phishguard-signals">';
        data.signals.slice(0, 2).forEach(sig => {
          html += `<span class="phishguard-signal-chip">${sig}</span>`;
        });
        html += '</div>';
      }
    }
    html += '</div>';

    // ── Suspicious phrases ───────────────────────────────
    if (result.highlighted_phrases?.length) {
      html += `<div class="pg-section"><p class="pg-section-title">Suspicious Phrases</p>`;
      result.highlighted_phrases.slice(0, 4).forEach(phrase => {
        html += `
          <div class="phishguard-phrase severity-${phrase.severity.toLowerCase()}">
            <strong>"${phrase.text}"</strong>
            <p>${phrase.reason}</p>
          </div>
        `;
      });
      html += '</div>';
    }

    // ── URL verdicts ─────────────────────────────────────
    if (result.url_verdicts?.length) {
      html += `<div class="pg-section"><p class="pg-section-title">URLs</p>`;
      result.url_verdicts.forEach(u => {
        const truncated = u.url.length > 52 ? u.url.slice(0, 52) + '…' : u.url;
        html += `
          <div class="phishguard-url verdict-${u.verdict.toLowerCase()}">
            <span class="phishguard-url-verdict">${u.verdict}</span>
            <span class="phishguard-url-text" title="${u.url}">${truncated}</span>
          </div>
        `;
      });
      html += '</div>';
    }

    html += `</div>`; // close card-body

    // ── Footer ───────────────────────────────────────────
    const ms = result.processing_time_ms;
    html += `
      <div class="phishguard-footer">
        <span>PhishGuard AI${ms ? ` · ${Math.round(ms)}ms` : ''}</span>
        <a href="#" class="phishguard-report-link">Report false positive</a>
      </div>
    `;

    const card = document.createElement('div');
    card.id            = 'phishguard-card';
    card.className     = 'phishguard-card';
    card.dataset.verdict = v;
    card.style.display = 'none';
    card.innerHTML     = html;

    const badge = document.getElementById('phishguard-badge');
    if (badge) badge.parentNode.insertBefore(card, badge.nextSibling);

    card.querySelector('#phishguard-close')?.addEventListener('click', () => {
      card.style.display = 'none';
    });

    card.dataset.result = JSON.stringify(result);

    // Persist for popup display
    try {
      chrome.storage.local.set({ lastResult: result });
    } catch (_) {}

    return card;
  },

  /** Toggle card visibility */
  toggleCard() {
    const card = document.getElementById('phishguard-card');
    if (card) card.style.display = card.style.display === 'none' ? 'block' : 'none';
  },

  /** Show a compact toast notification */
  showToast(verdict, score, message) {
    document.getElementById('phishguard-toast')?.remove();

    const v      = (verdict || '').toUpperCase();
    const icons  = { SAFE: '✓', SUSPICIOUS: '⚠', PHISHING: '🛡' };
    const titles = { SAFE: 'No threats found', SUSPICIOUS: 'Suspicious email', PHISHING: 'Phishing detected' };

    const toast = document.createElement('div');
    toast.id        = 'phishguard-toast';
    toast.className = `phishguard-toast phishguard-toast-${v.toLowerCase()}`;
    toast.innerHTML = `
      <span class="phishguard-toast-icon">${icons[v] || '•'}</span>
      <div class="phishguard-toast-body">
        <div class="phishguard-toast-title">${titles[v] || v}</div>
        ${message ? `<div class="phishguard-toast-msg">${message}</div>` : ''}
      </div>
      <button class="phishguard-toast-close" title="Dismiss">✕</button>
    `;

    document.body.appendChild(toast);

    toast.querySelector('.phishguard-toast-close').addEventListener('click', () => {
      toast.classList.add('phishguard-toast-hide');
      setTimeout(() => toast.remove(), 250);
    });

    setTimeout(() => {
      if (toast.isConnected) {
        toast.classList.add('phishguard-toast-hide');
        setTimeout(() => toast.remove(), 250);
      }
    }, 5000);
  },

  /** Show full-screen phishing interstitial for dangerous link clicks */
  showInterstitial(url, onProceed, onBack) {
    document.getElementById('phishguard-interstitial')?.remove();

    const overlay = document.createElement('div');
    overlay.id        = 'phishguard-interstitial';
    overlay.className = 'phishguard-interstitial';
    overlay.innerHTML = `
      <div class="phishguard-interstitial-content">
        <div class="pg-interstitial-body">
          <div class="pg-warning-icon">
            <svg width="22" height="22" viewBox="0 0 16 16" fill="currentColor">
              <path d="M8.22 1.754a.25.25 0 00-.44 0L1.698 13.132a.25.25 0 00.22.368h12.164a.25.25 0 00.22-.368L8.22 1.754zm-1.763-.707c.659-1.234 2.427-1.234 3.086 0l6.082 11.378A1.75 1.75 0 0114.082 15H1.918a1.75 1.75 0 01-1.543-2.575L6.457 1.047zM9 11a1 1 0 11-2 0 1 1 0 012 0zm-.25-5.25a.75.75 0 00-1.5 0v2.5a.75.75 0 001.5 0v-2.5z"/>
            </svg>
          </div>
          <h2>Phishing Link Blocked</h2>
          <p class="pg-subhead">
            PhishGuard AI identified this link as a phishing attempt.
            It may be designed to steal your credentials or personal information.
          </p>
          <div class="pg-url-box">
            <strong>Blocked URL</strong>
            ${url}
          </div>
        </div>
        <div class="phishguard-interstitial-buttons">
          <button class="phishguard-btn-safe" id="pg-btn-back">← Go back to safety</button>
          <button class="phishguard-btn-danger" id="pg-btn-proceed">Proceed anyway</button>
        </div>
      </div>
    `;

    document.body.appendChild(overlay);

    overlay.querySelector('#pg-btn-back').addEventListener('click', () => {
      overlay.remove();
      if (onBack) onBack();
    });

    overlay.querySelector('#pg-btn-proceed').addEventListener('click', () => {
      overlay.remove();
      if (onProceed) onProceed();
    });
  },

  /** Remove all PhishGuard UI elements */
  cleanup() {
    ['phishguard-badge', 'phishguard-card', 'phishguard-toast'].forEach(id => {
      document.getElementById(id)?.remove();
    });
  }
};

window.UIInjector = UIInjector;
