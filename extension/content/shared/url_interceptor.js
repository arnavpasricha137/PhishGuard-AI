/**
 * URL Interceptor - Shared Module
 * Labels URLs and intercepts clicks on dangerous links
 */

const URLInterceptor = {
  urlVerdicts: {},
  
  /**
   * Label all URLs based on verdicts
   */
  labelUrls(urlVerdicts) {
    if (!urlVerdicts || urlVerdicts.length === 0) {
      return;
    }
    
    // Store verdicts for click interception
    this.urlVerdicts = {};
    urlVerdicts.forEach(verdict => {
      this.urlVerdicts[verdict.url] = verdict;
    });
    
    // Get email body
    let bodyElement = null;
    
    if (window.location.hostname.includes('mail.google.com')) {
      bodyElement = document.querySelector('.a3s.aiL');
    } else if (window.location.hostname.includes('outlook')) {
      bodyElement = document.querySelector('[aria-label="Message body"]');
    }
    
    if (!bodyElement) {
      return;
    }
    
    // Find all links
    const links = bodyElement.querySelectorAll('a[href]');
    
    links.forEach(link => {
      const href = link.href;
      const verdict = this.urlVerdicts[href];
      
      if (!verdict) {
        return;
      }
      
      // Add label based on verdict
      if (verdict.verdict === 'PHISHING') {
        this.addDangerousLabel(link);
      } else if (verdict.verdict === 'SUSPICIOUS') {
        this.addSuspiciousLabel(link);
      } else if (verdict.verdict === 'SAFE') {
        this.addSafeLabel(link);
      }
      
      // Add click handler
      link.addEventListener('mousedown', (e) => {
        this.handleLinkClick(e, verdict);
      }, true);
    });
  },
  
  /**
   * Add dangerous link label
   */
  addDangerousLabel(link) {
    const label = document.createElement('span');
    label.className = 'phishguard-url-label phishguard-url-dangerous';
    label.innerText = ' [🚨 Dangerous Link]';
    label.style.color = '#cc0000';
    label.style.fontWeight = 'bold';
    label.style.fontSize = '11px';
    label.style.marginLeft = '4px';
    label.style.cursor = 'pointer';
    
    link.parentNode.insertBefore(label, link.nextSibling);
  },
  
  /**
   * Add suspicious link label
   */
  addSuspiciousLabel(link) {
    const label = document.createElement('span');
    label.className = 'phishguard-url-label phishguard-url-suspicious';
    label.innerText = ' [⚠ Suspicious Link]';
    label.style.color = '#cc8800';
    label.style.fontWeight = 'bold';
    label.style.fontSize = '11px';
    label.style.marginLeft = '4px';
    
    link.parentNode.insertBefore(label, link.nextSibling);
  },
  
  /**
   * Add safe link label
   */
  addSafeLabel(link) {
    const label = document.createElement('span');
    label.className = 'phishguard-url-label phishguard-url-safe';
    label.innerText = ' [✓]';
    label.style.color = '#228822';
    label.style.fontSize = '11px';
    label.style.marginLeft = '4px';
    
    link.parentNode.insertBefore(label, link.nextSibling);
  },
  
  /**
   * Handle link click
   */
  handleLinkClick(event, verdict) {
    if (verdict.verdict === 'PHISHING') {
      // Block phishing links
      event.preventDefault();
      event.stopPropagation();
      this.showInterstitial(verdict);
    } else if (verdict.verdict === 'SUSPICIOUS') {
      // Show warning toast for suspicious links
      this.showToast('⚠ You clicked a suspicious link — proceed with caution');
    }
  },
  
  /**
   * Show blocking interstitial for phishing links
   */
  showInterstitial(verdict) {
    // Remove existing interstitial
    const existing = document.getElementById('phishguard-interstitial');
    if (existing) {
      existing.remove();
    }
    
    // Create interstitial
    const interstitial = document.createElement('div');
    interstitial.id = 'phishguard-interstitial';
    interstitial.className = 'phishguard-interstitial';
    
    const truncatedUrl = verdict.url.length > 80
      ? verdict.url.substring(0, 80) + '...'
      : verdict.url;
    
    const topSignals = verdict.signals.slice(0, 3).join(', ');
    
    interstitial.innerHTML = `
      <div class="phishguard-interstitial-content">
        <h2>🚨 PhishGuard AI blocked this link</h2>
        <p><strong>URL:</strong> ${truncatedUrl}</p>
        <p><strong>Risk:</strong> ${verdict.score}% — ${topSignals}</p>
        <div class="phishguard-interstitial-buttons">
          <button id="phishguard-go-back" class="phishguard-btn-safe">Go back (safe)</button>
          <button id="phishguard-open-anyway" class="phishguard-btn-danger">Open anyway (risky)</button>
        </div>
      </div>
    `;
    
    document.body.appendChild(interstitial);
    
    // Add event listeners
    document.getElementById('phishguard-go-back').addEventListener('click', () => {
      interstitial.remove();
    });
    
    document.getElementById('phishguard-open-anyway').addEventListener('click', () => {
      interstitial.remove();
      window.open(verdict.url, '_blank');
    });
  },
  
  /**
   * Show toast notification
   */
  showToast(message) {
    // Remove existing toast
    const existing = document.getElementById('phishguard-toast');
    if (existing) {
      existing.remove();
    }
    
    // Create toast
    const toast = document.createElement('div');
    toast.id = 'phishguard-toast';
    toast.className = 'phishguard-toast';
    toast.innerText = message;
    
    document.body.appendChild(toast);
    
    // Auto-remove after 5 seconds
    setTimeout(() => {
      toast.classList.add('phishguard-toast-hide');
      setTimeout(() => toast.remove(), 300);
    }, 5000);
  },
  
  /**
   * Remove all URL labels
   */
  cleanup() {
    const labels = document.querySelectorAll('.phishguard-url-label');
    labels.forEach(label => label.remove());
    
    const interstitial = document.getElementById('phishguard-interstitial');
    if (interstitial) interstitial.remove();
    
    const toast = document.getElementById('phishguard-toast');
    if (toast) toast.remove();
  }
};

// Make available globally
window.URLInterceptor = URLInterceptor;
