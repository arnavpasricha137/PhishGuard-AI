/**
 * UI Injector - Shared Module
 * Injects verdict badge and explainability card into email view
 */

const UIInjector = {
  /**
   * Inject verdict badge near sender name
   */
  injectBadge(verdict, score, confidence) {
    // Remove existing badge if any
    const existing = document.getElementById('phishguard-badge');
    if (existing) {
      existing.remove();
    }
    
    // Create badge
    const badge = document.createElement('span');
    badge.id = 'phishguard-badge';
    badge.className = `phishguard-badge phishguard-badge-${verdict.toLowerCase()}`;
    
    let text = 'PhishGuard: ';
    let emoji = '';
    
    if (verdict === 'SAFE') {
      text += 'Safe';
      emoji = '🟢';
    } else if (verdict === 'SUSPICIOUS') {
      text += `⚠ Suspicious (${score}%)`;
      emoji = '🟡';
    } else if (verdict === 'PHISHING') {
      text += `🚨 Phishing (${score}%)`;
      emoji = '🔴';
    }
    
    badge.innerText = text;
    badge.style.cursor = 'pointer';
    badge.title = 'Click for details';
    
    // Find insertion point
    let insertionPoint = null;
    
    // Gmail
    if (window.location.hostname.includes('mail.google.com')) {
      insertionPoint = document.querySelector('.gD');
      if (!insertionPoint) {
        insertionPoint = document.querySelector('h2.hP');
      }
    }
    // Outlook
    else if (window.location.hostname.includes('outlook')) {
      insertionPoint = document.querySelector('[aria-label*="From"]');
    }
    
    if (insertionPoint) {
      insertionPoint.parentNode.insertBefore(badge, insertionPoint.nextSibling);
      
      // Add click handler
      badge.addEventListener('click', () => {
        this.toggleCard();
      });
    }
    
    return badge;
  },
  
  /**
   * Show loading badge
   */
  showLoadingBadge() {
    const existing = document.getElementById('phishguard-badge');
    if (existing) {
      existing.remove();
    }
    
    const badge = document.createElement('span');
    badge.id = 'phishguard-badge';
    badge.className = 'phishguard-badge phishguard-badge-loading';
    badge.innerText = 'PhishGuard: Analyzing...';
    
    let insertionPoint = null;
    
    if (window.location.hostname.includes('mail.google.com')) {
      insertionPoint = document.querySelector('.gD') || document.querySelector('h2.hP');
    } else if (window.location.hostname.includes('outlook')) {
      insertionPoint = document.querySelector('[aria-label*="From"]');
    }
    
    if (insertionPoint) {
      insertionPoint.parentNode.insertBefore(badge, insertionPoint.nextSibling);
    }
  },
  
  /**
   * Inject explainability card
   */
  injectCard(result) {
    // Remove existing card
    const existing = document.getElementById('phishguard-card');
    if (existing) {
      existing.remove();
    }
    
    const card = document.createElement('div');
    card.id = 'phishguard-card';
    card.className = 'phishguard-card';
    card.style.display = 'none'; // Hidden by default
    
    // Build card HTML
    let html = `
      <div class="phishguard-card-header">
        <h3 class="phishguard-verdict-${result.verdict.toLowerCase()}">
          ${result.verdict} (${result.final_score}%)
        </h3>
        <p>Confidence: ${Math.round(result.confidence * 100)}%</p>
      </div>
    `;
    
    // Agent scores
    html += '<div class="phishguard-section"><h4>Agent Analysis</h4>';
    const agents = result.agent_scores || {};
    for (const [agentName, agentData] of Object.entries(agents)) {
      const displayName = agentName.replace('_agent', '').replace('_', ' ');
      html += `
        <div class="phishguard-agent-row">
          <div class="phishguard-agent-name">${displayName}</div>
          <div class="phishguard-score-bar">
            <div class="phishguard-score-fill" style="width: ${agentData.score}%"></div>
          </div>
          <div class="phishguard-agent-score">${agentData.score}</div>
        </div>
      `;
      
      if (agentData.signals && agentData.signals.length > 0) {
        html += '<div class="phishguard-signals">';
        agentData.signals.slice(0, 2).forEach(signal => {
          html += `<span class="phishguard-signal-chip">${signal}</span>`;
        });
        html += '</div>';
      }
    }
    html += '</div>';
    
    // Highlighted phrases
    if (result.highlighted_phrases && result.highlighted_phrases.length > 0) {
      html += '<div class="phishguard-section"><h4>Suspicious Phrases</h4>';
      result.highlighted_phrases.forEach(phrase => {
        const severityClass = `severity-${phrase.severity.toLowerCase()}`;
        html += `
          <div class="phishguard-phrase ${severityClass}">
            <strong>"${phrase.text}"</strong>
            <p>${phrase.reason}</p>
          </div>
        `;
      });
      html += '</div>';
    }
    
    // URL verdicts
    if (result.url_verdicts && result.url_verdicts.length > 0) {
      html += '<div class="phishguard-section"><h4>URL Analysis</h4>';
      result.url_verdicts.forEach(urlVerdict => {
        const verdictClass = `verdict-${urlVerdict.verdict.toLowerCase()}`;
        const truncatedUrl = urlVerdict.url.length > 50 
          ? urlVerdict.url.substring(0, 50) + '...'
          : urlVerdict.url;
        html += `
          <div class="phishguard-url ${verdictClass}">
            <span class="phishguard-url-verdict">${urlVerdict.verdict}</span>
            <span class="phishguard-url-text" title="${urlVerdict.url}">${truncatedUrl}</span>
          </div>
        `;
      });
      html += '</div>';
    }
    
    // Spear phishing warning
    if (result.spear_phishing_detected) {
      html += `
        <div class="phishguard-warning">
          ⚠ <strong>Personalized Attack Detected</strong><br>
          This email was crafted targeting you specifically
        </div>
      `;
    }
    
    // Footer
    html += `
      <div class="phishguard-footer">
        <span>Powered by PhishGuard AI</span>
        <a href="#" class="phishguard-report-link">Report False Positive</a>
      </div>
    `;
    
    card.innerHTML = html;
    
    // Insert card after badge
    const badge = document.getElementById('phishguard-badge');
    if (badge) {
      badge.parentNode.insertBefore(card, badge.nextSibling);
    }
    
    // Store result for later use
    card.dataset.result = JSON.stringify(result);
    
    return card;
  },
  
  /**
   * Toggle card visibility
   */
  toggleCard() {
    const card = document.getElementById('phishguard-card');
    if (card) {
      card.style.display = card.style.display === 'none' ? 'block' : 'none';
    }
  },
  
  /**
   * Remove all PhishGuard UI elements
   */
  cleanup() {
    const badge = document.getElementById('phishguard-badge');
    const card = document.getElementById('phishguard-card');
    
    if (badge) badge.remove();
    if (card) card.remove();
  }
};

// Make available globally
window.UIInjector = UIInjector;
