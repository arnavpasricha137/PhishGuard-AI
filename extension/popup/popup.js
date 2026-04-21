/**
 * PhishGuard AI - Popup Script
 */

document.addEventListener('DOMContentLoaded', async () => {
  checkBackendStatus();
  checkCurrentTab();
  setupToggle();

  document.getElementById('settings-link').addEventListener('click', (e) => {
    e.preventDefault();
  });
});

/** Backend connectivity check */
async function checkBackendStatus() {
  const dot   = document.getElementById('backend-dot');
  const label = document.getElementById('backend-label');

  dot.className = 'dot dot-checking';
  label.textContent = 'Connecting…';

  try {
    const response = await chrome.runtime.sendMessage({ type: 'GET_BACKEND_STATUS' });

    if (response && response.online) {
      dot.className   = 'dot dot-online';
      label.textContent = 'Connected';
    } else {
      dot.className   = 'dot dot-offline';
      label.textContent = 'Offline';
    }
  } catch {
    dot.className   = 'dot dot-offline';
    label.textContent = 'Offline';
  }
}

/** Current tab detection */
async function checkCurrentTab() {
  const el = document.getElementById('tab-status');

  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab) { el.textContent = 'No active tab'; return; }

    const url = tab.url || '';
    if (url.includes('mail.google.com'))   el.textContent = 'Gmail — active';
    else if (url.includes('outlook'))      el.textContent = 'Outlook — active';
    else                                   el.textContent = 'Not on a supported site';
  } catch {
    el.textContent = 'Unknown';
  }
}

/** Enable / disable toggle */
function setupToggle() {
  const toggle = document.getElementById('enable-toggle');

  chrome.storage.local.get(['enabled'], (r) => {
    toggle.checked = r.enabled !== false;
  });

  toggle.addEventListener('change', () => {
    chrome.storage.local.set({ enabled: toggle.checked });
  });
}

/** Load and render last analysis result */
function loadLastResult() {
  chrome.storage.local.get(['lastResult'], (r) => {
    if (r.lastResult) {
      renderResult(r.lastResult);
    }
  });
}

/** Render analysis result with score ring and agent bars */
function renderResult(result) {
  const panel  = document.getElementById('result-panel');
  const empty  = document.getElementById('empty-state');
  const score  = result.final_score || 0;
  const verdict = (result.verdict || 'UNKNOWN').toUpperCase();

  // Show panel, hide empty state
  panel.classList.remove('hidden');
  empty.classList.add('hidden');

  // Score ring: conic-gradient driven by CSS custom properties
  const ring  = document.getElementById('score-ring');
  const color = score >= 70 ? '#f85149' : score >= 40 ? '#d29922' : '#3fb950';
  ring.style.setProperty('--ring-pct',   score + '%');
  ring.style.setProperty('--ring-color', color);

  document.getElementById('score-number').textContent = score;
  document.getElementById('score-number').style.color = color;

  // Verdict badge
  const badge = document.getElementById('verdict-badge');
  badge.textContent = verdict;
  badge.className = 'verdict-badge verdict-' + verdict.toLowerCase();

  // Meta lines
  const conf = Math.round((result.confidence || 0) * 100);
  document.getElementById('confidence-text').textContent = `${conf}% confidence`;
  const ms = result.processing_time_ms;
  if (ms) {
    document.getElementById('latency-text').textContent = `Analyzed in ${Math.round(ms)}ms`;
  }

  // Agent breakdown
  const list   = document.getElementById('agent-list');
  list.innerHTML = '';
  const agents = result.agent_scores || {};
  const names  = { url_agent: 'URL', content_agent: 'Content',
                   header_agent: 'Header', reputation_agent: 'Reputation' };

  Object.entries(agents).forEach(([key, data]) => {
    const s     = data.score || 0;
    const fill  = s >= 70 ? '#f85149' : s >= 40 ? '#d29922' : '#3fb950';
    const label = names[key] || key.replace('_agent', '');

    const row = document.createElement('div');
    row.className = 'agent-row';
    row.innerHTML = `
      <span class="agent-name">${label}</span>
      <div class="agent-track">
        <div class="agent-fill" style="width:${s}%;background:${fill}"></div>
      </div>
      <span class="agent-val" style="color:${fill}">${s}</span>
    `;
    list.appendChild(row);
  });
}
