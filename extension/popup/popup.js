/**
 * PhishGuard AI - Popup Script
 */

document.addEventListener('DOMContentLoaded', async () => {
  // Check backend status
  checkBackendStatus();
  
  // Check current tab
  checkCurrentTab();
  
  // Set up toggle
  setupToggle();
  
  // Settings link
  document.getElementById('settings-link').addEventListener('click', (e) => {
    e.preventDefault();
    alert('Settings panel coming soon!');
  });
});

/**
 * Check backend connectivity
 */
async function checkBackendStatus() {
  const statusElement = document.getElementById('backend-status');
  
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'GET_BACKEND_STATUS'
    });
    
    if (response && response.online) {
      statusElement.innerHTML = `
        <span class="status-dot status-dot-online"></span>
        Connected
      `;
    } else {
      statusElement.innerHTML = `
        <span class="status-dot status-dot-offline"></span>
        Offline
      `;
    }
  } catch (error) {
    statusElement.innerHTML = `
      <span class="status-dot status-dot-offline"></span>
      Offline
    `;
  }
}

/**
 * Check current tab status
 */
async function checkCurrentTab() {
  const tabStatusElement = document.getElementById('tab-status');
  
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    if (!tab) {
      tabStatusElement.innerText = 'No active tab';
      return;
    }
    
    const url = tab.url || '';
    
    if (url.includes('mail.google.com')) {
      tabStatusElement.innerText = 'Gmail - Active';
    } else if (url.includes('outlook')) {
      tabStatusElement.innerText = 'Outlook - Active';
    } else {
      tabStatusElement.innerText = 'Not on supported site';
    }
  } catch (error) {
    tabStatusElement.innerText = 'Unknown';
  }
}

/**
 * Set up enable/disable toggle
 */
function setupToggle() {
  const toggle = document.getElementById('enable-toggle');
  
  // Load saved state
  chrome.storage.local.get(['enabled'], (result) => {
    toggle.checked = result.enabled !== false; // Default to true
  });
  
  // Save on change
  toggle.addEventListener('change', () => {
    chrome.storage.local.set({ enabled: toggle.checked });
    
    if (toggle.checked) {
      console.log('PhishGuard enabled');
    } else {
      console.log('PhishGuard disabled');
    }
  });
}
