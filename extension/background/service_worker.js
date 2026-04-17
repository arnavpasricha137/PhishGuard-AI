/**
 * PhishGuard AI - Background Service Worker
 * Handles API communication, caching, and message routing
 */

const BACKEND_URL = 'http://localhost:8000';
const CACHE_TTL_MS = 30 * 60 * 1000; // 30 minutes

/**
 * Generate cache key from email metadata
 */
function generateCacheKey(sender, subject) {
  const key = `${sender}:${hashString(subject)}`;
  return key;
}

/**
 * Simple string hash function
 */
function hashString(str) {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    const char = str.charCodeAt(i);
    hash = ((hash << 5) - hash) + char;
    hash = hash & hash; // Convert to 32bit integer
  }
  return Math.abs(hash).toString(36);
}

/**
 * Check if cached result is still valid
 */
function isCacheValid(cachedItem) {
  if (!cachedItem || !cachedItem.timestamp) {
    return false;
  }
  const age = Date.now() - cachedItem.timestamp;
  return age < CACHE_TTL_MS;
}

/**
 * Call backend API for email analysis
 */
async function analyzeEmail(payload) {
  try {
    const response = await fetch(`${BACKEND_URL}/analyze`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify(payload),
    });

    if (!response.ok) {
      throw new Error(`API returned ${response.status}`);
    }

    const result = await response.json();
    return { success: true, data: result };
  } catch (error) {
    console.error('Backend API error:', error);
    return { success: false, error: error.message };
  }
}

/**
 * Offline heuristic analysis fallback
 */
function offlineAnalysis(payload) {
  const urls = payload.urls || [];
  const text = payload.email_text || '';
  
  let score = 0;
  const signals = [];
  
  // Check URLs
  for (const url of urls) {
    const urlLower = url.toLowerCase();
    
    // Risky TLDs
    if (/\.(xyz|top|tk|ml|ga|cf)$/i.test(url)) {
      score += 15;
      signals.push('High-risk TLD detected');
    }
    
    // IP address
    if (/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(url)) {
      score += 20;
      signals.push('IP address used instead of domain');
    }
    
    // Long URL
    if (url.length > 80) {
      score += 10;
      signals.push('Very long URL detected');
    }
    
    // Missing HTTPS
    if (url.startsWith('http://')) {
      score += 10;
      signals.push('URL not using HTTPS');
    }
  }
  
  // Check text for keywords
  const textLower = text.toLowerCase();
  const suspiciousKeywords = [
    'verify your account', 'urgent', 'suspended', 
    'click here', 'reset password'
  ];
  
  for (const keyword of suspiciousKeywords) {
    if (textLower.includes(keyword)) {
      score += 10;
      signals.push(`Suspicious keyword: ${keyword}`);
    }
  }
  
  score = Math.min(score, 100);
  
  let verdict = 'SAFE';
  if (score >= 70) verdict = 'PHISHING';
  else if (score >= 40) verdict = 'SUSPICIOUS';
  
  return {
    verdict,
    confidence: score / 100,
    final_score: score,
    agent_scores: {},
    url_verdicts: urls.map(url => ({
      url,
      score,
      verdict,
      signals: ['Offline analysis']
    })),
    highlighted_phrases: [],
    spear_phishing_detected: false,
    processing_time_ms: 0,
    offline: true
  };
}

/**
 * Handle messages from content scripts
 */
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'ANALYZE_EMAIL') {
    handleAnalyzeEmail(message.payload, sender.tab.id)
      .then(sendResponse)
      .catch(error => {
        console.error('Analysis error:', error);
        sendResponse({ error: error.message });
      });
    return true; // Keep channel open for async response
  }
  
  if (message.type === 'CHECK_URL') {
    handleCheckUrl(message.url)
      .then(sendResponse)
      .catch(error => {
        console.error('URL check error:', error);
        sendResponse({ error: error.message });
      });
    return true;
  }
  
  if (message.type === 'GET_BACKEND_STATUS') {
    checkBackendStatus()
      .then(sendResponse)
      .catch(error => {
        sendResponse({ online: false });
      });
    return true;
  }
});

/**
 * Handle email analysis request
 */
async function handleAnalyzeEmail(payload, tabId) {
  // Generate cache key
  const cacheKey = generateCacheKey(
    payload.sender || '',
    payload.subject || ''
  );
  
  // Check cache
  try {
    const cached = await chrome.storage.session.get(cacheKey);
    if (cached[cacheKey] && isCacheValid(cached[cacheKey])) {
      console.log('Cache hit:', cacheKey);
      return {
        type: 'ANALYSIS_RESULT',
        result: cached[cacheKey].data,
        cached: true
      };
    }
  } catch (error) {
    console.error('Cache read error:', error);
  }
  
  // Call backend API
  const apiResult = await analyzeEmail(payload);
  
  let result;
  if (apiResult.success) {
    result = apiResult.data;
  } else {
    // Fallback to offline analysis
    console.log('Using offline analysis fallback');
    result = offlineAnalysis(payload);
  }
  
  // Cache the result
  try {
    await chrome.storage.session.set({
      [cacheKey]: {
        data: result,
        timestamp: Date.now()
      }
    });
  } catch (error) {
    console.error('Cache write error:', error);
  }
  
  // Send result to content script
  chrome.tabs.sendMessage(tabId, {
    type: 'ANALYSIS_RESULT',
    result,
    cached: false
  });
  
  return {
    type: 'ANALYSIS_RESULT',
    result,
    cached: false
  };
}

/**
 * Handle URL check request
 */
async function handleCheckUrl(url) {
  // Generate URL hash
  const urlHash = hashString(url);
  
  // Try to get cached verdict
  try {
    const response = await fetch(`${BACKEND_URL}/verdict/${urlHash}`);
    if (response.ok) {
      const verdict = await response.json();
      return { success: true, verdict };
    }
  } catch (error) {
    console.log('Cached verdict not found, analyzing...');
  }
  
  // Analyze the URL
  const payload = {
    urls: [url],
    email_text: '',
    headers: {}
  };
  
  const result = await analyzeEmail(payload);
  
  if (result.success && result.data.url_verdicts.length > 0) {
    return { success: true, verdict: result.data.url_verdicts[0] };
  }
  
  return { success: false, error: 'Analysis failed' };
}

/**
 * Check if backend is online
 */
async function checkBackendStatus() {
  try {
    console.log('Checking backend at:', BACKEND_URL);
    const response = await fetch(`${BACKEND_URL}/health`, {
      method: 'GET',
      signal: AbortSignal.timeout(5000)
    });
    
    console.log('Backend response status:', response.status);
    
    if (response.ok) {
      const data = await response.json();
      console.log('Backend is online:', data);
      return { online: true, status: data };
    }
    
    console.log('Backend returned non-OK status');
    return { online: false };
  } catch (error) {
    console.error('Backend check failed:', error);
    return { online: false, error: error.message };
  }
}

// Log service worker startup
console.log('PhishGuard AI service worker started');
