# PhishGuard AI - Testing Checklist

Complete testing checklist for backend and Chrome extension.

## Backend Testing

### ✅ Environment Setup

- [ ] Python 3.11+ installed
- [ ] Redis running on port 6379
- [ ] All dependencies installed (`pip install -r requirements.txt`)
- [ ] `.env` file created with valid configuration
- [ ] No port conflicts on 8000

### ✅ Service Startup

```bash
cd backend
python main.py
```

**Expected Output:**
```
============================================================
🛡️  PhishGuard AI Backend Starting...
============================================================
✓ Configuration loaded successfully
  - Redis: redis://localhost:6379
  - Backend Port: 8000
  - Log Level: INFO
  - Agent Timeout: 5s
  - Cache TTL: 86400s
✓ Redis connected
✓ ML models will load on first request
============================================================
🚀 Server ready on http://localhost:8000
============================================================
```

- [ ] No errors in startup
- [ ] Redis connection successful
- [ ] Server listening on port 8000

### ✅ Health Check Endpoint

```bash
curl http://localhost:8000/health
```

**Expected Response:**
```json
{
  "status": "ok",
  "redis": "connected",
  "agents": "ready"
}
```

- [ ] Status is "ok"
- [ ] Redis is "connected"
- [ ] Agents are "ready"

### ✅ Root Endpoint

```bash
curl http://localhost:8000/
```

**Expected Response:**
```json
{
  "name": "PhishGuard AI Backend",
  "version": "1.0.0",
  "status": "running",
  "docs": "/docs",
  "endpoints": {
    "analyze": "POST /analyze",
    "health": "GET /health",
    "cached_verdict": "GET /verdict/{url_hash}"
  }
}
```

- [ ] Returns API information
- [ ] All endpoints listed

### ✅ API Documentation

Open in browser: `http://localhost:8000/docs`

- [ ] Swagger UI loads
- [ ] All 3 endpoints visible
- [ ] Request/response schemas shown

### ✅ Safe Email Analysis

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "Hi John, here is the report you requested. Best regards, Sarah",
    "subject": "Report",
    "sender": "sarah@company.com",
    "urls": ["https://company.com/report.pdf"],
    "recipient_name": "John"
  }'
```

**Expected:**
- [ ] `"verdict": "SAFE"`
- [ ] `"final_score"` < 40
- [ ] `"confidence"` < 0.4
- [ ] All 4 agent scores present
- [ ] `"processing_time_ms"` < 3000
- [ ] No errors

### ✅ Suspicious Email Analysis

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "URGENT: Your account requires immediate verification. Click here now!",
    "subject": "Account Verification Required",
    "sender": "security@example.com",
    "urls": ["http://example.com/verify"],
    "recipient_name": "John"
  }'
```

**Expected:**
- [ ] `"verdict": "SUSPICIOUS"` or `"PHISHING"`
- [ ] `"final_score"` >= 40
- [ ] `"highlighted_phrases"` contains urgency keywords
- [ ] URL analysis shows missing HTTPS
- [ ] Content agent detects urgency patterns

### ✅ Phishing Email Analysis

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "Dear customer, your PayPal account has been suspended. Please verify your account immediately by entering your password at the link below.",
    "subject": "PayPal Account Suspended",
    "sender": "security@paypal-verify.com",
    "urls": ["http://paypal-verify.com/login"],
    "recipient_name": "John"
  }'
```

**Expected:**
- [ ] `"verdict": "PHISHING"`
- [ ] `"final_score"` >= 70
- [ ] Brand spoofing detected in URL signals
- [ ] Credential harvesting phrases highlighted
- [ ] High severity phrases present
- [ ] URL verdict is "PHISHING"

### ✅ Spear Phishing Detection

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "Hi John, I noticed unusual activity on your account. Please verify your bank details immediately.",
    "subject": "Security Alert",
    "sender": "security@fake-bank.com",
    "urls": ["http://fake-bank.com/verify"],
    "recipient_name": "John"
  }'
```

**Expected:**
- [ ] `"spear_phishing_detected": true`
- [ ] Final score boosted (>= 75)
- [ ] Personalization detected in signals

### ✅ Caching Test

Run the same request twice:

```bash
# First request
time curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"email_text": "Test", "urls": ["http://test.com"]}'

# Second request (should be faster)
time curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"email_text": "Test", "urls": ["http://test.com"]}'
```

**Expected:**
- [ ] First request: 800-2000ms
- [ ] Second request: <100ms (URL cached)
- [ ] Same verdict returned

### ✅ Agent Timeout Test

Mock a slow agent (requires code modification for testing):

**Expected:**
- [ ] Agent times out after 5 seconds
- [ ] Fallback score of 0 used
- [ ] Other agents continue normally
- [ ] Final verdict still returned

### ✅ Redis Cache Lookup

```bash
# Get URL hash (MD5 of URL)
echo -n "http://test.com" | md5

# Look up cached verdict
curl http://localhost:8000/verdict/<hash>
```

**Expected:**
- [ ] Returns cached verdict if exists
- [ ] 404 if not in cache

---

## Chrome Extension Testing

### ✅ Installation

- [ ] Extension loads without errors in `chrome://extensions/`
- [ ] No manifest errors
- [ ] Icons display correctly (or placeholders present)
- [ ] Extension appears in toolbar

### ✅ Popup UI

Click extension icon:

- [ ] Popup opens
- [ ] Backend status shows "Connected" (green dot)
- [ ] Current tab status shows correctly
- [ ] Toggle switch works
- [ ] UI renders properly

### ✅ Gmail Integration

**Setup:**
1. Open Gmail in Chrome
2. Open any email

**Tests:**

- [ ] Badge appears within 2 seconds
- [ ] Badge shows correct color (Safe/Suspicious/Phishing)
- [ ] Badge positioned near sender name
- [ ] Loading spinner shows during analysis
- [ ] No console errors

**Click Badge:**
- [ ] Card toggles open/closed
- [ ] Card shows all sections:
  - [ ] Verdict header with score
  - [ ] 4 agent scores with bars
  - [ ] Top signals for each agent
  - [ ] Highlighted phrases (if any)
  - [ ] URL verdicts (if any)
  - [ ] Footer with "Powered by PhishGuard AI"

**Phrase Highlighting:**
- [ ] Suspicious phrases highlighted in email body
- [ ] Colors match severity (red=HIGH, yellow=MEDIUM, green=LOW)
- [ ] Hover shows reason tooltip
- [ ] Highlights don't break email layout

**URL Labeling:**
- [ ] Safe URLs show `[✓]` label
- [ ] Suspicious URLs show `[⚠ Suspicious Link]` label
- [ ] Phishing URLs show `[🚨 Dangerous Link]` label
- [ ] Labels positioned after links

**URL Click Protection:**

Test phishing link:
- [ ] Click is blocked (preventDefault)
- [ ] Interstitial overlay appears
- [ ] Shows URL and risk score
- [ ] "Go back" button closes overlay
- [ ] "Open anyway" button opens URL in new tab

Test suspicious link:
- [ ] Click allowed
- [ ] Toast notification appears
- [ ] Toast shows warning message
- [ ] Toast auto-dismisses after 5 seconds

Test safe link:
- [ ] Click works normally
- [ ] No warnings shown

### ✅ Outlook Web Integration

**Setup:**
1. Open Outlook Web (outlook.live.com or outlook.office.com)
2. Open any email

**Tests:**

- [ ] Badge appears within 2 seconds
- [ ] Badge shows correct verdict
- [ ] Badge positioned correctly
- [ ] Click badge opens card
- [ ] All features work same as Gmail
- [ ] No console errors

### ✅ Multiple Emails

**Gmail:**
1. Open email #1 → verify badge appears
2. Open email #2 → verify badge updates
3. Go back to email #1 → verify badge still there
4. Open email #3 → verify badge appears

- [ ] Badge updates for each email
- [ ] No duplicate badges
- [ ] Previous badges cleaned up
- [ ] No memory leaks

### ✅ Caching

1. Open an email → wait for analysis
2. Close email
3. Re-open same email

**Expected:**
- [ ] Second analysis is instant (<100ms)
- [ ] Same verdict shown
- [ ] Badge appears immediately

### ✅ Offline Mode

1. Stop backend server
2. Open an email in Gmail

**Expected:**
- [ ] Extension still works
- [ ] Offline heuristics used
- [ ] Verdict shows "SUSPICIOUS" for risky patterns
- [ ] No crashes or errors
- [ ] Toast/warning about offline mode (optional)

### ✅ Service Worker

Open service worker console:
1. Go to `chrome://extensions/`
2. Find PhishGuard AI
3. Click "service worker" link

**Tests:**
- [ ] No errors in console
- [ ] Messages logged for API calls
- [ ] Cache operations logged
- [ ] No infinite loops

### ✅ Content Script Console

Open Gmail → F12 → Console tab:

- [ ] PhishGuard initialization message
- [ ] Analysis request logged
- [ ] Analysis result logged
- [ ] No JavaScript errors
- [ ] No CORS errors

### ✅ Performance

Open Chrome DevTools → Performance tab:

- [ ] Extension doesn't block page load
- [ ] Analysis completes in <2 seconds
- [ ] No excessive DOM mutations
- [ ] Memory usage stable (<20MB)

### ✅ Edge Cases

**Empty Email:**
- [ ] Badge shows "Safe" or neutral
- [ ] No errors

**Email with No URLs:**
- [ ] Analysis completes
- [ ] URL agent returns 0 score
- [ ] No errors

**Email with 10+ URLs:**
- [ ] All URLs analyzed
- [ ] All URLs labeled
- [ ] Performance acceptable

**Very Long Email:**
- [ ] Analysis completes
- [ ] Text truncated appropriately
- [ ] No performance issues

**HTML-Only Email:**
- [ ] Text extracted from HTML
- [ ] Analysis works normally

**Email with Images Only:**
- [ ] No text to analyze
- [ ] Graceful handling
- [ ] No errors

---

## Integration Testing

### ✅ End-to-End Flow

**Test Case: Phishing Email Detection**

1. Start backend
2. Load extension
3. Open Gmail
4. Compose test phishing email to yourself:
   ```
   Subject: Urgent Account Verification
   Body: Dear customer, your account has been suspended.
   Click here to verify: http://fake-paypal.com/login
   Enter your password immediately.
   ```
5. Send and open the email

**Expected Results:**
- [ ] Badge shows "🔴 PHISHING (85%)" or similar
- [ ] Card shows all 4 agent scores
- [ ] "verify your account" highlighted (MEDIUM)
- [ ] "Enter your password" highlighted (HIGH)
- [ ] URL labeled as `[🚨 Dangerous Link]`
- [ ] Clicking URL shows interstitial blocker
- [ ] Spear phishing detected if name used

### ✅ Cross-Browser Testing

Test in different Chrome-based browsers:

- [ ] Google Chrome (latest)
- [ ] Microsoft Edge (Chromium)
- [ ] Brave Browser
- [ ] Opera

### ✅ Stress Testing

**Backend:**
```bash
# Send 100 concurrent requests
for i in {1..100}; do
  curl -X POST http://localhost:8000/analyze \
    -H "Content-Type: application/json" \
    -d '{"email_text": "test", "urls": []}' &
done
```

**Expected:**
- [ ] All requests complete
- [ ] No crashes
- [ ] Response times acceptable
- [ ] Redis handles load

**Extension:**
1. Open 10 Gmail tabs
2. Open emails in each tab

**Expected:**
- [ ] All tabs work independently
- [ ] No interference between tabs
- [ ] Memory usage reasonable

---

## Security Testing

### ✅ CORS

```bash
# Try from unauthorized origin
curl -X POST http://localhost:8000/analyze \
  -H "Origin: https://evil.com" \
  -H "Content-Type: application/json" \
  -d '{"email_text": "test"}'
```

**Expected:**
- [ ] Request blocked or CORS headers restrict access

### ✅ Input Validation

```bash
# Send invalid JSON
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d 'invalid json'
```

**Expected:**
- [ ] 422 Unprocessable Entity
- [ ] Error message returned

```bash
# Send empty payload
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{}'
```

**Expected:**
- [ ] Request accepted (all fields optional)
- [ ] Returns safe verdict

### ✅ XSS Protection

Test email with script tags:

```json
{
  "email_text": "<script>alert('XSS')</script>",
  "email_html": "<script>alert('XSS')</script>"
}
```

**Expected:**
- [ ] Scripts not executed
- [ ] HTML sanitized
- [ ] No XSS vulnerability

---

## Regression Testing

After any code changes, re-run:

- [ ] Backend health check
- [ ] Safe email test
- [ ] Phishing email test
- [ ] Extension loads without errors
- [ ] Gmail badge appears
- [ ] Outlook badge appears

---

## Sign-Off Checklist

### Backend
- [ ] All API endpoints working
- [ ] All 4 agents functioning
- [ ] Redis caching working
- [ ] ML model loading correctly
- [ ] Error handling robust
- [ ] Logging appropriate
- [ ] Documentation complete

### Extension
- [ ] Loads without errors
- [ ] Gmail integration working
- [ ] Outlook integration working
- [ ] UI renders correctly
- [ ] Caching working
- [ ] Offline mode working
- [ ] No console errors
- [ ] Documentation complete

### System
- [ ] End-to-end flow working
- [ ] Performance acceptable
- [ ] Security validated
- [ ] Ready for demo/deployment

---

## Known Issues to Document

List any known issues or limitations:

1. Icons are placeholders (need production icons)
2. PhishTank API key optional (feature degraded without it)
3. First ML model load is slow (~30 seconds)
4. Gmail compose window not supported
5. Attachment scanning not implemented

---

## Test Results Template

```
Date: ___________
Tester: ___________
Environment: ___________

Backend Tests: ___/30 passed
Extension Tests: ___/40 passed
Integration Tests: ___/10 passed
Security Tests: ___/5 passed

Total: ___/85 passed

Critical Issues: ___________
Minor Issues: ___________
Notes: ___________
```
