# PhishGuard AI - Chrome Extension

Real-time phishing detection for Gmail and Outlook Web. Automatically scans emails when opened and provides instant verdicts with detailed explanations.

## Features

- **Auto-Detection**: Scans emails automatically when opened
- **Real-Time Analysis**: Connects to local backend for ML-powered detection
- **Visual Indicators**: Color-coded badges (Safe/Suspicious/Phishing)
- **Explainability Card**: Detailed breakdown of agent scores and signals
- **Phrase Highlighting**: Highlights suspicious text with severity levels
- **URL Protection**: Labels and blocks dangerous links
- **Offline Fallback**: Basic heuristics when backend unavailable
- **Session Caching**: 30-minute cache for faster repeat analysis

## Supported Platforms

- ✅ Gmail (mail.google.com)
- ✅ Outlook Web (outlook.live.com, outlook.office.com)

## Installation

### Prerequisites

1. **Backend Running**: The extension requires the PhishGuard AI backend running on `localhost:8000`
   ```bash
   cd ../backend
   docker-compose up
   ```

2. **Chrome Browser**: Version 88 or higher (Manifest V3 support)

### Load Extension (Development)

1. Open Chrome and navigate to `chrome://extensions/`

2. Enable **Developer mode** (toggle in top-right corner)

3. Click **Load unpacked**

4. Select the `extension` folder:
   ```
   /path/to/PhishGuard-AI/extension
   ```

5. The extension should now appear in your extensions list

6. Pin the extension to your toolbar for easy access

### Verify Installation

1. Click the PhishGuard AI icon in your toolbar
2. Check that "Backend: Connected" shows a green dot
3. Navigate to Gmail or Outlook Web
4. Open any email - you should see the PhishGuard badge appear

## Usage

### Gmail

1. Open Gmail in Chrome
2. Click on any email to open it
3. Wait 1-2 seconds for analysis
4. PhishGuard badge appears next to sender name:
   - 🟢 **Safe** - No threats detected
   - 🟡 **Suspicious** - Some indicators present
   - 🔴 **Phishing** - High-risk email
5. Click the badge to see detailed analysis

### Outlook Web

1. Open Outlook Web in Chrome
2. Click on any email to open it
3. Analysis works the same as Gmail
4. Badge appears near sender information

### Understanding Results

**Verdict Badge:**
- Shows overall risk level and score
- Click to toggle detailed card

**Explainability Card:**
- **Agent Scores**: Individual scores from 4 specialist agents
- **Suspicious Phrases**: Highlighted text with reasons
- **URL Analysis**: Per-URL verdicts with risk levels
- **Spear Phishing Warning**: If personalized attack detected

**Highlighted Phrases:**
- 🔴 **High Severity**: Credential harvesting attempts
- 🟡 **Medium Severity**: Urgency/social engineering
- 🟢 **Low Severity**: Mild suspicious indicators

**URL Labels:**
- `[🚨 Dangerous Link]` - Phishing URL (click blocked)
- `[⚠ Suspicious Link]` - Risky URL (warning shown)
- `[✓]` - Safe URL

### Clicking Links

**Phishing Links:**
- Click is blocked automatically
- Interstitial warning shown
- Options: "Go back (safe)" or "Open anyway (risky)"

**Suspicious Links:**
- Click allowed but warning toast shown
- Proceed with caution

**Safe Links:**
- Click works normally
- Small checkmark indicator

## Extension Structure

```
extension/
├── manifest.json              # Extension configuration
├── background/
│   └── service_worker.js      # API calls, caching, message routing
├── content/
│   ├── gmail.js               # Gmail-specific logic
│   ├── outlook.js             # Outlook-specific logic
│   └── shared/
│       ├── email_parser.js    # DOM parsing
│       ├── ui_injector.js     # Badge and card injection
│       ├── highlighter.js     # Phrase highlighting
│       └── url_interceptor.js # Link protection
├── popup/
│   ├── popup.html             # Extension popup UI
│   ├── popup.css
│   └── popup.js
├── styles/
│   └── injection.css          # Injected UI styles
└── icons/
    ├── icon16.png
    ├── icon48.png
    └── icon128.png
```

## How It Works

### 1. Email Detection

**Gmail:**
- MutationObserver watches for `div[data-message-id]` elements
- Debounced to avoid duplicate triggers (500ms)
- Triggers on new email open

**Outlook:**
- MutationObserver watches for message body changes
- Uses subject line as unique identifier
- Debounced to avoid duplicate triggers

### 2. Email Parsing

Extracts from DOM:
- Sender email and display name
- Subject line
- Email body (text and HTML)
- All URLs in email
- Reply-To address (if available)
- Recipient name (logged-in user)

### 3. Analysis Request

1. Content script sends message to service worker
2. Service worker checks session cache (30min TTL)
3. If cache miss, calls backend API: `POST /analyze`
4. Backend runs 4 agents in parallel
5. Result returned to content script

### 4. UI Injection

1. **Badge**: Injected near sender name with verdict
2. **Card**: Hidden by default, toggles on badge click
3. **Highlights**: Suspicious phrases marked in email body
4. **URL Labels**: Added after each link in email

### 5. Link Protection

1. All links get mousedown event listener
2. Phishing links: `preventDefault()` + show interstitial
3. Suspicious links: Show toast warning
4. Safe links: Normal behavior

## Caching Strategy

**Session Cache (Chrome Storage):**
- Key: `{sender}:{subject_hash}`
- TTL: 30 minutes
- Scope: Current browser session
- Cleared on browser close

**Backend Cache (Redis):**
- Key: `verdict:{url_md5}`
- TTL: 24 hours
- Scope: All users
- Persistent across sessions

## Offline Mode

When backend is unreachable, extension uses offline heuristics:

**URL Checks:**
- High-risk TLDs (.xyz, .top, .tk, .ml, .ga, .cf)
- IP addresses instead of domains
- Very long URLs (>80 chars)
- Missing HTTPS

**Text Checks:**
- Suspicious keywords (verify, urgent, suspended, etc.)

**Verdict:**
- Returns `SUSPICIOUS` with 50% confidence
- Marked as `offline: true`

## Troubleshooting

### Badge Not Appearing

1. Check backend is running: `http://localhost:8000/health`
2. Open browser console (F12) and look for errors
3. Reload the email
4. Try reloading the extension

### Backend Connection Failed

1. Verify backend is running on port 8000
2. Check CORS is configured correctly in backend
3. Look at service worker console:
   - Go to `chrome://extensions/`
   - Click "service worker" link under PhishGuard AI
   - Check for fetch errors

### Highlights Not Working

1. Email body must have readable text
2. Phrases must match exactly (case-insensitive)
3. Check browser console for errors
4. Some emails use complex HTML that may interfere

### URLs Not Labeled

1. URLs must be in `<a href="">` tags
2. Must start with `http://` or `https://`
3. Check if URLs were included in analysis payload

## Development

### Debugging

**Content Scripts:**
```javascript
// Add to gmail.js or outlook.js
console.log('PhishGuard Debug:', data);
```
View in page console (F12)

**Service Worker:**
```javascript
// Add to service_worker.js
console.log('Service Worker Debug:', data);
```
View in service worker console (chrome://extensions/ → service worker link)

### Testing

1. **Safe Email**: Regular email from known sender
2. **Suspicious Email**: Email with urgency keywords
3. **Phishing Email**: Email with credential requests + fake URLs

### Modifying Styles

Edit `styles/injection.css` and reload extension.

### Adding Features

1. Modify appropriate content script or shared module
2. Reload extension in `chrome://extensions/`
3. Reload Gmail/Outlook page
4. Test changes

## Security & Privacy

- **No Data Collection**: Extension does not collect or store user data
- **Local Processing**: All analysis done on user's machine (localhost backend)
- **No External Calls**: Extension only communicates with localhost:8000
- **Session-Only Cache**: Cache cleared when browser closes
- **No Tracking**: No analytics or telemetry

## Performance

- **Analysis Time**: 800-1500ms (first time), <50ms (cached)
- **Memory Usage**: ~10-15MB per tab
- **CPU Impact**: Minimal (only on email open)
- **Network**: One API call per email (unless cached)

## Known Limitations

1. **Gmail Compose**: Does not analyze outgoing emails
2. **Attachments**: Does not scan attachment contents
3. **Images**: Does not analyze embedded images
4. **Forwarded Emails**: May not parse correctly if heavily nested
5. **Custom Themes**: Some Gmail themes may affect badge placement

## Future Enhancements

- [ ] Support for more email clients (Yahoo Mail, ProtonMail)
- [ ] Attachment scanning
- [ ] Image-based phishing detection
- [ ] Report false positives to backend
- [ ] User settings panel
- [ ] Keyboard shortcuts
- [ ] Export analysis reports

## Contributing

See main project CONTRIBUTING.md

## License

See main project LICENSE file.
