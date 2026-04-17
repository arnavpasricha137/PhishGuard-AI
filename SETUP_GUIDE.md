# PhishGuard AI - Complete Setup Guide

This guide will walk you through setting up the complete PhishGuard AI system: backend + Chrome extension.

## System Requirements

- **OS**: macOS, Linux, or Windows
- **Python**: 3.11 or higher
- **Node.js**: Not required (extension is vanilla JS)
- **Docker**: Optional but recommended
- **Chrome**: Version 88+ for extension
- **RAM**: 4GB minimum, 8GB recommended
- **Disk**: 2GB free space (for ML models)

---

## Part 1: Backend Setup

### Option A: Docker (Recommended)

**Step 1: Navigate to backend directory**
```bash
cd backend
```

**Step 2: Create .env file**
```bash
cp .env.example .env
```

**Step 3: Edit .env (optional)**
```bash
# Add your PhishTank API key if you have one
nano .env
```

**Step 4: Start services**
```bash
docker-compose up
```

**Step 5: Verify backend is running**
Open browser: `http://localhost:8000/health`

Expected response:
```json
{
  "status": "ok",
  "redis": "connected",
  "agents": "ready"
}
```

### Option B: Local Development

**Step 1: Install Redis**

*macOS:*
```bash
brew install redis
brew services start redis
```

*Ubuntu/Debian:*
```bash
sudo apt-get install redis-server
sudo systemctl start redis
```

*Windows:*
Download from: https://github.com/microsoftarchive/redis/releases

**Step 2: Create Python virtual environment**
```bash
cd backend
python3 -m venv venv
```

**Step 3: Activate virtual environment**

*macOS/Linux:*
```bash
source venv/bin/activate
```

*Windows:*
```bash
venv\Scripts\activate
```

**Step 4: Install dependencies**
```bash
pip install -r requirements.txt
```

This will take 5-10 minutes. The ML models (~260MB) will download on first use.

**Step 5: Create .env file**
```bash
cp .env.example .env
```

**Step 6: Run the backend**
```bash
python main.py
```

**Step 7: Verify backend**
Open browser: `http://localhost:8000/health`

---

## Part 2: Chrome Extension Setup

**Step 1: Open Chrome Extensions**
Navigate to: `chrome://extensions/`

**Step 2: Enable Developer Mode**
Toggle the switch in the top-right corner

**Step 3: Load Extension**
1. Click "Load unpacked"
2. Navigate to the `extension` folder in your PhishGuard-AI directory
3. Select the folder and click "Open"

**Step 4: Verify Extension Loaded**
You should see "PhishGuard AI v1.0.0" in your extensions list

**Step 5: Pin Extension (Optional)**
Click the puzzle icon in Chrome toolbar and pin PhishGuard AI

**Step 6: Check Extension Status**
1. Click the PhishGuard AI icon
2. Verify "Backend: Connected" shows green dot
3. If offline, check backend is running on port 8000

---

## Part 3: Create Extension Icons (Temporary)

The extension needs icons to work properly. For development, create simple placeholders:

**Step 1: Create icons folder**
```bash
cd extension/icons
```

**Step 2: Create placeholder icons**

You can use any of these methods:

**Method A: Online Tool**
1. Go to https://www.favicon-generator.org/
2. Upload any image or use text "PG"
3. Download and rename to icon16.png, icon48.png, icon128.png

**Method B: ImageMagick (if installed)**
```bash
# Create simple colored squares
convert -size 16x16 xc:#1976d2 icon16.png
convert -size 48x48 xc:#1976d2 icon48.png
convert -size 128x128 xc:#1976d2 icon128.png
```

**Method C: Python Script**
```python
from PIL import Image, ImageDraw, ImageFont

def create_icon(size, filename):
    img = Image.new('RGB', (size, size), color='#1976d2')
    draw = ImageDraw.Draw(img)
    # Add text "PG"
    font_size = size // 2
    draw.text((size//4, size//4), "PG", fill='white')
    img.save(filename)

create_icon(16, 'icon16.png')
create_icon(48, 'icon48.png')
create_icon(128, 'icon128.png')
```

**Step 3: Reload Extension**
Go back to `chrome://extensions/` and click the reload icon on PhishGuard AI

---

## Part 4: Testing the System

### Test 1: Backend Health Check

```bash
curl http://localhost:8000/health
```

Expected:
```json
{
  "status": "ok",
  "redis": "connected",
  "agents": "ready"
}
```

### Test 2: Sample Phishing Email Analysis

```bash
curl -X POST http://localhost:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "email_text": "Dear customer, your account has been suspended. Click here to verify your account immediately.",
    "subject": "Account Suspended",
    "sender": "security@paypal-verify.com",
    "urls": ["http://paypal-verify.com/login"],
    "recipient_name": "John"
  }'
```

Expected: JSON response with `"verdict": "PHISHING"` and high score

### Test 3: Gmail Integration

1. Open Gmail in Chrome
2. Open any email
3. Wait 1-2 seconds
4. PhishGuard badge should appear near sender name
5. Click badge to see detailed analysis

### Test 4: URL Protection

1. Find an email with links in Gmail
2. PhishGuard should label each URL
3. Try clicking a phishing link (if detected)
4. Interstitial blocker should appear

---

## Part 5: Troubleshooting

### Backend Issues

**Problem: "Redis connection failed"**
```bash
# Check if Redis is running
redis-cli ping
# Should return: PONG

# If not running, start it
# macOS:
brew services start redis
# Linux:
sudo systemctl start redis
```

**Problem: "Module not found" errors**
```bash
# Reinstall dependencies
pip install --upgrade -r requirements.txt
```

**Problem: "Port 8000 already in use"**
```bash
# Find process using port 8000
lsof -i :8000
# Kill the process
kill -9 <PID>
# Or change port in .env
BACKEND_PORT=8001
```

**Problem: "Model download slow"**
The DistilBERT model (~260MB) downloads on first use. Be patient or download manually:
```python
from transformers import AutoTokenizer, AutoModelForSequenceClassification
model = AutoModelForSequenceClassification.from_pretrained("ealvaradob/bert-finetuned-phishing")
```

### Extension Issues

**Problem: "Backend: Offline" in popup**
1. Verify backend is running: `http://localhost:8000/health`
2. Check CORS settings in backend/.env
3. Look at service worker console for errors

**Problem: Badge not appearing**
1. Open browser console (F12)
2. Look for JavaScript errors
3. Reload the page
4. Try reloading the extension

**Problem: "Failed to load extension"**
1. Check all required files exist
2. Verify manifest.json is valid JSON
3. Create placeholder icons (see Part 3)
4. Check Chrome version (need 88+)

**Problem: Highlights not working**
1. Check email has text content (not just images)
2. Verify analysis returned highlighted_phrases
3. Look for console errors

---

## Part 6: Development Workflow

### Making Backend Changes

1. Edit Python files
2. Stop backend (Ctrl+C)
3. Restart: `python main.py`
4. Test changes

### Making Extension Changes

1. Edit JavaScript/CSS files
2. Go to `chrome://extensions/`
3. Click reload icon on PhishGuard AI
4. Reload Gmail/Outlook page
5. Test changes

### Viewing Logs

**Backend Logs:**
```bash
# In terminal where backend is running
# Logs appear in real-time
```

**Extension Logs:**
```javascript
// Content script logs (in page console)
F12 → Console tab

// Service worker logs
chrome://extensions/ → PhishGuard AI → "service worker" link
```

---

## Part 7: Production Deployment (Optional)

### Backend Production

**Step 1: Use production WSGI server**
```bash
pip install gunicorn
gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000
```

**Step 2: Set up HTTPS**
Use nginx or Caddy as reverse proxy

**Step 3: Use managed Redis**
AWS ElastiCache, Redis Cloud, or similar

**Step 4: Environment variables**
```env
LOG_LEVEL=WARNING
CORS_ORIGINS=https://yourdomain.com
```

### Extension Production

**Step 1: Create production icons**
Hire designer or use tools like Figma

**Step 2: Update manifest.json**
```json
{
  "host_permissions": [
    "https://mail.google.com/*",
    "https://outlook.live.com/*",
    "https://outlook.office.com/*",
    "https://api.yourdomain.com/*"
  ]
}
```

**Step 3: Update service worker**
Change `BACKEND_URL` to production API

**Step 4: Package extension**
```bash
cd extension
zip -r phishguard-extension.zip *
```

**Step 5: Submit to Chrome Web Store**
https://chrome.google.com/webstore/devconsole

---

## Part 8: API Keys (Optional)

### PhishTank API Key

1. Sign up at: https://www.phishtank.com/api_register.php
2. Get your API key
3. Add to backend/.env:
   ```env
   PHISHTANK_API_KEY=your_key_here
   ```
4. Restart backend

Without this key, PhishTank checks are skipped (not critical).

---

## Quick Reference

### Start Everything

```bash
# Terminal 1: Backend
cd backend
docker-compose up
# OR
python main.py

# Chrome: Load extension
chrome://extensions/ → Load unpacked → select extension folder
```

### Stop Everything

```bash
# Backend (Docker)
docker-compose down

# Backend (Local)
Ctrl+C in terminal

# Extension
chrome://extensions/ → Remove PhishGuard AI
```

### Check Status

```bash
# Backend health
curl http://localhost:8000/health

# Redis
redis-cli ping

# Extension
Click PhishGuard icon → check "Backend: Connected"
```

---

## Support

If you encounter issues:

1. Check logs (backend terminal + browser console)
2. Verify all prerequisites installed
3. Try the troubleshooting steps above
4. Check GitHub issues
5. Create new issue with:
   - OS and versions
   - Error messages
   - Steps to reproduce

---

## Next Steps

- Read backend/README.md for API details
- Read extension/README.md for extension details
- Explore the code to understand architecture
- Try analyzing different types of emails
- Customize detection rules
- Add new features

Happy phishing hunting! 🛡️
