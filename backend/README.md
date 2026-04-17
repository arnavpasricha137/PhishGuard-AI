# PhishGuard AI Backend

Multi-agent phishing detection system with FastAPI, Redis caching, and LangGraph orchestration.

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    FastAPI Application                       │
│                     (main.py)                                │
└──────────────────┬──────────────────────────────────────────┘
                   │
        ┌──────────┴──────────┬──────────────┐
        │                     │              │
        ▼                     ▼              ▼
┌──────────────┐    ┌──────────────┐   ┌──────────────┐
│ URL Agent    │    │Content Agent │   │Header Agent  │
│              │    │              │   │              │
│ - Lexical    │    │ - DistilBERT │   │ - SPF/DKIM   │
│ - Brand      │    │ - Patterns   │   │ - Spoofing   │
│ - Features   │    │ - Spear      │   │ - Reply-To   │
└──────┬───────┘    └──────┬───────┘   └──────┬───────┘
       │                   │                   │
       └───────────────────┴───────────────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │  Reputation Agent    │
                │  - PhishTank         │
                │  - URLhaus           │
                │  - WHOIS             │
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │  Consensus Agent     │
                │  - Weighted scoring  │
                │  - Critical overrides│
                └──────────┬───────────┘
                           │
                           ▼
                ┌──────────────────────┐
                │  Final Verdict       │
                │  + Explainability    │
                └──────────────────────┘
```

## Features

- **4 Specialist Agents**: URL, Content, Header, Reputation
- **LangGraph Orchestration**: Parallel agent execution with timeout protection
- **ML-Powered**: DistilBERT fine-tuned on phishing detection
- **Redis Caching**: 24-hour TTL for URL verdicts
- **Threat Intelligence**: PhishTank and URLhaus integration
- **Explainable AI**: Detailed signals from each agent
- **Async/Await**: Full async support for high performance

## Quick Start

### Option 1: Docker (Recommended)

```bash
cd backend
docker-compose up
```

The backend will be available at `http://localhost:8000`

### Option 2: Local Development

```bash
cd backend

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Edit .env and add your API keys

# Start Redis (if not using Docker)
redis-server

# Run the application
python main.py
```

## Environment Variables

Create a `.env` file with:

```env
REDIS_URL=redis://localhost:6379
PHISHTANK_API_KEY=your_key_here
BACKEND_PORT=8000
LOG_LEVEL=INFO
CORS_ORIGINS=chrome-extension://*,http://localhost:3000
AGENT_TIMEOUT=5
CACHE_TTL=86400
MODEL_NAME=ealvaradob/bert-finetuned-phishing
EXTERNAL_API_TIMEOUT=3
```

## API Endpoints

### POST /analyze

Analyze an email for phishing indicators.

**Request:**
```json
{
  "email_text": "string",
  "email_html": "string",
  "subject": "string",
  "sender": "string",
  "reply_to": "string",
  "headers": {},
  "urls": ["http://example.com"],
  "recipient_name": "John"
}
```

**Response:**
```json
{
  "verdict": "PHISHING",
  "confidence": 0.87,
  "final_score": 87,
  "agent_scores": {
    "url_agent": {"score": 85, "signals": [...]},
    "content_agent": {"score": 78, "signals": [...]},
    "header_agent": {"score": 60, "signals": [...]},
    "reputation_agent": {"score": 50, "signals": [...]}
  },
  "url_verdicts": [...],
  "highlighted_phrases": [...],
  "spear_phishing_detected": false,
  "processing_time_ms": 1250
}
```

### GET /health

Check backend health status.

**Response:**
```json
{
  "status": "ok",
  "redis": "connected",
  "agents": "ready"
}
```

### GET /verdict/{url_hash}

Get cached verdict for a URL by its MD5 hash.

## Agent Details

### URL Agent
- Lexical feature extraction (entropy, length, hyphens, etc.)
- Brand spoofing detection (PayPal, Amazon, Google, etc.)
- Homoglyph detection (Unicode lookalikes)
- URL shortener detection
- TLD risk scoring

### Content Agent
- DistilBERT phishing classifier
- Highlighted phrase extraction with severity levels
- Spear phishing detection (personalized attacks)
- Urgency pattern detection
- Generic greeting detection

### Header Agent
- SPF validation
- DKIM signature verification
- DMARC policy checking
- Reply-To domain mismatch detection
- Display name spoofing detection

### Reputation Agent
- PhishTank database lookup
- URLhaus malware database lookup
- WHOIS domain age checking
- Async HTTP with fallback on timeout

### Consensus Agent
- Weighted scoring: 35% URL, 30% Content, 20% Header, 15% Reputation
- Max signal detection (strongest indicator)
- Critical overrides for high-risk patterns
- Verdict thresholds: 0-39 SAFE, 40-69 SUSPICIOUS, 70-100 PHISHING

## Development

### Running Tests

```bash
# Install test dependencies
pip install pytest pytest-asyncio httpx

# Run tests
pytest
```

### Code Structure

```
backend/
├── main.py              # FastAPI app entry point
├── config.py            # Environment configuration
├── api/
│   ├── routes.py        # API endpoints
│   └── models.py        # Pydantic models
├── agents/
│   ├── url_agent.py
│   ├── content_agent.py
│   ├── header_agent.py
│   ├── reputation_agent.py
│   ├── consensus.py
│   └── orchestrator.py  # LangGraph coordination
├── ml/
│   ├── classifier.py    # DistilBERT wrapper
│   ├── url_features.py  # URL feature extraction
│   └── brand_detector.py
├── cache/
│   └── redis_client.py
└── feeds/
    └── threat_feeds.py  # PhishTank/URLhaus
```

## Performance

- **Average analysis time**: 800-1500ms
- **Cache hit response**: <50ms
- **Parallel agent execution**: All 4 agents run simultaneously
- **Timeout protection**: 5s per agent with graceful fallback

## Troubleshooting

**Redis connection failed:**
```bash
# Start Redis
docker run -d -p 6379:6379 redis:7-alpine
```

**Model download slow:**
The DistilBERT model (~260MB) downloads on first use. Subsequent runs use cached model.

**PhishTank/URLhaus timeout:**
External APIs have 3s timeout. Analysis continues with offline heuristics on failure.

## Production Deployment

1. Set `LOG_LEVEL=WARNING` in production
2. Use production WSGI server (Gunicorn):
   ```bash
   gunicorn main:app -w 4 -k uvicorn.workers.UvicornWorker
   ```
3. Enable HTTPS
4. Set up proper CORS origins
5. Use managed Redis (AWS ElastiCache, Redis Cloud, etc.)
6. Monitor with application performance monitoring (APM)

## License

See main project LICENSE file.
