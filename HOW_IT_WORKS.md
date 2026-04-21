# PhishGuard AI — How It Works

> Complete technical reference: models, data sources, algorithms, and concepts for every step of the pipeline.

---

## Table of Contents

1. [System Overview](#1-system-overview)
2. [Component Map](#2-component-map)
3. [Chrome Extension — Data Collection](#3-chrome-extension--data-collection)
4. [Backend API — Request Entry Point](#4-backend-api--request-entry-point)
5. [Orchestrator — LangGraph Multi-Agent Engine](#5-orchestrator--langgraph-multi-agent-engine)
6. [Agent 1 — URL Agent](#6-agent-1--url-agent)
7. [Agent 2 — Content Agent + ML Model](#7-agent-2--content-agent--ml-model)
8. [Agent 3 — Header Agent](#8-agent-3--header-agent)
9. [Agent 4 — Reputation Agent](#9-agent-4--reputation-agent)
10. [Consensus Agent — Final Verdict](#10-consensus-agent--final-verdict)
11. [Caching Layer — Redis](#11-caching-layer--redis)
12. [Extension Response — UI Feedback](#12-extension-response--ui-feedback)
13. [Evaluation Framework](#13-evaluation-framework)
14. [Tech Stack Summary](#14-tech-stack-summary)
15. [Data Flow Diagram](#15-data-flow-diagram)

---

## 1. System Overview

PhishGuard AI detects phishing emails **in real-time** as users read them in Gmail or Outlook. It works as two parts:

| Component | What it does |
|---|---|
| **Chrome Extension** | Reads email from the browser DOM, extracts fields, sends to backend, shows warnings |
| **FastAPI Backend** | Runs 4 specialist AI agents in parallel, combines their scores, returns a verdict |

**Detection philosophy:** No single signal is trusted alone. Four independent agents each score the email from a different angle. A weighted consensus makes the final call.

---

## 2. Component Map

```
Gmail / Outlook (Browser)
        │
        │ DOM scraping
        ▼
┌─────────────────────────────────┐
│      Chrome Extension            │
│  • email_parser.js   (extract)  │
│  • url_interceptor.js (links)   │
│  • gmail.js / outlook.js        │
│  • highlighter.js   (warnings)  │
│  • ui_injector.js   (banners)   │
└────────────┬────────────────────┘
             │ POST /analyze (JSON)
             ▼
┌─────────────────────────────────┐
│      FastAPI Backend             │
│  • main.py           (app)      │
│  • api/routes.py     (endpoint) │
│  • config.py         (settings) │
└────────────┬────────────────────┘
             │
             ▼
┌─────────────────────────────────┐
│   LangGraph Orchestrator         │
│   orchestrator.py                │
│   Parallel async execution       │
└──┬──────┬──────┬──────┬─────────┘
   │      │      │      │
   ▼      ▼      ▼      ▼
URL    Content Header  Reputation
Agent  Agent   Agent   Agent
   │      │      │      │
   └──────┴──────┴──────┘
             │
             ▼
    Consensus Agent
    Final Score + Verdict
             │
             ▼
     Redis Cache (TTL 24h)
             │
             ▼
   JSON Response → Extension
```

---

## 3. Chrome Extension — Data Collection

**Files:** `extension/content/gmail.js`, `outlook.js`, `shared/email_parser.js`, `shared/url_interceptor.js`

**Platform support:** Gmail (`mail.google.com`), Outlook Web (`outlook.live.com`, `outlook.office.com`)

### What it extracts from the DOM

| Field | How it's extracted |
|---|---|
| `sender` | `From:` header visible in email view |
| `subject` | Email subject line |
| `email_text` | Plain text body |
| `email_html` | Full HTML body (for richer analysis) |
| `reply_to` | Reply-To header |
| `urls` | All `<a href>` tags via `url_interceptor.js` |
| `headers` | SPF/DKIM/DMARC values when shown by mail client |
| `recipient_name` | Signed-in user's name (for spear phishing detection) |

### Concept: Content Script Injection
Chrome MV3 content scripts run in the context of the web page at `document_idle` (after DOM is fully loaded). They can read the DOM but run in an isolated JavaScript sandbox — they cannot directly access the page's JavaScript variables.

### Concept: Link Interception
`url_interceptor.js` intercepts `click` events on all links. When clicked, it sends the URL to the service worker for a verdict check *before* navigating, blocking the navigation if PHISHING is returned.

---

## 4. Backend API — Request Entry Point

**Files:** `backend/api/routes.py`, `backend/api/models.py`, `backend/main.py`

**Framework:** FastAPI (Python async HTTP framework)

### Request Schema (`AnalyzeRequest`)

```json
{
  "email_text": "Dear Customer, your account...",
  "email_html": "<html>...</html>",
  "subject":    "Urgent: Verify your account",
  "sender":     "support@paypa1-verify.com",
  "reply_to":   "attacker@evil.com",
  "headers":    { "spf": "FAIL", "dkim": "FAIL" },
  "urls":       ["http://paypa1-verify.com/verify"],
  "recipient_name": "John"
}
```

### Response Schema (`AnalyzeResponse`)

```json
{
  "verdict":    "PHISHING",
  "confidence": 0.87,
  "final_score": 87,
  "agent_scores": {
    "url_agent":        { "score": 85, "signals": ["Brand spoofing"] },
    "content_agent":    { "score": 78, "signals": ["ML confidence 78%"] },
    "header_agent":     { "score": 60, "signals": ["SPF FAIL"] },
    "reputation_agent": { "score": 50, "signals": ["New domain"] }
  },
  "url_verdicts": [...],
  "highlighted_phrases": [...],
  "spear_phishing_detected": false,
  "processing_time_ms": 1250
}
```

### Startup: ML Model Pre-loading
On server start, `main.py` pre-loads the BERT model in a **thread executor** (`asyncio.run_in_executor`) so it never blocks the asyncio event loop during live requests:

```python
await loop.run_in_executor(None, classifier.load_model)
```

---

## 5. Orchestrator — LangGraph Multi-Agent Engine

**File:** `backend/agents/orchestrator.py`  
**Library:** LangGraph (`langgraph>=0.0.26`) + LangChain Core

### Concept: LangGraph State Machine
LangGraph is a graph-based execution framework built on top of LangChain. It models workflows as **nodes** (processing steps) and **edges** (transitions). Each node receives a typed `AgentState` dict and can update it.

### Graph Structure

```
START
  │
  ▼
parallel_agents   ← runs all 4 agents concurrently via asyncio.gather
  │
  ▼
consensus         ← combines results into final verdict
  │
  ▼
END
```

### Concept: Async Parallel Execution
All 4 agents run simultaneously using Python's `asyncio.gather`. This means a 5-second WHOIS lookup in the reputation agent does not delay the content agent — they race in parallel.

```python
results = await asyncio.gather(
    url_agent.analyze(payload),
    content_agent.analyze(payload),
    header_agent.analyze(payload),
    reputation_agent.analyze(payload)
)
```

### Timeout Protection
Each agent is wrapped in `asyncio.wait_for(agent_func(), timeout=10s)`. If an agent stalls (e.g. network call hangs), it returns score=0 with a timeout signal rather than blocking the response.

---

## 6. Agent 1 — URL Agent

**File:** `backend/agents/url_agent.py`  
**ML file:** `backend/ml/url_features.py`  
**Brand file:** `backend/ml/brand_detector.py`

### What it does
Analyzes every URL in the email using **lexical (no network) features** + **brand spoofing detection**. Results are cached in Redis.

### Features extracted (`url_features.py`)

| Feature | Concept | Weight |
|---|---|---|
| `is_https` | Legitimate services use HTTPS | +10 if missing |
| `has_ip_address` | IP in domain = suspicious | +20 |
| `is_shortener` | Hides real destination | +20 |
| `has_at_symbol` | `user@legit.com@evil.com` trick | +25 |
| `suspicious_keywords` | `/login`, `/verify`, `/secure` in path | +7 each |
| `risky_tld` | `.tk`, `.xyz`, `.ml` = abuse-prone TLDs | +12 |
| `subdomain_count` | `login.verify.secure.evil.com` obfuscation | +10 if >3 |
| `url_length` | Very long URLs hide real destination | +12 if >75 chars |
| `entropy` | High randomness = generated domain | scored |
| `percent_encoding` | `%XX` chars = obfuscation | +8 |
| `has_port` | Unusual port in URL | +8 |

**Library used:** `tldextract` — correctly parses TLD even for multi-part TLDs like `.co.uk`

### Brand Spoofing Detection (`brand_detector.py`)

**Concept: Levenshtein/Substring Brand Matching**  
Checks if a URL's domain contains a known brand name but is NOT on the official domain list.

```
paypa1.com      → contains "paypal" → NOT paypal.com → SPOOFING +25
amazon-login.xyz → contains "amazon" → NOT amazon.com → SPOOFING +25
```

**28 brands monitored:** PayPal, Amazon, Google, Microsoft, Apple, Facebook, Netflix, Chase, Wells Fargo, Bank of America, Citi, Amex, Discover, eBay, LinkedIn, Twitter/X, Dropbox, Adobe, Spotify, Coinbase, Binance, Walmart, Target, Best Buy, FedEx, UPS, USPS, DHL

### Output per URL
```json
{ "score": 85, "verdict": "PHISHING", "signals": ["Brand spoofing: paypal"] }
```

Final agent score = `0.7 × max_url_score + 0.3 × avg_url_score`

---

## 7. Agent 2 — Content Agent + ML Model

**File:** `backend/agents/content_agent.py`  
**ML file:** `backend/ml/classifier.py`

### ML Model: `ealvaradob/bert-finetuned-phishing`

| Property | Value |
|---|---|
| **Base architecture** | DistilBERT (distilled BERT — 40% smaller, 60% faster) |
| **Fine-tuned on** | Phishing email dataset (HuggingFace Hub) |
| **Task** | Binary sequence classification: SAFE (0) vs PHISHING (1) |
| **Library** | HuggingFace `transformers` |
| **Input** | Tokenized email body, max 512 tokens |
| **Output** | Softmax probabilities → `phishing_probability` (0.0–1.0) |
| **Device** | CPU (GPU if available via `torch.cuda.is_available()`) |
| **Model size** | ~440 MB (stored in `~/.cache/huggingface/hub/`) |

**Source:** [huggingface.co/ealvaradob/bert-finetuned-phishing](https://huggingface.co/ealvaradob/bert-finetuned-phishing)

### Text preprocessing pipeline
```
Raw email body
    → strip HTML tags (regex)
    → replace URLs with [URL] token
    → replace emails with [EMAIL] token  
    → normalize whitespace
    → tokenize (WordPiece tokenizer, max 512 tokens)
    → BERT inference → softmax → phishing_probability
```

### Concept: Transfer Learning
DistilBERT was pre-trained on BookCorpus + Wikipedia to learn language patterns. Fine-tuning on phishing emails adapts these general language representations to recognize phishing-specific linguistic patterns (urgency language, credential harvesting phrasing, social engineering vocabulary).

### Rule-based fallback (when model not loaded)

If the model fails to load, content agent falls back to keyword scoring:

| Keyword category | Score added |
|---|---|
| Credential harvesting (`enter your password`, `share your OTP`) | +25 |
| Account threats (`verify your account`, `unusual activity`) | +18 |
| Urgency (`urgent`, `click here`, `act now`) | +12 |
| Urgency pattern (`within 24 hours`) | +15 |
| Generic greeting (`dear customer`) | +10 |

### Phrase detection (always active)
Even with ML running, the agent also checks for 33 hard-coded phrases:
- **HIGH severity** (10 phrases): credential harvesting → `+20 each`
- **MEDIUM severity** (13 phrases): urgency/social engineering → `+10 each`
- **LOW severity** (9 phrases): mild indicators → `+5 each`

### Spear Phishing Detection
If `recipient_name` is provided and appears in the email body alongside brand impersonation OR credential requests:
```
"Dear John, your PayPal account..." + paypal-verify.com sender → spear phishing → +25
```

---

## 8. Agent 3 — Header Agent

**File:** `backend/agents/header_agent.py`

### What it does
Analyzes email authentication headers that prove whether the email truly came from who it claims.

### Email authentication concepts

| Protocol | What it verifies | How |
|---|---|---|
| **SPF** (Sender Policy Framework) | Did this IP have permission to send for this domain? | DNS TXT record lists authorized IPs |
| **DKIM** (DomainKeys Identified Mail) | Was this email cryptographically signed by the domain? | RSA signature in `DKIM-Signature` header |
| **DMARC** (Domain-based Message Authentication) | Did SPF/DKIM align with the `From:` domain? | Policy published in DNS |

### Scoring logic

| Signal | Score |
|---|---|
| SPF FAIL | +30 |
| SPF SOFTFAIL | +20 |
| DKIM missing/FAIL | +25 |
| DMARC FAIL | +20 |
| Reply-To ≠ From domain | +20 |
| From display name ≠ From address domain | +15 |
| Brand impersonation in From display name | +25 |
| No SPF record | +10 |

### Concept: Display Name Spoofing
Phishers set `From: "PayPal Security" <attacker@evil.com>`. Email clients show the display name ("PayPal Security") but the actual sending address is `evil.com`. Header agent checks if the display name contains a known brand that doesn't match the actual sending domain.

---

## 9. Agent 4 — Reputation Agent

**File:** `backend/agents/reputation_agent.py`  
**Threat feed file:** `backend/feeds/threat_feeds.py`

### Data sources queried (live, per request)

| Source | What it contains | Protocol |
|---|---|---|
| **PhishTank** | Community-verified phishing URLs (~50k active) | HTTP GET with API key |
| **URLhaus** | Malware distribution URLs (~700k active) | HTTP GET (free, no key) |
| **WHOIS** | Domain registration date | TCP/WHOIS protocol |

### Scoring

| Signal | Score |
|---|---|
| URL found in PhishTank | +60 |
| URL found in URLhaus | +55 |
| Domain registered < 30 days ago | +20 |
| Domain registered 30–90 days ago | +10 |

### Concept: Threat Intelligence Feeds
Real-time feeds of known-bad URLs maintained by security communities. PhishTank is crowd-validated (users submit + vote). URLhaus is run by abuse.ch and tracks active malware distribution.

### Concept: Domain Age as Signal
Phishers register new domains for each campaign to avoid blocklists. A domain registered hours before sending an email impersonating a bank is highly suspicious.

### Async optimization
All URL reputation checks run in parallel via `asyncio.gather`. WHOIS (blocking TCP) runs in `loop.run_in_executor` to avoid blocking the event loop. A 3-second timeout is enforced on the WHOIS call.

---

## 10. Consensus Agent — Final Verdict

**File:** `backend/agents/consensus.py`

### Weighted scoring formula

```
weighted_score = (url_score    × 0.35)
               + (content_score × 0.30)
               + (header_score  × 0.20)
               + (reputation_score × 0.15)

max_score = max(url, content, header, reputation)

final_score = (weighted_score × 0.60) + (max_score × 0.40)
```

The `max_score` component (40% weight) ensures that **one extremely strong signal can override a lukewarm average**. For example, if url_score=90 (clear brand spoofing) but other agents score 0, final_score still reaches ~36+36=~50+.

### Critical overrides (hard floors)

| Condition | Minimum final_score forced |
|---|---|
| `url_score >= 70` | 72 (guaranteed PHISHING) |
| `content_score >= 80` | 75 |
| `header_score >= 70` | 68 (SUSPICIOUS border) |
| `spear_phishing_detected = True` | 80 |
| `brand_spoofing in url_verdicts` | 78 |

### Verdict thresholds

```
0  ──────────── 39 ──────────── 69 ──────────── 100
       SAFE          SUSPICIOUS        PHISHING
```

| Verdict | Meaning | Action in extension |
|---|---|---|
| **SAFE** | Score 0–39 | Green badge, no warning |
| **SUSPICIOUS** | Score 40–69 | Yellow warning toast |
| **PHISHING** | Score 70–100 | Red interstitial, link blocked |

### Concept: Ensemble Scoring
Combining multiple weak classifiers (each with limited accuracy alone) into a stronger combined classifier. This is the same principle as Random Forests / Boosting in ML — diversity of signal sources reduces false positives and false negatives.

---

## 11. Caching Layer — Redis

**File:** `backend/cache/redis_client.py`  
**Library:** `redis[hiredis]==5.0.1` (async client)

### What is cached
- URL verdicts keyed by `verdict:{md5(url)}` with **24-hour TTL**
- If the same URL appears in multiple emails, the cached verdict is returned instantly

### Concept: Content-Addressable Cache
URLs are hashed with MD5 before storage. This normalizes URL length (long URLs → fixed 32-char key) and provides O(1) lookup regardless of URL complexity.

### Connection pooling
`BlockingConnectionPool` with `max_connections=50`. The pool is initialized once at startup and shared across all requests in a process.

---

## 12. Extension Response — UI Feedback

**Files:** `extension/content/shared/highlighter.js`, `ui_injector.js`

| Verdict | Visual feedback |
|---|---|
| **SAFE** | Small green shield badge injected into email toolbar |
| **SUSPICIOUS** | Yellow warning banner above email body with signal list |
| **PHISHING** | Full red warning overlay, suspicious phrases highlighted in yellow in email body, all links blocked |

### Phrase highlighting
The `highlighted_phrases` array from the backend response (with `text`, `reason`, `severity`) is used to find and highlight the exact text inside the email DOM using `document.createTreeWalker`.

---

## 13. Evaluation Framework

**Files:** `backend/eval_agents.py`, `backend/eval_url_agent.py`, `backend/prepare_dataset.py`

### Email evaluation (`eval_agents.py`)
- **Dataset:** 7 CSV phishing email datasets (CEAS_08, Enron, Ling, Nazario, Nigerian_Fraud, SpamAssasin, phishing_email.csv)
- **Method:** Sends real emails to running backend, compares verdict to ground truth
- **Metrics:** Accuracy, Precision, Recall, F1, ROC-AUC, P95 Latency, Cache Hit Rate
- **Current results:** Accuracy 91.2%, Precision 93.3%, Recall 91.4%, F1 0.924

### URL evaluation (`eval_url_agent.py`)
- **Dataset:** PhiUSIIL Phishing URL Dataset (235,795 URLs)
- **Method:** Sends URL-only payloads (empty body, neutral headers) to isolate URL agent
- **Key finding:** ROC-AUC 0.82 (strong ranking) but Recall 1.4% in isolation — URL signals alone rarely clear the 70-point threshold without email body/header context

### Metrics explanation

| Metric | Formula | What it means for phishing |
|---|---|---|
| **Accuracy** | (TP+TN) / total | Overall correctness |
| **Precision** | TP / (TP+FP) | Of emails flagged as phishing, how many were real? (false alarm rate) |
| **Recall** | TP / (TP+FN) | Of actual phishing emails, how many were caught? (miss rate) |
| **F1** | 2×(P×R)/(P+R) | Harmonic mean balancing precision and recall |
| **ROC-AUC** | Area under ROC curve | Ranking quality regardless of threshold |

---

## 14. Tech Stack Summary

### Backend

| Layer | Technology | Purpose |
|---|---|---|
| **API framework** | FastAPI | Async HTTP server, auto-generated OpenAPI docs |
| **Server** | Uvicorn | ASGI server for FastAPI |
| **Agent orchestration** | LangGraph + LangChain Core | Multi-agent state machine |
| **ML model** | HuggingFace Transformers + PyTorch | DistilBERT phishing classifier |
| **URL parsing** | `tldextract` | Accurate domain/TLD extraction |
| **WHOIS** | `python-whois` | Domain registration date lookup |
| **HTTP client** | `httpx` | Async HTTP for threat feed queries |
| **Cache** | Redis + `redis[hiredis]` | URL verdict caching (24h TTL) |
| **Config** | Pydantic Settings | Type-safe environment variable loading |
| **Validation** | Pydantic v2 | Request/response schema validation |
| **Eval metrics** | scikit-learn | Accuracy, Precision, Recall, F1, ROC-AUC |

### Chrome Extension

| Component | Technology | Purpose |
|---|---|---|
| **Manifest** | MV3 (Manifest Version 3) | Modern Chrome extension architecture |
| **Background** | Service Worker | Persistent message handler |
| **Content scripts** | Vanilla JavaScript | DOM parsing, UI injection |

### External Data Sources

| Source | URL | What it provides |
|---|---|---|
| **HuggingFace Hub** | `ealvaradob/bert-finetuned-phishing` | Pre-trained phishing BERT model |
| **PhishTank** | `data.phishtank.com` | Known phishing URLs database |
| **URLhaus** | `urlhaus-api.abuse.ch` | Malware distribution URLs |
| **WHOIS servers** | Various (via `python-whois`) | Domain registration data |

---

## 15. Data Flow Diagram

```
User opens email in Gmail
         │
         ▼
email_parser.js scrapes:
  sender, subject, body, URLs, headers
         │
         ▼
POST http://localhost:8000/analyze
{email_text, subject, sender, urls, headers}
         │
         ▼
FastAPI validates request (Pydantic)
         │
         ▼
Orchestrator spawns 4 agents (asyncio.gather, 10s timeout each)
         │
    ┌────┴────┬──────────┬──────────────┐
    ▼         ▼          ▼              ▼
URL Agent  Content    Header         Reputation
           Agent      Agent          Agent
    │         │          │              │
lexical    DistilBERT  SPF/DKIM/     PhishTank
features   + 33 phrase DMARC check   URLhaus
+ brand    patterns   + display      + WHOIS
spoofing   (NLP)      name spoof     domain age
    │         │          │              │
score 0-100  0-100     0-100          0-100
    │         │          │              │
    └────┬────┴──────────┴──────────────┘
         │
         ▼
Consensus Agent:
  final = 0.6 × weighted + 0.4 × max
  + critical overrides
         │
         ▼
┌────────────────────────────┐
│ final_score  │  verdict    │
│   0 – 39     │  SAFE       │
│  40 – 69     │  SUSPICIOUS │
│  70 – 100    │  PHISHING   │
└────────────────────────────┘
         │
         ▼
Cache result in Redis (24h)
         │
         ▼
Return JSON to extension
         │
         ▼
Extension injects UI:
  SAFE → green badge
  SUSPICIOUS → yellow warning
  PHISHING → red block + phrase highlights
```

---

*Document generated from live codebase — `PhishGuard-AI/` commit state April 2026.*
