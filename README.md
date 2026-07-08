# 🛡️ DeZerra Shield — Phishing Detection System

**Cross-browser extension + Outlook add-in for real-time phishing and threat detection.**

Built by Dzenan Muratovic

---

## What this does

DeZerra Shield intercepts every URL a user visits and every email they open, runs it through a multi-layer detection pipeline, and alerts the user when a phishing or malware threat is detected.

---

## System architecture

```
CLIENT LAYER
├── Browser Extension (WebExtensions API — Chrome, Firefox, Edge, Brave)
│   ├── Local Heuristics (instant, offline)
│   └── → Backend API Aggregator
└── Outlook Add-in (Office.js — Desktop, Web, Mobile)
    ├── Email Header Analysis (SPF/DKIM/DMARC)
    └── → Backend API Aggregator

YOUR BACKEND (Node.js / FastAPI)
└── API Keys stored server-side (never in the extension)
    ├── Google Safe Browsing  — blocklist, 40% weight
    ├── VirusTotal            — 70+ engine consensus, 30% weight
    └── IPQualityScore        — dedicated phishing score, 30% weight

USER NOTIFICATIONS
├── Block page  — full redirect for score ≥ 80
├── Warning banner — injected via Shadow DOM for score ≥ 40
└── Email flag + panel — threat score + signal breakdown
```

---

## Detection methodology

### Layer 1 — Local heuristics (runs instantly, no API call)

These checks run in under 1ms and catch threats that haven't reached threat intelligence feeds yet ("zero-day phishing").

| Check | What it detects | Cyber concept |
|---|---|---|
| HTTPS validation | Unencrypted connections | Transport security |
| Suspicious TLD | `.tk`, `.xyz`, `.click` etc | TLD abuse patterns |
| Brand impersonation | `paypal.evil.com` | Subdomain spoofing |
| Homoglyph detection | `pаypal.com` (Cyrillic а) | Unicode substitution attacks |
| URL entropy scoring | Algorithmically generated domains | DGA detection |
| Excessive subdomains | `secure.login.verify.paypal.evil.com` | URL obfuscation |
| Raw IP as hostname | `http://192.168.1.1/login` | Bulletproof hosting indicator |
| Credential keywords | `/login/verify/update` in path | Phishing page pattern |

### Layer 2 — Threat intelligence APIs (weighted aggregate)

| Source | Type | Weight | Why |
|---|---|---|---|
| Google Safe Browsing | Blocklist (binary) | 40% | Highest trust, fed by billions of Chrome users |
| VirusTotal | Multi-engine consensus | 30% | 70+ independent AV engines reduce false positives |
| IPQualityScore | Continuous risk score | 30% | Domain age, DNS history, behavioral patterns |

**Score aggregation:** `final_score = (gsb × 0.40) + (vt × 0.30) + (ipqs × 0.30)`

### Layer 3 — Email authentication (Outlook add-in)

| Protocol | What it checks | Failure meaning |
|---|---|---|
| SPF | Did this email come from an authorized server? | Sender IP not permitted by domain |
| DKIM | Was the email cryptographically signed? | Email may have been tampered in transit |
| DMARC | Does the domain have an enforcement policy? | Policy violated — likely spoofing |

---

## Threat thresholds

| Score | Verdict | Action |
|---|---|---|
| 0–39  | Safe | Silent pass |
| 40–79 | Warned | Warning banner injected via Shadow DOM |
| 80–100 | Blocked | Full-page block interstitial |

## Example Video Walk-Through:



---

## Known limitations and false positives

Understanding where a tool fails is as important as knowing what it catches.

**False positives (safe sites flagged as threats):**
- Newly registered legitimate domains score high on entropy checks
- URL shorteners (bit.ly, t.co) trigger redirect chain detection
- Legitimate sites on free TLDs (.tk is used by some real businesses)
- Large enterprise internal URLs with many subdomain levels

**False negatives (threats not caught):**
- Freshly registered phishing domains not yet in GSB or VirusTotal
- Phishing pages hosted on legitimate compromised infrastructure (good domain reputation)
- Targeted spear-phishing with custom domains and valid TLS certificates
- Adversary-in-the-middle (AiTM) proxy phishing kits that relay real sites

**Mitigation:** The multi-source weighted scoring model reduces both error types — a URL must look suspicious to multiple independent sources before triggering a block. Local heuristics catch what APIs miss; APIs catch what heuristics miss.

---

## Setup

### Browser extension

1. Clone this repo
2. Open `chrome://extensions/`
3. Enable **Developer mode**
4. Click **Load unpacked** → select the `phishing-detector/` folder
5. Add your API keys to `background/config.js` (or deploy the backend and point `BACKEND_URL` to it)

### Outlook add-in

```bash
cd outlook-addin
npm install -g yo generator-office
yo office
# Choose: Outlook task pane
npm start
```

### Backend

```bash
cd backend
pip install fastapi uvicorn httpx
export GOOGLE_SAFE_BROWSING_KEY="..."
export VIRUSTOTAL_KEY="..."
export IPQUALITYSCORE_KEY="..."
uvicorn server:app --reload
```

Deploy to Railway: `railway up`

---

## API keys (free tiers)

| API | Free tier | Link |
|---|---|---|
| Google Safe Browsing | 10,000 requests/day | [console.cloud.google.com](https://console.cloud.google.com) |
| VirusTotal | 4 requests/min | [virustotal.com/gui/sign-in](https://www.virustotal.com/gui/sign-in) |
| IPQualityScore | 5,000 requests/month | [ipqualityscore.com](https://www.ipqualityscore.com) |

---

## Project files

```
phishing-detector/
├── manifest.json                  # Extension identity + permissions
├── background/
│   ├── service_worker.js          # Navigation interception + orchestration
│   ├── api_detection.js           # External threat API calls
│   └── config.js                  # API keys + scoring weights
├── content/
│   └── content_script.js          # Shadow DOM banner injection
├── heuristics/
│   └── url_heuristics.js          # Local offline detection logic
├── popup/
│   ├── popup.html                 # Extension popup UI
│   ├── popup.js                   # Popup data rendering
│   └── log.html                   # Threat log viewer
├── outlook-addin/
│   ├── taskpane.html              # Outlook task pane UI
│   └── taskpane.js                # Email analysis + Office.js integration
└── backend/
    └── server.py                  # FastAPI aggregator + threat log
```

---

## Threat coverage matrix

| Attack type | Local heuristics | GSB | VirusTotal | IPQS | Email auth |
|---|---|---|---|---|---|
| Credential harvesting page | ✓ (keywords, entropy) | ✓ | ✓ | ✓ | — |
| Business email compromise | — | — | — | — | ✓ (Reply-To mismatch) |
| Lookalike domain | ✓ (homoglyph, brand check) | ✓ | ✓ | ✓ | ✓ (SPF/DKIM) |
| Drive-by malware download | — | ✓ (MALWARE type) | ✓ | ✓ | — |
| URL shortener redirect | ✓ (redirect chain) | ✓ | ✓ | ✓ | — |
| Raw IP hosting | ✓ (IP hostname check) | ✓ | ✓ | ✓ | — |
| Email spoofing | — | — | — | — | ✓ (DMARC fail) |
| DGA / algorithmically generated domain | ✓ (entropy) | ✓ | ✓ | ✓ | — |

---

*DeZerra Shield is a portfolio and educational project demonstrating multi-layer phishing detection. It is not a commercial security product!!
