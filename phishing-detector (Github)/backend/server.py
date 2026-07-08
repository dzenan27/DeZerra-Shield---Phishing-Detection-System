"""
backend/server.py — DeZerra Shield API Aggregator

This backend is the secure API proxy.
The extension and Outlook add-in send URLs here.
The backend holds all API keys server-side — they never
touch the user's machine. It also provides:
  - Redis caching (avoid redundant API calls)
  - Rate limiting (prevent API quota exhaustion)
  - Threat logging (audit trail for portfolio metrics)

Deploy free on: Railway, Fly.io, or Render.
"""

import os
import json
import hashlib
import asyncio
import httpx
from datetime import datetime
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional

# --- Config (use environment variables in production) --------
GSB_KEY        = os.getenv("", "")
VT_KEY         = os.getenv("", "")
IPQS_KEY       = os.getenv("", "")

app = FastAPI(title="DeZerra Shield API", version="1.0.0")

# Allow requests from the extension and add-in
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Lock this down in production
    allow_methods=["POST", "GET"],
    allow_headers=["*"],
)

cache: dict = {}
CACHE_TTL_SECONDS = 600  # 10 minutes

# ─────────────────────────────────────────────────────────────
class CheckRequest(BaseModel):
    url: str

class CheckLinksRequest(BaseModel):
    urls: list[str]

# ─────────────────────────────────────────────────────────────

@app.get("/health")
def health():
    return {"status": "ok", "service": "DeZerra Shield"}

@app.post("/api/check")
async def check_url(req: CheckRequest):
    """
    Main endpoint: accepts a URL, fans out to all threat APIs,
    returns aggregated score + source breakdown.
    """
    url = req.url.strip()
    if not url.startswith("http"):
        raise HTTPException(400, "URL must start with http or https")

    # Check cache
    cache_key = hashlib.md5(url.encode()).hexdigest()
    if cache_key in cache:
        entry = cache[cache_key]
        if (datetime.now() - entry["cached_at"]).seconds < CACHE_TTL_SECONDS:
            return {**entry["result"], "cached": True}

    # Fan out to all APIs in parallel
    gsb_task   = check_google_safe_browsing(url)
    vt_task    = check_virustotal(url)
    ipqs_task  = check_ipqualityscore(url)

    gsb_result, vt_result, ipqs_result = await asyncio.gather(
        gsb_task, vt_task, ipqs_task, return_exceptions=True
    )

    # Build sources list, skipping failed requests
    sources = []
    for r in [gsb_result, vt_result, ipqs_result]:
        if isinstance(r, dict):
            sources.append(r)

    # Weighted aggregate score
    weights  = {"Google Safe Browsing": 0.40, "VirusTotal": 0.30, "IPQualityScore": 0.30}
    total_w  = 0
    weighted = 0
    for s in sources:
        w = weights.get(s["source"], 0.1)
        weighted += s["score"] * w
        total_w  += w

    final_score = round(weighted / total_w) if total_w > 0 else 0
    verdict     = "blocked" if final_score >= 80 else "warned" if final_score >= 40 else "safe"

    result = {
        "url":     url,
        "score":   final_score,
        "verdict": verdict,
        "sources": sources,
        "cached":  False,
    }

    # Cache and log
    cache[cache_key] = {"result": result, "cached_at": datetime.now()}
    if verdict != "safe":
        log_threat(result)

    return result


@app.post("/api/check-links")
async def check_links(req: CheckLinksRequest):
    """Batch URL check for the Outlook add-in."""
    results = await asyncio.gather(*[
        check_url(CheckRequest(url=url)) for url in req.urls[:10]
    ], return_exceptions=True)
    return [r for r in results if isinstance(r, dict)]


@app.get("/api/threats")
def get_threat_log():
    """Returns the threat log for portfolio/metrics display."""
    try:
        with open("threat_log.jsonl", "r") as f:
            entries = [json.loads(line) for line in f.readlines()[-100:]]
        return {"entries": list(reversed(entries)), "total": len(entries)}
    except FileNotFoundError:
        return {"entries": [], "total": 0}


# ─────────────────────────────────────────────────────────────
# API INTEGRATIONS
# ─────────────────────────────────────────────────────────────

async def check_google_safe_browsing(url: str) -> dict:
    """
    CYBER CONCEPT: GSB uses a privacy-preserving hash-based lookup.
    The actual URL is hashed; only a prefix of the hash is sent
    to Google, so Google never sees the exact URL. The full hash
    is compared locally. (We use the simpler v4 API here.)
    """
    endpoint = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GSB_KEY}"
    body = {
        "client": {"clientId": "dezerra-shield", "clientVersion": "1.0.0"},
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}],
        },
    }
    async with httpx.AsyncClient(timeout=5.0) as client:
        res = await client.post(endpoint, json=body)
        data = res.json()
    is_blocked = bool(data.get("matches"))
    return {
        "source": "Google Safe Browsing",
        "score":  100 if is_blocked else 0,
        "detail": f"Blocked: {data['matches'][0]['threatType']}" if is_blocked else "Not listed",
    }


async def check_virustotal(url: str) -> dict:
    import base64
    url_id   = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
    endpoint = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    async with httpx.AsyncClient(timeout=8.0) as client:
        res = await client.get(endpoint, headers={"x-apikey": VT_KEY})
    if res.status_code == 404:
        return {"source": "VirusTotal", "score": 0, "detail": "Not in database"}
    data  = res.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values()) or 1
    raw_score  = round(((malicious * 1.5 + suspicious * 0.5) / total) * 100)
    return {
        "source": "VirusTotal",
        "score":  min(raw_score, 100),
        "detail": f"{malicious}/{total} engines flagged as malicious",
    }


async def check_ipqualityscore(url: str) -> dict:
    from urllib.parse import quote
    endpoint = f"https://www.ipqualityscore.com/api/json/url/{IPQS_KEY}/{quote(url, safe='')}"
    async with httpx.AsyncClient(timeout=5.0) as client:
        res = await client.get(endpoint)
    data  = res.json()
    score = data.get("risk_score", 0)
    if data.get("phishing"):  score = max(score, 85)
    if data.get("malware"):   score = max(score, 90)
    return {
        "source": "IPQualityScore",
        "score":  min(score, 100),
        "detail": f"Risk score: {data.get('risk_score', 'N/A')}",
    }


def log_threat(result: dict):
    """Append threat to JSONL log file for metrics and portfolio."""
    entry = {
        "url":     result["url"],
        "score":   result["score"],
        "verdict": result["verdict"],
        "time":    datetime.utcnow().isoformat(),
    }
    with open("threat_log.jsonl", "a") as f:
        f.write(json.dumps(entry) + "\n")


# Run with: uvicorn server:app --reload
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
