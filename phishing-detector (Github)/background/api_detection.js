// ============================================================
//  API_DETECTION.JS — External threat intelligence queries
// ============================================================

import { CONFIG } from "./config.js";


// ============================================================
//  MASTER FUNCTION — query all APIs and return aggregate score
// ============================================================

export async function queryAllAPIs(url) {
  // If backend proxy is configured, route through it
  if (CONFIG.BACKEND_URL) {
    return queryBackend(url);
  }

  // Otherwise call APIs directly (dev mode)
  const [gsbResult, vtResult, ipqsResult] = await Promise.allSettled([
    checkGoogleSafeBrowsing(url),
    checkVirusTotal(url),
    checkIPQualityScore(url),
  ]);

  const results = {
    google_safe_browsing: gsbResult.status === "fulfilled" ? gsbResult.value : null,
    virustotal:           vtResult.status  === "fulfilled" ? vtResult.value  : null,
    ipqualityscore:       ipqsResult.status === "fulfilled" ? ipqsResult.value : null,
  };

  return aggregateScore(results);
}


// ============================================================
//  GOOGLE SAFE BROWSING
// ============================================================

async function checkGoogleSafeBrowsing(url) {
  const endpoint = `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${CONFIG.GOOGLE_SAFE_BROWSING_KEY}`;

  const body = {
    client: { clientId: "dezerra-shield", clientVersion: "1.0.0" },
    threatInfo: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
      platformTypes: ["ANY_PLATFORM"],
      threatEntryTypes: ["URL"],
      threatEntries: [{ url }],
    },
  };

  const res = await fetch(endpoint, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });

  if (!res.ok) throw new Error(`GSB API error: ${res.status}`);
  const data = await res.json();

  // If "matches" exists, the URL is on a blocklist
  const isBlocked = !!(data.matches && data.matches.length > 0);
  const threatType = isBlocked ? data.matches[0].threatType : null;

  return {
    source: "Google Safe Browsing",
    score: isBlocked ? 100 : 0,  // Binary: blocked or not
    isBlocked,
    threatType,
    detail: isBlocked
      ? `Blocked by Google Safe Browsing: ${threatType}`
      : "Not found in Google Safe Browsing database",
  };
}


// ============================================================
//  VIRUSTOTAL
// ============================================================

async function checkVirusTotal(url) {
  // VT requires the URL to be base64 encoded (URL-safe)
  const urlId = btoa(url).replace(/=/g, "").replace(/\+/g, "-").replace(/\//g, "_");
  const endpoint = `https://www.virustotal.com/api/v3/urls/${urlId}`;

  const res = await fetch(endpoint, {
    headers: { "x-apikey": CONFIG.VIRUSTOTAL_KEY },
  });

  // 404 = URL not yet in VT database — not necessarily clean
  if (res.status === 404) {
    return { source: "VirusTotal", score: 0, detail: "URL not in VirusTotal database yet", engines: {} };
  }
  if (!res.ok) throw new Error(`VirusTotal API error: ${res.status}`);

  const data = await res.json();
  const stats = data.data?.attributes?.last_analysis_stats || {};

  const malicious  = stats.malicious  || 0;
  const suspicious = stats.suspicious || 0;
  const total      = Object.values(stats).reduce((a, b) => a + b, 0);

  
  const rawScore = total > 0
    ? Math.round(((malicious * 1.5 + suspicious * 0.5) / total) * 100)
    : 0;

  return {
    source: "VirusTotal",
    score: Math.min(rawScore, 100),
    malicious,
    suspicious,
    total,
    detail: `${malicious} of ${total} engines flagged as malicious`,
  };
}


// ============================================================
//  IPQUALITYSCORE
// ============================================================

async function checkIPQualityScore(url) {
  const encoded = encodeURIComponent(url);
  const endpoint = `https://www.ipqualityscore.com/api/json/url/${CONFIG.IPQUALITYSCORE_KEY}/${encoded}`;

  const res = await fetch(endpoint);
  if (!res.ok) throw new Error(`IPQS API error: ${res.status}`);

  const data = await res.json();

  // CYBER CONCEPT: IPQS returns explicit phishing/malware
  let score = data.risk_score || 0;
  if (data.phishing)    score = Math.max(score, 85);
  if (data.malware)     score = Math.max(score, 90);
  if (data.suspicious)  score = Math.max(score, 50);

  // Notable signals from IPQS worth surfacing
  const signals = [];
  if (data.recently_registered) signals.push("Recently registered domain");
  if (data.short_link_redirect)  signals.push("URL shortener / redirect detected");
  if (data.parking)              signals.push("Domain appears to be parked");
  if (data.spamming)             signals.push("Domain associated with spam activity");

  return {
    source: "IPQualityScore",
    score: Math.min(score, 100),
    phishing:  data.phishing,
    malware:   data.malware,
    riskScore: data.risk_score,
    signals,
    detail: signals.length > 0 ? signals.join("; ") : `Risk score: ${data.risk_score}`,
  };
}


// ============================================================
//  BACKEND PROXY (production mode)
// ============================================================

async function queryBackend(url) {
  const res = await fetch(`${CONFIG.BACKEND_URL}/api/check`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  });
  if (!res.ok) throw new Error(`Backend error: ${res.status}`);
  return res.json();
}


// ============================================================
//  SCORE AGGREGATOR
// ============================================================

function aggregateScore(results) {
  const weights = CONFIG.SCORE_WEIGHTS;
  let totalWeight = 0;
  let weightedSum = 0;
  const sourceSummary = [];

  for (const [key, result] of Object.entries(results)) {
    if (!result || result.score === undefined) continue;
    const w = weights[key] || 0;
    weightedSum += result.score * w;
    totalWeight += w;
    sourceSummary.push({ source: result.source, score: result.score, detail: result.detail });
  }

  const finalScore = totalWeight > 0
    ? Math.round(weightedSum / totalWeight)
    : 0;

  return {
    score:   finalScore,
    sources: sourceSummary,
    raw:     results,
  };
}
