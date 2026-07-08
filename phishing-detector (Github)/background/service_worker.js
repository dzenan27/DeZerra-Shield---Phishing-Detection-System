// ============================================================
//  SERVICE_WORKER.JS — Extension brain / orchestrator
// ============================================================

import { CONFIG }       from "./config.js";
import { queryAllAPIs } from "./api_detection.js";
import { analyzeURL }   from "../heuristics/url_heuristics.js";

// In-memory cache for this session (lost on service worker restart)
// chrome.storage.session is the persistent equivalent
const sessionCache = new Map();

// ============================================================
//  NAVIGATION LISTENER — fires on every committed navigation
// ============================================================

chrome.webNavigation.onCommitted.addListener(async ({ tabId, url, frameId }) => {
  // Only check top-level frames (frameId 0 = main page)
  // Iframes are secondary targets — reduce noise for now
  if (frameId !== 0) return;
  if (!url || !url.startsWith("http")) return;

  await evaluateUrl(tabId, url);
});

// ============================================================
//  SPA / HISTORY API LISTENER
// ============================================================

chrome.webNavigation.onHistoryStateUpdated.addListener(async ({ tabId, url, frameId }) => {
  if (frameId !== 0) return;
  if (!url || !url.startsWith("http")) return;
  await evaluateUrl(tabId, url);
});

// ============================================================
//  CORE EVALUATION PIPELINE
// ============================================================

async function evaluateUrl(tabId, url) {
  if (isAllowlisted(url)) {
    storeThreatResult(tabId, url, { score: 0, verdict: "safe", sources: [], signals: [] });
    return;
  }

  const cached = getFromCache(url);
  if (cached) {
    applyVerdict(tabId, url, cached);
    return;
  }

  // Run local heuristics first — instant, no API call needed
  
  const heuristics = analyzeURL(url);

  // If local score is already very high, act immediately
  //    while API calls run in the background
  if (heuristics.score >= CONFIG.THRESHOLDS.BLOCK) {
    const earlyResult = buildResult(url, heuristics.score, [], heuristics.signals, "blocked");
    applyVerdict(tabId, url, earlyResult);
    cacheResult(url, earlyResult);
    // Still kick off API calls to confirm and log
    confirmWithAPIs(tabId, url, heuristics);
    return;
  }

  // Query all external APIs in parallel
  let apiResult = { score: 0, sources: [] };
  try {
    apiResult = await queryAllAPIs(url);
  } catch (err) {
    console.warn("[DeZerra Shield] API query failed, using local heuristics only:", err);
  }

  // Combine heuristic and API scores
  //    Local heuristics = 10% weight, APIs = 90%
  const combinedScore = Math.round(
    apiResult.score * CONFIG.SCORE_WEIGHTS.google_safe_browsing +
    apiResult.score * CONFIG.SCORE_WEIGHTS.virustotal +
    apiResult.score * CONFIG.SCORE_WEIGHTS.ipqualityscore +
    heuristics.score * CONFIG.SCORE_WEIGHTS.local_heuristics
  );

  const finalScore = Math.min(combinedScore, 100);
  const verdict    = scoreToVerdict(finalScore);
  const result     = buildResult(url, finalScore, apiResult.sources || [], heuristics.signals, verdict);

  // Cache, store, and act
  cacheResult(url, result);
  storeThreatResult(tabId, url, result);
  applyVerdict(tabId, url, result);
}

// ============================================================
//  CONFIRM WITH APIS (runs after early block for logging)
// ============================================================

async function confirmWithAPIs(tabId, url, heuristics) {
  try {
    const apiResult = await queryAllAPIs(url);
    const result    = buildResult(url, Math.max(heuristics.score, apiResult.score), apiResult.sources || [], heuristics.signals, "blocked");
    storeThreatResult(tabId, url, result);
  } catch (_) { /* silent */ }
}

// ============================================================
//  VERDICT APPLICATION — tells content script what to show
// ============================================================

function applyVerdict(tabId, url, result) {
  if (result.verdict === "safe") return;

  chrome.tabs.sendMessage(tabId, {
    type:    "DEZERRA_VERDICT",
    verdict: result.verdict,
    score:   result.score,
    url,
    signals: result.signals,
    sources: result.sources,
  }).catch(() => {
    // Tab may not have a content script loaded yet — retry once
    setTimeout(() => {
      chrome.tabs.sendMessage(tabId, {
        type:    "DEZERRA_VERDICT",
        verdict: result.verdict,
        score:   result.score,
        url,
        signals: result.signals,
        sources: result.sources,
      }).catch(() => {});
    }, 500);
  });
}

// ============================================================
//  POPUP MESSAGE HANDLER
//  The popup asks the background for the current tab's result
// ============================================================

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "GET_CURRENT_RESULT") {
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (!tab) return sendResponse(null);
      chrome.storage.session.get(`result:${tab.id}`, (data) => {
        sendResponse(data[`result:${tab.id}`] || null);
      });
    });
    return true; // async response
  }
});

// ============================================================
//  HELPERS
// ============================================================

function scoreToVerdict(score) {
  if (score >= CONFIG.THRESHOLDS.BLOCK) return "blocked";
  if (score >= CONFIG.THRESHOLDS.WARN)  return "warned";
  return "safe";
}

function buildResult(url, score, sources, signals, verdict) {
  return { url, score, sources, signals, verdict, timestamp: Date.now() };
}

function isAllowlisted(url) {
  try {
    const hostname = new URL(url).hostname;
    return CONFIG.ALLOWLIST.some(d => hostname === d || hostname.endsWith("." + d));
  } catch { return false; }
}

function getFromCache(url) {
  const entry = sessionCache.get(url);
  if (!entry) return null;
  if (Date.now() - entry.timestamp > CONFIG.CACHE_TTL_MS) {
    sessionCache.delete(url);
    return null;
  }
  return entry;
}

function cacheResult(url, result) {
  sessionCache.set(url, result);
}

function storeThreatResult(tabId, url, result) {
  chrome.storage.session.set({ [`result:${tabId}`]: result });
  // If it's a threat, also log to the persistent threat log
  if (result.verdict !== "safe") {
    logThreat(result);
  }
}

async function logThreat(result) {
  const log = await chrome.storage.local.get("threatLog");
  const entries = log.threatLog || [];
  entries.unshift({
    url:      result.url,
    score:    result.score,
    verdict:  result.verdict,
    signals:  result.signals,
    time:     new Date().toISOString(),
  });
  // Keep last 500 events
  await chrome.storage.local.set({ threatLog: entries.slice(0, 500) });
}
