// ============================================================
//  CONFIG.JS — Central configuration for DeZerra Shield
//  
//  SECURITY NOTE FOR YOUR PORTFOLIO:
//  In production, API keys must NEVER be stored in extension
//  code — they ship to every user's machine. The correct
//  approach is a backend proxy (see backend/ folder) that
//  holds keys server-side. This config is for local dev only.
// ============================================================

export const CONFIG = {

  // API Keys (replace with your own, see README) 
  GOOGLE_SAFE_BROWSING_KEY: "",
  VIRUSTOTAL_KEY:           "",
  URLSCAN_KEY:              "",
  IPQUALITYSCORE_KEY:       "",

  // -- Backend proxy (Phase 2 of build) 
  // Once you deploy your backend, point this here and
  // remove the API keys above. The backend holds the keys.
  BACKEND_URL: null, // e.g. "https://dezerra-shield.fly.dev"

  // -- Threat score thresholds 
  // Score is 0–100. These thresholds control what the user sees.
  THRESHOLDS: {
    BLOCK:  80,  // Full block page — high confidence phishing
    WARN:   40,  // Warning banner — suspicious but not confirmed
    SAFE:   20,  // Silent pass — clear
  },

  // How much each source contributes to the final score.
  // CYBER CONCEPT: Weighted scoring lets you tune false positive
  // rates. GSB is highly trusted (Google's data), so it gets
  // the most weight. Local heuristics are fast but imprecise.
  SCORE_WEIGHTS: {
    google_safe_browsing: 0.40,  // Most trusted — block-listed by Google
    virustotal:           0.30,  // Multi-AV consensus
    ipqualityscore:       0.20,  // Dedicated fraud/phishing score
    local_heuristics:     0.10,  // Our own checks — fast, offline
  },

  // Cache TTL (time-to-live) in milliseconds 
  // CYBER CONCEPT: Caching reduces API calls and latency,
  // but stale cache is a risk — a URL could be weaponized
  // after you cached a "clean" result. 10 minutes is a
  // reasonable balance for browsing sessions.
  CACHE_TTL_MS: 10 * 60 * 1000, // 10 minutes

  // Domains to never scan (too much noise) 
  ALLOWLIST: [
    "google.com", "microsoft.com", "github.com",
    "apple.com", "amazon.com", "cloudflare.com",
    "localhost", "127.0.0.1"
  ],
};
