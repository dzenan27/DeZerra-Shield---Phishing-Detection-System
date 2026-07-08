// ============================================================
//  URL_HEURISTICS.JS — Local phishing signal detection
//
//  CYBER CONCEPT: Heuristics are pattern-based rules that flag
//  suspicious behavior WITHOUT needing an external API. They're
//  fast (run in <1ms), offline-capable, and catch threats that
//  haven't hit threat intel feeds yet (zero-day phishing).
// ============================================================

const SUSPICIOUS_TLDS = new Set([
  ".tk", ".ml", ".ga", ".cf", ".gq",  // Free Freenom TLDs, massively abused
  ".xyz", ".top", ".click", ".link",   // Cheap TLDs popular with spammers
  ".zip", ".mov",                       // Google TLDs that look like file extensions
  ".ru", ".cn",                         // High phishing volume (not blocking, just flagging)
]);

// -- Legitimate brands commonly spoofed ---------------------

const TARGET_BRANDS = [
  "paypal", "microsoft", "google", "apple", "amazon",
  "netflix", "facebook", "instagram", "twitter", "linkedin",
  "bank", "chase", "wellsfargo", "citibank", "irs", "usps",
  "fedex", "ups", "dhl",
];

// -- Homoglyph map ------------------------------------------

const HOMOGLYPHS = {
  "0": "o", "1": "l", "3": "e", "4": "a",
  "5": "s", "6": "g", "7": "t", "8": "b", "@": "a",
};


// ============================================================
//  MAIN EXPORT — analyzeURL(url) → { score, signals }
// ============================================================

export function analyzeURL(rawUrl) {
  const signals = [];
  let score = 0;

  let parsed;
  try {
    parsed = new URL(rawUrl);
  } catch {
    // Unparseable URL — itself suspicious
    return { score: 30, signals: ["URL could not be parsed"] };
  }

  const hostname = parsed.hostname.toLowerCase();
  const fullUrl  = rawUrl.toLowerCase();

  // ── Check 1: HTTPS ──────────────────────────────────────
 
  if (parsed.protocol === "http:") {
    score += 20;
    signals.push("No HTTPS — connection is unencrypted");
  }

  // ── Check 2: Suspicious TLD ─────────────────────────────
  const tld = "." + hostname.split(".").slice(-1)[0];
  if (SUSPICIOUS_TLDS.has(tld)) {
    score += 15;
    signals.push(`Suspicious TLD: ${tld} (high phishing abuse rate)`);
  }

  // ── Check 3: Brand impersonation in domain ───────────────
 
  const registrableDomain = getRegistrableDomain(hostname);
  for (const brand of TARGET_BRANDS) {
    if (fullUrl.includes(brand) && !registrableDomain.includes(brand)) {
      score += 25;
      signals.push(`Brand "${brand}" appears in URL but not the actual domain`);
      break;
    }
  }

  // ── Check 4: Homoglyph / character substitution ─────────
  const normalized = normalizeHomoglyphs(hostname);
  for (const brand of TARGET_BRANDS) {
    if (normalized.includes(brand) && !hostname.includes(brand)) {
      score += 30;
      signals.push(`Homoglyph substitution detected — "${hostname}" resembles "${brand}"`);
      break;
    }
  }

  // ── Check 5: Excessive subdomains ───────────────────────
  
  const labelCount = hostname.split(".").length;
  if (labelCount >= 5) {
    score += 15;
    signals.push(`Excessive subdomains (${labelCount} labels) — common in phishing URLs`);
  }

  // ── Check 6: URL entropy / randomness ───────────────────

  const entropy = shannonEntropy(registrableDomain.split(".")[0]);
  if (entropy > 3.8) {
    score += 20;
    signals.push(`High domain entropy (${entropy.toFixed(2)}) — may be algorithmically generated`);
  }

  // ── Check 7: IP address as hostname ─────────────────────
  
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 35;
    signals.push("URL uses a raw IP address instead of a domain name");
  }

  // ── Check 8: Credential keywords in URL path ────────────
  
  const credentialKeywords = ["login", "signin", "verify", "account", "secure", "update", "confirm", "password", "credential"];
  const pathMatches = credentialKeywords.filter(k => parsed.pathname.includes(k));
  if (pathMatches.length >= 2) {
    score += 10;
    signals.push(`Credential-related keywords in path: ${pathMatches.join(", ")}`);
  }

  // ── Check 9: URL length ──────────────────────────────────
  
  if (rawUrl.length > 150) {
    score += 10;
    signals.push(`Unusually long URL (${rawUrl.length} chars) — may embed redirect or tracking data`);
  }

  // Cap at 100
  score = Math.min(score, 100);

  return {
    score,
    signals,
    meta: { hostname, registrableDomain, labelCount, entropy: shannonEntropy(registrableDomain) }
  };
}


// ============================================================
//  HELPER FUNCTIONS
// ============================================================


function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  return Object.values(freq).reduce((e, count) => {
    const p = count / str.length;
    return e - p * Math.log2(p);
  }, 0);
}


function normalizeHomoglyphs(str) {
 
  const normalized = str.normalize("NFKD").replace(/[^\x00-\x7F]/g, "");

  return normalized.replace(/[013456780@]/g, ch => HOMOGLYPHS[ch] || ch);
}


function getRegistrableDomain(hostname) {
  const parts = hostname.split(".");
  if (parts.length < 2) return hostname;
  return parts.slice(-2).join(".");
}
