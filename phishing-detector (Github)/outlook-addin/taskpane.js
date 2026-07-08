// ============================================================
//  TASKPANE.JS — Outlook add-in email scanner
//
//  Email authentication checks (SPF/DKIM/DMARC) are read from
//  the Internet Message Headers — the raw routing metadata that
//  accompanies every email through SMTP relay chains.
// ============================================================

const BACKEND_URL = null; // e.g. "https://dezerra-shield.fly.dev"

Office.onReady((info) => {
  if (info.host === Office.HostType.Outlook) {
    document.getElementById("scan-btn").addEventListener("click", scanEmail);
  }
});

// ============================================================
//  MAIN SCAN FUNCTION
// ============================================================

async function scanEmail() {
  const btn    = document.getElementById("scan-btn");
  const status = document.getElementById("status");

  btn.disabled = true;
  btn.textContent = "Scanning...";
  status.textContent = "Reading email headers and content...";

  try {
    const item = Office.context.mailbox.item;

    // ── Step 1: Collect email metadata ───────────────────────
    const emailData = await collectEmailData(item);
    status.textContent = "Analyzing headers and links...";

    // ── Step 2: Local email heuristics ───────────────────────
    const analysis = analyzeEmail(emailData);
    status.textContent = "Querying threat intelligence...";

    // ── Step 3: Query threat APIs for extracted links ─────────
    let linkResults = [];
    if (emailData.links.length > 0 && BACKEND_URL) {
      linkResults = await checkLinksViaBacked(emailData.links);
    }

    // ── Step 4: Render results ────────────────────────────────
    renderResult(analysis, emailData, linkResults);
    status.textContent = "";

  } catch (err) {
    status.textContent = `Error: ${err.message}`;
    console.error("[DeZerra Shield]", err);
  } finally {
    btn.disabled = false;
    btn.textContent = "Scan this email";
  }
}

// ============================================================
//  EMAIL DATA COLLECTION via Office.js
// ============================================================

function collectEmailData(item) {
  return new Promise((resolve, reject) => {
    // Get sender info
    const sender  = item.from?.emailAddress || "unknown";
    const subject = item.subject || "";
    const replyTo = item.replyTo?.map(r => r.emailAddress) || [];

    item.getAllInternetHeadersAsync((result) => {
      if (result.status === Office.AsyncResultStatus.Failed) {
        reject(new Error("Could not read email headers"));
        return;
      }

      const headers = result.value || "";

      // Parse authentication results from headers
      const auth = parseAuthHeaders(headers);

      // Get email body to extract links
      item.body.getAsync(Office.CoercionType.Text, (bodyResult) => {
        const bodyText = bodyResult.value || "";
        const links    = extractLinks(bodyText);

        // Also get HTML body for more thorough link extraction
        item.body.getAsync(Office.CoercionType.Html, (htmlResult) => {
          const htmlBody   = htmlResult.value || "";
          const htmlLinks  = extractLinks(htmlBody);

          // Merge and deduplicate
          const allLinks = [...new Set([...links, ...htmlLinks])];

          resolve({
            sender, subject, replyTo, headers, auth,
            links: allLinks.slice(0, 20), // Cap at 20 links
            bodyText: bodyText.slice(0, 2000),
          });
        });
      });
    });
  });
}

// ============================================================
//  EMAIL HEURISTIC ANALYSIS
// ============================================================

function analyzeEmail(data) {
  const signals = [];
  let score = 0;

  // Check 1: SPF / DKIM / DMARC 

  if (data.auth.spf === "fail") {
    score += 30;
    signals.push("SPF check FAILED — sending server not authorized for this domain");
  } else if (data.auth.spf === "softfail") {
    score += 15;
    signals.push("SPF softfail — sender may be spoofed");
  }

  if (data.auth.dkim === "fail") {
    score += 25;
    signals.push("DKIM signature FAILED — email may have been tampered with");
  }

  if (data.auth.dmarc === "fail") {
    score += 20;
    signals.push("DMARC check FAILED — domain policy violated");
  }

  // Check 2: Reply-To mismatch 
  
  if (data.replyTo.length > 0) {
    const senderDomain  = getDomain(data.sender);
    const replyDomains  = data.replyTo.map(getDomain);
    const mismatch      = replyDomains.some(d => d !== senderDomain);
    if (mismatch) {
      score += 25;
      signals.push(`Reply-To domain differs from sender domain — possible BEC`);
    }
  }

  //Check 3: Urgency language 
  
  const urgencyPatterns = [
    /urgent/i, /immediate(ly)?/i, /account (will be )?closed/i,
    /verify (your )?account/i, /suspended/i, /unusual (sign-in|activity)/i,
    /click (here|below|now)/i, /limited time/i, /act now/i,
  ];
  const bodySnippet = data.bodyText.toLowerCase();
  const urgencyHits = urgencyPatterns.filter(p => p.test(bodySnippet));
  if (urgencyHits.length >= 2) {
    score += 15;
    signals.push(`Urgency/manipulation language detected (${urgencyHits.length} patterns)`);
  }

  // ── Check 4: Suspicious link count 
  if (data.links.length === 0 && data.bodyText.length > 200) {
    // Some phishing emails use image-only content to avoid text scanning
    score += 10;
    signals.push("No text links found — possible image-only phishing email");
  }

  // Check 5: Credential keywords in subject
  const credSubject = /password|verify|account|login|confirm|security alert/i;
  if (credSubject.test(data.subject)) {
    score += 10;
    signals.push("Subject line contains credential/security keywords");
  }

  const verdict = score >= 70 ? "blocked"
                : score >= 30 ? "warned"
                : "safe";

  return { score: Math.min(score, 100), signals, verdict };
}

// ============================================================
//  RENDER RESULTS
// ============================================================

function renderResult(analysis, emailData, linkResults) {
  const card       = document.getElementById("result-card");
  const icon       = document.getElementById("result-icon");
  const title      = document.getElementById("result-title");
  const desc       = document.getElementById("result-desc");
  const details    = document.getElementById("details");
  const linksSection = document.getElementById("links-section");
  const linksList  = document.getElementById("links-list");

  card.style.display = "block";
  card.className     = `result-card ${analysis.verdict}`;

  const verdictMap = {
    safe:    ["✓",  "Email looks safe",        "No significant phishing indicators detected."],
    warned:  ["⚠️", "Suspicious email",         "This email shows phishing indicators. Do not click links or enter credentials."],
    blocked: ["🚫", "High-risk phishing email", "Strong phishing signals detected. Do not interact with this email."],
  };
  const [ico, ttl, dsc] = verdictMap[analysis.verdict];
  icon.textContent       = ico;
  title.textContent      = ttl;
  title.className        = `result-title ${analysis.verdict}`;
  desc.textContent       = dsc;

  // Detail rows
  details.innerHTML = `
    <div class="detail-row"><span class="detail-label">Threat score</span><span class="detail-value">${analysis.score}/100</span></div>
    <div class="detail-row"><span class="detail-label">Sender</span><span class="detail-value">${escapeHtml(emailData.sender)}</span></div>
    <div class="detail-row"><span class="detail-label">SPF</span><span class="detail-value">${emailData.auth.spf || "not found"}</span></div>
    <div class="detail-row"><span class="detail-label">DKIM</span><span class="detail-value">${emailData.auth.dkim || "not found"}</span></div>
    <div class="detail-row"><span class="detail-label">DMARC</span><span class="detail-value">${emailData.auth.dmarc || "not found"}</span></div>
    ${analysis.signals.map(s => `<div class="detail-row"><span class="detail-label">Signal</span><span class="detail-value" style="color:#f59e0b">${escapeHtml(s)}</span></div>`).join("")}
  `;

  // Links
  if (emailData.links.length > 0) {
    linksSection.style.display = "block";
    linksList.innerHTML = emailData.links.map(link => {
      const linkResult = linkResults.find(r => r.url === link);
      const suspicious = linkResult && linkResult.score >= 40;
      return `<div class="link-item ${suspicious ? "suspicious" : ""}">${suspicious ? "⚠ " : ""}${escapeHtml(link)}</div>`;
    }).join("");
  }
}

// ============================================================
//  HELPERS
// ============================================================

// Parse SPF/DKIM/DMARC results from raw email headers
function parseAuthHeaders(headers) {
  const auth = { spf: null, dkim: null, dmarc: null };

  const authHeader = headers.match(/Authentication-Results:[\s\S]*?(?=\r?\n\S|\r?\n\r?\n|$)/i)?.[0] || "";

  const spfMatch   = authHeader.match(/spf=(\w+)/i);
  const dkimMatch  = authHeader.match(/dkim=(\w+)/i);
  const dmarcMatch = authHeader.match(/dmarc=(\w+)/i);

  if (spfMatch)   auth.spf   = spfMatch[1].toLowerCase();
  if (dkimMatch)  auth.dkim  = dkimMatch[1].toLowerCase();
  if (dmarcMatch) auth.dmarc = dmarcMatch[1].toLowerCase();

  return auth;
}

// Extract URLs from text or HTML
function extractLinks(text) {
  const urlPattern = /https?:\/\/[^\s"'<>)]+/g;
  return [...new Set(text.match(urlPattern) || [])];
}

function getDomain(email) {
  return email.split("@")[1]?.toLowerCase() || "";
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}

async function checkLinksViaBacked(links) {
  if (!BACKEND_URL) return [];
  try {
    const res = await fetch(`${BACKEND_URL}/api/check-links`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ urls: links }),
    });
    return res.ok ? res.json() : [];
  } catch { return []; }
}
