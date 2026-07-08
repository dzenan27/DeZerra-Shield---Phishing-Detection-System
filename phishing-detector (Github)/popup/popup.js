// popup.js — Renders the current tab's threat result in the popup

document.addEventListener("DOMContentLoaded", async () => {
  // Ask the background service worker for this tab's result
  chrome.runtime.sendMessage({ type: "GET_CURRENT_RESULT" }, (result) => {
    render(result);
  });

  document.getElementById("log-link").addEventListener("click", (e) => {
    e.preventDefault();
    chrome.tabs.create({ url: chrome.runtime.getURL("popup/log.html") });
  });
});

function render(result) {
  const ring    = document.getElementById("score-ring");
  const scoreEl = document.getElementById("score-number");
  const title   = document.getElementById("verdict-title");
  const desc    = document.getElementById("verdict-desc");
  const urlBar  = document.getElementById("url-bar");

  if (!result) {
    title.textContent = "No data yet";
    title.className   = "verdict-title";
    desc.textContent  = "Navigate to a page to start scanning.";
    return;
  }

  // Score ring
  scoreEl.textContent = result.score;
  ring.className = `score-ring ${result.verdict}`;
  title.className = `verdict-title ${result.verdict}`;

  // URL
  urlBar.textContent = result.url || "Unknown URL";
  urlBar.title       = result.url || "";

  // Verdict text
  const verdictMap = {
    safe:    ["Page looks safe",       "No phishing signals detected on this page."],
    warned:  ["Suspicious page",       "This page shows signs of deception. Proceed with caution."],
    blocked: ["Phishing site blocked", "High-confidence phishing or malware site. Do not enter credentials."],
  };
  const [t, d] = verdictMap[result.verdict] || ["Unknown", ""];
  title.textContent = t;
  desc.textContent  = d;

  // Signals
  if (result.signals?.length) {
    const section = document.getElementById("signals-section");
    const list    = document.getElementById("signals-list");
    section.style.display = "block";
    list.innerHTML = result.signals.map(s => `
      <div class="signal-item">
        <span class="signal-dot">›</span>
        <span>${escapeHtml(s)}</span>
      </div>
    `).join("");
  }

  // API sources
  if (result.sources?.length) {
    const section = document.getElementById("sources-section");
    const list    = document.getElementById("sources-list");
    section.style.display = "block";
    list.innerHTML = result.sources.map(s => {
      const level = s.score >= 60 ? "high" : s.score >= 30 ? "med" : "low";
      return `
        <div class="source-item">
          <span class="source-name">${escapeHtml(s.source)}</span>
          <span class="source-score ${level}">${s.score}/100</span>
        </div>
      `;
    }).join("");
  }
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;").replace(/</g, "&lt;")
    .replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
