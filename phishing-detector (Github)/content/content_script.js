// ============================================================
//  CONTENT_SCRIPT.JS — Page-level injector
//
//  This script does two things:
//  1. Listens for verdicts from the service worker
//  2. Injects UI (banner or block page) using Shadow DOM
//     so the host page's CSS cannot interfere
// ============================================================

chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type !== "DEZERRA_VERDICT") return;

  if (msg.verdict === "blocked") {
    showBlockPage(msg);
  } else if (msg.verdict === "warned") {
    showWarningBanner(msg);
  }
});


// ============================================================
//  BLOCK PAGE — full-page takeover for high-confidence threats
//  CYBER CONCEPT: Chrome's own Safe Browsing uses a full-page
//  interstitial for the same reason — a dismissible banner
//  is too easy to ignore when the risk is high.
// ============================================================

function showBlockPage(data) {
  // Freeze the page from loading further content
  window.stop();

  const overlay = document.createElement("div");
  overlay.id = "dezerra-block-overlay";
  Object.assign(overlay.style, {
    position: "fixed",
    inset: "0",
    zIndex: "2147483647",
    background: "#0f172a",
    display: "flex",
    alignItems: "center",
    justifyContent: "center",
    fontFamily: "system-ui, sans-serif",
  });

  const shadow = overlay.attachShadow({ mode: "closed" });
  shadow.innerHTML = `
    <style>
      * { box-sizing: border-box; margin: 0; padding: 0; }
      :host { all: initial; }
      .page {
        display: flex; flex-direction: column; align-items: center;
        justify-content: center; padding: 2rem;
        min-height: 100vh; background: #0f172a; color: #f1f5f9;
        font-family: system-ui, -apple-system, sans-serif;
      }
      .icon { font-size: 64px; margin-bottom: 1.5rem; }
      .title {
        font-size: 28px; font-weight: 700; color: #ef4444;
        margin-bottom: 0.75rem; text-align: center;
      }
      .subtitle {
        font-size: 16px; color: #94a3b8; text-align: center;
        max-width: 480px; line-height: 1.6; margin-bottom: 2rem;
      }
      .score-badge {
        display: inline-flex; align-items: center; gap: 8px;
        background: #1e293b; border: 1px solid #ef4444;
        padding: 8px 16px; border-radius: 8px;
        font-size: 14px; color: #ef4444; font-weight: 600;
        margin-bottom: 2rem;
      }
      .signals {
        background: #1e293b; border: 1px solid #334155;
        border-radius: 10px; padding: 1.25rem 1.5rem;
        max-width: 520px; width: 100%; margin-bottom: 2rem;
      }
      .signals-title {
        font-size: 12px; font-weight: 600; color: #64748b;
        text-transform: uppercase; letter-spacing: 0.05em;
        margin-bottom: 0.75rem;
      }
      .signal-item {
        display: flex; align-items: flex-start; gap: 8px;
        font-size: 13px; color: #cbd5e1; padding: 4px 0;
        line-height: 1.5;
      }
      .signal-dot { color: #ef4444; margin-top: 2px; }
      .actions { display: flex; gap: 12px; flex-wrap: wrap; justify-content: center; }
      .btn {
        all: initial; font-family: system-ui, sans-serif;
        font-size: 14px; font-weight: 600;
        padding: 10px 24px; border-radius: 8px;
        cursor: pointer; transition: opacity 0.15s;
      }
      .btn:hover { opacity: 0.85; }
      .btn-leave   { background: #ef4444; color: #fff; }
      .btn-proceed {
        background: transparent; color: #64748b;
        border: 1px solid #334155; font-size: 13px;
      }
      .url-display {
        font-size: 12px; color: #475569; margin-bottom: 2rem;
        max-width: 480px; word-break: break-all; text-align: center;
        background: #1e293b; padding: 8px 12px; border-radius: 6px;
      }
    </style>
    <div class="page">
      <div class="icon">🛡️</div>
      <div class="title">Phishing site blocked</div>
      <div class="subtitle">
        DeZerra Shield has blocked this page because it shows strong indicators 
        of being a phishing or malware site designed to steal your information.
      </div>
      <div class="score-badge">
        ⚠ Threat score: ${data.score}/100
      </div>
      <div class="url-display">${escapeHtml(data.url)}</div>
      ${data.signals && data.signals.length ? `
        <div class="signals">
          <div class="signals-title">Detection signals</div>
          ${data.signals.map(s => `
            <div class="signal-item">
              <span class="signal-dot">›</span>
              <span>${escapeHtml(s)}</span>
            </div>
          `).join("")}
        </div>
      ` : ""}
      <div class="actions">
        <button class="btn btn-leave" id="leave-btn">← Go back to safety</button>
        <button class="btn btn-proceed" id="proceed-btn">Proceed anyway (unsafe)</button>
      </div>
    </div>
  `;

  document.documentElement.innerHTML = "";
  document.documentElement.appendChild(overlay);

  shadow.getElementById("leave-btn").addEventListener("click", () => {
    history.back();
    setTimeout(() => { window.location.href = "about:newtab"; }, 300);
  });

  shadow.getElementById("proceed-btn").addEventListener("click", () => {
    overlay.remove();
    window.location.reload();
  });
}


// ============================================================
//  WARNING BANNER — for medium-confidence threats
//  Uses Shadow DOM for full style isolation
// ============================================================

function showWarningBanner(data) {
  if (document.getElementById("dezerra-warning-host")) return;

  const host = document.createElement("div");
  host.id = "dezerra-warning-host";
  Object.assign(host.style, {
    position: "fixed",
    top: "0",
    left: "0",
    width: "100%",
    zIndex: "2147483647",
    pointerEvents: "none",
  });

  const shadow = host.attachShadow({ mode: "closed" });
  shadow.innerHTML = `
    <style>
      * { box-sizing: border-box; }
      :host { all: initial; }
      .banner {
        all: initial; display: flex; align-items: center;
        justify-content: space-between; flex-wrap: wrap; gap: 10px;
        padding: 10px 16px;
        background: linear-gradient(135deg, #92400e, #b45309);
        color: #fef3c7;
        font-family: system-ui, -apple-system, sans-serif;
        font-size: 13px; line-height: 1.4;
        pointer-events: all;
        box-shadow: 0 2px 12px rgba(0,0,0,0.3);
        width: 100%;
      }
      .left { display: flex; align-items: center; gap: 10px; }
      .icon { font-size: 18px; }
      .score {
        background: rgba(0,0,0,0.25); padding: 2px 8px;
        border-radius: 12px; font-size: 11px; font-weight: 600;
        color: #fde68a; white-space: nowrap;
      }
      .label { font-weight: 600; color: #fef9c3; }
      .desc  { color: #fde68a; font-size: 12px; }
      .signals-toggle {
        font-size: 11px; color: #fde68a; cursor: pointer;
        text-decoration: underline; white-space: nowrap;
      }
      .actions { display: flex; gap: 8px; align-items: center; }
      .btn {
        all: initial; font-family: system-ui, sans-serif;
        font-size: 12px; font-weight: 600;
        padding: 5px 14px; border-radius: 6px;
        cursor: pointer; transition: opacity 0.15s;
        pointer-events: all;
      }
      .btn:hover { opacity: 0.85; }
      .btn-leave    { background: #fff; color: #92400e; }
      .btn-dismiss  {
        background: transparent; color: #fde68a;
        border: 1px solid rgba(255,255,255,0.3);
      }
      .signals-panel {
        background: #1c1007; border-top: 1px solid rgba(255,255,255,0.1);
        padding: 10px 16px; display: none; width: 100%;
      }
      .signals-panel.open { display: block; }
      .signal-item {
        font-size: 12px; color: #fde68a; padding: 2px 0;
        display: flex; gap: 6px;
      }
    </style>
    <div class="banner">
      <div class="left">
        <span class="icon">⚠️</span>
        <div>
          <span class="label">Suspicious page detected</span>
          <span class="score">Risk: ${data.score}/100</span>
          <div class="desc">This site shows signs of phishing or deception.
            ${data.signals?.length ? `<span class="signals-toggle" id="toggle-signals">View ${data.signals.length} signal${data.signals.length > 1 ? "s" : ""}</span>` : ""}
          </div>
        </div>
      </div>
      <div class="actions">
        <button class="btn btn-leave" id="banner-leave">Leave site</button>
        <button class="btn btn-dismiss" id="banner-dismiss">Dismiss</button>
      </div>
    </div>
    ${data.signals?.length ? `
      <div class="signals-panel" id="signals-panel">
        ${data.signals.map(s => `<div class="signal-item"><span>›</span><span>${escapeHtml(s)}</span></div>`).join("")}
      </div>
    ` : ""}
  `;

  document.documentElement.prepend(host);

  // Push page content down so banner doesn't overlap it
  const originalMargin = document.documentElement.style.marginTop;
  document.documentElement.style.marginTop = "52px";

  shadow.getElementById("banner-leave")?.addEventListener("click", () => {
    history.back();
  });

  shadow.getElementById("banner-dismiss")?.addEventListener("click", () => {
    host.remove();
    document.documentElement.style.marginTop = originalMargin;
  });

  shadow.getElementById("toggle-signals")?.addEventListener("click", () => {
    const panel = shadow.getElementById("signals-panel");
    panel?.classList.toggle("open");
  });

  // MutationObserver: re-inject if the page removes our banner
  // CYBER CONCEPT: Sophisticated phishing pages may try to remove
  // security warnings via JS. The observer catches this and re-injects.
  const observer = new MutationObserver(() => {
    if (!document.getElementById("dezerra-warning-host")) {
      document.documentElement.prepend(host);
    }
  });
  observer.observe(document.documentElement, { childList: true });
}


// Prevent XSS when displaying attacker-controlled URL content
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}
