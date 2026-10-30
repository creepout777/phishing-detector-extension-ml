// Phishing Shield popup: shows the verdict for the active tab.

const RING_LENGTH = 263.89;
const COLORS = {
  phishing: "var(--color-phish)",
  suspicious: "var(--color-warn)",
  legitimate: "var(--color-safe)",
  allowed: "var(--color-safe)",
};
const MESSAGES = {
  phishing: "This page looks like a phishing site.",
  suspicious: "Some signs of phishing. Be careful with passwords.",
  legitimate: "No phishing detected on this page.",
  allowed: "You chose to trust this site for this session.",
};

const $ = (id) => document.getElementById(id);
let activeTab = null;

document.querySelectorAll(".tab-btn").forEach((btn) =>
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.toggle("active", b === btn));
    document.querySelectorAll(".tab-pane").forEach((p) => p.classList.toggle("active", p.id === `tab-${btn.dataset.tab}`));
  })
);

function render(result) {
  if (!result) {
    $("status").textContent = "This page cannot be scanned.";
    $("model-badge").textContent = "Idle";
    return;
  }
  const status = result.status;
  const risk = Math.round((result.probability || 0) * 100);
  const color = COLORS[status] || "var(--color-scan)";

  $("ring").style.stroke = color;
  $("ring").style.strokeDashoffset = String(RING_LENGTH * (1 - risk / 100));
  $("score").textContent = status === "allowed" ? "-" : `${risk}%`;
  $("pulse").style.backgroundColor = color;
  $("status").textContent = MESSAGES[status] || "Scan complete.";
  $("model-badge").textContent = status === "allowed" ? "Allowed" : "Scanned";

  $("url").textContent = result.url || activeTab.url;
  $("url").title = result.url || activeTab.url;
  const verdict = $("verdict");
  verdict.textContent = status.charAt(0).toUpperCase() + status.slice(1);
  verdict.className = `badge ${status === "phishing" ? "danger" : status === "suspicious" ? "" : "safe"}`;
  const summary = result.features_summary || {};
  $("https").textContent = summary.https === undefined ? "-" : summary.https ? "HTTPS" : "Not encrypted";
  $("model").textContent = result.model_used || "-";

  const cues = result.cues || [];
  const list = $("cues");
  list.replaceChildren();
  if (cues.length === 0) {
    const empty = document.createElement("div");
    empty.className = "empty-cues-state";
    empty.innerHTML = '<span class="empty-icon">&#10003;</span><p>No warning signs found in the address or the page.</p>';
    list.appendChild(empty);
  } else {
    cues.forEach((cue) => {
      const item = document.createElement("div");
      item.className = `cue-item${status === "phishing" ? "" : " warn"}`;
      item.textContent = cue;
      list.appendChild(item);
    });
  }

  $("stat-length").textContent = summary.length_url ?? "-";
  $("stat-subdomains").textContent = summary.nb_subdomains ?? "-";
  $("stat-links").textContent = summary.nb_hyperlinks ?? "-";
  $("stat-login").textContent = summary.login_form === undefined ? "-" : summary.login_form ? "Yes" : "No";
}

function request(action) {
  $("status").textContent = "Analysing this page...";
  chrome.runtime.sendMessage({ action, tabId: activeTab.id, url: activeTab.url }, render);
}

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  activeTab = tabs[0];
  if (!activeTab || !/^https?:/.test(activeTab.url || "")) {
    render(null);
    return;
  }
  request("get_result");
});

$("rescan").addEventListener("click", () => activeTab && request("rescan"));
