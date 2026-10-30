// Phishing Shield service worker.
// Receives page features from the content script, asks the local API for a
// verdict, caches it per tab and redirects to the warning page on phishing.

const API_URL = "http://localhost:8000/predict";
const CACHE_KEY = "scanCache";
const ALLOW_KEY = "allowedHosts";

// chrome.storage.session survives the service worker going to sleep.
async function getStore(key, fallback) {
  const data = await chrome.storage.session.get(key);
  return data[key] ?? fallback;
}
async function setStore(key, value) {
  await chrome.storage.session.set({ [key]: value });
}

function hostOf(url) {
  try {
    return new URL(url).hostname;
  } catch (e) {
    return null;
  }
}

async function callApi(url, pageFeatures) {
  const response = await fetch(API_URL, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url, page_features: pageFeatures || null }),
  });
  if (!response.ok) throw new Error(`API returned ${response.status}`);
  return response.json();
}

// Used when the API is not running: a few transparent rules, clearly labelled.
function offlineVerdict(url, page) {
  const cues = [];
  let score = 0;
  const parsed = new URL(url);
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(parsed.hostname)) { score += 0.35; cues.push("The address uses a raw IP instead of a domain name"); }
  if (parsed.hostname.split(".").length > 4) { score += 0.2; cues.push("Unusually many subdomains"); }
  if (url.includes("@")) { score += 0.25; cues.push("The URL contains '@', which hides the real destination"); }
  const hints = ["login", "signin", "verify", "account", "update", "secure", "banking"].filter((k) => url.toLowerCase().includes(k));
  if (hints.length >= 2) { score += 0.2; cues.push("Several login or account keywords in the URL"); }
  if (page && page.login_form && parsed.protocol !== "https:") { score += 0.35; cues.unshift("Password form on a page without HTTPS"); }
  const probability = Math.min(0.95, score);
  return {
    status: probability >= 0.7 ? "phishing" : probability >= 0.5 ? "suspicious" : "legitimate",
    probability,
    model_used: "Offline rules (API not reachable)",
    cues,
    features_summary: {},
  };
}

async function scan(url, pageFeatures) {
  try {
    return await callApi(url, pageFeatures);
  } catch (e) {
    console.warn("Phishing Shield: API unreachable, using offline rules.", e);
    return offlineVerdict(url, pageFeatures);
  }
}

async function analyseTab(tabId, url, pageFeatures) {
  const host = hostOf(url);
  if (!host) return null;
  const allowed = await getStore(ALLOW_KEY, []);
  if (allowed.includes(host)) return { status: "allowed", url };

  const result = { ...(await scan(url, pageFeatures)), url, scannedAt: Date.now() };
  const cache = await getStore(CACHE_KEY, {});
  cache[tabId] = result;
  await setStore(CACHE_KEY, cache);
  updateBadge(tabId, result.status);

  if (result.status === "phishing") {
    const warning = chrome.runtime.getURL(`warning.html?tab=${tabId}&url=${encodeURIComponent(url)}`);
    chrome.tabs.update(tabId, { url: warning });
  }
  return result;
}

function updateBadge(tabId, status) {
  const styles = {
    phishing: { text: "!", color: "#E5484D" },
    suspicious: { text: "?", color: "#F5A524" },
    legitimate: { text: "", color: "#30A46C" },
  };
  const style = styles[status] || styles.legitimate;
  chrome.action.setBadgeText({ tabId, text: style.text });
  chrome.action.setBadgeBackgroundColor({ tabId, color: style.color });
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === "page_features" && sender.tab) {
    analyseTab(sender.tab.id, sender.tab.url, message.features);
    sendResponse({ ok: true });
    return false;
  }

  if (message.action === "get_result") {
    (async () => {
      const cache = await getStore(CACHE_KEY, {});
      const cached = cache[message.tabId];
      if (cached && cached.url === message.url) {
        sendResponse(cached);
      } else {
        // Page not scanned yet (for example opened before the extension was installed).
        sendResponse(await analyseTab(message.tabId, message.url, null));
      }
    })();
    return true;
  }

  if (message.action === "rescan") {
    analyseTab(message.tabId, message.url, null).then(sendResponse);
    return true;
  }

  if (message.action === "get_warning_details") {
    getStore(CACHE_KEY, {}).then((cache) => sendResponse(cache[message.tabId] || null));
    return true;
  }

  if (message.action === "allow_host") {
    (async () => {
      const host = hostOf(message.url);
      const allowed = await getStore(ALLOW_KEY, []);
      if (host && !allowed.includes(host)) allowed.push(host);
      await setStore(ALLOW_KEY, allowed);
      if (sender.tab) chrome.tabs.update(sender.tab.id, { url: message.url });
      sendResponse({ ok: true });
    })();
    return true;
  }
  return false;
});

chrome.tabs.onRemoved.addListener(async (tabId) => {
  const cache = await getStore(CACHE_KEY, {});
  delete cache[tabId];
  await setStore(CACHE_KEY, cache);
});
