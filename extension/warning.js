// Warning page shown instead of a page classified as phishing.

document.addEventListener("DOMContentLoaded", () => {
  const params = new URLSearchParams(window.location.search);
  const blockedUrl = params.get("url");
  const tabId = Number(params.get("tab"));
  const list = document.getElementById("threats-list");

  document.getElementById("blocked-url").textContent = blockedUrl || "Unknown address";

  function renderCues(result) {
    const cues = (result && result.cues && result.cues.length)
      ? result.cues
      : ["The model rated this page as very likely to be phishing."];
    list.replaceChildren();
    if (result && typeof result.probability === "number") {
      const li = document.createElement("li");
      li.textContent = `Phishing risk: ${Math.round(result.probability * 100)}% (${result.model_used})`;
      list.appendChild(li);
    }
    cues.forEach((cue) => {
      const li = document.createElement("li");
      li.textContent = cue;
      list.appendChild(li);
    });
  }

  chrome.runtime.sendMessage({ action: "get_warning_details", tabId }, renderCues);

  document.getElementById("back-btn").addEventListener("click", () => {
    // History holds the phishing page itself, so go back twice when possible.
    if (window.history.length > 2) window.history.go(-2);
    else window.location.href = "https://www.google.com/";
  });

  document.getElementById("bypass-btn").addEventListener("click", () => {
    if (blockedUrl) chrome.runtime.sendMessage({ action: "allow_host", url: blockedUrl });
  });
});
