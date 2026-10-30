// Phishing Shield content script.
// Reads the structure of the page once it has loaded and sends it to the
// background service worker. Nothing leaves the browser except these numbers
// and the page URL, which go to the local API on localhost.
//
// Definitions follow the dataset used for training (Hannousse & Yahiouche, 2021):
// link and media ratios marked "percent" are 0-100, the hyperlink ratios are 0-1,
// and domain_in_title / domain_with_copyright are 1 when the domain is MISSING.

(() => {
  const host = window.location.hostname.toLowerCase();
  const domainKeyword = (() => {
    const parts = host.replace(/^www\./, "").split(".");
    return parts.length >= 2 ? parts[parts.length - 2] : parts[0];
  })();

  function classify(raw) {
    if (raw === null || raw === undefined) return "none";
    const href = raw.trim().toLowerCase();
    if (href === "" || href.startsWith("#") || href.startsWith("javascript:") || href.startsWith("mailto:")) return "null";
    try {
      const url = new URL(raw, window.location.href);
      if (!["http:", "https:"].includes(url.protocol)) return "other";
      return url.hostname.toLowerCase() === host ? "internal" : "external";
    } catch (e) {
      return "null";
    }
  }

  const pct = (part, total, empty = 0) => (total > 0 ? (100 * part) / total : empty);
  const ratio = (part, total) => (total > 0 ? part / total : 0);

  function extractFeatures() {
    const f = {};

    // Hyperlinks
    const anchors = Array.from(document.querySelectorAll("a"));
    const kinds = anchors.map((a) => classify(a.getAttribute("href")));
    const internal = kinds.filter((k) => k === "internal").length;
    const external = kinds.filter((k) => k === "external").length;
    const unsafe = kinds.filter((k) => k === "null").length;
    f.nb_hyperlinks = anchors.length;
    f.ratio_intHyperlinks = ratio(internal, anchors.length);
    f.ratio_extHyperlinks = ratio(external, anchors.length);
    f.safe_anchor = pct(unsafe, anchors.length); // share of "#" / javascript: anchors, percent

    // Stylesheets and favicon
    const links = Array.from(document.querySelectorAll("link"));
    f.nb_extCSS = links.filter(
      (l) => (l.getAttribute("rel") || "").toLowerCase().includes("stylesheet") && classify(l.getAttribute("href")) === "external"
    ).length;
    const favicon = links.find((l) => (l.getAttribute("rel") || "").toLowerCase().includes("icon"));
    f.external_favicon = favicon && classify(favicon.getAttribute("href")) === "external" ? 1 : 0;

    // Resources referenced from <link> and <script>, percent internal
    const tagRefs = [
      ...links.map((l) => l.getAttribute("href")),
      ...Array.from(document.querySelectorAll("script[src]")).map((s) => s.getAttribute("src")),
    ].map(classify).filter((k) => k === "internal" || k === "external");
    f.links_in_tags = pct(tagRefs.filter((k) => k === "internal").length, tagRefs.length);

    // Media, percent internal / external
    const media = Array.from(document.querySelectorAll("img[src], video[src], audio[src], source[src]"))
      .map((m) => classify(m.getAttribute("src")))
      .filter((k) => k === "internal" || k === "external");
    f.ratio_intMedia = pct(media.filter((k) => k === "internal").length, media.length);
    f.ratio_extMedia = pct(media.filter((k) => k === "external").length, media.length);

    // Forms
    f.login_form = document.querySelector("input[type='password']") ? 1 : 0;

    // Frames, pop-ups and other tricks
    f.iframe = Array.from(document.querySelectorAll("iframe")).some((fr) => {
      const style = window.getComputedStyle(fr);
      return fr.width === "0" || fr.height === "0" || style.display === "none" || style.visibility === "hidden" || fr.hasAttribute("hidden");
    }) ? 1 : 0;
    const scripts = Array.from(document.querySelectorAll("script:not([src])")).map((s) => s.textContent || "").join("\n");
    f.popup_window = /window\.open\s*\(|\bprompt\s*\(/.test(scripts) ? 1 : 0;
    f.onmouseover = Array.from(document.querySelectorAll("[onmouseover]")).some((el) =>
      /window\.status|status\s*=/.test(el.getAttribute("onmouseover") || "")
    ) ? 1 : 0;
    f.right_clic = document.oncontextmenu !== null ||
      (document.body && document.body.getAttribute("oncontextmenu")) ||
      /event\.button\s*==\s*2/.test(scripts) ? 1 : 0;

    // Title and copyright (1 = domain missing)
    const title = (document.title || "").trim().toLowerCase();
    f.empty_title = title === "" ? 1 : 0;
    f.domain_in_title = title.includes(domainKeyword) ? 0 : 1;
    const text = document.body ? document.body.innerText || "" : "";
    const mark = text.search(/[©®™]/);
    f.domain_with_copyright = mark >= 0 && !text.slice(Math.max(0, mark - 50), mark + 50).toLowerCase().includes(domainKeyword) ? 1 : 0;

    return f;
  }

  chrome.runtime.sendMessage({ action: "page_features", features: extractFeatures() }).catch(() => {
    // The extension was reloaded while this tab was open; nothing to do.
  });
})();
