"""
Feature extraction for the phishing detector.

URL features are computed here from the raw URL, both when training (from the
`url` column of the dataset) and when the API scores a page, so the model always
sees features built by the same code.

Page features come from the browser extension's content script. They follow the
definitions used by the dataset authors (Hannousse & Yahiouche, 2021): ratios of
links and media are percentages from 0 to 100, and `domain_in_title` and
`domain_with_copyright` are 1 when the domain is *missing*.
"""

import ipaddress
import os
import re
from urllib.parse import urlparse

PHISH_HINTS = ["wp", "login", "includes", "admin", "content", "site", "images", "js", "alibaba",
               "css", "myaccount", "dropbox", "themes", "plugins", "signin", "view", "verify",
               "secure", "account", "update", "banking", "confirm", "webscr", "ebayisapi"]
SHORTENERS = {"bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "is.gd", "t.ly", "buff.ly",
              "adf.ly", "bitly.com", "cutt.ly", "rb.gy", "shorturl.at", "tiny.cc", "rebrand.ly",
              "bl.ink", "s.id", "v.gd", "x.co", "lnkd.in", "db.tt", "qr.net", "1url.com", "tr.im"}
SUSPICIOUS_TLDS = {"zip", "top", "gq", "fit", "tk", "ml", "ga", "cf", "xyz", "club", "cc", "site",
                   "online", "vip", "shop", "work", "support", "rest", "live", "icu", "buzz",
                   "cyou", "monster", "country", "kim", "loan", "men", "date", "review", "info"}
BRANDS = ["paypal", "apple", "microsoft", "office365", "outlook", "google", "gmail", "facebook",
          "instagram", "whatsapp", "netflix", "amazon", "ebay", "dropbox", "adobe", "linkedin",
          "yahoo", "chase", "wellsfargo", "bankofamerica", "dhl", "fedex", "usps", "alibaba",
          "steam", "binance", "coinbase", "docusign", "icloud", "wetransfer"]
RISKY_EXTENSIONS = {".exe", ".dll", ".zip", ".scr", ".jar", ".bat", ".apk", ".msi", ".rar", ".js"}
SECOND_LEVEL = {"co", "com", "ac", "gov", "org", "net", "edu", "ne", "or", "go", "gob", "nic"}

# Well-known sites that are never sent to the model. Hosts that serve user-uploaded
# content are excluded, because phishing pages are often hosted there.
TRUSTED_DOMAINS = {
    "google.com", "youtube.com", "gmail.com", "github.com", "microsoft.com", "live.com",
    "office.com", "outlook.com", "apple.com", "icloud.com", "amazon.com", "wikipedia.org",
    "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com", "x.com", "twitter.com",
    "reddit.com", "netflix.com", "paypal.com", "ebay.com", "yahoo.com", "bing.com",
    "stackoverflow.com", "mozilla.org", "python.org", "claude.ai", "anthropic.com",
    "bbc.co.uk", "nytimes.com", "zoom.us", "dropbox.com", "adobe.com", "spotify.com",
}
USER_CONTENT_HOSTS = {
    "sites.google.com", "docs.google.com", "drive.google.com", "forms.gle",
    "storage.googleapis.com", "firebasestorage.googleapis.com", "gist.github.com",
    "raw.githubusercontent.com", "dl.dropboxusercontent.com",
}

URL_FEATURES = [
    "length_url", "length_hostname", "ip", "nb_dots", "nb_hyphens", "nb_at", "nb_qm", "nb_and",
    "nb_eq", "nb_underscore", "nb_tilde", "nb_percent", "nb_slash", "nb_star", "nb_colon",
    "nb_comma", "nb_semicolumn", "nb_dollar", "nb_space", "nb_www", "nb_com", "nb_dslash",
    "http_in_path", "https_token", "is_https", "ratio_digits_url", "ratio_digits_host", "punycode",
    "port", "tld_in_path", "tld_in_subdomain", "abnormal_subdomain", "nb_subdomains",
    "prefix_suffix", "shortening_service", "path_extension", "length_words_raw", "char_repeat",
    "shortest_words_raw", "shortest_word_host", "shortest_word_path", "longest_words_raw",
    "longest_word_host", "longest_word_path", "avg_words_raw", "avg_word_host", "avg_word_path",
    "phish_hints", "brand_in_subdomain", "brand_in_path", "suspecious_tld", "path_depth",
    "query_length",
]

PAGE_FEATURES = [
    "nb_hyperlinks", "ratio_intHyperlinks", "ratio_extHyperlinks", "nb_extCSS", "login_form",
    "external_favicon", "links_in_tags", "ratio_intMedia", "ratio_extMedia", "iframe",
    "popup_window", "safe_anchor", "onmouseover", "right_clic", "empty_title", "domain_in_title",
    "domain_with_copyright",
]


def split_host(host):
    """Return (subdomain labels, registered domain, tld) for a hostname."""
    labels = [label for label in host.split(".") if label]
    if len(labels) < 2:
        return [], host, ""
    tld = labels[-1]
    if len(labels) >= 3 and labels[-2] in SECOND_LEVEL and len(tld) == 2:
        return labels[:-3], ".".join(labels[-3:]), tld
    return labels[:-2], ".".join(labels[-2:]), tld


def _words(text):
    return [w for w in re.split(r"[^a-zA-Z0-9]+", text) if w]


def _word_stats(words):
    if not words:
        return 0, 0, 0.0
    lengths = [len(w) for w in words]
    return min(lengths), max(lengths), sum(lengths) / len(lengths)


def _is_ip(host):
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"0x[0-9a-f]+|\d{8,10}", host))


def url_features(url):
    """Compute the URL feature dict for one URL."""
    raw = url.strip()
    parsed = urlparse(raw if "://" in raw else "http://" + raw)
    host = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    is_ip = _is_ip(host)
    subdomains, domain, tld = ([], host, "") if is_ip else split_host(host)
    lowered = raw.lower()
    url_words = _words(raw)
    host_words = _words(host)
    path_words = _words(path + ("?" + query if query else ""))
    s_raw, l_raw, a_raw = _word_stats(url_words)
    s_host, l_host, a_host = _word_stats(host_words)
    s_path, l_path, a_path = _word_stats(path_words)
    try:
        has_port = parsed.port is not None
    except ValueError:
        has_port = True
    first_label = subdomains[0] if subdomains else ""

    return {
        "length_url": len(raw),
        "length_hostname": len(host),
        "ip": int(is_ip),
        "nb_dots": raw.count("."),
        "nb_hyphens": raw.count("-"),
        "nb_at": raw.count("@"),
        "nb_qm": raw.count("?"),
        "nb_and": raw.count("&"),
        "nb_eq": raw.count("="),
        "nb_underscore": raw.count("_"),
        "nb_tilde": raw.count("~"),
        "nb_percent": raw.count("%"),
        "nb_slash": raw.count("/"),
        "nb_star": raw.count("*"),
        "nb_colon": raw.count(":"),
        "nb_comma": raw.count(","),
        "nb_semicolumn": raw.count(";"),
        "nb_dollar": raw.count("$"),
        "nb_space": raw.count(" ") + lowered.count("%20"),
        "nb_www": sum(1 for w in url_words if "www" in w.lower()),
        "nb_com": sum(1 for w in url_words if "com" in w.lower()),
        "nb_dslash": int(raw.rfind("//") > 7),
        "http_in_path": (path + query).lower().count("http"),
        "https_token": int("https" in host or "https" in (path + query).lower()),
        "is_https": int(parsed.scheme == "https"),
        "ratio_digits_url": sum(c.isdigit() for c in raw) / max(len(raw), 1),
        "ratio_digits_host": sum(c.isdigit() for c in host) / max(len(host), 1),
        "punycode": int("xn--" in host),
        "port": int(has_port),
        "tld_in_path": int(bool(tld) and f".{tld}" in path.lower()),
        "tld_in_subdomain": int(any(label in {"com", "net", "org", "co"} for label in subdomains)),
        "abnormal_subdomain": int(bool(re.fullmatch(r"w[w\d]{1,3}", first_label)) and first_label != "www"),
        "nb_subdomains": len(subdomains),
        "prefix_suffix": int("-" in domain),
        "shortening_service": int(domain in SHORTENERS or host in SHORTENERS),
        "path_extension": int(os.path.splitext(path)[1].lower() in RISKY_EXTENSIONS),
        "length_words_raw": len(url_words),
        "char_repeat": _char_repeat(url_words),
        "shortest_words_raw": s_raw,
        "shortest_word_host": s_host,
        "shortest_word_path": s_path,
        "longest_words_raw": l_raw,
        "longest_word_host": l_host,
        "longest_word_path": l_path,
        "avg_words_raw": a_raw,
        "avg_word_host": a_host,
        "avg_word_path": a_path,
        "phish_hints": sum(lowered.count(h) for h in PHISH_HINTS if h not in domain),
        "brand_in_subdomain": int(any(b in ".".join(subdomains) for b in BRANDS)),
        "brand_in_path": int(any(b in path.lower() for b in BRANDS)),
        "suspecious_tld": int(tld in SUSPICIOUS_TLDS),
        "path_depth": len([p for p in path.split("/") if p]),
        "query_length": len(query),
    }


def _char_repeat(words):
    """Number of words containing a character repeated 3+ times in a row."""
    return sum(1 for w in words if re.search(r"(.)\1\1", w))


def is_trusted(url):
    """True for well-known domains that are skipped by the model."""
    host = (urlparse(url).hostname or "").lower()
    if host in USER_CONTENT_HOSTS:
        return False
    return split_host(host)[1] in TRUSTED_DOMAINS


def page_features_complete(page):
    """True when the content script sent every page feature."""
    return bool(page) and all(name in page for name in PAGE_FEATURES)


def explain(url_feats, page=None):
    """Human-readable signals shown in the extension, most serious first."""
    cues = []
    if url_feats["ip"]:
        cues.append("The address uses a raw IP instead of a domain name")
    if url_feats["nb_at"]:
        cues.append("The URL contains '@', which hides the real destination")
    if url_feats["punycode"]:
        cues.append("The domain uses punycode, often used for look-alike domains")
    if url_feats["shortening_service"]:
        cues.append("The link goes through a URL shortener")
    if url_feats["brand_in_subdomain"]:
        cues.append("A well-known brand name appears in the subdomain")
    if url_feats["brand_in_path"] and url_feats["phish_hints"]:
        cues.append("A well-known brand name appears in the path next to login keywords")
    if url_feats["suspecious_tld"]:
        cues.append("The domain ends with a TLD often used for abuse")
    if url_feats["nb_subdomains"] >= 3:
        cues.append(f"Unusually many subdomains ({url_feats['nb_subdomains']})")
    if url_feats["prefix_suffix"]:
        cues.append("The domain name contains a hyphen")
    if url_feats["phish_hints"] >= 2:
        cues.append("Several login or account keywords in the URL")
    if url_feats["path_extension"]:
        cues.append("The link points to a downloadable executable or archive")
    if not url_feats["is_https"]:
        cues.append("The connection is not encrypted (no HTTPS)")
    if page:
        if page.get("login_form") and not url_feats["is_https"]:
            cues.insert(0, "Password form on a page without HTTPS")
        elif page.get("login_form"):
            cues.append("The page asks for a password")
        if page.get("domain_in_title"):
            cues.append("The page title does not mention the site's domain")
        if page.get("empty_title"):
            cues.append("The page has no title")
        if page.get("ratio_extHyperlinks", 0) > 0.6:
            cues.append("Most links point to other websites")
        if page.get("iframe"):
            cues.append("The page embeds invisible frames")
        if page.get("right_clic"):
            cues.append("Right-click is disabled")
    return cues
