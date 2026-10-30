"""API and feature tests. Train the models first: python backend/train_model.py"""

import os
import sys

from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "backend"))
from api import app  # noqa: E402
from features import PAGE_FEATURES, split_host, url_features  # noqa: E402

client = TestClient(app)


def test_health():
    r = client.get("/health")
    assert r.status_code == 200 and set(r.json()["models"]) == {"url", "page"}


def test_url_only_prediction_shape():
    r = client.post("/predict", json={"url": "https://www.example-shop.fr/produits/chaussures"})
    body = r.json()
    assert r.status_code == 200
    assert body["status"] in {"phishing", "suspicious", "legitimate"} and 0 <= body["probability"] <= 1
    assert body["model_used"] == "URL model"


def test_trusted_domains_skip_the_model_but_user_content_does_not():
    assert client.post("/predict", json={"url": "https://accounts.google.com/signin"}).json()["model_used"] == "Trusted domain list"
    assert client.post("/predict", json={"url": "https://sites.google.com/view/login"}).json()["model_used"] == "URL model"


def test_obvious_phishing_url_is_flagged():
    url = "http://paypal.com.secure-login.verify-account.xyz/webscr/signin/update.php?cmd=login"
    body = client.post("/predict", json={"url": url}).json()
    assert body["status"] == "phishing"
    assert any("brand" in c for c in body["cues"])


def test_page_features_switch_to_page_model():
    page = {name: 0 for name in PAGE_FEATURES}
    page.update(nb_hyperlinks=120, ratio_intHyperlinks=0.8, ratio_extHyperlinks=0.2, safe_anchor=20,
                links_in_tags=60, ratio_intMedia=70, ratio_extMedia=30)
    body = client.post("/predict", json={"url": "https://www.lemonde.fr/international/", "page_features": page}).json()
    assert body["model_used"] == "URL + page model"


def test_rejects_non_http_urls():
    assert client.post("/predict", json={"url": "chrome://extensions"}).status_code == 400


def test_url_features():
    f = url_features("http://192.168.0.1:8080/login@evil")
    assert f["ip"] == 1 and f["port"] == 1 and f["nb_at"] == 1 and f["is_https"] == 0
    assert split_host("mail.google.co.uk") == (["mail"], "google.co.uk", "uk")
    assert url_features("https://bit.ly/abc")["shortening_service"] == 1
