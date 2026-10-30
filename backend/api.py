"""
Phishing detection API used by the browser extension.

    POST /predict   {"url": "...", "page_features": {...optional...}}
    GET  /health

Run:  uvicorn api:app --port 8000      (from the backend/ folder)
"""

import json
import os
import sys

import joblib
import pandas as pd
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from features import PAGE_FEATURES, explain, is_trusted, page_features_complete, url_features  # noqa: E402

MODELS_DIR = os.path.join(HERE, "models")
BLOCK_THRESHOLD = 0.7     # the extension shows the warning page
SUSPICIOUS_THRESHOLD = 0.5


def _load(name):
    path = os.path.join(MODELS_DIR, f"{name}_model.joblib")
    if not os.path.exists(path):
        raise RuntimeError(f"Missing {path}. Train the models first: python backend/train_model.py")
    return joblib.load(path)


MODELS = {"url": _load("url"), "page": _load("page")}
with open(os.path.join(MODELS_DIR, "metrics.json"), encoding="utf-8") as f:
    METRICS = json.load(f)

app = FastAPI(title="Phishing Detector API", version="2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origin_regex=r"^(chrome-extension|moz-extension)://.*$|^http://(localhost|127\.0\.0\.1)(:\d+)?$",
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


class PredictRequest(BaseModel):
    url: str = Field(..., max_length=4096)
    page_features: dict | None = None


@app.get("/health")
def health():
    return {"status": "ok", "models": {name: METRICS[name]["accuracy"] for name in MODELS}}


@app.post("/predict")
def predict(req: PredictRequest):
    url = req.url.strip()
    if not url.lower().startswith(("http://", "https://")):
        raise HTTPException(status_code=400, detail="Only http and https URLs can be scanned")

    feats = url_features(url)
    summary = {
        "length_url": feats["length_url"],
        "length_hostname": feats["length_hostname"],
        "nb_subdomains": feats["nb_subdomains"],
        "https": bool(feats["is_https"]),
    }
    if is_trusted(url):
        return {"status": "legitimate", "probability": 0.0, "model_used": "Trusted domain list",
                "model_accuracy": None, "cues": [], "features_summary": summary}

    use_page = page_features_complete(req.page_features)
    if use_page:
        feats.update({name: float(req.page_features[name]) for name in PAGE_FEATURES})
    bundle = MODELS["page" if use_page else "url"]

    X = pd.DataFrame([[feats[name] for name in bundle["features"]]], columns=bundle["features"])
    probability = float(bundle["model"].predict_proba(X)[0, 1])

    if probability >= BLOCK_THRESHOLD:
        status = "phishing"
    elif probability >= SUSPICIOUS_THRESHOLD:
        status = "suspicious"
    else:
        status = "legitimate"
    summary.update(login_form=bool(feats.get("login_form", 0)), nb_hyperlinks=int(feats.get("nb_hyperlinks", 0)))

    return {
        "status": status,
        "probability": round(probability, 4),
        "model_used": "URL + page model" if use_page else "URL model",
        "model_accuracy": METRICS["page" if use_page else "url"]["accuracy"],
        "cues": explain(feats, req.page_features if use_page else None),
        "features_summary": summary,
    }


if __name__ == "__main__":
    import uvicorn

    uvicorn.run("api:app", host="127.0.0.1", port=8000)
