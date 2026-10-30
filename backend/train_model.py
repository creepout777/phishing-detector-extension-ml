"""
Train the two phishing models used by the API.

* url model   - URL features only, used when the extension has no page data
* page model  - URL features plus the page-structure features from the content script

URL features are recomputed from the raw `url` column with backend/features.py,
the same code the API runs, so training and serving can never drift apart.

Usage:  python backend/train_model.py
"""

import json
import os
import sys
import time

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score, roc_auc_score, confusion_matrix
from sklearn.model_selection import train_test_split

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from features import PAGE_FEATURES, URL_FEATURES, url_features  # noqa: E402

ROOT = os.path.dirname(HERE)
DATASET = os.path.join(ROOT, "data", "dataset_phishing.csv")
MODELS_DIR = os.path.join(HERE, "models")
RANDOM_STATE = 457


def load_dataset(path=DATASET):
    df = pd.read_csv(path)
    url_df = pd.DataFrame([url_features(u) for u in df["url"]])[URL_FEATURES]
    X = pd.concat([url_df, df[PAGE_FEATURES].reset_index(drop=True)], axis=1)
    y = (df["status"] == "phishing").astype(int).to_numpy()
    return X, y


def evaluate(model, X_test, y_test):
    proba = model.predict_proba(X_test)[:, 1]
    pred = (proba >= 0.5).astype(int)
    return {
        "accuracy": round(float(accuracy_score(y_test, pred)), 4),
        "precision": round(float(precision_score(y_test, pred)), 4),
        "recall": round(float(recall_score(y_test, pred)), 4),
        "f1": round(float(f1_score(y_test, pred)), 4),
        "roc_auc": round(float(roc_auc_score(y_test, proba)), 4),
        "confusion_matrix": confusion_matrix(y_test, pred).tolist(),
    }


def train(columns, X_train, y_train):
    model = RandomForestClassifier(n_estimators=300, min_samples_leaf=1, n_jobs=-1, random_state=RANDOM_STATE)
    model.fit(X_train[columns], y_train)
    return model


def main():
    print("Loading dataset and computing URL features...")
    X, y = load_dataset()
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, stratify=y, random_state=RANDOM_STATE
    )
    print(f"  {len(X_train)} training rows, {len(X_test)} test rows, {X.shape[1]} features")

    os.makedirs(MODELS_DIR, exist_ok=True)
    report = {}
    for name, columns in {"url": URL_FEATURES, "page": URL_FEATURES + PAGE_FEATURES}.items():
        start = time.time()
        model = train(columns, X_train, y_train)
        metrics = evaluate(model, X_test[columns], y_test)
        metrics["n_features"] = len(columns)
        metrics["train_seconds"] = round(time.time() - start, 1)
        importances = sorted(zip(columns, model.feature_importances_), key=lambda kv: -kv[1])[:10]
        metrics["top_features"] = [[n, round(float(v), 4)] for n, v in importances]
        report[name] = metrics
        joblib.dump({"model": model, "features": columns}, os.path.join(MODELS_DIR, f"{name}_model.joblib"), compress=3)
        print(f"  {name:4} model: accuracy={metrics['accuracy']:.4f} f1={metrics['f1']:.4f} auc={metrics['roc_auc']:.4f}")

    with open(os.path.join(MODELS_DIR, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)
    print(f"Saved models and metrics to {MODELS_DIR}")


if __name__ == "__main__":
    np.random.seed(RANDOM_STATE)
    main()
