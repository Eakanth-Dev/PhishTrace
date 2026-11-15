"""Optional scikit-learn URL classifier.

HONESTY NOTE: PhishTrace ships WITHOUT a trained model because no labelled dataset is bundled and
none may be fabricated. Until you train one, the engine is reported as 'not available' and the
risk score is purely rule-based. To train on your own labelled data:

    python -m core.ml_engine train path/to/urls.csv      # columns: url,label   (1 = malicious, 0 = benign)

Metrics are computed on a held-out split of YOUR data and stored in models/url_model_metrics.json.
"""
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from config import MODEL_DIR
from core.findings import make_finding
from core.url_analyzer import url_features

MODEL_PATH = MODEL_DIR / "url_model.joblib"
METRICS_PATH = MODEL_DIR / "url_model_metrics.json"
_cache = {}


def is_available(model_path: Path = MODEL_PATH) -> bool:
    return Path(model_path).is_file()


def load_metrics():
    try:
        return json.loads(METRICS_PATH.read_text())
    except Exception:
        return None


def _load(model_path: Path = MODEL_PATH):
    key = str(model_path)
    if key in _cache:
        return _cache[key]
    try:
        import joblib
        _cache[key] = joblib.load(model_path)
    except Exception:
        _cache[key] = None
    return _cache[key]


def predict_proba(url: str, model_path: Path = MODEL_PATH):
    """Probability (0-1) that the URL is malicious, or None when no model is available."""
    if not is_available(model_path):
        return None
    bundle = _load(model_path)
    if not bundle:
        return None
    try:
        import pandas as pd
        feats = url_features(url)
        row = pd.DataFrame([[feats.get(n, 0) for n in bundle["features"]]], columns=bundle["features"])
        return float(bundle["model"].predict_proba(row)[0][1])
    except Exception:
        return None


def ml_finding(url: str):
    p = predict_proba(url)
    if p is None:
        return None
    m = load_metrics() or {}
    sev = "high" if p >= 0.8 else "medium" if p >= 0.5 else "info"
    return make_finding("ML model estimate", f"User-trained model gives {p:.0%} probability of malicious "
                        f"(held-out F1 on its own training data: {m.get('f1', 'n/a')}). Statistical estimate only.",
                        sev, "scikit-learn RandomForest (locally trained)", points=round(p * 30) if p >= 0.5 else 0)


def train_from_csv(csv_path, out_dir=MODEL_DIR, test_size: float = 0.25, seed: int = 42) -> dict:
    import joblib
    import pandas as pd
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
    from sklearn.model_selection import train_test_split

    df = pd.read_csv(csv_path)
    if not {"url", "label"} <= set(df.columns):
        raise ValueError("CSV must contain columns: url,label")
    df = df.dropna(subset=["url", "label"]).drop_duplicates(subset=["url"])
    y = df["label"].astype(int)
    if len(df) < 50 or y.value_counts().min() < 10:
        raise ValueError("Need at least 50 rows with 10+ examples of each class to train a meaningful model.")
    names = list(url_features("http://example.com").keys())
    X = pd.DataFrame([[url_features(u).get(n, 0) for n in names] for u in df["url"]], columns=names)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=test_size, stratify=y, random_state=seed)
    clf = RandomForestClassifier(n_estimators=200, class_weight="balanced", random_state=seed, n_jobs=-1).fit(Xtr, ytr)
    pred = clf.predict(Xte)
    metrics = {"accuracy": round(accuracy_score(yte, pred), 4), "precision": round(precision_score(yte, pred, zero_division=0), 4),
               "recall": round(recall_score(yte, pred, zero_division=0), 4), "f1": round(f1_score(yte, pred, zero_division=0), 4),
               "confusion_matrix": confusion_matrix(yte, pred).tolist(), "n_train": int(len(Xtr)), "n_test": int(len(Xte)),
               "dataset": Path(csv_path).name, "trained_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
               "note": "Measured on a held-out split of the supplied dataset only; real-world performance may differ."}
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    joblib.dump({"model": clf, "features": names}, out_dir / "url_model.joblib")
    (out_dir / "url_model_metrics.json").write_text(json.dumps(metrics, indent=2))
    _cache.clear()
    return metrics


if __name__ == "__main__":  # pragma: no cover
    if len(sys.argv) == 3 and sys.argv[1] == "train":
        print(json.dumps(train_from_csv(sys.argv[2]), indent=2))
    else:
        print("usage: python -m core.ml_engine train urls.csv")
