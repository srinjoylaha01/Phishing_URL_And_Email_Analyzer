"""Training and inference helpers for the optional URL ML model."""
from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path

MODEL_VERSION = "url-logistic-regression-v1"

@dataclass(frozen=True)
class MLPrediction:
    """Model prediction for a single URL."""
    label: str
    probability: float
    model_version: str = MODEL_VERSION

def train_model(X, y, random_state: int = 42):
    """Train a reproducible Logistic Regression pipeline."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    pipeline = Pipeline([
        ("scaler", StandardScaler()),
        ("classifier", LogisticRegression(max_iter=1000, random_state=random_state)),
    ])
    pipeline.fit(X, y)
    return pipeline

def save_model(model, path: str | Path) -> None:
    """Persist a trained model using joblib."""
    import joblib
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, destination)

def load_model(path: str | Path):
    """Load a previously trained model from a trusted local path."""
    import joblib
    return joblib.load(Path(path))

def predict_url(model, features) -> MLPrediction:
    """Predict whether a URL is phishing-like according to the trained model."""
    from phishguard.ml.features import url_features_to_vector
    vector = [url_features_to_vector(features)]
    probability = float(model.predict_proba(vector)[0][1])
    label = "PHISHING" if probability >= 0.5 else "LEGITIMATE"
    return MLPrediction(label=label, probability=probability)
