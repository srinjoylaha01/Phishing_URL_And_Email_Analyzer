"""Reproducible training and evaluation entry point for the URL ML model."""
from __future__ import annotations
import argparse
import csv
import json
from pathlib import Path
from phishguard.ml.features import FEATURE_NAMES, training_vector_from_row
from phishguard.ml.model import save_model, train_model

def load_dataset(path: str | Path):
    """Load the versioned CSV dataset without network access."""
    from sklearn.model_selection import train_test_split
    with Path(path).open("r", encoding="utf-8", newline="") as handle:
        rows = list(csv.DictReader(handle))
    if not rows:
        raise ValueError("Training dataset is empty")
    required = set(FEATURE_NAMES) | {"label"}
    missing = required - set(rows[0])
    if missing:
        raise ValueError(f"Training dataset is missing columns: {sorted(missing)}")
    X = [training_vector_from_row(row) for row in rows]
    y = [int(row["label"]) for row in rows]
    if len(set(y)) != 2:
        raise ValueError("Training dataset must contain both labels 0 and 1")
    return train_test_split(X, y, test_size=0.25, random_state=42, stratify=y)

def evaluate_model(model, X_test, y_test) -> dict[str, object]:
    """Return classification metrics and a 2x2 confusion matrix."""
    from sklearn.metrics import accuracy_score, confusion_matrix, f1_score, precision_score, recall_score
    predictions = model.predict(X_test)
    matrix = confusion_matrix(y_test, predictions, labels=[0, 1])
    return {
        "accuracy": round(float(accuracy_score(y_test, predictions)), 4),
        "precision": round(float(precision_score(y_test, predictions, zero_division=0)), 4),
        "recall": round(float(recall_score(y_test, predictions, zero_division=0)), 4),
        "f1": round(float(f1_score(y_test, predictions, zero_division=0)), 4),
        "confusion_matrix": matrix.tolist(), "test_samples": len(y_test),
        "model": "LogisticRegression", "random_state": 42,
    }

def train_from_csv(data_path: str | Path, model_path: str | Path, metrics_path: str | Path | None = None):
    """Train, evaluate, and optionally save evaluation metrics."""
    X_train, X_test, y_train, y_test = load_dataset(data_path)
    model = train_model(X_train, y_train, random_state=42)
    metrics = evaluate_model(model, X_test, y_test)
    save_model(model, model_path)
    if metrics_path:
        destination = Path(metrics_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return metrics

def main() -> int:
    parser = argparse.ArgumentParser(description="Train the PhishGuard URL ML model.")
    parser.add_argument("--data", default="data/ml/url_training.csv")
    parser.add_argument("--model", default="models/phishguard_url_model.joblib")
    parser.add_argument("--metrics", default="models/phishguard_url_metrics.json")
    args = parser.parse_args()
    metrics = train_from_csv(args.data, args.model, args.metrics)
    print(json.dumps(metrics, indent=2))
    print(f"Model saved to: {args.model}")
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
