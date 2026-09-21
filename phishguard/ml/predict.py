"""Local URL prediction entry point for a trained PhishGuard model."""
from __future__ import annotations
import argparse
import json
from phishguard.features.url_features import extract_url_features
from phishguard.ml.model import load_model, predict_url

def predict_url_from_path(url: str, model_path: str):
    """Parse a URL locally and run the trusted local model."""
    features = extract_url_features(url)
    model = load_model(model_path)
    return predict_url(model, features)

def main() -> int:
    parser = argparse.ArgumentParser(description="Predict a URL with the PhishGuard ML model.")
    parser.add_argument("url")
    parser.add_argument("--model", default="models/phishguard_url_model.joblib")
    args = parser.parse_args()
    prediction = predict_url_from_path(args.url, args.model)
    print(json.dumps({"url": args.url, "label": prediction.label,
                      "probability": round(prediction.probability, 4),
                      "model_version": prediction.model_version}, indent=2))
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
