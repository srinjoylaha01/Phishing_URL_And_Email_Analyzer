from pathlib import Path
import pytest

from phishguard.features.url_features import extract_url_features

pytest.importorskip("sklearn")
pytest.importorskip("joblib")

from phishguard.ml.features import FEATURE_NAMES, training_vector_from_row, url_features_to_vector
from phishguard.ml.model import MODEL_VERSION, predict_url
from phishguard.ml.train import load_dataset, train_from_csv

def test_feature_vector_matches_declared_order():
    features = extract_url_features("https://portal.example.com/login?next=%2Fhome")
    vector = url_features_to_vector(features)
    assert len(vector) == len(FEATURE_NAMES)
    assert vector[0] == float(features.url_length)
    assert vector[7] == 0.0

def test_training_dataset_is_reproducible():
    data = Path("data/ml/url_training.csv")
    assert load_dataset(data) == load_dataset(data)

def test_train_evaluate_and_predict(tmp_path: Path):
    model_path = tmp_path / "model.joblib"
    metrics_path = tmp_path / "metrics.json"
    metrics = train_from_csv(Path("data/ml/url_training.csv"), model_path, metrics_path)
    assert model_path.exists() and metrics_path.exists()
    assert {"accuracy", "precision", "recall", "f1", "confusion_matrix"} <= set(metrics)
    assert len(metrics["confusion_matrix"]) == 2
    from phishguard.ml.model import load_model
    model = load_model(model_path)
    prediction = predict_url(model, extract_url_features("http://192.0.2.10/login"))
    assert prediction.model_version == MODEL_VERSION
    assert 0.0 <= prediction.probability <= 1.0
    assert prediction.label in {"PHISHING", "LEGITIMATE"}

def test_training_vector_from_row():
    import csv
    with Path("data/ml/url_training.csv").open(newline="", encoding="utf-8") as handle:
        row = next(csv.DictReader(handle))
    assert len(training_vector_from_row(row)) == len(FEATURE_NAMES)
