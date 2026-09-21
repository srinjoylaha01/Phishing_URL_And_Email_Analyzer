# Phase 10 — Machine-Learning Module

## Objective
Add an optional, reproducible ML pipeline that provides a separate URL signal alongside PhishGuard's explainable rule engine.

## Design
- Model: Logistic Regression inside a scikit-learn pipeline with feature scaling.
- Input: deterministic URL features already produced by Phase 3.
- Dataset: small synthetic, versioned CSV dataset committed under data/ml/.
- Split: 75% training / 25% test, stratified, random_state=42.
- Metrics: accuracy, precision, recall, F1, and a 2x2 confusion matrix.
- Artifact: local Joblib model under models/; generated artifacts are ignored by Git.
- Prediction threshold: probability >= 0.5 is labeled PHISHING.
- Model version: url-logistic-regression-v1.

## Commands
Install the optional ML dependencies:
python -m pip install -e ".[ml]"

Train and evaluate:
python -m phishguard.ml.train

Predict a URL locally:
python -m phishguard.ml.predict "http://192.0.2.10/login"

The prediction command only parses the submitted URL and loads a local model. It does not resolve DNS, visit the URL, or contact external services.

## CLI integration
After installing the project with the ML extra:
phishguard ml-train
phishguard ml-predict-url "http://192.0.2.10/login"

The ML signal is deliberately separate from the Phase 6 risk score. A model probability is not added to the rule-based score, and neither signal is treated as proof of maliciousness.

## Limitations
The committed dataset is synthetic and intentionally small. Its metrics demonstrate a reproducible ML workflow, not production phishing-detection performance. A real deployment would require a larger, representative, carefully labeled dataset and independent validation.

## Security boundary
No external URLs, live threat feeds, email systems, credentials, or suspicious infrastructure are contacted by the training or prediction workflow.
