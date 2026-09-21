# PhishGuard Requirements

## Project Goal

Build a professional defensive cybersecurity analyzer that examines user-provided URLs and email content for phishing indicators and produces transparent security findings.

## Functional Requirements

### URL Analysis

Analyze URL length, subdomains, HTTPS usage, IP-hostname usage, suspicious encoding, special characters, @ symbol, ports, Punycode/IDN, suspicious keywords, suspicious TLD indicators, hostname mismatch indicators, safely supported redirects, and optional domain-age enrichment through a legitimate configured API.

A single indicator must not automatically classify a URL as malicious.

### URL Feature Extraction

Expose scheme, hostname, port, path, query, fragment, URL length, hostname length, path length, dots, hyphens, subdomains, query parameters, IP presence, @ presence, encoded-character presence, suspicious-keyword presence, and HTTPS status.

Use Python `urllib.parse` where appropriate.

### Email Analysis

Accept `.txt`, `.eml`, and pasted email text. Inspect sender, sender domain, Reply-To, subject, body, URLs, suspicious keywords, urgency indicators, credential requests, financial/payment requests, attachment names, suspicious HTML indicators, domain mismatches, and display-name versus email-address mismatch.

### Detection Engine

Provide a configurable rule-based engine. Every rule defines Rule ID, description, severity, evidence, explanation, and recommendation.

### Risk Scoring

Initial bands: 0–19 LOW, 20–39 MEDIUM, 40–69 HIGH, 70–100 CRITICAL.

Prevent duplicate scoring where appropriate. Show total score, risk level, triggered rules, evidence, and recommended action. Do not claim the score proves maliciousness.

### Threat Intelligence

Support a local IOC database for suspicious domains, IP addresses, and hashes. Use synthetic/example indicators only. Optional external reputation APIs must use environment variables and never hardcoded keys.

### Machine Learning

Keep ML optional and separate from rule-based detection. Use Logistic Regression or Random Forest. Include dataset preparation, preprocessing, training, validation, evaluation, precision, recall, F1-score, confusion matrix, and prediction. Document dataset limitations.

### CLI

```bash
python -m phishguard url analyze "https://example.com"
python -m phishguard email analyze samples/phishing_email.eml
python -m phishguard url batch --file data/urls.csv
python -m phishguard report --input reports/results.json
python -m phishguard ioc check "example.com"
python -m phishguard --help
```

### Dashboard

A Streamlit interface may expose Overview, URL Analyzer, Email Analyzer, IOC Checker, Risk Analysis, Detection History, and Statistics.

### Reporting

Planned formats: JSON, CSV, HTML, TXT. Include analysis ID, timestamp, input, risk score, risk level, triggered rules, extracted features, evidence, IOC matches, and recommendations.

### Persistence

Use SQLite with logical tables: `analyses`, `url_features`, `detections`, and `iocs`. Use parameterized SQL and avoid unnecessary personal data.

## Non-Functional Requirements

### Security

- input validation
- safe URL parsing
- safe email parsing
- exception handling
- logging
- parameterized SQL
- environment variables for API keys
- no hardcoded credentials
- no shell execution from user input
- no automatic interaction with suspicious websites
- no credential collection
- no unauthorized scanning

### Maintainability

Use a modular package structure, clear error handling, type hints where useful, and automated tests.

### Explainability

Every finding should be traceable to an observed feature, a rule, a severity, evidence, an explanation, and a recommendation.

## Testing Requirements

Use pytest for URL parsing, IP detection, keyword detection, encoding detection, subdomain detection, sender/Reply-To mismatch, email parsing, scoring, IOC matching, and report generation.

Include normal, suspicious, phishing-like synthetic, and malformed inputs.
