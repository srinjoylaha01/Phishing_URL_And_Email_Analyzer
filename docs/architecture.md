# PhishGuard Architecture

## Purpose
PhishGuard separates parsing, feature extraction, detection, scoring, IOC matching, persistence, machine learning, reporting, and presentation so security logic remains testable and explainable.

## Data flow
```text
Input
  |
  +--> URL --------------------+
  |                            |
  +--> Email (.eml/text) ------+--> Feature Extraction
                                      |
                           +----------+----------+
                           |                     |
                           v                     v
                    Detection Rules        Local IOC Match
                           |                     |
                           +----------+----------+
                                      v
                              Risk Score 0-100
                                      |
                 +--------------------+--------------------+
                 |                    |                    |
                 v                    v                    v
             SQLite DB            Reports              CLI/UI

                         Optional separate ML signal
```

## Component responsibilities
- **URL analyzer:** safe parsing and feature extraction without HTTP requests or DNS resolution.
- **Email analyzer:** standard-library parsing and extraction of sender, Reply-To, subject, body, URLs, attachments, HTML indicators, and domain relationships.
- **Feature extraction:** creates structured observations without deciding whether content is malicious.
- **Detection engine:** evaluates deterministic rules and emits rule IDs, severity, points, evidence, explanations, and recommendations.
- **Risk scoring:** aggregates finding points into LOW, MEDIUM, HIGH, or CRITICAL bands.
- **IOC manager:** performs deterministic matching against local domain, URL, IP, and email indicators.
- **SQLite repository:** stores analysis metadata, features, findings, IOC records, and IOC matches using parameterized SQL.
- **ML module:** optional Logistic Regression URL classifier kept separate from the rule-based score.
- **Reporting:** renders stored analyses as JSON, CSV, HTML, or TXT.
- **CLI:** primary terminal workflow.
- **Dashboard:** optional local Streamlit presentation layer.

## Security boundaries
```text
UNTRUSTED INPUT
      |
      v
+----------------------+
| Validation + Parsing |
+----------+-----------+
           |
           v
+----------------------+
| Local Feature Logic  |
+----------+-----------+
           |
           +----> Local IOC matching
           +----> Rule evaluation
           +----> Optional local ML
           |
           v
+----------------------+
| Local Storage/Output |
+----------------------+
```

The architecture intentionally avoids automatic URL requests, DNS lookups during analysis, credential submission, email sending, attachment execution, shell execution from submitted content, and unauthorized vulnerability scanning.

## Current repository layout
```text
phishguard/
├── analyzers/
├── database/
├── detection/
├── features/
├── ioc/
├── ml/
├── reporting/
├── scoring/
└── cli.py

dashboard/
data/
docs/
models/
reports/
tests/
```

Visual diagram source: [`architecture.mmd`](architecture.mmd).