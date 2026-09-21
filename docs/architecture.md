# PhishGuard Architecture

## Architectural Goal

Separate collection, parsing, feature extraction, detection, scoring, persistence, and presentation so security functions can be tested independently.

## Data Flow

```text
+-------------------+
|    User Input     |
| URL / TXT / EML   |
+---------+---------+
          |
          v
+-------------------+
| Input Validation  |
+---------+---------+
          |
          v
+-------------------+
| URL / Email Parse |
+---------+---------+
          |
          v
+-------------------+
| Feature Extraction|
+---------+---------+
          |
          v
+-------------------+
| Detection Engine  |
| Configurable Rules|
+----+----------+---+
     |          |
     |          v
     |    +-----------+
     |    | IOC Check |
     |    +-----------+
     |          |
     +----+-----+
          v
+-------------------+
|   Risk Scoring    |
+---------+---------+
          |
          +--------------------+
          |                    |
          v                    v
+-------------------+   +----------------+
| Optional ML Model |   | Report/History |
+-------------------+   +-------+--------+
                                |
                   +------------+------------+
                   |                         |
                   v                         v
                CLI Output             Dashboard
```

## Components

### Input Validation
Reject malformed or unsupported input before deeper processing. Validation is a control boundary, not a verdict engine.

### URL Analyzer
Coordinates safe parsing and analysis of submitted URLs without automatically requesting or browsing the destination.

### Email Analyzer
Uses standard email parsing for `.eml` content and controlled text processing for text/pasted messages.

### Feature Extractor
Produces structured observations consumed by both rules and the optional ML pipeline.

### Detection Engine
Evaluates configured rules and emits findings. Detection logic remains separate from score aggregation.

### IOC Manager
Performs local matching against synthetic/example indicators. External reputation services remain optional.

### Risk Scoring
Converts unique rule findings into a bounded explainable score and risk level.

### ML Module
Consumes extracted features independently from the deterministic rule engine. ML output is presented as a separate signal.

### Database Layer
Stores analysis metadata and findings in SQLite using parameterized queries.

### Reporting Layer
Serializes results into machine-readable and human-readable formats.

### CLI
Provides the primary terminal interface.

### Dashboard
Provides an optional visual interface and must not be required by the core analyzer.

## Separation of Concerns

Parsers parse. Feature extractors extract. Rules detect. Scoring aggregates. IOC logic matches. ML predicts. Reporting formats. CLI/dashboard present.

## Security Model

PhishGuard analyzes submitted content rather than interacting with suspicious infrastructure. The default architecture avoids outbound requests to analyzed URLs, credential submission, shell execution, active vulnerability scanning, and unauthorized service enumeration.

Any future network-backed enrichment must be explicit, optional, isolated, documented, and protected with environment-based credentials.

## Planned Package Layout

```text
phishguard/
├── phishguard/
│   ├── __init__.py
│   ├── cli.py
│   ├── analyzers/
│   │   ├── url_analyzer.py
│   │   ├── email_analyzer.py
│   │   └── attachment_analyzer.py
│   ├── detection/
│   │   ├── rule_engine.py
│   │   ├── url_rules.py
│   │   └── email_rules.py
│   ├── features/
│   │   └── url_features.py
│   ├── scoring/
│   │   └── risk_score.py
│   ├── ioc/
│   │   └── ioc_manager.py
│   ├── ml/
│   │   ├── feature_pipeline.py
│   │   ├── train.py
│   │   └── predict.py
│   ├── database/
│   │   └── database.py
│   ├── reporting/
│   │   └── report_generator.py
│   └── utils/
│       ├── logger.py
│       └── validators.py
├── dashboard/
│   └── app.py
├── config/
│   └── rules.yaml
├── data/
├── models/
├── reports/
├── tests/
├── docs/
└── screenshots/
```

## Key Architecture Decisions

- Rule-based detection is the primary signal because evidence can be shown directly to an analyst.
- ML is optional and isolated so model uncertainty does not replace deterministic evidence.
- Local IOC matching keeps demonstrations reproducible without shipping active malicious infrastructure.
- SQLite keeps persistence self-contained.
- CLI-first design keeps the core workflow usable without Streamlit.
