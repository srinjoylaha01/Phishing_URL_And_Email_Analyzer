# Phase 2 — Project Structure

```text
phishguard/
├── phishguard/
│   ├── __init__.py
│   ├── cli.py
│   ├── analyzers/
│   ├── detection/
│   ├── features/
│   ├── scoring/
│   ├── ioc/
│   ├── ml/
│   ├── database/
│   ├── reporting/
│   └── utils/
├── dashboard/
├── config/
├── data/
├── models/
├── reports/
├── screenshots/
├── tests/
├── docs/
├── .env.example
├── .gitignore
├── pyproject.toml
├── requirements.txt
└── README.md
```

## Design Rationale

The package is split by responsibility so URL parsing, email parsing, detection, scoring, persistence, reporting, and presentation can be independently tested.

The ML and dashboard components are optional. The core package has no third-party runtime dependency in Phase 2.

## Directory Responsibilities

| Directory | Responsibility |
|---|---|
| phishguard/analyzers | URL/email analysis orchestration |
| phishguard/detection | Detection rules and rule engine |
| phishguard/features | Reusable feature extraction |
| phishguard/scoring | Transparent risk scoring |
| phishguard/ioc | Local IOC handling |
| phishguard/ml | Optional ML pipeline |
| phishguard/database | SQLite persistence |
| phishguard/reporting | Report generation |
| phishguard/utils | Shared utilities |
| dashboard | Optional Streamlit interface |
| config | Rule configuration |
| data | Synthetic/sample datasets |
| models | Local model artifacts |
| reports | Generated reports |
| tests | Automated tests |
| screenshots | Portfolio screenshots |
