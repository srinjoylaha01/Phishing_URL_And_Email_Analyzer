# PhishGuard — Phishing URL & Email Security Analyzer

PhishGuard is a **defensive, explainable cybersecurity analysis tool** for identifying phishing indicators in user-provided URLs and email content.

It combines deterministic security rules, local IOC matching, transparent risk scoring, optional machine learning, SQLite history, CLI workflows, Streamlit visualization, and exportable reports.

> **Safety boundary:** PhishGuard analyzes submitted content locally. It does not visit submitted URLs, send emails, collect credentials, execute attachments, exploit systems, bypass controls, or perform unauthorized scanning.

## Capabilities
| Capability | Implementation |
|---|---|
| URL analysis | Safe parsing and phishing-oriented feature extraction |
| Email analysis | RFC-style parsing and suspicious-content indicators |
| Detection | Explainable rules with evidence |
| Risk scoring | 0–100 score with four risk bands |
| IOC matching | Local synthetic/example indicators |
| ML | Optional Logistic Regression URL classifier |
| Persistence | SQLite analysis history |
| CLI | Analyze, inspect, history, and reports |
| Dashboard | Optional local Streamlit interface |
| Reporting | JSON, CSV, HTML, TXT |
| Testing | pytest + GitHub Actions CI |

## Risk model
- **0–19 — LOW**
- **20–39 — MEDIUM**
- **40–69 — HIGH**
- **70–100 — CRITICAL**

The score is a heuristic indicator of risk, not proof that a URL or email is malicious. The ML pipeline is a separate signal and does not replace rule-based evidence.

## Detection coverage
### URL indicators
- IP address used as hostname
- Unusually long URL
- Excessive subdomains
- Suspicious security-related keywords
- `@` in the URL authority
- Punycode/IDN indicator
- Encoded characters and other extracted URL features

### Email indicators
- Urgency language
- Credential-related requests
- Financial/payment requests
- Reply-To domain mismatch
- Sender-domain versus URL-domain mismatch
- Suspicious HTML
- Attachments
- Display-name/email mismatch

## Architecture
```text
User Input (URL / TXT / EML)
          |
          v
Validation + Parsing
          |
          v
Feature Extraction
     /         \
    v           v
Rule Engine   Local IOC
    |           |
    +-----+-----+
          v
   Transparent Risk Score
          |
   +------+------+
   |      |      |
  CLI   SQLite  Reports
          |
      Dashboard

Optional ML remains a separate signal alongside the core workflow.
```

See [`docs/architecture.md`](docs/architecture.md) and [`docs/architecture.mmd`](docs/architecture.mmd).

## Project structure
```text
.
├── phishguard/          # Core Python package
│   ├── analyzers/
│   ├── database/
│   ├── detection/
│   ├── features/
│   ├── ioc/
│   ├── ml/
│   ├── reporting/
│   ├── scoring/
│   └── cli.py
├── dashboard/           # Optional Streamlit UI
├── data/                # Example IOC and ML training data
├── docs/                # Architecture and phase documentation
├── tests/               # Automated and security-boundary tests
├── models/              # Local ML output directory
├── reports/             # Local generated reports
└── .github/workflows/   # CI
```

## Quick start
### 1. Clone
```bash
git clone https://github.com/srinjoylaha01/iam-access-review-risk-analyzer.git
cd iam-access-review-risk-analyzer
```

### 2. Create a virtual environment
Windows PowerShell:
```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```
Linux/macOS:
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install
```bash
python -m pip install -e .
```

### 4. Analyze a URL
```bash
phishguard analyze-url "https://example.com/login"
```

### 5. Analyze an email
```bash
phishguard analyze-email --text "From: Security <alerts@example.com>

Subject: Verify your account

Please verify your account immediately."
```

Or use a file:
```bash
phishguard analyze-email --file samples/example.eml
```

### 6. History and stored analysis
```bash
phishguard history --limit 20
phishguard show 1
```

### 7. Export a report
```bash
phishguard report 1 --format json --output reports/analysis.json
phishguard report 1 --format html --output reports/analysis.html
```

Supported formats: `json`, `csv`, `html`, `txt`.

## Optional machine learning
Install ML dependencies:
```bash
python -m pip install -e ".[ml]"
```
Train:
```bash
phishguard ml-train
```
Predict:
```bash
phishguard ml-predict-url "https://example.com/login"
```
The pipeline uses Logistic Regression, standardized URL features, a fixed random seed, and a synthetic versioned dataset. ML output is not proof of maliciousness.

## Optional Streamlit dashboard
```bash
python -m pip install -e ".[dashboard]"
streamlit run dashboard/app.py
```
The dashboard reuses the core analysis services and local SQLite history.

## Testing
```bash
python -m pip install -e ".[dev]"
pytest
```
GitHub Actions runs the test suite on pushes to `main` and pull requests.

## Security design
1. Submitted URLs are parsed and are **not automatically requested or browsed**.
2. Email attachments are recorded as metadata and are **not executed**.
3. SQLite operations use parameterized queries.
4. HTML reports escape analysis-derived values.
5. Default IOC data is local synthetic/example data.
6. Core analysis requires no API credentials.
7. ML is optional and isolated from deterministic risk scoring.
8. User-provided content is not converted into shell commands.

See [`docs/phase-13-security-review.md`](docs/phase-13-security-review.md).

## Development roadmap
| Phase | Status |
|---|---|
| 1–13 | Completed |
| 14. README + documentation + architecture diagram | **Completed** |
| 15. Final GitHub audit + interview preparation | Next |

## Portfolio talking points
- Python security tooling
- URL and email security analysis
- Explainable detection engineering
- Risk scoring and IOC matching
- SQLite persistence
- Machine-learning evaluation
- CLI and dashboard development
- Secure parsing and output encoding
- Automated testing and CI
- Security-focused documentation

## Responsible use
Use PhishGuard for defensive analysis of content you are authorized to inspect. Do not use it to facilitate credential theft, unauthorized access, evasion, exploitation, or interaction with suspicious infrastructure.

## License
MIT License. See [`LICENSE`](LICENSE).