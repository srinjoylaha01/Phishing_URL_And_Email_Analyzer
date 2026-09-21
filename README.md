# PhishGuard — Phishing URL & Email Security Analyzer

**Phase 1 — Requirements & Architecture**

PhishGuard is a defensive Python cybersecurity analysis tool designed to inspect user-provided URLs and email content for phishing indicators and produce a transparent, explainable risk assessment.

## Security Boundary

It analyzes submitted URLs, email text, and synthetic/sample data. It does not send emails, collect credentials, attack websites, bypass controls, exploit systems, perform unauthorized scanning, or automatically interact with suspicious infrastructure.

## Planned Architecture

```text
User Input
    |
    v
Input Validation
    |
    v
URL / Email Parser
    |
    v
Feature Extraction
    |
    v
Detection Engine
    |
    +-----> IOC Analysis
    |
    v
Risk Scoring
    |
    v
Optional ML Model
    |
    v
Report Generator
    |
    +-----> CLI
    +-----> Streamlit Dashboard
```

## Planned Detection Rules

- RULE-001 — IP address used as hostname
- RULE-002 — Suspicious URL length
- RULE-003 — Excessive subdomains
- RULE-004 — Suspicious keyword in hostname/path
- RULE-005 — URL contains @ symbol
- RULE-006 — Punycode/IDN indicator
- RULE-007 — Sender and Reply-To domain mismatch
- RULE-008 — Urgent credential request
- RULE-009 — Financial/payment request
- RULE-010 — Suspicious attachment extension

## Risk Scoring

- 0–19: LOW
- 20–39: MEDIUM
- 40–69: HIGH
- 70–100: CRITICAL

The score is an indicator-based assessment, not proof that a URL or email is malicious.

## Development Roadmap

1. Requirements + architecture
2. Project structure + environment setup
3. URL parser + URL feature extraction
4. URL phishing detection rules
5. Email parser + email analysis
6. Risk scoring engine
7. IOC database + threat intelligence
8. SQLite database + analysis history
9. CLI application
10. Machine-learning module
11. Streamlit dashboard
12. Report generation
13. Testing + security review
14. README + documentation + architecture diagram
15. Final GitHub audit + interview preparation

## Project Principles

1. Defensive-by-design.
2. Explainable detections.
3. Rule-based detection and ML remain separate signals.
4. Synthetic/sample indicators only.
5. No secrets committed.
6. Parameterized SQL and controlled parsing.
7. Core CLI works without the dashboard or ML stack.
8. Tests and documentation are part of the engineering workflow.

## License

MIT — planned for the completed repository.
