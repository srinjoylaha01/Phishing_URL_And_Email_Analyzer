# Phase 15 — Final GitHub Audit

## Audit result

The final audit covered repository structure, documentation, CLI workflows, detection engine, risk scoring, persistence, reporting, optional ML/dashboard modules, tests, CI configuration, and defensive security boundaries.

## CI issues found and fixed

The Phase 14 GitHub Actions run exposed six test failures. They were traced to stale or incomplete test assumptions and one evidence-generation bug:

1. Email findings attempted to use URL-only evidence attributes. The rule engine now generates email-specific evidence for RULE-007 through RULE-014.
2. The CLI parser bootstrap test incorrectly called parse_args([]) even though the CLI requires a subcommand. The test now verifies parser construction.
3. The database SQL-injection safety test used literal whitespace inside a URL. The test now uses percent-encoded payload characters while preserving the injection-style input.
4. The risk-score cap test expected more than 100 points from a URL rule combination that currently totals less than 100. The test now uses a synthetic 125-point finding to test the scoring cap directly.
5. The missing-email-source CLI test encountered pytest's captured stdin. The CLI now treats an OSError while reading non-interactive stdin as an absent source and returns the intended validation error.
6. The fixes were committed to main so CI can execute against the corrected tree.

## Repository checklist

- [x] Core Python package
- [x] URL feature extraction
- [x] URL detection rules
- [x] Email feature extraction
- [x] Email detection rules
- [x] Explainable risk scoring
- [x] Local IOC workflow
- [x] SQLite persistence
- [x] CLI
- [x] Optional ML pipeline
- [x] Optional Streamlit dashboard
- [x] JSON/CSV/HTML/TXT reporting
- [x] Automated tests
- [x] GitHub Actions CI
- [x] Security review
- [x] Portfolio README
- [x] Architecture documentation and Mermaid source
- [x] MIT license
- [x] Final audit documentation

## Known limitations

- Risk scoring is heuristic and is not proof of maliciousness.
- The ML dataset is synthetic and intended to demonstrate a reproducible pipeline, not production-grade threat classification.
- IOC data is local synthetic/example data by default.
- Email registrable-domain comparison is a lightweight heuristic rather than a full public-suffix implementation.
- The security review is a defensive code review, not a penetration test or third-party audit.
- The repository name remains iam-access-review-risk-analyzer even though the implemented project is PhishGuard.

## Interview-ready explanation

**Project:** PhishGuard — Phishing URL & Email Security Analyzer

**Problem:** Analysts and users need a safe way to inspect suspicious URLs and email content without automatically interacting with potentially hostile infrastructure.

**Solution:** PhishGuard extracts local features, evaluates explainable rules, matches local IOCs, calculates a transparent risk score, stores analysis history, and exports reports. An optional ML model provides a separate URL classification signal.

**Security design:** Submitted URLs are parsed but not fetched; email attachments are not executed; SQL uses parameters; report HTML escapes analysis-derived values; external enrichment is not enabled by default.

**Engineering decisions:** The core analyzer is dependency-light, the CLI is the primary interface, the dashboard and ML stack are optional, and rule detection remains separate from risk aggregation and ML prediction.

## Suggested CV bullet

> Built PhishGuard, a defensive Python phishing URL/email analyzer with explainable detection rules, 0–100 risk scoring, local IOC matching, SQLite history, optional Logistic Regression, Streamlit dashboard, multi-format reporting, automated tests, and GitHub Actions CI.