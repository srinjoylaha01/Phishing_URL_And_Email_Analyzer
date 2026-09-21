# Development Phases

This repository is intentionally built incrementally.

## Phase 1 — Requirements + Architecture
**Completed.** Outputs: project scope, security boundaries, functional requirements, architecture, and development roadmap.

## Phase 2 — Project Structure + Environment Setup
**Completed.** Created the Python package, dependency management, configuration directories, test layout, and development tooling.

## Phase 3 — URL Parser + URL Feature Extraction
**Completed.** Implemented safe URL parsing and reusable URL features.

## Phase 4 — URL Phishing Detection Rules
**Completed.** Implemented configurable URL rules and evidence-based findings.

## Phase 5 — Email Parser + Email Analysis
**Completed.** Added safe email parsing and deterministic email feature extraction for pasted/RFC-style email content.

## Phase 6 — Risk Scoring Engine
**Completed.** Added transparent 0–100 risk aggregation, documented risk bands, and email-specific scored findings.

## Phase 7 — IOC Database + Threat Intelligence
**Completed.** Added a local JSON IOC store, deterministic IOC matching, a provider interface for optional enrichment, and synthetic/reserved example indicators. External network enrichment remains disabled by default.

## Phase 8 — SQLite Database + Analysis History
**Completed.** Added local SQLite persistence for analysis metadata, URL/email features, detections, IOC records, IOC matches, and recent analysis history.

## Phase 9 — CLI Application
**Completed.** Added URL/email analysis commands, local IOC matching, SQLite persistence, analysis history, stored-analysis inspection, stdin/file input, and structured terminal error handling.

## Phase 10 — Machine-Learning Module
**Completed.** Added a separate, optional, reproducible URL ML training/evaluation/prediction pipeline using a synthetic versioned dataset, Logistic Regression, scaling, metrics, confusion matrix, and local model persistence. ML remains a separate signal from the rule-based risk score.

## Phase 11 — Streamlit Dashboard
**Completed.** Added a local Streamlit presentation layer for URL/email analysis, explainable findings, IOC matches, and SQLite analysis history. The dashboard reuses the core services and does not fetch submitted URLs or send content externally.

## Phase 12 — Report Generation
Implement JSON, CSV, HTML, and TXT output.

## Phase 13 — Testing + Security Review
Expand automated tests and perform a defensive secure-code review.

## Phase 14 — README + Documentation + Architecture Diagram
Polish the repository for portfolio use.

## Phase 15 — Final GitHub Audit + Interview Preparation
Audit the repository and prepare project explanations, technical questions, resume bullets, and LinkedIn content.
