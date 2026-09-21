# Phase 8 — SQLite Database + Analysis History

## Objective

Persist PhishGuard analysis results locally so later CLI, dashboard, and reporting layers can reuse historical data.

## Database design

Phase 8 uses Python's standard-library sqlite3; no additional runtime dependency is required.

### Tables

- analyses — metadata, timestamp, input SHA-256, score, raw score, and risk level.
- url_features — normalized URL feature set.
- email_features — normalized email feature set.
- detections — triggered rules and evidence.
- iocs — local IOC records referenced by persisted matches.
- ioc_matches — relationship between an analysis and an IOC.

Foreign keys and indexes are enabled.

## Repository API

AnalysisRepository provides save_url_analysis(...), save_email_analysis(...), list_history(limit=50), and get_analysis(analysis_id).

All application values are passed through parameterized SQL statements.

## Data handling

- Raw input is not stored in analyses; only a SHA-256 fingerprint is retained there.
- URL/email feature tables contain extracted analysis data for later presentation.
- No URL is fetched and no email is sent.
- SQLite persistence is local and offline.
- IOC records are stored only when an IOC match is persisted.

## Next phase

Phase 9 will expose these capabilities through the user-facing CLI.
