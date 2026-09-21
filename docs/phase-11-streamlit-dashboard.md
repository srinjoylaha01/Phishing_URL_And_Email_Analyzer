# Phase 11 — Streamlit Dashboard

## Objective
Provide a local web UI over the existing PhishGuard analysis services without changing the core detection or scoring logic.

## Dashboard sections
- **URL Analyzer** — submit a URL, display extracted features, rule findings, risk score, and local IOC matches.
- **Email Analyzer** — paste RFC-style email content, display email indicators, rule findings, risk score, and local IOC matches.
- **History** — view recent SQLite analyses and risk-level counts.

## Run locally

Install the dashboard extra:

    python -m pip install -e ".[dashboard]"

Start Streamlit:

    streamlit run dashboard/app.py

The application uses the same local database and IOC file as the CLI by default:

- data/phishguard.db
- data/iocs.example.json

## Safety boundary

The dashboard does not fetch, resolve, crawl, or open submitted URLs. It does not send email content to external services, execute attachments, or perform active scanning. All analysis remains local.

## Architecture

    Streamlit UI
        |
        +--> URL / Email Feature Extraction
        |          |
        |          +--> Detection Rules --> Risk Score
        |          |
        |          +--> Local IOC Matching
        |
        +--> SQLite History

The dashboard is a presentation layer; the existing CLI, analyzers, rule engine, IOC matcher, and repository remain reusable independently.
