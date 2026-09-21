# Phase 9 — CLI Application

## Objective
Expose URL/email analysis, scoring, IOC matching, and SQLite history through a clean terminal interface.

## Commands
- analyze-url "http://192.0.2.10/login"
- analyze-email --text "From: Team <team@example.com>\nSubject: Meeting\n\nHello"
- analyze-email --file samples/message.eml
- analyze-email with email content piped through stdin
- history --limit 20
- show 1

## CLI behavior
- Analysis commands print a compact terminal summary.
- Findings include rule ID, severity, points, and evidence.
- Risk output includes bounded score, raw score, and actionable flag.
- Local IOC matches are displayed when present.
- Results are persisted through the Phase 8 SQLite repository.
- Errors are sent to stderr and return non-zero exit codes.
- User-provided URLs are parsed locally and never visited.

## Safety boundary
The CLI does not send email, submit credentials, execute attachments, resolve domains, fetch URLs, or perform external threat-intelligence lookups.

JSON/CSV/HTML/TXT reporting remains Phase 12. Streamlit remains Phase 11. Machine learning remains Phase 10.
