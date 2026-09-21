# Phase 12 — Report Generation

PhishGuard now supports exporting a stored analysis in four portable formats:

- JSON — structured machine-readable report.
- CSV — tabular findings and IOC matches for spreadsheet analysis.
- HTML — standalone browser-readable report with escaped analysis-derived values.
- TXT — concise terminal-friendly report.

## CLI

Use the report command with a stored analysis ID:

    phishguard report 1 --format json --output reports/analysis-1.json
    phishguard report 1 --format csv --output reports/analysis-1.csv
    phishguard report 1 --format html --output reports/analysis-1.html
    phishguard report 1 --format txt --output reports/analysis-1.txt

Use --db when the SQLite database is stored elsewhere.

## Security considerations

Report generation is local-only. It does not open URLs, contact external threat-intelligence services, execute attachments, or send email. HTML output escapes analysis-derived values before inserting them into the document.

Reports contain the analysis input SHA-256 fingerprint rather than the original URL/email input in the top-level analysis record.
