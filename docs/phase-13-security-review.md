# Phase 13 — Testing + Security Review

## Automated testing

Phase 13 expands the test suite around:

- CLI command registration and report export.
- URL parsing and the no-network parsing boundary.
- Email parsing and attachment handling.
- SQLite history validation.
- Report format validation and HTML escaping.
- Existing URL/email detection, IOC, risk-scoring, ML, and dashboard behavior.

Run the test suite with:

    python -m pip install -e ".[dev]"
    pytest

Optional modules are skipped when their dependencies are unavailable.

## Security review

The review is focused on the project's defensive, local-only design.

### Findings

**No high-severity issue identified in the reviewed project paths.**

Controls verified in source:

1. **No submitted URL fetching** — URL feature extraction uses parsing utilities and does not open network connections.
2. **No attachment execution** — email parsing records attachment names without executing or extracting them.
3. **Parameterized SQL** — repository writes and reads use SQLite parameters rather than string interpolation.
4. **HTML output escaping** — report values derived from analysis data are escaped before insertion into HTML.
5. **Local IOC matching** — the default IOC workflow uses a local JSON store and a no-op external enrichment provider.
6. **No hardcoded secrets** — project configuration uses an example environment file and does not require credentials for core analysis.
7. **Input validation** — URL schemes, URL structure, report formats, history limits, and risk-score boundaries are validated.
8. **ML isolation** — the optional ML signal remains separate from the rule-based risk score.
9. **Local persistence** — the application does not send analyzed URLs or email content to external services by default.

### Residual considerations

- The email registrable-domain comparison is intentionally a lightweight heuristic and is not a full public-suffix implementation.
- HTML reports are intended for local use; users should still treat exported reports as untrusted files if they are copied to other systems.
- Optional ML predictions are model outputs, not proof that a URL is malicious.
- Future external threat-intelligence integrations must preserve explicit timeouts, authentication handling, response validation, and network isolation boundaries.

## CI

A GitHub Actions workflow runs the core test suite on pushes and pull requests. It installs the development dependency set and executes pytest.

## Scope

This review is a defensive code review, not a formal penetration test, malware analysis, or third-party security audit.
