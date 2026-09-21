# Phase 7 — IOC Database + Threat Intelligence

## Goal

Add a small, local indicator-of-compromise (IOC) workflow while keeping external threat-intelligence enrichment optional and disabled by default.

## What was added

- phishguard/ioc/models.py — validated IOC model.
- phishguard/ioc/store.py — JSON-backed local IOC store.
- phishguard/ioc/matcher.py — deterministic exact/subdomain matching.
- phishguard/ioc/enrichment.py — provider interface and safe no-op provider.
- data/iocs.example.json — synthetic/reserved example indicators.
- tests/test_ioc.py — IOC storage, matching, and no-op enrichment tests.

## IOC types

The local workflow supports domain, url, ip, and email indicators.

Domain indicators match the hostname exactly or a subdomain of the indicator. URL, IP, and email indicators use normalized exact matching.

## Threat-intelligence boundary

Phase 7 does not make network requests. NoOpThreatIntelProvider is the default safe implementation. A future provider can implement ThreatIntelProvider behind explicit configuration and credentials.

No API key, external service, suspicious URL, or submitted email is contacted by this phase.

## Relationship to risk scoring

IOC matches are returned as structured IOCMatch objects. They are not automatically assigned risk points yet, keeping threat-intelligence evidence separate from the existing rule-based score until later application/reporting integration.

## Security notes

- No IOC is visited or resolved.
- No DNS lookup is performed.
- No automatic interaction with external services occurs.
- Example indicators use reserved/synthetic values.
- External credentials belong in environment variables when a provider is added later.

## Next phase

Phase 8 will add SQLite persistence for analysis history, features, findings, and IOC matches. The JSON IOC store is intentionally a simple local IOC source and is not a replacement for Phase 8 persistence.
