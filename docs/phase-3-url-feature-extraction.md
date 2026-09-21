# Phase 3 — URL Parser & Feature Extraction

## Objective
Implement the first functional security-analysis component: a reusable, deterministic URL parser and feature extractor.

## Security Design
Phase 3 performs no DNS lookup, HTTP request, redirect following, TLS inspection, or external reputation lookup. The submitted URL is treated as data.

## Extracted Features
- scheme
- hostname
- port
- path
- query
- fragment
- URL length
- hostname length
- path length
- dot count
- hyphen count
- subdomain count
- query parameter count
- IP-address indicator
- @-symbol indicator
- encoded-character indicator
- suspicious keywords
- HTTPS indicator

## Design Decision
The feature extractor is separate from the future detection engine. Phase 3 identifies observable URL characteristics; later phases decide which configured security rules are triggered.

## Testing
Coverage includes HTTPS parsing, IPv4/IPv6 detection, @ detection, subdomain counting, character counting, encoding detection, suspicious keywords, malformed URLs, and malformed ports.

## Limitations
This phase does not determine whether a URL is malicious. HTTPS, keywords, IP addresses, and URL length are features rather than verdicts. Punycode, redirects, domain age, and reputation are deferred to later phases.