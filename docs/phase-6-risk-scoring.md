# Phase 6 — Risk Scoring Engine

## Objective

Phase 6 converts individual security findings into one transparent, bounded risk assessment.

## Risk bands

| Score | Level |
|---:|---|
| 0–19 | LOW |
| 20–39 | MEDIUM |
| 40–69 | HIGH |
| 70–100 | CRITICAL |

The displayed score is always capped at 100. The internal raw score is retained so analysts can see when multiple indicators exceed the display range.

## Scoring model

Each detection finding contributes its configured points.

1. Sum all non-negative finding points.
2. Preserve the raw total.
3. Cap the displayed score at 100.
4. Map the displayed score to the documented risk band.

The engine does not claim that an email or URL is malicious. It communicates the number and type of indicators observed.

## Email findings

Phase 6 adds email-specific scored rules for urgency, credential requests, financial requests, Reply-To mismatches, sender/URL domain mismatches, suspicious HTML, attachments, and display-name/email mismatches.

## Safety

Scoring is deterministic and offline. It performs no network requests, DNS lookups, URL visits, attachment execution, credential submission, or external reputation checks.

## Example

    from phishguard.analyzers.url_analyzer import analyze_url
    from phishguard.detection.url_rules import analyze_url_rules
    from phishguard.scoring.risk_score import calculate_risk

    features = analyze_url("http://192.0.2.10/login")
    findings = analyze_url_rules(features)
    assessment = calculate_risk(findings)

    print(assessment.score, assessment.level)

For the example above, the URL feature set triggers the IP-hostname rule and the suspicious-keyword rule, producing a raw score of 35 and a MEDIUM risk band.

## Limitations

The score is a rule-based heuristic, not proof of maliciousness. Reputation, IOC enrichment, persistence, machine learning, reporting, and user interfaces remain separate phases.
