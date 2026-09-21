# Phase 4 — URL Phishing Detection Rules

## Objective
Convert Phase 3 URL observations into transparent security findings.

## Detection Model
Phase 3 extracts facts. Phase 4 evaluates rules against those facts.
The engine does not declare a URL malicious. A finding means a documented indicator was observed and should be investigated in context.

## Implemented Rules
| Rule | Condition | Severity | Points |
|---|---|---|---:|
| RULE-001 | IP address used as hostname | HIGH | 25 |
| RULE-002 | URL length greater than 120 characters | LOW | 5 |
| RULE-003 | At least 3 subdomain levels | MEDIUM | 10 |
| RULE-004 | Suspicious security-related keyword | MEDIUM | 10 |
| RULE-005 | @ symbol in URL authority | HIGH | 20 |
| RULE-006 | Punycode/IDN hostname indicator | MEDIUM | 10 |

## Finding Structure
Every triggered rule produces Rule ID, description, severity, points, evidence, explanation, and recommendation.

## Security Properties
The engine consumes extracted data only. It performs no DNS resolution, HTTP requests, redirect following, command execution, credential submission, or destination scanning.

## Current Limitations
Sender/Reply-To rules, financial requests, attachment rules, reputation APIs, domain age, redirect analysis, and risk-score aggregation are deferred to later phases.
