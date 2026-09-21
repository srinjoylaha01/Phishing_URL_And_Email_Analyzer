"""Generic rule evaluation engine for PhishGuard."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Callable

@dataclass(frozen=True)
class DetectionRule:
    rule_id: str
    description: str
    severity: str
    points: int
    explanation: str
    recommendation: str
    evaluator: Callable[[Any], bool]

@dataclass(frozen=True)
class DetectionFinding:
    rule_id: str
    description: str
    severity: str
    points: int
    evidence: str
    explanation: str
    recommendation: str

class RuleEngine:
    def __init__(self, rules: tuple[DetectionRule, ...]) -> None:
        self._rules = rules

    def evaluate(self, target: Any) -> list[DetectionFinding]:
        findings = []
        for rule in self._rules:
            try:
                matched = rule.evaluator(target)
            except (AttributeError, TypeError, ValueError):
                matched = False
            if matched:
                findings.append(DetectionFinding(
                    rule_id=rule.rule_id, description=rule.description,
                    severity=rule.severity, points=rule.points,
                    evidence=_build_evidence(rule.rule_id, target),
                    explanation=rule.explanation, recommendation=rule.recommendation,
                ))
        return findings

def _build_evidence(rule_id: str, target: Any) -> str:
    evidence = {
        'RULE-001': f'hostname={target.hostname}',
        'RULE-002': f'url_length={target.url_length}',
        'RULE-003': f'subdomain_count={target.subdomain_count}',
        'RULE-004': f'suspicious_keywords={", ".join(target.suspicious_keywords)}',
        'RULE-005': 'at_symbol_present=true',
        'RULE-006': f'hostname={target.hostname}',
    }
    return evidence.get(rule_id, 'configured rule condition matched')
