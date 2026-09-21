"""Transparent risk scoring for PhishGuard findings."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from phishguard.detection.rule_engine import DetectionFinding

LOW_MAX = 19
MEDIUM_MAX = 39
HIGH_MAX = 69

@dataclass(frozen=True)
class RiskAssessment:
    """Bounded risk assessment derived only from triggered findings."""
    raw_score: int
    score: int
    level: str
    finding_count: int

    @property
    def is_actionable(self) -> bool:
        return self.level in {"HIGH", "CRITICAL"}

def classify_score(score: int) -> str:
    """Map a 0-100 score to the documented risk band."""
    if not 0 <= score <= 100:
        raise ValueError("Risk score must be between 0 and 100")
    if score <= LOW_MAX:
        return "LOW"
    if score <= MEDIUM_MAX:
        return "MEDIUM"
    if score <= HIGH_MAX:
        return "HIGH"
    return "CRITICAL"

def calculate_risk(findings: Iterable[DetectionFinding]) -> RiskAssessment:
    """Aggregate finding points and clamp the displayed score to 0-100."""
    items = list(findings)
    raw_score = sum(max(0, int(finding.points)) for finding in items)
    score = min(raw_score, 100)
    return RiskAssessment(
        raw_score=raw_score,
        score=score,
        level=classify_score(score),
        finding_count=len(items),
    )
