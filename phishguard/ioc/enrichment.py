"""Threat-intelligence enrichment interfaces for PhishGuard."""
from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol

@dataclass(frozen=True)
class ThreatIntelResult:
    indicator: str
    found: bool
    source: str
    confidence: int | None = None
    summary: str = ""

class ThreatIntelProvider(Protocol):
    def lookup(self, indicator: str) -> ThreatIntelResult:
        """Look up an indicator using a provider-specific implementation."""

class NoOpThreatIntelProvider:
    """Safe default provider that never performs network activity."""
    def lookup(self, indicator: str) -> ThreatIntelResult:
        return ThreatIntelResult(
            indicator=indicator,
            found=False,
            source="disabled",
            summary="External threat-intelligence enrichment is disabled.",
        )
