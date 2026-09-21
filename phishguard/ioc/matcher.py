"""Deterministic local IOC matching for PhishGuard."""
from __future__ import annotations
from dataclasses import dataclass
from urllib.parse import urlsplit
from phishguard.ioc.models import IOC

@dataclass(frozen=True)
class IOCMatch:
    """A local indicator matched against an extracted value."""
    indicator: IOC
    observed_value: str

    @property
    def explanation(self) -> str:
        return f"Observed {self.indicator.ioc_type} matched local IOC from source '{self.indicator.source}'."

def _normalize_domain(value: str) -> str:
    return value.strip().lower().rstrip(".")

def _url_domain(value: str) -> str | None:
    try:
        return urlsplit(value).hostname
    except ValueError:
        return None

def match_ioc_values(values: dict[str, list[str] | tuple[str, ...]], indicators: list[IOC]) -> list[IOCMatch]:
    """Match normalized IOCs against caller-supplied values."""
    matches: list[IOCMatch] = []
    for indicator in indicators:
        candidates = values.get(indicator.ioc_type, ())
        normalized_ioc = indicator.value.strip().lower().rstrip(".")
        for observed in candidates:
            observed_value = str(observed).strip()
            normalized_observed = observed_value.lower().rstrip(".")
            if indicator.ioc_type == "domain":
                hostname = _normalize_domain(_url_domain(observed_value) or observed_value)
                matched = hostname == normalized_ioc or hostname.endswith("." + normalized_ioc)
            else:
                matched = normalized_observed == normalized_ioc
            if matched:
                matches.append(IOCMatch(indicator, observed_value))
    return matches
