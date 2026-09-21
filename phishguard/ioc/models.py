"""IOC data models for PhishGuard."""
from __future__ import annotations
from dataclasses import asdict, dataclass
from typing import Literal

IOCType = Literal["domain", "url", "ip", "email"]

@dataclass(frozen=True)
class IOC:
    """A local threat-intelligence indicator."""
    value: str
    ioc_type: IOCType
    source: str = "local"
    confidence: int = 50
    description: str = ""

    def __post_init__(self) -> None:
        if not self.value.strip():
            raise ValueError("IOC value must not be empty")
        if self.ioc_type not in {"domain", "url", "ip", "email"}:
            raise ValueError("Unsupported IOC type")
        if not 0 <= self.confidence <= 100:
            raise ValueError("Confidence must be between 0 and 100")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)
