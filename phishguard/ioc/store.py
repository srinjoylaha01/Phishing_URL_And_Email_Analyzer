"""Local JSON IOC store for PhishGuard."""
from __future__ import annotations
import json
from pathlib import Path
from phishguard.ioc.models import IOC

class IOCStore:
    """Read and write a small local IOC collection without network access."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)

    def load(self) -> list[IOC]:
        if not self.path.exists():
            return []
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValueError(f"Unable to read IOC store: {self.path}") from exc
        if not isinstance(data, list):
            raise ValueError("IOC store must contain a JSON array")
        indicators = []
        for item in data:
            if not isinstance(item, dict):
                raise ValueError("Each IOC entry must be a JSON object")
            indicators.append(IOC(
                value=str(item["value"]),
                ioc_type=item["ioc_type"],
                source=str(item.get("source", "local")),
                confidence=int(item.get("confidence", 50)),
                description=str(item.get("description", "")),
            ))
        return indicators

    def save(self, indicators: list[IOC]) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = [indicator.to_dict() for indicator in indicators]
        self.path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")

    def add(self, indicator: IOC) -> None:
        indicators = self.load()
        key = (indicator.ioc_type, indicator.value.strip().lower())
        if any((item.ioc_type, item.value.strip().lower()) == key for item in indicators):
            return
        indicators.append(indicator)
        self.save(indicators)
