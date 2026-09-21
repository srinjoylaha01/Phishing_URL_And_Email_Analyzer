from pathlib import Path

from phishguard.ioc.enrichment import NoOpThreatIntelProvider
from phishguard.ioc.matcher import match_ioc_values
from phishguard.ioc.models import IOC
from phishguard.ioc.store import IOCStore

def test_ioc_store_round_trip(tmp_path: Path) -> None:
    path = tmp_path / "iocs.json"
    store = IOCStore(path)
    indicator = IOC("login-example.invalid", "domain", "test", 90)
    store.add(indicator)
    assert store.load() == [indicator]

def test_domain_ioc_matches_subdomain() -> None:
    indicator = IOC("example.invalid", "domain")
    matches = match_ioc_values({"domain": ("login.example.invalid", "safe.invalid")}, [indicator])
    assert [match.observed_value for match in matches] == ["login.example.invalid"]

def test_url_ioc_is_exact() -> None:
    indicator = IOC("https://login.example.invalid/verify", "url")
    matches = match_ioc_values({"url": ("https://login.example.invalid/verify",)}, [indicator])
    assert len(matches) == 1

def test_noop_provider_does_not_enrich() -> None:
    result = NoOpThreatIntelProvider().lookup("example.invalid")
    assert result.found is False
    assert result.source == "disabled"
