from pathlib import Path

from phishguard.database.repository import AnalysisRepository
from phishguard.detection.email_rules import analyze_email_rules
from phishguard.detection.url_rules import analyze_url_rules
from phishguard.features.email_features import extract_email_features
from phishguard.features.url_features import extract_url_features
from phishguard.ioc.matcher import match_ioc_values
from phishguard.ioc.models import IOC
from phishguard.scoring.risk_score import calculate_risk

def test_url_analysis_is_persisted(tmp_path: Path) -> None:
    repository = AnalysisRepository(tmp_path / "history.db")
    features = extract_url_features("http://192.0.2.10/login")
    findings = analyze_url_rules(features)
    assessment = calculate_risk(findings)
    indicator = IOC("192.0.2.10", "ip", "test", 90)
    matches = match_ioc_values({"ip": (features.hostname,)}, [indicator])

    analysis_id = repository.save_url_analysis(
        features.original_url, features, findings, assessment, matches
    )
    record = repository.get_analysis(analysis_id)

    assert record is not None
    assert record["analysis"]["analysis_type"] == "url"
    assert record["analysis"]["risk_score"] == 35
    assert len(record["findings"]) == 2
    assert len(record["ioc_matches"]) == 1

def test_email_analysis_and_history_are_persisted(tmp_path: Path) -> None:
    repository = AnalysisRepository(tmp_path / "history.db")
    content = """From: Security Team <alerts@example.com>
Reply-To: helpdesk@reply-example.net
Subject: Urgent action required

Please verify your password and make a payment.
"""
    features = extract_email_features(content)
    findings = analyze_email_rules(features)
    assessment = calculate_risk(findings)

    analysis_id = repository.save_email_analysis(content, features, findings, assessment)
    history = repository.list_history()

    assert history[0]["id"] == analysis_id
    assert history[0]["analysis_type"] == "email"
    assert history[0]["risk_level"] in {"HIGH", "CRITICAL"}

def test_database_uses_parameterized_values(tmp_path: Path) -> None:
    repository = AnalysisRepository(tmp_path / "history.db")
    features = extract_url_features("https://example.com/?q='; DROP TABLE analyses;--")
    findings = analyze_url_rules(features)
    assessment = calculate_risk(findings)

    repository.save_url_analysis(features.original_url, features, findings, assessment)
    assert repository.list_history()
