from phishguard.detection.url_rules import analyze_url_rules
from phishguard.features.url_features import extract_url_features
from phishguard.scoring.risk_score import calculate_risk, classify_score

def test_documented_risk_boundaries() -> None:
    assert classify_score(0) == "LOW"
    assert classify_score(19) == "LOW"
    assert classify_score(20) == "MEDIUM"
    assert classify_score(39) == "MEDIUM"
    assert classify_score(40) == "HIGH"
    assert classify_score(69) == "HIGH"
    assert classify_score(70) == "CRITICAL"
    assert classify_score(100) == "CRITICAL"

def test_url_findings_are_aggregated() -> None:
    features = extract_url_features("http://192.0.2.10/login")
    assessment = calculate_risk(analyze_url_rules(features))
    assert assessment.raw_score == 35
    assert assessment.score == 35
    assert assessment.level == "MEDIUM"
    assert assessment.finding_count == 2

def test_score_is_capped_at_100() -> None:
    features = extract_url_features(
        "https://user@a.b.c.example.com/account/login/" + "x" * 130
    )
    assessment = calculate_risk(analyze_url_rules(features))
    assert assessment.raw_score > 100
    assert assessment.score == 100
    assert assessment.level == "CRITICAL"

def test_invalid_score_is_rejected() -> None:
    for value in (-1, 101):
        try:
            classify_score(value)
        except ValueError:
            pass
        else:
            raise AssertionError("Expected ValueError")
