from phishguard.detection.email_rules import analyze_email_rules
from phishguard.features.email_features import extract_email_features

SAMPLE_EMAIL = """From: Security Team <alerts@example.com>
Reply-To: helpdesk@reply-example.net
Subject: Urgent action required

Your account is suspended. Please verify your password and make a payment.
Visit https://account-check.example.net/login
"""

def test_email_rules_detect_multiple_indicators() -> None:
    features = extract_email_features(SAMPLE_EMAIL)
    ids = {finding.rule_id for finding in analyze_email_rules(features)}
    assert {
        "RULE-007", "RULE-008", "RULE-009", "RULE-010", "RULE-011"
    }.issubset(ids)

def test_clean_email_has_no_email_findings() -> None:
    content = """From: Team <team@example.com>
Subject: Meeting

The meeting is at 10 AM.
"""
    features = extract_email_features(content)
    assert analyze_email_rules(features) == []
