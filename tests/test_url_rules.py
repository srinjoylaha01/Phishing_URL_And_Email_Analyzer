from phishguard.detection.url_rules import analyze_url_rules
from phishguard.features.url_features import extract_url_features

def rule_ids(url: str) -> set[str]:
    return {f.rule_id for f in analyze_url_rules(extract_url_features(url))}

def test_ip_rule() -> None:
    assert 'RULE-001' in rule_ids('http://192.0.2.10/login')

def test_long_url_rule() -> None:
    assert 'RULE-002' in rule_ids('https://example.com/' + 'a' * 125)

def test_subdomain_rule() -> None:
    assert 'RULE-003' in rule_ids('https://a.b.c.example.com/login')

def test_keyword_rule() -> None:
    assert 'RULE-004' in rule_ids('https://example.com/account/login')

def test_at_symbol_rule() -> None:
    assert 'RULE-005' in rule_ids('https://user@example.com/login')

def test_punycode_rule() -> None:
    assert 'RULE-006' in rule_ids('https://xn--example-dk9c.com/login')

def test_clean_url_has_no_url_rule_findings() -> None:
    assert analyze_url_rules(extract_url_features('https://example.com/')) == []
