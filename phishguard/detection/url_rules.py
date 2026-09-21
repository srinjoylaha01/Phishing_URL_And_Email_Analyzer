"""URL phishing detection rules."""
from __future__ import annotations
from phishguard.detection.rule_engine import DetectionRule, RuleEngine
from phishguard.features.url_features import URLFeatures

def _has_suspicious_keywords(features: URLFeatures) -> bool:
    return bool(features.suspicious_keywords)

def _has_punycode(features: URLFeatures) -> bool:
    return bool(features.hostname and 'xn--' in features.hostname.lower())

def build_url_rules() -> tuple[DetectionRule, ...]:
    return (
        DetectionRule('RULE-001', 'IP address used as hostname', 'HIGH', 25,
            'The submitted URL uses an IP address instead of a conventional hostname.',
            'Verify the destination independently before entering sensitive information.',
            lambda f: f.has_ip_address),
        DetectionRule('RULE-002', 'Suspicious URL length', 'LOW', 5,
            'An unusually long URL can make inspection difficult and may conceal suspicious parameters.',
            'Inspect the complete URL and verify its destination through a trusted source.',
            lambda f: f.url_length > 120),
        DetectionRule('RULE-003', 'Excessive subdomains', 'MEDIUM', 10,
            'Multiple subdomain levels can make a hostname harder to interpret.',
            'Identify the registrable domain and independently verify the organization.',
            lambda f: f.subdomain_count >= 3),
        DetectionRule('RULE-004', 'Suspicious keyword in hostname or path', 'MEDIUM', 10,
            'The URL contains a security-sensitive keyword that can occur in phishing lures.',
            'Confirm that the domain and requested action are legitimate before proceeding.',
            _has_suspicious_keywords),
        DetectionRule('RULE-005', 'URL contains @ symbol', 'HIGH', 20,
            'An @ symbol in URL authority can obscure the actual hostname from a casual reader.',
            'Inspect the parsed hostname rather than trusting the visible beginning of the URL.',
            lambda f: f.has_at_symbol),
        DetectionRule('RULE-006', 'Punycode/IDN indicator', 'MEDIUM', 10,
            'An xn-- hostname indicates an internationalized domain representation that warrants inspection.',
            'Verify the domain using a trusted source and inspect for look-alike characters.',
            _has_punycode),
    )

def analyze_url_rules(features: URLFeatures):
    return RuleEngine(build_url_rules()).evaluate(features)
