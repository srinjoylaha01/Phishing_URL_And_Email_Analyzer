import pytest
from phishguard.features.url_features import extract_url_features, parse_url

def test_https_url_features() -> None:
    features = extract_url_features('https://portal.example.com/account/login?next=%2Fhome')
    assert features.scheme == 'https'
    assert features.hostname == 'portal.example.com'
    assert features.subdomain_count == 1
    assert features.query_parameter_count == 1
    assert features.has_encoded_characters is True
    assert 'login' in features.suspicious_keywords
    assert features.is_https is True

def test_ip_address_detection() -> None:
    features = extract_url_features('http://192.0.2.10/login')
    assert features.has_ip_address is True

def test_at_symbol_detection() -> None:
    features = extract_url_features('https://user@example.com/login')
    assert features.has_at_symbol is True

def test_subdomain_count() -> None:
    features = extract_url_features('https://a.b.example-site.com/verify')
    assert features.subdomain_count == 2
    assert features.dot_count == 3
    assert features.hyphen_count == 1

def test_ipv6_detection() -> None:
    features = extract_url_features('https://[2001:db8::1]/login')
    assert features.has_ip_address is True

@pytest.mark.parametrize('url', ['', 'example.com', 'ftp://example.com/file', 'https://', 'https://example.com/a b'])
def test_invalid_urls_are_rejected(url: str) -> None:
    with pytest.raises((TypeError, ValueError)):
        parse_url(url)

def test_malformed_port_is_rejected() -> None:
    with pytest.raises(ValueError):
        parse_url('https://example.com:not-a-port/')