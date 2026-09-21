"""Reusable URL parsing and feature extraction for PhishGuard."""
from __future__ import annotations
import ipaddress
import re
from dataclasses import asdict, dataclass
from urllib.parse import parse_qsl, unquote, urlsplit

SUSPICIOUS_KEYWORDS = frozenset({
    "account", "authenticate", "bank", "billing", "confirm", "credential",
    "invoice", "login", "password", "payment", "recover", "secure", "signin",
    "support", "unlock", "verify",
})
ENCODED_PATTERN = re.compile(r"%[0-9A-Fa-f]{2}")

@dataclass(frozen=True)
class URLFeatures:
    """Normalized features extracted from a submitted URL."""
    original_url: str
    scheme: str
    hostname: str | None
    port: int | None
    path: str
    query: str
    fragment: str
    url_length: int
    hostname_length: int
    path_length: int
    dot_count: int
    hyphen_count: int
    subdomain_count: int
    query_parameter_count: int
    has_ip_address: bool
    has_at_symbol: bool
    has_encoded_characters: bool
    suspicious_keywords: tuple[str, ...]
    is_https: bool

    def to_dict(self) -> dict[str, object]:
        """Return a JSON-friendly representation."""
        return asdict(self)

def parse_url(url: str):
    """Parse a URL after basic validation without network access."""
    if not isinstance(url, str):
        raise TypeError("URL must be a string")
    value = url.strip()
    if not value:
        raise ValueError("URL must not be empty")
    if any(char.isspace() for char in value):
        raise ValueError("URL must not contain whitespace")
    parsed = urlsplit(value)
    if not parsed.scheme:
        raise ValueError("URL must include a scheme, for example https://")
    if parsed.scheme.lower() not in {"http", "https"}:
        raise ValueError("Unsupported URL scheme; expected http or https")
    if not parsed.netloc:
        raise ValueError("URL must include a hostname")
    _ = parsed.port
    if parsed.hostname is None:
        raise ValueError("URL must include a hostname")
    return parsed

def _is_ip_address(hostname: str | None) -> bool:
    if not hostname:
        return False
    candidate = hostname.strip("[]")
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return False
    return True

def _subdomain_count(hostname: str | None) -> int:
    if not hostname or _is_ip_address(hostname):
        return 0
    labels = [label for label in hostname.split('.') if label]
    return max(len(labels) - 2, 0)

def _suspicious_keywords(value: str) -> tuple[str, ...]:
    normalized = unquote(value).lower()
    found = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if re.search(
        rf'(?<![a-z0-9]){re.escape(keyword)}(?![a-z0-9])', normalized
    ))
    return tuple(found)

def extract_url_features(url: str) -> URLFeatures:
    """Extract deterministic, non-network URL features."""
    parsed = parse_url(url)
    hostname = parsed.hostname.lower() if parsed.hostname else None
    path_and_query = f'{parsed.path}?{parsed.query}' if parsed.query else parsed.path
    return URLFeatures(
        original_url=url.strip(), scheme=parsed.scheme.lower(), hostname=hostname,
        port=parsed.port, path=parsed.path, query=parsed.query, fragment=parsed.fragment,
        url_length=len(url.strip()), hostname_length=len(hostname or ''),
        path_length=len(parsed.path), dot_count=(hostname or '').count('.'),
        hyphen_count=(hostname or '').count('-'), subdomain_count=_subdomain_count(hostname),
        query_parameter_count=len(parse_qsl(parsed.query, keep_blank_values=True)),
        has_ip_address=_is_ip_address(hostname), has_at_symbol='@' in parsed.netloc,
        has_encoded_characters=bool(ENCODED_PATTERN.search(url)),
        suspicious_keywords=_suspicious_keywords(path_and_query),
        is_https=parsed.scheme.lower() == 'https',
    )