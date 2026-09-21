"""Feature-vector construction for the PhishGuard URL ML model."""
from __future__ import annotations

from phishguard.features.url_features import URLFeatures

FEATURE_NAMES = (
    "url_length", "hostname_length", "path_length", "dot_count", "hyphen_count",
    "subdomain_count", "query_parameter_count", "has_ip_address", "has_at_symbol",
    "has_encoded_characters", "suspicious_keyword_count", "is_https",
)

def url_features_to_vector(features: URLFeatures) -> list[float]:
    """Convert deterministic URL features to the model's numeric vector."""
    return [
        float(features.url_length), float(features.hostname_length), float(features.path_length),
        float(features.dot_count), float(features.hyphen_count), float(features.subdomain_count),
        float(features.query_parameter_count), float(features.has_ip_address),
        float(features.has_at_symbol), float(features.has_encoded_characters),
        float(len(features.suspicious_keywords)), float(features.is_https),
    ]

def training_vector_from_row(row: dict[str, str]) -> list[float]:
    """Convert one CSV training row to the same vector used for inference."""
    return [float(row[name]) for name in FEATURE_NAMES]
