"""URL analysis orchestration."""
from phishguard.features.url_features import URLFeatures, extract_url_features

def analyze_url(url: str) -> URLFeatures:
    """Analyze a submitted URL without contacting its destination."""
    return extract_url_features(url)