"""High-level email analysis entry point."""
from __future__ import annotations

from phishguard.features.email_features import EmailFeatures, extract_email_features

def analyze_email(content: str) -> EmailFeatures:
    """Parse and analyze an email without sending or contacting any network service."""
    return extract_email_features(content)
