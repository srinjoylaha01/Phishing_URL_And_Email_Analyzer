from pathlib import Path

import pytest

pytest.importorskip("streamlit")

from dashboard.app import _risk_counts


def test_risk_counts():
    history = [
        {"risk_level": "LOW"},
        {"risk_level": "HIGH"},
        {"risk_level": "HIGH"},
        {"risk_level": "CRITICAL"},
        {"risk_level": "UNKNOWN"},
    ]
    assert _risk_counts(history) == {"LOW": 1, "MEDIUM": 0, "HIGH": 2, "CRITICAL": 1}
