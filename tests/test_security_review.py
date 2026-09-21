from pathlib import Path

import pytest

from phishguard.database.repository import AnalysisRepository
from phishguard.features.email_features import extract_email_features
from phishguard.features.url_features import extract_url_features
from phishguard.reporting.report import render_report


def test_url_parser_never_performs_network_access(monkeypatch):
    import socket

    def blocked(*args, **kwargs):
        raise AssertionError("network access must not occur during URL parsing")

    monkeypatch.setattr(socket, "create_connection", blocked)
    features = extract_url_features("https://example.com/login")
    assert features.hostname == "example.com"


def test_email_parser_does_not_execute_attachment(tmp_path: Path):
    content = """From: Example <alerts@example.com>
Subject: Invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="x"

--x
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.exe"

not executable
--x--
"""
    features = extract_email_features(content)
    assert features.attachment_names == ("invoice.exe",)
    assert not (tmp_path / "invoice.exe").exists()


def test_repository_rejects_invalid_history_limit(tmp_path: Path):
    repository = AnalysisRepository(tmp_path / "history.db")
    for value in (0, 501):
        with pytest.raises(ValueError):
            repository.list_history(value)


def test_html_report_escapes_analysis_derived_values():
    record = {
        "analysis": {
            "id": 1,
            "created_at": "now",
            "analysis_type": "url",
            "input_sha256": "hash",
            "risk_score": 0,
            "raw_score": 0,
            "risk_level": "LOW",
        },
        "findings": [{
            "rule_id": "<script>",
            "severity": "LOW",
            "points": 1,
            "description": "<img src=x onerror=alert(1)>",
            "evidence": "x",
            "recommendation": "y",
        }],
        "ioc_matches": [],
    }
    output = render_report(record, "html")
    assert "&lt;script&gt;" in output
    assert "&lt;img" in output
    assert "<img src=x onerror=alert(1)>" not in output


def test_report_rejects_unknown_format():
    with pytest.raises(ValueError):
        render_report({
            "analysis": {},
            "findings": [],
            "ioc_matches": [],
        }, "xml")
