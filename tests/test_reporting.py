from phishguard.reporting.report import render_report


def _record():
    return {
        "analysis": {
            "id": 7, "created_at": "2026-09-21T10:00:00+00:00", "analysis_type": "url",
            "input_sha256": "abc123", "risk_score": 40, "raw_score": 40, "risk_level": "HIGH",
        },
        "features": {"hostname": "example.test"},
        "findings": [{
            "rule_id": "RULE-001", "severity": "HIGH", "points": 25,
            "description": "IP address used as hostname", "evidence": "hostname=192.0.2.10",
            "explanation": "Test explanation", "recommendation": "Test recommendation",
        }],
        "ioc_matches": [{
            "ioc_type": "ip", "observed_value": "192.0.2.10", "source": "example",
            "confidence": 90, "description": "Synthetic IOC",
        }],
    }


def test_all_report_formats_include_analysis_identity():
    record = _record()
    for fmt in ("json", "csv", "html", "txt"):
        output = render_report(record, fmt)
        assert "7" in output
        assert "HIGH" in output


def test_json_is_structured():
    import json
    data = json.loads(render_report(_record(), "json"))
    assert data["analysis"]["risk_score"] == 40
    assert data["findings"][0]["rule_id"] == "RULE-001"


def test_html_escapes_untrusted_values():
    record = _record()
    record["findings"][0]["description"] = "<script>alert(1)</script>"
    output = render_report(record, "html")
    assert "&lt;script&gt;" in output
    assert "<script>alert(1)</script>" not in output


def test_unsupported_format_rejected():
    import pytest
    with pytest.raises(ValueError):
        render_report(_record(), "pdf")
