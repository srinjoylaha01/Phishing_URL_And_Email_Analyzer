from phishguard.analyzers.email_analyzer import analyze_email

SAMPLE_EMAIL = """From: Security Team <alerts@example.com>
Reply-To: helpdesk@reply-example.net
Subject: Urgent action required - verify your account

Hello,
Your account will be suspended within 24 hours. Please login and verify your password.
Visit https://example.com/login and https://account-check.example.net/verify.
"""

def test_email_headers_and_urls_are_extracted() -> None:
    features = analyze_email(SAMPLE_EMAIL)
    assert features.sender_email == "alerts@example.com"
    assert features.sender_domain == "example.com"
    assert features.reply_to_domain == "reply-example.net"
    assert "https://example.com/login" in features.urls
    assert "https://account-check.example.net/verify" in features.urls

def test_email_risk_relevant_indicators_are_extracted() -> None:
    features = analyze_email(SAMPLE_EMAIL)
    assert "urgent" in features.urgency_terms
    assert "within 24 hours" in features.urgency_terms
    assert "password" in features.credential_requests
    assert features.reply_to_domain_mismatch is True
    assert features.sender_domain_url_mismatches == ("account-check.example.net",)

def test_attachments_and_html_are_detected() -> None:
    content = """From: Billing <billing@example.com>
Subject: Invoice
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="x"

--x
Content-Type: text/html

<form action="https://example.com">
<input name="password">
</form>
--x
Content-Type: application/pdf
Content-Disposition: attachment; filename="invoice.pdf"

fake
--x--
"""
    features = analyze_email(content)
    assert features.suspicious_html is True
    assert features.attachment_names == ("invoice.pdf",)

def test_invalid_email_content_is_rejected() -> None:
    try:
        analyze_email("")
    except ValueError as exc:
        assert "must not be empty" in str(exc)
    else:
        raise AssertionError("Expected ValueError")
