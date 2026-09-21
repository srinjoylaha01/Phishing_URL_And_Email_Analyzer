"""Email phishing detection rules."""
from __future__ import annotations

from phishguard.detection.rule_engine import DetectionRule, RuleEngine
from phishguard.features.email_features import EmailFeatures

def build_email_rules() -> tuple[DetectionRule, ...]:
    return (
        DetectionRule(
            "RULE-007", "Urgency language in email", "MEDIUM", 10,
            "The message contains language commonly used to pressure recipients into immediate action.",
            "Verify the request through an independent trusted channel.",
            lambda f: bool(f.urgency_terms),
        ),
        DetectionRule(
            "RULE-008", "Credential-related request", "HIGH", 15,
            "The message requests or references credentials, passwords, or account verification.",
            "Do not disclose credentials from an unsolicited message; use the official service directly.",
            lambda f: bool(f.credential_requests),
        ),
        DetectionRule(
            "RULE-009", "Financial-related request", "HIGH", 15,
            "The message contains financial or payment-related request language.",
            "Verify financial requests independently before taking action.",
            lambda f: bool(f.financial_requests),
        ),
        DetectionRule(
            "RULE-010", "Reply-To domain mismatch", "HIGH", 15,
            "The Reply-To domain differs from the sender domain at the registrable-domain level.",
            "Verify the sender and reply destination independently.",
            lambda f: f.reply_to_domain_mismatch,
        ),
        DetectionRule(
            "RULE-011", "Sender domain versus URL domain mismatch", "HIGH", 15,
            "A URL in the message uses a different registrable domain from the sender.",
            "Inspect the destination domain and verify it through a trusted source.",
            lambda f: bool(f.sender_domain_url_mismatches),
        ),
        DetectionRule(
            "RULE-012", "Suspicious HTML element", "MEDIUM", 10,
            "The message HTML contains elements that can be used for deceptive interaction.",
            "Treat embedded forms or scripts as untrusted and verify the destination separately.",
            lambda f: f.suspicious_html,
        ),
        DetectionRule(
            "RULE-013", "Attachment present", "LOW", 5,
            "The message contains an attachment filename that should be treated as untrusted input.",
            "Do not open unexpected attachments; verify the sender and attachment purpose first.",
            lambda f: bool(f.attachment_names),
        ),
        DetectionRule(
            "RULE-014", "Display-name/email mismatch", "LOW", 5,
            "The sender display name does not align with the sender email address.",
            "Inspect the complete sender address rather than relying on the display name.",
            lambda f: f.display_name_email_mismatch,
        ),
    )

def analyze_email_rules(features: EmailFeatures):
    return RuleEngine(build_email_rules()).evaluate(features)
