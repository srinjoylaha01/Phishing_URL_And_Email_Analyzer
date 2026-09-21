# Phase 5 — Email Parser + Email Analysis

## Objective

Phase 5 adds deterministic parsing and feature extraction for .eml-style content and pasted email text. It does not send email, open links, resolve domains, download attachments, or contact external services.

## What is extracted

- Sender display name, sender address, and sender domain
- Reply-To address and domain
- Subject and text body
- URLs and URL domains
- Security-sensitive keywords
- Urgency language
- Credential-related requests
- Financial-related requests
- Attachment filenames
- Suspicious HTML indicators such as forms, inputs, iframes, scripts, and javascript:
- Reply-To versus sender-domain mismatch
- Sender-domain versus URL-domain mismatches

## Safety boundary

The parser treats email content as untrusted input. URL extraction is text-only. Extracted URLs are not visited and attachments are not opened.

## Design

phishguard/features/email_features.py contains parsing and feature-extraction logic. phishguard/analyzers/email_analyzer.py provides the high-level analysis entry point.

Phase 5 intentionally stops before final risk scoring. Features from this phase can be converted into scored detections in later phases.

## Example

    from phishguard.analyzers.email_analyzer import analyze_email

    content = "From: Security Team <alerts@example.com>\nSubject: Verify your account\n\nPlease visit https://example.com/login"
    features = analyze_email(content)
    print(features.to_dict())

The result is deterministic for the same input and requires no network access.
