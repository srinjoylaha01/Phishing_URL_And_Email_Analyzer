"""Email parsing and feature extraction for PhishGuard."""
from __future__ import annotations

import re
from dataclasses import asdict, dataclass
from email import policy
from email.parser import Parser
from email.utils import parseaddr
from urllib.parse import urlsplit

EMAIL_PATTERN = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
URL_PATTERN = re.compile(r"https?://[^\s<>'\"]+|www\.[^\s<>'\"]+", re.IGNORECASE)

SUSPICIOUS_KEYWORDS = frozenset({
    "account", "authenticate", "bank", "billing", "confirm", "credential",
    "invoice", "login", "password", "payment", "recover", "secure", "signin",
    "support", "unlock", "verify",
})
URGENCY_TERMS = frozenset({
    "action required", "act now", "immediately", "urgent", "urgently",
    "within 24 hours", "suspend", "suspended", "last warning",
})
CREDENTIAL_TERMS = frozenset({
    "password", "login", "credential", "username", "sign in", "verify your account",
    "confirm your identity",
})
FINANCIAL_TERMS = frozenset({
    "payment", "invoice", "bank account", "credit card", "debit card",
    "wire transfer", "gift card", "billing",
})

@dataclass(frozen=True)
class EmailFeatures:
    """Normalized, non-network features extracted from an email."""
    sender_name: str
    sender_email: str
    sender_domain: str | None
    reply_to_email: str
    reply_to_domain: str | None
    subject: str
    body_text: str
    urls: tuple[str, ...]
    url_domains: tuple[str, ...]
    suspicious_keywords: tuple[str, ...]
    urgency_terms: tuple[str, ...]
    credential_requests: tuple[str, ...]
    financial_requests: tuple[str, ...]
    attachment_names: tuple[str, ...]
    suspicious_html: bool
    display_name_email_mismatch: bool
    reply_to_domain_mismatch: bool
    sender_domain_url_mismatches: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)

def _clean_url(value: str) -> str:
    return value.rstrip(".,;:!?)]}>")

def _extract_urls(text: str) -> tuple[str, ...]:
    urls = []
    for match in URL_PATTERN.findall(text):
        value = _clean_url(match)
        if value.lower().startswith("www."):
            value = "http://" + value
        if value not in urls:
            urls.append(value)
    return tuple(urls)

def _domain_from_email(value: str) -> str | None:
    address = parseaddr(value)[1].strip().lower()
    if not EMAIL_PATTERN.match(address):
        return None
    return address.rsplit("@", 1)[1]

def _domain_from_url(value: str) -> str | None:
    try:
        hostname = urlsplit(value).hostname
    except ValueError:
        return None
    return hostname.lower().rstrip(".") if hostname else None

def _registrable_like_domain(domain: str | None) -> str | None:
    if not domain:
        return None
    labels = domain.split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else domain

def _matching_terms(text: str, terms: frozenset[str]) -> tuple[str, ...]:
    normalized = text.lower()
    return tuple(sorted(term for term in terms if term in normalized))

def _extract_body(message) -> str:
    parts = []
    if message.is_multipart():
        for part in message.walk():
            if part.get_content_disposition() == "attachment":
                continue
            if part.get_content_type() == "text/plain":
                try:
                    parts.append(part.get_content())
                except (LookupError, UnicodeError):
                    continue
            elif part.get_content_type() == "text/html" and not parts:
                try:
                    parts.append(part.get_content())
                except (LookupError, UnicodeError):
                    continue
    else:
        try:
            content = message.get_content()
            if isinstance(content, str):
                parts.append(content)
        except (LookupError, UnicodeError):
            payload = message.get_payload(decode=True)
            if isinstance(payload, bytes):
                parts.append(payload.decode(message.get_content_charset() or "utf-8", errors="replace"))
    return "\n".join(part.strip() for part in parts if part and part.strip()).strip()

def parse_email(content: str):
    """Parse RFC-style email text without network access."""
    if not isinstance(content, str):
        raise TypeError("Email content must be a string")
    if not content.strip():
        raise ValueError("Email content must not be empty")
    return Parser(policy=policy.default).parsestr(content)

def extract_email_features(content: str) -> EmailFeatures:
    """Extract deterministic features from an .eml or pasted email."""
    message = parse_email(content)
    sender_header = message.get("From", "")
    sender_name, sender_email = parseaddr(sender_header)
    reply_to_email = parseaddr(message.get("Reply-To", ""))[1].strip().lower()
    sender_email = sender_email.strip().lower()
    sender_domain = _domain_from_email(sender_email)
    reply_to_domain = _domain_from_email(reply_to_email)
    subject = str(message.get("Subject", "") or "").strip()
    body = _extract_body(message)
    combined = f"{subject}\n{body}"
    urls = _extract_urls(combined)
    url_domains = tuple(sorted({
        domain for url in urls
        if (domain := _domain_from_url(url))
    }))
    sender_base = _registrable_like_domain(sender_domain)
    mismatches = tuple(sorted(
        domain for domain in url_domains
        if sender_base and _registrable_like_domain(domain) != sender_base
    ))
    display_mismatch = bool(
        sender_name and sender_email
        and sender_name.lower() not in sender_email.lower()
        and not any(part.lower() in sender_email.lower() for part in sender_name.split() if part)
    )
    attachments = []
    if message.is_multipart():
        for part in message.walk():
            filename = part.get_filename()
            if filename:
                attachments.append(filename)
    html_body = ""
    for part in message.walk() if message.is_multipart() else [message]:
        if part.get_content_type() == "text/html":
            try:
                html_body += str(part.get_content())
            except (LookupError, UnicodeError):
                pass
    if not html_body and "<html" in body.lower():
        html_body = body
    suspicious_html = bool(re.search(
        r"<(?:script|iframe|form|input)\b|javascript:",
        html_body,
        re.IGNORECASE,
    ))
    return EmailFeatures(
        sender_name=sender_name.strip(),
        sender_email=sender_email,
        sender_domain=sender_domain,
        reply_to_email=reply_to_email,
        reply_to_domain=reply_to_domain,
        subject=subject,
        body_text=body,
        urls=urls,
        url_domains=url_domains,
        suspicious_keywords=_matching_terms(combined, SUSPICIOUS_KEYWORDS),
        urgency_terms=_matching_terms(combined, URGENCY_TERMS),
        credential_requests=_matching_terms(combined, CREDENTIAL_TERMS),
        financial_requests=_matching_terms(combined, FINANCIAL_TERMS),
        attachment_names=tuple(dict.fromkeys(attachments)),
        suspicious_html=suspicious_html,
        display_name_email_mismatch=display_mismatch,
        reply_to_domain_mismatch=bool(
            sender_domain and reply_to_domain
            and _registrable_like_domain(sender_domain) != _registrable_like_domain(reply_to_domain)
        ),
        sender_domain_url_mismatches=mismatches,
    )
