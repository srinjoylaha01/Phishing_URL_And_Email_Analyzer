"""Streamlit dashboard for PhishGuard."""
from __future__ import annotations

from pathlib import Path

import streamlit as st

from phishguard.database.repository import AnalysisRepository
from phishguard.detection.email_rules import analyze_email_rules
from phishguard.detection.url_rules import analyze_url_rules
from phishguard.features.email_features import extract_email_features
from phishguard.features.url_features import extract_url_features
from phishguard.ioc.matcher import match_ioc_values
from phishguard.ioc.store import IOCStore
from phishguard.scoring.risk_score import calculate_risk

DB_PATH = Path("data/phishguard.db")
IOC_PATH = Path("data/iocs.example.json")

def _repository():
    return AnalysisRepository(DB_PATH)

def _load_iocs():
    return IOCStore(IOC_PATH).load()

def _risk_counts(history):
    counts = {"LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
    for item in history:
        level = item["risk_level"]
        if level in counts:
            counts[level] += 1
    return counts

def _show_findings(findings):
    if not findings:
        st.success("No rule findings detected.")
        return
    for finding in findings:
        with st.expander(f"{finding.rule_id} · {finding.severity} · +{finding.points}"):
            st.write(finding.description)
            st.write(f"Evidence: {finding.evidence}")
            st.write(f"Why it matters: {finding.explanation}")
            st.write(f"Recommendation: {finding.recommendation}")

def _show_assessment(assessment):
    c1, c2, c3 = st.columns(3)
    c1.metric("Risk score", f"{assessment.score}/100")
    c2.metric("Risk level", assessment.level)
    c3.metric("Findings", assessment.finding_count)
    st.caption("Rule-based risk is an explainable indicator, not proof that the URL or email is malicious.")

def analyze_url_tab():
    st.subheader("URL Analyzer")
    url = st.text_input("URL", placeholder="https://example.com/login")
    if st.button("Analyze URL", type="primary", key="analyze-url"):
        try:
            features = extract_url_features(url)
            findings = analyze_url_rules(features)
            assessment = calculate_risk(findings)
            indicators = _load_iocs()
            values = {
                "domain": (features.hostname,) if features.hostname else (),
                "url": (features.original_url,),
                "ip": (features.hostname,) if features.has_ip_address else (),
            }
            matches = match_ioc_values(values, indicators)
            analysis_id = _repository().save_url_analysis(
                features.original_url, features, findings, assessment, matches
            )
        except (OSError, TypeError, ValueError) as exc:
            st.error(f"Analysis error: {exc}")
            return
        st.success(f"Analysis #{analysis_id} saved.")
        _show_assessment(assessment)
        st.write({
            "hostname": features.hostname,
            "scheme": features.scheme,
            "https": features.is_https,
            "URL length": features.url_length,
            "subdomains": features.subdomain_count,
            "IP hostname": features.has_ip_address,
            "@ symbol": features.has_at_symbol,
            "encoded characters": features.has_encoded_characters,
            "suspicious keywords": list(features.suspicious_keywords),
        })
        st.markdown("#### Detection findings")
        _show_findings(findings)
        if matches:
            st.markdown("#### Local IOC matches")
            for match in matches:
                st.warning(
                    f"{match.indicator.ioc_type}: {match.observed_value} · "
                    f"source={match.indicator.source} · confidence={match.indicator.confidence}"
                )

def analyze_email_tab():
    st.subheader("Email Analyzer")
    email = st.text_area("Paste RFC-style email content", height=280)
    if st.button("Analyze Email", type="primary", key="analyze-email"):
        try:
            features = extract_email_features(email)
            findings = analyze_email_rules(features)
            assessment = calculate_risk(findings)
            indicators = _load_iocs()
            values = {
                "domain": features.url_domains,
                "url": features.urls,
                "email": tuple(v for v in (features.sender_email, features.reply_to_email) if v),
            }
            matches = match_ioc_values(values, indicators)
            analysis_id = _repository().save_email_analysis(
                email, features, findings, assessment, matches
            )
        except (OSError, TypeError, ValueError) as exc:
            st.error(f"Analysis error: {exc}")
            return
        st.success(f"Analysis #{analysis_id} saved.")
        _show_assessment(assessment)
        st.write({
            "sender": features.sender_email,
            "reply-to": features.reply_to_email,
            "subject": features.subject,
            "URLs": len(features.urls),
            "urgency terms": list(features.urgency_terms),
            "credential requests": list(features.credential_requests),
            "financial requests": list(features.financial_requests),
            "suspicious HTML": features.suspicious_html,
        })
        st.markdown("#### Detection findings")
        _show_findings(findings)
        if matches:
            st.markdown("#### Local IOC matches")
            for match in matches:
                st.warning(
                    f"{match.indicator.ioc_type}: {match.observed_value} · "
                    f"source={match.indicator.source} · confidence={match.indicator.confidence}"
                )

def history_tab():
    st.subheader("Analysis History")
    limit = st.slider("Entries", min_value=1, max_value=100, value=20)
    try:
        history = _repository().list_history(limit)
    except (OSError, ValueError) as exc:
        st.error(f"History error: {exc}")
        return
    if not history:
        st.info("No analysis history yet.")
        return
    counts = _risk_counts(history)
    columns = st.columns(4)
    for column, level in zip(columns, counts):
        column.metric(level, counts[level])
    st.bar_chart({"count": [counts[level] for level in counts]}, x=None)
    st.dataframe(
        [
            {
                "ID": item["id"],
                "Created": item["created_at"],
                "Type": item["analysis_type"],
                "Risk": item["risk_level"],
                "Score": item["risk_score"],
            }
            for item in history
        ],
        use_container_width=True,
        hide_index=True,
    )

def main():
    st.set_page_config(page_title="PhishGuard", page_icon="PG", layout="wide")
    st.title("PhishGuard")
    st.caption("Defensive phishing URL and email security analyzer")
    st.info(
        "Local-only analysis: submitted URLs are parsed but never visited, "
        "and email content is not sent to external services."
    )
    tab_url, tab_email, tab_history = st.tabs(["URL Analyzer", "Email Analyzer", "History"])
    with tab_url:
        analyze_url_tab()
    with tab_email:
        analyze_email_tab()
    with tab_history:
        history_tab()

if __name__ == "__main__":
    main()
