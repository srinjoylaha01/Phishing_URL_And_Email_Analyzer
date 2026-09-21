"""Persistence repository for PhishGuard analysis history."""
from __future__ import annotations
import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from phishguard.database.schema import connect, initialize_database
from phishguard.detection.rule_engine import DetectionFinding
from phishguard.features.email_features import EmailFeatures
from phishguard.features.url_features import URLFeatures
from phishguard.ioc.matcher import IOCMatch
from phishguard.ioc.models import IOC
from phishguard.scoring.risk_score import RiskAssessment

def _json(value: object) -> str:
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False)

def _bool(value: bool) -> int:
    return int(bool(value))

class AnalysisRepository:
    """Store complete analysis results using parameterized SQLite queries."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        initialize_database(self.path)

    def _save_analysis(self, analysis_type: str, content: str, assessment: RiskAssessment) -> int:
        created_at = datetime.now(timezone.utc).isoformat()
        input_sha256 = hashlib.sha256(content.encode("utf-8")).hexdigest()
        with connect(self.path) as db:
            cursor = db.execute(
                """INSERT INTO analyses
                   (created_at, analysis_type, input_sha256, risk_score, raw_score, risk_level)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (created_at, analysis_type, input_sha256, assessment.score,
                 assessment.raw_score, assessment.level),
            )
            return int(cursor.lastrowid)

    def save_url_analysis(self, content: str, features: URLFeatures,
                          findings: Iterable[DetectionFinding], assessment: RiskAssessment,
                          ioc_matches: Iterable[IOCMatch] = ()) -> int:
        analysis_id = self._save_analysis("url", content, assessment)
        findings, matches = list(findings), list(ioc_matches)
        with connect(self.path) as db:
            db.execute(
                """INSERT INTO url_features
                (analysis_id, original_url, scheme, hostname, port, path, query, fragment,
                 url_length, hostname_length, path_length, dot_count, hyphen_count,
                 subdomain_count, query_parameter_count, has_ip_address, has_at_symbol,
                 has_encoded_characters, suspicious_keywords, is_https)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (analysis_id, features.original_url, features.scheme, features.hostname,
                 features.port, features.path, features.query, features.fragment,
                 features.url_length, features.hostname_length, features.path_length,
                 features.dot_count, features.hyphen_count, features.subdomain_count,
                 features.query_parameter_count, _bool(features.has_ip_address),
                 _bool(features.has_at_symbol), _bool(features.has_encoded_characters),
                 _json(features.suspicious_keywords), _bool(features.is_https)),
            )
            self._insert_findings(db, analysis_id, findings)
            self._insert_ioc_matches(db, analysis_id, matches)
        return analysis_id

    def save_email_analysis(self, content: str, features: EmailFeatures,
                            findings: Iterable[DetectionFinding], assessment: RiskAssessment,
                            ioc_matches: Iterable[IOCMatch] = ()) -> int:
        analysis_id = self._save_analysis("email", content, assessment)
        findings, matches = list(findings), list(ioc_matches)
        with connect(self.path) as db:
            db.execute(
                """INSERT INTO email_features
                (analysis_id, sender_name, sender_email, sender_domain, reply_to_email,
                 reply_to_domain, subject, body_text, urls, url_domains, suspicious_keywords,
                 urgency_terms, credential_requests, financial_requests, attachment_names,
                 suspicious_html, display_name_email_mismatch, reply_to_domain_mismatch,
                 sender_domain_url_mismatches)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (analysis_id, features.sender_name, features.sender_email, features.sender_domain,
                 features.reply_to_email, features.reply_to_domain, features.subject,
                 features.body_text, _json(features.urls), _json(features.url_domains),
                 _json(features.suspicious_keywords), _json(features.urgency_terms),
                 _json(features.credential_requests), _json(features.financial_requests),
                 _json(features.attachment_names), _bool(features.suspicious_html),
                 _bool(features.display_name_email_mismatch), _bool(features.reply_to_domain_mismatch),
                 _json(features.sender_domain_url_mismatches)),
            )
            self._insert_findings(db, analysis_id, findings)
            self._insert_ioc_matches(db, analysis_id, matches)
        return analysis_id

    @staticmethod
    def _insert_findings(db, analysis_id: int, findings: Iterable[DetectionFinding]) -> None:
        db.executemany(
            """INSERT INTO detections
               (analysis_id, rule_id, description, severity, points, evidence, explanation, recommendation)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            [(analysis_id, f.rule_id, f.description, f.severity, f.points,
              f.evidence, f.explanation, f.recommendation) for f in findings],
        )

    @staticmethod
    def _upsert_ioc(db, indicator: IOC) -> int:
        db.execute(
            """INSERT INTO iocs (value, ioc_type, source, confidence, description)
               VALUES (?, ?, ?, ?, ?)
               ON CONFLICT(ioc_type, value) DO UPDATE SET
               source=excluded.source, confidence=excluded.confidence, description=excluded.description""",
            (indicator.value, indicator.ioc_type, indicator.source,
             indicator.confidence, indicator.description),
        )
        row = db.execute(
            "SELECT id FROM iocs WHERE ioc_type = ? AND value = ?",
            (indicator.ioc_type, indicator.value),
        ).fetchone()
        return int(row["id"])

    def _insert_ioc_matches(self, db, analysis_id: int, matches: Iterable[IOCMatch]) -> None:
        rows = []
        for match in matches:
            ioc_id = self._upsert_ioc(db, match.indicator)
            rows.append((analysis_id, ioc_id, match.observed_value))
        db.executemany(
            "INSERT INTO ioc_matches (analysis_id, ioc_id, observed_value) VALUES (?, ?, ?)",
            rows,
        )

    def list_history(self, limit: int = 50) -> list[dict[str, object]]:
        if not 1 <= limit <= 500:
            raise ValueError("limit must be between 1 and 500")
        with connect(self.path) as db:
            rows = db.execute(
                """SELECT id, created_at, analysis_type, input_sha256,
                          risk_score, raw_score, risk_level
                   FROM analyses ORDER BY id DESC LIMIT ?""",
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_analysis(self, analysis_id: int) -> dict[str, object] | None:
        with connect(self.path) as db:
            analysis = db.execute(
                "SELECT * FROM analyses WHERE id = ?", (analysis_id,)
            ).fetchone()
            if analysis is None:
                return None
            findings = db.execute(
                "SELECT * FROM detections WHERE analysis_id = ? ORDER BY id",
                (analysis_id,),
            ).fetchall()
            matches = db.execute(
                """SELECT im.id, im.observed_value, i.value, i.ioc_type,
                          i.source, i.confidence, i.description
                   FROM ioc_matches im JOIN iocs i ON i.id = im.ioc_id
                   WHERE im.analysis_id = ? ORDER BY im.id""",
                (analysis_id,),
            ).fetchall()
            return {
                "analysis": dict(analysis),
                "findings": [dict(row) for row in findings],
                "ioc_matches": [dict(row) for row in matches],
            }
