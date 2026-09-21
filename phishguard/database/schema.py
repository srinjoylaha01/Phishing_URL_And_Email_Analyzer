"""SQLite schema and connection helpers for PhishGuard."""
from __future__ import annotations
import sqlite3
from pathlib import Path

SCHEMA = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS analyses (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    analysis_type TEXT NOT NULL CHECK (analysis_type IN ('url', 'email')),
    input_sha256 TEXT NOT NULL,
    risk_score INTEGER NOT NULL CHECK (risk_score BETWEEN 0 AND 100),
    raw_score INTEGER NOT NULL CHECK (raw_score >= 0),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    UNIQUE(input_sha256, created_at)
);

CREATE TABLE IF NOT EXISTS url_features (
    analysis_id INTEGER PRIMARY KEY,
    original_url TEXT NOT NULL, scheme TEXT NOT NULL, hostname TEXT, port INTEGER,
    path TEXT NOT NULL, query TEXT NOT NULL, fragment TEXT NOT NULL,
    url_length INTEGER NOT NULL, hostname_length INTEGER NOT NULL, path_length INTEGER NOT NULL,
    dot_count INTEGER NOT NULL, hyphen_count INTEGER NOT NULL, subdomain_count INTEGER NOT NULL,
    query_parameter_count INTEGER NOT NULL, has_ip_address INTEGER NOT NULL,
    has_at_symbol INTEGER NOT NULL, has_encoded_characters INTEGER NOT NULL,
    suspicious_keywords TEXT NOT NULL, is_https INTEGER NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS email_features (
    analysis_id INTEGER PRIMARY KEY,
    sender_name TEXT NOT NULL, sender_email TEXT NOT NULL, sender_domain TEXT,
    reply_to_email TEXT NOT NULL, reply_to_domain TEXT, subject TEXT NOT NULL,
    body_text TEXT NOT NULL, urls TEXT NOT NULL, url_domains TEXT NOT NULL,
    suspicious_keywords TEXT NOT NULL, urgency_terms TEXT NOT NULL,
    credential_requests TEXT NOT NULL, financial_requests TEXT NOT NULL,
    attachment_names TEXT NOT NULL, suspicious_html INTEGER NOT NULL,
    display_name_email_mismatch INTEGER NOT NULL, reply_to_domain_mismatch INTEGER NOT NULL,
    sender_domain_url_mismatches TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS detections (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL, rule_id TEXT NOT NULL, description TEXT NOT NULL,
    severity TEXT NOT NULL, points INTEGER NOT NULL, evidence TEXT NOT NULL,
    explanation TEXT NOT NULL, recommendation TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS iocs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    value TEXT NOT NULL, ioc_type TEXT NOT NULL CHECK (ioc_type IN ('domain', 'url', 'ip', 'email')),
    source TEXT NOT NULL, confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    description TEXT NOT NULL DEFAULT '', UNIQUE (ioc_type, value)
);

CREATE TABLE IF NOT EXISTS ioc_matches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    analysis_id INTEGER NOT NULL, ioc_id INTEGER NOT NULL, observed_value TEXT NOT NULL,
    FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE,
    FOREIGN KEY (ioc_id) REFERENCES iocs(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_analyses_created_at ON analyses(created_at);
CREATE INDEX IF NOT EXISTS idx_detections_analysis_id ON detections(analysis_id);
CREATE INDEX IF NOT EXISTS idx_ioc_matches_analysis_id ON ioc_matches(analysis_id);
"""

def connect(path: str | Path) -> sqlite3.Connection:
    connection = sqlite3.connect(Path(path))
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection

def initialize_database(path: str | Path) -> None:
    db_path = Path(path)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with connect(db_path) as connection:
        connection.executescript(SCHEMA)
