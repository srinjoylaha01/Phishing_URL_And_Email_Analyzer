"""Command-line interface for PhishGuard."""
from __future__ import annotations
import argparse
import sys
from pathlib import Path
from phishguard.database.repository import AnalysisRepository
from phishguard.detection.email_rules import analyze_email_rules
from phishguard.detection.url_rules import analyze_url_rules
from phishguard.features.email_features import extract_email_features
from phishguard.features.url_features import extract_url_features
from phishguard.ioc.matcher import match_ioc_values
from phishguard.ioc.store import IOCStore
from phishguard.scoring.risk_score import calculate_risk
from phishguard.reporting.report import write_report

DEFAULT_DB = Path("data/phishguard.db")
DEFAULT_IOCS = Path("data/iocs.example.json")

def _add_storage_options(parser):
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite history database path.")
    parser.add_argument("--ioc-file", default=str(DEFAULT_IOCS), help="Local JSON IOC file.")

def _load_iocs(path):
    return IOCStore(path).load() if path else []

def _print_findings(findings):
    if not findings:
        print("Findings: none")
        return
    print(f"Findings: {len(findings)}")
    for finding in findings:
        print(f"- {finding.rule_id} [{finding.severity}] +{finding.points}: {finding.description}")
        print(f"  Evidence: {finding.evidence}")

def _print_assessment(assessment):
    print(f"Risk: {assessment.level} ({assessment.score}/100)")
    print(f"Raw score: {assessment.raw_score}")
    print(f"Actionable: {'yes' if assessment.is_actionable else 'no'}")

def _print_ioc_matches(matches):
    if not matches:
        print("IOC matches: none")
        return
    print(f"IOC matches: {len(matches)}")
    for match in matches:
        indicator = match.indicator
        print(f"- {indicator.ioc_type}: {match.observed_value} (source={indicator.source}, confidence={indicator.confidence})")

def analyze_url_command(args):
    try:
        features = extract_url_features(args.url)
        findings = analyze_url_rules(features)
        assessment = calculate_risk(findings)
        indicators = _load_iocs(args.ioc_file)
        values = {"domain": (features.hostname,) if features.hostname else (), "url": (features.original_url,),
                  "ip": (features.hostname,) if features.has_ip_address else ()}
        matches = match_ioc_values(values, indicators)
        analysis_id = AnalysisRepository(args.db).save_url_analysis(features.original_url, features, findings, assessment, matches)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print("PhishGuard URL Analysis")
    print(f"URL: {features.original_url}")
    print(f"Hostname: {features.hostname}")
    print(f"HTTPS: {'yes' if features.is_https else 'no'}")
    _print_assessment(assessment)
    _print_findings(findings)
    _print_ioc_matches(matches)
    print(f"Analysis ID: {analysis_id}")
    return 0

def _read_email(args):
    if args.file:
        return Path(args.file).read_text(encoding="utf-8")
    if args.text is not None:
        return args.text
    try:
        if not sys.stdin.isatty():
            return sys.stdin.read()
    except OSError:
        # Captured/non-interactive stdin may reject reads; treat it like no source.
        pass
    raise ValueError("Provide --text, --file, or pipe email content through stdin")

def analyze_email_command(args):
    try:
        content = _read_email(args)
        features = extract_email_features(content)
        findings = analyze_email_rules(features)
        assessment = calculate_risk(findings)
        indicators = _load_iocs(args.ioc_file)
        values = {"domain": features.url_domains, "url": features.urls,
                  "email": tuple(v for v in (features.sender_email, features.reply_to_email) if v)}
        matches = match_ioc_values(values, indicators)
        analysis_id = AnalysisRepository(args.db).save_email_analysis(content, features, findings, assessment, matches)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print("PhishGuard Email Analysis")
    print(f"From: {features.sender_email or '(not provided)'}")
    print(f"Subject: {features.subject or '(none)'}")
    print(f"URLs: {len(features.urls)}")
    _print_assessment(assessment)
    _print_findings(findings)
    _print_ioc_matches(matches)
    print(f"Analysis ID: {analysis_id}")
    return 0

def history_command(args):
    try:
        history = AnalysisRepository(args.db).list_history(args.limit)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if not history:
        print("No analysis history.")
        return 0
    print("PhishGuard Analysis History")
    for item in history:
        print(f"#{item['id']} | {item['created_at']} | {item['analysis_type'].upper()} | {item['risk_level']} {item['risk_score']}/100")
    return 0

def show_command(args):
    try:
        record = AnalysisRepository(args.db).get_analysis(args.analysis_id)
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    if record is None:
        print(f"Analysis ID {args.analysis_id} was not found.", file=sys.stderr)
        return 1
    analysis = record["analysis"]
    print("PhishGuard Analysis")
    print(f"ID: {analysis['id']}")
    print(f"Type: {analysis['analysis_type']}")
    print(f"Created: {analysis['created_at']}")
    print(f"Risk: {analysis['risk_level']} ({analysis['risk_score']}/100)")
    print(f"Findings: {len(record['findings'])}")
    for finding in record["findings"]:
        print(f"- {finding['rule_id']} [{finding['severity']}] +{finding['points']}")
    print(f"IOC matches: {len(record['ioc_matches'])}")
    for match in record["ioc_matches"]:
        print(f"- {match['ioc_type']}: {match['observed_value']} (source={match['source']})")
    return 0

def report_command(args):
    try:
        record = AnalysisRepository(args.db).get_analysis(args.analysis_id)
        if record is None:
            print(f"Analysis ID {args.analysis_id} was not found.", file=sys.stderr)
            return 1
        path = write_report(record, args.format, args.output)
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print(f"Report written to: {path}")
    return 0

def ml_train_command(args):
    try:
        from phishguard.ml.train import train_from_csv
        metrics = train_from_csv(args.data, args.model, args.metrics)
    except ImportError as exc:
        print('ML dependencies are not installed. Run: python -m pip install -e ".[ml]"', file=sys.stderr)
        print(f"Details: {exc}", file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print("PhishGuard ML Training")
    for key, value in metrics.items():
        print(f"{key}: {value}")
    print(f"Model saved to: {args.model}")
    print(f"Metrics saved to: {args.metrics}")
    return 0

def ml_predict_url_command(args):
    try:
        from phishguard.ml.predict import predict_url_from_path
        prediction = predict_url_from_path(args.url, args.model)
    except ImportError as exc:
        print('ML dependencies are not installed. Run: python -m pip install -e ".[ml]"', file=sys.stderr)
        print(f"Details: {exc}", file=sys.stderr)
        return 2
    except (OSError, TypeError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    print("PhishGuard ML URL Prediction")
    print(f"URL: {args.url}")
    print(f"Label: {prediction.label}")
    print(f"Probability: {prediction.probability:.4f}")
    print(f"Model version: {prediction.model_version}")
    return 0

def build_parser():
    parser = argparse.ArgumentParser(prog="phishguard", description="Defensive phishing URL and email security analyzer.")
    parser.add_argument("--version", action="version", version="phishguard 0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)
    url_parser = subparsers.add_parser("analyze-url", help="Analyze a URL.")
    url_parser.add_argument("url")
    _add_storage_options(url_parser)
    url_parser.set_defaults(func=analyze_url_command)
    email_parser = subparsers.add_parser("analyze-email", help="Analyze email content.")
    source = email_parser.add_mutually_exclusive_group()
    source.add_argument("--text", help="Email content supplied directly.")
    source.add_argument("--file", help="Path to an .eml or text email file.")
    _add_storage_options(email_parser)
    email_parser.set_defaults(func=analyze_email_command)
    history_parser = subparsers.add_parser("history", help="Show recent analysis history.")
    history_parser.add_argument("--limit", type=int, default=20)
    history_parser.add_argument("--db", default=str(DEFAULT_DB))
    history_parser.set_defaults(func=history_command)
    show_parser = subparsers.add_parser("show", help="Show a stored analysis.")
    show_parser.add_argument("analysis_id", type=int)
    show_parser.add_argument("--db", default=str(DEFAULT_DB))
    show_parser.set_defaults(func=show_command)
    report_parser = subparsers.add_parser("report", help="Export a stored analysis report.")
    report_parser.add_argument("analysis_id", type=int)
    report_parser.add_argument("--format", choices=("json", "csv", "html", "txt"), required=True)
    report_parser.add_argument("--output", required=True, help="Output report path.")
    report_parser.add_argument("--db", default=str(DEFAULT_DB))
    report_parser.set_defaults(func=report_command)
    train_parser = subparsers.add_parser("ml-train", help="Train and evaluate the optional URL ML model.")
    train_parser.add_argument("--data", default="data/ml/url_training.csv")
    train_parser.add_argument("--model", default="models/phishguard_url_model.joblib")
    train_parser.add_argument("--metrics", default="models/phishguard_url_metrics.json")
    train_parser.set_defaults(func=ml_train_command)
    predict_parser = subparsers.add_parser("ml-predict-url", help="Predict a URL with the local ML model.")
    predict_parser.add_argument("url")
    predict_parser.add_argument("--model", default="models/phishguard_url_model.joblib")
    predict_parser.set_defaults(func=ml_predict_url_command)
    return parser

def main():
    args = build_parser().parse_args()
    return args.func(args)

if __name__ == "__main__":
    raise SystemExit(main())
