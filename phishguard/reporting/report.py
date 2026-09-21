"""Report generation for stored PhishGuard analyses."""
from __future__ import annotations

import csv
import html
import io
import json
from pathlib import Path
from typing import Mapping

SUPPORTED_FORMATS = ("json", "csv", "html", "txt")


def _validate_record(record: Mapping[str, object]) -> None:
    if "analysis" not in record or "findings" not in record or "ioc_matches" not in record:
        raise ValueError("Invalid analysis record")


def build_report_data(record: Mapping[str, object]) -> dict[str, object]:
    """Normalize a stored analysis into a JSON-safe report structure."""
    _validate_record(record)
    analysis = dict(record["analysis"])
    findings = [dict(item) for item in record["findings"]]
    matches = [dict(item) for item in record["ioc_matches"]]
    features = record.get("features")
    return {
        "analysis": analysis,
        "features": dict(features) if isinstance(features, Mapping) else None,
        "findings": findings,
        "ioc_matches": matches,
    }


def render_json(record: Mapping[str, object]) -> str:
    return json.dumps(build_report_data(record), indent=2, ensure_ascii=False, default=str) + "\n"


def render_txt(record: Mapping[str, object]) -> str:
    data = build_report_data(record)
    analysis = data["analysis"]
    lines = [
        "PhishGuard Analysis Report",
        "=" * 27,
        f"Analysis ID: {analysis.get('id')}",
        f"Type: {str(analysis.get('analysis_type', '')).upper()}",
        f"Created: {analysis.get('created_at')}",
        f"Risk: {analysis.get('risk_level')} ({analysis.get('risk_score')}/100)",
        f"Raw score: {analysis.get('raw_score')}",
        f"Input SHA-256: {analysis.get('input_sha256')}",
        "",
        f"Findings: {len(data['findings'])}",
    ]
    for finding in data["findings"]:
        lines.extend([
            f"- {finding.get('rule_id')} [{finding.get('severity')}] +{finding.get('points')}: {finding.get('description')}",
            f"  Evidence: {finding.get('evidence')}",
            f"  Explanation: {finding.get('explanation')}",
            f"  Recommendation: {finding.get('recommendation')}",
        ])
    lines.append("")
    lines.append(f"IOC matches: {len(data['ioc_matches'])}")
    for match in data["ioc_matches"]:
        lines.append(
            f"- {match.get('ioc_type')}: {match.get('observed_value')} "
            f"(source={match.get('source')}, confidence={match.get('confidence')})"
        )
    return "\n".join(lines) + "\n"


def render_csv(record: Mapping[str, object]) -> str:
    data = build_report_data(record)
    analysis = data["analysis"]
    rows = []
    for finding in data["findings"]:
        rows.append({
            "analysis_id": analysis.get("id"),
            "created_at": analysis.get("created_at"),
            "analysis_type": analysis.get("analysis_type"),
            "risk_level": analysis.get("risk_level"),
            "risk_score": analysis.get("risk_score"),
            "raw_score": analysis.get("raw_score"),
            "record_type": "finding",
            "rule_id": finding.get("rule_id"),
            "severity": finding.get("severity"),
            "points": finding.get("points"),
            "description": finding.get("description"),
            "evidence": finding.get("evidence"),
            "ioc_type": "",
            "observed_value": "",
            "ioc_source": "",
            "ioc_confidence": "",
        })
    for match in data["ioc_matches"]:
        rows.append({
            "analysis_id": analysis.get("id"),
            "created_at": analysis.get("created_at"),
            "analysis_type": analysis.get("analysis_type"),
            "risk_level": analysis.get("risk_level"),
            "risk_score": analysis.get("risk_score"),
            "raw_score": analysis.get("raw_score"),
            "record_type": "ioc_match",
            "rule_id": "",
            "severity": "",
            "points": "",
            "description": match.get("description", ""),
            "evidence": "",
            "ioc_type": match.get("ioc_type"),
            "observed_value": match.get("observed_value"),
            "ioc_source": match.get("source"),
            "ioc_confidence": match.get("confidence"),
        })
    if not rows:
        rows.append({
            "analysis_id": analysis.get("id"), "created_at": analysis.get("created_at"),
            "analysis_type": analysis.get("analysis_type"), "risk_level": analysis.get("risk_level"),
            "risk_score": analysis.get("risk_score"), "raw_score": analysis.get("raw_score"),
            "record_type": "summary", "rule_id": "", "severity": "", "points": "",
            "description": "No findings or IOC matches", "evidence": "", "ioc_type": "",
            "observed_value": "", "ioc_source": "", "ioc_confidence": "",
        })
    output = io.StringIO()
    fields = list(rows[0].keys())
    writer = csv.DictWriter(output, fieldnames=fields, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def render_html(record: Mapping[str, object]) -> str:
    data = build_report_data(record)
    analysis = data["analysis"]

    def esc(value: object) -> str:
        return html.escape(str(value if value is not None else ""))

    finding_rows = "".join(
        "<tr>" + "".join(
            f"<td>{esc(finding.get(key))}</td>"
            for key in ("rule_id", "severity", "points", "description", "evidence", "recommendation")
        ) + "</tr>"
        for finding in data["findings"]
    ) or "<tr><td colspan='6'>No findings.</td></tr>"
    ioc_rows = "".join(
        f"<tr><td>{esc(match.get('ioc_type'))}</td><td>{esc(match.get('observed_value'))}</td>"
        f"<td>{esc(match.get('source'))}</td><td>{esc(match.get('confidence'))}</td></tr>"
        for match in data["ioc_matches"]
    ) or "<tr><td colspan='4'>No IOC matches.</td></tr>"
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PhishGuard Analysis Report #{esc(analysis.get('id'))}</title>
<style>body{{font-family:Arial,sans-serif;max-width:1100px;margin:40px auto;padding:0 20px;color:#222}}
table{{border-collapse:collapse;width:100%;margin:16px 0 28px}}
th,td{{border:1px solid #ccc;padding:8px;text-align:left;vertical-align:top}}
th{{background:#f2f2f2}}.risk{{font-size:1.2rem;font-weight:700}}</style>
</head><body>
<h1>PhishGuard Analysis Report</h1>
<p>Analysis ID: {esc(analysis.get('id'))} | Type: {esc(analysis.get('analysis_type'))} | Created: {esc(analysis.get('created_at'))}</p>
<p class="risk">Risk: {esc(analysis.get('risk_level'))} ({esc(analysis.get('risk_score'))}/100), raw score {esc(analysis.get('raw_score'))}</p>
<p>Input SHA-256: {esc(analysis.get('input_sha256'))}</p>
<h2>Findings</h2><table><thead><tr><th>Rule</th><th>Severity</th><th>Points</th><th>Description</th><th>Evidence</th><th>Recommendation</th></tr></thead><tbody>{finding_rows}</tbody></table>
<h2>IOC Matches</h2><table><thead><tr><th>Type</th><th>Observed value</th><th>Source</th><th>Confidence</th></tr></thead><tbody>{ioc_rows}</tbody></table>
</body></html>
"""
 
 
def render_report(record: Mapping[str, object], format_name: str) -> str:
    """Render a report as json, csv, html, or txt."""
    format_name = format_name.lower().strip()
    renderers = {"json": render_json, "csv": render_csv, "html": render_html, "txt": render_txt}
    try:
        renderer = renderers[format_name]
    except KeyError as exc:
        raise ValueError(f"Unsupported report format: {format_name}") from exc
    return renderer(record)


def write_report(record: Mapping[str, object], format_name: str, output: str | Path) -> Path:
    """Render and write a report, creating its parent directory when needed."""
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(render_report(record, format_name), encoding="utf-8")
    return path
