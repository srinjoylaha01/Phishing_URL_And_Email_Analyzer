from pathlib import Path
from phishguard.cli import build_parser, main

def test_cli_parser_has_expected_commands():
    help_text = build_parser().format_help()
    assert "analyze-url" in help_text
    assert "analyze-email" in help_text
    assert "history" in help_text
    assert "show" in help_text
    assert "report" in help_text

def test_cli_url_analysis_persists_history(tmp_path: Path, capsys, monkeypatch):
    db = tmp_path / "history.db"
    monkeypatch.setattr("sys.argv", ["phishguard", "analyze-url", "http://192.0.2.10/login", "--db", str(db)])
    assert main() == 0
    output = capsys.readouterr().out
    assert "PhishGuard URL Analysis" in output
    assert "MEDIUM" in output
    assert "Analysis ID: 1" in output

def test_cli_email_text_analysis(tmp_path: Path, capsys, monkeypatch):
    db = tmp_path / "history.db"
    content = "From: Team <team@example.com>\nSubject: Meeting\n\nSee you at 10 AM."
    monkeypatch.setattr("sys.argv", ["phishguard", "analyze-email", "--text", content, "--db", str(db)])
    assert main() == 0
    output = capsys.readouterr().out
    assert "PhishGuard Email Analysis" in output
    assert "Risk: LOW" in output

def test_cli_history_and_show(tmp_path: Path, capsys, monkeypatch):
    db = tmp_path / "history.db"
    monkeypatch.setattr("sys.argv", ["phishguard", "analyze-url", "https://example.com", "--db", str(db)])
    assert main() == 0
    capsys.readouterr()
    monkeypatch.setattr("sys.argv", ["phishguard", "history", "--db", str(db)])
    assert main() == 0
    assert "#1" in capsys.readouterr().out
    monkeypatch.setattr("sys.argv", ["phishguard", "show", "1", "--db", str(db)])
    assert main() == 0
    assert "ID: 1" in capsys.readouterr().out

def test_cli_report_exports_json(tmp_path: Path, capsys, monkeypatch):
    db = tmp_path / "history.db"
    output_file = tmp_path / "analysis.json"
    monkeypatch.setattr("sys.argv", ["phishguard", "analyze-url", "https://example.com", "--db", str(db)])
    assert main() == 0
    capsys.readouterr()
    monkeypatch.setattr(
        "sys.argv",
        ["phishguard", "report", "1", "--format", "json", "--output", str(output_file), "--db", str(db)],
    )
    assert main() == 0
    assert output_file.exists()
    assert '"risk_level"' in output_file.read_text(encoding="utf-8")


def test_cli_missing_email_source_returns_error(tmp_path: Path, capsys, monkeypatch):
    db = tmp_path / "history.db"
    monkeypatch.setattr("sys.argv", ["phishguard", "analyze-email", "--db", str(db)])
    assert main() == 2
    assert "Provide --text" in capsys.readouterr().err
