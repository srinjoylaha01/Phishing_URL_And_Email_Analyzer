# Phase 2 — Project Structure & Environment Setup

## Objective

Create a maintainable Python package layout and a reproducible development environment before implementing security-analysis logic.

## Requirements

- Python 3.10 or newer
- Git
- A virtual environment
- pip

## Windows PowerShell

```powershell
python --version
python -m venv .venv
.\\.venv\\Scripts\\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Linux / macOS

```bash
python3 --version
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

## Verify

```bash
python -m phishguard --help
python -m phishguard --version
pytest
ruff check .
```

Expected version: phishguard 0.1.0.

## Optional Dependencies

Dashboard: python -m pip install -e ".[dashboard]"

Machine learning: python -m pip install -e ".[ml]"

Both: python -m pip install -e ".[dashboard,ml,dev]"

## Security Notes

- Never commit .env.
- Never place real API keys in .env.example.
- Runtime databases and generated reports are ignored.
- ML model artifacts are ignored.
- Phase 2 performs no network requests.

## Exit Criteria

- Package imports.
- CLI starts.
- Repository structure exists.
- Development dependencies are separate.
- Dashboard and ML dependencies remain optional.
- Basic automated tests exist.
