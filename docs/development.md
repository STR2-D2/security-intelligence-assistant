# Development

This document is for developers working on Security Intelligence Assistant.

## Project Structure

```text
agents/          Agent coordination
collectors/      Source-specific vulnerability collectors
pipeline/        Shared collector processing workflow
skills/          Reusable storage and validation skills
database/        SQLAlchemy models and session management
risk/            Generic vulnerability risk scoring
watchlist/       YAML watchlist loading and matching
priority/        Enterprise priority scoring
reporting/       Weekly report data model and Markdown renderer
notifications/   SMTP email notification
app/             Runnable module entry points
scripts/         Operational PowerShell scripts
tests/           Unit tests
docs/            Project documentation
```

## Test Suite

Run all tests:

```powershell
.venv\Scripts\python.exe -m pytest
```

Current baseline:

```text
171 passed
```

Tests should not access real SMTP servers, external APIs, or the local development database unless a task explicitly asks for live verification.

## Continuous Integration

GitHub Actions runs the test suite on every push and pull request.

The CI workflow:

```text
checkout
setup Python 3.11 and 3.12
install requirements.txt
run python -m pytest
```

The workflow sets `PYTHONPATH=.` and uses pip dependency caching to keep repeated runs faster.

CI exists to catch regressions before changes are merged. Local tests should still be run before committing.

## Git Workflow

Recommended flow:

```powershell
git checkout main
git pull
git checkout -b feature/task-XXX-short-name
```

Before committing:

```powershell
.venv\Scripts\python.exe -m pytest
git status
git diff --cached --name-only
```

Do not commit:

- `.env`
- `security_intelligence.db`
- `*.db.bak`
- generated Markdown reports under `reports/`
- logs

## Adding Collectors

New collectors should implement `BaseCollector`:

```text
fetch() -> list[RawAdvisory]
normalize(raw_items) -> list[NormalizedVulnerability]
```

Keep source-specific parsing in the collector and shared validation/storage behavior in the pipeline and skills.

## Adding Watchlists

Add or update YAML files in `config/watchlists/`.

Keep watchlist changes deterministic:

- Clear category names
- Stable canonical names
- Aliases as explicit lists
- Tags as explicit lists
- Score from 0 to 100

## Local Database

The default development database is:

```text
security_intelligence.db
```

It is ignored by Git. See [development database notes](development_database.md) for local rebuild guidance.
