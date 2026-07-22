# Security Intelligence Assistant

Security Intelligence Assistant is an automated vulnerability intelligence and advisory platform for enterprise security engineers.

It collects vulnerability advisories, normalizes them into a reusable data model, evaluates generic security risk, applies enterprise watchlists, generates an explainable Markdown report, and sends the report by SMTP email.

## Overview

Security teams often need to review large volumes of vulnerability advisories from different sources and decide which items matter to their own environment. This project provides a deterministic workflow for turning advisory feeds into a prioritized weekly security report.

Current workflow:

```text
Collectors
    |
    v
Collector Pipeline
    |
    v
SQLite Database
    |
    v
Risk Engine
    |
    v
Watchlist Matcher
    |
    v
Enterprise Priority Engine
    |
    v
Markdown Report
    |
    v
SMTP Email
```

## Features

### Vulnerability Collection

- CISA Known Exploited Vulnerabilities collector
- NVD CVE enrichment collector
- Collector abstraction for future sources
- Validation and deduplicating upsert storage

### Risk Analysis

- Deterministic generic vulnerability risk scoring
- CISA KEV, public PoC, CVSS, and severity rules
- Explainable risk reasons for every scored item

### Enterprise Context

- YAML-based modular watchlists
- Keyword matching across title, description, vendor, product, and source
- Separate relevance and vulnerability-type scoring
- Enterprise priority score combining generic risk and watchlist context

### Reporting and Notification

- Markdown weekly security advisory report
- Top focus items with score explanations, matched keywords, tags, and source references
- SMTP email delivery with STARTTLS, SSL, and plain SMTP support
- Email provider presets for `163` and `qq`

### Operations

- One-command PowerShell workflow scripts
- Console and file logging with rotation
- Unit tests covering collectors, storage, scoring, reporting, email, and scripts

## Quick Start

### Requirements

- Python 3.12 or compatible Python 3.x runtime
- PowerShell on Windows for the provided operational scripts

### Install

```powershell
git clone https://github.com/STR2-D2/security-intelligence-assistant.git
cd security-intelligence-assistant
python -m venv .venv
.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### Configure

Create a local `.env` file from `.env.example`.

Minimal email configuration with a provider preset:

```env
EMAIL_PROVIDER=163
EMAIL_USERNAME=your-email@163.com
EMAIL_PASSWORD=your-smtp-authorization-code
EMAIL_FROM_NAME=Security Intelligence Assistant
REPORT_EMAIL_RECIPIENTS=recipient@example.com
```

Do not commit `.env`. It may contain API keys, SMTP authorization codes, and local database settings.

### Run

Collect vulnerability intelligence:

```powershell
.venv\Scripts\python.exe -m app.main
```

Generate a Markdown report:

```powershell
.venv\Scripts\python.exe -m app.generate_report
```

Send the newest generated report by email:

```powershell
.venv\Scripts\python.exe -m app.send_report
```

Run the full workflow:

```powershell
.\scripts\run_weekly_report.ps1
```

Individual scripts are also available:

```powershell
.\scripts\collect.ps1
.\scripts\generate_report.ps1
.\scripts\send_report.ps1
```

## Configuration

Configuration is loaded with `pydantic-settings` from environment variables and `.env`.

Key configuration areas:

- Application: `APP_NAME`, `ENVIRONMENT`, `LOG_LEVEL`
- Database: `DATABASE_URL`
- NVD: `NVD_API_URL`, `NVD_API_KEY`, pagination and delay settings
- Email presets: `EMAIL_PROVIDER`, `EMAIL_USERNAME`, `EMAIL_PASSWORD`
- Advanced SMTP overrides: `SMTP_HOST`, `SMTP_PORT`, `SMTP_USE_TLS`, `SMTP_USE_SSL`
- Recipients: `REPORT_EMAIL_RECIPIENTS`
- Watchlists: YAML files under `config/watchlists/`

See [Configuration](docs/configuration.md) for details.

## Documentation

- [Architecture](docs/architecture.md)
- [Configuration](docs/configuration.md)
- [Workflow](docs/workflow.md)
- [Development](docs/development.md)
- [Roadmap](docs/roadmap.md)
- [Operational Scripts](scripts/README.md)

## Testing

Run the test suite:

```powershell
.venv\Scripts\python.exe -m pytest
```

Current baseline:

```text
171 passed
```

## Roadmap

### v1.0

- CISA KEV collection
- NVD CVE enrichment
- SQLite storage with deduplicating upsert behavior
- Deterministic risk scoring
- YAML watchlists
- Enterprise priority scoring
- Markdown weekly reports
- SMTP email notification
- PowerShell workflow scripts

### v1.1

- Scheduler integration
- NVD retry and backoff resilience
- Additional collectors
- Improved report templates

### v2.0

- Dashboard
- Trend analysis
- Asset inventory correlation
- Multi-team notification routing
