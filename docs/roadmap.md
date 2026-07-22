# Roadmap

## v1.0

Current v1.0 scope is focused on a working end-to-end security advisory workflow.

Completed:

- CISA KEV collector
- NVD CVE collector
- Collector pipeline
- SQLAlchemy SQLite storage
- Deduplicating upsert behavior
- Deterministic risk engine
- YAML watchlists
- Enterprise priority engine
- Markdown weekly report generation
- SMTP email delivery
- Email provider presets
- PowerShell workflow scripts
- Unit test baseline: `171 passed`

## v1.1

Planned engineering improvements:

- Windows Task Scheduler documentation or helper
- NVD retry, timeout, and backoff resilience
- Better operational logging summaries
- Report template refinements
- More collector unit fixtures

## v1.2

Potential collection expansion:

- Vendor advisory collectors
- GitHub Security Advisories
- Microsoft Security Update Guide
- Apache, Cisco, Fortinet, Palo Alto, VMware advisories

## v2.0

Longer-term product direction:

- Web dashboard
- Trend analysis
- Asset inventory correlation
- Team-specific watchlists
- Multi-recipient routing
- Remediation workflow tracking
