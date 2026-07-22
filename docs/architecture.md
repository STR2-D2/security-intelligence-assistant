# Architecture

Security Intelligence Assistant is organized as small modules that can evolve independently. The current implementation is deterministic and does not use AI services.

## System Flow

```text
CollectorAgent
    |
    v
Collectors
    |
    v
CollectorPipeline
    |
    v
Validator
    |
    v
Storage
    |
    v
SQLite Database
    |
    v
Risk Engine + Watchlist Matcher
    |
    v
Enterprise Priority Engine
    |
    v
Weekly Report
    |
    v
SMTP Notification
```

## Components

### CollectorAgent

`CollectorAgent` coordinates the enabled collectors and runs one `CollectorPipeline` for each source. A collector failure is logged and isolated so other collectors can continue.

Current collectors:

- `CisaKevCollector`
- `NvdCollector`

### Collectors

Collectors implement the shared `BaseCollector` interface:

```text
fetch() -> list[RawAdvisory]
normalize(raw_items) -> list[NormalizedVulnerability]
```

This keeps source-specific parsing separate from validation, storage, and analysis.

### Pipeline

`CollectorPipeline` performs the common processing workflow:

```text
fetch
normalize
validate
save
return counts
```

It returns fetched, normalized, valid, rejected, inserted, updated, and unchanged counts.

### Storage

The storage skill writes normalized vulnerabilities into SQLite with deduplicating upsert behavior.

Identity rules:

- CVE records are matched by normalized `cve_id`.
- Records without CVE are matched by `source + title + source_url`.

Existing records are updated only when mutable source fields actually change.

### Risk Engine

The generic risk engine calculates a 0..100 risk score using deterministic rules:

- CISA KEV listing
- Public proof of concept flag
- CVSS score
- Severity fallback

Each contributing rule produces an explanatory reason.

### Watchlist

Watchlists are YAML files under `config/watchlists/`. They define enterprise-relevant keywords, aliases, tags, and scores.

The matcher separates:

- Relevance matches, such as vendors, products, cloud platforms, business systems
- Vulnerability type matches, such as RCE, SQL injection, privilege escalation

### Enterprise Priority

The priority engine combines:

```text
generic risk score * 0.60
relevance score * 0.30
vulnerability type score * 0.10
```

It also applies explainable guardrails, such as limiting vulnerability-type-only matches to at most `MEDIUM` priority.

### Reporting

The reporting service builds a weekly report from database rows and scoring results. The Markdown renderer outputs a readable advisory report with focus items, distributions, keyword counts, tags, and deterministic handling guidance.

### Notification

The notification module sends reports with the Python standard library:

- `email.message.EmailMessage`
- `smtplib`

It supports STARTTLS, SMTP over SSL, plain SMTP, attachments, provider presets, and testable SMTP injection.
