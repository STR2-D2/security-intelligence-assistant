# Configuration

Configuration is loaded by `app.config.Settings` from environment variables and a local `.env` file.

Do not commit `.env`. It may contain API keys, SMTP authorization codes, and local database paths.

## Basic Application Settings

```env
APP_NAME=Security Intelligence Assistant
ENVIRONMENT=development
LOG_LEVEL=INFO
DATABASE_URL=sqlite:///./security_intelligence.db
```

## NVD Settings

```env
NVD_API_URL=https://services.nvd.nist.gov/rest/json/cves/2.0
NVD_API_KEY=
NVD_RESULTS_PER_PAGE=2000
NVD_REQUEST_DELAY_SECONDS=6.0
NVD_LOOKBACK_DAYS=7
```

`NVD_API_KEY` is optional for basic use. If configured, it is sent through the NVD `apiKey` request header.

## Email Provider Presets

For common personal mailbox providers, use:

```env
EMAIL_PROVIDER=163
EMAIL_USERNAME=your-email@163.com
EMAIL_PASSWORD=your-smtp-authorization-code
EMAIL_FROM_NAME=Security Intelligence Assistant
REPORT_EMAIL_RECIPIENTS=recipient@example.com
```

Supported providers:

```text
163 -> smtp.163.com, port 465, SSL
qq  -> smtp.qq.com, port 465, SSL
```

`EMAIL_PASSWORD` should be an SMTP authorization code or application-specific password, not necessarily the web login password.

## Advanced SMTP Overrides

Enterprise SMTP servers can be configured directly:

```env
SMTP_HOST=
SMTP_PORT=
SMTP_USERNAME=
SMTP_PASSWORD=
SMTP_FROM_ADDRESS=
SMTP_FROM_NAME=
SMTP_USE_TLS=
SMTP_USE_SSL=
SMTP_TIMEOUT_SECONDS=30
```

Priority rules:

```text
SMTP_* overrides EMAIL_PROVIDER presets.
SMTP_USERNAME overrides EMAIL_USERNAME.
SMTP_PASSWORD overrides EMAIL_PASSWORD.
SMTP_FROM_NAME overrides EMAIL_FROM_NAME.
```

`SMTP_USE_TLS` and `SMTP_USE_SSL` cannot both be enabled.

## Recipients

Use a comma-separated list:

```env
REPORT_EMAIL_RECIPIENTS=secops@example.com,platform@example.com
```

The application trims whitespace and removes duplicate recipients while preserving order.

## Watchlists

Watchlists live in:

```text
config/watchlists/
```

Each YAML file defines one category and a set of keywords:

```yaml
category: cloud
keywords:
  Azure:
    aliases:
      - Microsoft Azure
    tags:
      - cloud
    score: 30
```

The canonical keyword name is automatically included as an alias.

The category `vulnerability_type` contributes to vulnerability-type score. All other categories contribute to enterprise relevance score.
