# Operational Scripts

## Available Scripts

### Full workflow

PowerShell:

```powershell
scripts\run_weekly_report.ps1
```

Runs vulnerability collection, report generation, and email delivery.

### Collect only

```powershell
scripts\collect.ps1
```

### Generate report only

```powershell
scripts\generate_report.ps1
```

### Send report only

```powershell
scripts\send_report.ps1
```

## Notes

- Scripts assume `.venv` exists under the project root.
- Scripts do not store credentials.
- SMTP configuration comes from `.env`.
- Reports are generated under `reports/`.
