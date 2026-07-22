# Workflow

The project can be run step by step or through the full workflow script.

## Full Workflow

```text
Collect
  |
  v
Normalize
  |
  v
Validate
  |
  v
Upsert into SQLite
  |
  v
Evaluate Risk
  |
  v
Match Watchlists
  |
  v
Calculate Enterprise Priority
  |
  v
Generate Markdown Report
  |
  v
Send Email
```

Run everything:

```powershell
.\scripts\run_weekly_report.ps1
```

The script automatically locates the project root and `.venv\Scripts\python.exe`.

## Individual Steps

Collect and store vulnerabilities:

```powershell
.\scripts\collect.ps1
```

Generate the Markdown report:

```powershell
.\scripts\generate_report.ps1
```

Send the newest generated report:

```powershell
.\scripts\send_report.ps1
```

Equivalent Python module commands:

```powershell
.venv\Scripts\python.exe -m app.main
.venv\Scripts\python.exe -m app.generate_report
.venv\Scripts\python.exe -m app.send_report
```

## Reports

Reports are written under:

```text
reports/
```

Generated Markdown reports are ignored by Git:

```text
reports/*.md
```

## Error Behavior

The workflow script stops when a command returns a non-zero exit code.

Inside `CollectorAgent`, individual collector failures are logged and isolated. For example, if NVD times out, CISA KEV results can still be collected and later steps can continue if the application command exits successfully.
