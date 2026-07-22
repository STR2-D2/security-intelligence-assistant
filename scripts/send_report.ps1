$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

if (-not (Test-Path -LiteralPath $Python)) {
    Write-Error "Python executable not found: $Python"
    exit 1
}

Set-Location $ProjectRoot
Write-Host "Sending security report..."
& $Python -m app.send_report
exit $LASTEXITCODE
