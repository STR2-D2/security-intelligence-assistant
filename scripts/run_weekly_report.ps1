$ErrorActionPreference = "Stop"

$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Python = Join-Path $ProjectRoot ".venv\Scripts\python.exe"

function Invoke-WorkflowStep {
    param(
        [string]$StepName,
        [string]$ModuleName
    )

    Write-Host ""
    Write-Host $StepName
    & $Python -m $ModuleName

    if ($LASTEXITCODE -ne 0) {
        Write-Error "Failed step: $StepName"
        exit $LASTEXITCODE
    }
}

if (-not (Test-Path -LiteralPath $Python)) {
    Write-Error "Python executable not found: $Python"
    exit 1
}

Set-Location $ProjectRoot

Write-Host "===================================="
Write-Host "Security Intelligence Assistant"
Write-Host "Weekly Security Report Workflow"
Write-Host "===================================="

Invoke-WorkflowStep "[1/3] Collecting vulnerability intelligence..." "app.main"
Invoke-WorkflowStep "[2/3] Generating security report..." "app.generate_report"
Invoke-WorkflowStep "[3/3] Sending email..." "app.send_report"

Write-Host ""
Write-Host "Workflow completed successfully."
