<#
.SYNOPSIS
Runs the local Python checks for this repository.

.DESCRIPTION
This helper resolves the repo root automatically, uses the local virtual
environment when available, and auto-installs missing Python test dependencies
from the local package extras (`.[dev]`).

.EXAMPLE
.\scripts\check.ps1

.EXAMPLE
.\scripts\check.ps1 -NoCompile
#>

param(
    [switch]$NoCompile
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$PythonExe = Join-Path $RepoRoot ".venv\Scripts\python.exe"
if (-not (Test-Path $PythonExe)) {
    $PythonExe = "python"
}

Push-Location $RepoRoot
try {
    & $PythonExe -c "import pytest, build, numpy, scapy" 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Host "Installing Python check dependencies..."
        & $PythonExe -m pip install -q -e ".[dev]"
    }

    if (-not $NoCompile) {
        & $PythonExe -m compileall -q (Join-Path $RepoRoot "wifi_pipeline")
    }

    & $PythonExe -m pytest -q
}
finally {
    Pop-Location
}
