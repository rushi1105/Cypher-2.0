param(
    [string]$HostAddress = "127.0.0.1",
    [int]$Port = 8000
)

$ErrorActionPreference = "Stop"

$root = Split-Path -Parent $PSScriptRoot
$venv = Join-Path $root ".venv"
$python = Join-Path $venv "Scripts\python.exe"

if (-not (Test-Path $python)) {
    Write-Output "Creating virtual environment..."
    python -m venv $venv
    if ($LASTEXITCODE -ne 0) {
        throw "Failed to create virtual environment"
    }
    & $python -m pip install --upgrade pip
    & $python -m pip install -r (Join-Path $root "server\requirements.txt")
}

Push-Location $root
try {
    & $python -m uvicorn server.server:app --host $HostAddress --port $Port --reload
}
finally {
    Pop-Location
}
