<<<<<<< Updated upstream
# AI Code Scanner - start in host mode (no Docker, fast iteration)
# Usage: .\start-host.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location "$root\backend"

if (-not (Test-Path ".\venv\Scripts\Activate.ps1")) {
    Write-Host "venv not found - creating it..." -ForegroundColor Yellow
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt
} else {
    .\venv\Scripts\Activate.ps1
}

$env:SEMGREP_USE_DOCKER = "false"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " AI Code Scanner - host mode (fast)"        -ForegroundColor Green
Write-Host " Sandbox:    OFF"                           -ForegroundColor Green
Write-Host " UI:         http://127.0.0.1:8000/"        -ForegroundColor Green
Write-Host " Docs:       http://127.0.0.1:8000/docs"    -ForegroundColor Green
Write-Host " Stop:       Ctrl + C"                      -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

uvicorn main:app --reload
=======
# AI Code Scanner - start in host mode (no Docker, fast iteration)
# Usage: .\start-host.ps1

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location "$root\backend"

if (-not (Test-Path ".\venv\Scripts\Activate.ps1")) {
    Write-Host "venv not found - creating it..." -ForegroundColor Yellow
    python -m venv venv
    .\venv\Scripts\Activate.ps1
    Write-Host "Installing dependencies..." -ForegroundColor Yellow
    pip install -r requirements.txt
} else {
    .\venv\Scripts\Activate.ps1
}

$env:SEMGREP_USE_DOCKER = "false"

Write-Host ""
Write-Host "==========================================" -ForegroundColor Green
Write-Host " AI Code Scanner - host mode (fast)"        -ForegroundColor Green
Write-Host " Sandbox:    OFF"                           -ForegroundColor Green
Write-Host " UI:         http://127.0.0.1:8000/"        -ForegroundColor Green
Write-Host " Docs:       http://127.0.0.1:8000/docs"    -ForegroundColor Green
Write-Host " Stop:       Ctrl + C"                      -ForegroundColor Green
Write-Host "==========================================" -ForegroundColor Green
Write-Host ""

uvicorn main:app --reload
>>>>>>> Stashed changes
