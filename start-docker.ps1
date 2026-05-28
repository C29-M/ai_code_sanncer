<<<<<<< Updated upstream
# AI Code Scanner - start in Docker sandbox mode
# Usage:
#   .\start-docker.ps1                                  # auto-detect language (fast + accurate)
#   .\start-docker.ps1 /opt/semgrep-rules               # full pack (slowest, all languages)
#   .\start-docker.ps1 /opt/semgrep-rules/javascript    # force JS-only
#   .\start-docker.ps1 /opt/semgrep-rules/python        # force Python-only

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

# Verify Docker is reachable
try { docker ps | Out-Null } catch {
    Write-Host ""
    Write-Host "ERROR: Docker is not running. Start Docker Desktop and re-run this script." -ForegroundColor Red
    Write-Host ""
    exit 1
}

$env:SEMGREP_USE_DOCKER = "true"
if ($args[0]) {
    $env:DOCKER_SEMGREP_CONFIG = $args[0]
} else {
    $env:DOCKER_SEMGREP_CONFIG = "auto"
}

# Local dev: effectively no timeout (30 min). Production keeps 90s default per OSS Plan.
if (-not $env:SCAN_TIMEOUT_SECONDS) {
    $env:SCAN_TIMEOUT_SECONDS = "1800"
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " AI Code Scanner - Docker sandbox mode"     -ForegroundColor Cyan
Write-Host " Rule scope: $env:DOCKER_SEMGREP_CONFIG"    -ForegroundColor Cyan
Write-Host " UI:         http://127.0.0.1:8000/"        -ForegroundColor Cyan
Write-Host " Docs:       http://127.0.0.1:8000/docs"    -ForegroundColor Cyan
Write-Host " Stop:       Ctrl + C"                      -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

uvicorn main:app --reload
=======
# AI Code Scanner - start in Docker sandbox mode
# Usage:
#   .\start-docker.ps1                                  # auto-detect language (fast + accurate)
#   .\start-docker.ps1 /opt/semgrep-rules               # full pack (slowest, all languages)
#   .\start-docker.ps1 /opt/semgrep-rules/javascript    # force JS-only
#   .\start-docker.ps1 /opt/semgrep-rules/python        # force Python-only

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

# Verify Docker is reachable
try { docker ps | Out-Null } catch {
    Write-Host ""
    Write-Host "ERROR: Docker is not running. Start Docker Desktop and re-run this script." -ForegroundColor Red
    Write-Host ""
    exit 1
}

$env:SEMGREP_USE_DOCKER = "true"
if ($args[0]) {
    $env:DOCKER_SEMGREP_CONFIG = $args[0]
} else {
    $env:DOCKER_SEMGREP_CONFIG = "auto"
}

# Local dev: effectively no timeout (30 min). Production keeps 90s default per OSS Plan.
if (-not $env:SCAN_TIMEOUT_SECONDS) {
    $env:SCAN_TIMEOUT_SECONDS = "1800"
}

Write-Host ""
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host " AI Code Scanner - Docker sandbox mode"     -ForegroundColor Cyan
Write-Host " Rule scope: $env:DOCKER_SEMGREP_CONFIG"    -ForegroundColor Cyan
Write-Host " UI:         http://127.0.0.1:8000/"        -ForegroundColor Cyan
Write-Host " Docs:       http://127.0.0.1:8000/docs"    -ForegroundColor Cyan
Write-Host " Stop:       Ctrl + C"                      -ForegroundColor Cyan
Write-Host "==========================================" -ForegroundColor Cyan
Write-Host ""

uvicorn main:app --reload
>>>>>>> Stashed changes
