import logging
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from exceptions import ScannerError
from models import ScanRequest, ScanResponse
from repo_cloner import clone_repository
from scanner import extract_findings, run_semgrep_scan

STATIC_DIR = Path(__file__).resolve().parent / "static"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Code Scanner",
    description=(
        "Clone a GitHub repo and run Semgrep. With SEMGREP_USE_DOCKER=true (default), "
        "scans run in Docker using vendored rules at /opt/semgrep-rules (network none). "
        "Set DOCKER_SEMGREP_NETWORK=bridge and DOCKER_SEMGREP_CONFIG=auto for registry rules; "
        "set SEMGREP_USE_DOCKER=false for host Semgrep. See backend/DOCKER.md."
    ),
    version="0.2.0",
)


@app.exception_handler(ScannerError)
async def scanner_error_handler(_request: Request, exc: ScannerError) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.message},
    )


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(
        status_code=422,
        content={"detail": exc.errors()},
    )


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan_repository(body: ScanRequest) -> ScanResponse:
    repo_url = str(body.repo_url)
    logger.info("Starting scan for %s", repo_url)

    clone_path = clone_repository(repo_url)
    logger.info("Cloned repository to %s", clone_path)

    semgrep_output = run_semgrep_scan(clone_path)
    logger.info("Semgrep scan finished successfully")
    logger.info("Total findings: %d", len(extract_findings(semgrep_output)))
    findings = extract_findings(semgrep_output)

    logger.info("Scan complete: %d finding(s)", len(findings))

    return ScanResponse(
        repo_url=repo_url,
        clone_path=str(clone_path),
        findings_count=len(findings),
        findings=semgrep_output,
    )
