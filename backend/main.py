"""Week 4/5 multi-scanner orchestration — 10 parallel scanners + classifier."""

from __future__ import annotations
import asyncio
import logging
import shutil
import time
from pathlib import Path
from fastapi import BackgroundTasks, FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from classifier_client import enrich_findings, is_classifier_available
from bandit_runner import run_bandit_scan
from eslint_runner import run_eslint_scan
from exceptions import ScannerError
from gitleaks_runner import run_gitleaks_scan
from gosec_runner import run_gosec_scan
from language_detection import detect_languages
from models import ScanRequest, ScanResponse
from normalizer import normalise_all
from owasp_depcheck_runner import run_owasp_depcheck_scan
from repo_cloner import clone_repository
from safety_runner import run_safety_scan
from scanner import extract_findings, run_semgrep_scan
from spotbugs_runner import run_spotbugs_scan
from trivy_runner import ensure_trivy_db, run_trivy_scan
from trufflehog_runner import run_trufflehog_scan

STATIC_DIR = Path(__file__).resolve().parent / "static"
MANIFEST_FILES = {
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "requirements.txt",
    "Pipfile",
    "setup.py",
    "setup.cfg",
    "pyproject.toml",
    "pom.xml",
    "build.gradle",
    "build.gradle.kts",
    "go.mod",
    "go.sum",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "Cargo.toml",
}
SIZE_WARN_BYTES = 50 * 1024 * 1024

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="AI Code Scanner",
    description="10-scanner security pipeline + Week 5 classifier.",
    version="0.5.0",
)


@app.on_event("startup")
async def _startup() -> None:
    loop = asyncio.get_event_loop()
    await loop.run_in_executor(None, ensure_trivy_db)
    clf_ok = is_classifier_available()
    logger.info(
        "Classifier service: %s", "READY" if clf_ok else "UNAVAILABLE (fallback mode)"
    )


@app.exception_handler(ScannerError)
async def scanner_error_handler(_request: Request, exc: ScannerError) -> JSONResponse:
    return JSONResponse(status_code=exc.status_code, content={"detail": exc.message})


@app.exception_handler(RequestValidationError)
async def validation_error_handler(
    _request: Request, exc: RequestValidationError
) -> JSONResponse:
    return JSONResponse(status_code=422, content={"detail": exc.errors()})


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict:
    return {"status": "ok"}


def _run_scanner(func, *args):
    try:
        return func(*args)
    except Exception as exc:
        return exc


def _unpack_list(raw, name: str) -> list:
    if isinstance(raw, Exception):
        logger.warning("Scanner %s skipped: %s", name, raw)
        return []
    return raw if isinstance(raw, list) else []


def _unpack_dict(raw, name: str) -> dict:
    if isinstance(raw, Exception):
        logger.warning("Scanner %s skipped: %s", name, raw)
        return {"Results": []}
    return raw if isinstance(raw, dict) else {"Results": []}


def _validate_clone(clone_path: Path, lang_counts: dict) -> list:
    warnings = []
    all_files = [
        f for f in clone_path.rglob("*") if f.is_file() and ".git" not in f.parts
    ]
    if not all_files:
        warnings.append("Repository appears empty — no files found.")
        return warnings
    total_bytes = sum(f.stat().st_size for f in all_files if not f.is_symlink())
    if total_bytes > SIZE_WARN_BYTES:
        warnings.append(
            f"Large repository ({total_bytes/1024/1024:.0f} MB) — scans may be slower."
        )
    if not lang_counts:
        warnings.append("No recognised source files — Semgrep may return no findings.")
    if not any(
        f.name in MANIFEST_FILES
        for f in clone_path.rglob("*")
        if f.is_file() and ".git" not in f.parts
    ):
        warnings.append("No dependency manifest found — Trivy has nothing to scan.")
    return warnings


@app.post("/scan", response_model=ScanResponse)
async def scan_repository(
    body: ScanRequest, background_tasks: BackgroundTasks
) -> ScanResponse:
    repo_url = str(body.repo_url)
    logger.info("Starting scan for %s", repo_url)
    _scan_start = time.time()
    clone_path = clone_repository(repo_url, github_token=body.github_token)
    logger.info("Cloned repository to %s", clone_path)

    lang_counts = detect_languages(clone_path)
    has_python = lang_counts.get("python", 0) > 0
    has_js = lang_counts.get("javascript", 0) + lang_counts.get("typescript", 0) > 0
    has_go = lang_counts.get("go", 0) > 0
    has_java = lang_counts.get("java", 0) > 0
    logger.info(
        "Language detection: python=%s js=%s go=%s java=%s | counts=%s",
        has_python,
        has_js,
        has_go,
        has_java,
        lang_counts,
    )

    scan_warnings = _validate_clone(clone_path, lang_counts)
    for w in scan_warnings:
        logger.warning("Edge-case: %s", w)

    loop = asyncio.get_event_loop()
    fut_semgrep = loop.run_in_executor(None, run_semgrep_scan, clone_path)
    fut_gitleaks = loop.run_in_executor(
        None, _run_scanner, run_gitleaks_scan, clone_path
    )
    fut_trivy = loop.run_in_executor(None, _run_scanner, run_trivy_scan, clone_path)
    fut_trufflehog = loop.run_in_executor(
        None, _run_scanner, run_trufflehog_scan, clone_path
    )
    fut_bandit = (
        loop.run_in_executor(None, _run_scanner, run_bandit_scan, clone_path)
        if has_python
        else None
    )
    fut_safety = (
        loop.run_in_executor(None, _run_scanner, run_safety_scan, clone_path)
        if has_python
        else None
    )
    fut_eslint = (
        loop.run_in_executor(None, _run_scanner, run_eslint_scan, clone_path)
        if has_js
        else None
    )
    fut_gosec = (
        loop.run_in_executor(None, _run_scanner, run_gosec_scan, clone_path)
        if has_go
        else None
    )
    fut_spotbugs = (
        loop.run_in_executor(None, _run_scanner, run_spotbugs_scan, clone_path)
        if has_java
        else None
    )
    fut_owasp = (
        loop.run_in_executor(None, _run_scanner, run_owasp_depcheck_scan, clone_path)
        if has_java
        else None
    )

    try:
        semgrep_output = await fut_semgrep
    except Exception as exc:
        logger.warning("Semgrep failed or timed out: %s", exc)
        semgrep_output = {"results": [], "errors": []}
    gitleaks_raw = await fut_gitleaks
    trivy_raw = await fut_trivy
    trufflehog_raw = await fut_trufflehog
    bandit_raw = await fut_bandit if fut_bandit is not None else None
    safety_raw = await fut_safety if fut_safety is not None else None
    eslint_raw = await fut_eslint if fut_eslint is not None else None
    gosec_raw = await fut_gosec if fut_gosec is not None else None
    spotbugs_raw = await fut_spotbugs if fut_spotbugs is not None else None
    owasp_raw = await fut_owasp if fut_owasp is not None else None
    logger.info("All scanners finished")

    semgrep_findings = extract_findings(semgrep_output)
    gitleaks_findings = _unpack_list(gitleaks_raw, "gitleaks")
    trivy_output_d = _unpack_dict(trivy_raw, "trivy")
    trufflehog_findings = _unpack_list(trufflehog_raw, "trufflehog")
    bandit_findings = (
        _unpack_list(bandit_raw, "bandit") if bandit_raw is not None else None
    )
    safety_findings = (
        _unpack_list(safety_raw, "safety") if safety_raw is not None else None
    )
    eslint_findings = (
        _unpack_list(eslint_raw, "eslint") if eslint_raw is not None else None
    )
    gosec_findings = _unpack_list(gosec_raw, "gosec") if gosec_raw is not None else None
    spotbugs_findings = (
        _unpack_list(spotbugs_raw, "spotbugs") if spotbugs_raw is not None else None
    )
    owasp_findings = (
        _unpack_list(owasp_raw, "owasp_depcheck") if owasp_raw is not None else None
    )

    def _status(raw, fut, findings) -> str:
        if fut is None:
            return "na"
        if isinstance(raw, Exception):
            return "skipped"
        return "active"

    scanner_status = {
        "semgrep": "active",
        "gitleaks": _status(gitleaks_raw, fut_gitleaks, gitleaks_findings),
        "trivy": _status(trivy_raw, fut_trivy, trivy_output_d),
        "trufflehog": _status(trufflehog_raw, fut_trufflehog, trufflehog_findings),
        "bandit": _status(bandit_raw, fut_bandit, bandit_findings),
        "safety": _status(safety_raw, fut_safety, safety_findings),
        "eslint": _status(eslint_raw, fut_eslint, eslint_findings),
        "gosec": _status(gosec_raw, fut_gosec, gosec_findings),
        "spotbugs": _status(spotbugs_raw, fut_spotbugs, spotbugs_findings),
        "owasp_depcheck": _status(owasp_raw, fut_owasp, owasp_findings),
    }
    scanners_active = [n for n, s in scanner_status.items() if s == "active"]

    unified = normalise_all(
        semgrep_findings=semgrep_findings,
        gitleaks_findings=gitleaks_findings,
        trivy_output=trivy_output_d,
        bandit_findings=bandit_findings,
        safety_findings=safety_findings,
        eslint_findings=eslint_findings,
        gosec_findings=gosec_findings,
        trufflehog_findings=trufflehog_findings,
        spotbugs_findings=spotbugs_findings,
        owasp_depcheck_findings=owasp_findings,
    )

    findings_by_severity: dict = {}
    for f in unified:
        sev = f.get("severity", "INFO")
        findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

    # Week 5 — enrich HIGH/CRITICAL findings with classifier output
    # Falls back silently if classifier service is down or times out
    unified = await enrich_findings(unified)
    classifier_enriched = sum(
        1 for f in unified if f.get("classifier_confidence", 0.0) > 0.0
    )
    classifier_ok = classifier_enriched > 0
    logger.info(
        "Scan complete: %d finding(s), %d classifier-enriched | scanners: %s",
        len(unified),
        classifier_enriched,
        ", ".join(scanners_active) if scanners_active else "none",
    )
    background_tasks.add_task(shutil.rmtree, clone_path, True)

    return ScanResponse(
        repo_url=repo_url,
        clone_path=str(clone_path),
        findings_count=len(unified),
        findings=unified,
        scanners_active=scanners_active,
        findings_by_severity=findings_by_severity,
        scanner_status=scanner_status,
        warnings=scan_warnings,
        scan_time_s=round(time.time() - _scan_start, 1),
        classifier_available=classifier_ok,
        classifier_enriched_count=classifier_enriched,
    )
