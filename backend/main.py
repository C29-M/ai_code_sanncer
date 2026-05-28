import asyncio
import logging
<<<<<<< Updated upstream
from pathlib import Path
=======
import shutil
import time
import uuid
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
>>>>>>> Stashed changes

from fastapi import FastAPI, Header, HTTPException, Request, BackgroundTasks
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

from bandit_runner import run_bandit_scan
from eslint_runner import run_eslint_scan
from exceptions import RepoCloneError, ScannerError
from gitleaks_runner import run_gitleaks_scan
from gosec_runner import run_gosec_scan
from language_detection import detect_languages
from models import ScanRequest, ScanResponse
from normalizer import normalise_all
from repo_cloner import clone_repository
from safety_runner import run_safety_scan
from scanner import extract_findings, run_semgrep_scan
from owasp_depcheck_runner import run_owasp_depcheck_scan
from spotbugs_runner import run_spotbugs_scan
from trufflehog_runner import run_trufflehog_scan
from trivy_runner import ensure_trivy_db, run_trivy_scan

STATIC_DIR = Path(__file__).resolve().parent / "static"

STATIC_DIR = Path(__file__).resolve().parent / "static"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# API key auth + rate limiting (Problem #4 — structured for future JWT)
# ---------------------------------------------------------------------------
# For the demo a single dev key is fine; swap this for a DB-backed key store later.
VALID_API_KEYS: set[str] = {"dev-api-key-week4"}
RATE_LIMIT_PER_HOUR = 10

# {api_key: [timestamp, ...]}  — old entries are pruned on each request
_rate_limit_store: dict[str, list[float]] = defaultdict(list)


def _check_api_key(api_key: str | None) -> str:
    if not api_key or api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=401, detail="Invalid or missing X-API-Key header."
        )
    return api_key


def _check_rate_limit(api_key: str) -> None:
    now = time.time()
    window = now - 3600  # 1-hour rolling window
    calls = [t for t in _rate_limit_store[api_key] if t > window]
    if len(calls) >= RATE_LIMIT_PER_HOUR:
        raise HTTPException(
            status_code=429,
            detail=f"Rate limit exceeded — max {RATE_LIMIT_PER_HOUR} scans per hour.",
        )
    calls.append(now)
    _rate_limit_store[api_key] = calls


# ---------------------------------------------------------------------------
# Async job store (Problem #4 — structured so mobile can poll)
# BullMQ + Redis is Phase 5; FastAPI BackgroundTasks covers Week 4.
# ---------------------------------------------------------------------------
@dataclass
class ScanJob:
    job_id: str
    repo_url: str
    status: str  # pending | running | completed | failed
    created_at: datetime
    progress: str = "Queued"
    findings: list[dict] = field(default_factory=list)
    scanner_summary: dict[str, int] = field(default_factory=dict)
    scanner_status: dict[str, str] = field(default_factory=dict)
    findings_count: int = 0
    error: str | None = None
    elapsed_s: float | None = None


_jobs: dict[str, ScanJob] = {}
_jobs_lock = asyncio.Lock()


# ---------------------------------------------------------------------------
# Post-clone repo validation
# ---------------------------------------------------------------------------
SCANNABLE_EXTENSIONS = {
    ".py",
    ".js",
    ".ts",
    ".jsx",
    ".tsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".cs",
    ".cpp",
    ".c",
    ".h",
    ".rs",
    ".kt",
    ".scala",
}

MANIFEST_FILES = {
    "package.json",
    "requirements.txt",
    "Pipfile",
    "Pipfile.lock",
    "poetry.lock",
    "go.mod",
    "go.sum",
    "pom.xml",
    "build.gradle",
    "Gemfile",
    "Gemfile.lock",
    "composer.json",
    "cargo.toml",
    "cargo.lock",
}

REPO_SIZE_WARN_MB = 500


def _validate_repo(clone_path: Path) -> None:
    all_files = [f for f in clone_path.rglob("*") if f.is_file()]
    non_git = [f for f in all_files if ".git" not in f.parts]
    if not non_git:
        raise RepoCloneError("Repository appears to be empty — no files found to scan.")
    total_bytes = sum(f.stat().st_size for f in non_git)
    total_mb = total_bytes / (1024 * 1024)
    if total_mb > REPO_SIZE_WARN_MB:
        logger.warning("Large repo: %.0f MB — scans may be slow or timeout.", total_mb)
    else:
        logger.info("Repo size: %.1f MB, %d files", total_mb, len(non_git))

    scannable = [f for f in non_git if f.suffix.lower() in SCANNABLE_EXTENSIONS]
    if not scannable:
        logger.warning(
            "No scannable source files found — Semgrep may return 0 findings."
        )
    else:
        logger.info("Scannable source files: %d", len(scannable))

    manifests = [f for f in non_git if f.name.lower() in MANIFEST_FILES]
    if not manifests:
        logger.warning(
            "No manifest files found — Trivy/Safety will return 0 CVE findings."
        )
    else:
        logger.info(
            "Manifest files found: %s", ", ".join(sorted({f.name for f in manifests}))
        )


# ---------------------------------------------------------------------------
# Safe wrappers — every scanner returns (findings/output, status: str)
# Problem #3: all failures are caught per-scanner; never kill the whole job.
# ---------------------------------------------------------------------------


def _safe(name: str, fn, *args, default=None):
    """
    Generic safe runner. Returns (result, 'ok') or (default, 'skipped').
    Logs failures with timing. Never raises.
    """
    if default is None:
        default = []
    t0 = time.perf_counter()
    try:
        result = fn(*args)
        elapsed = time.perf_counter() - t0
        count = (
            len(result)
            if isinstance(result, list)
            else (
                sum(
                    len(r.get("Vulnerabilities") or [])
                    for r in (result.get("Results") or [])
                )
                if isinstance(result, dict)
                else 0
            )
        )
        logger.info("%s: %d finding(s) in %.2fs", name, count, elapsed)
        return result, "ok"
    except Exception as exc:  # noqa: BLE001
        elapsed = time.perf_counter() - t0
        logger.warning("%s skipped after %.2fs — %s", name, elapsed, exc)
        return default, "skipped"


def _run_semgrep_safe(clone_path):
    return _safe("Semgrep", run_semgrep_scan, clone_path, default={})


def _run_gitleaks_safe(clone_path):
    return _safe("Gitleaks", run_gitleaks_scan, clone_path)


def _run_trivy_safe(clone_path):
    return _safe("Trivy", run_trivy_scan, clone_path, default={"Results": []})


def _run_bandit_safe(clone_path):
    return _safe("Bandit", run_bandit_scan, clone_path)


def _run_safety_safe(clone_path):
    return _safe("Safety", run_safety_scan, clone_path)


def _run_eslint_safe(clone_path):
    return _safe("ESLint", run_eslint_scan, clone_path)


def _run_gosec_safe(clone_path):
    return _safe("Gosec", run_gosec_scan, clone_path)


def _run_trufflehog_safe(clone_path):
    return _safe("TruffleHog", run_trufflehog_scan, clone_path)


def _run_spotbugs_safe(clone_path):
    return _safe("SpotBugs", run_spotbugs_scan, clone_path)


def _run_owasp_depcheck_safe(clone_path):
    return _safe("OWASP-DepCheck", run_owasp_depcheck_scan, clone_path)


# ---------------------------------------------------------------------------
# Core scan logic — shared by sync endpoint and async job runner
# ---------------------------------------------------------------------------
async def _execute_scan(repo_url: str, progress_cb=None) -> dict[str, Any]:
    """
    Clone, validate, run all applicable scanners, normalise.
    Returns a dict with findings, scanner_summary, scanner_status, elapsed_s.
    Raises ScannerError on unrecoverable failures (bad URL, empty repo, etc.)
    """
    scan_start = time.perf_counter()

    if progress_cb:
        progress_cb("Cloning repository…")

    t_clone = time.perf_counter()
    clone_path = clone_repository(repo_url)
    logger.info("Cloned to %s in %.2fs", clone_path, time.perf_counter() - t_clone)
    _validate_repo(clone_path)

    lang_map = detect_languages(clone_path)
    logger.info("Languages detected: %s", lang_map)

    has_python = lang_map.get("python", 0) > 0
    has_js = lang_map.get("javascript", 0) + lang_map.get("typescript", 0) > 0
    has_go = lang_map.get("go", 0) > 0
    has_java = lang_map.get("java", 0) > 0

    try:
        if progress_cb:
            progress_cb("Running scanners…")

        t_scanners = time.perf_counter()
        loop = asyncio.get_event_loop()

        # Build named futures — only fire language-specific scanners when relevant
        # Problem #6: file-count + percentage detection already in detect_languages()
        futures: dict[str, Any] = {}

        with ThreadPoolExecutor(max_workers=8) as executor:
            futures["semgrep"] = loop.run_in_executor(
                executor, _run_semgrep_safe, clone_path
            )
            futures["gitleaks"] = loop.run_in_executor(
                executor, _run_gitleaks_safe, clone_path
            )
            futures["trivy"] = loop.run_in_executor(
                executor, _run_trivy_safe, clone_path
            )
            futures["trufflehog"] = loop.run_in_executor(
                executor, _run_trufflehog_safe, clone_path
            )

            if has_python:
                futures["bandit"] = loop.run_in_executor(
                    executor, _run_bandit_safe, clone_path
                )
                futures["safety"] = loop.run_in_executor(
                    executor, _run_safety_safe, clone_path
                )
            if has_js:
                futures["eslint"] = loop.run_in_executor(
                    executor, _run_eslint_safe, clone_path
                )
            if has_go:
                futures["gosec"] = loop.run_in_executor(
                    executor, _run_gosec_safe, clone_path
                )
            if has_java:
                # Problem #7: SpotBugs runs in the shared pool but safe wrapper
                # has its own dedicated timeout — can't slow others.
                futures["spotbugs"] = loop.run_in_executor(
                    executor, _run_spotbugs_safe, clone_path
                )
                futures["owasp_depcheck"] = loop.run_in_executor(
                    executor, _run_owasp_depcheck_safe, clone_path
                )

            # Problem #3: return_exceptions=True — one crash can't kill the gather
            keys = list(futures.keys())
            raw_results = await asyncio.gather(
                *futures.values(), return_exceptions=True
            )

        logger.info(
            "All scanners finished in %.2fs (wall time)",
            time.perf_counter() - t_scanners,
        )

        # Unpack results — handle any unexpected exceptions that slipped through
        results: dict[str, tuple] = {}
        for k, r in zip(keys, raw_results):
            if isinstance(r, Exception):
                logger.error("Unhandled exception from %s: %s", k, r)
                default = {"Results": []} if k == "trivy" else []
                results[k] = (default, "skipped")
            else:
                results[k] = r

        def get(name, default_val):
            return results.get(name, (default_val, "skipped"))

        semgrep_raw, semgrep_status = get("semgrep", {})
        gitleaks_findings, gitleaks_status = get("gitleaks", [])
        trivy_output, trivy_status = get("trivy", {"Results": []})
        trufflehog_findings, trufflehog_status = get("trufflehog", [])
        bandit_findings, bandit_status = get("bandit", [])
        safety_findings, safety_status = get("safety", [])
        eslint_findings, eslint_status = get("eslint", [])
        gosec_findings, gosec_status = get("gosec", [])
        spotbugs_findings, spotbugs_status = get("spotbugs", [])
        owasp_depcheck_findings, owasp_depcheck_status = get("owasp_depcheck", [])

        semgrep_findings = extract_findings(
            semgrep_raw if isinstance(semgrep_raw, dict) else {}
        )
        logger.info("Semgrep: %d finding(s)", len(semgrep_findings))

        if progress_cb:
            progress_cb("Normalising findings…")

        t_norm = time.perf_counter()
        findings = normalise_all(
            semgrep_findings,
            gitleaks_findings,
            trivy_output,
            bandit_findings,
            safety_findings,
            eslint_findings,
            gosec_findings,
            trufflehog_findings,
            spotbugs_findings,
            owasp_depcheck_findings,
        )
        logger.info(
            "Normalised to %d finding(s) in %.2fs",
            len(findings),
            time.perf_counter() - t_norm,
        )

        scanner_summary: dict[str, int] = {
            "semgrep": 0,
            "gitleaks": 0,
            "trivy": 0,
            "bandit": 0,
            "safety": 0,
            "eslint": 0,
            "gosec": 0,
            "trufflehog": 0,
            "spotbugs": 0,
            "owasp_depcheck": 0,
        }
        for f in findings:
            tool = f["tool"]
            scanner_summary[tool] = scanner_summary.get(tool, 0) + 1

        # Scanners not activated for this repo show as "not_applicable"
        scanner_status: dict[str, str] = {
            "semgrep": semgrep_status,
            "gitleaks": gitleaks_status,
            "trivy": trivy_status,
            "trufflehog": trufflehog_status,
            "bandit": bandit_status if has_python else "not_applicable",
            "safety": safety_status if has_python else "not_applicable",
            "eslint": eslint_status if has_js else "not_applicable",
            "gosec": gosec_status if has_go else "not_applicable",
            "spotbugs": spotbugs_status if has_java else "not_applicable",
            "owasp_depcheck": owasp_depcheck_status if has_java else "not_applicable",
        }

        elapsed = time.perf_counter() - scan_start
        logger.info("Scan complete — %d findings, total %.2fs", len(findings), elapsed)

        return {
            "findings": findings,
            "scanner_summary": scanner_summary,
            "scanner_status": scanner_status,
            "findings_count": len(findings),
            "elapsed_s": round(elapsed, 2),
        }

    finally:
        if clone_path.exists():
            shutil.rmtree(clone_path, ignore_errors=True)
            logger.info("Cleaned up clone: %s", clone_path)


# ---------------------------------------------------------------------------
# Background job runner (REST API async path)
# ---------------------------------------------------------------------------
async def _run_job(job_id: str, repo_url: str) -> None:
    """Run a scan job in the background. Updates _jobs in place."""
    async with _jobs_lock:
        job = _jobs.get(job_id)
        if not job:
            return
        job.status = "running"
        job.progress = "Starting scan…"

    def _progress(msg: str) -> None:
        job.progress = msg

    try:
        result = await _execute_scan(repo_url, progress_cb=_progress)
        async with _jobs_lock:
            job.status = "completed"
            job.findings = result["findings"]
            job.scanner_summary = result["scanner_summary"]
            job.scanner_status = result["scanner_status"]
            job.findings_count = result["findings_count"]
            job.elapsed_s = result["elapsed_s"]
            job.progress = "Done"
    except Exception as exc:  # noqa: BLE001
        logger.error("Job %s failed: %s", job_id, exc)
        async with _jobs_lock:
            job.status = "failed"
            job.error = str(exc)
            job.progress = "Failed"


# ---------------------------------------------------------------------------
# FastAPI app
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(_app: FastAPI):
    loop = asyncio.get_event_loop()
    loop.run_in_executor(None, ensure_trivy_db)
    logger.info("Trivy DB refresh scheduled in background.")
    yield


app = FastAPI(
    title="AI Code Scanner",
    description=(
        "Week 4 — 10-scanner pipeline: Semgrep · Gitleaks · Trivy · Bandit · Safety "
        "· ESLint Security · Gosec · TruffleHog · SpotBugs · OWASP Dependency-Check. "
        "REST API with async job queue."
    ),
    version="0.4.0",
    lifespan=lifespan,
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


app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
async def index() -> FileResponse:
    return FileResponse(STATIC_DIR / "index.html")


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Sync scan endpoint — used by the web UI (backward compatible)
# ---------------------------------------------------------------------------
@app.post("/scan", response_model=ScanResponse)
async def scan_repository(body: ScanRequest) -> ScanResponse:
    repo_url = str(body.repo_url)
    logger.info("Sync scan requested: %s", repo_url)

    result = await _execute_scan(repo_url)

    return ScanResponse(
        repo_url=repo_url,
        clone_path="",
        findings_count=result["findings_count"],
        findings=result["findings"],
        scanner_summary=result["scanner_summary"],
        scanner_status=result["scanner_status"],
    )


# ---------------------------------------------------------------------------
# REST API — async job queue (for mobile / external clients)
# Problem #4: structured for future WebSocket/SSE migration
# ---------------------------------------------------------------------------


@app.post("/api/v1/scan", status_code=202)
async def submit_scan(
    body: ScanRequest,
    background_tasks: BackgroundTasks,
    x_api_key: str | None = Header(default=None),
) -> dict:
    """
    Submit a scan job. Returns job_id immediately.
    Poll GET /api/v1/scan/{job_id} for status and results.
    """
    api_key = _check_api_key(x_api_key)
    _check_rate_limit(api_key)

    repo_url = str(body.repo_url)
    job_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    job = ScanJob(
        job_id=job_id,
        repo_url=repo_url,
        status="pending",
        created_at=now,
    )
    _jobs[job_id] = job

    background_tasks.add_task(_run_job, job_id, repo_url)

    logger.info("Job %s submitted for %s", job_id, repo_url)
    return {
        "job_id": job_id,
        "status": "pending",
        "created_at": now.isoformat(),
        # Future migration hint: when WebSocket support is added, connect to
        # ws://.../api/v1/scan/{job_id}/stream instead of polling this endpoint.
    }


@app.get("/api/v1/scan/{job_id}")
async def get_scan_status(
    job_id: str, x_api_key: str | None = Header(default=None)
) -> dict:
    """
    Poll for scan status and results.

    Returns:
      - pending/running: {job_id, status, progress}
      - completed:       {job_id, status, findings_count, findings, scanner_summary, scanner_status, elapsed_s}
      - failed:          {job_id, status, error}
    """
    _check_api_key(x_api_key)

    job = _jobs.get(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found.")

    base = {
        "job_id": job.job_id,
        "status": job.status,
        "repo_url": job.repo_url,
        "created_at": job.created_at.isoformat(),
    }

    if job.status in ("pending", "running"):
        return {**base, "progress": job.progress}

    if job.status == "failed":
        return {**base, "error": job.error}

    # completed
    return {
        **base,
        "findings_count": job.findings_count,
        "findings": job.findings,
        "scanner_summary": job.scanner_summary,
        "scanner_status": job.scanner_status,
        "elapsed_s": job.elapsed_s,
    }


@app.get("/api/v1/jobs")
async def list_jobs(x_api_key: str | None = Header(default=None)) -> dict:
    """List recent jobs (last 20). Useful for debugging."""
    _check_api_key(x_api_key)
    recent = sorted(_jobs.values(), key=lambda j: j.created_at, reverse=True)[:20]
    return {
        "jobs": [
            {
                "job_id": j.job_id,
                "repo_url": j.repo_url,
                "status": j.status,
                "created_at": j.created_at.isoformat(),
            }
            for j in recent
        ]
    }
