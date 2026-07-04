"""
Trivy runner for AI Code Scanner — Week 3.

Runs trivy fs (filesystem mode) on the host against the cloned repository.
Detects dependency CVEs across npm, pip, Maven, Go modules.
Failures are non-fatal: the scan continues with Semgrep + Gitleaks results.
"""

from __future__ import annotations

import json
import logging
import os
import re
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

from exceptions import TrivyScanError

TRIVY_SUCCESS_EXIT_CODES = {0}
TRIVY_DB_MAX_AGE_HOURS = 24  # refresh DB if older than this


def _trivy_cache_dir() -> Path:
    """
    Cache dir trivy will use. Honours TRIVY_CACHE_DIR (set at image build
    time so the DB is baked in and scans don't depend on runtime network
    access). Falls back to trivy's own default under $HOME.
    """
    env_dir = os.environ.get("TRIVY_CACHE_DIR")
    if env_dir:
        return Path(env_dir)
    return Path.home() / ".cache" / "trivy"


logger = logging.getLogger(__name__)


def _trivy_cli() -> str:
    exe = shutil.which("trivy") or shutil.which("trivy.exe")
    if not exe:
        raise TrivyScanError(
            "Trivy is not installed or not on PATH. "
            "Install from https://github.com/aquasecurity/trivy/releases"
        )
    return exe


def _trivy_db_age_hours() -> float | None:
    """
    Return how many hours ago the Trivy DB was last updated, or None if unknown.
    Trivy stores DB metadata at <cache-dir>/db/metadata.json.
    """
    candidates = [
        _trivy_cache_dir() / "db" / "metadata.json",
        Path.home() / ".cache" / "trivy" / "db" / "metadata.json",
        Path.home() / "AppData" / "Local" / "trivy" / "db" / "metadata.json",
    ]
    for meta_path in candidates:
        if meta_path.exists():
            try:
                import json as _json

                data = _json.loads(meta_path.read_text(encoding="utf-8"))
                updated_at = data.get("UpdatedAt") or data.get("updated_at")
                if updated_at:
                    dt = datetime.fromisoformat(updated_at.replace("Z", "+00:00"))
                    age = (datetime.now(timezone.utc) - dt).total_seconds() / 3600
                    return age
            except Exception:  # noqa: BLE001
                pass
    return None


def ensure_trivy_db(timeout: int | None = None) -> None:
    """
    Download or refresh the Trivy vulnerability database if it is missing
    or older than TRIVY_DB_MAX_AGE_HOURS hours.

    Called once at server startup — non-fatal if it fails.
    """
    try:
        trivy = _trivy_cli()
    except TrivyScanError:
        logger.warning("Trivy not found — skipping DB refresh.")
        return

    age = _trivy_db_age_hours()
    if age is not None and age < TRIVY_DB_MAX_AGE_HOURS:
        logger.info("Trivy DB is %.1f h old — no refresh needed.", age)
        return

    reason = f"{age:.1f} h old" if age is not None else "not found"
    logger.info("Trivy DB %s — downloading update…", reason)

    try:
        result = subprocess.run(
            [
                trivy,
                "fs",
                "--download-db-only",
                "--cache-dir",
                str(_trivy_cache_dir()),
                "--quiet",
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if result.returncode == 0:
            logger.info("Trivy DB refreshed successfully.")
        else:
            logger.warning(
                "Trivy DB refresh exited %d: %s",
                result.returncode,
                (result.stderr or "").strip(),
            )
    except subprocess.TimeoutExpired:
        logger.warning(
            "Trivy DB refresh timed out after %ds — using existing DB.", timeout
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning("Trivy DB refresh failed: %s", exc)


def _parse_trivy_json(stdout: str) -> dict:
    """Extract JSON from trivy stdout (may include log lines)."""
    stripped = stdout.strip()
    if not stripped:
        return {"Results": []}
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    for line in reversed(stripped.splitlines()):
        line = line.strip()
        if line.startswith("{"):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return {"Results": []}


_MAVEN_RETRY_AFTER_RE = re.compile(r"Retry-After:\s*(\d+)", re.IGNORECASE)


def _is_maven_rate_limited(stderr: str) -> int | None:
    """
    Return the suggested wait in seconds if stderr shows a Maven Central 429
    (common when Trivy's Java analyzer, the SpotBugs Maven build, and OWASP
    Dependency-Check all hit repo.maven.apache.org at once), else None.
    """
    if "429 Too Many Requests" not in stderr:
        return None
    m = _MAVEN_RETRY_AFTER_RE.search(stderr)
    return int(m.group(1)) if m else 30


def run_trivy_scan(repo_path: Path) -> dict:
    """
    Run trivy fs against the cloned repository in vulnerability scan mode.

    Returns the raw trivy JSON output dict.
    Returns {"Results": []} on no findings or parse failures.
    Raises TrivyScanError on tool errors.
    """
    if not repo_path.is_dir():
        raise TrivyScanError(f"Repository path does not exist: {repo_path}")

    trivy = _trivy_cli()
    abs_repo = str(repo_path.resolve())

    cmd = [
        trivy,
        "fs",
        "--format",
        "json",
        "--quiet",
        "--exit-code",
        "0",  # always exit 0
        "--cache-dir",
        str(_trivy_cache_dir()),
        "--skip-db-update",  # DB is baked into the image — don't depend on network per-scan
        "--offline-scan",  # never reach out to Maven Central etc. mid-scan — rely on the pre-warmed local repo
        "--scanners",
        "vuln",  # dependency CVEs only (no secret scan — Gitleaks handles that)
        abs_repo,
    ]

    result = None
    attempt = 0
    while True:
        attempt += 1
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=None,
                check=False,
            )
        except OSError as exc:
            raise TrivyScanError(f"Failed to run Trivy: {exc}") from exc

        if result.returncode in TRIVY_SUCCESS_EXIT_CODES:
            break
        wait_s = _is_maven_rate_limited(result.stderr or "")
        if wait_s is None:
            break
        logger.warning(
            "Trivy hit Maven Central rate limit (attempt %d) — "
            "waiting %ds as instructed.",
            attempt,
            wait_s,
        )
        time.sleep(wait_s)

    if result.returncode not in TRIVY_SUCCESS_EXIT_CODES:
        raise TrivyScanError(
            f"Trivy exited with code {result.returncode}: "
            f"{(result.stderr or '').strip()}"
        )

    return _parse_trivy_json(result.stdout or "")
