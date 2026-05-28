"""
Trivy runner for AI Code Scanner — Week 3.

Runs trivy fs (filesystem mode) on the host against the cloned repository.
Detects dependency CVEs across npm, pip, Maven, Go modules.
Failures are non-fatal: the scan continues with Semgrep + Gitleaks results.
"""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from exceptions import TrivyScanError

TRIVY_TIMEOUT = 180
TRIVY_SUCCESS_EXIT_CODES = {0}
TRIVY_DB_MAX_AGE_HOURS = 24  # refresh DB if older than this


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
    Trivy stores DB metadata at ~/.cache/trivy/db/metadata.json.
    """
    candidates = [
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


def ensure_trivy_db(timeout: int = 300) -> None:
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
            [trivy, "fs", "--download-db-only", "--quiet"],
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
        "--scanners",
        "vuln",  # dependency CVEs only (no secret scan — Gitleaks handles that)
        abs_repo,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TRIVY_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TrivyScanError(f"Trivy scan timed out after {TRIVY_TIMEOUT}s.") from exc
    except OSError as exc:
        raise TrivyScanError(f"Failed to run Trivy: {exc}") from exc

    if result.returncode not in TRIVY_SUCCESS_EXIT_CODES:
        raise TrivyScanError(
            f"Trivy exited with code {result.returncode}: "
            f"{(result.stderr or '').strip()}"
        )

    return _parse_trivy_json(result.stdout or "")
