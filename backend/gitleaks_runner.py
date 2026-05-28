"""
Gitleaks runner for AI Code Scanner — Week 3.

Runs gitleaks detect on the host against the cloned repository.
With --depth 50 cloning, this covers current HEAD + recent history.
Failures are non-fatal: the scan continues with Semgrep + Trivy results.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from exceptions import GitleaksScanError

GITLEAKS_TIMEOUT = 120
# 0 = no leaks found, 1 = leaks found — both are valid outcomes.
GITLEAKS_SUCCESS_EXIT_CODES = {0, 1}


def _gitleaks_cli() -> str:
    exe = shutil.which("gitleaks") or shutil.which("gitleaks.exe")
    if not exe:
        raise GitleaksScanError(
            "Gitleaks is not installed or not on PATH. "
            "Install from https://github.com/gitleaks/gitleaks/releases"
        )
    return exe


def run_gitleaks_scan(repo_path: Path) -> list[dict]:
    """
    Run gitleaks detect against the cloned repository.

    Returns a list of raw gitleaks finding dicts.
    Returns an empty list if no secrets are found.
    Raises GitleaksScanError on tool errors (not on finding detection).
    """
    if not repo_path.is_dir():
        raise GitleaksScanError(f"Repository path does not exist: {repo_path}")

    gitleaks = _gitleaks_cli()
    abs_repo = str(repo_path.resolve())

    # Write report to a temp file — more reliable than stdout across versions.
    with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
        report_path = tmp.name

    cmd = [
        gitleaks,
        "detect",
        "--source",
        abs_repo,
        "--report-format",
        "json",
        "--report-path",
        report_path,
        "--no-banner",
        "--exit-code",
        "0",  # always exit 0; we check the report file
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=GITLEAKS_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise GitleaksScanError(
            f"Gitleaks scan timed out after {GITLEAKS_TIMEOUT}s."
        ) from exc
    except OSError as exc:
        raise GitleaksScanError(f"Failed to run Gitleaks: {exc}") from exc

    if result.returncode not in GITLEAKS_SUCCESS_EXIT_CODES:
        raise GitleaksScanError(
            f"Gitleaks exited with code {result.returncode}: "
            f"{(result.stderr or '').strip()}"
        )

    # Parse the JSON report file
    try:
        report_file = Path(report_path)
        if report_file.exists() and report_file.stat().st_size > 0:
            with open(report_file, "r", encoding="utf-8") as f:
                findings = json.load(f)
            report_file.unlink(missing_ok=True)
            return findings if isinstance(findings, list) else []
    except (json.JSONDecodeError, OSError):
        pass

    return []
