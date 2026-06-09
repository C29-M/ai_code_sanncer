"""
Bandit runner for AI Code Scanner — Week 4.

AST-based Python security analysis. Activated only when the repo contains
Python source files (language_map["python"] > 0).

Bandit exit codes:
  0 — no issues found
  1 — issues found (still success for us)
  2 — tool error
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from exceptions import ScannerError

BANDIT_TIMEOUT = 120
BANDIT_SUCCESS_EXIT_CODES = {0, 1}


class BanditScanError(ScannerError):
    def __init__(self, message: str = "Bandit scan failed.") -> None:
        super().__init__(message, status_code=500)


def _bandit_cli() -> str:
    exe = shutil.which("bandit") or shutil.which("bandit.exe")
    if not exe:
        raise BanditScanError(
            "Bandit is not installed or not on PATH. Install with: pip install bandit"
        )
    return exe


def run_bandit_scan(repo_path: Path) -> list[dict]:
    """
    Run Bandit against the cloned repository.

    Returns a list of raw Bandit finding dicts.
    Raises BanditScanError on tool errors.
    """
    if not repo_path.is_dir():
        raise BanditScanError(f"Repository path does not exist: {repo_path}")

    bandit = _bandit_cli()

    cmd = [
        bandit,
        "-r",  # recursive
        str(repo_path),
        "-f",
        "json",  # JSON output
        "-q",  # suppress progress/banner
        "--exit-zero",  # always exit 0 so we handle codes ourselves
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=BANDIT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise BanditScanError(
            f"Bandit scan timed out after {BANDIT_TIMEOUT}s."
        ) from exc
    except OSError as exc:
        raise BanditScanError(f"Failed to run Bandit: {exc}") from exc

    stdout = (result.stdout or "").strip()
    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        # Try finding JSON in output (Bandit sometimes emits log lines)
        for line in reversed(stdout.splitlines()):
            line = line.strip()
            if line.startswith("{"):
                try:
                    data = json.loads(line)
                    break
                except json.JSONDecodeError:
                    continue
        else:
            return []

    results = data.get("results")
    return results if isinstance(results, list) else []
