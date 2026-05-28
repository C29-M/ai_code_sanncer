"""
Gosec runner for AI Code Scanner — Week 4.

Go security checker — catches SQL injection, weak crypto, unsafe file ops,
integer overflow. Activated only when the repo contains Go source files.

Exit codes:
  0 — no issues found
  1 — issues found (still success for us)
  2 — build/parse error (skip gracefully)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from exceptions import ScannerError

GOSEC_TIMEOUT = 120
GOSEC_SUCCESS_EXIT_CODES = {0, 1}


class GosecScanError(ScannerError):
    def __init__(self, message: str = "Gosec scan failed.") -> None:
        super().__init__(message, status_code=500)


def _gosec_cli() -> str:
    exe = shutil.which("gosec") or shutil.which("gosec.exe")
    if not exe:
        raise GosecScanError(
            "Gosec is not installed or not on PATH. "
            "Install with: go install github.com/securego/gosec/v2/cmd/gosec@latest"
        )
    return exe


def run_gosec_scan(repo_path: Path) -> list[dict]:
    """
    Run Gosec against the cloned repository.

    Returns a list of raw Gosec issue dicts.
    Raises GosecScanError on tool errors.
    """
    if not repo_path.is_dir():
        raise GosecScanError(f"Repository path does not exist: {repo_path}")

    # Verify there's a go.mod — no point running without it
    go_mods = list(repo_path.rglob("go.mod"))
    if not go_mods:
        raise GosecScanError("No go.mod found — not a Go module repo.")

    gosec = _gosec_cli()

    cmd = [
        gosec,
        "-fmt",
        "json",
        "-quiet",
        "-exclude-generated",  # skip generated code
        "./...",  # all packages recursively
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=GOSEC_TIMEOUT,
            check=False,
            cwd=str(repo_path),  # gosec needs to run from the module root
        )
    except subprocess.TimeoutExpired as exc:
        raise GosecScanError(f"Gosec scan timed out after {GOSEC_TIMEOUT}s.") from exc
    except OSError as exc:
        raise GosecScanError(f"Failed to run Gosec: {exc}") from exc

    if result.returncode not in GOSEC_SUCCESS_EXIT_CODES:
        raise GosecScanError(
            f"Gosec exited with code {result.returncode}: "
            f"{(result.stderr or '').strip()[:200]}"
        )

    stdout = (result.stdout or "").strip()
    if not stdout:
        return []

    try:
        data = json.loads(stdout)
    except json.JSONDecodeError:
        return []

    issues = data.get("Issues") or data.get("issues") or []
    return issues if isinstance(issues, list) else []
