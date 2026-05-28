"""
TruffleHog runner for AI Code Scanner — Week 4.

Scans full Git history for secrets — catches credentials deleted in old
commits that Gitleaks (HEAD-only) would miss. Activated for all repos.

TruffleHog v3 outputs JSONL (one JSON object per line).
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from exceptions import ScannerError

TRUFFLEHOG_TIMEOUT = 180


class TruffleHogScanError(ScannerError):
    def __init__(self, message: str = "TruffleHog scan failed.") -> None:
        super().__init__(message, status_code=500)


def _trufflehog_cli() -> str:
    exe = shutil.which("trufflehog") or shutil.which("trufflehog.exe")
    if not exe:
        raise TruffleHogScanError(
            "TruffleHog is not installed or not on PATH. "
            "Install with: pip install trufflehog  or  brew install trufflehog"
        )
    return exe


def _parse_jsonl(stdout: str) -> list[dict]:
    """Parse TruffleHog's JSONL output — one JSON object per line."""
    findings = []
    for line in stdout.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            findings.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return findings


def run_trufflehog_scan(repo_path: Path) -> list[dict]:
    """
    Run TruffleHog against the full Git history of the cloned repository.

    Returns a list of raw TruffleHog finding dicts.
    Raises TruffleHogScanError on tool errors.
    """
    if not repo_path.is_dir():
        raise TruffleHogScanError(f"Repository path does not exist: {repo_path}")

    # Need a .git directory to scan history
    if not (repo_path / ".git").exists():
        raise TruffleHogScanError("No .git directory found — cannot scan history.")

    trufflehog = _trufflehog_cli()
    abs_path = repo_path.resolve()

    cmd = [
        trufflehog,
        "git",
        f"file://{abs_path}",
        "--json",
        "--no-update",  # don't phone home for updates
        "--only-verified=false",  # include unverified findings too
        "--concurrency=2",
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=TRUFFLEHOG_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise TruffleHogScanError(
            f"TruffleHog scan timed out after {TRUFFLEHOG_TIMEOUT}s."
        ) from exc
    except OSError as exc:
        raise TruffleHogScanError(f"Failed to run TruffleHog: {exc}") from exc

    # TruffleHog exits 183 when findings exist, 0 when clean — both are fine
    stdout = result.stdout or ""
    return _parse_jsonl(stdout)
