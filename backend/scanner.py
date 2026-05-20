import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

from exceptions import SemgrepScanError

# Semgrep exits 0 when no findings, 1 when findings exist — both are success for us.
SEMGREP_SUCCESS_EXIT_CODES = {0, 1}
SCAN_TIMEOUT_SECONDS = 600


def _semgrep_executable() -> str:
    """Resolve Semgrep binary from the active Python environment."""
    scripts_dir = Path(sys.executable).parent
    for name in ("pysemgrep", "semgrep"):
        candidate = scripts_dir / name
        if candidate.exists():
            return str(candidate)
        candidate_exe = candidate.with_suffix(".exe")
        if candidate_exe.exists():
            return str(candidate_exe)

    resolved = shutil.which("pysemgrep") or shutil.which("semgrep")
    if resolved:
        return resolved

    raise SemgrepScanError(
        "Semgrep is not installed or not on PATH. Install with: pip install semgrep"
    )


def _parse_semgrep_json(stdout: str) -> dict:
    """Extract JSON object from Semgrep stdout (may include log lines)."""
    stripped = stdout.strip()
    if not stripped:
        raise SemgrepScanError("Semgrep produced no JSON output.")

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

    raise SemgrepScanError("Failed to parse Semgrep JSON output.")


def _use_docker_sandbox() -> bool:
    """When true, run Semgrep inside an isolated Docker container (Phase 2)."""
    return os.environ.get("SEMGREP_USE_DOCKER", "true").lower() in (
        "1",
        "true",
        "yes",
    )


def run_semgrep_scan(repo_path: Path) -> dict:
    """
    Run Semgrep against the cloned repository and return parsed JSON.

    When SEMGREP_USE_DOCKER is true (default), the Docker runner executes
    ``semgrep scan --config … --json`` inside an isolated container (offline
    rules path by default; see docker_runner / DOCKER.md). Otherwise runs
    ``semgrep scan --config auto --json`` on the host.

    Returns parsed Semgrep JSON output.
    """
    if not repo_path.is_dir():
        raise SemgrepScanError(f"Repository path does not exist: {repo_path}")

    if _use_docker_sandbox():
        from docker_runner import run_semgrep_in_docker

        return run_semgrep_in_docker(repo_path)

    command = [
        _semgrep_executable(),
        "scan",
        "--config",
        "auto",
        "--json",
        str(repo_path),
    ]

    try:
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepScanError(
            f"Semgrep scan timed out after {SCAN_TIMEOUT_SECONDS} seconds."
        ) from exc
    except OSError as exc:
        raise SemgrepScanError(f"Failed to execute Semgrep: {exc}") from exc

    if result.returncode not in SEMGREP_SUCCESS_EXIT_CODES:
        stderr = (result.stderr or "").strip()
        raise SemgrepScanError(
            stderr or f"Semgrep exited with code {result.returncode}."
        )

    stdout = result.stdout or ""
    return _parse_semgrep_json(stdout)


def extract_findings(semgrep_output: dict) -> list[dict]:
    """Return the findings list from Semgrep JSON."""
    results = semgrep_output.get("results")
    if isinstance(results, list):
        return results
    return []
