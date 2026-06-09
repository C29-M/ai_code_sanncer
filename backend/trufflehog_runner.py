"""
TruffleHog runner — runs inside Docker using trufflesecurity/trufflehog:latest.
Mounts the cloned repo at /repo and scans full git history.
No timeouts — scans run as long as needed.
"""

from __future__ import annotations
import json
import logging
import shutil
import subprocess
from pathlib import Path
from exceptions import ScannerError

logger = logging.getLogger(__name__)
TRUFFLEHOG_V3_SUCCESS_CODES = {0, 183}
DOCKER_IMAGE = "trufflesecurity/trufflehog:latest"
REPO_MOUNT = "/repo"


class TruffleHogScanError(ScannerError):
    def __init__(self, message: str = "TruffleHog scan failed.") -> None:
        super().__init__(message, status_code=500)


def _docker_cli() -> str | None:
    return shutil.which("docker")


def _host_cli() -> str | None:
    exe = (
        shutil.which("trufflehog")
        or shutil.which("trufflehog.exe")
        or shutil.which("trufflehog3")
    )
    if not exe:
        import sys

        if sys.platform == "win32":
            for c in [
                r"C:\Tools\trufflehog\trufflehog.exe",
                r"C:\tools\trufflehog\trufflehog.exe",
            ]:
                if Path(c).exists():
                    return c
    return exe


def _parse_jsonl(stdout: str) -> list[dict]:
    out = []
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("{"):
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def _run_in_docker(repo_path: Path) -> list[dict]:
    docker = _docker_cli()
    if not docker:
        raise TruffleHogScanError("Docker not found.")
    abs_repo = str(repo_path.resolve())
    logger.info("TruffleHog: running in Docker, repo=%s", abs_repo)
    cmd = [
        docker,
        "run",
        "--rm",
        "-v",
        f"{abs_repo}:{REPO_MOUNT}:ro",
        DOCKER_IMAGE,
        "git",
        f"file://{REPO_MOUNT}",
        "--json",
        "--no-update",
        "--concurrency=2",
    ]
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=None,
            check=False,
        )
    except OSError as exc:
        raise TruffleHogScanError(f"Docker run failed: {exc}") from exc
    if r.returncode not in TRUFFLEHOG_V3_SUCCESS_CODES:
        parsed = _parse_jsonl(r.stdout or "")
        if parsed:
            return parsed
        raise TruffleHogScanError(
            f"TruffleHog Docker exited {r.returncode}: {(r.stderr or '')[:300]}"
        )
    return _parse_jsonl(r.stdout or "")


def _run_host(exe: str, repo_path: Path) -> list[dict]:
    import sys

    if sys.platform == "win32":
        raise TruffleHogScanError(
            "TruffleHog local scanning not supported on Windows — Docker required."
        )
    target = repo_path.resolve().as_uri()
    logger.info("TruffleHog host: %s", target)
    cmd = [exe, "git", target, "--json", "--no-update", "--concurrency=2"]
    r = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=None,
        check=False,
    )
    if r.returncode not in TRUFFLEHOG_V3_SUCCESS_CODES:
        parsed = _parse_jsonl(r.stdout or "")
        if parsed:
            return parsed
        raise TruffleHogScanError(
            f"TruffleHog exited {r.returncode}: {(r.stderr or '')[:200]}"
        )
    return _parse_jsonl(r.stdout or "")


def run_trufflehog_scan(repo_path: Path) -> list[dict]:
    if not repo_path.is_dir():
        raise TruffleHogScanError(f"Path does not exist: {repo_path}")
    if not (repo_path / ".git").exists():
        raise TruffleHogScanError("No .git directory — cannot scan history.")
    if _docker_cli():
        return _run_in_docker(repo_path)
    exe = _host_cli()
    if exe:
        return _run_host(exe, repo_path)
    raise TruffleHogScanError("Neither Docker nor TruffleHog binary found.")
