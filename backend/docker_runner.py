from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from exceptions import SemgrepScanError
from scanner import (
    SEMGREP_SUCCESS_EXIT_CODES,
    SCAN_TIMEOUT_SECONDS,
    _parse_semgrep_json,
)

DEFAULT_IMAGE = "ai-code-scanner-semgrep:latest"
REPO_MOUNT_PATH = "/repo"
DEFAULT_OFFLINE_CONFIG = "/opt/semgrep-rules/java"
DOCKER_MEMORY = os.environ.get("DOCKER_SEMGREP_MEMORY", "2g")
DOCKER_MEMORY_SWAP = os.environ.get("DOCKER_SEMGREP_MEMORY_SWAP", "2g")
DOCKER_CPUS = os.environ.get("DOCKER_SEMGREP_CPUS", "1")

DOCKER_TMPFS_TMP = os.environ.get(
    "DOCKER_SEMGREP_TMPFS_TMP",
    "rw,nosuid,noexec,nodev,mode=1777,size=512m",
)


def _docker_cli() -> str:
    docker = shutil.which("docker")

    if not docker:
        raise SemgrepScanError(
            "Docker is not installed or not on PATH."
        )

    return docker


def _scanner_image() -> str:
    return os.environ.get(
        "DOCKER_SEMGREP_IMAGE",
        DEFAULT_IMAGE,
    ).strip() or DEFAULT_IMAGE


def _docker_network() -> str:
    mode = os.environ.get(
        "DOCKER_SEMGREP_NETWORK",
        "none",
    ).strip().lower()

    if mode in ("none", "bridge", "host"):
        return mode

    return "none"


def _semgrep_config() -> str:
    return (
        os.environ.get(
            "DOCKER_SEMGREP_CONFIG",
            DEFAULT_OFFLINE_CONFIG,
        ).strip()
        or DEFAULT_OFFLINE_CONFIG
    )


def _config_is_offline_path(config: str) -> bool:
    c = config.strip()

    return len(c) >= 2 and c[0] == "/" and c[1] != "/"


def run_semgrep_in_docker(repo_path: Path) -> dict:

    if not repo_path.is_dir():
        raise SemgrepScanError(
            f"Repository path does not exist: {repo_path}"
        )

    abs_repo = repo_path.resolve()

    docker = _docker_cli()
    image = _scanner_image()
    network = _docker_network()
    semgrep_config = _semgrep_config()

    cmd = [
        docker,
        "run",
        "--rm",
        "-i",
        "--network",
        network,
        "--read-only",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        "--memory",
        DOCKER_MEMORY,
        "--memory-swap",
        DOCKER_MEMORY_SWAP,
        "--cpus",
        DOCKER_CPUS,
        "--tmpfs",
        f"/tmp:{DOCKER_TMPFS_TMP}",
        "-e",
        "PYTHONUNBUFFERED=1",
        "-v",
        f"{abs_repo}:{REPO_MOUNT_PATH}:ro",
        image,
        "scan",
        "--config",
        semgrep_config,
        "--json",
        REPO_MOUNT_PATH,
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=SCAN_TIMEOUT_SECONDS,
            check=False,
        )

    except subprocess.TimeoutExpired as exc:
        raise SemgrepScanError(
            f"Docker Semgrep scan timed out after {SCAN_TIMEOUT_SECONDS} seconds."
        ) from exc

    except OSError as exc:
        raise SemgrepScanError(
            f"Failed to run Docker: {exc}"
        ) from exc

    print("RETURN CODE:")
    print(result.returncode)

    print("STDOUT:")
    print(result.stdout)

    print("STDERR:")
    print(result.stderr)

    if result.returncode not in SEMGREP_SUCCESS_EXIT_CODES:
        stderr = (result.stderr or "").strip()

        raise SemgrepScanError(
            stderr
            or f"Semgrep in Docker exited with code {result.returncode}."
        )

    output = result.stdout or result.stderr or ""

    return _parse_semgrep_json(output)