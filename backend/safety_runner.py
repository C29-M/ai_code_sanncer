"""
Safety runner for AI Code Scanner — Week 4.

CVE check against Python dependency files (requirements.txt, Pipfile.lock,
poetry.lock). Activated only when at least one manifest is present.

Safety outputs two formats depending on version — both are handled:
  - Legacy (2.x): list of [name, spec, version, description, id]
  - Newer (2.3+): {"vulnerabilities": [{...}], ...}
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

from exceptions import ScannerError

SAFETY_TIMEOUT = 90
SAFETY_SUCCESS_EXIT_CODES = {
    0,
    1,
    64,
    255,
}  # 0=clean, 1=vulns found, 64/255=some versions

MANIFEST_CANDIDATES = [
    "requirements.txt",
    "requirements-dev.txt",
    "requirements_dev.txt",
    "Pipfile.lock",
    "poetry.lock",
]


class SafetyScanError(ScannerError):
    def __init__(self, message: str = "Safety scan failed.") -> None:
        super().__init__(message, status_code=500)


def _safety_cli() -> str:
    exe = shutil.which("safety") or shutil.which("safety.exe")
    if not exe:
        raise SafetyScanError(
            "Safety is not installed or not on PATH. Install with: pip install safety"
        )
    return exe


def _find_manifests(repo_path: Path) -> list[Path]:
    """Return all Python dependency manifest files found in the repo."""
    found = []
    for name in MANIFEST_CANDIDATES:
        for match in repo_path.rglob(name):
            # Skip vendored / virtual env paths
            parts = match.parts
            if any(
                p in parts for p in ("node_modules", ".git", "venv", ".venv", "env")
            ):
                continue
            found.append(match)
    return found


def _parse_safety_output(stdout: str) -> list[dict]:
    """
    Parse Safety JSON output — handles both legacy list format and newer dict format.
    Always returns a list of normalised dicts with keys:
      package, version, description, cve_id, severity
    """
    if not stdout.strip():
        return []

    try:
        data = json.loads(stdout.strip())
    except json.JSONDecodeError:
        return []

    vulns = []

    # Newer dict format: {"vulnerabilities": [...], ...}
    if isinstance(data, dict):
        raw_vulns = data.get("vulnerabilities") or data.get("affected_packages") or []
        for v in raw_vulns:
            if not isinstance(v, dict):
                continue
            vulns.append(
                {
                    "package": v.get("package_name") or v.get("name", "unknown"),
                    "version": v.get("analyzed_version")
                    or v.get("installed_version")
                    or "",
                    "description": v.get("advisory") or v.get("description") or "",
                    "cve_id": v.get("CVE") or v.get("cve") or "",
                    "severity": (v.get("severity") or "MEDIUM").upper(),
                }
            )
        return vulns

    # Legacy list format: [[name, spec, version, description, id], ...]
    if isinstance(data, list):
        for item in data:
            if isinstance(item, list) and len(item) >= 4:
                vulns.append(
                    {
                        "package": item[0] if len(item) > 0 else "unknown",
                        "version": item[2] if len(item) > 2 else "",
                        "description": item[3] if len(item) > 3 else "",
                        "cve_id": "",
                        "severity": "MEDIUM",
                    }
                )
            elif isinstance(item, dict):
                vulns.append(
                    {
                        "package": item.get("package_name")
                        or item.get("name", "unknown"),
                        "version": item.get("installed_version")
                        or item.get("version", ""),
                        "description": item.get("advisory")
                        or item.get("description", ""),
                        "cve_id": item.get("CVE") or item.get("cve", ""),
                        "severity": (item.get("severity") or "MEDIUM").upper(),
                    }
                )
        return vulns

    return []


def run_safety_scan(repo_path: Path) -> list[dict]:
    """
    Run Safety against all Python manifest files found in the repo.

    Returns a list of parsed vulnerability dicts.
    Raises SafetyScanError if Safety is not installed or critically fails.
    Returns [] if no manifests are found or no vulnerabilities detected.
    """
    if not repo_path.is_dir():
        raise SafetyScanError(f"Repository path does not exist: {repo_path}")

    safety = _safety_cli()
    manifests = _find_manifests(repo_path)

    if not manifests:
        return []  # No Python manifests — nothing for Safety to check

    all_vulns: list[dict] = []

    for manifest in manifests:
        cmd = [
            safety,
            "check",
            "-r",
            str(manifest),
            "--json",
            "--disable-telemetry",
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=SAFETY_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            continue  # skip this manifest, try others
        except OSError as exc:
            raise SafetyScanError(f"Failed to run Safety: {exc}") from exc

        if result.returncode not in SAFETY_SUCCESS_EXIT_CODES:
            continue  # skip manifests that cause unexpected errors

        vulns = _parse_safety_output(result.stdout or "")
        # Tag each finding with the manifest it came from
        for v in vulns:
            v["manifest"] = str(manifest)
        all_vulns.extend(vulns)

    # Deduplicate by (package, version, cve_id) across manifests
    seen: set[tuple] = set()
    unique: list[dict] = []
    for v in all_vulns:
        key = (v["package"], v["version"], v["cve_id"])
        if key not in seen:
            seen.add(key)
            unique.append(v)

    return unique
