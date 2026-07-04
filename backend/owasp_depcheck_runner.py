"""
OWASP Dependency-Check runner for AI Code Scanner — Week 4 (scanner #10).

Scans Java/Maven/Gradle projects for known CVEs via the NVD database.

Requires OWASP Dependency-Check CLI installed and on PATH:
  https://jeremylong.github.io/DependencyCheck/dependency-check-cli/

Gracefully skips when:
  - dependency-check binary not found
  - No Java files or build manifest in the repo
  - Tool fails or times out
  - JSON report not produced

NVD Database handling:
  - If the NVD DB already exists (pre-warmed in Docker image), uses --noupdate
    for fast scans with no network required.
  - If the DB is missing, allows an automatic download on first scan (~2-5 min).
  - Set NVD_API_KEY env var to speed up NVD downloads (strongly recommended
    for v9+ — get a free key at https://nvd.nist.gov/developers/request-an-api-key).
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from exceptions import ScannerError

SCAN_TIMEOUT = None  # no cap — first run downloads the NVD DB, let it finish

_BUILD_MANIFESTS = {"pom.xml", "build.gradle", "build.gradle.kts"}


class OwaspDepCheckScanError(ScannerError):
    def __init__(self, message: str = "OWASP Dependency-Check scan failed.") -> None:
        super().__init__(message, status_code=500)


def _has_depcheck() -> bool:
    return bool(
        shutil.which("dependency-check")
        or shutil.which("dependency-check.bat")  # Windows
        or shutil.which("dependency-check.sh")  # Linux/macOS
    )


def _depcheck_binary() -> str:
    return (
        shutil.which("dependency-check")
        or shutil.which("dependency-check.bat")
        or shutil.which("dependency-check.sh")
        or "dependency-check"
    )


def _has_java_project(repo_path: Path) -> bool:
    """Return True if the repo has .java files or a build manifest."""
    for manifest in _BUILD_MANIFESTS:
        if (repo_path / manifest).exists():
            return True
    return any(repo_path.rglob("*.java"))


def _parse_depcheck_json(report_path: Path) -> list[dict]:
    """Parse OWASP Dependency-Check JSON report into a list of finding dicts."""
    try:
        with report_path.open(encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except (json.JSONDecodeError, OSError):
        return []

    findings: list[dict] = []

    for dep in data.get("dependencies", []):
        file_path = dep.get("filePath", "") or dep.get("fileName", "")
        pkg_name = dep.get("fileName", "") or Path(file_path).name

        for vuln in dep.get("vulnerabilities", []):
            cve_id = vuln.get("name", "")  # usually the CVE-YYYY-NNNNN id
            source = vuln.get("source", "NVD")
            raw_sev = (vuln.get("severity") or "MEDIUM").upper()
            desc = (vuln.get("description") or "").strip()

            # CVSS v3 preferred, fall back to v2
            cvss_v3 = vuln.get("cvssv3") or {}
            cvss_v2 = vuln.get("cvssv2") or {}
            cvss_score: float | None = None
            if cvss_v3.get("baseScore") is not None:
                cvss_score = float(cvss_v3["baseScore"])
            elif cvss_v2.get("score") is not None:
                cvss_score = float(cvss_v2["score"])

            # References: grab first URL for shortlink
            refs = vuln.get("references", [])
            shortlink = next(
                (r.get("url", "") for r in refs if r.get("url")),
                (
                    f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                    if cve_id.startswith("CVE")
                    else ""
                ),
            )

            # CWE ids
            cwes = vuln.get("cwes", [])
            if isinstance(cwes, str):
                cwes = [cwes]
            cwe_list = [c if c.startswith("CWE-") else f"CWE-{c}" for c in cwes if c]

            findings.append(
                {
                    "cve_id": cve_id,
                    "severity": raw_sev,
                    "cvss_score": cvss_score,
                    "description": desc or cve_id,
                    "file": file_path,
                    "pkg_name": pkg_name,
                    "source": source,
                    "shortlink": shortlink,
                    "cwes": cwe_list,
                }
            )

    return findings


def run_owasp_depcheck_scan(repo_path: Path) -> list[dict]:
    """
    Run OWASP Dependency-Check on repo_path.

    Returns a list of raw finding dicts (pre-normalisation).
    Raises OwaspDepCheckScanError on any non-fatal skip condition.
    """
    if not _has_depcheck():
        raise OwaspDepCheckScanError(
            "dependency-check binary not found — skipping OWASP Dependency-Check."
        )

    if not _has_java_project(repo_path):
        raise OwaspDepCheckScanError(
            "No Java files or Maven/Gradle manifest found — skipping OWASP Dependency-Check."
        )

    # Check whether the NVD database has been pre-populated.
    # DEPENDENCY_CHECK_DATA is set in the Dockerfile to /opt/dependency-check/data.
    data_dir = Path(
        os.environ.get("DEPENDENCY_CHECK_DATA", "/opt/dependency-check/data")
    )
    nvd_db_exists = any(data_dir.glob("*.mv.db")) or any(data_dir.glob("nvd*.db"))

    # NVD API key from env — strongly recommended for v9+ to avoid rate limiting.
    nvd_api_key = os.environ.get("NVD_API_KEY", "").strip()

    with tempfile.TemporaryDirectory(prefix="depcheck_out_") as out_dir:
        cmd = [
            _depcheck_binary(),
            "--scan",
            str(repo_path),
            "--format",
            "JSON",
            "--out",
            out_dir,
            "--disableRetireJS",  # covered by ESLint
            "--disableNodeAudit",  # not our concern
            "--disableNodeAuditCache",
            "--prettyPrint",
        ]

        # Use --noupdate only if the DB is already present — avoids a 2-5 min
        # NVD download on every scan when the image was pre-warmed.
        if nvd_db_exists:
            cmd.append("--noupdate")

        # Provide API key if available — speeds up NVD sync significantly.
        if nvd_api_key:
            cmd.extend(["--nvdApiKey", nvd_api_key])

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=SCAN_TIMEOUT,
                check=False,
            )
        except subprocess.TimeoutExpired:
            raise OwaspDepCheckScanError(
                f"OWASP Dependency-Check timed out after {SCAN_TIMEOUT}s."
            )
        except OSError as exc:
            raise OwaspDepCheckScanError(f"Failed to run dependency-check: {exc}")

        # DC exits non-zero when vulnerabilities are found (exit code 1) — that's OK.
        # Only fail on exit code ≥ 2 (tool error).
        if result.returncode >= 2:
            stderr_tail = (result.stderr or "")[-500:]
            raise OwaspDepCheckScanError(
                f"OWASP Dependency-Check exited with code {result.returncode}. "
                f"stderr: {stderr_tail}"
            )

        report_path = Path(out_dir) / "dependency-check-report.json"
        if not report_path.exists():
            raise OwaspDepCheckScanError(
                "OWASP Dependency-Check report not produced — "
                "the NVD database may still be downloading on first run. "
                "Set NVD_API_KEY env var to speed up the initial DB sync."
            )

        return _parse_depcheck_json(report_path)
