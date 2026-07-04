"""
SpotBugs runner for AI Code Scanner — Week 4.

Java bytecode analysis. Requires:
  1. Java installed
  2. Maven or Gradle build system in the repo
  3. SpotBugs JAR available (via mvn spotbugs:spotbugs or standalone)

Gracefully skips at multiple points (Problem #1 + #7):
  - No Java files
  - No pom.xml / build.gradle
  - Build fails or times out
  - SpotBugs not available
  - No .class files produced

Run with a dedicated timeout so it can't slow the full pipeline.
"""

from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

from exceptions import ScannerError

# No timeout — Maven/Gradle build is allowed to take as long as it needs
# (e.g. waiting out an upstream Maven Central rate limit).
BUILD_TIMEOUT = None


class SpotBugsScanError(ScannerError):
    def __init__(self, message: str = "SpotBugs scan failed.") -> None:
        super().__init__(message, status_code=500)


# Severity mapping: SpotBugs uses 1 (High), 2 (Medium), 3 (Low)
_PRIORITY_MAP = {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}

# Fully-qualified plugin goal — works even when the project's pom.xml does not
# declare spotbugs-maven-plugin itself (the bare "spotbugs:spotbugs" prefix
# only resolves when the plugin is already registered in the POM).
_SPOTBUGS_PLUGIN_GOAL = "com.github.spotbugs:spotbugs-maven-plugin:4.8.6.0:spotbugs"


def _has_java() -> bool:
    return bool(shutil.which("java"))


def _find_build_file(repo_path: Path) -> tuple[str, Path] | None:
    """Return (build_system, build_file_path) or None."""
    pom = repo_path / "pom.xml"
    if pom.exists():
        return ("maven", pom)
    gradle = repo_path / "build.gradle"
    if gradle.exists():
        return ("gradle", gradle)
    gradle_kts = repo_path / "build.gradle.kts"
    if gradle_kts.exists():
        return ("gradle", gradle_kts)
    return None


def _run_maven_spotbugs(repo_path: Path) -> Path | None:
    """
    Run mvn spotbugs:spotbugs.
    Returns path to the XML report, or None if build/spotbugs failed.
    """
    mvn = shutil.which("mvn") or shutil.which("mvnw")
    if not mvn:
        raise SpotBugsScanError("Maven not found — cannot build Java project.")

    cmd = [
        mvn,
        "compile",  # ensure target/classes exists — the goal below doesn't bind to the lifecycle
        _SPOTBUGS_PLUGIN_GOAL,
        "-DskipTests",  # don't run tests, just compile + analyse
        "-q",  # quiet
        "--batch-mode",
        "-f",
        str(repo_path / "pom.xml"),
    ]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT,
            check=False,
            cwd=str(repo_path),
        )
    except subprocess.TimeoutExpired:
        raise SpotBugsScanError(f"Maven build timed out after {BUILD_TIMEOUT}s.")
    except OSError as exc:
        raise SpotBugsScanError(f"Failed to run Maven: {exc}")

    if result.returncode != 0:
        raise SpotBugsScanError(
            f"Maven build failed (exit {result.returncode}). "
            "Missing dependencies or build config issue — skipping SpotBugs."
        )

    # SpotBugs Maven plugin writes to target/spotbugsXml.xml by default
    report = repo_path / "target" / "spotbugsXml.xml"
    return report if report.exists() else None


def _run_gradle_spotbugs(repo_path: Path) -> Path | None:
    """
    Run gradle spotbugsMain.
    Returns path to the XML report, or None if build/spotbugs failed.
    """
    gradle = shutil.which("gradle") or shutil.which("gradlew")
    if not gradle:
        raise SpotBugsScanError("Gradle not found — cannot build Java project.")

    cmd = [gradle, "spotbugsMain", "--no-daemon", "-x", "test"]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=BUILD_TIMEOUT,
            check=False,
            cwd=str(repo_path),
        )
    except subprocess.TimeoutExpired:
        raise SpotBugsScanError(f"Gradle build timed out after {BUILD_TIMEOUT}s.")
    except OSError as exc:
        raise SpotBugsScanError(f"Failed to run Gradle: {exc}")

    if result.returncode != 0:
        raise SpotBugsScanError(
            f"Gradle build failed (exit {result.returncode}). "
            "Missing dependencies or build config issue — skipping SpotBugs."
        )

    # Gradle SpotBugs plugin default output location
    report = repo_path / "build" / "reports" / "spotbugs" / "main.xml"
    return report if report.exists() else None


def _parse_spotbugs_xml(report_path: Path) -> list[dict]:
    """Parse a SpotBugs XML report into a list of finding dicts."""
    try:
        tree = ET.parse(report_path)
    except ET.ParseError:
        return []

    root = tree.getroot()
    findings = []

    for bug in root.findall(".//BugInstance"):
        bug_type = bug.get("type", "UNKNOWN")
        priority = bug.get("priority", "2")
        rank = bug.get("rank", "")
        category = bug.get("category", "")
        abbrev = bug.get("abbrev", "")

        # Short message
        short = bug.find("ShortMessage")
        long_msg = bug.find("LongMessage")
        description = (
            (long_msg.text if long_msg is not None else None)
            or (short.text if short is not None else None)
            or bug_type
        )

        # File + line from SourceLine
        source = bug.find("SourceLine")
        file_path = source.get("sourcepath", "") if source is not None else ""
        line = int(source.get("start", 0)) if source is not None else 0

        # Source code snippet
        source_line = bug.find(".//SourceLine[@primary='true']")
        if source_line is None:
            source_line = source
        snippet_text = f"{file_path}:{line}" if file_path and line else ""

        findings.append(
            {
                "type": bug_type,
                "priority": priority,
                "rank": rank,
                "category": category,
                "abbrev": abbrev,
                "description": description,
                "file": file_path,
                "line": line,
                "snippet": snippet_text,
            }
        )

    return findings


def run_spotbugs_scan(repo_path: Path) -> list[dict]:
    """
    Run SpotBugs on the Java project in repo_path.

    Gracefully skips (raises SpotBugsScanError) when:
      - Java not installed
      - No pom.xml / build.gradle found
      - Build fails or times out
      - No SpotBugs report produced
    """
    # Skip point 1: Java not installed
    if not _has_java():
        raise SpotBugsScanError("Java not installed — skipping SpotBugs.")

    # Skip point 2: No build file
    build_info = _find_build_file(repo_path)
    if not build_info:
        raise SpotBugsScanError("No pom.xml or build.gradle found — skipping SpotBugs.")

    build_system, _ = build_info

    # Skip point 3/4: Build fails or no report produced
    report_path: Path | None = None
    if build_system == "maven":
        report_path = _run_maven_spotbugs(repo_path)
    else:
        report_path = _run_gradle_spotbugs(repo_path)

    if not report_path:
        raise SpotBugsScanError(
            "SpotBugs report not found after build — "
            "SpotBugs plugin may not be configured in this project."
        )

    return _parse_spotbugs_xml(report_path)
