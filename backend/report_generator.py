"""
report_generator.py — Final ScanResult assembly for AI Code Scanner.

Responsibilities:
  - Deduplicate findings (three-pass, delegating to normalizer.deduplicate)
  - Calculate overall risk score
  - Build severity_counts, category_counts, scanner_results breakdown
  - Sort findings: CRITICAL → HIGH → MEDIUM → LOW → INFO
  - Serialise findings to plain dicts (JSON-safe)
  - Format a plain-text summary for CLI output
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from normalizer import deduplicate

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: Dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
    "INFO": 4,
}

_ALL_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


# A Finding is just a typed alias over the unified-schema dict produced by
# the normaliser.  We keep it as a plain dict so the rest of the codebase
# (which already works with dicts) doesn't need to change.
Finding = Dict[str, Any]


@dataclass
class ScanResult:
    """Aggregated output of a full repository scan."""

    scan_id: str
    prompt_text: str
    prompt_file_path: Optional[str]
    scanners_run: List[str]
    scan_duration: float
    scanned_at: str  # ISO-8601 UTC timestamp

    findings: List[Finding]
    findings_count: int

    risk_score: int  # 0–100 overall score
    severity_counts: Dict[str, int]  # {"CRITICAL": 3, "HIGH": 7, …}
    category_counts: Dict[str, int]  # {"sast": 5, "secrets": 2, …}
    scanner_results: Dict[str, Dict[str, Any]]  # per-scanner breakdown

    error_messages: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _severity_sort_key(finding: Finding) -> int:
    sev = (finding.get("severity") or "INFO").upper()
    return _SEVERITY_ORDER.get(sev, 99)


def _build_severity_counts(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {s: 0 for s in _ALL_SEVERITIES}
    for f in findings:
        sev = (f.get("severity") or "INFO").upper()
        if sev in counts:
            counts[sev] += 1
        else:
            counts["INFO"] += 1
    return counts


def _build_category_counts(findings: List[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        cat = (f.get("category") or "sast").lower()
        counts[cat] = counts.get(cat, 0) + 1
    return counts


def _build_scanner_results(
    findings: List[Finding],
    scanners_run: List[str],
) -> Dict[str, Dict[str, Any]]:
    """Return per-scanner breakdown: count + severity sub-counts."""
    results: Dict[str, Dict[str, Any]] = {}

    # Initialise all scanners that were run (even if they found nothing)
    for scanner in scanners_run:
        results[scanner] = {
            "findings_count": 0,
            "severity_counts": {s: 0 for s in _ALL_SEVERITIES},
        }

    for f in findings:
        tool = (f.get("tool") or "unknown").lower()
        if tool not in results:
            results[tool] = {
                "findings_count": 0,
                "severity_counts": {s: 0 for s in _ALL_SEVERITIES},
            }
        results[tool]["findings_count"] += 1
        sev = (f.get("severity") or "INFO").upper()
        sev_key = sev if sev in _SEVERITY_ORDER else "INFO"
        results[tool]["severity_counts"][sev_key] += 1

    return results


def _calculate_risk_score(findings: List[Finding]) -> int:
    """
    Aggregate risk score (0–100).

    Strategy:
      1. Take the maximum individual risk_score among all findings.
      2. Add a logarithmic volume penalty so large finding counts push the
         score upward without ever exceeding 100.
      3. Apply a severity multiplier: any CRITICAL finding locks the floor
         at 70; any HIGH finding locks the floor at 50.

    Formula:
      base   = max(individual risk_scores) or 0
      volume = min(10, round(log2(len(findings) + 1) * 2))
      score  = min(100, base + volume)
    """
    if not findings:
        return 0

    individual_scores = [f.get("risk_score", 0) for f in findings]
    base = max(individual_scores)

    volume_bonus = min(10, round(math.log2(len(findings) + 1) * 2))
    score = min(100, base + volume_bonus)

    # Severity floors
    severities = {(f.get("severity") or "INFO").upper() for f in findings}
    if "CRITICAL" in severities:
        score = max(score, 70)
    elif "HIGH" in severities:
        score = max(score, 50)

    return score


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def generate_report(
    scan_id: str,
    prompt_text: str,
    all_findings: List[Finding],
    scanners_run: List[str],
    scan_duration: float,
    prompt_file_path: Optional[str] = None,
    error_messages: Optional[List[str]] = None,
) -> ScanResult:
    """
    Build a ScanResult from raw (possibly duplicated) findings.

    Steps:
      1. Deduplicate using the normaliser's three-pass strategy.
      2. Sort: CRITICAL → HIGH → MEDIUM → LOW → INFO, ties broken by
         descending risk_score.
      3. Calculate aggregate risk score.
      4. Build severity_counts, category_counts, scanner_results.
    """
    if error_messages is None:
        error_messages = []

    # 1. Deduplicate
    deduped = deduplicate(all_findings)

    # 2. Sort by severity then risk_score descending
    deduped.sort(key=lambda f: (_severity_sort_key(f), -f.get("risk_score", 0)))

    # 3. Metrics
    risk_score = _calculate_risk_score(deduped)
    severity_counts = _build_severity_counts(deduped)
    category_counts = _build_category_counts(deduped)
    scanner_results = _build_scanner_results(deduped, scanners_run)

    scanned_at = datetime.now(timezone.utc).isoformat(timespec="seconds")

    return ScanResult(
        scan_id=scan_id,
        prompt_text=prompt_text,
        prompt_file_path=prompt_file_path,
        scanners_run=scanners_run,
        scan_duration=scan_duration,
        scanned_at=scanned_at,
        findings=deduped,
        findings_count=len(deduped),
        risk_score=risk_score,
        severity_counts=severity_counts,
        category_counts=category_counts,
        scanner_results=scanner_results,
        error_messages=error_messages,
    )


def findings_to_dict(findings: List[Finding]) -> List[dict]:
    """
    Return findings as a list of plain, JSON-serialisable dicts.

    Each finding is already a dict, but this function guarantees:
      - All values are JSON primitives (no custom objects).
      - Missing optional fields are filled with sensible defaults.
    """
    result: List[dict] = []
    for f in findings:
        entry: dict = {
            "tool": f.get("tool", "unknown"),
            "rule_id": f.get("rule_id", ""),
            "severity": f.get("severity", "INFO"),
            "language": f.get("language", "all"),
            "file": f.get("file", ""),
            "line": f.get("line", 0),
            "snippet": f.get("snippet", ""),
            "description": f.get("description", ""),
            "category": f.get("category", "sast"),
            "cve_id": f.get("cve_id"),
            "cvss_score": f.get("cvss_score"),
            "risk_score": f.get("risk_score", 0),
            "metadata": f.get("metadata") or {},
        }
        result.append(entry)
    return result


def format_text_report(result: ScanResult) -> str:
    """
    Render a plain-text summary suitable for CLI output.

    Example output:
    ================================================================
    AI Code Scanner — Scan Report
    ================================================================
    Scan ID   : abc123
    Scanned   : 2024-01-15T10:30:00+00:00  (3.42 s)
    Scanners  : semgrep, bandit, trivy
    Prompt    : scan this repo for secrets and vulns

    RISK SCORE : 85 / 100
    FINDINGS   : 42 total

    Severity breakdown
      CRITICAL :  3
      HIGH     : 12
      MEDIUM   : 18
      LOW      :  7
      INFO     :  2

    Category breakdown
      sast     : 25
      cve      : 12
      secrets  :  5

    Per-scanner breakdown
      semgrep        :  18  (CRITICAL=2, HIGH=8, MEDIUM=6, LOW=2)
      bandit         :   7  (HIGH=2, MEDIUM=4, LOW=1)
      trivy          :  12  (CRITICAL=1, HIGH=2, MEDIUM=8, LOW=1)

    Top findings
      [CRITICAL] semgrep  app/auth.py:42
                 Hardcoded password detected
      ...

    Errors / warnings
      - trivy: timeout after 30 s
    ================================================================
    """
    SEP = "=" * 64
    lines: List[str] = [SEP, "AI Code Scanner — Scan Report", SEP]

    # Header
    lines.append(f"Scan ID   : {result.scan_id}")
    lines.append(f"Scanned   : {result.scanned_at}  ({result.scan_duration:.2f} s)")
    lines.append(f"Scanners  : {', '.join(result.scanners_run) or '(none)'}")

    prompt_display = result.prompt_text
    if len(prompt_display) > 80:
        prompt_display = prompt_display[:77] + "..."
    lines.append(f"Prompt    : {prompt_display}")
    if result.prompt_file_path:
        lines.append(f"File      : {result.prompt_file_path}")
    lines.append("")

    # Overall score
    lines.append(f"RISK SCORE : {result.risk_score} / 100")
    lines.append(f"FINDINGS   : {result.findings_count} total")
    lines.append("")

    # Severity breakdown
    lines.append("Severity breakdown")
    for sev in _ALL_SEVERITIES:
        count = result.severity_counts.get(sev, 0)
        lines.append(f"  {sev:<10}: {count:>4}")
    lines.append("")

    # Category breakdown
    if result.category_counts:
        lines.append("Category breakdown")
        for cat, count in sorted(result.category_counts.items(), key=lambda x: -x[1]):
            lines.append(f"  {cat:<12}: {count:>4}")
        lines.append("")

    # Per-scanner breakdown
    if result.scanner_results:
        lines.append("Per-scanner breakdown")
        for scanner, info in sorted(result.scanner_results.items()):
            total = info["findings_count"]
            sev_parts = []
            for sev in _ALL_SEVERITIES:
                c = info["severity_counts"].get(sev, 0)
                if c:
                    sev_parts.append(f"{sev}={c}")
            detail = ", ".join(sev_parts)
            sev_str = f"  ({detail})" if detail else ""
            lines.append(f"  {scanner:<20}: {total:>4}{sev_str}")
        lines.append("")

    # Top findings (up to 20)
    if result.findings:
        lines.append("Top findings")
        shown = result.findings[:20]
        for f in shown:
            sev = f.get("severity", "INFO")
            tool = f.get("tool", "?")
            fpath = f.get("file", "") or ""
            line_no = f.get("line", 0)
            desc = (f.get("description") or "").strip()
            if len(desc) > 80:
                desc = desc[:77] + "..."
            location = f"{fpath}:{line_no}" if fpath else "(no file)"
            lines.append(f"  [{sev}] {tool}  {location}")
            lines.append(f"         {desc}")
        if result.findings_count > 20:
            lines.append(f"  ... and {result.findings_count - 20} more finding(s).")
        lines.append("")

    # Errors / warnings
    if result.error_messages:
        lines.append("Errors / warnings")
        for msg in result.error_messages:
            lines.append(f"  - {msg}")
        lines.append("")

    lines.append(SEP)
    return "\n".join(lines)
