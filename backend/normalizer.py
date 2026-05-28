"""
Unified findings normaliser for AI Code Scanner — Week 3.

Maps raw Semgrep / Gitleaks / Trivy output to the unified schema,
applies three-pass deduplication, computes risk scores, and enforces
operational limits.

Unified schema fields
---------------------
tool          : semgrep | gitleaks | trivy
rule_id       : scanner-specific rule identifier
severity      : CRITICAL | HIGH | MEDIUM | LOW | INFO  (display enum)
language      : python | javascript | go | java | all | …
file          : relative or absolute path to the affected file
line          : start line number (0 for dependency-level findings)
snippet       : up to 200 chars of context (secrets partially masked)
description   : scanner-provided description
category      : sast | secrets | cve | iac | history
cve_id        : CVE identifier or None
cvss_score    : CVSS v3 score 0–10 or None
risk_score    : computed 0–100 integer
metadata      : dict with cwe, owasp, confidence, impact, likelihood, shortlink
"""

from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# Operational limits
# ---------------------------------------------------------------------------
MAX_FINDINGS = 500
MAX_SNIPPET_LEN = 200

# ---------------------------------------------------------------------------
# Scanner-specific severity weights (risk scoring)
#
# Each scanner's severity labels carry different confidence levels.
# Trivy CRITICAL is backed by an NVD CVSS score; Semgrep ERROR is a rule
# author's assessment. Weighting them identically would flatten that signal.
# ---------------------------------------------------------------------------
SCANNER_SEVERITY_WEIGHTS: dict[str, dict[str, int]] = {
    "semgrep": {"ERROR": 10, "WARNING": 6, "INFO": 2},
    "gitleaks": {"CRITICAL": 9, "HIGH": 7, "MEDIUM": 5, "LOW": 3, "INFO": 1},
    "trivy": {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2, "INFO": 0},
    "bandit": {"HIGH": 7, "MEDIUM": 4, "LOW": 2},
    "safety": {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2},
    "eslint": {"ERROR": 7, "WARN": 4},
    "gosec": {"HIGH": 7, "MEDIUM": 4, "LOW": 2},
    "trufflehog": {"CRITICAL": 9},
    "spotbugs": {"HIGH": 7, "MEDIUM": 4, "LOW": 2},
    "owasp_depcheck": {"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2},
}

# ---------------------------------------------------------------------------
# Display severity normalisation
# Maps each scanner's raw severity label → standard CRITICAL/HIGH/MEDIUM/LOW/INFO
# ---------------------------------------------------------------------------
SEVERITY_DISPLAY: dict[str, dict[str, str]] = {
    "semgrep": {
        "ERROR": "CRITICAL",
        "WARNING": "HIGH",
        "INFO": "INFO",
    },
    "gitleaks": {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO",
    },
    "trivy": {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
        "INFO": "INFO",
    },
    "bandit": {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    },
    "safety": {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    },
    "eslint": {
        "ERROR": "HIGH",  # _normalise_display_severity uppercases before lookup
        "WARN": "MEDIUM",
    },
    "gosec": {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    },
    "trufflehog": {
        "CRITICAL": "CRITICAL",
    },
    "spotbugs": {
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    },
    "owasp_depcheck": {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "LOW",
    },
}

_STANDARD_SEVS = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"}

# ---------------------------------------------------------------------------
# Risk scoring
#
# Formula: risk_score = round((severity_weight * 0.5) + (cvss_score * 0.3)
#                             + (category_weight * 0.2)) * 10
# Clamp:   0–100
# Solution 1: secrets always score ≥ 70 regardless of formula output.
# ---------------------------------------------------------------------------
_CATEGORY_WEIGHT: dict[str, int] = {
    "secrets": 10,
    "cve": 7,
    "sast": 6,
    "history": 5,
    "iac": 5,
}


def compute_risk_score(
    tool: str,
    raw_severity: str,
    cvss_score: float | None,
    category: str,
) -> int:
    sw = SCANNER_SEVERITY_WEIGHTS.get(tool, {}).get(raw_severity.upper(), 0)
    cv = float(cvss_score) if cvss_score is not None else 0.0
    cw = _CATEGORY_WEIGHT.get(category, 0)
    raw = (sw * 0.5) + (cv * 0.3) + (cw * 0.2)
    score = max(0, min(100, round(raw) * 10))
    # Solution 1 — secrets floor
    if category in ("secrets", "history"):
        score = max(score, 70)
    return score


def _normalise_display_severity(tool: str, raw: str) -> str:
    up = (raw or "").strip().upper()
    mapped = SEVERITY_DISPLAY.get(tool, {}).get(up)
    if mapped:
        return mapped
    return up if up in _STANDARD_SEVS else "INFO"


# ---------------------------------------------------------------------------
# Language detection from file path
# ---------------------------------------------------------------------------
_EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".java": "java",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".rs": "rust",
    ".kt": "kotlin",
    ".scala": "scala",
    ".swift": "swift",
    ".c": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".tf": "terraform",
    ".yaml": "yaml",
    ".yml": "yaml",
}

_TARGET_TO_LANG: dict[str, str] = {
    "package-lock.json": "javascript",
    "package.json": "javascript",
    "yarn.lock": "javascript",
    "requirements.txt": "python",
    "Pipfile.lock": "python",
    "Pipfile": "python",
    "poetry.lock": "python",
    "go.sum": "go",
    "go.mod": "go",
    "pom.xml": "java",
    "build.gradle": "java",
    "Gemfile.lock": "ruby",
    "composer.lock": "php",
}


def _lang_from_path(file_path: str) -> str:
    if not file_path:
        return "all"
    name = Path(file_path).name
    if name in _TARGET_TO_LANG:
        return _TARGET_TO_LANG[name]
    return _EXT_TO_LANG.get(Path(file_path).suffix.lower(), "all")


# ---------------------------------------------------------------------------
# Secret masking  (Solution 6)
# Partially mask secrets so the snippet is useful without re-exposing the value.
# Example: AKIA5B4Y92XQ  →  AKIA****92XQ
# ---------------------------------------------------------------------------
_PEM_RE = re.compile(
    r"-----BEGIN [A-Z ]*(?:PRIVATE KEY|CERTIFICATE|RSA|DSA|EC|OPENSSH)[A-Z ]*-----"
    r"[\s\S]*?"
    r"(?:-----END [A-Z ]*(?:PRIVATE KEY|CERTIFICATE|RSA|DSA|EC|OPENSSH)[A-Z ]*-----|$)",
    re.IGNORECASE,
)


def mask_secret(value: str) -> str:
    v = (value or "").strip()
    if v.startswith("-----BEGIN"):
        return "[PRIVATE KEY REDACTED]"
    if len(v) <= 8:
        return "****"
    return v[:4] + "*" * (len(v) - 8) + v[-4:]


def safe_snippet(text: str, is_secret: bool = False) -> str:
    if not text:
        return ""
    text = text.strip()
    if is_secret:
        # Redact PEM private key / certificate blocks before anything else
        text = _PEM_RE.sub("[PRIVATE KEY REDACTED]", text)
        # Redact values that follow secret-like key names
        text = re.sub(
            r"((?:password|passwd|secret|token|api[_\-]?key|auth[_\-]?key"
            r"|access[_\-]?key|private[_\-]?key|credential)\s*[=:]\s*)"
            r"[\"']?[\w\-./+]{6,}[\"']?",
            r"\1[REDACTED]",
            text,
            flags=re.IGNORECASE,
        )
        # Mask long uppercase alphanumeric strings (common secret patterns)
        text = re.sub(
            r"\b([A-Z0-9]{20,})\b",
            lambda m: mask_secret(m.group(1)),
            text,
        )
    return text[:MAX_SNIPPET_LEN]


# ---------------------------------------------------------------------------
# CWE extraction helper
# ---------------------------------------------------------------------------
def _cwe_from_meta(meta: dict) -> list[str]:
    cwe = meta.get("cwe") or meta.get("CWE") or []
    if isinstance(cwe, str):
        return [cwe]
    return list(cwe)


# ---------------------------------------------------------------------------
# Semgrep normaliser
# ---------------------------------------------------------------------------
def normalise_semgrep(raw_findings: list[dict]) -> list[dict]:
    """Map Semgrep findings list to unified schema."""
    out: list[dict] = []
    for r in raw_findings:
        extra = r.get("extra") or {}
        meta = extra.get("metadata") or {}
        raw_sev = (extra.get("severity") or "INFO").upper()
        severity = _normalise_display_severity("semgrep", raw_sev)
        file_path = r.get("path", "")
        line = (r.get("start") or {}).get("line", 0)
        snippet = safe_snippet(extra.get("lines", ""))
        desc = (extra.get("message") or "").strip()
        rule_id = r.get("check_id", "")

        category = "sast"
        _id_lower = rule_id.lower()
        if any(
            k in _id_lower
            for k in (
                "secret",
                "credential",
                "hardcoded",
                "password",
                "token",
                "api-key",
            )
        ):
            category = "secrets"

        risk_score = compute_risk_score("semgrep", raw_sev, None, category)

        out.append(
            {
                "tool": "semgrep",
                "rule_id": rule_id,
                "severity": severity,
                "language": _lang_from_path(file_path),
                "file": file_path,
                "line": line,
                "snippet": snippet,
                "description": desc,
                "category": category,
                "cve_id": None,
                "cvss_score": None,
                "risk_score": risk_score,
                "metadata": {
                    "cwe": _cwe_from_meta(meta),
                    "owasp": meta.get("owasp") or meta.get("OWASP") or "",
                    "confidence": meta.get("confidence", ""),
                    "impact": meta.get("impact", ""),
                    "likelihood": meta.get("likelihood", ""),
                    "shortlink": meta.get("shortlink") or extra.get("shortlink") or "",
                },
            }
        )
    return out


# ---------------------------------------------------------------------------
# Gitleaks normaliser
# ---------------------------------------------------------------------------
def normalise_gitleaks(raw_findings: list[dict]) -> list[dict]:
    """Map Gitleaks findings list to unified schema."""
    out: list[dict] = []
    for r in raw_findings:
        file_path = r.get("File", "")
        line = r.get("StartLine", 0)
        match_text = r.get("Match", "")
        rule_id = r.get("RuleID", "unknown")
        description = r.get("Description", "Secret detected")
        commit = r.get("Commit", "")

        # Findings with a commit hash came from history scan
        category = "history" if commit else "secrets"
        raw_sev = "CRITICAL"
        snippet = safe_snippet(match_text, is_secret=True)
        risk_score = compute_risk_score("gitleaks", raw_sev, None, category)

        out.append(
            {
                "tool": "gitleaks",
                "rule_id": rule_id,
                "severity": _normalise_display_severity("gitleaks", raw_sev),
                "language": _lang_from_path(file_path),
                "file": file_path,
                "line": line,
                "snippet": snippet,
                "description": description,
                "category": category,
                "cve_id": None,
                "cvss_score": None,
                "risk_score": risk_score,
                "metadata": {
                    "cwe": [],
                    "owasp": "A07:2021 - Identification and Authentication Failures",
                    "confidence": "HIGH",
                    "impact": "HIGH",
                    "likelihood": "HIGH",
                    "shortlink": "",
                    "commit": commit,
                    "fingerprint": r.get("Fingerprint", ""),
                    "author": r.get("Author", ""),
                    "date": r.get("Date", ""),
                },
            }
        )
    return out


# ---------------------------------------------------------------------------
# Trivy normaliser
# ---------------------------------------------------------------------------
def normalise_trivy(raw_output: dict) -> list[dict]:
    """Map Trivy filesystem scan output to unified schema."""
    out: list[dict] = []
    for result in raw_output.get("Results") or []:
        target = result.get("Target", "")
        for vuln in result.get("Vulnerabilities") or []:
            cve_id = vuln.get("VulnerabilityID", "")
            raw_sev = (vuln.get("Severity") or "MEDIUM").upper()
            severity = raw_sev if raw_sev in _STANDARD_SEVS else "MEDIUM"
            pkg = vuln.get("PkgName", "")
            inst_ver = vuln.get("InstalledVersion", "")
            fix_ver = vuln.get("FixedVersion", "")
            title = vuln.get("Title") or vuln.get("Description") or cve_id

            # Extract best available CVSS v3 score
            nvd_score: float | None = None
            for src in ("nvd", "ghsa", "redhat"):
                v3 = (vuln.get("CVSS") or {}).get(src, {}).get("V3Score")
                if v3 is not None:
                    nvd_score = float(v3)
                    break

            snippet = f"{pkg}@{inst_ver}"
            if fix_ver:
                snippet += f" → fix: {fix_ver}"

            risk_score = compute_risk_score("trivy", raw_sev, nvd_score, "cve")

            out.append(
                {
                    "tool": "trivy",
                    "rule_id": cve_id,
                    "severity": severity,
                    "language": _lang_from_path(target),
                    "file": target,
                    "line": 0,
                    "snippet": snippet[:MAX_SNIPPET_LEN],
                    "description": title,
                    "category": "cve",
                    "cve_id": cve_id,
                    "cvss_score": nvd_score,
                    "risk_score": risk_score,
                    "metadata": {
                        "cwe": [],
                        "owasp": "",
                        "confidence": "HIGH",
                        "impact": "",
                        "likelihood": "",
                        "shortlink": (
                            f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                            if cve_id
                            else ""
                        ),
                        "pkg_name": pkg,
                        "installed_version": inst_ver,
                        "fixed_version": fix_ver,
                        "target": target,
                    },
                }
            )
    return out


# ---------------------------------------------------------------------------
# ESLint normaliser
# ---------------------------------------------------------------------------
def normalise_eslint(raw_findings: list[dict]) -> list[dict]:
    """Map ESLint security findings to unified schema."""
    out: list[dict] = []
    for r in raw_findings:
        file_path = r.get("filePath", "")
        line = r.get("line", 0)
        rule_id = r.get("ruleId", "") or ""
        message = (r.get("message") or "").strip()
        # ESLint severity: 2=error, 1=warn
        sev_num = r.get("severity", 1)
        raw_sev = "error" if sev_num == 2 else "warn"
        severity = _normalise_display_severity("eslint", raw_sev)
        snippet = safe_snippet(r.get("source", "") or "")
        risk_score = compute_risk_score("eslint", raw_sev, None, "sast")

        out.append(
            {
                "tool": "eslint",
                "rule_id": rule_id,
                "severity": severity,
                "language": _lang_from_path(file_path),
                "file": file_path,
                "line": line,
                "snippet": snippet,
                "description": message or rule_id,
                "category": "sast",
                "cve_id": None,
                "cvss_score": None,
                "risk_score": risk_score,
                "metadata": {
                    "cwe": [],
                    "owasp": "",
                    "confidence": "MEDIUM",
                    "impact": "",
                    "likelihood": "",
                    "shortlink": (
                        f"https://github.com/eslint-community/eslint-plugin-security/blob/main/docs/rules/{rule_id.replace('security/', '')}.md"
                        if rule_id
                        else ""
                    ),
                },
            }
        )
    return out


# ---------------------------------------------------------------------------
# Gosec normaliser
# ---------------------------------------------------------------------------
def normalise_gosec(raw_findings: list[dict]) -> list[dict]:
    """Map Gosec findings to unified schema."""
    out: list[dict] = []
    for r in raw_findings:
        file_path = r.get("file", "")
        line_str = r.get("line", "0")
        line = int(line_str) if str(line_str).isdigit() else 0
        rule_id = r.get("rule_id", "") or r.get("test_id", "")
        desc = (r.get("details") or "").strip()
        raw_sev = (r.get("severity") or "MEDIUM").upper()
        confidence = (r.get("confidence") or "MEDIUM").upper()
        code = r.get("code", "")
        snippet = safe_snippet(code)
        severity = _normalise_display_severity("gosec", raw_sev)
        risk_score = compute_risk_score("gosec", raw_sev, None, "sast")

        # CWE from Gosec
        cwe_info = r.get("cwe") or {}
        cwe_id = cwe_info.get("ID") or cwe_info.get("id") or ""
        cwe_list = [f"CWE-{cwe_id}"] if cwe_id else []

        out.append(
            {
                "tool": "gosec",
                "rule_id": rule_id,
                "severity": severity,
                "language": "go",
                "file": file_path,
                "line": line,
                "snippet": snippet,
                "description": desc or rule_id,
                "category": "sast",
                "cve_id": None,
                "cvss_score": None,
                "risk_score": risk_score,
                "metadata": {
                    "cwe": cwe_list,
                    "owasp": "",
                    "confidence": confidence,
                    "impact": raw_sev,
                    "likelihood": confidence,
                    "shortlink": (
                        f"https://securego.io/docs/rules/{rule_id.lower()}.html"
                        if rule_id
                        else ""
                    ),
                },
            }
        )
    return out


# ---------------------------------------------------------------------------
# TruffleHog normaliser
# ---------------------------------------------------------------------------
def normalise_trufflehog(raw_findings: list[dict]) -> list[dict]:
    """Map TruffleHog JSONL findings to unified schema."""
    out: list[dict] = []
    for r in raw_findings:
        detector = r.get("DetectorName") or r.get("DetectorType", "secret")
        verified = r.get("Verified", False)
        raw_secret = r.get("Raw", "") or r.get("RawV2", "")
        redacted = r.get("Redacted", "") or safe_snippet(raw_secret, is_secret=True)

        # Pull source metadata
        src_meta = (r.get("SourceMetadata") or {}).get("Data", {})
        git_meta = src_meta.get("Git", {})
        file_path = git_meta.get("file", "")
        line = git_meta.get("line", 0)
        commit = git_meta.get("commit", "")

        desc = f"{detector} credential found in git history"
        if verified:
            desc += " (VERIFIED — still active)"

        raw_sev = "CRITICAL"
        risk_score = compute_risk_score("trufflehog", raw_sev, None, "history")
        # Verified secrets score even higher
        if verified:
            risk_score = min(100, risk_score + 10)

        out.append(
            {
                "tool": "trufflehog",
                "rule_id": str(detector).lower().replace(" ", "-"),
                "severity": "CRITICAL",
                "language": _lang_from_path(file_path),
                "file": file_path,
                "line": int(line) if str(line).isdigit() else 0,
                "snippet": safe_snippet(redacted, is_secret=True),
                "description": desc,
                "category": "history",
                "cve_id": None,
                "cvss_score": None,
                "risk_score": risk_score,
                "metadata": {
                    "cwe": ["CWE-798"],
                    "owasp": "A07:2021 - Identification and Authentication Failures",
                    "confidence": "HIGH" if verified else "MEDIUM",
                    "impact": "HIGH",
                    "likelihood": "HIGH",
                    "shortlink": "",
                    "commit": commit,
                    "verified": verified,
                    "detector": str(detector),
                },
            }
        )
    return out


# ---------------------------------------------------------------------------
# SpotBugs normaliser
# ---------------------------------------------------------------------------
def normalise_spotbugs(raw_findings: list[dict]) -> list[dict]:
    """Map SpotBugs findings to unified schema."""
    _PRIORITY_TO_SEV = {"1": "HIGH", "2": "MEDIUM", "3": "LOW"}

    out: list[dict] = []
    for r in raw_findings:
        priority = str(r.get("priority", "2"))
        raw_sev = _PRIORITY_TO_SEV.get(priority, "MEDIUM")
        bug_type = r.get("type", "UNKNOWN")
        desc = (r.get("description") or bug_type).strip()
        file_path = r.get("file", "")
        line = int(r.get("line", 0))
        snippet = r.get("snippet", "")
        severity = _normalise_display_severity("spotbugs", raw_sev)
        risk_score = compute_risk_score("spotbugs", raw_sev, None, "sast")

        out.append(
            {
                "tool": "spotbugs",
                "rule_id": bug_type,
                "severity": severity,
                "language": "java",
                "file": file_path,
                "line": line,
                "snippet": safe_snippet(snippet),
                "description": desc,
                "category": "sast",
                "cve_id": None,
                "cvss_score": None,
                "risk_score": risk_score,
                "metadata": {
                    "cwe": [],
                    "owasp": "",
                    "confidence": "MEDIUM",
                    "impact": raw_sev,
                    "likelihood": "MEDIUM",
                    "shortlink": (
                        f"https://spotbugs.readthedocs.io/en/stable/bugDescriptions.html#{bug_type}"
                        if bug_type
                        else ""
                    ),
                },
            }
        )
    return out


# ---------------------------------------------------------------------------
# Bandit normaliser
# ---------------------------------------------------------------------------
def normalise_bandit(raw_findings: list[dict]) -> list[dict]:
    """Map Bandit findings list to unified schema."""
    out: list[dict] = []
    for r in raw_findings:
        file_path = r.get("filename", "")
        line = r.get("line_number", 0)
        raw_sev = (r.get("issue_severity") or "MEDIUM").upper()
        confidence = (r.get("issue_confidence") or "MEDIUM").upper()
        rule_id = r.get("test_id", "")
        test_name = r.get("test_name", "")
        desc = r.get("issue_text", "").strip()
        snippet = safe_snippet(r.get("code", ""))

        # Extract CWE if present (Bandit >= 1.7.5 includes issue_cwe)
        cwe_info = r.get("issue_cwe") or {}
        cwe_id = str(cwe_info.get("id", "")) if cwe_info else ""
        cwe_list = [f"CWE-{cwe_id}"] if cwe_id else []

        severity = _normalise_display_severity("bandit", raw_sev)
        risk_score = compute_risk_score("bandit", raw_sev, None, "sast")

        out.append(
            {
                "tool": "bandit",
                "rule_id": rule_id or test_name,
                "severity": severity,
                "language": "python",
                "file": file_path,
                "line": line,
                "snippet": snippet,
                "description": desc,
                "category": "sast",
                "cve_id": None,
                "cvss_score": None,
                "risk_score": risk_score,
                "metadata": {
                    "cwe": cwe_list,
                    "owasp": "",
                    "confidence": confidence,
                    "impact": raw_sev,
                    "likelihood": confidence,
                    "shortlink": (
                        f"https://bandit.readthedocs.io/en/latest/plugins/{rule_id.lower()}.html"
                        if rule_id
                        else ""
                    ),
                },
            }
        )
    return out


# ---------------------------------------------------------------------------
# Safety normaliser
# ---------------------------------------------------------------------------
def normalise_safety(raw_findings: list[dict]) -> list[dict]:
    """Map Safety findings list to unified schema."""
    out: list[dict] = []
    for r in raw_findings:
        pkg = r.get("package", "unknown")
        version = r.get("version", "")
        desc = r.get("description", "").strip()
        cve_id = r.get("cve_id", "") or ""
        raw_sev = (r.get("severity") or "MEDIUM").upper()
        manifest = r.get("manifest", "")

        severity = _normalise_display_severity("safety", raw_sev)
        risk_score = compute_risk_score("safety", raw_sev, None, "cve")
        snippet = f"{pkg}@{version}" if version else pkg

        out.append(
            {
                "tool": "safety",
                "rule_id": cve_id or f"safety-{pkg}",
                "severity": severity,
                "language": "python",
                "file": manifest,
                "line": 0,
                "snippet": snippet,
                "description": desc or f"Known vulnerability in {pkg}",
                "category": "cve",
                "cve_id": cve_id or None,
                "cvss_score": None,
                "risk_score": risk_score,
                "metadata": {
                    "cwe": [],
                    "owasp": "",
                    "confidence": "HIGH",
                    "impact": "",
                    "likelihood": "",
                    "shortlink": (
                        f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else ""
                    ),
                    "pkg_name": pkg,
                    "installed_version": version,
                    "fixed_version": "",
                    "target": manifest,
                },
            }
        )
    return out


# ---------------------------------------------------------------------------
# OWASP Dependency-Check normaliser
# ---------------------------------------------------------------------------
def normalise_owasp_depcheck(raw_findings: list[dict]) -> list[dict]:
    """Map OWASP Dependency-Check findings to unified schema."""
    out: list[dict] = []
    for r in raw_findings:
        cve_id = r.get("cve_id", "") or ""
        raw_sev = (r.get("severity") or "MEDIUM").upper()
        cvss_score = r.get("cvss_score")
        desc = (r.get("description") or cve_id).strip()
        file_path = r.get("file", "")
        pkg_name = r.get("pkg_name", "")
        shortlink = r.get("shortlink", "")
        cwe_list = r.get("cwes", [])

        severity = _normalise_display_severity("owasp_depcheck", raw_sev)
        risk_score = compute_risk_score("owasp_depcheck", raw_sev, cvss_score, "cve")

        snippet = pkg_name
        if cvss_score is not None:
            snippet += f" (CVSS {cvss_score:.1f})"

        out.append(
            {
                "tool": "owasp_depcheck",
                "rule_id": cve_id or f"depcheck-{pkg_name}",
                "severity": severity,
                "language": "java",
                "file": file_path,
                "line": 0,
                "snippet": snippet[:MAX_SNIPPET_LEN],
                "description": desc,
                "category": "cve",
                "cve_id": cve_id or None,
                "cvss_score": cvss_score,
                "risk_score": risk_score,
                "metadata": {
                    "cwe": cwe_list,
                    "owasp": "",
                    "confidence": "HIGH",
                    "impact": "",
                    "likelihood": "",
                    "shortlink": shortlink
                    or (f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else ""),
                    "pkg_name": pkg_name,
                    "installed_version": "",
                    "fixed_version": "",
                    "target": file_path,
                    "source": r.get("source", "NVD"),
                },
            }
        )
    return out


# ---------------------------------------------------------------------------
# Three-pass deduplication
#
# Pass 1 — per-scanner dedup
#   CVE  findings: key = (cve_id, pkg_name, file)       — Solution 2
#   SAST/secrets:  key = (file, line, rule_id)
#
# Pass 2 — cross-scanner dedup                           — Solution 3
#   key = (file, line, normalised_title[:40])
#   Catches the same secret found by both Semgrep and Gitleaks.
#
# In both passes, when two findings share a key, the higher risk_score wins.
# ---------------------------------------------------------------------------
def deduplicate(findings: list[dict]) -> list[dict]:
    # Pass 1
    seen: dict[tuple, dict] = {}
    for f in findings:
        cat = f.get("category", "sast")
        if cat == "cve":
            pkg = (f.get("metadata") or {}).get("pkg_name", "")
            key: tuple = ("cve", f.get("cve_id", ""), pkg, f.get("file", ""))
        else:
            key = ("sast", f.get("file", ""), f.get("line", 0), f.get("rule_id", ""))

        existing = seen.get(key)
        if existing is None or f["risk_score"] > existing["risk_score"]:
            seen[key] = f

    # Pass 2 — cross-scanner dedup (Problem #2 fix)
    # CVE key uses (cve_id, pkg_name) only — no file path — so the same CVE
    # found by Trivy in package-lock.json AND Safety in requirements.txt
    # collapses to one finding. Higher risk_score wins.
    cross: dict[tuple, dict] = {}
    for f in seen.values():
        if f.get("category") == "cve":
            pkg = (f.get("metadata") or {}).get("pkg_name", "") or f.get(
                "snippet", ""
            ).split("@")[0]
            cve = f.get("cve_id", "") or ""
            xkey: tuple = ("cve", cve, pkg)
        else:
            title_norm = re.sub(r"[\s\-_]+", "", f.get("description", "").lower())[:40]
            xkey = ("sast", f.get("file", ""), f.get("line", 0), title_norm)
        existing = cross.get(xkey)
        if existing is None or f["risk_score"] > existing["risk_score"]:
            cross[xkey] = f

    return list(cross.values())


# ---------------------------------------------------------------------------
# Top-level entry point
# ---------------------------------------------------------------------------
def normalise_all(
    semgrep_findings: list[dict],
    gitleaks_findings: list[dict],
    trivy_output: dict,
    bandit_findings: list[dict] | None = None,
    safety_findings: list[dict] | None = None,
    eslint_findings: list[dict] | None = None,
    gosec_findings: list[dict] | None = None,
    trufflehog_findings: list[dict] | None = None,
    spotbugs_findings: list[dict] | None = None,
    owasp_depcheck_findings: list[dict] | None = None,
) -> list[dict]:
    """
    Normalise findings from all scanners, deduplicate, sort by
    risk_score descending, and enforce the MAX_FINDINGS cap.
    """
    unified: list[dict] = []
    unified.extend(normalise_semgrep(semgrep_findings))
    unified.extend(normalise_gitleaks(gitleaks_findings))
    unified.extend(normalise_trivy(trivy_output))
    if bandit_findings:
        unified.extend(normalise_bandit(bandit_findings))
    if safety_findings:
        unified.extend(normalise_safety(safety_findings))
    if eslint_findings:
        unified.extend(normalise_eslint(eslint_findings))
    if gosec_findings:
        unified.extend(normalise_gosec(gosec_findings))
    if trufflehog_findings:
        unified.extend(normalise_trufflehog(trufflehog_findings))
    if spotbugs_findings:
        unified.extend(normalise_spotbugs(spotbugs_findings))
    if owasp_depcheck_findings:
        unified.extend(normalise_owasp_depcheck(owasp_depcheck_findings))
    unified = deduplicate(unified)
    unified.sort(key=lambda x: x["risk_score"], reverse=True)
    return unified[:MAX_FINDINGS]
