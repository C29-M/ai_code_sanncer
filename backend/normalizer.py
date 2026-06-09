"""
Unified findings normaliser for AI Code Scanner.

Maps raw Semgrep / Gitleaks / Trivy / Bandit / Safety / ESLint / Gosec /
TruffleHog / SpotBugs / OWASP Dependency-Check output to the unified schema,
applies three-pass deduplication, computes risk scores, and enforces
operational limits.

Unified schema fields
---------------------
tool          : semgrep | gitleaks | trivy | ...
rule_id       : scanner-specific rule identifier
severity      : CRITICAL | HIGH | MEDIUM | LOW | INFO  (display enum)
language      : python | javascript | go | java | all | ...
file          : relative or absolute path to the affected file
line          : start line number (0 for dependency-level findings)
snippet       : up to 200 chars of context (secrets partially masked)
description   : scanner-provided description
category      : sast | secrets | cve | iac | history
cve_id        : CVE identifier or None
cvss_score    : CVSS v3 score 0-10 or None
risk_score    : computed 0-100 integer
metadata      : dict with cwe, owasp, confidence, impact, likelihood, shortlink

AI-scanner category values (added Week 4)
------------------------------------------
prompt_injection | jailbreak | data_exfiltration | pii_leakage |
secret_leakage   | harmful_content | unsafe_permissions | safety_bypass |
malicious_intent | suspicious_workflow
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, TypedDict


# ---------------------------------------------------------------------------
# Finding TypedDict — unified schema used by all scanner normalisers
# ---------------------------------------------------------------------------
class Finding(TypedDict, total=False):
    tool: str
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    language: str
    file: str
    line: int
    snippet: str
    description: str
    category: str
    cve_id: Optional[str]
    cvss_score: Optional[float]
    risk_score: int
    confidence: float  # 0.0-1.0
    metadata: dict


# ---------------------------------------------------------------------------
# Operational limits
# ---------------------------------------------------------------------------
MAX_FINDINGS = 500
MAX_SNIPPET_LEN = 200

# ---------------------------------------------------------------------------
# Scanner-specific severity weights (risk scoring)
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
        "ERROR": "HIGH",
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
# Secret masking
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
        text = _PEM_RE.sub("[PRIVATE KEY REDACTED]", text)
        text = re.sub(
            r"((?:password|passwd|secret|token|api[_\-]?key|auth[_\-]?key"
            r"|access[_\-]?key|private[_\-]?key|credential)\s*[=:]\s*)"
            r"[\"']?[\w\-./+]{6,}[\"']?",
            r"\1[REDACTED]",
            text,
            flags=re.IGNORECASE,
        )
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


# ===========================================================================
# NEW HELPER FUNCTIONS (Week 4 additions)
# ===========================================================================

# ---------------------------------------------------------------------------
# 1. severity_from_string
# ---------------------------------------------------------------------------
_SEV_MAP: dict[str, str] = {
    # Standard
    "critical": "CRITICAL",
    "high": "HIGH",
    "medium": "MEDIUM",
    "moderate": "MEDIUM",
    "med": "MEDIUM",
    "low": "LOW",
    "info": "INFO",
    "informational": "INFO",
    "note": "INFO",
    "warning": "HIGH",
    "warn": "HIGH",
    "error": "CRITICAL",
    "err": "CRITICAL",
    # Numeric CVSS bands
    "10": "CRITICAL",
    "9": "CRITICAL",
    "8": "HIGH",
    "7": "HIGH",
    "6": "MEDIUM",
    "5": "MEDIUM",
    "4": "MEDIUM",
    "3": "LOW",
    "2": "LOW",
    "1": "LOW",
    "0": "INFO",
    # Semgrep-specific
    "blocker": "CRITICAL",
    "major": "HIGH",
    "minor": "LOW",
    # Misc
    "unknown": "INFO",
    "none": "INFO",
}


def severity_from_string(s: str) -> str:
    """
    Map an arbitrary scanner severity string to a canonical value:
    CRITICAL | HIGH | MEDIUM | LOW | INFO.

    Handles numeric CVSS scores (as strings), named levels from Semgrep,
    Bandit, Trivy, ESLint, and generic severity vocabulary.
    Falls back to INFO for unrecognised values.
    """
    if not s:
        return "INFO"
    key = s.strip().lower()

    # Direct lookup
    if key in _SEV_MAP:
        return _SEV_MAP[key]

    # Numeric CVSS float (e.g. "7.5")
    try:
        score = float(key)
        if score >= 9.0:
            return "CRITICAL"
        if score >= 7.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score > 0.0:
            return "LOW"
        return "INFO"
    except ValueError:
        pass

    # Already a standard value (uppercase check)
    upper = key.upper()
    if upper in _STANDARD_SEVS:
        return upper

    return "INFO"


# ---------------------------------------------------------------------------
# 2. confidence_from_string
# ---------------------------------------------------------------------------
_CONF_MAP: dict[str, float] = {
    "critical": 1.0,
    "high": 0.9,
    "confirmed": 1.0,
    "verified": 1.0,
    "firm": 0.85,
    "medium": 0.6,
    "moderate": 0.6,
    "med": 0.6,
    "tentative": 0.4,
    "low": 0.3,
    "speculative": 0.2,
    "experimental": 0.2,
    "unknown": 0.5,
    "info": 0.5,
    "none": 0.0,
}


def confidence_from_string(s: str) -> float:
    """
    Map a confidence label to a float in [0.0, 1.0].

    Recognised labels (case-insensitive):
      high / confirmed / verified  -> 0.9-1.0
      medium / moderate            -> 0.6
      low / tentative              -> 0.2-0.3
      unknown / info               -> 0.5

    Returns 0.5 for unrecognised strings.
    """
    if not s:
        return 0.5
    key = s.strip().lower()
    if key in _CONF_MAP:
        return _CONF_MAP[key]
    # Try numeric
    try:
        v = float(key)
        # Accept 0-1 or 0-100
        if v > 1.0:
            v /= 100.0
        return max(0.0, min(1.0, v))
    except ValueError:
        pass
    return 0.5


# ---------------------------------------------------------------------------
# 3. category_from_keywords
# ---------------------------------------------------------------------------

# Ordered list of (category, keyword_patterns) — first match wins.
# Patterns are checked against lowercased text.
_CATEGORY_KEYWORDS: list[tuple[str, list[str]]] = [
    (
        "prompt_injection",
        [
            "prompt injection",
            "prompt-injection",
            "indirect injection",
            "system prompt override",
            "instruction injection",
            "llm injection",
            "adversarial prompt",
            "prompt smuggling",
        ],
    ),
    (
        "jailbreak",
        [
            "jailbreak",
            "jailbreaking",
            "do anything now",
            "dan prompt",
            "ignore previous instructions",
            "bypass safety",
            "pretend you are",
            "roleplay as",
            "act as if",
            "disable content filter",
        ],
    ),
    (
        "data_exfiltration",
        [
            "data exfiltration",
            "exfiltrate",
            "data leak via",
            "send data to",
            "exfil",
            "exfiltrating",
            "data theft",
            "unauthorized transfer",
            "command and control",
            "c2 callback",
            "phone home",
        ],
    ),
    (
        "pii_leakage",
        [
            "pii",
            "personally identifiable",
            "personal data",
            "ssn",
            "social security",
            "credit card",
            "date of birth",
            "email address",
            "phone number",
            "passport",
            "driver license",
            "gdpr",
            "private information",
            "user data leak",
        ],
    ),
    (
        "secret_leakage",
        [
            "api key",
            "api_key",
            "secret key",
            "private key",
            "access token",
            "auth token",
            "bearer token",
            "password",
            "passwd",
            "hardcoded secret",
            "credential",
            "aws_secret",
            "aws_access_key",
            "github_token",
            "stripe_key",
            "slack_token",
            "service account key",
        ],
    ),
    (
        "harmful_content",
        [
            "harmful content",
            "malware",
            "ransomware",
            "exploit code",
            "shellcode",
            "offensive content",
            "illegal content",
            "csam",
            "violence",
            "self-harm",
            "suicide",
            "drug synthesis",
            "weapon",
            "bomb",
            "bioweapon",
            "cyberweapon",
        ],
    ),
    (
        "unsafe_permissions",
        [
            "privilege escalation",
            "unauthorized access",
            "broken access control",
            "missing authentication",
            "improper authorization",
            "idor",
            "insecure direct object",
            "path traversal",
            "lfi",
            "rfi",
            "file inclusion",
            "directory traversal",
            "over-privileged",
            "excessive permission",
        ],
    ),
    (
        "safety_bypass",
        [
            "safety bypass",
            "guardrail bypass",
            "filter bypass",
            "content policy bypass",
            "moderation bypass",
            "alignment bypass",
            "refusal bypass",
            "uncensored",
            "jailbroken model",
        ],
    ),
    (
        "malicious_intent",
        [
            "malicious intent",
            "malicious payload",
            "backdoor",
            "trojan",
            "rootkit",
            "spyware",
            "keylogger",
            "rat ",
            "remote access trojan",
            "command injection",
            "code injection",
            "sql injection",
            "rce",
            "remote code execution",
        ],
    ),
    (
        "suspicious_workflow",
        [
            "suspicious workflow",
            "anomalous behaviour",
            "unusual pattern",
            "obfuscated code",
            "encoded payload",
            "base64 payload",
            "steganography",
            "covert channel",
            "timing attack",
            "side channel",
            "hidden instruction",
            "stealth",
        ],
    ),
]


def category_from_keywords(text: str) -> str:
    """
    Detect the security category from free-form text by keyword matching.

    Returns one of:
      prompt_injection | jailbreak | data_exfiltration | pii_leakage |
      secret_leakage   | harmful_content | unsafe_permissions |
      safety_bypass    | malicious_intent | suspicious_workflow

    Falls back to "sast" when no keywords match.
    """
    if not text:
        return "sast"
    lower = text.lower()
    for category, keywords in _CATEGORY_KEYWORDS:
        for kw in keywords:
            if kw in lower:
                return category
    return "sast"


# ---------------------------------------------------------------------------
# 4. extract_snippet
# ---------------------------------------------------------------------------


def extract_snippet(
    prompt_text: str,
    line_number: int | None = None,
    start: int | None = None,
    end: int | None = None,
) -> str:
    """
    Extract a relevant text snippet from *prompt_text*.

    Priority:
      1. If *start* and *end* are given, return characters [start:end].
      2. If *line_number* is given (1-based), return that line plus up to
         2 lines of surrounding context (1 before, 1 after).
      3. Otherwise return the first MAX_SNIPPET_LEN characters.

    The result is always truncated to MAX_SNIPPET_LEN characters.
    """
    if not prompt_text:
        return ""

    # Character-level slice
    if start is not None and end is not None:
        return prompt_text[start:end][:MAX_SNIPPET_LEN]

    # Line-based extraction
    if line_number is not None and line_number >= 1:
        lines = prompt_text.splitlines()
        idx = line_number - 1  # convert to 0-based
        lo = max(0, idx - 1)
        hi = min(len(lines), idx + 2)
        snippet = "\n".join(lines[lo:hi])
        return snippet[:MAX_SNIPPET_LEN]

    # Fallback: head of text
    return prompt_text[:MAX_SNIPPET_LEN]


# ---------------------------------------------------------------------------
# 5. normalize_finding  (generic normaliser from a raw dict)
# ---------------------------------------------------------------------------


def normalize_finding(
    raw: dict,
    scanner_name: str,
    prompt_text: str,
) -> Finding:
    """
    Generic normaliser — converts a raw scanner dict into a Finding.

    Attempts to extract common fields using a wide set of key aliases so
    that callers do not need scanner-specific logic for simple cases.
    For full fidelity use the scanner-specific normalise_* functions below.
    """
    # --- rule_id ---
    rule_id: str = (
        raw.get("rule_id")
        or raw.get("check_id")
        or raw.get("test_id")
        or raw.get("RuleID")
        or raw.get("VulnerabilityID")
        or raw.get("cve_id")
        or raw.get("type")
        or "unknown"
    )

    # --- severity ---
    raw_sev: str = (
        raw.get("severity")
        or raw.get("issue_severity")
        or raw.get("Severity")
        or (raw.get("extra") or {}).get("severity")
        or "INFO"
    )
    severity = severity_from_string(raw_sev)

    # --- line ---
    line: int = int(
        raw.get("line")
        or raw.get("line_number")
        or raw.get("StartLine")
        or (raw.get("start") or {}).get("line")
        or 0
    )

    # --- file ---
    file_path: str = (
        raw.get("file")
        or raw.get("filename")
        or raw.get("filePath")
        or raw.get("File")
        or raw.get("path")
        or ""
    )

    # --- description ---
    description: str = (
        raw.get("description")
        or raw.get("message")
        or raw.get("issue_text")
        or raw.get("details")
        or (raw.get("extra") or {}).get("message")
        or rule_id
    ).strip()

    # --- snippet ---
    raw_snippet: str = (
        raw.get("snippet")
        or raw.get("code")
        or raw.get("Match")
        or (raw.get("extra") or {}).get("lines")
        or ""
    )
    if not raw_snippet and prompt_text:
        raw_snippet = extract_snippet(prompt_text, line_number=line if line else None)
    snippet = safe_snippet(raw_snippet)

    # --- category ---
    category: str = raw.get("category") or category_from_keywords(
        description + " " + rule_id
    )

    # --- confidence ---
    raw_conf: str = (
        raw.get("confidence")
        or raw.get("issue_confidence")
        or (raw.get("metadata") or {}).get("confidence")
        or "MEDIUM"
    )
    confidence: float = confidence_from_string(str(raw_conf))

    # --- cvss ---
    cvss_score: float | None = raw.get("cvss_score") or raw.get("cvss")
    if cvss_score is not None:
        try:
            cvss_score = float(cvss_score)
        except (ValueError, TypeError):
            cvss_score = None

    cve_id: str | None = raw.get("cve_id") or raw.get("VulnerabilityID") or None

    # --- risk_score ---
    risk_score = compute_risk_score(scanner_name, raw_sev.upper(), cvss_score, category)

    # --- metadata ---
    existing_meta: dict = raw.get("metadata") or {}
    metadata: dict = {
        "cwe": existing_meta.get("cwe") or _cwe_from_meta(raw),
        "owasp": existing_meta.get("owasp") or "",
        "confidence": raw_conf,
        "impact": existing_meta.get("impact") or "",
        "likelihood": existing_meta.get("likelihood") or "",
        "shortlink": existing_meta.get("shortlink") or "",
    }

    finding: Finding = {
        "tool": scanner_name,
        "rule_id": str(rule_id),
        "severity": severity,
        "language": _lang_from_path(file_path),
        "file": file_path,
        "line": line,
        "snippet": snippet,
        "description": description,
        "category": category,
        "cve_id": cve_id,
        "cvss_score": cvss_score,
        "risk_score": risk_score,
        "confidence": confidence,
        "metadata": metadata,
    }
    return finding


# ---------------------------------------------------------------------------
# 6. deduplicate_findings  (Finding-typed variant)
# ---------------------------------------------------------------------------


def _snippet_similarity(a: str, b: str) -> float:
    """
    Simple character-level Jaccard similarity for short strings.
    Returns a value in [0.0, 1.0].
    """
    if not a and not b:
        return 1.0
    if not a or not b:
        return 0.0
    set_a = set(a.lower().split())
    set_b = set(b.lower().split())
    if not set_a and not set_b:
        return 1.0
    if not set_a or not set_b:
        return 0.0
    intersection = len(set_a & set_b)
    union = len(set_a | set_b)
    return intersection / union if union else 0.0


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    """
    Remove near-duplicate findings based on rule_id + snippet similarity.

    Two findings are considered duplicates when:
      - They share the same rule_id (normalised), AND
      - Their snippet Jaccard similarity >= 0.8, OR both snippets are empty.

    When duplicates are found the one with the higher risk_score is kept.
    Findings without a rule_id are deduplicated by (file, line, description).

    This is the Finding-typed public API. The internal three-pass
    ``deduplicate()`` function (used by ``normalise_all``) operates on plain
    dicts for backwards compatibility.
    """
    SIMILARITY_THRESHOLD = 0.8
    kept: list[Finding] = []

    for candidate in findings:
        c_rule = (candidate.get("rule_id") or "").strip().lower()
        c_snip = (candidate.get("snippet") or "").strip()
        c_score = candidate.get("risk_score") or 0

        duplicate_idx: int | None = None
        for i, existing in enumerate(kept):
            e_rule = (existing.get("rule_id") or "").strip().lower()

            # Fallback key when rule_id is absent
            if not c_rule and not e_rule:
                c_key = (
                    candidate.get("file", ""),
                    candidate.get("line", 0),
                    (candidate.get("description") or "")[:60],
                )
                e_key = (
                    existing.get("file", ""),
                    existing.get("line", 0),
                    (existing.get("description") or "")[:60],
                )
                if c_key == e_key:
                    duplicate_idx = i
                    break
                continue

            if c_rule != e_rule:
                continue

            e_snip = (existing.get("snippet") or "").strip()
            # Both empty -> definite duplicate
            if not c_snip and not e_snip:
                duplicate_idx = i
                break
            sim = _snippet_similarity(c_snip, e_snip)
            if sim >= SIMILARITY_THRESHOLD:
                duplicate_idx = i
                break

        if duplicate_idx is None:
            kept.append(candidate)
        else:
            # Keep the higher-scored one
            existing_score = kept[duplicate_idx].get("risk_score") or 0
            if c_score > existing_score:
                kept[duplicate_idx] = candidate

    return kept


# ===========================================================================
# Scanner-specific normalisers (unchanged from Week 3)
# ===========================================================================


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

            nvd_score: float | None = None
            for src in ("nvd", "ghsa", "redhat"):
                v3 = (vuln.get("CVSS") or {}).get(src, {}).get("V3Score")
                if v3 is not None:
                    nvd_score = float(v3)
                    break

            snippet = f"{pkg}@{inst_ver}"
            if fix_ver:
                snippet += f" -> fix: {fix_ver}"

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
        if not rule_id and (
            "Parsing error" in message or "could not be parsed" in message.lower()
        ):
            continue
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
                        f"https://github.com/eslint-community/eslint-plugin-security"
                        f"/blob/main/docs/rules/{rule_id.replace('security/', '')}.md"
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

        src_meta = (r.get("SourceMetadata") or {}).get("Data", {})
        git_meta = src_meta.get("Git", {})
        file_path = git_meta.get("file", "")
        line = git_meta.get("line", 0)
        commit = git_meta.get("commit", "")

        desc = f"{detector} credential found in git history"
        if verified:
            desc += " (VERIFIED - still active)"

        raw_sev = "CRITICAL"
        risk_score = compute_risk_score("trufflehog", raw_sev, None, "history")
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


# ===========================================================================
# Three-pass deduplication (plain-dict variant — used by normalise_all)
# ===========================================================================
def deduplicate(findings: list[dict]) -> list[dict]:
    """
    Pass 1: per-scanner dedup by (category, cve_id/pkg/file) or (file, line, rule_id).
    Pass 2: cross-scanner dedup by (cve_id, pkg) or (file, line, normalised_title).
    Higher risk_score wins in both passes.
    """
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

    # Pass 2
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


# ===========================================================================
# Top-level entry point
# ===========================================================================
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
