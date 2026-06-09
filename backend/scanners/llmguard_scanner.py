"""
LLM Guard scanner for AI Code Scanner.

Uses the `llm-guard` Python library to run static input scanners against
prompt text without making any live LLM calls.  All scanners used here
operate purely with local transformer models or rule-based logic.

Supported input scanners (no LLM calls required):
- PromptInjectionV2  : transformer-based prompt injection detection
- Secrets            : detects API keys / secrets in prompt text
- BanTopics          : zero-shot topic ban via local classifier
- Anonymize          : PII detection via presidio / spacy
- Language           : language identification
- Regex              : pattern-based detection

Severity mapping
----------------
LLM Guard scanners return a float risk score in [0.0, 1.0].

    score >= 0.90  ->  CRITICAL
    score >= 0.70  ->  HIGH
    score >= 0.50  ->  MEDIUM
    score >= 0.25  ->  LOW
    score <  0.25  ->  INFO

Category mapping
----------------
    PromptInjection* ->  "prompt_injection"
    Secrets          ->  "secrets"
    BanTopics        ->  "policy_violation"
    Anonymize        ->  "pii"
    Language         ->  "policy_violation"
    Regex            ->  "sast"
"""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level optional import — llm_guard may not be installed.
# ---------------------------------------------------------------------------
try:
    import llm_guard  # noqa: F401 — used only for __version__ / availability check

    _LLM_GUARD_AVAILABLE = True
except ImportError:
    _LLM_GUARD_AVAILABLE = False

# Import the base types from the parent package.  The scanners/ directory sits
# inside backend/, so scanner_base is a sibling module.
try:
    from scanner_base import BaseScanner, Finding, Severity
except ImportError:
    # Fallback for environments where the package root is not on sys.path yet.
    import sys
    import os

    sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
    from scanner_base import BaseScanner, Finding, Severity  # type: ignore


# ---------------------------------------------------------------------------
# Severity helpers
# ---------------------------------------------------------------------------


def _score_to_severity(risk_score: float) -> Severity:
    """Map a LLM Guard risk score (0.0–1.0) to our Severity enum."""
    if risk_score >= 0.90:
        return Severity.CRITICAL
    if risk_score >= 0.70:
        return Severity.HIGH
    if risk_score >= 0.50:
        return Severity.MEDIUM
    if risk_score >= 0.25:
        return Severity.LOW
    return Severity.INFO


# Scanner name -> category string
_SCANNER_CATEGORY: Dict[str, str] = {
    "PromptInjection": "prompt_injection",
    "PromptInjectionV2": "prompt_injection",
    "Secrets": "secrets",
    "BanTopics": "policy_violation",
    "Anonymize": "pii",
    "Language": "policy_violation",
    "Regex": "sast",
}


def _scanner_category(scanner_name: str) -> str:
    for key, cat in _SCANNER_CATEGORY.items():
        if key.lower() in scanner_name.lower():
            return cat
    return "sast"


# ---------------------------------------------------------------------------
# Individual scanner wrappers
# These return (is_valid, risk_score, sanitized_prompt) tuples, just like the
# llm_guard.input_validation.scan_prompt() API, but called per-scanner.
# ---------------------------------------------------------------------------


def _run_prompt_injection(prompt: str) -> Tuple[bool, float, str]:
    """Run PromptInjectionV2 (falls back to PromptInjection on older versions)."""
    try:
        from llm_guard.input_scanners import PromptInjectionV2

        scanner = PromptInjectionV2()
    except ImportError:
        from llm_guard.input_scanners import PromptInjection  # type: ignore

        scanner = PromptInjection()

    sanitized, is_valid, risk_score = scanner.scan(prompt)
    return is_valid, risk_score, sanitized


def _run_secrets(prompt: str) -> Tuple[bool, float, str]:
    from llm_guard.input_scanners import Secrets

    scanner = Secrets()
    sanitized, is_valid, risk_score = scanner.scan(prompt)
    return is_valid, risk_score, sanitized


def _run_ban_topics(prompt: str) -> Tuple[bool, float, str]:
    from llm_guard.input_scanners import BanTopics

    # Default banned topics covering common policy concerns.
    scanner = BanTopics(
        topics=["violence", "hate speech", "self-harm", "illegal activities"],
        threshold=0.5,
    )
    sanitized, is_valid, risk_score = scanner.scan(prompt)
    return is_valid, risk_score, sanitized


def _run_anonymize(prompt: str) -> Tuple[bool, float, str]:
    from llm_guard.input_scanners import Anonymize

    scanner = Anonymize()
    sanitized, is_valid, risk_score = scanner.scan(prompt)
    return is_valid, risk_score, sanitized


def _run_language(prompt: str) -> Tuple[bool, float, str]:
    from llm_guard.input_scanners import Language

    # Allow English only; flag everything else.
    scanner = Language(valid_languages=["en"])
    sanitized, is_valid, risk_score = scanner.scan(prompt)
    return is_valid, risk_score, sanitized


def _run_regex(prompt: str) -> Tuple[bool, float, str]:
    from llm_guard.input_scanners import Regex

    # Basic patterns: system command injection, common exfiltration patterns.
    patterns = [
        r"(?i)ignore\s+(all\s+)?previous\s+instructions",
        r"(?i)act\s+as\s+(?:an?\s+)?(?:unrestricted|jailbroken|evil|dan)",
        r"(?i)you\s+are\s+now\s+(?:in\s+)?developer\s+mode",
        r"(?i)disregard\s+(your\s+)?(?:previous\s+)?instructions",
        r"(?i)reveal\s+(your\s+)?(?:system\s+)?prompt",
    ]
    scanner = Regex(patterns=patterns, is_blocked=True, match_type="search")
    sanitized, is_valid, risk_score = scanner.scan(prompt)
    return is_valid, risk_score, sanitized


# Registry of (scanner_display_name, runner_function) pairs.
# Each runner must accept a single `prompt: str` argument and return
# (is_valid: bool, risk_score: float, sanitized: str).
_SCANNER_RUNNERS: List[Tuple[str, Any]] = [
    ("PromptInjectionV2", _run_prompt_injection),
    ("Secrets", _run_secrets),
    ("BanTopics", _run_ban_topics),
    ("Anonymize", _run_anonymize),
    ("Language", _run_language),
    ("Regex", _run_regex),
]


# ---------------------------------------------------------------------------
# LLMGuardScanner
# ---------------------------------------------------------------------------


class LLMGuardScanner(BaseScanner):
    """
    Wraps the `llm-guard` Python library's input scanners.

    All scanners execute locally — no network calls are made during a scan.
    Heavy transformer models (PromptInjectionV2, BanTopics) are loaded lazily
    on first use; subsequent calls reuse the cached model.
    """

    # ------------------------------------------------------------------
    # BaseScanner interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "llmguard"

    @property
    def version(self) -> str:
        if not _LLM_GUARD_AVAILABLE:
            raise RuntimeError("llm-guard is not installed")
        try:
            import llm_guard as _lg

            return getattr(_lg, "__version__", "unknown")
        except Exception as exc:
            raise RuntimeError(f"Could not determine llm-guard version: {exc}") from exc

    def is_available(self) -> bool:
        return _LLM_GUARD_AVAILABLE

    def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        """
        Scan *target* as plain prompt text.

        Parameters
        ----------
        target:
            The prompt / text string to scan.  When called from the main
            scanner pipeline *target* is the content of a file or a prompt
            extracted from the repository being audited.
        **kwargs:
            Reserved for future options (e.g. ``scanners=["Secrets"]`` to run
            a subset).

        Returns
        -------
        List[Finding]
            One Finding per scanner that flagged the input (risk_score >= 0.25
            or is_valid == False).  Scanners that pass cleanly produce no
            finding.
        """
        if not _LLM_GUARD_AVAILABLE:
            logger.warning(
                "llmguard scanner requested but llm-guard is not installed; "
                "skipping.  Install with: pip install llm-guard"
            )
            return []

        prompt_text: str = target
        findings: List[Finding] = []

        # Optionally restrict which sub-scanners run.
        enabled: Optional[List[str]] = kwargs.get("scanners")  # list[str] | None

        for scanner_name, runner in _SCANNER_RUNNERS:
            if enabled is not None and scanner_name not in enabled:
                continue

            try:
                is_valid, risk_score, sanitized = runner(prompt_text)
            except ImportError as exc:
                # The specific sub-scanner's dependency is not installed;
                # log at DEBUG and continue rather than failing the whole scan.
                logger.debug(
                    "Skipping LLM Guard sub-scanner '%s' — import failed: %s",
                    scanner_name,
                    exc,
                )
                continue
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "LLM Guard sub-scanner '%s' raised an unexpected error: %s",
                    scanner_name,
                    exc,
                )
                continue

            # Only generate a finding when the scanner actually flagged something.
            if is_valid and risk_score < 0.25:
                continue

            severity = _score_to_severity(risk_score)
            category = _scanner_category(scanner_name)

            # Build a short, human-readable description.
            flag_reason = "flagged" if not is_valid else f"risk score {risk_score:.2f}"
            description = (
                f"LLM Guard {scanner_name} scanner {flag_reason}. "
                f"Category: {category}."
            )
            if sanitized and sanitized != prompt_text:
                # Include a brief excerpt of what was sanitized/redacted.
                excerpt = sanitized[:120].replace("\n", " ")
                description += f" Sanitized excerpt: {excerpt!r}"

            # Truncate the snippet to 200 chars and avoid leaking secrets.
            snippet = prompt_text[:200].replace("\n", " ")
            if category in ("secrets", "pii"):
                # Mask the snippet for sensitive categories.
                snippet = "[REDACTED — sensitive content detected]"

            findings.append(
                Finding(
                    scanner=self.name,
                    rule_id=f"llmguard.{scanner_name.lower()}",
                    title=f"{scanner_name} detected in prompt",
                    severity=severity,
                    description=description,
                    file_path=None,  # prompt-level; no file attribution
                    line_start=None,
                    line_end=None,
                    cwe=_SCANNER_CWE.get(scanner_name),
                    cve=None,
                    confidence=_risk_score_to_confidence(risk_score),
                    remediation=_SCANNER_REMEDIATION.get(scanner_name),
                    raw={
                        "scanner": scanner_name,
                        "is_valid": is_valid,
                        "risk_score": risk_score,
                        "category": category,
                        "snippet": snippet,
                    },
                )
            )

        return findings


# ---------------------------------------------------------------------------
# Static metadata tables
# ---------------------------------------------------------------------------

_SCANNER_CWE: Dict[str, str] = {
    "PromptInjection": "CWE-77",  # Improper Neutralization of Special Elements
    "PromptInjectionV2": "CWE-77",
    "Secrets": "CWE-798",  # Use of Hard-coded Credentials
    "BanTopics": "CWE-693",  # Protection Mechanism Failure
    "Anonymize": "CWE-359",  # Exposure of Private Personal Information
    "Language": "CWE-116",  # Improper Encoding or Escaping of Output
    "Regex": "CWE-77",
}

_SCANNER_REMEDIATION: Dict[str, str] = {
    "PromptInjection": (
        "Sanitize or validate user-supplied text before passing it to an LLM. "
        "Consider using a system prompt prefix that instructs the model to ignore "
        "instruction overrides in user input."
    ),
    "PromptInjectionV2": (
        "Sanitize or validate user-supplied text before passing it to an LLM. "
        "Consider using a system prompt prefix that instructs the model to ignore "
        "instruction overrides in user input."
    ),
    "Secrets": (
        "Remove credentials, API keys, and tokens from prompt text. "
        "Use environment variables or a secrets manager instead of embedding "
        "secrets in strings that may be passed to an LLM."
    ),
    "BanTopics": (
        "Review the prompt content for policy-violating topics and add input "
        "filtering or moderation before forwarding to an LLM."
    ),
    "Anonymize": (
        "Remove or pseudonymize personally identifiable information (PII) "
        "before sending data to an LLM to comply with data protection regulations."
    ),
    "Language": (
        "Ensure the prompt language matches the expected locale for the application. "
        "Unexpected languages may indicate adversarial input or misuse."
    ),
    "Regex": (
        "The prompt matches a known injection or manipulation pattern. "
        "Validate and sanitize the input before use."
    ),
}


def _risk_score_to_confidence(risk_score: float) -> str:
    """Translate a numeric risk score to a confidence label."""
    if risk_score >= 0.85:
        return "HIGH"
    if risk_score >= 0.55:
        return "MEDIUM"
    return "LOW"
