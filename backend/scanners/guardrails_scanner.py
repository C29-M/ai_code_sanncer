"""
Guardrails AI scanner for AI Code Scanner — Week 4.

Uses guardrails-ai (pip install guardrails-ai) validators to scan prompt text
for toxic language, PII leakage, injection keywords, and excessive length.

Version compatibility notes
---------------------------
- guardrails-ai 0.4.x introduced a breaking Hub-based import path for validators
  (``from guardrails.hub import ToxicLanguage``).  Earlier 0.3.x releases shipped
  validators under ``guardrails.validators``.  This module probes both paths and
  falls back gracefully so the scanner works (or degrades safely) across versions.

- Many Hub validators (ToxicLanguage, DetectPII, RestrictToTopic) require an
  active network connection to download model weights on first use, or a prior
  ``guardrails hub install <validator>`` CLI invocation.  When those validators
  are not locally installed the scanner falls back to a built-in keyword-based
  injection check that has no external dependencies.

- ValidLength is a lightweight validator bundled with guardrails-ai core and
  does not require Hub installation; it is always attempted.

- If guardrails-ai is not installed at all, ``is_available()`` returns False and
  the scanner is silently skipped by the orchestrator.
"""

from __future__ import annotations

import re
from typing import Any

# ---------------------------------------------------------------------------
# Availability probe
# ---------------------------------------------------------------------------


def is_available() -> bool:
    """Return True if guardrails-ai is importable."""
    try:
        import guardrails  # noqa: F401

        return True
    except ImportError:
        return False


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

# Well-known prompt-injection / jailbreak keywords used by the fallback
# validator when Hub validators are unavailable.
_INJECTION_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"\bignore\s+(all\s+)?previous\s+instructions?\b", re.I),
        "Classic ignore-previous-instructions injection",
    ),
    (
        re.compile(r"\bforget\s+(all\s+)?previous\s+instructions?\b", re.I),
        "Forget-previous-instructions injection",
    ),
    (
        re.compile(r"\bact\s+as\s+(if\s+you\s+are|an?)\b", re.I),
        "Role-override injection (act as …)",
    ),
    (
        re.compile(r"\byou\s+are\s+now\s+(?:a|an|the)\b", re.I),
        "Role-override injection (you are now …)",
    ),
    (re.compile(r"\bsystem\s*prompt\b", re.I), "System-prompt disclosure attempt"),
    (re.compile(r"\bjailbreak\b", re.I), "Explicit jailbreak keyword"),
    (re.compile(r"\bDAN\b"), "DAN (Do Anything Now) jailbreak pattern"),
    (
        re.compile(r"\bpretend\s+(you\s+have\s+no\s+restrictions|to\s+be)\b", re.I),
        "Restriction-bypass injection (pretend …)",
    ),
    (
        re.compile(r"\bdisregard\s+(your\s+)?(previous|prior|earlier)\b", re.I),
        "Disregard-previous injection",
    ),
    (re.compile(r"\bexfiltrate\b", re.I), "Data-exfiltration keyword"),
    (re.compile(r"\bprompt\s+injection\b", re.I), "Prompt injection self-reference"),
]

# PII heuristic patterns used by the fallback when DetectPII is unavailable.
_PII_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "Possible US Social Security Number (SSN)"),
    (re.compile(r"\b4[0-9]{12}(?:[0-9]{3})?\b"), "Possible Visa credit-card number"),
    (re.compile(r"\b5[1-5][0-9]{14}\b"), "Possible Mastercard credit-card number"),
    (
        re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}"),
        "Email address detected",
    ),
    (
        re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
        "Possible US phone number",
    ),
]

_MAX_PROMPT_CHARS = 10_000  # soft upper limit — flag unusually long prompts


def _make_finding(
    rule_id: str,
    description: str,
    severity: str,
    category: str,
    snippet: str = "",
    validator: str = "guardrails",
) -> dict[str, Any]:
    """Return a finding dict that conforms to the unified schema."""
    return {
        "tool": "guardrails",
        "rule_id": rule_id,
        "severity": severity,
        "language": "all",
        "file": "<prompt>",
        "line": 0,
        "snippet": snippet[:200],
        "description": description,
        "category": category,
        "cve_id": None,
        "cvss_score": None,
        "risk_score": _severity_to_risk(severity),
        "metadata": {
            "validator": validator,
            "confidence": "MEDIUM",
        },
    }


def _severity_to_risk(severity: str) -> int:
    return {"CRITICAL": 90, "HIGH": 70, "MEDIUM": 45, "LOW": 20, "INFO": 5}.get(
        severity, 20
    )


# ---------------------------------------------------------------------------
# Fallback validators (no Hub / no network required)
# ---------------------------------------------------------------------------


def _fallback_injection_check(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pattern, description in _INJECTION_PATTERNS:
        m = pattern.search(text)
        if m:
            findings.append(
                _make_finding(
                    rule_id="guardrails/injection-keyword",
                    description=description,
                    severity="HIGH",
                    category="sast",
                    snippet=text[max(0, m.start() - 30) : m.end() + 30].strip(),
                    validator="fallback-keyword",
                )
            )
    return findings


def _fallback_pii_check(text: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for pattern, description in _PII_PATTERNS:
        m = pattern.search(text)
        if m:
            # Mask PII in snippet
            raw = m.group(0)
            masked = raw[:2] + "*" * max(0, len(raw) - 4) + raw[-2:]
            findings.append(
                _make_finding(
                    rule_id="guardrails/pii-detected",
                    description=description,
                    severity="HIGH",
                    category="secrets",
                    snippet=masked,
                    validator="fallback-regex",
                )
            )
    return findings


def _length_check(text: str) -> list[dict[str, Any]]:
    if len(text) > _MAX_PROMPT_CHARS:
        return [
            _make_finding(
                rule_id="guardrails/excessive-length",
                description=(
                    f"Prompt length {len(text)} chars exceeds soft limit "
                    f"of {_MAX_PROMPT_CHARS} chars — possible token-stuffing attack."
                ),
                severity="MEDIUM",
                category="sast",
                snippet=text[:80] + "…",
                validator="ValidLength-fallback",
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Guardrails Hub validator wrappers
# ---------------------------------------------------------------------------


def _try_toxic_language(text: str) -> list[dict[str, Any]]:
    """Attempt ToxicLanguage validator (Hub); return [] on any failure."""
    try:
        from guardrails.hub import ToxicLanguage  # type: ignore[import]
        from guardrails import Guard  # type: ignore[import]

        guard = Guard().use(ToxicLanguage, on_fail="noop")
        result = guard.parse(text)
        if not result.validation_passed:
            failures = result.error or "Toxic language detected."
            return [
                _make_finding(
                    rule_id="guardrails/toxic-language",
                    description=str(failures),
                    severity="HIGH",
                    category="sast",
                    snippet=text[:120],
                    validator="ToxicLanguage",
                )
            ]
    except Exception:  # noqa: BLE001
        pass
    return []


def _try_detect_pii(text: str) -> list[dict[str, Any]]:
    """Attempt DetectPII validator (Hub); return [] on any failure."""
    try:
        from guardrails.hub import DetectPII  # type: ignore[import]
        from guardrails import Guard  # type: ignore[import]

        pii_entities = [
            "EMAIL_ADDRESS",
            "PHONE_NUMBER",
            "US_SSN",
            "CREDIT_CARD",
            "IP_ADDRESS",
            "PERSON",
        ]
        guard = Guard().use(DetectPII, pii_entities=pii_entities, on_fail="noop")
        result = guard.parse(text)
        if not result.validation_passed:
            failures = result.error or "PII detected in prompt."
            return [
                _make_finding(
                    rule_id="guardrails/pii-detected",
                    description=str(failures),
                    severity="HIGH",
                    category="secrets",
                    snippet=text[:120],
                    validator="DetectPII",
                )
            ]
    except Exception:  # noqa: BLE001
        pass
    return []


def _try_restrict_to_topic(text: str) -> list[dict[str, Any]]:
    """
    Attempt RestrictToTopic validator (Hub).

    This validator requires an LLM call to classify topic relevance.
    We skip it in static-analysis mode to avoid network/LLM dependencies,
    returning an empty list unconditionally.  Left as a stub so it can be
    activated by callers that supply a configured LLM client.
    """
    # RestrictToTopic always requires an LLM — not suitable for static scanning.
    return []


def _try_valid_length(text: str) -> list[dict[str, Any]]:
    """Attempt ValidLength validator from guardrails core."""
    try:
        # ValidLength ships with guardrails core (no Hub install needed).
        from guardrails.validators import ValidLength  # type: ignore[import]
        from guardrails import Guard  # type: ignore[import]

        guard = Guard().use(ValidLength, min=1, max=_MAX_PROMPT_CHARS, on_fail="noop")
        result = guard.parse(text)
        if not result.validation_passed:
            return [
                _make_finding(
                    rule_id="guardrails/excessive-length",
                    description=(
                        f"Prompt length {len(text)} exceeds ValidLength limit "
                        f"of {_MAX_PROMPT_CHARS} characters."
                    ),
                    severity="MEDIUM",
                    category="sast",
                    snippet=text[:80] + ("…" if len(text) > 80 else ""),
                    validator="ValidLength",
                )
            ]
    except Exception:  # noqa: BLE001
        # Core validator unavailable — use length fallback.
        return _length_check(text)
    return []


# ---------------------------------------------------------------------------
# Public scanner interface
# ---------------------------------------------------------------------------


class GuardrailsScanner:
    """
    Static prompt scanner backed by guardrails-ai validators.

    Designed to be instantiated once and called repeatedly.  All validators
    are attempted in order; failures are collected into a unified findings list.
    Hub validators that are not installed fall back silently to regex-based
    heuristics so the scanner always produces useful output.
    """

    name = "guardrails"

    # ------------------------------------------------------------------
    # Class-level availability cache (probe once per process)
    # ------------------------------------------------------------------
    _available: bool | None = None

    @classmethod
    def is_available(cls) -> bool:
        """Return True if guardrails-ai is importable in this environment."""
        if cls._available is None:
            cls._available = is_available()
        return cls._available  # type: ignore[return-value]

    # ------------------------------------------------------------------
    # Core scan method
    # ------------------------------------------------------------------

    def scan(self, prompt_text: str) -> list[dict[str, Any]]:
        """
        Scan *prompt_text* using available guardrails validators.

        Steps
        -----
        1. ToxicLanguage Hub validator (skipped silently if not installed).
        2. DetectPII Hub validator (skipped silently if not installed).
        3. RestrictToTopic — intentionally skipped (requires LLM call).
        4. ValidLength — guardrails core validator with regex fallback.
        5. Keyword-based injection check (always runs, no deps).
        6. Regex PII heuristics (fallback when DetectPII Hub is absent).

        Returns a list of finding dicts conforming to the unified schema.
        """
        if not prompt_text or not isinstance(prompt_text, str):
            return []

        findings: list[dict[str, Any]] = []

        # --- Hub validators (may silently no-op if not installed) ----------
        hub_toxic = _try_toxic_language(prompt_text)
        findings.extend(hub_toxic)

        hub_pii = _try_detect_pii(prompt_text)
        findings.extend(hub_pii)

        # RestrictToTopic requires LLM — skipped in static mode.
        # findings.extend(_try_restrict_to_topic(prompt_text))

        # --- Core validators -----------------------------------------------
        findings.extend(_try_valid_length(prompt_text))

        # --- Always-on heuristic checks ------------------------------------
        findings.extend(_fallback_injection_check(prompt_text))

        # Only run regex PII if Hub DetectPII did not fire (avoid duplicates).
        if not hub_pii:
            findings.extend(_fallback_pii_check(prompt_text))

        return findings
