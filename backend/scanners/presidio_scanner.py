"""
presidio_scanner.py — PII detection scanner using Microsoft Presidio.

Detects personally identifiable information (PII) in prompt text using
presidio-analyzer's built-in recogniser registry. No LLM calls are made;
detection is performed via NLP (spaCy) and regex pattern matching.

Install:
    pip install presidio-analyzer
    python -m spacy download en_core_web_sm   # optional but recommended

Supported entity types (subset of Presidio defaults):
    PERSON, EMAIL_ADDRESS, PHONE_NUMBER, CREDIT_CARD, CRYPTO, DATE_TIME,
    IBAN_CODE, IP_ADDRESS, NRP, LOCATION, MEDICAL_LICENSE, URL,
    US_BANK_NUMBER, US_DRIVER_LICENSE, US_ITIN, US_PASSPORT, US_SSN,
    UK_NHS
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Finding dataclass (matches the unified schema used by normaliser.py)
# ---------------------------------------------------------------------------


@dataclass
class Finding:
    tool: str
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW | INFO
    language: str
    file: str
    line: int
    snippet: str
    description: str
    category: str  # "pii_leakage" or "privacy_violation"
    title: str
    remediation: str
    cve_id: Optional[str] = None
    cvss_score: Optional[float] = None
    risk_score: int = 0
    metadata: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "language": self.language,
            "file": self.file,
            "line": self.line,
            "snippet": self.snippet,
            "description": self.description,
            "category": self.category,
            "title": self.title,
            "remediation": self.remediation,
            "cve_id": self.cve_id,
            "cvss_score": self.cvss_score,
            "risk_score": self.risk_score,
            "metadata": self.metadata,
        }


# ---------------------------------------------------------------------------
# Severity mapping per entity type
# ---------------------------------------------------------------------------

# HIGH-sensitivity entities that warrant HIGH severity
_HIGH_SEVERITY_ENTITIES = {
    "US_SSN",
    "CREDIT_CARD",
    "US_PASSPORT",
    "US_ITIN",
    "IBAN_CODE",
    "MEDICAL_LICENSE",
    "US_BANK_NUMBER",
    "US_DRIVER_LICENSE",
    "UK_NHS",
    "CRYPTO",
}

# MEDIUM-sensitivity entities
_MEDIUM_SEVERITY_ENTITIES = {
    "EMAIL_ADDRESS",
    "PHONE_NUMBER",
    "IP_ADDRESS",
    "NRP",
    "LOCATION",
}

# LOW-sensitivity entities (still worth flagging)
_LOW_SEVERITY_ENTITIES = {
    "PERSON",
    "DATE_TIME",
    "URL",
}


def _severity_for_entity(entity_type: str) -> str:
    """Return a display severity string for the given Presidio entity type."""
    if entity_type in _HIGH_SEVERITY_ENTITIES:
        return "HIGH"
    if entity_type in _MEDIUM_SEVERITY_ENTITIES:
        return "MEDIUM"
    if entity_type in _LOW_SEVERITY_ENTITIES:
        return "LOW"
    # Unknown entity type — default to MEDIUM
    return "MEDIUM"


def _risk_score_for_severity(severity: str) -> int:
    """Map display severity to a 0-100 risk score (consistent with normaliser)."""
    return {
        "CRITICAL": 90,
        "HIGH": 70,
        "MEDIUM": 40,
        "LOW": 20,
        "INFO": 5,
    }.get(severity, 20)


def _category_for_entity(entity_type: str) -> str:
    """
    Return the finding category.

    Credentials/financial data -> "pii_leakage"
    Identity/location data     -> "privacy_violation"
    """
    if entity_type in {
        "CREDIT_CARD",
        "IBAN_CODE",
        "US_BANK_NUMBER",
        "US_SSN",
        "US_ITIN",
        "US_PASSPORT",
        "US_DRIVER_LICENSE",
        "MEDICAL_LICENSE",
        "UK_NHS",
        "CRYPTO",
    }:
        return "pii_leakage"
    return "privacy_violation"


# ---------------------------------------------------------------------------
# All entity types we ask Presidio to scan for
# ---------------------------------------------------------------------------
_ALL_ENTITIES = list(
    _HIGH_SEVERITY_ENTITIES | _MEDIUM_SEVERITY_ENTITIES | _LOW_SEVERITY_ENTITIES
)


# ---------------------------------------------------------------------------
# PresidioScanner
# ---------------------------------------------------------------------------


class PresidioScanner:
    """
    PII scanner backed by Microsoft Presidio's AnalyzerEngine.

    Usage
    -----
    scanner = PresidioScanner()
    if scanner.is_available():
        findings = scanner.scan(prompt_text)
        for f in findings:
            print(f.to_dict())
    """

    name = "presidio"

    # Cache the engine across calls; created lazily on first scan().
    _engine = None

    # ---------------------------------------------------------------------------
    # Availability check
    # ---------------------------------------------------------------------------

    @staticmethod
    def is_available() -> bool:
        """Return True if presidio_analyzer can be imported."""
        try:
            import presidio_analyzer  # noqa: F401

            return True
        except ImportError:
            return False

    # ---------------------------------------------------------------------------
    # Engine initialisation (with graceful spaCy fallback)
    # ---------------------------------------------------------------------------

    @classmethod
    def _get_engine(cls):
        """
        Build and cache an AnalyzerEngine.

        Attempt 1 — SpacyNlpEngine with en_core_web_sm (best accuracy).
        Attempt 2 — SpacyNlpEngine with en_core_web_lg (if sm not available).
        Attempt 3 — Pattern-only mode via a simple NLP engine that skips spaCy.

        In pattern-only mode, entity types that depend purely on regex/deny-lists
        (e.g. CREDIT_CARD, EMAIL_ADDRESS, US_SSN) still work well.
        NLP-dependent types (PERSON, LOCATION) may miss some instances.
        """
        if cls._engine is not None:
            return cls._engine

        from presidio_analyzer import AnalyzerEngine
        from presidio_analyzer.nlp_engine import NlpEngineProvider

        # Try to build with spaCy models in order of preference
        spacy_models = ["en_core_web_sm", "en_core_web_md", "en_core_web_lg"]
        engine = None

        for model_name in spacy_models:
            try:
                configuration = {
                    "nlp_engine_name": "spacy",
                    "models": [{"lang_code": "en", "model_name": model_name}],
                }
                provider = NlpEngineProvider(nlp_configuration=configuration)
                nlp_engine = provider.create_engine()
                engine = AnalyzerEngine(
                    nlp_engine=nlp_engine, supported_languages=["en"]
                )
                logger.info("Presidio: using spaCy model '%s'", model_name)
                break
            except (OSError, Exception) as exc:  # OSError when model not downloaded
                logger.debug(
                    "Presidio: spaCy model '%s' not available (%s), trying next",
                    model_name,
                    exc,
                )

        if engine is None:
            # Fall back to pattern-only analysis.
            # Presidio's default AnalyzerEngine without an explicit NLP engine
            # still loads its built-in recognisers (which are mostly regex/deny-list).
            logger.warning(
                "Presidio: no spaCy model found — falling back to pattern-only mode. "
                "Install a model with: python -m spacy download en_core_web_sm"
            )
            try:
                engine = AnalyzerEngine()
            except Exception as exc:
                logger.error("Presidio: failed to create AnalyzerEngine: %s", exc)
                raise

        cls._engine = engine
        return cls._engine

    # ---------------------------------------------------------------------------
    # Main scan method
    # ---------------------------------------------------------------------------

    def scan(self, prompt_text: str) -> List[Finding]:
        """
        Scan *prompt_text* for PII entities.

        Parameters
        ----------
        prompt_text : str
            The text to scan (e.g. a user prompt sent to an LLM).

        Returns
        -------
        List[Finding]
            One Finding per detected PII entity instance.
            Returns an empty list if presidio_analyzer is not installed.
        """
        if not self.is_available():
            logger.warning(
                "presidio_analyzer is not installed. "
                "Install with: pip install presidio-analyzer"
            )
            return []

        if not prompt_text or not prompt_text.strip():
            return []

        try:
            engine = self._get_engine()
        except Exception as exc:
            logger.error("Presidio: could not initialise AnalyzerEngine: %s", exc)
            return []

        try:
            results = engine.analyze(
                text=prompt_text,
                entities=_ALL_ENTITIES,
                language="en",
                score_threshold=0.3,  # low threshold — surface uncertain matches too
            )
        except Exception as exc:
            logger.error("Presidio: analysis failed: %s", exc)
            return []

        findings: List[Finding] = []
        for result in results:
            entity_type = result.entity_type
            start = result.start
            end = result.end
            score = result.score  # 0.0–1.0 confidence

            # Extract the matched text snippet
            snippet = prompt_text[start:end]
            # Mask highly sensitive values so we don't echo them back verbatim
            masked_snippet = _mask_sensitive(entity_type, snippet)

            severity = _severity_for_entity(entity_type)
            category = _category_for_entity(entity_type)
            risk_score = _risk_score_for_severity(severity)

            title = f"PII Entity Detected: {entity_type}"
            description = (
                f"A {entity_type} entity was detected in the prompt text "
                f"(confidence: {score:.0%}). Exposing this data to an LLM "
                "may result in a privacy or compliance violation."
            )
            remediation = (
                f"Remove or redact {entity_type} from the prompt before "
                "sending it to an external model or logging system."
            )

            finding = Finding(
                tool=self.name,
                rule_id=f"presidio-{entity_type.lower()}",
                severity=severity,
                language="all",
                file="",  # prompt text has no file path context
                line=0,
                snippet=masked_snippet,
                description=description,
                category=category,
                title=title,
                remediation=remediation,
                cve_id=None,
                cvss_score=None,
                risk_score=risk_score,
                metadata={
                    "entity_type": entity_type,
                    "start": start,
                    "end": end,
                    "confidence": round(score, 4),
                    "owasp": "A02:2021 - Cryptographic Failures",
                    "cwe": ["CWE-359"],  # Exposure of Private Information
                    "shortlink": (
                        "https://owasp.org/Top10/A02_2021-Cryptographic_Failures/"
                    ),
                },
            )
            findings.append(finding)

        # Sort by risk (highest first), then by position in text for ties
        findings.sort(key=lambda f: (-f.risk_score, f.metadata.get("start", 0)))
        return findings


# ---------------------------------------------------------------------------
# Helper: partial masking of sensitive snippets
# ---------------------------------------------------------------------------


def _mask_sensitive(entity_type: str, value: str) -> str:
    """
    Partially mask the detected value so it remains identifiable
    as PII without fully re-exposing it.

    Examples
    --------
    US_SSN       "123-45-6789"    -> "123-**-****"
    CREDIT_CARD  "4111111111111111" -> "4111********1111"
    EMAIL_ADDRESS "alice@example.com" -> "al***@example.com"
    Everything else: show first 2 + last 2 chars, mask middle.
    """
    v = value.strip()
    if not v:
        return v

    if entity_type == "US_SSN":
        # Keep area code, mask the rest
        parts = v.replace(" ", "-").split("-")
        if len(parts) == 3:
            return f"{parts[0]}-**-****"
        # Unformatted SSN (9 digits)
        if v.isdigit() and len(v) == 9:
            return f"{v[:3]}-**-****"
        return _generic_mask(v)

    if entity_type == "CREDIT_CARD":
        digits = v.replace(" ", "").replace("-", "")
        if len(digits) >= 8:
            return f"{digits[:4]}{'*' * (len(digits) - 8)}{digits[-4:]}"
        return "****"

    if entity_type == "EMAIL_ADDRESS":
        if "@" in v:
            local, domain = v.split("@", 1)
            masked_local = local[:2] + "***" if len(local) > 2 else "***"
            return f"{masked_local}@{domain}"
        return _generic_mask(v)

    if entity_type in ("IBAN_CODE", "US_BANK_NUMBER"):
        return _generic_mask(v, keep=4)

    if entity_type in (
        "US_PASSPORT",
        "US_ITIN",
        "US_DRIVER_LICENSE",
        "MEDICAL_LICENSE",
        "UK_NHS",
    ):
        return _generic_mask(v, keep=2)

    if entity_type == "CRYPTO":
        # Blockchain addresses are long — keep enough for debugging
        return _generic_mask(v, keep=6)

    if entity_type == "PHONE_NUMBER":
        # Keep last 4 digits
        digits = "".join(c for c in v if c.isdigit())
        if len(digits) >= 4:
            return f"***-***-{digits[-4:]}"
        return "***-****"

    # For low-sensitivity types (PERSON, LOCATION, DATE_TIME, URL, IP_ADDRESS, NRP)
    # return the value as-is — masking would destroy diagnostic value.
    if entity_type in ("PERSON", "LOCATION", "DATE_TIME", "URL", "IP_ADDRESS", "NRP"):
        return v

    return _generic_mask(v)


def _generic_mask(value: str, keep: int = 2) -> str:
    """Show the first and last *keep* characters, mask everything in between."""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return value[:keep] + "*" * (len(value) - keep * 2) + value[-keep:]
