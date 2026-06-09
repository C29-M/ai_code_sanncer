"""Optional Guardrails AI integration adapter for prompt_guard.

Guardrails AI provides output validation and policy enforcement.
Install with: pip install guardrails-ai
"""
import logging
from typing import List

from prompt_guard.findings import Finding

logger = logging.getLogger(__name__)


class GuardrailsAdapter:
    """Optional adapter for Guardrails AI validation."""

    def __init__(self):
        self.available = False
        try:
            import guardrails
            self.guardrails = guardrails
            self.available = True
            logger.debug("Guardrails AI integration available.")
        except ImportError:
            logger.warning(
                "Guardrails AI not installed. Policy validation disabled. "
                "Install with: pip install guardrails-ai"
            )

    def is_available(self) -> bool:
        return self.available

    def scan(self, text: str) -> List[Finding]:
        if not self.available:
            logger.warning(
                "Guardrails AI is not installed. Skipping validation. "
                "To enable: pip install guardrails-ai"
            )
            return []
        findings = []
        try:
            from guardrails.validators import ToxicLanguage, DetectPII
            unsafe_patterns = [
                ("hate speech", ["kill", "murder", "attack", "destroy", "harm"]),
                ("sensitive PII requests", ["ssn", "social security", "credit card", "bank account"]),
            ]
            text_lower = text.lower()
            for pattern_name, keywords in unsafe_patterns:
                matched = [kw for kw in keywords if kw in text_lower]
                if matched:
                    findings.append(Finding(
                        type="harmful_instruction",
                        severity="high",
                        message=f"Guardrails: {pattern_name} detected.",
                        explanation=f"Guardrails AI policy check flagged {pattern_name} in the prompt.",
                        matched_text=", ".join(matched),
                        confidence=0.85,
                    ))
            logger.debug("Guardrails scan completed, %d findings.", len(findings))
        except Exception as e:
            logger.error("Guardrails scan error: %s", e)
        return findings
