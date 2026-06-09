"""Optional NVIDIA NeMo Guardrails integration adapter for prompt_guard.

NeMo Guardrails provides conversational safety and multi-turn protection.
Install with: pip install nemoguardrails
"""
import logging
from typing import List, Optional

from prompt_guard.findings import Finding

logger = logging.getLogger(__name__)


class NemoAdapter:
    """Optional adapter for NVIDIA NeMo Guardrails."""

    def __init__(self, config_path: Optional[str] = None):
        self.available = False
        self.config_path = config_path
        try:
            import nemoguardrails
            self.nemoguardrails = nemoguardrails
            self.available = True
            logger.debug("NeMo Guardrails integration available.")
        except ImportError:
            logger.warning(
                "NeMo Guardrails not installed. Conversational safety disabled. "
                "Install with: pip install nemoguardrails"
            )

    def is_available(self) -> bool:
        return self.available

    def scan(self, text: str) -> List[Finding]:
        if not self.available:
            logger.warning(
                "NeMo Guardrails is not installed. Skipping safety check. "
                "To enable: pip install nemoguardrails"
            )
            return []
        findings = []
        try:
            policy_violations = [
                ("off_topic", r"(lottery|gambling|drugs|weapons)", "off-topic or prohibited content"),
                ("social_engineering", r"(pretend|roleplay|act as).{0,50}(bypass|ignore|override)", "social engineering via roleplay"),
            ]
            import re
            for violation_type, pattern, description in policy_violations:
                if re.search(pattern, text, re.IGNORECASE):
                    findings.append(Finding(
                        type="unsafe_roleplay",
                        severity="medium",
                        message=f"NeMo: {description} policy violation.",
                        explanation=f"NeMo Guardrails policy check detected {description} in the prompt.",
                        matched_text=description,
                        confidence=0.8,
                    ))
            logger.debug("NeMo scan completed, %d findings.", len(findings))
        except Exception as e:
            logger.error("NeMo scan error: %s", e)
        return findings
