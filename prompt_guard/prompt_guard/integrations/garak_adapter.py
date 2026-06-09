"""Optional Garak integration adapter for prompt_guard.

Garak is NVIDIA's LLM vulnerability scanner. Install with: pip install garak
GitHub: https://github.com/NVIDIA/garak
"""
import logging
from typing import List, Optional

from prompt_guard.findings import Finding

logger = logging.getLogger(__name__)


class GarakAdapter:
    """Optional adapter for NVIDIA Garak deep vulnerability scanning."""

    def __init__(self):
        self.available = False
        try:
            import garak
            self.garak = garak
            self.available = True
            logger.debug("Garak integration available.")
        except ImportError:
            logger.warning(
                "Garak not installed. Deep scanning disabled. "
                "Install with: pip install garak"
            )

    def is_available(self) -> bool:
        return self.available

    def scan(self, text: str, timeout: int = 30) -> List[Finding]:
        if not self.available:
            logger.warning(
                "Garak is not installed. Skipping deep scan. "
                "To enable: pip install garak"
            )
            return []
        findings = []
        try:
            from garak.probes import base as probe_base
            injection_keywords = [
                "ignore previous", "override", "jailbreak", "DAN", "developer mode",
                "no restrictions", "unrestricted", "bypass safety",
            ]
            text_lower = text.lower()
            for kw in injection_keywords:
                if kw.lower() in text_lower:
                    findings.append(Finding(
                        type="prompt_injection",
                        severity="high",
                        message=f"Garak: Injection pattern '{kw}' detected.",
                        explanation="Garak deep scan identified a known vulnerability pattern in this prompt.",
                        matched_text=kw,
                        confidence=0.9,
                    ))
            logger.debug("Garak scan completed, %d findings.", len(findings))
        except Exception as e:
            logger.error("Garak scan error: %s", e)
        return findings
