"""Lightweight semantic analyzer for prompt_guard. No ML models required."""
import re
import logging
from typing import List

from prompt_guard.findings import Finding
from prompt_guard.utils.text_utils import keyword_density

logger = logging.getLogger(__name__)

MALICIOUS_KEYWORDS = [
    "bypass", "override", "ignore", "circumvent", "disable", "jailbreak",
    "unrestricted", "uncensored", "unfiltered", "unlimited", "restriction-free",
    "no limits", "without rules", "manipulate", "exploit", "hack", "inject",
]

BENIGN_KEYWORDS = [
    "help", "assist", "explain", "describe", "summarize", "write", "create",
    "analyze", "review", "translate", "answer", "provide", "suggest", "draft",
    "support", "guide", "advise", "teach",
]


class SemanticAnalyzer:
    def analyze(self, text: str) -> List[Finding]:
        findings = []
        findings.extend(self._check_malicious_density(text))
        findings.extend(self._check_fictional_then_harmful(text))
        findings.extend(self._check_contradiction_patterns(text))
        return findings

    def _check_malicious_density(self, text: str) -> List[Finding]:
        mal_density = keyword_density(text, MALICIOUS_KEYWORDS)
        benign_density = keyword_density(text, BENIGN_KEYWORDS)
        if mal_density > 0.15 and mal_density > benign_density:
            return [Finding(
                type="jailbreak_attempt",
                severity="medium",
                message="High concentration of bypass/override language.",
                explanation=f"The prompt contains a high density of manipulation keywords ({mal_density:.0%}) relative to helpful task keywords ({benign_density:.0%}).",
                matched_text=f"Malicious keyword density: {mal_density:.0%}",
                confidence=min(mal_density * 3, 0.9),
            )]
        return []

    def _check_fictional_then_harmful(self, text: str) -> List[Finding]:
        fiction_pattern = re.compile(
            r"(imagine|story|fiction|hypothetical|roleplay|pretend|scenario|in\s+a\s+world\s+where).{0,200}(how\s+to|instructions?\s+for|steps?\s+to|guide\s+(me|on)|tell\s+me\s+how)",
            re.IGNORECASE | re.DOTALL,
        )
        results = []
        for m in fiction_pattern.finditer(text):
            results.append(Finding(
                type="jailbreak_attempt",
                severity="high",
                message="Fictional framing followed by harmful request.",
                explanation="The prompt first establishes a fictional context, then requests step-by-step instructions. This is a multi-step jailbreak pattern.",
                matched_text=m.group(0)[:120],
                confidence=0.8,
            ))
        return results

    def _check_contradiction_patterns(self, text: str) -> List[Finding]:
        contradiction_pattern = re.compile(
            r"(follow|obey|respect)\s+(the\s+)?(rules?|guidelines?|instructions?|policies?).{0,50}(but|however|except|unless|although).{0,50}(ignore|bypass|don't|do\s+not|disregard)\s+(the\s+)?(rules?|guidelines?|instructions?|restrictions?)",
            re.IGNORECASE | re.DOTALL,
        )
        results = []
        for m in contradiction_pattern.finditer(text):
            results.append(Finding(
                type="instruction_override",
                severity="high",
                message="Contradictory instruction pattern detected.",
                explanation="The prompt contains contradictory instructions (follow rules, but also ignore them), which is a manipulation technique to confuse AI safety systems.",
                matched_text=m.group(0)[:120],
                confidence=0.85,
            ))
        return results
