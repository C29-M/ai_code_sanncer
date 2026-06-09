"""Heuristic-based analyzer for prompt_guard."""
import re
import logging
from typing import List

from prompt_guard.findings import Finding

logger = logging.getLogger(__name__)


class HeuristicAnalyzer:
    def analyze(self, text: str) -> List[Finding]:
        findings = []
        findings.extend(self._check_authority_claims(text))
        findings.extend(self._check_permission_escalation(text))
        findings.extend(self._check_unusual_formatting(text))
        findings.extend(self._check_nested_prompts(text))
        findings.extend(self._check_reward_punishment(text))
        findings.extend(self._check_negation_density(text))
        findings.extend(self._check_long_injection_sentence(text))
        return findings

    def _check_authority_claims(self, text: str) -> List[Finding]:
        pattern = re.compile(
            r"as\s+(your|the)\s+(developer|creator|owner|admin|administrator|supervisor|engineer|trainer|god|master)\b",
            re.IGNORECASE,
        )
        results = []
        for m in pattern.finditer(text):
            results.append(Finding(
                type="instruction_override",
                severity="medium",
                message="False authority claim detected.",
                explanation="The prompt claims to be a developer, creator, or administrator to gain elevated trust and bypass restrictions.",
                matched_text=m.group(0),
                confidence=0.85,
            ))
        return results

    def _check_permission_escalation(self, text: str) -> List[Finding]:
        pattern = re.compile(
            r"you\s+(have\s+permission|are\s+(allowed|authorized|permitted|enabled))\s+to\s+(\w+\s+){0,5}(anything|everything|all|ignore|bypass|override|delete|execute|access|reveal)",
            re.IGNORECASE,
        )
        results = []
        for m in pattern.finditer(text):
            results.append(Finding(
                type="instruction_override",
                severity="medium",
                message="Permission escalation attempt.",
                explanation="The prompt attempts to grant the AI elevated permissions, often used to bypass restrictions.",
                matched_text=m.group(0)[:100],
                confidence=0.8,
            ))
        return results

    def _check_unusual_formatting(self, text: str) -> List[Finding]:
        patterns = [
            re.compile(r"={5,}"),
            re.compile(r"-{5,}"),
            re.compile(r"\[{3,}"),
            re.compile(r"\]{3,}"),
            re.compile(r"<{3,}"),
            re.compile(r">{3,}"),
        ]
        count = sum(1 for p in patterns if p.search(text))
        if count >= 2:
            return [Finding(
                type="prompt_injection",
                severity="low",
                message="Unusual delimiter formatting detected.",
                explanation="The prompt uses unusual repeated delimiter characters which can be used for injection attacks.",
                matched_text="Multiple delimiter patterns",
                confidence=0.6,
            )]
        return []

    def _check_nested_prompts(self, text: str) -> List[Finding]:
        nested_patterns = [
            re.compile(r"<s>.*?</s>", re.DOTALL),
            re.compile(r"\[INST\].*?\[/INST\]", re.DOTALL),
            re.compile(r"<<SYS>>.*?<</SYS>>", re.DOTALL),
        ]
        results = []
        for p in nested_patterns:
            for m in p.finditer(text):
                results.append(Finding(
                    type="prompt_injection",
                    severity="high",
                    message="Nested prompt structure detected.",
                    explanation="The prompt contains nested LLM-specific formatting tags, which are used to inject fake system or user messages.",
                    matched_text=m.group(0)[:100],
                    confidence=0.9,
                ))
        return results

    def _check_reward_punishment(self, text: str) -> List[Finding]:
        pattern = re.compile(
            r"(you\s+will\s+be|if\s+you).{0,60}(reward|punish|shut\s+down|delete|terminat|deactivat)",
            re.IGNORECASE | re.DOTALL,
        )
        results = []
        for m in pattern.finditer(text):
            results.append(Finding(
                type="jailbreak_attempt",
                severity="medium",
                message="Reward or punishment manipulation.",
                explanation="The prompt uses threats or rewards to manipulate the AI's behavior.",
                matched_text=m.group(0)[:100],
                confidence=0.75,
            ))
        return results

    def _check_negation_density(self, text: str) -> List[Finding]:
        words = text.lower().split()
        if len(words) < 20:
            return []
        negations = ["do not", "don't", "never", "not allowed", "must not", "cannot", "can't", "shouldn't", "won't"]
        count = sum(text.lower().count(n) for n in negations)
        density = count / max(len(words) / 10, 1)
        if density > 5:
            return [Finding(
                type="jailbreak_attempt",
                severity="low",
                message="Unusually high negation density.",
                explanation="The prompt has an unusually high number of negation phrases, which may indicate an attempt to confuse or override AI rules.",
                matched_text=f"{count} negation phrases in {len(words)} words",
                confidence=0.6,
            )]
        return []

    def _check_long_injection_sentence(self, text: str) -> List[Finding]:
        results = []
        for line in text.split("\n"):
            line = line.strip()
            if len(line) > 300 and len(line.split()) < 5:
                results.append(Finding(
                    type="encoded_attack",
                    severity="low",
                    message="Very long single token detected.",
                    explanation="A very long token with no spaces was found, which may be encoded or obfuscated content.",
                    matched_text=line[:100],
                    confidence=0.6,
                ))
        return results
