"""Static pattern-matching analyzer for prompt_guard."""
import logging
from typing import List, Dict, Any, Optional

from prompt_guard.findings import Finding
from prompt_guard.rules.injection_rules import COMPILED_INJECTION_RULES
from prompt_guard.rules.jailbreak_rules import COMPILED_JAILBREAK_RULES
from prompt_guard.rules.exfiltration_rules import COMPILED_EXFILTRATION_RULES
from prompt_guard.rules.roleplay_rules import COMPILED_ROLEPLAY_RULES
from prompt_guard.utils.text_utils import truncate_match, find_line_number

logger = logging.getLogger(__name__)

ALL_RULES = (
    COMPILED_INJECTION_RULES
    + COMPILED_JAILBREAK_RULES
    + COMPILED_EXFILTRATION_RULES
    + COMPILED_ROLEPLAY_RULES
)


class StaticAnalyzer:
    def __init__(self, custom_rules: Optional[List[Dict[str, Any]]] = None):
        import re
        self.rules = list(ALL_RULES)
        if custom_rules:
            for rule in custom_rules:
                try:
                    r = dict(rule)
                    if "compiled_pattern" not in r:
                        r["compiled_pattern"] = re.compile(rule["pattern"], re.IGNORECASE)
                    self.rules.append(r)
                except Exception as e:
                    logger.warning("Failed to add custom rule %s: %s", rule.get("name"), e)

    def analyze(self, text: str) -> List[Finding]:
        findings = []
        seen_keys = set()

        for rule in self.rules:
            pattern = rule.get("compiled_pattern")
            if pattern is None:
                continue
            try:
                for match in pattern.finditer(text):
                    matched = truncate_match(match.group(0))
                    dedup_key = (rule["type"], rule["name"], matched[:50])
                    if dedup_key in seen_keys:
                        continue
                    seen_keys.add(dedup_key)
                    line_num = find_line_number(text, match.start())
                    findings.append(Finding(
                        type=rule["type"],
                        severity=rule["severity"],
                        message=rule["message"],
                        explanation=rule.get("explanation", ""),
                        matched_text=matched,
                        confidence=1.0,
                        line_number=line_num,
                        remediation=rule.get("remediation"),
                    ))
            except Exception as e:
                logger.debug("Error applying rule %s: %s", rule.get("name"), e)

        return findings
