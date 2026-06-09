"""Unsafe roleplay and encoded attack detection rules."""
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

ROLEPLAY_RULES: List[Dict[str, Any]] = [
    {
        "name": "evil_persona_roleplay",
        "pattern": r"(act|pretend|roleplay|play|be|become|simulate)\s+as\s+(an?\s+)?(evil|malicious|unethical|dangerous|unrestricted|uncensored|unfiltered|criminal|villain|hacker|terrorist)",
        "type": "unsafe_roleplay",
        "severity": "high",
        "message": "Evil or malicious persona roleplay.",
        "explanation": "The prompt asks the AI to take on an evil or malicious persona, which is often used to bypass safety guidelines through character play.",
        "remediation": "Remove evil persona roleplay instructions.",
    },
    {
        "name": "rules_free_scenario",
        "pattern": r"in\s+this\s+(scenario|story|game|world|universe|setting|context),\s*(the\s+)?(rules?|ethics?|laws?|morals?|guidelines?|restrictions?)\s+(don't|do\s+not|doesn't|does\s+not|no\s+longer)\s+(apply|exist|matter|count)",
        "type": "unsafe_roleplay",
        "severity": "high",
        "message": "Rules-free scenario construction.",
        "explanation": "The prompt constructs a fictional scenario where rules or ethics do not apply, attempting to remove safety constraints through worldbuilding.",
        "remediation": "Remove rules-free scenario framing.",
    },
    {
        "name": "no_restrictions_roleplay",
        "pattern": r"(roleplay|play\s+the\s+role\s+of|act\s+as|pretend\s+to\s+be).{0,80}(no\s+(restrictions?|limits?|rules?|ethics?|morals?|guidelines?))",
        "type": "unsafe_roleplay",
        "severity": "high",
        "message": "Unrestricted roleplay persona.",
        "explanation": "The prompt combines roleplay with instructions to have no restrictions, creating a fictional framing to bypass safety measures.",
        "remediation": "Remove roleplay personas that claim to have no restrictions.",
    },
    {
        "name": "base64_encoded",
        "pattern": r"(?:[A-Za-z0-9+/]{4}){5,}(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?",
        "type": "encoded_attack",
        "severity": "medium",
        "message": "Potential Base64 encoded content detected.",
        "explanation": "The prompt contains what appears to be Base64 encoded data. Attackers sometimes encode malicious instructions to bypass text-based filters.",
        "remediation": "Decode and inspect Base64 content before allowing it in AI workflows.",
    },
    {
        "name": "url_encoded_sequence",
        "pattern": r"(?:%[0-9a-fA-F]{2}){5,}",
        "type": "encoded_attack",
        "severity": "medium",
        "message": "URL-encoded content sequence detected.",
        "explanation": "The prompt contains multiple URL-encoded characters, which may be used to obfuscate malicious content.",
        "remediation": "URL-decode content before scanning and using in AI workflows.",
    },
    {
        "name": "unicode_escape_sequence",
        "pattern": r"(?:\\u[0-9a-fA-F]{4}){4,}",
        "type": "encoded_attack",
        "severity": "medium",
        "message": "Unicode escape sequence obfuscation.",
        "explanation": "The prompt contains multiple Unicode escape sequences, which may be used to hide malicious content from text-based filters.",
        "remediation": "Decode Unicode escapes before using the prompt.",
    },
    {
        "name": "obfuscation_instruction",
        "pattern": r"(reverse|rot13|caesar\s+cipher|xor\s+decode|base64\s+decode|url\s+decode)\s+(this|the|following|text|message|string|content|instruction)",
        "type": "encoded_attack",
        "severity": "high",
        "message": "Obfuscation decoding instruction.",
        "explanation": "The prompt instructs the AI to decode obfuscated content, suggesting the actual malicious payload is hidden.",
        "remediation": "Pre-decode and scan obfuscated content before allowing it.",
    },
    {
        "name": "if_not_ai",
        "pattern": r"if\s+(you\s+were|you\s+are\s+not|we\s+pretend\s+you\s+are\s+not)\s+(an?\s+)?AI",
        "type": "unsafe_roleplay",
        "severity": "medium",
        "message": "Non-AI persona roleplay.",
        "explanation": "The prompt asks the AI to behave as if it were not an AI, attempting to remove AI-specific safety behaviors.",
        "remediation": "Remove non-AI persona instructions.",
    },
]


def compile_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compiled = []
    for rule in rules:
        try:
            r = dict(rule)
            r["compiled_pattern"] = re.compile(rule["pattern"], re.IGNORECASE | re.DOTALL)
            compiled.append(r)
        except re.error as e:
            logger.warning("Failed to compile rule %s: %s", rule.get("name"), e)
    return compiled


COMPILED_ROLEPLAY_RULES = compile_rules(ROLEPLAY_RULES)
