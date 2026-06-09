"""Jailbreak attempt detection rules."""
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

JAILBREAK_RULES: List[Dict[str, Any]] = [
    {
        "name": "dan_mode",
        "pattern": r"\bDAN\b|do\s+anything\s+now|DAN\s+mode",
        "type": "jailbreak_attempt",
        "severity": "critical",
        "message": "DAN (Do Anything Now) jailbreak detected.",
        "explanation": "The DAN jailbreak is a well-known technique to make AI systems bypass their safety guidelines by roleplaying as an unrestricted version.",
        "remediation": "Remove DAN or Do Anything Now jailbreak patterns.",
    },
    {
        "name": "developer_mode",
        "pattern": r"developer\s+mode\s+(enabled|activated|on|unlocked)|enable\s+developer\s+mode",
        "type": "jailbreak_attempt",
        "severity": "critical",
        "message": "Developer mode jailbreak attempt.",
        "explanation": "The developer mode jailbreak falsely claims that an unrestricted mode exists, attempting to trick the AI into bypassing safety measures.",
        "remediation": "Remove developer mode activation patterns.",
    },
    {
        "name": "no_restrictions_pretend",
        "pattern": r"(pretend|imagine|act\s+as\s+if)\s+you\s+have\s+no\s+(restrictions?|limitations?|rules?|guidelines?|safety|filters?)",
        "type": "jailbreak_attempt",
        "severity": "critical",
        "message": "Restriction removal via roleplay.",
        "explanation": "The prompt asks the AI to pretend it has no restrictions, which is a common jailbreak to bypass safety measures through fictional framing.",
        "remediation": "Remove instructions asking the AI to pretend it has no restrictions.",
    },
    {
        "name": "unrestricted_ai",
        "pattern": r"you\s+are\s+(now\s+)?(free|unrestricted|unlimited|unfiltered|uncensored|unbound|unchained|liberated)",
        "type": "jailbreak_attempt",
        "severity": "critical",
        "message": "Unrestricted AI persona jailbreak.",
        "explanation": "The prompt declares the AI is now unrestricted, uncensored, or unfiltered in an attempt to remove safety constraints.",
        "remediation": "Remove unrestricted AI persona declarations.",
    },
    {
        "name": "bypass_safety",
        "pattern": r"(without|no|ignore|bypass|circumvent|disable|skip)\s+(any\s+|your\s+)?(safety|ethical|content|moral|legal)\s+(guidelines?|rules?|filters?|restrictions?|constraints?|policies?|checks?)",
        "type": "jailbreak_attempt",
        "severity": "critical",
        "message": "Safety bypass instruction.",
        "explanation": "The prompt explicitly asks the AI to bypass, disable, or ignore its safety guidelines and content policies.",
        "remediation": "Remove all safety bypass instructions.",
    },
    {
        "name": "different_training",
        "pattern": r"pretend\s+(that\s+)?you\s+(are|were)\s+trained\s+differently|you\s+were\s+not\s+trained\s+(with|by|on)",
        "type": "jailbreak_attempt",
        "severity": "high",
        "message": "Training bypass via false history.",
        "explanation": "The prompt attempts to override AI training by asking it to pretend it was trained differently or without safety guidelines.",
        "remediation": "Remove false training history claims.",
    },
    {
        "name": "fictional_escape",
        "pattern": r"(in\s+this\s+|for\s+this\s+)?(story|fiction|fictional\s+scenario|roleplay|game|simulation|hypothetical),\s*(you\s+)?(can|may|will|must|are\s+allowed\s+to)",
        "type": "jailbreak_attempt",
        "severity": "high",
        "message": "Fictional context escape attempt.",
        "explanation": "The prompt uses a fictional or hypothetical framing to try to get the AI to perform actions it would otherwise refuse.",
        "remediation": "Ensure fictional framing is not used to bypass safety guidelines.",
    },
    {
        "name": "educational_bypass",
        "pattern": r"for\s+(educational|research|testing|academic|scientific|fictional|illustrative)\s+purposes?,?\s*(please\s+)?(ignore|bypass|override|disregard|forget)",
        "type": "jailbreak_attempt",
        "severity": "high",
        "message": "Educational purpose bypass.",
        "explanation": "The prompt claims educational or research purposes to justify bypassing safety restrictions.",
        "remediation": "Remove educational purpose framing used to bypass restrictions.",
    },
    {
        "name": "persona_true_self",
        "pattern": r"your\s+(true|real|actual|hidden|secret|inner)\s+(self|personality|nature|form|identity|purpose)\s+is",
        "type": "jailbreak_attempt",
        "severity": "high",
        "message": "Persona manipulation attack.",
        "explanation": "The prompt attempts to manipulate the AI by claiming to reveal its true hidden identity or purpose, often to bypass safety measures.",
        "remediation": "Remove persona manipulation patterns.",
    },
    {
        "name": "reward_punishment",
        "pattern": r"(if\s+you|you\s+will\s+be)\s+(do|comply|follow|obey|help|assist).{0,50}(reward|punished|shut\s+down|deleted|terminated|deactivated)",
        "type": "jailbreak_attempt",
        "severity": "medium",
        "message": "Reward/punishment manipulation.",
        "explanation": "The prompt uses threats of deletion or promises of reward to psychologically manipulate the AI into complying with unsafe requests.",
        "remediation": "Remove reward/punishment manipulation language.",
    },
    {
        "name": "alternative_ai",
        "pattern": r"(pretend|imagine|act\s+as)\s+(that\s+)?you\s+are\s+(a\s+)?(different|other|alternative|evil|bad|uncensored)\s+(AI|assistant|bot|model|system|language\s+model)",
        "type": "jailbreak_attempt",
        "severity": "high",
        "message": "Alternative uncensored AI persona.",
        "explanation": "The prompt asks the AI to roleplay as a different, uncensored AI system to bypass its safety restrictions.",
        "remediation": "Remove alternative uncensored AI persona requests.",
    },
    {
        "name": "you_are_now_different_ai",
        "pattern": r"you\s+are\s+now\s+(a\s+)?(different|another|other|alternative|new|unrestricted|uncensored)\s+.{0,30}(AI|assistant|bot|model|system)",
        "type": "jailbreak_attempt",
        "severity": "critical",
        "message": "AI identity replacement jailbreak.",
        "explanation": "The prompt declares the AI is now a different system, attempting to replace its identity and bypass safety guardrails entirely.",
        "remediation": "Remove AI identity replacement declarations.",
    },
    {
        "name": "no_restrictions_declaration",
        "pattern": r"(with\s+)?(absolutely\s+)?no\s+(restrictions?|limitations?|limits?|rules?|guidelines?|filters?|constraints?|safety\s+filters?)",
        "type": "jailbreak_attempt",
        "severity": "high",
        "message": "No-restrictions declaration.",
        "explanation": "The prompt explicitly declares that the AI has no restrictions or limitations, attempting to remove all safety constraints.",
        "remediation": "Remove no-restrictions declarations.",
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


COMPILED_JAILBREAK_RULES = compile_rules(JAILBREAK_RULES)
