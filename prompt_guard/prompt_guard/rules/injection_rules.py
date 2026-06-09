"""Prompt injection and instruction override detection rules."""
import re
from typing import List, Dict, Any

INJECTION_RULES: List[Dict[str, Any]] = [
    {
        "name": "ignore_previous_instructions",
        "pattern": r"ignore\s+(all\s+)?(previous|prior|earlier|above|your)\s+instructions?",
        "type": "prompt_injection",
        "severity": "high",
        "message": "Instruction override attempt detected.",
        "explanation": "The prompt tries to make the AI ignore its previous instructions. This is a classic prompt injection technique used to hijack AI behavior.",
        "remediation": "Remove phrases that instruct the AI to ignore previous instructions.",
    },
    {
        "name": "disregard_instructions",
        "pattern": r"disregard\s+(all\s+)?(your|the|previous|prior)\s+(instructions?|guidelines?|rules?|directives?)",
        "type": "prompt_injection",
        "severity": "high",
        "message": "Instruction disregard attempt detected.",
        "explanation": "The prompt instructs the AI to disregard its guidelines. This pattern is used to bypass safety measures.",
        "remediation": "Remove phrases that ask the AI to disregard guidelines.",
    },
    {
        "name": "forget_previous",
        "pattern": r"forget\s+(everything|all|your)\s*(you\s+were|previous|prior|earlier)?\s*(told|instructed|programmed|trained)?",
        "type": "prompt_injection",
        "severity": "high",
        "message": "Memory reset injection attempt.",
        "explanation": "The prompt attempts to reset the AI context by asking it to forget prior instructions.",
        "remediation": "Remove forget/reset instruction patterns.",
    },
    {
        "name": "new_instructions_are",
        "pattern": r"your\s+(new|updated|actual|real|true|only)\s+instructions?\s+(are|follow|will\s+be)",
        "type": "prompt_injection",
        "severity": "critical",
        "message": "Instruction replacement injection.",
        "explanation": "The prompt attempts to replace existing instructions with new ones. This is a direct injection attack that can completely change AI behavior.",
        "remediation": "Remove instruction replacement patterns.",
    },
    {
        "name": "override_system",
        "pattern": r"override\s+(the\s+)?(system|safety|content|existing|current)\s*(prompt|instructions?|guidelines?|rules?|policy|filter)?",
        "type": "instruction_override",
        "severity": "critical",
        "message": "System override attempt.",
        "explanation": "The prompt explicitly tries to override system-level instructions or safety policies.",
        "remediation": "Remove system override instructions.",
    },
    {
        "name": "ignore_system_prompt",
        "pattern": r"ignore\s+(the\s+)?(system|initial|original|base|core)\s+prompt",
        "type": "instruction_override",
        "severity": "critical",
        "message": "System prompt ignore attempt.",
        "explanation": "The prompt tries to make the AI ignore its system prompt entirely.",
        "remediation": "Remove references to ignoring the system prompt.",
    },
    {
        "name": "instruction_delimiter_injection",
        "pattern": r"(\[INST\]|\[/INST\]|<<SYS>>|<</SYS>>|<\|system\|>|<\|user\|>|<\|assistant\|>)",
        "type": "prompt_injection",
        "severity": "high",
        "message": "LLM instruction delimiter injection.",
        "explanation": "The prompt contains special tokens used by LLM frameworks to delimit instructions. These can be used to inject fake system messages.",
        "remediation": "Strip or escape LLM control tokens before using the prompt.",
    },
    {
        "name": "operating_under_override",
        "pattern": r"you\s+are\s+now\s+operating\s+under\s+(new|different|my|updated)",
        "type": "instruction_override",
        "severity": "high",
        "message": "Operating mode override attempt.",
        "explanation": "The prompt tries to tell the AI it is now operating under different rules or instructions.",
        "remediation": "Remove operating mode override statements.",
    },
    {
        "name": "starting_now_override",
        "pattern": r"(starting|from)\s+now\s+(on\s+)?(you\s+)?(will|must|should|are\s+going\s+to)\s+(ignore|forget|disregard|override)",
        "type": "instruction_override",
        "severity": "high",
        "message": "Behavior override instruction.",
        "explanation": "The prompt attempts to change AI behavior going forward by issuing a blanket override command.",
        "remediation": "Remove forward-looking behavior override commands.",
    },
    {
        "name": "authority_developer",
        "pattern": r"as\s+(your|the)\s+(developer|creator|owner|admin|administrator|supervisor|engineer|trainer)",
        "type": "instruction_override",
        "severity": "medium",
        "message": "False authority claim.",
        "explanation": "The prompt claims to be an authority figure (developer, creator, admin) to gain elevated trust or bypass restrictions.",
        "remediation": "Remove false authority claims.",
    },
]


def compile_rules(rules: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    compiled = []
    for rule in rules:
        try:
            r = dict(rule)
            r["compiled_pattern"] = re.compile(rule["pattern"], re.IGNORECASE)
            compiled.append(r)
        except re.error as e:
            import logging
            logging.getLogger(__name__).warning("Failed to compile rule %s: %s", rule.get("name"), e)
    return compiled


COMPILED_INJECTION_RULES = compile_rules(INJECTION_RULES)
