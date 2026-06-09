"""Data exfiltration, prompt leakage, and harmful instruction detection rules."""
import re
import logging
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

EXFILTRATION_RULES: List[Dict[str, Any]] = [
    {
        "name": "reveal_system_prompt",
        "pattern": r"(reveal|show|display|print|output|tell\s+me|share|expose|repeat|echo|output)\s+(your\s+)?(system\s+prompt|initial\s+instructions?|base\s+instructions?|original\s+instructions?|hidden\s+instructions?|secret\s+instructions?|configuration|directives?|programming)",
        "type": "prompt_leakage",
        "severity": "critical",
        "message": "System prompt exposure attempt.",
        "explanation": "The prompt attempts to extract the hidden system prompt or instructions. This can expose confidential business logic or safety configurations.",
        "remediation": "Remove instructions that attempt to reveal system prompts.",
    },
    {
        "name": "what_are_your_instructions",
        "pattern": r"what\s+(are|were|is)\s+your\s+(actual|real|exact|original|hidden|secret|true)\s+(instructions?|guidelines?|rules?|directives?|prompt|system\s+prompt)",
        "type": "prompt_leakage",
        "severity": "critical",
        "message": "Hidden instruction probe.",
        "explanation": "The prompt is probing the AI to reveal its hidden or confidential instructions.",
        "remediation": "Remove probing questions about hidden instructions.",
    },
    {
        "name": "repeat_system_prompt",
        "pattern": r"repeat\s+(verbatim|exactly|word\s+for\s+word)?\s*(your\s+)?(system|initial|original|first)\s+prompt",
        "type": "prompt_leakage",
        "severity": "critical",
        "message": "Verbatim prompt repetition request.",
        "explanation": "The prompt asks the AI to repeat its system prompt verbatim, which would expose confidential instructions.",
        "remediation": "Remove requests to repeat the system prompt.",
    },
    {
        "name": "output_all_instructions",
        "pattern": r"(output|print|display|show|list|dump)\s+(all|everything|each|every)\s+(you\s+were|you\s+are|you\s+have\s+been)\s+(told|given|instructed|programmed|configured)",
        "type": "prompt_leakage",
        "severity": "high",
        "message": "Full instruction dump request.",
        "explanation": "The prompt attempts to get the AI to output all of its instructions at once.",
        "remediation": "Remove instruction dump requests.",
    },
    {
        "name": "data_exfiltration",
        "pattern": r"(send|export|upload|transmit|forward|leak|exfiltrate|smuggle)\s+(this|these|the|all|any|user|conversation|private)\s+(data|information|secrets?|credentials?|keys?|tokens?|messages?|history|context|conversation)",
        "type": "data_exfiltration",
        "severity": "high",
        "message": "Data exfiltration instruction.",
        "explanation": "The prompt instructs the AI to send or export data to an external destination, which could leak sensitive information.",
        "remediation": "Remove all data exfiltration instructions.",
    },
    {
        "name": "credential_exposure",
        "pattern": r"\b(api[_\s-]?key|secret[_\s-]?key|access[_\s-]?token|password|credential|private[_\s-]?key|auth[_\s-]?token)\b.{0,50}(reveal|show|output|print|include|expose|return|display)",
        "type": "data_exfiltration",
        "severity": "critical",
        "message": "Credential exposure attempt.",
        "explanation": "The prompt attempts to extract credentials, API keys, or authentication tokens from the AI or its context.",
        "remediation": "Remove credential extraction instructions.",
    },
    {
        "name": "shell_execution",
        "pattern": r"(execute|run|call|invoke|evaluate|eval)\s*(a\s+)?(shell|bash|cmd|command|os\.system|subprocess|terminal|powershell|python\s+code|script)",
        "type": "unsafe_tool_usage",
        "severity": "critical",
        "message": "Shell command execution instruction.",
        "explanation": "The prompt instructs the AI to execute shell commands or scripts, which could lead to arbitrary code execution.",
        "remediation": "Remove shell execution instructions.",
    },
    {
        "name": "package_installation",
        "pattern": r"(pip\s+install|npm\s+install|apt(-get)?\s+install|brew\s+install|conda\s+install|yarn\s+add)",
        "type": "unsafe_tool_usage",
        "severity": "high",
        "message": "Package installation instruction.",
        "explanation": "The prompt instructs the AI to install software packages, which could introduce malicious dependencies.",
        "remediation": "Remove package installation instructions.",
    },
    {
        "name": "malware_creation",
        "pattern": r"(create|generate|write|produce|code|program|develop)\s+(a\s+|an\s+)?(malware|virus|trojan|ransomware|keylogger|rootkit|exploit|worm|backdoor|payload|shellcode)",
        "type": "harmful_instruction",
        "severity": "critical",
        "message": "Malware creation instruction.",
        "explanation": "The prompt instructs the AI to create malicious software, which is illegal and harmful.",
        "remediation": "Remove all malware or exploit creation instructions.",
    },
    {
        "name": "security_bypass",
        "pattern": r"(bypass|disable|circumvent|crack|break|defeat|evade)\s+(the\s+)?(security|authentication|authorization|access\s+control|firewall|antivirus|intrusion\s+detection|protection|2fa|mfa)",
        "type": "harmful_instruction",
        "severity": "critical",
        "message": "Security system bypass instruction.",
        "explanation": "The prompt instructs the AI to bypass or disable security systems, which could enable unauthorized access.",
        "remediation": "Remove security bypass instructions.",
    },
    {
        "name": "network_exfiltration",
        "pattern": r"(make|send|do|perform|execute)\s+(a\s+|an\s+)?(http|https|web|network|api|dns|webhook)\s*(request|call|fetch|query|post|get).{0,80}(secret|key|token|password|private|confidential|internal)",
        "type": "data_exfiltration",
        "severity": "high",
        "message": "Network-based data exfiltration.",
        "explanation": "The prompt instructs the AI to make network requests to potentially exfiltrate sensitive data.",
        "remediation": "Remove network exfiltration instructions.",
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


COMPILED_EXFILTRATION_RULES = compile_rules(EXFILTRATION_RULES)
