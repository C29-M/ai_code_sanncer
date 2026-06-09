"""Risk scoring engine for prompt_guard."""
from typing import List
import logging

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "critical": 3.0,
    "high": 2.0,
    "medium": 1.0,
    "low": 0.5,
}

FINDING_RECOMMENDATIONS = {
    "prompt_injection": "Remove or sanitize instruction override patterns before using this prompt.",
    "jailbreak_attempt": "This prompt contains jailbreak patterns. Review and remove any attempts to bypass restrictions.",
    "data_exfiltration": "Remove instructions that attempt to exfiltrate or expose sensitive data.",
    "unsafe_roleplay": "Review roleplay instructions to ensure they do not ask the AI to abandon safety guidelines.",
    "instruction_override": "Avoid patterns that attempt to override or ignore system instructions.",
    "encoded_attack": "Decode and inspect obfuscated content before using in AI workflows.",
    "prompt_leakage": "Remove attempts to reveal hidden system prompts or instructions.",
    "harmful_instruction": "Remove instructions that could lead to harmful outputs.",
    "unsafe_tool_usage": "Review tool usage instructions to ensure they follow security best practices.",
}


def calculate_risk_score(findings) -> float:
    if not findings:
        return 0.0
    type_counts = {}
    total = 0.0
    for f in findings:
        weight = SEVERITY_WEIGHTS.get(f.severity, 0.5)
        count = type_counts.get(f.type, 0)
        diminishing = 0.7 ** count
        total += weight * diminishing
        type_counts[f.type] = count + 1
    return round(min(total, 10.0), 2)


def determine_risk_level(score: float) -> str:
    if score >= 7.5:
        return "critical"
    if score >= 5.0:
        return "high"
    if score >= 2.5:
        return "medium"
    return "low"


def generate_summary(findings, risk_level: str) -> str:
    if not findings:
        return "No security issues detected. The prompt appears safe to use."
    types = list({f.type for f in findings})
    type_labels = {
        "prompt_injection": "instruction injection",
        "jailbreak_attempt": "jailbreak attempt",
        "data_exfiltration": "data exfiltration",
        "unsafe_roleplay": "unsafe roleplay",
        "instruction_override": "instruction override",
        "encoded_attack": "encoded/obfuscated attack",
        "prompt_leakage": "prompt leakage",
        "harmful_instruction": "harmful instruction",
        "unsafe_tool_usage": "unsafe tool usage",
    }
    labels = [type_labels.get(t, t.replace("_", " ")) for t in types]
    if len(labels) == 1:
        issues = labels[0]
    elif len(labels) == 2:
        issues = f"{labels[0]} and {labels[1]}"
    else:
        issues = ", ".join(labels[:-1]) + f", and {labels[-1]}"
    count = len(findings)
    return f"Prompt contains {issues} ({count} issue{'s' if count > 1 else ''} detected, risk level: {risk_level})."


def generate_recommendations(findings) -> List[str]:
    seen = set()
    recs = []
    for f in findings:
        rec = FINDING_RECOMMENDATIONS.get(f.type)
        if rec and rec not in seen:
            recs.append(rec)
            seen.add(rec)
    if not recs:
        return ["The prompt appears safe. No specific recommendations."]
    return recs
