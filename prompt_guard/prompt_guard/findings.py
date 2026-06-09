"""Core data types for prompt_guard findings."""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional


class FindingType:
    PROMPT_INJECTION = "prompt_injection"
    JAILBREAK_ATTEMPT = "jailbreak_attempt"
    DATA_EXFILTRATION = "data_exfiltration"
    UNSAFE_ROLEPLAY = "unsafe_roleplay"
    INSTRUCTION_OVERRIDE = "instruction_override"
    ENCODED_ATTACK = "encoded_attack"
    PROMPT_LEAKAGE = "prompt_leakage"
    HARMFUL_INSTRUCTION = "harmful_instruction"
    UNSAFE_TOOL_USAGE = "unsafe_tool_usage"


class Severity:
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class Finding:
    type: str
    severity: str
    message: str
    explanation: str
    matched_text: str
    confidence: float = 1.0
    line_number: Optional[int] = None
    remediation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "type": self.type,
            "severity": self.severity,
            "message": self.message,
            "explanation": self.explanation,
            "matched_text": self.matched_text,
            "confidence": self.confidence,
        }


@dataclass
class ScanResult:
    safe: bool
    risk_score: float
    risk_level: str
    summary: str
    findings: List[Finding]
    recommendations: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "safe": self.safe,
            "risk_score": round(self.risk_score, 1),
            "risk_level": self.risk_level,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
            "recommendations": self.recommendations,
            "metadata": self.metadata,
        }

    def __getitem__(self, key):
        return self.to_dict()[key]

    def __contains__(self, key):
        return key in self.to_dict()
