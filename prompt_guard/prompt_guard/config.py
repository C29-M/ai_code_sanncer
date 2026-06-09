"""Configuration for prompt_guard scanning."""
from dataclasses import dataclass, field
from typing import List, Dict, Any


@dataclass
class ScanConfig:
    deep_scan: bool = False
    enable_garak: bool = False
    enable_guardrails: bool = False
    enable_nemo: bool = False
    risk_threshold: float = 5.0
    custom_rules: List[Dict[str, Any]] = field(default_factory=list)
    timeout: int = 30
    max_findings: int = 100


DEFAULT_CONFIG = ScanConfig()

RISK_THRESHOLD_MAP = {
    "low": 2.5,
    "medium": 5.0,
    "high": 7.5,
    "critical": 10.0,
}
