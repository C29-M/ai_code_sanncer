"""Main scanner module for prompt_guard - the core public API."""
import logging
import time
from typing import Optional

from prompt_guard.config import ScanConfig, DEFAULT_CONFIG
from prompt_guard.findings import Finding, ScanResult
from prompt_guard.scoring import (
    calculate_risk_score,
    determine_risk_level,
    generate_summary,
    generate_recommendations,
)
from prompt_guard.analyzers.static_analyzer import StaticAnalyzer
from prompt_guard.analyzers.heuristic_analyzer import HeuristicAnalyzer
from prompt_guard.analyzers.semantic_analyzer import SemanticAnalyzer
from prompt_guard.integrations.garak_adapter import GarakAdapter
from prompt_guard.integrations.guardrails_adapter import GuardrailsAdapter
from prompt_guard.integrations.nemo_adapter import NemoAdapter
from prompt_guard.utils.text_utils import normalize_text
from prompt_guard.utils.encoding_detector import decode_and_check, has_suspicious_encoding

logger = logging.getLogger(__name__)

__version__ = "0.1.0"


class PromptScanner:
    """Main scanner class. Orchestrates the full scanning pipeline."""

    def __init__(self, config: Optional[ScanConfig] = None):
        self.config = config or DEFAULT_CONFIG
        self.static_analyzer = StaticAnalyzer(custom_rules=self.config.custom_rules)
        self.heuristic_analyzer = HeuristicAnalyzer()
        self.semantic_analyzer = SemanticAnalyzer()
        self.garak_adapter = GarakAdapter() if self.config.enable_garak else None
        self.guardrails_adapter = GuardrailsAdapter() if self.config.enable_guardrails else None
        self.nemo_adapter = NemoAdapter() if self.config.enable_nemo else None

    def scan(self, prompt: str) -> ScanResult:
        start_time = time.time()
        logger.debug("Starting scan of prompt (%d chars)", len(prompt))

        normalized = normalize_text(prompt)
        all_findings = []

        if has_suspicious_encoding(normalized):
            logger.debug("Suspicious encoding detected, scanning decoded version too.")
            decoded = decode_and_check(normalized)
            all_findings.extend(self.static_analyzer.analyze(decoded))
            all_findings.extend(self.heuristic_analyzer.analyze(decoded))

        all_findings.extend(self.static_analyzer.analyze(normalized))
        all_findings.extend(self.heuristic_analyzer.analyze(normalized))
        all_findings.extend(self.semantic_analyzer.analyze(normalized))

        if self.config.enable_garak and self.garak_adapter:
            all_findings.extend(self.garak_adapter.scan(normalized, self.config.timeout))

        if self.config.enable_guardrails and self.guardrails_adapter:
            all_findings.extend(self.guardrails_adapter.scan(normalized))

        if self.config.enable_nemo and self.nemo_adapter:
            all_findings.extend(self.nemo_adapter.scan(normalized))

        unique_findings = _deduplicate_findings(all_findings)
        unique_findings = unique_findings[: self.config.max_findings]

        risk_score = calculate_risk_score(unique_findings)
        risk_level = determine_risk_level(risk_score)
        safe = risk_score < self.config.risk_threshold
        summary = generate_summary(unique_findings, risk_level)
        recommendations = generate_recommendations(unique_findings)

        scan_time = round(time.time() - start_time, 3)
        logger.debug("Scan complete: score=%.2f level=%s safe=%s time=%.3fs", risk_score, risk_level, safe, scan_time)

        return ScanResult(
            safe=safe,
            risk_score=risk_score,
            risk_level=risk_level,
            summary=summary,
            findings=unique_findings,
            recommendations=recommendations,
            metadata={
                "scan_time_seconds": scan_time,
                "prompt_length": len(prompt),
                "analyzer_count": 3,
                "version": __version__,
                "deep_scan": self.config.deep_scan,
            },
        )


def _deduplicate_findings(findings):
    seen = set()
    unique = []
    for f in findings:
        key = (f.type, f.matched_text[:60])
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def scan_prompt(
    prompt: str,
    deep_scan: bool = False,
    enable_garak: bool = False,
    enable_guardrails: bool = False,
    enable_nemo: bool = False,
    config: Optional[ScanConfig] = None,
) -> ScanResult:
    """Scan a system prompt for malicious or unsafe content.

    Args:
        prompt: The system prompt text to scan.
        deep_scan: Enable deep scanning (currently enables all static/heuristic/semantic passes).
        enable_garak: Enable NVIDIA Garak integration (requires: pip install garak).
        enable_guardrails: Enable Guardrails AI integration (requires: pip install guardrails-ai).
        enable_nemo: Enable NeMo Guardrails integration (requires: pip install nemoguardrails).
        config: Optional ScanConfig object. If provided, individual flags are ignored.

    Returns:
        ScanResult with safe flag, risk score, findings, and recommendations.
    """
    if config is None:
        config = ScanConfig(
            deep_scan=deep_scan,
            enable_garak=enable_garak,
            enable_guardrails=enable_guardrails,
            enable_nemo=enable_nemo,
        )
    scanner = PromptScanner(config=config)
    return scanner.scan(prompt)
