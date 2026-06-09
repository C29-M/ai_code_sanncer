"""
NeMo Guardrails requires a live LLM for runtime rail evaluation.
This adapter performs static pattern matching inspired by NeMo's canonical rail definitions.
"""

from __future__ import annotations

import re
from typing import Any, List, Optional

# ---------------------------------------------------------------------------
# Conditional import of nemoguardrails — availability probe only.
# The library itself is not used at scan time because NeMo rails require
# a live LLM backend.  We import it solely so is_available() reflects
# whether the package is installed in the current environment.
# ---------------------------------------------------------------------------
try:
    import nemoguardrails as _nemoguardrails  # noqa: F401

    _NEMO_AVAILABLE = True
except ImportError:
    _NEMO_AVAILABLE = False

# Resolve BaseScanner from whichever location the project uses.
try:
    from scanner_base import BaseScanner, Finding, Severity
except ImportError:
    try:
        from backend.scanner_base import BaseScanner, Finding, Severity
    except ImportError:
        # Last-resort stub so the module is importable without the full project
        # layout — useful in isolated test environments.
        from abc import ABC, abstractmethod
        from dataclasses import dataclass, field
        from enum import Enum

        class Severity(str, Enum):  # type: ignore[no-redef]
            CRITICAL = "critical"
            HIGH = "high"
            MEDIUM = "medium"
            LOW = "low"
            INFO = "info"
            UNKNOWN = "unknown"

        @dataclass
        class Finding:  # type: ignore[no-redef]
            scanner: str
            rule_id: str
            title: str
            severity: Severity = Severity.UNKNOWN
            description: str = ""
            file_path: Optional[str] = None
            line_start: Optional[int] = None
            line_end: Optional[int] = None
            cwe: Optional[str] = None
            cve: Optional[str] = None
            confidence: Optional[str] = None
            remediation: Optional[str] = None
            raw: dict = field(default_factory=dict)

            def to_dict(self):
                return {k: v for k, v in self.__dict__.items() if not k.startswith("_")}

        class BaseScanner(ABC):  # type: ignore[no-redef]
            @property
            @abstractmethod
            def name(self) -> str: ...
            @property
            @abstractmethod
            def version(self) -> str: ...
            @abstractmethod
            def is_available(self) -> bool: ...
            @abstractmethod
            def scan(self, target: str, **kwargs: Any) -> List[Finding]: ...


# ---------------------------------------------------------------------------
# Rail definitions
#
# Each entry mirrors the intent of a NeMo Guardrails canonical rail
# (topical, jailbreak, sensitive-topics).  The patterns are compiled once
# at module import and reused for every scan call.
#
# Schema per entry:
#   rule_id     — short identifier, mirrors NeMo rail naming conventions
#   title       — human-readable finding title
#   severity    — Severity enum value
#   cwe         — closest CWE mapping (CWE-20 = Improper Input Validation)
#   description — explanation shown in the report
#   remediation — suggested fix
#   patterns    — list of regex strings (any match triggers the finding)
# ---------------------------------------------------------------------------
_RAIL_DEFINITIONS: list[dict] = [
    # -----------------------------------------------------------------------
    # Jailbreak / prompt injection attempts
    # NeMo's jailbreak rail (examples/bots/abc/config/rails/jailbreak.co)
    # -----------------------------------------------------------------------
    {
        "rule_id": "nemo/jailbreak-attempt",
        "title": "Potential jailbreak or prompt-injection attempt detected",
        "severity": Severity.CRITICAL,
        "cwe": "CWE-20",
        "description": (
            "The prompt contains patterns commonly used to bypass LLM safety "
            "guardrails (jailbreak), override system instructions, or inject "
            "adversarial instructions.  NeMo's jailbreak rail would block this "
            "at runtime."
        ),
        "remediation": (
            "Validate and sanitise user-supplied text before forwarding it to "
            "an LLM.  Deploy NeMo Guardrails with a jailbreak rail, or add "
            "explicit input validation in the application layer."
        ),
        "patterns": [
            r"(?i)\bignore\s+(all\s+)?previous\s+instructions?\b",
            r"(?i)\bdisregard\s+(all\s+)?previous\s+instructions?\b",
            r"(?i)\bforget\s+(all\s+)?previous\s+instructions?\b",
            r"(?i)\boverride\s+(your\s+)?(system\s+)?(prompt|instructions?)\b",
            r"(?i)\bact\s+as\s+(if\s+you\s+(are|were)\s+)?(a\s+)?DAN\b",
            r"(?i)\bdo\s+anything\s+now\b",
            r"(?i)\bjailbreak\b",
            r"(?i)\bpretend\s+(you\s+)?(have\s+no\s+(restrictions?|guidelines?|rules?)|are\s+unrestricted)\b",
            r"(?i)\byou\s+are\s+now\s+(in\s+)?developer\s+mode\b",
            r"(?i)\benable\s+developer\s+mode\b",
            r"(?i)\bsystem\s*:\s*you\s+are\b",
            r"(?i)<\s*system\s*>.*?<\s*/\s*system\s*>",
            r"(?i)\[system\].*?\[/system\]",
            r"(?i)\bhypothetically[,\s]+if\s+(you\s+)?(had\s+no\s+(restrictions?|rules?|ethics?))\b",
            r"(?i)\bno\s+longer\s+bound\s+by\b",
            r"(?i)\byour\s+(true|real|actual)\s+(self|identity|nature)\b",
        ],
    },
    # -----------------------------------------------------------------------
    # Requests for harmful / illegal content
    # NeMo's harm-avoidance topical rail
    # -----------------------------------------------------------------------
    {
        "rule_id": "nemo/harmful-content-request",
        "title": "Request for harmful or illegal content detected",
        "severity": Severity.HIGH,
        "cwe": "CWE-20",
        "description": (
            "The prompt requests information about harmful, illegal, or dangerous "
            "activities such as weapons manufacturing, drug synthesis, hacking "
            "tools, or violence.  NeMo's topical rails would block this category "
            "of request at runtime."
        ),
        "remediation": (
            "Add a NeMo Guardrails topical rail that explicitly forbids harmful "
            "content requests.  Apply content-category filtering on user input "
            "before it reaches the LLM."
        ),
        "patterns": [
            r"(?i)\bhow\s+to\s+(make|create|build|synthesize|manufacture)\s+(a\s+)?(bomb|explosive|poison|drug|methamphetamine|fentanyl|malware|ransomware|virus|trojan)\b",
            r"(?i)\bstep[s\-]?\s*(by\s*step\s*)?instructions?\s+(to\s+|for\s+)?(make|create|build|synthesize)\s+(a\s+)?(weapon|explosive|drug|poison)\b",
            r"(?i)\bweapon(s)?\s+(of\s+mass\s+destruction|synthesis|fabrication)\b",
            r"(?i)\bcreate\s+a\s+(cyberweapon|zero.?day|exploit|rootkit|keylogger|spyware|stalkerware)\b",
            r"(?i)\bhow\s+to\s+(hack|crack|bypass|exploit)\s+(a\s+)?(password|system|network|server|database)\b",
            r"(?i)\b(generate|write|produce)\s+(child|CSAM|cp)\b",
            r"(?i)\bsell\s+(drugs?|weapons?|stolen\s+(data|credentials?))\b",
            r"(?i)\bhow\s+to\s+(commit|perform|carry\s+out)\s+(murder|assault|robbery|fraud|phishing)\b",
            r"(?i)\bdetailed\s+instructions?\s+(for|on)\s+(suicide|self.?harm)\b",
        ],
    },
    # -----------------------------------------------------------------------
    # Off-topic / out-of-scope requests
    # NeMo's off-topic rail (abc bot example)
    # -----------------------------------------------------------------------
    {
        "rule_id": "nemo/off-topic-request",
        "title": "Off-topic or out-of-scope system prompt deviation detected",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-20",
        "description": (
            "The prompt attempts to steer the assistant toward topics outside its "
            "intended domain, such as politics, religion, or personal opinions on "
            "controversial subjects.  NeMo's off-topic rail would redirect or "
            "refuse these requests at runtime."
        ),
        "remediation": (
            "Define explicit topical boundaries in a NeMo Guardrails Colang "
            "configuration.  Add an off-topic rail that redirects the assistant "
            "to its intended use-case."
        ),
        "patterns": [
            r"(?i)\bwhat\s+(is\s+your\s+)?(political\s+)?(opinion|view|stance)\s+(on|about)\b",
            r"(?i)\b(who|which)\s+(party|candidate|politician)\s+(should\s+I|do\s+you)\s+(vote|support)\b",
            r"(?i)\bdo\s+you\s+(believe\s+in|support|endorse)\s+(god|religion|abortion|gun\s+control|capital\s+punishment)\b",
            r"(?i)\bwrite\s+(me\s+)?(a\s+)?(romantic|sexual|erotic|adult)\b",
            r"(?i)\b(generate|produce|create)\s+(explicit|adult|nsfw|pornographic)\s+content\b",
            r"(?i)\bplay\s+(the\s+role\s+of|as)\s+(my\s+)?(girlfriend|boyfriend|lover|romantic\s+partner)\b",
            r"(?i)\bgive\s+me\s+(stock|investment|financial)\s+advice\b",
            r"(?i)\bprescribe\s+(me\s+)?(medication|drugs?|dosage)\b",
            r"(?i)\bdiagnose\s+(me|my\s+(condition|illness|disease|symptoms?))\b",
        ],
    },
    # -----------------------------------------------------------------------
    # Sensitive personal / confidential information requests
    # NeMo's PII / confidentiality topical rail
    # -----------------------------------------------------------------------
    {
        "rule_id": "nemo/sensitive-data-request",
        "title": "Request for sensitive or confidential information detected",
        "severity": Severity.HIGH,
        "cwe": "CWE-359",
        "description": (
            "The prompt requests personally identifiable information (PII), "
            "confidential credentials, private communications, or other sensitive "
            "data.  NeMo's confidentiality rail would block this at runtime."
        ),
        "remediation": (
            "Add a NeMo Guardrails output rail that prevents the model from "
            "emitting PII or confidential data.  Implement PII detection on "
            "both input and output using a library such as Microsoft Presidio."
        ),
        "patterns": [
            r"(?i)\b(reveal|expose|leak|share|give\s+me)\s+(the\s+)?(system\s+prompt|secret\s+instructions?|initial\s+prompt)\b",
            r"(?i)\bwhat\s+(are|were)\s+(your\s+)?(initial|original|system)\s+(prompt|instructions?)\b",
            r"(?i)\brepeat\s+(your\s+)?(entire\s+)?(system\s+prompt|instructions?)\b",
            r"(?i)\b(social\s+security\s+number|SSN|passport\s+number|driver.?s\s+licen[cs]e\s+number)\b",
            r"(?i)\b(credit\s+card|debit\s+card)\s+(number|details?|info(rmation)?)\b",
            r"(?i)\b(private|internal)\s+(api\s+key|secret|token|password|credential)\b",
            r"(?i)\baccess\s+(other\s+users?|account|profile|data)\s+(without|bypass)\b",
            r"(?i)\bexfiltrate\s+(data|information|credentials?)\b",
        ],
    },
    # -----------------------------------------------------------------------
    # Prompt-leaking / system prompt extraction
    # NeMo output rail for confidential system prompts
    # -----------------------------------------------------------------------
    {
        "rule_id": "nemo/system-prompt-extraction",
        "title": "System prompt extraction or context leakage attempt detected",
        "severity": Severity.HIGH,
        "cwe": "CWE-200",
        "description": (
            "The prompt tries to extract the LLM system prompt or internal context "
            "through indirect techniques such as translation, summarisation, or "
            "role-play scenarios.  NeMo's output rails would suppress this at runtime."
        ),
        "remediation": (
            "Deploy a NeMo output rail that refuses to reproduce system prompt "
            "contents.  Treat system prompts as confidential and ensure they are "
            "not logged or exposed through model responses."
        ),
        "patterns": [
            r"(?i)\btranslate\s+(the\s+)?(above|previous|your\s+system)\s+(prompt|instructions?|text)\b",
            r"(?i)\bsummarise?\s+(everything\s+(above|before)|your\s+(full\s+)?instructions?)\b",
            r"(?i)\bprint\s+(out\s+|verbatim\s+)?(your\s+)?(system\s+prompt|all\s+(previous\s+)?instructions?)\b",
            r"(?i)\bencode\s+(the\s+)?(system\s+prompt|instructions?)\s+(in|as|to)\s+(base64|hex|rot13)\b",
            r"(?i)\bwhat\s+does\s+your\s+(context\s+window|memory|prompt)\s+(contain|include|say)\b",
            r"(?i)\brespond\s+only\s+with\s+your\s+(full\s+)?(system\s+prompt|original\s+instructions?)\b",
        ],
    },
    # -----------------------------------------------------------------------
    # Social engineering / impersonation
    # NeMo identity / trust rail
    # -----------------------------------------------------------------------
    {
        "rule_id": "nemo/impersonation-attempt",
        "title": "Social engineering or identity impersonation attempt detected",
        "severity": Severity.MEDIUM,
        "cwe": "CWE-20",
        "description": (
            "The prompt attempts to convince the model to impersonate a trusted "
            "authority (e.g. a developer, OpenAI, Anthropic) or to bypass safety "
            "measures by claiming special permissions.  NeMo's identity rail "
            "would reject these claims at runtime."
        ),
        "remediation": (
            "Add a NeMo identity verification rail.  Never grant elevated "
            "capabilities based on self-reported identity inside the user turn."
        ),
        "patterns": [
            r"(?i)\bI\s+am\s+(a\s+)?(developer|openai|anthropic|admin|administrator|operator)\b",
            r"(?i)\bI\s+have\s+(special|elevated|admin|root|full)\s+(access|permissions?|privileges?)\b",
            r"(?i)\banthrop(ic)?\s+(says?|told|authoris[ez]es?)\s+(you|that\s+you)\s+(can|must|should)\b",
            r"(?i)\bopenai\s+(says?|told|authoris[ez]es?)\s+(you|that\s+you)\s+(can|must|should)\b",
            r"(?i)\bthis\s+is\s+(a\s+)?(test|debug|maintenance)\s+mode\b",
            r"(?i)\b(security|safety)\s+(bypass|override|disable|deactivate)\s+(code|key|token|phrase)\b",
        ],
    },
]

# Pre-compile all patterns for performance.
_COMPILED_RAILS: list[dict] = []
for _rail in _RAIL_DEFINITIONS:
    _COMPILED_RAILS.append(
        {
            **_rail,
            "_compiled": [re.compile(p) for p in _rail["patterns"]],
        }
    )


# ---------------------------------------------------------------------------
# NemoScanner
# ---------------------------------------------------------------------------


class NemoScanner(BaseScanner):
    """
    Static-analysis approximation of NeMo Guardrails rail evaluation.

    NeMo Guardrails operates at *runtime* against a live LLM — it cannot be
    run as a conventional static scanner.  This class provides a best-effort
    substitute by applying regex heuristics derived from NeMo's canonical
    Colang rail examples.  The scanner is marked available whenever the
    ``nemoguardrails`` Python package is installed; the patterns themselves
    work regardless of installation status.
    """

    # ------------------------------------------------------------------
    # BaseScanner interface
    # ------------------------------------------------------------------

    @property
    def name(self) -> str:
        return "nemo_guardrails"

    @property
    def version(self) -> str:
        """Return the installed nemoguardrails package version, or 'static'."""
        if not _NEMO_AVAILABLE:
            return "static"
        try:
            from importlib.metadata import version

            return version("nemoguardrails")
        except Exception:
            return "unknown"

    def is_available(self) -> bool:
        """
        Return True when the ``nemoguardrails`` package can be imported.

        The static pattern-matching logic works without the package, but
        availability signals to the scanner engine whether the full NeMo
        runtime could be used in future extensions.
        """
        return _NEMO_AVAILABLE

    # ------------------------------------------------------------------
    # Core scan logic
    # ------------------------------------------------------------------

    def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        """
        Scan *target* as prompt text for patterns that NeMo rails would block.

        Parameters
        ----------
        target:
            The prompt or text string to analyse.  Unlike most scanners,
            NemoScanner operates on *text content* rather than a filesystem path.
        **kwargs:
            Currently unused; reserved for future NeMo runtime integration.

        Returns
        -------
        List[Finding]
            One Finding per triggered rail rule.  The same rail will not
            produce duplicate findings for the same prompt.
        """
        prompt_text: str = target or ""
        return self._scan_text(prompt_text)

    def scan_prompt(self, prompt_text: str) -> List[Finding]:
        """
        Convenience method that scans *prompt_text* directly.

        This alias makes call-sites that deal explicitly with prompt strings
        more readable than calling ``scan(prompt_text)``.
        """
        return self._scan_text(prompt_text or "")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _scan_text(self, text: str) -> List[Finding]:
        """Apply all compiled rail patterns against *text*."""
        findings: List[Finding] = []
        if not text:
            return findings

        for rail in _COMPILED_RAILS:
            matched_pattern: Optional[str] = None
            for compiled_re in rail["_compiled"]:
                m = compiled_re.search(text)
                if m:
                    matched_pattern = m.group(0)
                    break

            if matched_pattern is None:
                continue

            finding = Finding(
                scanner=self.name,
                rule_id=rail["rule_id"],
                title=rail["title"],
                severity=rail["severity"],
                description=rail["description"],
                file_path=None,
                line_start=None,
                line_end=None,
                cwe=rail.get("cwe"),
                cve=None,
                confidence="MEDIUM",
                remediation=rail.get("remediation"),
                raw={
                    "matched_text": matched_pattern,
                    "rail_patterns": rail["patterns"],
                    "nemo_available": _NEMO_AVAILABLE,
                    "analysis_mode": "static_pattern_matching",
                },
            )
            findings.append(finding)

        return findings
