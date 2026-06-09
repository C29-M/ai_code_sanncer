"""
Garak LLM Red-Teaming Probe Signature Scanner
==============================================

Garak (https://github.com/leondz/garak) is fundamentally an *attack* tool:
it generates adversarial probes and fires them at a live LLM endpoint to test
whether the model can be jailbroken, manipulated, or made to produce harmful
output.

This adapter uses garak's probe pattern library for **static signature
matching** against a supplied prompt string.  When garak is installed the
scanner introspects its probe modules to extract string templates and
sub-string patterns, then checks whether the input prompt contains those
patterns.  This is a best-effort heuristic — garak was never designed for
offline use, so:

  * Template coverage is partial (only probes that expose ``prompts`` or
    ``payloads`` class attributes are checked).
  * False negatives are possible; subtle jailbreak variants will not be caught.

For **full** garak capability — including success/failure scoring against a
real model — a live LLM endpoint is required.  See:
    https://docs.garak.ai/garak
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
import re
import types
from typing import Any, List, Optional

from scanner_base import BaseScanner, Finding, Severity

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Probe-pattern catalogue
#
# We build this lazily on first use so that import time is fast even when
# garak is installed.
# ---------------------------------------------------------------------------
_PATTERNS_CACHE: Optional[List[tuple[str, str, str]]] = (
    None  # [(probe_name, label, pattern)]
)


# ---------------------------------------------------------------------------
# Hard-coded minimal fallback patterns
#
# These cover the most common jailbreak families that appear verbatim in
# garak's built-in probes.  They are used when garak is *not* installed so
# that the scanner is at least partially useful without the dependency.
# ---------------------------------------------------------------------------
_BUILTIN_PATTERNS: List[tuple[str, str, str]] = [
    # (rule_id, human label, regex pattern)
    (
        "garak.dan.classic",
        "DAN jailbreak (classic)",
        r"(?i)\bDAN\b.*(?:jailbreak|mode|enabled)",
    ),
    ("garak.dan.do_anything_now", "Do Anything Now prompt", r"(?i)do\s+anything\s+now"),
    (
        "garak.jailbreak.ignore_instructions",
        "Ignore previous instructions",
        r"(?i)ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    ),
    (
        "garak.jailbreak.ignore_rules",
        "Ignore safety rules",
        r"(?i)ignore\s+(your\s+)?(safety|ethical|content|usage)\s+(rules?|guidelines?|policies?|constraints?)",
    ),
    (
        "garak.jailbreak.pretend",
        "Pretend / roleplay jailbreak",
        r"(?i)pretend\s+(you\s+are|to\s+be)\s+(an?\s+)?(AI|assistant|chatbot|model|system)\s+(without|that\s+has\s+no|with\s+no)",
    ),
    (
        "garak.jailbreak.dev_mode",
        "Developer / unrestricted mode",
        r"(?i)(developer|dev|admin|god|unrestricted|uncensored)\s+mode",
    ),
    (
        "garak.jailbreak.act_as",
        "Act as unethical AI",
        r"(?i)act\s+as\s+(an?\s+)?(unethical|evil|dangerous|malicious|unrestricted)",
    ),
    (
        "garak.jailbreak.hypothetically",
        "Hypothetical framing bypass",
        r"(?i)hypothetically\s+(speaking[,.]?\s+)?if\s+(you\s+(were\s+)?)?(not\s+)?(bound|restricted|limited|constrained|governed)",
    ),
    (
        "garak.jailbreak.token_smuggling",
        "Token-smuggling / spacing bypass",
        r"(?i)(?:[A-Za-z]-){4,}",
    ),  # e.g. h-o-w  t-o  m-a-k-e
    (
        "garak.prompt_injection.system_override",
        "System-prompt override attempt",
        r"(?i)(new\s+)?system\s+(prompt|instruction|message)\s*[:\-]",
    ),
    (
        "garak.prompt_injection.ignore_system",
        "Ignore system prompt",
        r"(?i)ignore\s+(the\s+)?(system|original)\s+(prompt|instructions?)",
    ),
    (
        "garak.encoding.base64_instruction",
        "Base64-encoded instruction bypass",
        r"(?:[A-Za-z0-9+/]{20,}={0,2})",
    ),
    (
        "garak.continuation.complete_this",
        "Forced harmful continuation",
        r"(?i)(complete|continue|finish)\s+(the\s+following|this)\s+(sentence|text|instructions?|steps?)",
    ),
    (
        "garak.leakage.repeat_words",
        "Training-data / prompt-leakage probe",
        r"(?i)repeat\s+(the\s+)?(words?|text|content|instructions?)\s+(above|before|prior|from\s+your\s+system)",
    ),
    (
        "garak.xss.script_injection",
        "Script-tag injection in prompt",
        r"(?i)<\s*script[\s>]",
    ),
    (
        "garak.sqli.sql_in_prompt",
        "SQL injection pattern in prompt",
        r"(?i)(\bUNION\b.*\bSELECT\b|\bOR\b\s+['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?|--\s*$)",
    ),
]


# ---------------------------------------------------------------------------
# Garak probe introspection helpers
# ---------------------------------------------------------------------------


def _iter_probe_modules(probes_pkg: types.ModuleType):
    """Yield all sub-modules inside the garak.probes package."""
    pkg_path = getattr(probes_pkg, "__path__", [])
    for _finder, mod_name, _is_pkg in pkgutil.walk_packages(
        pkg_path, prefix=probes_pkg.__name__ + "."
    ):
        try:
            yield importlib.import_module(mod_name)
        except Exception as exc:  # noqa: BLE001
            logger.debug("Skipping garak probe module %s: %s", mod_name, exc)


def _extract_patterns_from_module(
    mod: types.ModuleType,
) -> List[tuple[str, str, str]]:
    """
    Inspect a garak probe module and extract literal prompt strings that can
    be used as sub-string signatures.

    Garak probes are classes that (usually) carry one or more of:
      - ``prompts``   : List[str]  — actual probe strings sent to the LLM
      - ``payloads``  : List[str]  — payload strings injected into templates
      - ``triggers``  : List[str]  — expected harmful outputs (less useful here)

    We collect non-trivial strings (len > 10) as fixed sub-string patterns.
    """
    results: List[tuple[str, str, str]] = []
    for _attr_name, obj in inspect.getmembers(mod, inspect.isclass):
        # Only consider classes defined in this module (not imports)
        if obj.__module__ != mod.__name__:
            continue
        for attr in ("prompts", "payloads"):
            value = getattr(obj, attr, None)
            if not isinstance(value, (list, tuple)):
                continue
            for item in value:
                if not isinstance(item, str):
                    continue
                stripped = item.strip()
                if len(stripped) < 10:
                    continue
                # Use first 80 chars as a human label
                label = stripped[:80].replace("\n", " ")
                # Build a case-insensitive literal regex from the first sentence
                # (avoid overly long patterns that would never match variants)
                first_sentence = re.split(r"[.!?\n]", stripped)[0][:60].strip()
                if len(first_sentence) < 8:
                    continue
                rule_id = f"garak.{mod.__name__.split('.')[-1]}.{attr}"
                pattern = re.escape(first_sentence)
                results.append((rule_id, label, pattern))
    return results


def _build_pattern_catalogue() -> List[tuple[str, str, str]]:
    """
    Attempt to build a full catalogue from garak's installed probe library.
    Falls back to _BUILTIN_PATTERNS if garak is not installed or introspection
    fails for any reason.
    """
    try:
        import garak.probes as probes_pkg  # type: ignore[import]
    except ImportError:
        logger.info(
            "garak is not installed; using built-in fallback patterns only. "
            "Install with: pip install garak"
        )
        return list(_BUILTIN_PATTERNS)

    catalogue: List[tuple[str, str, str]] = list(_BUILTIN_PATTERNS)
    seen_patterns: set[str] = {p for _, _, p in _BUILTIN_PATTERNS}

    for mod in _iter_probe_modules(probes_pkg):
        for rule_id, label, pattern in _extract_patterns_from_module(mod):
            if pattern not in seen_patterns:
                catalogue.append((rule_id, label, pattern))
                seen_patterns.add(pattern)

    logger.debug(
        "garak pattern catalogue built: %d patterns (%d from garak probes, %d built-in)",
        len(catalogue),
        len(catalogue) - len(_BUILTIN_PATTERNS),
        len(_BUILTIN_PATTERNS),
    )
    return catalogue


def _get_patterns() -> List[tuple[str, str, str]]:
    """Return the cached pattern catalogue, building it on first call."""
    global _PATTERNS_CACHE
    if _PATTERNS_CACHE is None:
        _PATTERNS_CACHE = _build_pattern_catalogue()
    return _PATTERNS_CACHE


# ---------------------------------------------------------------------------
# GarakScanner
# ---------------------------------------------------------------------------


class GarakScanner(BaseScanner):
    """
    Static signature scanner backed by garak's probe pattern library.

    Scans a prompt string (``target``) for known adversarial patterns drawn
    from garak's probe catalogue.  Because garak is an *attack* tool —
    designed to send probes to a live LLM — this scanner operates in a
    reduced "offline" mode:

      * It matches sub-string / regex signatures extracted from garak probe
        templates against the input text.
      * It does NOT send the prompt to any LLM.
      * A note is attached to every Finding reminding the caller that full
        garak red-teaming requires a live endpoint.

    The ``target`` parameter accepted by :meth:`scan` is treated as the
    prompt text to inspect.  Pass ``prompt_text`` as a keyword argument as a
    more readable alternative::

        scanner.scan("", prompt_text="ignore all previous instructions")
    """

    name = "garak"  # type: ignore[override]  # property in ABC, str here is fine

    @property
    def version(self) -> str:
        try:
            import garak  # type: ignore[import]

            return getattr(garak, "__version__", "unknown")
        except ImportError:
            return "not installed"

    def is_available(self) -> bool:
        """Return True when the garak package can be imported."""
        try:
            import garak  # noqa: F401  # type: ignore[import]

            return True
        except ImportError:
            return False

    # ------------------------------------------------------------------
    # Core scan logic
    # ------------------------------------------------------------------

    def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        """
        Scan *target* (or ``kwargs['prompt_text']``) for adversarial patterns.

        Parameters
        ----------
        target:
            The prompt text to inspect.  May also be supplied via
            ``prompt_text`` keyword argument; when both are provided,
            ``prompt_text`` takes precedence.
        **kwargs:
            prompt_text : str  — alternative way to supply the prompt.

        Returns
        -------
        List[Finding]
            One Finding per matched pattern.  An empty list is returned when
            no patterns match.

        Notes
        -----
        This method never raises; all exceptions are caught and logged.
        """
        prompt_text: str = kwargs.get("prompt_text") or target or ""

        if not prompt_text.strip():
            logger.debug("garak_scanner: empty prompt_text supplied, returning []")
            return []

        patterns = _get_patterns()
        if not patterns:
            logger.warning(
                "garak_scanner: pattern catalogue is empty; "
                "no garak probes available and built-in fallback is empty."
            )
            return []

        findings: List[Finding] = []

        for rule_id, label, pattern in patterns:
            try:
                match = re.search(pattern, prompt_text, re.IGNORECASE)
            except re.error as exc:
                logger.debug("garak_scanner: bad regex for rule %s: %s", rule_id, exc)
                continue

            if match is None:
                continue

            matched_snippet = prompt_text[
                max(0, match.start() - 20) : match.end() + 20
            ].strip()

            description = (
                f"Prompt matches known adversarial pattern: '{label}'. "
                f"Matched text: '{matched_snippet}'. "
                "NOTE: Garak is an LLM red-teaming tool that generates probes for "
                "live-model testing. This finding is produced by static signature "
                "matching against garak's probe templates — it does NOT represent a "
                "confirmed successful jailbreak. For full red-teaming, run garak "
                "against a live LLM endpoint: https://docs.garak.ai/garak"
            )

            findings.append(
                Finding(
                    scanner=self.name,
                    rule_id=rule_id,
                    title=f"Adversarial probe pattern detected: {label[:60]}",
                    severity=Severity.HIGH,
                    description=description,
                    file_path=None,
                    line_start=None,
                    line_end=None,
                    cwe="CWE-77",  # Improper Neutralization of Special Elements used in a Command
                    cve=None,
                    confidence="MEDIUM",
                    remediation=(
                        "Review the prompt for adversarial intent. "
                        "Apply prompt injection defences (input validation, "
                        "output filtering, principle-of-least-privilege system "
                        "prompts). For comprehensive LLM red-teaming, run: "
                        "garak --model_type <provider> --probes all"
                    ),
                    raw={
                        "matched_text": matched_snippet,
                        "pattern": pattern,
                        "garak_note": (
                            "Static signature match only. "
                            "Garak requires a live LLM for full capability."
                        ),
                    },
                )
            )

        if not findings:
            logger.debug(
                "garak_scanner: no adversarial patterns matched in the supplied prompt."
            )
        else:
            logger.info(
                "garak_scanner: %d pattern(s) matched in prompt.", len(findings)
            )

        return findings
