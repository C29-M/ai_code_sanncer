"""
scanner_engine.py — Main orchestration engine for AI Code Scanner.

Provides ScannerEngine, which loads all scanner adapters from the scanners/
registry, runs them in parallel via ThreadPoolExecutor, normalises and
deduplicates findings, and delegates report generation to report_generator.
"""

from __future__ import annotations

import logging
import time
import uuid
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class ScanResult:
    """Unified result returned by ScannerEngine.scan()."""

    scan_id: str
    findings: List[Dict[str, Any]]
    findings_count: int
    findings_by_severity: Dict[str, int]
    scanner_status: Dict[str, str]  # {tool: "active" | "skipped" | "error" | "na"}
    scanners_active: List[str]
    errors: List[str]
    duration_s: float
    report: Optional[Dict[str, Any]] = None


@dataclass
class ScannerStatus:
    """Describes a registered scanner and its availability."""

    name: str
    available: bool
    reason: str = ""


# ---------------------------------------------------------------------------
# Scanner registry
#
# Each entry describes one scanner adapter.  The callable stored under "run"
# accepts a single positional argument — the repo Path — and returns either a
# list[dict] or a dict (for Trivy-style output).  The "condition" callable
# receives the language-count map and returns True when the scanner should be
# activated.  None means "always run".
# ---------------------------------------------------------------------------


def _always(_lang_counts: Dict[str, int]) -> bool:
    return True


def _has_python(lang_counts: Dict[str, int]) -> bool:
    return lang_counts.get("python", 0) > 0


def _has_js(lang_counts: Dict[str, int]) -> bool:
    return lang_counts.get("javascript", 0) + lang_counts.get("typescript", 0) > 0


def _has_go(lang_counts: Dict[str, int]) -> bool:
    return lang_counts.get("go", 0) > 0


def _has_java(lang_counts: Dict[str, int]) -> bool:
    return lang_counts.get("java", 0) > 0


def _build_registry() -> Dict[str, Dict[str, Any]]:
    """
    Import scanner runners and build the registry.

    Each value is a dict with:
      run       : Callable[[Path], list | dict]
      condition : Callable[[dict], bool] | None
      output    : "list" | "dict"   — shape of the runner's return value
    """
    registry: Dict[str, Dict[str, Any]] = {}

    def _try_register(
        name: str,
        module: str,
        func: str,
        condition: Optional[Callable],
        output: str,
    ) -> None:
        try:
            import importlib

            mod = importlib.import_module(module)
            runner = getattr(mod, func)
            registry[name] = {
                "run": runner,
                "condition": condition,
                "output": output,
                "available": True,
                "reason": "",
            }
        except Exception as exc:  # noqa: BLE001
            registry[name] = {
                "run": None,
                "condition": condition,
                "output": output,
                "available": False,
                "reason": str(exc),
            }

    # Core scanners (always active when the runner is available)
    _try_register("semgrep", "scanner", "run_semgrep_scan", _always, "dict")
    _try_register("gitleaks", "gitleaks_runner", "run_gitleaks_scan", _always, "list")
    _try_register("trivy", "trivy_runner", "run_trivy_scan", _always, "dict")
    _try_register(
        "trufflehog", "trufflehog_runner", "run_trufflehog_scan", _always, "list"
    )

    # Language-conditional scanners
    _try_register("bandit", "bandit_runner", "run_bandit_scan", _has_python, "list")
    _try_register("safety", "safety_runner", "run_safety_scan", _has_python, "list")
    _try_register("eslint", "eslint_runner", "run_eslint_scan", _has_js, "list")
    _try_register("gosec", "gosec_runner", "run_gosec_scan", _has_go, "list")
    _try_register("spotbugs", "spotbugs_runner", "run_spotbugs_scan", _has_java, "list")
    _try_register(
        "owasp_depcheck",
        "owasp_depcheck_runner",
        "run_owasp_depcheck_scan",
        _has_java,
        "list",
    )

    return registry


# ---------------------------------------------------------------------------
# ScannerEngine
# ---------------------------------------------------------------------------


class ScannerEngine:
    """
    Orchestrates parallel execution of all registered security scanners.

    Parameters
    ----------
    scanner_names:
        Optional allow-list of scanner names.  When provided, only scanners
        whose name appears in the list will run.  Unknown names are silently
        ignored so callers can pass user-supplied input safely.
    """

    def __init__(self, scanner_names: Optional[List[str]] = None) -> None:
        self._registry = _build_registry()
        self._filter = set(scanner_names) if scanner_names else None
        logger.debug(
            "ScannerEngine initialised — registry=%s filter=%s",
            list(self._registry.keys()),
            self._filter,
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def scan(self, repo_path: Path, scan_id: Optional[str] = None) -> ScanResult:
        """
        Run all available (and conditionally applicable) scanners against
        *repo_path* in parallel, then normalise, deduplicate and return a
        ScanResult.

        Parameters
        ----------
        repo_path:
            Path to the cloned repository on the local filesystem.
        scan_id:
            Optional caller-supplied identifier; one is generated when omitted.
        """
        if scan_id is None:
            scan_id = str(uuid.uuid4())

        start = time.monotonic()
        repo_path = Path(repo_path)

        # ------------------------------------------------------------------
        # Language detection (used to activate conditional scanners)
        # ------------------------------------------------------------------
        lang_counts: Dict[str, int] = {}
        try:
            from language_detection import detect_languages

            lang_counts = detect_languages(repo_path)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Language detection failed: %s", exc)

        # ------------------------------------------------------------------
        # Determine which scanners to run
        # ------------------------------------------------------------------
        active_scanners: Dict[str, Dict[str, Any]] = {}
        skipped_na: Dict[str, str] = {}

        for name, meta in self._registry.items():
            # Filter by caller-supplied allow-list
            if self._filter is not None and name not in self._filter:
                skipped_na[name] = "na"
                continue

            if not meta["available"]:
                skipped_na[name] = "na"
                logger.debug("Scanner %s unavailable: %s", name, meta["reason"])
                continue

            condition = meta["condition"]
            if condition is not None and not condition(lang_counts):
                skipped_na[name] = "na"
                logger.debug("Scanner %s not applicable for detected languages", name)
                continue

            active_scanners[name] = meta

        logger.info(
            "scan_id=%s | active=%s | skipped=%s",
            scan_id,
            list(active_scanners.keys()),
            list(skipped_na.keys()),
        )

        # ------------------------------------------------------------------
        # Run scanners in parallel
        # ------------------------------------------------------------------
        raw_results: Dict[str, Any] = {}
        errors: List[str] = []

        with ThreadPoolExecutor(max_workers=4) as executor:
            future_to_name = {
                executor.submit(self._safe_scan, name, meta["run"], repo_path): name
                for name, meta in active_scanners.items()
            }
            for future in as_completed(future_to_name):
                name = future_to_name[future]
                result, error = future.result()
                raw_results[name] = result
                if error:
                    errors.append(f"{name}: {error}")

        logger.info("scan_id=%s | all scanners finished", scan_id)

        # ------------------------------------------------------------------
        # Build scanner_status map
        # ------------------------------------------------------------------
        scanner_status: Dict[str, str] = {}
        for name in self._registry:
            if name in skipped_na:
                scanner_status[name] = skipped_na[name]
            elif name in raw_results:
                scanner_status[name] = (
                    "error" if raw_results[name] is None else "active"
                )
            else:
                scanner_status[name] = "na"

        scanners_active = [n for n, s in scanner_status.items() if s == "active"]

        # ------------------------------------------------------------------
        # Normalise findings
        # ------------------------------------------------------------------
        findings = self._normalise(raw_results, active_scanners)

        findings_by_severity: Dict[str, int] = {}
        for f in findings:
            sev = f.get("severity", "INFO")
            findings_by_severity[sev] = findings_by_severity.get(sev, 0) + 1

        duration_s = round(time.monotonic() - start, 3)

        # ------------------------------------------------------------------
        # Report generation
        # ------------------------------------------------------------------
        report: Optional[Dict[str, Any]] = None
        try:
            from report_generator import generate_report  # type: ignore[import]

            report = generate_report(
                scan_id=scan_id,
                findings=findings,
                scanner_status=scanner_status,
                duration_s=duration_s,
            )
        except ImportError:
            logger.debug("report_generator not available; skipping report step")
        except Exception as exc:  # noqa: BLE001
            logger.warning("Report generation failed: %s", exc)
            errors.append(f"report_generator: {exc}")

        logger.info(
            "scan_id=%s | findings=%d | duration=%.3fs",
            scan_id,
            len(findings),
            duration_s,
        )

        return ScanResult(
            scan_id=scan_id,
            findings=findings,
            findings_count=len(findings),
            findings_by_severity=findings_by_severity,
            scanner_status=scanner_status,
            scanners_active=scanners_active,
            errors=errors,
            duration_s=duration_s,
            report=report,
        )

    def get_available_scanners(self) -> List[ScannerStatus]:
        """Return a list of ScannerStatus for every registered scanner."""
        statuses: List[ScannerStatus] = []
        for name, meta in self._registry.items():
            if self._filter is not None and name not in self._filter:
                continue
            statuses.append(
                ScannerStatus(
                    name=name,
                    available=meta["available"],
                    reason=meta.get("reason", ""),
                )
            )
        return statuses

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _safe_scan(
        name: str,
        run: Callable,
        repo_path: Path,
    ) -> tuple[Any, Optional[str]]:
        """
        Call *run(repo_path)* and return (result, error_message).

        On success  : (result, None)
        On failure  : (None,   str(exc))
        """
        try:
            result = run(repo_path)
            return result, None
        except Exception as exc:  # noqa: BLE001
            logger.warning("Scanner %s raised: %s", name, exc)
            return None, str(exc)

    @staticmethod
    def _normalise(
        raw_results: Dict[str, Any],
        active_scanners: Dict[str, Dict[str, Any]],
    ) -> List[Dict[str, Any]]:
        """
        Map raw scanner output to the unified schema via normalizer.normalise_all(),
        then return deduplicated, risk-score-sorted findings.
        """
        from normalizer import normalise_all
        from scanner import extract_findings

        def _as_list(name: str, default: Optional[list] = None) -> Optional[List[dict]]:
            raw = raw_results.get(name)
            if raw is None:
                return default
            if isinstance(raw, list):
                return raw
            return default

        def _as_dict(name: str) -> dict:
            raw = raw_results.get(name)
            if isinstance(raw, dict):
                return raw
            return {"Results": []}

        # Semgrep returns a dict; extract the findings list from it
        semgrep_raw = raw_results.get("semgrep")
        if isinstance(semgrep_raw, dict):
            semgrep_findings = extract_findings(semgrep_raw)
        else:
            semgrep_findings = []

        return normalise_all(
            semgrep_findings=semgrep_findings,
            gitleaks_findings=_as_list("gitleaks") or [],
            trivy_output=_as_dict("trivy"),
            bandit_findings=_as_list("bandit"),
            safety_findings=_as_list("safety"),
            eslint_findings=_as_list("eslint"),
            gosec_findings=_as_list("gosec"),
            trufflehog_findings=_as_list("trufflehog"),
            spotbugs_findings=_as_list("spotbugs"),
            owasp_depcheck_findings=_as_list("owasp_depcheck"),
        )


# ---------------------------------------------------------------------------
# Factory function
# ---------------------------------------------------------------------------


def create_engine(scanner_names: Optional[List[str]] = None) -> ScannerEngine:
    """
    Convenience factory.  Creates and returns a configured ScannerEngine.

    Parameters
    ----------
    scanner_names:
        Optional list of scanner names to restrict to.  Pass None (default)
        to enable all registered scanners.
    """
    return ScannerEngine(scanner_names=scanner_names)
