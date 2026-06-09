"""
Classifier client — called by the scanner backend after findings are normalised.

Sends HIGH/CRITICAL findings to the classifier microservice (port 8001) in a
single batch call, appends the 4 new fields, and falls back gracefully if the
service is unreachable or times out.

Fields added to each finding:
  vuln_type             : str   — sqli | xss | rce | secrets | iac | crypto | other
  classifier_confidence : float — 0.0-1.0 (VulBERTa confidence for "insecure")
  semantic_similarity   : float — 0.0-1.0 (CodeBERT cosine similarity to known-vuln)
  adjusted_risk_score   : float — risk_score + (similarity * 10), capped at 100
"""

from __future__ import annotations

import logging
import os
from typing import Any

import httpx

logger = logging.getLogger(__name__)

CLASSIFIER_URL = os.getenv("CLASSIFIER_URL", "http://localhost:8001")
CLASSIFY_TIMEOUT = float(os.getenv("CLASSIFIER_TIMEOUT_S", "10"))

# Only classify findings at these severities (per week 5 spec)
_CLASSIFY_SEVERITIES = {"CRITICAL", "HIGH"}

# Fallback values added when classifier is unavailable
_FALLBACK = {
    "vuln_type": "other",
    "classifier_confidence": 0.0,
    "semantic_similarity": 0.0,
    "adjusted_risk_score": None,  # filled per-finding from risk_score
}


def _fallback_fields(risk_score: int) -> dict:
    return {
        **_FALLBACK,
        "adjusted_risk_score": float(risk_score),
    }


async def enrich_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """
    Async — enrich findings with classifier output.

    HIGH/CRITICAL findings are sent to the classifier in one batch call.
    All other findings get fallback values (so the schema is consistent).
    If the classifier is unreachable or times out, ALL findings get fallbacks.

    Returns the enriched findings list (same order, same length).
    """
    # Split HIGH/CRITICAL vs rest
    to_classify_indices: list[int] = []
    for i, f in enumerate(findings):
        if f.get("severity") in _CLASSIFY_SEVERITIES and f.get("snippet"):
            to_classify_indices.append(i)

    # Apply fallbacks to everything first (ensures schema completeness)
    enriched = []
    for f in findings:
        enriched.append({**f, **_fallback_fields(f.get("risk_score", 0))})

    if not to_classify_indices:
        return enriched

    # Build batch payload
    batch = [
        {
            "snippet": findings[i].get("snippet", ""),
            "description": findings[i].get("description", ""),
            "risk_score": findings[i].get("risk_score", 0),
        }
        for i in to_classify_indices
    ]

    try:
        async with httpx.AsyncClient(timeout=CLASSIFY_TIMEOUT) as client:
            resp = await client.post(
                f"{CLASSIFIER_URL}/classify/batch",
                json=batch,
            )
            resp.raise_for_status()
            results = resp.json()  # list of ClassifyResponse dicts

        # Merge classifier output back into findings
        for idx, clf_result in zip(to_classify_indices, results):
            enriched[idx].update(
                {
                    "vuln_type": clf_result.get("vuln_type", "other"),
                    "classifier_confidence": clf_result.get(
                        "classifier_confidence", 0.0
                    ),
                    "semantic_similarity": clf_result.get("semantic_similarity", 0.0),
                    "adjusted_risk_score": clf_result.get(
                        "adjusted_risk_score", float(findings[idx].get("risk_score", 0))
                    ),
                }
            )
        logger.info(
            "Classifier enriched %d/%d findings",
            len(to_classify_indices),
            len(findings),
        )

    except httpx.TimeoutException:
        logger.warning(
            "Classifier timed out after %.1fs — findings pass through with fallback scores",
            CLASSIFY_TIMEOUT,
        )
    except Exception as exc:
        logger.warning(
            "Classifier unavailable (%s) — findings pass through with fallback scores",
            exc,
        )

    return enriched


def is_classifier_available() -> bool:
    """Synchronous health check — used at startup to log classifier status."""
    try:
        resp = httpx.get(f"{CLASSIFIER_URL}/health", timeout=2.0)
        return resp.status_code == 200 and resp.json().get("models_ready", False)
    except Exception:
        return False
