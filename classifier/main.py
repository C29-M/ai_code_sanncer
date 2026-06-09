"""
Week 5 — Classifier microservice.

Runs on port 8001. Loads CodeBERT + VulBERTa on startup.
The scanner backend calls POST /classify for each HIGH/CRITICAL finding.

Endpoints:
  GET  /health           → {"status": "ok", "models_ready": bool}
  POST /classify         → ClassifyResponse
  POST /classify/batch   → list[ClassifyResponse]
"""

from __future__ import annotations

import hashlib
import logging
import os
from contextlib import asynccontextmanager
from typing import Optional

import redis
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from models_loader import load_models, models_ready, run_codebert_similarity, run_vulberta
from vuln_labels import classify_vuln_type, vulberta_confidence

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Redis cache (optional — graceful fallback if Redis not available)
# ---------------------------------------------------------------------------
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
_redis: Optional[redis.Redis] = None

def _get_redis() -> Optional[redis.Redis]:
    global _redis
    if _redis is not None:
        return _redis
    try:
        client = redis.from_url(REDIS_URL, socket_connect_timeout=1)
        client.ping()
        _redis = client
        logger.info("Redis connected at %s", REDIS_URL)
        return _redis
    except Exception as e:
        logger.warning("Redis unavailable (%s) — caching disabled", e)
        return None


def _cache_key(snippet: str) -> str:
    return "clf:" + hashlib.sha256(snippet.encode()).hexdigest()


def _cache_get(snippet: str) -> Optional[dict]:
    r = _get_redis()
    if r is None:
        return None
    try:
        raw = r.get(_cache_key(snippet))
        return json.loads(raw) if raw else None
    except Exception:
        return None


def _cache_set(snippet: str, result: dict, ttl: int = 3600) -> None:
    r = _get_redis()
    if r is None:
        return
    try:
        r.setex(_cache_key(snippet), ttl, json.dumps(result))
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Lifespan — load models on startup
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Loading models on startup...")
    load_models()
    logger.info("Models ready.")
    yield


app = FastAPI(
    title="AI Code Scanner — Classifier Service",
    description="VulBERTa + CodeBERT inference microservice (Week 5)",
    version="0.5.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------
class ClassifyRequest(BaseModel):
    snippet: str
    description: str = ""
    risk_score: int = 0


class ClassifyResponse(BaseModel):
    vuln_type: str
    classifier_confidence: float
    semantic_similarity: float
    adjusted_risk_score: float


# ---------------------------------------------------------------------------
# Core classification logic
# ---------------------------------------------------------------------------
def _classify(snippet: str, description: str, risk_score: int) -> dict:
    # 1. Check cache
    cached = _cache_get(snippet)
    if cached:
        logger.debug("Cache hit for snippet hash")
        return cached

    # 2. VulBERTa
    label, score = run_vulberta(snippet)
    confidence = vulberta_confidence(label, score)

    # 3. vuln_type from keywords (VulBERTa is binary, not multi-class)
    vuln_type = classify_vuln_type(snippet, description)

    # 4. CodeBERT similarity
    semantic_similarity = run_codebert_similarity(snippet)

    # 5. adjusted_risk_score = risk_score + (similarity * 10), capped at 100
    adjusted = min(100.0, risk_score + (semantic_similarity * 10))

    result = {
        "vuln_type":             vuln_type,
        "classifier_confidence": confidence,
        "semantic_similarity":   semantic_similarity,
        "adjusted_risk_score":   round(adjusted, 2),
    }

    # 6. Cache
    _cache_set(snippet, result)
    return result


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@app.get("/health")
async def health() -> dict:
    return {"status": "ok", "models_ready": models_ready()}


@app.post("/classify", response_model=ClassifyResponse)
async def classify(body: ClassifyRequest) -> ClassifyResponse:
    if not models_ready():
        raise HTTPException(status_code=503, detail="Models not loaded yet")

    if not body.snippet or not body.snippet.strip():
        return ClassifyResponse(
            vuln_type="other",
            classifier_confidence=0.0,
            semantic_similarity=0.0,
            adjusted_risk_score=float(body.risk_score),
        )

    result = _classify(body.snippet, body.description, body.risk_score)
    return ClassifyResponse(**result)


@app.post("/classify/batch", response_model=list[ClassifyResponse])
async def classify_batch(bodies: list[ClassifyRequest]) -> list[ClassifyResponse]:
    if not models_ready():
        raise HTTPException(status_code=503, detail="Models not loaded yet")

    responses = []
    for body in bodies:
        if not body.snippet or not body.snippet.strip():
            responses.append(ClassifyResponse(
                vuln_type="other",
                classifier_confidence=0.0,
                semantic_similarity=0.0,
                adjusted_risk_score=float(body.risk_score),
            ))
            continue
        result = _classify(body.snippet, body.description, body.risk_score)
        responses.append(ClassifyResponse(**result))
    return responses
