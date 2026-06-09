"""
Model loader — loads CodeBERT and VulBERTa once on startup and holds them in memory.

Models loaded:
  VulBERTa : mrm8488/codebert-base-finetuned-detect-insecure-code
             Binary text-classification pipeline (secure vs insecure)
  CodeBERT : microsoft/codebert-base
             Feature-extraction pipeline for embedding generation

Both models are CPU-only. Combined ~2GB RAM, ~500MB download on first run.
Downloads are cached in HuggingFace's default cache dir
(~/.cache/huggingface/hub) which should be mapped to a Docker volume.
"""

from __future__ import annotations

import logging
import math
from typing import Optional

import torch
from transformers import (
    AutoModel,
    AutoTokenizer,
    RobertaForSequenceClassification,
    RobertaTokenizer,
    pipeline,
)

from reference_corpus import REFERENCE_CORPUS

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Global model holders (populated once by load_models())
# ---------------------------------------------------------------------------
_vulberta_pipeline = None
_codebert_model: Optional[AutoModel] = None
_codebert_tokenizer: Optional[AutoTokenizer] = None
_corpus_embeddings: list[dict] = []  # [{snippet, label, vuln_type, embedding}]


def load_models() -> None:
    """Load both models into memory. Call once at startup."""
    global _vulberta_pipeline, _codebert_model, _codebert_tokenizer, _corpus_embeddings

    logger.info("Loading VulBERTa (mrm8488/codebert-base-finetuned-detect-insecure-code)...")
    _vulberta_pipeline = pipeline(
        "text-classification",
        model="mrm8488/codebert-base-finetuned-detect-insecure-code",
        tokenizer="mrm8488/codebert-base-finetuned-detect-insecure-code",
        device=-1,           # CPU
        truncation=True,
        max_length=512,
    )
    logger.info("VulBERTa loaded.")

    logger.info("Loading CodeBERT (microsoft/codebert-base)...")
    _codebert_tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    _codebert_model = AutoModel.from_pretrained("microsoft/codebert-base")
    _codebert_model.eval()
    logger.info("CodeBERT loaded.")

    logger.info("Pre-computing reference corpus embeddings (%d snippets)...", len(REFERENCE_CORPUS))
    _corpus_embeddings = []
    for entry in REFERENCE_CORPUS:
        emb = _embed(entry["snippet"])
        _corpus_embeddings.append({
            "snippet":   entry["snippet"],
            "label":     entry["label"],
            "vuln_type": entry["vuln_type"],
            "embedding": emb,
        })
    logger.info("Corpus embeddings ready.")


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _embed(text: str) -> list[float]:
    """Return the [CLS] token embedding from CodeBERT as a float list."""
    assert _codebert_tokenizer is not None and _codebert_model is not None
    inputs = _codebert_tokenizer(
        text,
        return_tensors="pt",
        truncation=True,
        max_length=512,
        padding=True,
    )
    with torch.no_grad():
        outputs = _codebert_model(**inputs)
    # CLS token = first token of last hidden state
    cls_embedding = outputs.last_hidden_state[:, 0, :].squeeze(0)
    return cls_embedding.tolist()


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    norm_a = math.sqrt(sum(x * x for x in a))
    norm_b = math.sqrt(sum(y * y for y in b))
    if norm_a == 0 or norm_b == 0:
        return 0.0
    return dot / (norm_a * norm_b)


# ---------------------------------------------------------------------------
# Public inference functions
# ---------------------------------------------------------------------------
def run_vulberta(snippet: str) -> tuple[str, float]:
    """
    Run VulBERTa on a code snippet.

    Returns:
        (label, score) where label is "LABEL_0" (secure) or "LABEL_1" (insecure)
        and score is the model's confidence for that label.
    """
    assert _vulberta_pipeline is not None, "Models not loaded — call load_models() first"
    result = _vulberta_pipeline(snippet[:512])
    # pipeline returns list of dicts: [{"label": "LABEL_1", "score": 0.97}]
    top = result[0] if isinstance(result, list) else result
    return top["label"], float(top["score"])


def run_codebert_similarity(snippet: str) -> float:
    """
    Compute the maximum cosine similarity between snippet's CodeBERT embedding
    and all VULNERABLE entries in the reference corpus.

    Returns a float in [0.0, 1.0].
    """
    assert _codebert_model is not None, "Models not loaded — call load_models() first"
    query_emb = _embed(snippet)

    max_sim = 0.0
    for entry in _corpus_embeddings:
        if entry["label"] != "vulnerable":
            continue
        sim = _cosine_similarity(query_emb, entry["embedding"])
        if sim > max_sim:
            max_sim = sim

    # Clamp to [0, 1]
    return round(max(0.0, min(1.0, max_sim)), 4)


def models_ready() -> bool:
    return _vulberta_pipeline is not None and _codebert_model is not None
