# Week 5 — Classifier microservice Docker image
# CPU-only PyTorch to keep image lean (~3GB vs ~8GB GPU)

FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install CPU-only PyTorch first (separate index so pip doesn't pull CUDA wheels)
RUN pip install --no-cache-dir \
    torch==2.3.0 \
    --index-url https://download.pytorch.org/whl/cpu

# Install remaining dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# HuggingFace model cache — mount a Docker volume here to persist downloads
# across container restarts (avoids re-downloading ~500MB every restart)
ENV HF_HOME=/models_cache
ENV TRANSFORMERS_CACHE=/models_cache

# Redis URL — override via docker-compose environment
ENV REDIS_URL=redis://redis:6379/0

EXPOSE 8001

# Workers=1 so both models share one process (avoids double RAM usage)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001", "--workers", "1"]
