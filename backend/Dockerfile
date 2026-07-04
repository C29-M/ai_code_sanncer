# Multi-stage scanner sandbox image (OSS Plan Week 4 — all 10 scanners).
# Build:  docker build -t ai-code-scanner:latest -f Dockerfile .
# Build with NVD pre-warm:
#   docker build --build-arg NVD_API_KEY=<your-key> -t ai-code-scanner:latest -f Dockerfile .
#
# Scanners bundled:
#   Python SAST      : Semgrep, Bandit
#   Python SCA       : Safety
#   JS/TS SAST       : ESLint + eslint-plugin-security  (Node 20, global npm)
#   Go SAST          : Gosec binary                     (v2.21.4)
#   Secrets (live)   : Gitleaks                         (v8.27.2)
#   Secrets (history): TruffleHog                       (pip)
#   Container CVE    : Trivy                             (v0.70.0)
#   Java SAST        : SpotBugs via mvn spotbugs plugin (Temurin JDK 21 + Maven 3)
#   Java SCA         : OWASP Dependency-Check CLI       (v9.2.0, JRE 21)

ARG NVD_API_KEY=""

# ═══════════════════════════ Stage 1: builder ═══════════════════════════════
FROM python:3.11-slim-bookworm AS builder

ARG NVD_API_KEY

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    DEBIAN_FRONTEND=noninteractive

# ── Core build tools ─────────────────────────────────────────────────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       git ca-certificates curl unzip gnupg jq wget \
    && rm -rf /var/lib/apt/lists/*

# ── Node 20 (ESLint) ─────────────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── Java 21 JDK (Eclipse Temurin — Debian bookworm only ships JDK 17) ────────
# Modern Spring Boot 3.2+ projects commonly target java.version=21; SpotBugs
# needs to compile the project first, so the build JDK must match or exceed it.
RUN apt-get update \
    && apt-get install -y --no-install-recommends wget apt-transport-https gnupg \
    && wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public \
       | gpg --dearmor | tee /usr/share/keyrings/adoptium.gpg > /dev/null \
    && echo "deb [signed-by=/usr/share/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb bookworm main" \
       | tee /etc/apt/sources.list.d/adoptium.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends temurin-21-jdk \
    && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# ── Python scanners — two venvs to avoid pydantic version conflict ────────────
# semgrep 1.163+ pulls mcp which needs pydantic>=2.11; safety needs pydantic<2.10.
RUN python -m venv /opt/main-venv
ENV PATH="/opt/main-venv/bin:$PATH"
RUN pip install \
        "semgrep==1.163.0" \
        "bandit[toml]==1.8.3"

RUN python -m venv /opt/safety-venv
RUN /opt/safety-venv/bin/pip install "safety==3.5.2" "typer>=0.12.1,<0.13.0"

# ── Backend API dependencies (fastapi, uvicorn, httpx, gitpython, etc.) ──────
COPY api-requirements.txt /tmp/api-requirements.txt
RUN pip install -r /tmp/api-requirements.txt

# ── Semgrep offline rule pack ─────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/semgrep/semgrep-rules.git /opt/semgrep-rules \
    && rm -f  /opt/semgrep-rules/.pre-commit-config.yaml \
    && rm -rf /opt/semgrep-rules/.github \
              /opt/semgrep-rules/stats \
              /opt/semgrep-rules/scripts \
              /opt/semgrep-rules/bento \
              /opt/semgrep-rules/fingerprints \
              /opt/semgrep-rules/trusted_python \
              /opt/semgrep-rules/contrib

# ── Warm Semgrep cache ────────────────────────────────────────────────────────
RUN mkdir -p /warm \
    && printf '# warm\nx = eval(input())\n' > /warm/insecure.py \
    && semgrep scan --config /opt/semgrep-rules/python --json /warm > /dev/null 2>&1 || true \
    && mkdir -p /opt/semgrep-seed \
    && if [ -d /root/.semgrep ]; then cp -a /root/.semgrep/. /opt/semgrep-seed/; fi \
    && chmod -R a+rX /opt/semgrep-seed /opt/semgrep-rules

# ── Gitleaks (latest release via GitHub API) ─────────────────────────────────
RUN URL=$(curl -s https://api.github.com/repos/gitleaks/gitleaks/releases/latest \
      | jq -r '.assets[] | select(.name | test("linux_x64.tar.gz")) | .browser_download_url') \
    && curl -sSL "$URL" | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && gitleaks version

# ── Gosec (latest release via GitHub API, anchored pattern) ──────────────────
RUN URL=$(curl -s https://api.github.com/repos/securego/gosec/releases/latest \
      | jq -r '[.assets[] | select(.name | test("linux_amd64\\.tar\\.gz$")) | .browser_download_url] | first') \
    && curl -sSL "$URL" | tar -xz -C /usr/local/bin gosec \
    && chmod +x /usr/local/bin/gosec \
    && gosec --version 2>&1 | head -1

# ── TruffleHog (latest release via GitHub API, anchored pattern) ─────────────
RUN URL=$(curl -s https://api.github.com/repos/trufflesecurity/trufflehog/releases/latest \
      | jq -r '[.assets[] | select(.name | test("linux_amd64\\.tar\\.gz$")) | .browser_download_url] | first') \
    && curl -sSL "$URL" | tar -xz -C /usr/local/bin trufflehog \
    && chmod +x /usr/local/bin/trufflehog \
    && trufflehog --version 2>&1 | head -1

# ── ESLint 8 + eslint-plugin-security 3 (global npm) ────────────────────────
RUN npm install -g eslint@8 eslint-plugin-security@3 \
    && eslint --version

# ── OWASP Dependency-Check (latest release via GitHub API) ───────────────────
RUN URL=$(curl -s https://api.github.com/repos/jeremylong/DependencyCheck/releases/latest \
      | jq -r '[.assets[] | select(.name | test("release\\.zip$")) | .browser_download_url] | first') \
    && curl -sSL "$URL" -o /tmp/depcheck.zip \
    && unzip -q /tmp/depcheck.zip -d /opt/ \
    && rm /tmp/depcheck.zip \
    && chmod +x /opt/dependency-check/bin/dependency-check.sh

# ── Pre-warm OWASP NVD database (optional) ───────────────────────────────────
RUN if [ -n "${NVD_API_KEY}" ]; then \
      echo "Pre-warming OWASP NVD database..." \
      && /opt/dependency-check/bin/dependency-check.sh \
           --updateonly \
           --nvdApiKey "${NVD_API_KEY}" || true; \
    else \
      echo "NVD_API_KEY not set — NVD DB will download on first scan."; \
    fi

# ═══════════════════════════ Stage 2: runtime ═══════════════════════════════
FROM python:3.11-slim-bookworm AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# ── Runtime system packages + Trivy + Temurin JDK 21 apt repos ───────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg wget apt-transport-https \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key \
       | gpg --dearmor | tee /usr/share/keyrings/trivy.gpg > /dev/null \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb generic main" \
       | tee /etc/apt/sources.list.d/trivy.list \
    && wget -qO - https://packages.adoptium.net/artifactory/api/gpg/key/public \
       | gpg --dearmor | tee /usr/share/keyrings/adoptium.gpg > /dev/null \
    && echo "deb [signed-by=/usr/share/keyrings/adoptium.gpg] https://packages.adoptium.net/artifactory/deb bookworm main" \
       | tee /etc/apt/sources.list.d/adoptium.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
       nodejs \
       temurin-21-jdk \
       maven \
       trivy \
       git \
    && rm -rf /var/lib/apt/lists/*
ENV JAVA_HOME=/usr/lib/jvm/temurin-21-jdk-amd64
ENV PATH="${JAVA_HOME}/bin:${PATH}"

# ── Pre-warm Trivy vulnerability DB into the image ───────────────────────────
# Bakes the DB in at build time so scans never depend on runtime network
# access to ghcr.io (which may be blocked in the scan sandbox).
ENV TRIVY_CACHE_DIR=/opt/trivy-cache
RUN mkdir -p ${TRIVY_CACHE_DIR} \
    && trivy fs --download-db-only --cache-dir ${TRIVY_CACHE_DIR} --quiet \
    && chmod -R a+rwX ${TRIVY_CACHE_DIR}

# ── Python venvs + Semgrep assets ────────────────────────────────────────────
COPY --from=builder /opt/main-venv     /opt/main-venv
COPY --from=builder /opt/safety-venv   /opt/safety-venv
COPY --from=builder /opt/semgrep-rules /opt/semgrep-rules
COPY --from=builder /opt/semgrep-seed  /opt/semgrep-seed

# ── Native scanner binaries ───────────────────────────────────────────────────
COPY --from=builder /usr/local/bin/gitleaks    /usr/local/bin/gitleaks
COPY --from=builder /usr/local/bin/gosec       /usr/local/bin/gosec
COPY --from=builder /usr/local/bin/trufflehog  /usr/local/bin/trufflehog

# ── ESLint global modules ─────────────────────────────────────────────────────
COPY --from=builder /usr/lib/node_modules /usr/lib/node_modules
RUN ln -sf /usr/lib/node_modules/eslint/bin/eslint.js /usr/local/bin/eslint \
    && chmod +x /usr/lib/node_modules/eslint/bin/eslint.js

# ── OWASP Dependency-Check ────────────────────────────────────────────────────
COPY --from=builder /opt/dependency-check /opt/dependency-check
RUN ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check \
    && mkdir -p /opt/dependency-check/data

# ── Environment ───────────────────────────────────────────────────────────────
ENV PATH="/opt/main-venv/bin:/opt/safety-venv/bin:$PATH" \
    NODE_PATH="/usr/lib/node_modules" \
    DEPENDENCY_CHECK_DATA="/opt/dependency-check/data" \
    GIT_PYTHON_REFRESH=quiet

# ── Non-root scanner user ─────────────────────────────────────────────────────
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint.sh \
    && useradd --create-home --uid 10001 --shell /bin/bash scanner \
    && chown -R scanner:scanner /opt/dependency-check/data

USER scanner
WORKDIR /home/scanner
ENV HOME=/tmp/semgrep-home

# Copy backend application code
COPY --chown=scanner:scanner . /home/scanner/

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
