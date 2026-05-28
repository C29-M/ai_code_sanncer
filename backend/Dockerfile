<<<<<<< Updated upstream
# Multi-stage Semgrep sandbox image (Phase 2, OSS Plan Week 2).
# Build:  docker build -t ai-code-scanner-semgrep:latest -f Dockerfile .
#
# Stage 1 (builder): full toolchain — git, build deps, pip — used to install
#                    Semgrep and clone the offline rule pack.
# Stage 2 (runtime): slim, non-root, read-only-friendly. Only ships the runtime
#                    Python interpreter and the assets the builder produced.

# ---------- Stage 1: builder ----------
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Build-time tools: git for cloning the rule pack, ca-certificates for HTTPS.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Semgrep into /opt/venv so the runtime stage can copy it as a whole.
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install "semgrep==1.163.0"

# Vendor the community rule pack at /opt/semgrep-rules. Strip non-rule data
# directories so a top-level scan doesn't choke on YAMLs missing a `rules:` key.
RUN git clone --depth 1 https://github.com/semgrep/semgrep-rules.git /opt/semgrep-rules \
    && rm -f /opt/semgrep-rules/.pre-commit-config.yaml \
=======
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
#   Java SAST        : SpotBugs via mvn spotbugs plugin (JDK 17 + Maven 3)
#   Java SCA         : OWASP Dependency-Check CLI       (v9.2.0, JRE 17)
#
# Stage 1 (builder): downloads/installs everything.
# Stage 2 (runtime): lean final image — copies artifacts, installs runtime apt deps.

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
       git ca-certificates curl unzip gnupg \
    && rm -rf /var/lib/apt/lists/*

# ── Node 20 (ESLint) ─────────────────────────────────────────────────────────
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── Java 17 JDK (pre-warm OWASP NVD DB during build) ────────────────────────
RUN apt-get update \
    && apt-get install -y --no-install-recommends default-jdk-headless \
    && rm -rf /var/lib/apt/lists/*

# ── Python scanners — two venvs to avoid pydantic version conflict ────────────
# semgrep 1.163+ pulls mcp which needs pydantic>=2.11; safety needs pydantic<2.10.
# Solution: semgrep+bandit share /opt/main-venv; safety gets its own /opt/safety-venv.
RUN python -m venv /opt/main-venv
ENV PATH="/opt/main-venv/bin:$PATH"
RUN pip install \
        "semgrep==1.163.0" \
        "bandit[toml]==1.8.3"

RUN python -m venv /opt/safety-venv
RUN /opt/safety-venv/bin/pip install "safety==3.5.2" "typer>=0.12.1,<0.13.0"

# ── Semgrep offline rule pack ─────────────────────────────────────────────────
RUN git clone --depth 1 https://github.com/semgrep/semgrep-rules.git /opt/semgrep-rules \
    && rm -f  /opt/semgrep-rules/.pre-commit-config.yaml \
>>>>>>> Stashed changes
    && rm -rf /opt/semgrep-rules/.github \
              /opt/semgrep-rules/stats \
              /opt/semgrep-rules/scripts \
              /opt/semgrep-rules/bento \
              /opt/semgrep-rules/fingerprints \
              /opt/semgrep-rules/trusted_python \
              /opt/semgrep-rules/contrib

<<<<<<< Updated upstream
# Warm Semgrep's per-user state so first scan is faster (build has network).
RUN mkdir -p /warm \
    && printf '# warm\nx = eval(input())\n' > /warm/insecure.py \
    && semgrep scan --config /opt/semgrep-rules/python --json /warm > /dev/null 2>&1 || true

RUN mkdir -p /opt/semgrep-seed \
    && if [ -d /root/.semgrep ]; then cp -a /root/.semgrep/. /opt/semgrep-seed/; fi \
    && chmod -R a+rX /opt/semgrep-seed /opt/semgrep-rules

# ---------- Stage 2: runtime ----------
FROM python:3.11-slim-bookworm AS runtime

# Runtime needs: ca-certificates (for any allowed HTTPS), nothing else heavy.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Pull in the prebuilt venv, vendored rules, and seed cache from the builder.
COPY --from=builder /opt/venv          /opt/venv
COPY --from=builder /opt/semgrep-rules /opt/semgrep-rules
COPY --from=builder /opt/semgrep-seed  /opt/semgrep-seed

ENV PATH="/opt/venv/bin:$PATH"

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint.sh \
    && useradd --create-home --uid 10001 --shell /bin/bash scanner
=======
# ── Warm Semgrep cache ────────────────────────────────────────────────────────
RUN mkdir -p /warm \
    && printf '# warm\nx = eval(input())\n' > /warm/insecure.py \
    && semgrep scan --config /opt/semgrep-rules/python --json /warm > /dev/null 2>&1 || true \
    && mkdir -p /opt/semgrep-seed \
    && if [ -d /root/.semgrep ]; then cp -a /root/.semgrep/. /opt/semgrep-seed/; fi \
    && chmod -R a+rX /opt/semgrep-seed /opt/semgrep-rules

# ── Gitleaks v8.27.2 ─────────────────────────────────────────────────────────
RUN curl -sSL \
      "https://github.com/gitleaks/gitleaks/releases/download/v8.27.2/gitleaks_8.27.2_linux_x64.tar.gz" \
      | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# ── Trivy v0.70.0 ────────────────────────────────────────────────────────────
RUN curl -sSL \
      "https://github.com/aquasecurity/trivy/releases/download/v0.70.0/trivy_0.70.0_Linux-64bit.tar.gz" \
      | tar -xz -C /usr/local/bin trivy \
    && chmod +x /usr/local/bin/trivy

# ── Gosec v2.21.4 ────────────────────────────────────────────────────────────
RUN curl -sSL \
      "https://github.com/securego/gosec/releases/download/v2.21.4/gosec_2.21.4_linux_amd64.tar.gz" \
      | tar -xz -C /usr/local/bin gosec \
    && chmod +x /usr/local/bin/gosec

# ── TruffleHog v3.88.28 (official Go binary) ─────────────────────────────────
RUN curl -sSL \
      "https://github.com/trufflesecurity/trufflehog/releases/download/v3.88.28/trufflehog_3.88.28_linux_amd64.tar.gz" \
      | tar -xz -C /usr/local/bin trufflehog \
    && chmod +x /usr/local/bin/trufflehog

# ── ESLint 8 + eslint-plugin-security 3 (global npm) ────────────────────────
RUN npm install -g eslint@8 eslint-plugin-security@3 \
    && eslint --version

# ── OWASP Dependency-Check v9.2.0 ────────────────────────────────────────────
RUN curl -sSL \
      "https://github.com/jeremylong/DependencyCheck/releases/download/v9.2.0/dependency-check-9.2.0-release.zip" \
      -o /tmp/depcheck.zip \
    && unzip -q /tmp/depcheck.zip -d /opt/ \
    && rm /tmp/depcheck.zip \
    && chmod +x /opt/dependency-check/bin/dependency-check.sh

# ── Pre-warm OWASP NVD database (optional — supply --build-arg NVD_API_KEY) ──
# Without an API key, the NVD DB is downloaded automatically on the first scan
# (~2-5 min). Providing the key during docker build bakes the DB into the image
# so every subsequent scan starts instantly.
RUN if [ -n "${NVD_API_KEY}" ]; then \
      echo "Pre-warming OWASP NVD database with API key..." \
      && /opt/dependency-check/bin/dependency-check.sh \
           --updateonly \
           --nvdApiKey "${NVD_API_KEY}" || true; \
    else \
      echo "NVD_API_KEY not set — NVD DB will download on first scan (~2-5 min)."; \
    fi

# ═══════════════════════════ Stage 2: runtime ═══════════════════════════════
FROM python:3.11-slim-bookworm AS runtime

ENV DEBIAN_FRONTEND=noninteractive

# ── Runtime system packages ───────────────────────────────────────────────────
# Node 20  : ESLint runner
# JDK 17   : SpotBugs (needs javac to compile) + OWASP (needs java to run)
# Maven 3  : SpotBugs runner calls `mvn spotbugs:spotbugs`
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg \
    && curl -fsSL https://deb.nodesource.com/setup_20.x | bash - \
    && apt-get install -y --no-install-recommends \
       nodejs \
       default-jdk-headless \
       maven \
    && rm -rf /var/lib/apt/lists/*

# ── Python venv + Semgrep assets ─────────────────────────────────────────────
COPY --from=builder /opt/main-venv     /opt/main-venv
COPY --from=builder /opt/safety-venv   /opt/safety-venv
COPY --from=builder /opt/semgrep-rules /opt/semgrep-rules
COPY --from=builder /opt/semgrep-seed  /opt/semgrep-seed

# ── Native scanner binaries ───────────────────────────────────────────────────
COPY --from=builder /usr/local/bin/gitleaks /usr/local/bin/gitleaks
COPY --from=builder /usr/local/bin/trivy    /usr/local/bin/trivy
COPY --from=builder /usr/local/bin/gosec        /usr/local/bin/gosec
COPY --from=builder /usr/local/bin/trufflehog   /usr/local/bin/trufflehog

# ── ESLint global modules ─────────────────────────────────────────────────────
COPY --from=builder /usr/lib/node_modules /usr/lib/node_modules
# Re-create the symlink rather than copying the dereferenced file — the eslint.js
# entrypoint uses require('../package.json') which only resolves correctly when
# run via a symlink whose target sits inside the eslint package directory.
RUN ln -sf /usr/lib/node_modules/eslint/bin/eslint.js /usr/local/bin/eslint \
    && chmod +x /usr/lib/node_modules/eslint/bin/eslint.js

# ── OWASP Dependency-Check ────────────────────────────────────────────────────
COPY --from=builder /opt/dependency-check /opt/dependency-check
RUN ln -s /opt/dependency-check/bin/dependency-check.sh /usr/local/bin/dependency-check \
    && mkdir -p /opt/dependency-check/data

# ── Environment ───────────────────────────────────────────────────────────────
ENV PATH="/opt/main-venv/bin:/opt/safety-venv/bin:$PATH" \
    NODE_PATH="/usr/lib/node_modules" \
    DEPENDENCY_CHECK_DATA="/opt/dependency-check/data"

# ── Non-root scanner user ─────────────────────────────────────────────────────
COPY backend/docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN sed -i 's/\r$//' /usr/local/bin/docker-entrypoint.sh \
    && chmod +x /usr/local/bin/docker-entrypoint.sh \
    && useradd --create-home --uid 10001 --shell /bin/bash scanner \
    && chown -R scanner:scanner /opt/dependency-check/data
>>>>>>> Stashed changes

USER scanner
WORKDIR /home/scanner
ENV HOME=/tmp/semgrep-home

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
