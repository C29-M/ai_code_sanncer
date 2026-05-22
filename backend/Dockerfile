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
    && rm -rf /opt/semgrep-rules/.github \
              /opt/semgrep-rules/stats \
              /opt/semgrep-rules/scripts \
              /opt/semgrep-rules/bento \
              /opt/semgrep-rules/fingerprints \
              /opt/semgrep-rules/trusted_python \
              /opt/semgrep-rules/contrib

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

USER scanner
WORKDIR /home/scanner
ENV HOME=/tmp/semgrep-home

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["--help"]
