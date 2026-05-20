# Semgrep scan sandbox image (Phase 2).
# Build: docker build -t ai-code-scanner-semgrep:latest -f Dockerfile .
#
# Runtime uses --network none. Registry configs like "auto" need semgrep.dev;
# this image therefore vendors the community rules tree at /opt/semgrep-rules
# so scans work fully offline. Override at run time with DOCKER_SEMGREP_CONFIG
# and DOCKER_SEMGREP_NETWORK if you need "auto" + outbound HTTPS.

FROM python:3.11-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir "semgrep>=1.90.0"

# Offline rule pack (filesystem path — no registry fetch at scan time).
RUN git clone --depth 1 https://github.com/semgrep/semgrep-rules.git /opt/semgrep-rules \
    && rm -f /opt/semgrep-rules/.pre-commit-config.yaml \
    && rm -rf /opt/semgrep-rules/.github

# Optional: warm ~/.semgrep for faster starts / fewer writes (build has network).
RUN mkdir -p /warm \
    && printf '# warm\nx = eval(input())\n' > /warm/insecure.py \
    && semgrep scan --config /opt/semgrep-rules --json /warm > /dev/null 2>&1 || true

RUN mkdir -p /opt/semgrep-seed \
    && if [ -d /root/.semgrep ]; then cp -a /root/.semgrep/. /opt/semgrep-seed/; fi \
    && chmod -R a+rX /opt/semgrep-seed /opt/semgrep-rules

COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod +x /usr/local/bin/docker-entrypoint.sh \
    && useradd --create-home --uid 10001 --shell /bin/bash scanner

USER scanner

WORKDIR /home/scanner

ENV HOME=/tmp/semgrep-home

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]

CMD ["--help"]