# Docker sandbox (Phase 2)

## Build the scanner image

```bash
cd backend
docker build -t ai-code-scanner-semgrep:latest -f Dockerfile .
```

## Why `network none` + `auto` fails

`--config auto` (and `p/...`, `r/...`) fetch rules from **semgrep.dev**. With **`DOCKER_SEMGREP_NETWORK=none`**, the container has no DNS or egress, so those configs fail.

This image clones **community rules** into **`/opt/semgrep-rules`**. The API defaults to that path in Docker so scans work offline.

## Environment variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `SEMGREP_USE_DOCKER` | `true` | Use Docker for scans |
| `DOCKER_SEMGREP_IMAGE` | `ai-code-scanner-semgrep:latest` | Image name |
| `DOCKER_SEMGREP_CONFIG` | `/opt/semgrep-rules` | Semgrep `--config` (absolute path in container for offline) |
| `DOCKER_SEMGREP_NETWORK` | `none` | `none`, `bridge`, or `host` |
| `DOCKER_SEMGREP_MEMORY` | `2g` | `--memory` |
| `DOCKER_SEMGREP_MEMORY_SWAP` | `2g` | `--memory-swap` |
| `DOCKER_SEMGREP_CPUS` | `1` | `--cpus` |

**Registry rules:** `DOCKER_SEMGREP_NETWORK=bridge` and `DOCKER_SEMGREP_CONFIG=auto` (or another registry id).
