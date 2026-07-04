# AI Code Scanner

Paste a GitHub repo URL, get back a unified security report. Runs 10 open-source scanners in parallel — SAST, secrets, CVE detection, dependency analysis — all inside Docker. No paid APIs required.

## Requirements

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (everything else installs automatically inside the image)
- Git

## Quick start

```bash
git clone https://github.com/spoc-ai-org/spoc-security-scanners.git
cd spoc-security-scanners
```

**Windows:**
```
start.bat
```

**Mac / Linux:**
```bash
chmod +x start.sh
./start.sh
```

The first build takes 3–5 minutes (downloads all scanner binaries, Semgrep rule packs, ML models). After that `docker compose up` starts in seconds.

Open **http://localhost:8000** in your browser — paste any public GitHub repo URL and click Scan.

## Configuration (optional)

Copy `.env.example` to `.env` and fill in what you need:

```bash
cp .env.example .env
```

| Variable | Default | Purpose |
|---|---|---|
| `GITHUB_TOKEN` | unset | Scan **private** repos (needs `repo` scope) |
| `NVD_API_KEY` | unset | Speeds up OWASP Java dependency scan — [get a free key](https://nvd.nist.gov/developers/request-an-api-key) |
| `SCANNER_API_KEY` | unset | Require `X-Api-Key` header on `/scan` — leave empty for open access |

## Scan via API

```bash
# Public repo
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/OWASP/NodeGoat"}'

# Private repo
curl -X POST http://localhost:8000/scan \
  -H "Content-Type: application/json" \
  -d '{"repo_url": "https://github.com/your-org/private-repo", "github_token": "ghp_..."}'
```

## What's inside

| Scanner | Finds | Languages |
|---|---|---|
| Semgrep | SAST bugs | All |
| Gitleaks | Hardcoded secrets | All |
| Trivy | CVEs in dependencies | All |
| TruffleHog | Secrets in git history | All |
| Bandit | Python security bugs | Python |
| Safety | Python dependency CVEs | Python |
| ESLint + security plugin | JS/TS security bugs | JS / TS |
| Gosec | Go security bugs | Go |
| SpotBugs | Java bytecode bugs | Java |
| OWASP Dependency-Check | Java dependency CVEs | Java |

Scanners that don't apply to a repo's language are automatically skipped.

## Export

Click **Export as PDF** in the web UI to get a full report with:
- Fix-right-away section (critical findings first)
- Per-finding: what's wrong, what could happen, how to fix it, why it's rated that severity
- CVE findings include the affected package and the version to upgrade to

## Verify it's running

```bash
curl http://localhost:8000/health
# {"status":"ok"}
```

API docs: http://localhost:8000/docs

## Stop

```bash
docker compose down
```
