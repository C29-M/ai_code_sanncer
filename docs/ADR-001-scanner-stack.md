# ADR-001: Open-Source Scanner Stack Selection

**Status:** Accepted
**Date:** 2026-05-22
**Phase:** 2 (Foundation & Sandbox)

## Context

The AI Code Scanner must detect security vulnerabilities across multiple programming language stacks without introducing per-scan API costs, transmitting user code to third parties, or relying on proprietary LLM inference. The OSS Plan mandates ten battle-tested open-source scanners, organised by category and language coverage.

## Decision

The platform integrates the following ten scanners. Each is open-source under a permissive or weak-copyleft licence, runs offline inside the Phase 2 Docker sandbox, and exposes machine-readable output that can be normalised into the unified findings schema (Phase 3, Week 3).

| Scanner | Category | Language Coverage | Licence | Pinned Version | Phase Introduced |
|---|---|---|---|---|---|
| **Semgrep** | SAST | All (multilang) | LGPL-2.1 | 1.163.0 | 2 |
| **Gitleaks** | Secrets | All | MIT | TBD | 3 |
| **Trivy** | CVE (deps) | npm, pip, Maven, Go | Apache-2.0 | TBD | 3 |
| **Bandit** | SAST | Python | Apache-2.0 | TBD | 4 |
| **Safety** | CVE (deps) | Python | MIT | TBD | 4 |
| **ESLint Security** | SAST | JavaScript / TypeScript | Apache-2.0 (eslint) + MIT (plugin) | TBD | 4 |
| **Gosec** | SAST | Go | Apache-2.0 | TBD | 4 |
| **SpotBugs** | SAST | Java | LGPL-2.1 | TBD | 4 |
| **OWASP Dep-Check** | CVE (deps) | Java | Apache-2.0 | TBD | 4 |
| **TruffleHog** | Secrets (history) | Git | AGPL-3.0 | TBD | 4 |

Versions for scanners marked TBD will be pinned when integrated. The canonical version manifest lives at `scanner_versions.json` in the repository root.

## Rationale

**Why these ten scanners.** Each scanner targets a security concern that the others do not cover well:

- **Cross-language SAST** (Semgrep) gives broad pattern-based coverage from a single tool, reducing operational complexity. Semgrep's community rule pack is comprehensive enough to serve as the Phase 2 baseline.
- **Language-specific SAST** (Bandit, ESLint Security, Gosec, SpotBugs) catches per-language idioms Semgrep's generic patterns miss — e.g. SpotBugs' bytecode analysis of Java concurrency bugs, Bandit's AST-aware detection of Python deserialization sinks.
- **Secret detection** (Gitleaks + TruffleHog) covers both the working tree (Gitleaks) and historical commits (TruffleHog). Leaked credentials are the single most catastrophic class of finding; redundancy here is justified.
- **Dependency CVE scanning** (Trivy + Safety + OWASP Dep-Check) covers different package manifests with different precision: Trivy is broad and fast, Safety and OWASP Dep-Check are deeper for their respective ecosystems.

**Why no LLMs.** Per the OSS Plan: zero variable cost per scan, no data leaving the user's infrastructure, fully deterministic and auditable findings. Phase 5 introduces CodeBERT and VulBERTa from HuggingFace for classification — also OSS, on-premise, no external API.

**Why pin exact versions.** Scanner output is the foundation of the findings schema. Rule changes between minor versions can shift severity classifications and break downstream consumers. Pinned versions are upgraded deliberately, in pull requests, with regression tests.

## Licence Compatibility

The platform itself is intended to be released under a permissive licence. Scanners under copyleft licences (LGPL, AGPL) are invoked as subprocesses, not statically linked or modified — this is a clean boundary that does not trigger copyleft obligations on the platform code.

- **MIT / Apache-2.0 / BSD**: no constraints.
- **LGPL-2.1** (Semgrep, SpotBugs): no constraints under subprocess invocation.
- **AGPL-3.0** (TruffleHog): no constraints under subprocess invocation; specifically does not trigger network-service copyleft because TruffleHog runs locally on the scanned repo, not as a network-facing service.

## Version Pinning Strategy

1. Every scanner is pinned to an exact version in either `backend/requirements.txt` (Python tools) or the Dockerfile (system tools).
2. The canonical version manifest is `scanner_versions.json` at the repo root.
3. Upgrades happen in a single PR per scanner, with a regression test against a known-vulnerable fixture repo (DVWA, NodeGoat, DSVW). If a finding changes severity or disappears, the PR is rejected until the schema mapper is updated.
4. Pinning is checked in CI (`pip check` and `docker run <image> --version` comparison against `scanner_versions.json`).

## Consequences

**Positive.** Reproducible scans across environments. Clear provenance for every finding. No vendor lock-in. Future scanner additions slot into the same Dockerfile + manifest + schema pattern.

**Negative.** More moving parts than a single-tool approach. Each scanner brings its own output format that the unified normaliser (Phase 3) must support. Image size grows with each scanner — mitigated by the multi-stage Dockerfile (see Phase 2 sandbox notes).

## Status of Implementation

As of Phase 2:

- Semgrep is **integrated and operational** end-to-end.
- The Docker sandbox infrastructure is in place to host all ten scanners with no security regression (network isolation, read-only rootfs, dropped capabilities, resource caps, non-root user).
- The remaining nine scanners are **planned** per the phase schedule above. The version manifest, Dockerfile, and unified schema (Phase 3) are designed to absorb them without rework.
