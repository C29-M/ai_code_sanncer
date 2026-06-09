from typing import Any, Optional

from pydantic import BaseModel, Field, HttpUrl


class ScanRequest(BaseModel):
    repo_url: HttpUrl = Field(
        ...,
        description="GitHub repository URL (https://github.com/owner/repo)",
        examples=["https://github.com/OWASP/NodeGoat"],
    )
    github_token: Optional[str] = Field(
        None,
        description="GitHub personal access token for scanning private repositories",
    )


class ScanResponse(BaseModel):
    repo_url: str
    clone_path: str
    findings_count: int
    findings: list[dict[str, Any]]  # unified findings — one schema for all scanners
    scanner_status: dict[str, str]  # {tool: "active" | "skipped" | "na"}
    scanners_active: list[str] = []
    findings_by_severity: dict[str, int] = {}
    warnings: list[str] = []
    scan_time_s: float = 0.0
    # Week 5 — classifier enrichment metadata
    classifier_available: bool = False
    classifier_enriched_count: int = 0
