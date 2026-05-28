from typing import Any

from pydantic import BaseModel, Field, HttpUrl


class ScanRequest(BaseModel):
    repo_url: HttpUrl = Field(
        ...,
        description="Public GitHub repository URL (https://github.com/owner/repo)",
        examples=["https://github.com/OWASP/NodeGoat"],
    )


class ScanResponse(BaseModel):
    repo_url: str
    clone_path: str
    findings_count: int
    findings: list[dict[str, Any]]  # unified findings — one schema for all scanners
    scanner_summary: dict[str, int]  # {tool: finding_count}
    scanner_status: dict[str, str]  # {tool: "ok" | "skipped"}
