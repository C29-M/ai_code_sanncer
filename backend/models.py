from pydantic import BaseModel, Field, HttpUrl


class ScanRequest(BaseModel):
    repo_url: HttpUrl = Field(
        ...,
        description="Public GitHub repository URL (https://github.com/owner/repo)",
        examples=["https://github.com/returntocorp/semgrep-rules"],
    )


class ScanResponse(BaseModel):
    repo_url: str
    clone_path: str
    findings_count: int
    findings: dict
