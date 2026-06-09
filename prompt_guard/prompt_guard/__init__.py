"""prompt_guard - AI Security Middleware for System Prompt Scanning."""

__version__ = "0.1.0"
__author__ = "AI Security Team"

from prompt_guard.scanner import scan_prompt, PromptScanner
from prompt_guard.config import ScanConfig, DEFAULT_CONFIG
from prompt_guard.findings import Finding, ScanResult

__all__ = [
    "scan_prompt",
    "PromptScanner",
    "ScanConfig",
    "DEFAULT_CONFIG",
    "Finding",
    "ScanResult",
    "__version__",
]
