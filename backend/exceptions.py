"""Application-specific exceptions for the code scanner API."""


class ScannerError(Exception):
    """Base exception for scanner operations."""

    def __init__(self, message: str, status_code: int = 500) -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code


class InvalidRepoUrlError(ScannerError):
    def __init__(self, message: str = "Invalid or unsupported repository URL.") -> None:
        super().__init__(message, status_code=400)


class RepoCloneError(ScannerError):
    def __init__(self, message: str = "Failed to clone repository.") -> None:
        super().__init__(message, status_code=502)


class SemgrepScanError(ScannerError):
    def __init__(self, message: str = "Semgrep scan failed.") -> None:
        super().__init__(message, status_code=500)
