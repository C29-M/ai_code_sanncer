<<<<<<< Updated upstream
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


class RepoTooLargeError(ScannerError):
    def __init__(
        self, message: str = "Repository exceeds the maximum allowed size."
    ) -> None:
        super().__init__(message, status_code=413)


class SemgrepScanError(ScannerError):
    def __init__(self, message: str = "Semgrep scan failed.") -> None:
        super().__init__(message, status_code=500)
=======
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


class ConfigError(ScannerError):
    def __init__(self, message: str = "Invalid configuration.") -> None:
        super().__init__(message, status_code=400)


class TimeoutError(ScannerError):
    def __init__(self, message: str = "Operation timed out.") -> None:
        super().__init__(message, status_code=504)


class RepoTooLargeError(ScannerError):
    def __init__(self, message: str = "Repository is too large to scan.") -> None:
        super().__init__(message, status_code=413)


class GitleaksScanError(ScannerError):
    def __init__(self, message: str = "Gitleaks scan failed.") -> None:
        super().__init__(message, status_code=500)


class TrivyScanError(ScannerError):
    def __init__(self, message: str = "Trivy scan failed.") -> None:
        super().__init__(message, status_code=500)
>>>>>>> Stashed changes
