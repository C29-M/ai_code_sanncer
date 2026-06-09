from __future__ import annotations

import concurrent.futures
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, Type

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Domain types (Finding and ScannerStatus) are defined here because models.py
# does not yet expose them.  All other modules should import from this file.
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"


@dataclass
class Finding:
    """Unified finding schema shared by every scanner."""

    scanner: str
    rule_id: str
    title: str
    severity: Severity = Severity.UNKNOWN
    description: str = ""
    file_path: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    cwe: Optional[str] = None
    cve: Optional[str] = None
    confidence: Optional[str] = None
    remediation: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scanner": self.scanner,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "file_path": self.file_path,
            "line_start": self.line_start,
            "line_end": self.line_end,
            "cwe": self.cwe,
            "cve": self.cve,
            "confidence": self.confidence,
            "remediation": self.remediation,
        }


class ScannerStatusEnum(str, Enum):
    ACTIVE = "active"
    UNAVAILABLE = "unavailable"
    ERROR = "error"


@dataclass
class ScannerStatus:
    name: str
    version: Optional[str]
    available: bool
    status: ScannerStatusEnum

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "version": self.version,
            "available": self.available,
            "status": self.status.value,
        }


# ---------------------------------------------------------------------------
# Abstract base class
# ---------------------------------------------------------------------------


class BaseScanner(ABC):
    """Abstract base class that every scanner plugin must implement."""

    # ------------------------------------------------------------------
    # Abstract interface
    # ------------------------------------------------------------------

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable, unique scanner name (e.g. 'bandit', 'trivy')."""

    @property
    @abstractmethod
    def version(self) -> str:
        """Version string of the underlying tool (e.g. '1.7.5')."""

    @abstractmethod
    def is_available(self) -> bool:
        """Return True when the underlying tool is installed and executable."""

    @abstractmethod
    def scan(self, target: str, **kwargs: Any) -> List[Finding]:
        """Run the scanner against *target* (a filesystem path or URL).

        Parameters
        ----------
        target:
            The path to the repository / file to scan, or a URL depending on
            the scanner implementation.
        **kwargs:
            Scanner-specific options forwarded from the caller.

        Returns
        -------
        List[Finding]
            Zero or more findings produced by this scanner.
        """

    # ------------------------------------------------------------------
    # Concrete helpers
    # ------------------------------------------------------------------

    def safe_scan(
        self,
        target: str,
        timeout: int = 30,
        **kwargs: Any,
    ) -> Tuple[List[Finding], Optional[str]]:
        """Wrap :meth:`scan` with a wall-clock timeout and exception handling.

        Parameters
        ----------
        target:
            Forwarded verbatim to :meth:`scan`.
        timeout:
            Maximum seconds to wait for :meth:`scan` to complete.
        **kwargs:
            Forwarded verbatim to :meth:`scan`.

        Returns
        -------
        (findings, error_message)
            *findings* is an empty list when an error occurs.
            *error_message* is ``None`` on success.
        """
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            future = executor.submit(self.scan, target, **kwargs)
            try:
                findings = future.result(timeout=timeout)
                return findings, None
            except concurrent.futures.TimeoutError:
                msg = (
                    f"Scanner '{self.name}' timed out after {timeout}s "
                    f"on target '{target}'"
                )
                logger.warning(msg)
                return [], msg
            except Exception as exc:  # noqa: BLE001
                msg = f"Scanner '{self.name}' raised an unexpected error: {exc}"
                logger.exception(msg)
                return [], msg

    def get_status(self) -> ScannerStatus:
        """Return a :class:`ScannerStatus` snapshot for this scanner."""
        try:
            available = self.is_available()
            version: Optional[str]
            try:
                version = self.version
            except Exception:  # noqa: BLE001
                version = None
            status = (
                ScannerStatusEnum.ACTIVE if available else ScannerStatusEnum.UNAVAILABLE
            )
        except Exception as exc:  # noqa: BLE001
            logger.debug("get_status failed for %s: %s", type(self).__name__, exc)
            available = False
            version = None
            status = ScannerStatusEnum.ERROR

        return ScannerStatus(
            name=self.name,
            version=version,
            available=available,
            status=status,
        )


# ---------------------------------------------------------------------------
# Scanner registry
# ---------------------------------------------------------------------------


class ScannerRegistry:
    """Central registry that maps scanner names to singleton instances."""

    _registry: Dict[str, BaseScanner] = {}

    # ------------------------------------------------------------------
    # Registration
    # ------------------------------------------------------------------

    @classmethod
    def register(cls, scanner_cls: Type[BaseScanner]) -> Type[BaseScanner]:
        """Instantiate *scanner_cls* and add it to the registry.

        Can be used as a class decorator::

            @ScannerRegistry.register
            class MyScanner(BaseScanner):
                ...

        Parameters
        ----------
        scanner_cls:
            A concrete subclass of :class:`BaseScanner`.

        Returns
        -------
        Type[BaseScanner]
            The same class, unmodified (allows decorator usage).

        Raises
        ------
        TypeError
            If *scanner_cls* is not a subclass of :class:`BaseScanner`.
        """
        if not (isinstance(scanner_cls, type) and issubclass(scanner_cls, BaseScanner)):
            raise TypeError(
                f"register() expects a BaseScanner subclass, got {scanner_cls!r}"
            )
        instance: BaseScanner = scanner_cls()
        cls._registry[instance.name] = instance
        logger.debug("Registered scanner: %s", instance.name)
        return scanner_cls

    # ------------------------------------------------------------------
    # Queries
    # ------------------------------------------------------------------

    @classmethod
    def get_all(cls) -> List[BaseScanner]:
        """Return all registered scanner instances regardless of availability."""
        return list(cls._registry.values())

    @classmethod
    def get_available(cls) -> List[BaseScanner]:
        """Return only those registered scanners that report :meth:`is_available` as True."""
        available: List[BaseScanner] = []
        for scanner in cls._registry.values():
            try:
                if scanner.is_available():
                    available.append(scanner)
            except Exception as exc:  # noqa: BLE001
                logger.warning(
                    "is_available() raised for scanner '%s': %s", scanner.name, exc
                )
        return available

    @classmethod
    def get_by_name(cls, name: str) -> Optional[BaseScanner]:
        """Return the scanner registered under *name*, or ``None`` if not found."""
        return cls._registry.get(name)
