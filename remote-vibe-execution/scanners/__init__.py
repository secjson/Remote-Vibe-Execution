"""Base scanner interface."""

from __future__ import annotations
from abc import ABC, abstractmethod
from scanner.config import ScanConfig
from scanner.models import Finding


class BaseScanner(ABC):
    """Abstract base class for all scanners."""

    name: str = "base"

    def __init__(self, config: ScanConfig):
        self.config = config

    @abstractmethod
    def scan(self, repo_path: str, **kwargs) -> list[Finding]:
        """Run the scan and return findings."""
        ...

    def is_available(self) -> bool:
        """Check if this scanner's dependencies are installed."""
        return True
