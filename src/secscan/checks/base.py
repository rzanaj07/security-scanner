"""The interface every check implements, and the context it runs in."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import ClassVar

from secscan.models import CheckResult
from secscan.target import Target


@dataclass
class ScanConfig:
    connect_timeout: float = 1.0  # per-port TCP connect timeout
    timeout: float = 6.0  # TLS handshake / HTTP request timeout
    workers: int = 50
    ports: dict[int, str] | None = None  # None = the default common-port list


@dataclass
class ScanContext:
    target: Target
    config: ScanConfig
    results: dict[str, CheckResult] = field(default_factory=dict)  # earlier checks, by name


class Check(ABC):
    name: ClassVar[str]
    title: ClassVar[str]

    @abstractmethod
    def run(self, ctx: ScanContext) -> CheckResult:
        """Run the check. Raise only on bugs; report expected failures in CheckResult.error."""

    def result(self) -> CheckResult:
        """An empty result pre-filled with this check's name and title."""
        return CheckResult(check=self.name, title=self.title)
