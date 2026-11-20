"""Data model shared by every check and report: findings, check results, scan results."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any


class Severity(str, Enum):
    """Finding severity, ordered from least to most severe."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)

    def __str__(self) -> str:
        return self.value


@dataclass
class Finding:
    """A single security issue discovered by a check."""

    id: str
    title: str
    severity: Severity
    description: str = ""
    evidence: str | None = None
    recommendation: str = ""
    references: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "recommendation": self.recommendation,
            "references": list(self.references),
        }


@dataclass
class CheckResult:
    """Output of one check: raw data for the report, findings, and an error if it failed."""

    check: str
    title: str
    data: dict[str, Any] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    error: str | None = None
    notes: list[str] = field(default_factory=list)  # neutral remarks, not findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "title": self.title,
            "data": self.data,
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "notes": list(self.notes),
        }


@dataclass
class ScanResult:
    """Everything produced by one scan of one target."""

    target: str
    address: str
    started_at: datetime
    finished_at: datetime | None = None
    results: list[CheckResult] = field(default_factory=list)

    @property
    def findings(self) -> list[Finding]:
        """All findings across checks, most severe first."""
        all_findings = [f for r in self.results for f in r.findings]
        return sorted(all_findings, key=lambda f: f.severity.rank, reverse=True)

    def severity_counts(self) -> dict[str, int]:
        """Number of findings per severity, most severe first."""
        counts = {s.value: 0 for s in reversed(Severity)}
        for f in self.findings:
            counts[f.severity.value] += 1
        return counts

    def highest_severity(self) -> Severity | None:
        findings = self.findings
        return findings[0].severity if findings else None

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "address": self.address,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "summary": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
            "checks": [r.to_dict() for r in self.results],
        }
