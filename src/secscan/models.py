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


# Points deducted from a perfect score of 100 for each finding of a severity.
SEVERITY_PENALTY: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 20,
    Severity.MEDIUM: 8,
    Severity.LOW: 3,
    Severity.INFO: 0,
}


def grade_for(score: int) -> str:
    """Letter grade for a 0-100 security score."""
    for threshold, letter in ((90, "A"), (75, "B"), (60, "C"), (40, "D")):
        if score >= threshold:
            return letter
    return "F"


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

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> Finding:
        return cls(
            id=d["id"],
            title=d["title"],
            severity=Severity(d["severity"]),
            description=d.get("description", ""),
            evidence=d.get("evidence"),
            recommendation=d.get("recommendation", ""),
            references=list(d.get("references", [])),
        )


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

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> CheckResult:
        return cls(
            check=d["check"],
            title=d["title"],
            data=dict(d.get("data", {})),
            findings=[Finding.from_dict(f) for f in d.get("findings", [])],
            error=d.get("error"),
            notes=list(d.get("notes", [])),
        )


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

    def score(self) -> int:
        """Security score from 0 (worst) to 100 (no deductions)."""
        return max(0, 100 - sum(SEVERITY_PENALTY[f.severity] for f in self.findings))

    def grade(self) -> str:
        return grade_for(self.score())

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "address": self.address,
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat() if self.finished_at else None,
            "score": self.score(),
            "grade": self.grade(),
            "summary": self.severity_counts(),
            "findings": [f.to_dict() for f in self.findings],
            "checks": [r.to_dict() for r in self.results],
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> ScanResult:
        finished = d.get("finished_at")
        return cls(
            target=d["target"],
            address=d["address"],
            started_at=datetime.fromisoformat(d["started_at"]),
            finished_at=datetime.fromisoformat(finished) if finished else None,
            results=[CheckResult.from_dict(c) for c in d.get("checks", [])],
        )
