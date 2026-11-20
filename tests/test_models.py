import json
from datetime import datetime, timezone

from secscan.models import CheckResult, Finding, ScanResult, Severity


def _scan(*severities):
    findings = [Finding(id=f"F{i}", title="t", severity=s) for i, s in enumerate(severities)]
    return ScanResult(
        target="h",
        address="127.0.0.1",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        results=[CheckResult(check="c", title="C", findings=findings)],
    )


def test_severity_order():
    assert Severity.INFO.rank < Severity.LOW.rank < Severity.MEDIUM.rank
    assert Severity.MEDIUM.rank < Severity.HIGH.rank < Severity.CRITICAL.rank


def test_findings_sorted_most_severe_first():
    scan = _scan(Severity.LOW, Severity.HIGH, Severity.INFO)
    assert [f.severity for f in scan.findings] == [Severity.HIGH, Severity.LOW, Severity.INFO]
    assert scan.highest_severity() is Severity.HIGH


def test_severity_counts():
    counts = _scan(Severity.LOW, Severity.LOW, Severity.HIGH).severity_counts()
    assert counts == {"critical": 0, "high": 1, "medium": 0, "low": 2, "info": 0}
    assert list(counts) == ["critical", "high", "medium", "low", "info"]


def test_no_findings():
    assert _scan().highest_severity() is None


def test_to_dict_is_json_serializable():
    data = json.loads(json.dumps(_scan(Severity.MEDIUM).to_dict()))
    assert data["findings"][0]["severity"] == "medium"
    assert data["summary"]["medium"] == 1
