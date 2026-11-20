import json
from datetime import datetime, timezone

from secscan.models import CheckResult, Finding, ScanResult, Severity
from secscan.reporting import render_html, write_json

PAYLOAD = "<script>alert(1)</script>"


def _hostile_scan():
    """A scan whose data was supplied by a malicious server."""
    ports = CheckResult(
        check="ports",
        title="Open ports",
        data={"scanned": 1, "open": [{"port": 21, "service": "FTP", "banner": PAYLOAD}]},
    )
    headers = CheckResult(
        check="headers",
        title="HTTP security headers",
        data={
            "url": "https://x/",
            "final_url": "https://x/",
            "status_code": 200,
            "present": {"Content-Security-Policy": PAYLOAD},
            "missing": [],
        },
        findings=[
            Finding(
                id="HEADER-DISCLOSURE-SERVER",
                title="Server header discloses software",
                severity=Severity.LOW,
                evidence=f"Server: {PAYLOAD}",
            )
        ],
    )
    return ScanResult(
        target="x",
        address="127.0.0.1",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, 0, 0, 3, tzinfo=timezone.utc),
        results=[ports, headers],
    )


def test_html_report_escapes_scanned_data():
    html = render_html(_hostile_scan())
    assert PAYLOAD not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_html_report_handles_failed_check():
    scan = _hostile_scan()
    scan.results.append(CheckResult(check="tls", title="TLS certificate", error="boom"))
    assert "Check could not complete: boom" in render_html(scan)


def test_json_report(tmp_path):
    path = write_json(_hostile_scan(), tmp_path / "r.json")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["tool"] == "secscan"
    assert data["summary"]["low"] == 1
    assert [c["check"] for c in data["checks"]] == ["ports", "headers"]
