from conftest import make_ctx

from secscan.checks.ports import PortCheck, findings_for_port
from secscan.models import Severity


def test_detects_open_and_closed_ports(listening_port, closed_port):
    ctx = make_ctx(ports={listening_port: "Test", closed_port: "Closed"}, connect_timeout=0.5)
    result = PortCheck().run(ctx)

    assert result.error is None
    assert result.data["scanned"] == 2
    assert [p["port"] for p in result.data["open"]] == [listening_port]
    assert result.data["open"][0]["service"] == "Test"


def test_risky_port_produces_finding():
    [finding] = findings_for_port(23, "Telnet")
    assert finding.id == "PORT-EXPOSED-23"
    assert finding.severity is Severity.HIGH


def test_ordinary_port_produces_no_finding():
    assert findings_for_port(443, "HTTPS") == []
