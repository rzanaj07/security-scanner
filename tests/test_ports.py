import socket

import pytest
from conftest import make_ctx

from secscan.checks.base import ScanConfig, ScanContext
from secscan.checks.ports import (
    COMMON_PORTS,
    PortCheck,
    PortSpecError,
    findings_for_port,
    parse_port_spec,
)
from secscan.models import Severity
from secscan.target import Target


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


# ---------------------------------------------------------------- port specs


def test_port_spec_common():
    assert parse_port_spec("common") == COMMON_PORTS


def test_port_spec_ranges_and_lists():
    ports = parse_port_spec("22, 80,8000-8002")
    assert list(ports) == [22, 80, 8000, 8001, 8002]
    assert ports[22] == "SSH"


def test_port_spec_mixed_with_common():
    ports = parse_port_spec("common,3000")
    assert 3000 in ports and 22 in ports


def test_port_spec_all():
    assert len(parse_port_spec("all")) == 65535


@pytest.mark.parametrize("spec", ["", "abc", "0", "70000", "100-10", "1-2-3", ","])
def test_port_spec_rejects_bad_input(spec):
    with pytest.raises(PortSpecError):
        parse_port_spec(spec)


def test_scan_over_ipv6():
    if not socket.has_ipv6:
        pytest.skip("no IPv6")
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.bind(("::1", 0))
    except OSError:
        pytest.skip("IPv6 loopback not available")
    with sock:
        sock.listen()
        port = sock.getsockname()[1]
        ctx = ScanContext(
            target=Target(host="::1", address="::1"),
            config=ScanConfig(ports={port: "Test"}, connect_timeout=0.5),
        )
        result = PortCheck().run(ctx)
    assert [p["port"] for p in result.data["open"]] == [port]
