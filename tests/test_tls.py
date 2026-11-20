from datetime import datetime, timedelta, timezone

from conftest import make_ctx

from secscan.checks.tls import TLSCheck, evaluate

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _info(**overrides):
    info = {
        "port": 443,
        "reachable": True,
        "protocol": "TLSv1.3",
        "issuer": "Let's Encrypt",
        "subject": "example.com",
        "not_after": NOW + timedelta(days=90),
        "verify_error": None,
        "error": None,
    }
    info.update(overrides)
    return info


def _ids(findings):
    return {f.id for f in findings}


def test_healthy_certificate_has_no_findings():
    assert evaluate(_info(), NOW) == []


def test_expired_certificate():
    assert _ids(evaluate(_info(not_after=NOW - timedelta(days=1)), NOW)) == {"TLS-CERT-EXPIRED"}


def test_expiring_certificate():
    assert _ids(evaluate(_info(not_after=NOW + timedelta(days=10)), NOW)) == {"TLS-CERT-EXPIRING"}


def test_weak_protocol():
    assert _ids(evaluate(_info(protocol="TLSv1"), NOW)) == {"TLS-WEAK-PROTOCOL"}


def test_untrusted_certificate():
    info = _info(verify_error="self-signed certificate", not_after=None, protocol=None)
    assert _ids(evaluate(info, NOW)) == {"TLS-CERT-UNTRUSTED"}


def test_no_tls_service_is_not_a_finding(closed_port):
    result = TLSCheck().run(make_ctx(port=closed_port, scheme="https", timeout=1.0))
    assert result.findings == []
    assert result.data["reachable"] is False
    assert result.data["port"] == closed_port
    assert result.notes == [f"No TLS service answered on port {closed_port}."]
