import ssl
from datetime import datetime, timedelta, timezone

import pytest
from conftest import make_cert, make_ctx, serve_tls

from secscan.checks.tls import (
    REJECTED,
    SUPPORTED,
    UNTESTED,
    TLSCheck,
    analyze_endpoint,
    evaluate,
    tls_ports_for,
)
from secscan.models import CheckResult, Severity

NOW = datetime(2026, 6, 1, tzinfo=timezone.utc)


def _ep(**overrides):
    ep = {
        "port": 443,
        "reachable": True,
        "error": None,
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "protocols": {
            "SSLv3": REJECTED,
            "TLSv1": REJECTED,
            "TLSv1.1": REJECTED,
            "TLSv1.2": SUPPORTED,
            "TLSv1.3": SUPPORTED,
        },
        "weak_cipher": REJECTED,
        "weak_cipher_name": None,
        "certificate": {
            "subject": "example.com",
            "issuer": "Let's Encrypt",
            "sans": ["example.com"],
            "not_before": NOW - timedelta(days=10),
            "not_after": NOW + timedelta(days=80),
            "key_type": "RSA",
            "key_bits": 2048,
            "signature": "sha256",
            "self_signed": False,
            "serial": "1",
        },
        "verify_code": None,
        "verification": "trusted",
    }
    ep.update(overrides)
    return ep


def _cert(**overrides):
    cert = dict(_ep()["certificate"])
    cert.update(overrides)
    return cert


def _ids(findings):
    return {f.id.split(":")[0] for f in findings}


# ---------------------------------------------------------------- evaluate (pure)


def test_healthy_endpoint_has_no_findings():
    assert evaluate(_ep(), NOW) == []


def test_unreachable_endpoint_has_no_findings():
    assert evaluate(_ep(reachable=False), NOW) == []


def test_finding_ids_include_port():
    [finding] = evaluate(_ep(port=8443, verify_code=20, verification="bad chain"), NOW)
    assert finding.id == "TLS-CERT-UNTRUSTED:8443"


@pytest.mark.parametrize(
    ("ep", "expected"),
    [
        ({"verify_code": 18, "verification": "self-signed"}, "TLS-CERT-SELF-SIGNED"),
        ({"verify_code": 20, "verification": "unable to get issuer"}, "TLS-CERT-UNTRUSTED"),
        ({"verify_code": 62, "verification": "Hostname mismatch"}, "TLS-CERT-HOSTNAME-MISMATCH"),
        ({"certificate": _cert(not_after=NOW - timedelta(days=3))}, "TLS-CERT-EXPIRED"),
        ({"certificate": _cert(not_after=NOW + timedelta(days=9))}, "TLS-CERT-EXPIRING"),
        ({"certificate": _cert(not_before=NOW + timedelta(days=2))}, "TLS-CERT-NOT-YET-VALID"),
        ({"certificate": _cert(key_bits=1024)}, "TLS-WEAK-KEY"),
        ({"certificate": _cert(key_type="EC secp192r1", key_bits=192)}, "TLS-WEAK-KEY"),
        ({"certificate": _cert(signature="sha1")}, "TLS-WEAK-SIGNATURE"),
        ({"weak_cipher": SUPPORTED, "weak_cipher_name": "DES-CBC3-SHA"}, "TLS-WEAK-CIPHER"),
    ],
)
def test_single_issue(ep, expected):
    assert _ids(evaluate(_ep(**ep), NOW)) == {expected}


def test_expired_verify_code_is_reported_once_with_date():
    ep = _ep(
        verify_code=10,
        verification="certificate has expired",
        certificate=_cert(not_after=NOW - timedelta(days=3)),
    )
    assert _ids(evaluate(ep, NOW)) == {"TLS-CERT-EXPIRED"}


def test_hostname_mismatch_is_info_when_scanning_by_ip():
    [finding] = evaluate(_ep(verify_code=62, verification="IP address mismatch"), NOW, True)
    assert finding.severity is Severity.INFO


def test_deprecated_protocols_take_highest_severity():
    protocols = dict(_ep()["protocols"], TLSv1=SUPPORTED)
    [finding] = evaluate(_ep(protocols=protocols), NOW)
    assert finding.severity is Severity.MEDIUM
    protocols["SSLv3"] = SUPPORTED
    [finding] = evaluate(_ep(protocols=protocols), NOW)
    assert finding.severity is Severity.HIGH
    assert "SSLv3, TLSv1" in finding.title


def test_no_modern_protocol():
    protocols = {"SSLv3": UNTESTED, "TLSv1": SUPPORTED, "TLSv1.1": REJECTED}
    protocols.update({"TLSv1.2": REJECTED, "TLSv1.3": REJECTED})
    assert _ids(evaluate(_ep(protocols=protocols), NOW)) == {
        "TLS-DEPRECATED-PROTOCOL",
        "TLS-NO-MODERN-PROTOCOL",
    }


def test_untested_protocols_are_not_findings():
    protocols = dict(_ep()["protocols"], SSLv3=UNTESTED, TLSv1=UNTESTED)
    assert evaluate(_ep(protocols=protocols), NOW) == []


# ---------------------------------------------------------------- port selection


def _ports_result(*ports):
    open_ = [{"port": p, "service": "x", "banner": None} for p in ports]
    return CheckResult(check="ports", title="Open ports", data={"scanned": 20, "open": open_})


def test_tls_ports_from_port_scan():
    ctx = make_ctx()
    ctx.results["ports"] = _ports_result(22, 443, 993, 8080)
    assert tls_ports_for(ctx) == [443, 993]


def test_tls_ports_include_target_port():
    ctx = make_ctx(port=9000, scheme="https")
    ctx.results["ports"] = _ports_result(22)
    assert tls_ports_for(ctx) == [9000]


def test_tls_ports_default_without_port_scan():
    assert tls_ports_for(make_ctx()) == [443]


def test_no_tls_ports_open():
    ctx = make_ctx()
    ctx.results["ports"] = _ports_result(22, 80)
    result = TLSCheck().run(ctx)
    assert result.data == {"endpoints": []}
    assert result.findings == []
    assert result.notes


# ---------------------------------------------------------------- live local TLS servers


def test_modern_self_signed_server(tmp_path):
    certfile, keyfile = make_cert(tmp_path)
    with serve_tls(certfile, keyfile, minimum=ssl.TLSVersion.TLSv1_2) as port:
        ep = analyze_endpoint("127.0.0.1", "localhost", port, 3)

    assert ep["reachable"]
    assert ep["protocols"]["TLSv1.2"] == SUPPORTED
    assert ep["protocols"]["TLSv1.3"] == SUPPORTED
    assert ep["protocols"]["TLSv1"] in (REJECTED, UNTESTED)
    assert ep["weak_cipher"] in (REJECTED, UNTESTED)
    cert = ep["certificate"]
    assert cert["subject"] == "localhost"
    assert set(cert["sans"]) == {"localhost", "127.0.0.1"}
    assert (cert["key_type"], cert["key_bits"], cert["signature"]) == ("RSA", 2048, "sha256")
    assert cert["self_signed"] is True

    ids = _ids(evaluate(ep, datetime.now(timezone.utc)))
    assert ids == {"TLS-CERT-SELF-SIGNED"}


def test_expired_weak_key_server(tmp_path):
    # (SHA-1 signatures are covered by the unit test; modern OpenSSL refuses to create them.)
    certfile, keyfile = make_cert(tmp_path, key_size=1024, expired=True)
    with serve_tls(certfile, keyfile, legacy=True) as port:
        ep = analyze_endpoint("127.0.0.1", "localhost", port, 3)
    ids = _ids(evaluate(ep, datetime.now(timezone.utc)))
    assert {"TLS-CERT-EXPIRED", "TLS-WEAK-KEY"} <= ids


def test_weak_cipher_server(tmp_path):
    certfile, keyfile = make_cert(tmp_path)
    with serve_tls(certfile, keyfile, maximum=ssl.TLSVersion.TLSv1_2, legacy=True) as port:
        ep = analyze_endpoint("127.0.0.1", "localhost", port, 3)
    if ep["weak_cipher"] == UNTESTED:
        pytest.skip("this OpenSSL build has no weak cipher suites")
    assert ep["weak_cipher"] == SUPPORTED
    assert "TLS-WEAK-CIPHER" in _ids(evaluate(ep, datetime.now(timezone.utc)))


def test_legacy_tls10_server(tmp_path):
    certfile, keyfile = make_cert(tmp_path)
    with serve_tls(
        certfile, keyfile, minimum=ssl.TLSVersion.TLSv1, maximum=ssl.TLSVersion.TLSv1, legacy=True
    ) as port:
        ep = analyze_endpoint("127.0.0.1", "localhost", port, 3)
    if not ep["reachable"] or ep["protocols"]["TLSv1"] == UNTESTED:
        pytest.skip("this OpenSSL build cannot negotiate TLS 1.0")
    assert ep["protocols"]["TLSv1"] == SUPPORTED
    assert ep["protocols"]["TLSv1.2"] == REJECTED
    ids = _ids(evaluate(ep, datetime.now(timezone.utc)))
    assert {"TLS-DEPRECATED-PROTOCOL", "TLS-NO-MODERN-PROTOCOL"} <= ids


def test_tls_check_end_to_end(tmp_path):
    certfile, keyfile = make_cert(tmp_path)
    with serve_tls(certfile, keyfile, minimum=ssl.TLSVersion.TLSv1_2) as port:
        result = TLSCheck().run(make_ctx(port=port, scheme="https", host="localhost", timeout=3))
    [ep] = result.data["endpoints"]
    assert ep["port"] == port
    assert isinstance(ep["certificate"]["not_after"], str)  # JSON-safe
    assert [f.id for f in result.findings] == [f"TLS-CERT-SELF-SIGNED:{port}"]


def test_no_tls_service_is_not_a_finding(closed_port):
    result = TLSCheck().run(make_ctx(port=closed_port, scheme="https", timeout=1.0))
    assert result.findings == []
    assert result.data["endpoints"][0]["reachable"] is False
    assert f"No TLS service answered on port {closed_port}." in result.notes
