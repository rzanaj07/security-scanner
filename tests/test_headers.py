import pytest
import requests
from conftest import make_ctx, serve_http

from secscan.checks.headers import (
    HeaderCheck,
    analyze_cookie,
    analyze_csp,
    analyze_hsts,
    check_https_redirect,
)
from secscan.models import Severity


def _ids(findings):
    return {f.id for f in findings}


# ---------------------------------------------------------------- live local server


def test_plain_http_site(http_server):
    result = HeaderCheck().run(make_ctx(port=http_server, scheme="http"))
    assert result.error is None
    assert result.data["status_code"] == 200
    assert "X-Content-Type-Options" in result.data["present"]

    by_id = {f.id: f for f in result.findings}
    assert by_id["HTTP-NO-TLS"].severity is Severity.HIGH
    assert "HEADER-MISSING-CONTENT_SECURITY_POLICY" in by_id
    assert "HEADER-MISSING-X_CONTENT_TYPE_OPTIONS" not in by_id
    # HSTS is meaningless over HTTP; HTTP-NO-TLS already covers it
    assert "HEADER-MISSING-STRICT_TRANSPORT_SECURITY" not in by_id
    assert by_id["HEADER-DISCLOSURE-SERVER"].severity is Severity.LOW
    assert "Apache/2.4.1" in (by_id["HEADER-DISCLOSURE-SERVER"].evidence or "")


def test_falls_back_to_http_when_https_fails(http_server):
    result = HeaderCheck().run(make_ctx(port=http_server, timeout=2))
    assert result.error is None
    assert result.data["final_url"].startswith("http://")
    assert any("tested HTTP instead" in n for n in result.notes)


def test_header_values_and_cookies():
    headers = [
        ("Content-Security-Policy", "default-src 'self'; frame-ancestors 'none'"),
        ("X-Content-Type-Options", "yes-please"),
        ("Referrer-Policy", "unsafe-url"),
        ("X-Powered-By", "PHP/8.1.2"),
        ("Set-Cookie", "sid=abc; Path=/"),
        ("Set-Cookie", "pref=dark; Path=/; HttpOnly; SameSite=Lax"),
    ]
    with serve_http(headers=headers) as port:
        result = HeaderCheck().run(make_ctx(port=port, scheme="http"))

    ids = _ids(result.findings)
    assert "HEADER-MISSING-X_FRAME_OPTIONS" not in ids  # CSP frame-ancestors covers it
    assert "HEADER-INVALID-X_CONTENT_TYPE_OPTIONS" in ids
    assert "HEADER-WEAK-REFERRER_POLICY" in ids
    assert "HEADER-DISCLOSURE-X_POWERED_BY" in ids
    assert "COOKIE-FLAGS:sid" in ids
    assert "COOKIE-FLAGS:pref" not in ids
    assert {c["name"] for c in result.data["cookies"]} == {"sid", "pref"}


def test_unreachable_host_reports_error(closed_port):
    result = HeaderCheck().run(make_ctx(port=closed_port, scheme="http", timeout=1.0))
    assert result.error is not None
    assert result.findings == []


# ---------------------------------------------------------------- HTTPS redirect


def test_redirect_to_https_is_detected_without_connecting_to_it():
    with serve_http(redirect="https://secure.example.invalid/") as port:
        status, url = check_https_redirect(requests.Session(), f"http://127.0.0.1:{port}/", 2)
    assert (status, url) == ("redirects", "https://secure.example.invalid/")


def test_no_redirect(http_server):
    status, _ = check_https_redirect(requests.Session(), f"http://127.0.0.1:{http_server}/", 2)
    assert status == "no-redirect"


def test_redirect_unreachable(closed_port):
    status, _ = check_https_redirect(requests.Session(), f"http://127.0.0.1:{closed_port}/", 1)
    assert status == "unreachable"


# ---------------------------------------------------------------- value analysis (pure)


@pytest.mark.parametrize(
    ("csp", "expected"),
    [
        ("default-src 'self'", set()),
        ("script-src 'self' 'unsafe-inline'", {"CSP-UNSAFE-INLINE"}),
        ("script-src 'self' 'unsafe-inline' 'nonce-abc123'", set()),
        ("script-src 'self' 'unsafe-eval'", {"CSP-UNSAFE-EVAL"}),
        ("default-src *", {"CSP-BROAD-SCRIPT-SOURCE"}),
        ("script-src https: 'strict-dynamic' 'nonce-x'", set()),
        ("upgrade-insecure-requests", {"CSP-NO-SCRIPT-RESTRICTION"}),
        # script-src overrides default-src
        ("default-src 'self'; script-src 'self' 'unsafe-inline'", {"CSP-UNSAFE-INLINE"}),
    ],
)
def test_analyze_csp(csp, expected):
    assert _ids(analyze_csp(csp)) == expected


@pytest.mark.parametrize(
    ("value", "weak"),
    [
        ("max-age=31536000; includeSubDomains", False),
        ("max-age=15552000", False),
        ("max-age=3600", True),
        ("max-age=0", True),
        ("includeSubDomains", True),
    ],
)
def test_analyze_hsts(value, weak):
    assert bool(analyze_hsts(value)) is weak


def test_cookie_over_https_needs_secure():
    info, finding = analyze_cookie("sid=1; HttpOnly; SameSite=Lax", over_https=True)
    assert info == {"name": "sid", "secure": False, "httponly": True, "samesite": "Lax"}
    assert finding is not None and finding.severity is Severity.MEDIUM


def test_cookie_with_all_flags_is_fine():
    _, finding = analyze_cookie("sid=1; Secure; HttpOnly; SameSite=Strict", over_https=True)
    assert finding is None


def test_samesite_none_without_secure():
    _, finding = analyze_cookie("t=1; HttpOnly; SameSite=None", over_https=False)
    assert finding is not None and "SameSite=None without Secure" in finding.description
