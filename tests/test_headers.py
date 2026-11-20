from conftest import make_ctx

from secscan.checks.headers import HeaderCheck
from secscan.models import Severity


def test_header_check_against_local_server(http_server):
    result = HeaderCheck().run(make_ctx(port=http_server, scheme="http"))
    assert result.error is None
    assert result.data["status_code"] == 200
    assert "X-Content-Type-Options" in result.data["present"]

    by_id = {f.id: f for f in result.findings}
    assert "HEADER-MISSING-STRICT_TRANSPORT_SECURITY" in by_id
    assert "HEADER-MISSING-CONTENT_SECURITY_POLICY" in by_id
    assert "HEADER-MISSING-X_CONTENT_TYPE_OPTIONS" not in by_id
    assert by_id["HTTP-NO-TLS"].severity is Severity.HIGH
    assert by_id["HEADER-DISCLOSURE-SERVER"].severity is Severity.LOW
    assert "Apache/2.4.1" in (by_id["HEADER-DISCLOSURE-SERVER"].evidence or "")


def test_unreachable_host_reports_error(closed_port):
    result = HeaderCheck().run(make_ctx(port=closed_port, scheme="http", timeout=1.0))
    assert result.error is not None
    assert result.findings == []
