import time

import pytest
from fastapi.testclient import TestClient

import secscan.checks
from secscan.checks.base import Check
from secscan.models import Finding, ScanResult, Severity, grade_for
from secscan.target import Target
from secscan.web.app import create_app

HOSTILE = "<img src=x onerror=alert(1)>"


class ConfigurableCheck(Check):
    """Reports whatever findings the test puts in `ConfigurableCheck.ids`."""

    name = "fake"
    title = "Fake check"
    ids: list[str] = []

    def run(self, ctx):
        result = self.result()
        result.data = {"banner": HOSTILE}
        for fid in self.ids:
            result.findings.append(
                Finding(id=fid, title=f"Issue {fid}", severity=Severity.HIGH, evidence=HOSTILE)
            )
        return result


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setattr(secscan.checks, "CHECKS", {"fake": ConfigurableCheck})
    monkeypatch.setattr(
        "secscan.web.service.resolve_target",
        lambda raw: Target(host="lab.local", address="127.0.0.1"),
    )
    app = create_app(tmp_path / "test.db", allowed_hosts=["testserver", "127.0.0.1", "localhost"])
    with TestClient(app) as c:
        yield c


def start(client, target="lab.local", **extra):
    body = {"target": target, "authorized": True, **extra}
    res = client.post("/api/scans", json=body)
    assert res.status_code == 202, res.text
    return res.json()["id"]


def wait_done(client, scan_id, timeout=10):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        scan = client.get(f"/api/scans/{scan_id}").json()
        if scan["status"] in ("done", "failed"):
            return scan
        time.sleep(0.05)
    raise AssertionError("scan did not finish")


def test_score_and_grade():
    assert grade_for(100) == "A" and grade_for(75) == "B" and grade_for(0) == "F"
    scan = ScanResult.from_dict(
        {
            "target": "t",
            "address": "1.2.3.4",
            "started_at": "2026-01-01T00:00:00+00:00",
            "checks": [
                {
                    "check": "c",
                    "title": "C",
                    "findings": [
                        {"id": "A", "title": "a", "severity": "high"},
                        {"id": "B", "title": "b", "severity": "medium"},
                    ],
                }
            ],
        }
    )
    assert scan.score() == 72
    assert scan.grade() == "C"


def test_scan_lifecycle_and_comparison(client):
    ConfigurableCheck.ids = ["A", "B"]
    first = wait_done(client, start(client))
    assert first["status"] == "done"
    assert first["score"] == 60
    assert first["completed"] == ["fake"]
    assert first["comparison"] is None

    ConfigurableCheck.ids = ["B", "C"]
    second = wait_done(client, start(client, target="https://lab.local/"))
    cmp = second["comparison"]
    assert cmp["previous_id"] == first["id"]
    assert cmp["new_ids"] == ["C"]
    assert [f["id"] for f in cmp["fixed"]] == ["A"]

    listing = client.get("/api/scans").json()
    assert [s["id"] for s in listing] == [second["id"], first["id"]]
    assert "result" not in listing[0]  # list stays light


def test_requires_authorization(client):
    res = client.post("/api/scans", json={"target": "lab.local"})
    assert res.status_code == 400
    assert "permission" in res.json()["detail"]


@pytest.mark.parametrize(
    ("body", "status"),
    [
        ({"target": "ftp://lab.local", "authorized": True}, 422),
        ({"target": "", "authorized": True}, 422),
        ({"target": "lab.local", "checks": ["nope"], "authorized": True}, 422),
    ],
)
def test_rejects_bad_requests(client, body, status):
    assert client.post("/api/scans", json=body).status_code == status


def test_unresolvable_target_marks_scan_failed(client, monkeypatch):
    from secscan.target import TargetError

    def fail(raw):
        raise TargetError("cannot resolve 'nowhere.invalid'")

    monkeypatch.setattr("secscan.web.service.resolve_target", fail)
    scan = wait_done(client, start(client, target="nowhere.invalid"))
    assert scan["status"] == "failed"
    assert "cannot resolve" in scan["error"]


def test_exports_are_escaped_and_locked_down(client):
    ConfigurableCheck.ids = ["A"]
    scan_id = wait_done(client, start(client))["id"]

    html = client.get(f"/api/scans/{scan_id}/report.html")
    assert html.status_code == 200
    assert HOSTILE not in html.text
    assert "default-src 'none'" in html.headers["content-security-policy"]

    js = client.get(f"/api/scans/{scan_id}/report.json")
    assert js.json()["score"] == 80
    assert "attachment" in js.headers["content-disposition"]


def test_delete_scan(client):
    ConfigurableCheck.ids = []
    scan_id = wait_done(client, start(client))["id"]
    assert client.delete(f"/api/scans/{scan_id}").status_code == 204
    assert client.get(f"/api/scans/{scan_id}").status_code == 404


def test_dashboard_page_has_security_headers(client):
    res = client.get("/")
    assert res.status_code == 200
    assert "secscan" in res.text
    assert "script-src 'self'" in res.headers["content-security-policy"]
    assert res.headers["x-frame-options"] == "DENY"
    assert client.get("/static/app.js").status_code == 200


def test_rejects_foreign_host_header(client):
    """DNS rebinding protection: requests addressed to another hostname are refused."""
    res = client.get("/api/scans", headers={"Host": "attacker.example"})
    assert res.status_code == 400


def test_unfinished_scans_are_marked_interrupted(tmp_path):
    from secscan.store import ScanStore

    store = ScanStore(tmp_path / "s.db")
    scan_id = store.create("lab.local", "lab.local", ["fake"])
    store.mark_running(scan_id, "127.0.0.1")
    create_app(tmp_path / "s.db")
    scan = store.get(scan_id)
    assert scan["status"] == "failed"
    assert "Interrupted" in scan["error"]


def test_ports_option_is_stored_and_used(client, monkeypatch):
    seen = {}

    def spy(self, ctx):
        seen["ports"] = ctx.config.ports
        return self.result()

    monkeypatch.setattr(ConfigurableCheck, "run", spy)
    scan = wait_done(client, start(client, ports="22,8000-8001"))
    assert scan["options"] == {"ports": "22,8000-8001"}
    assert list(seen["ports"]) == [22, 8000, 8001]


def test_invalid_ports_rejected(client):
    res = client.post(
        "/api/scans", json={"target": "lab.local", "ports": "1-99999", "authorized": True}
    )
    assert res.status_code == 422
    assert "65535" in res.json()["detail"]


def test_old_database_is_migrated(tmp_path):
    import sqlite3

    from secscan.store import ScanStore

    db = tmp_path / "old.db"
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY AUTOINCREMENT, target TEXT NOT NULL, "
            "input TEXT NOT NULL, address TEXT, status TEXT NOT NULL, checks TEXT NOT NULL, "
            "completed TEXT NOT NULL DEFAULT '[]', current_check TEXT, created_at TEXT NOT NULL, "
            "started_at TEXT, finished_at TEXT, score INTEGER, grade TEXT, counts TEXT, "
            "result TEXT, error TEXT)"
        )
        conn.execute(
            "INSERT INTO scans (target, input, status, checks, created_at) "
            "VALUES ('a', 'a', 'done', '[]', '2026-01-01')"
        )
    store = ScanStore(db)
    assert store.get(1)["options"] == {}
    assert store.get(store.create("b", "b", [], {"ports": "80"}))["options"] == {"ports": "80"}
