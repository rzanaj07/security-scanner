import json

import pytest

import secscan.cli as cli
from secscan.checks.base import Check
from secscan.models import Finding, Severity
from secscan.scanner import run_scan
from secscan.target import Target, TargetError

LOCAL = Target(host="127.0.0.1", address="127.0.0.1")


class FakeCheck(Check):
    name = "fake"
    title = "Fake check"

    def run(self, ctx):
        result = self.result()
        result.findings.append(Finding(id="FAKE", title="fake", severity=Severity.MEDIUM))
        return result


class BrokenCheck(Check):
    name = "broken"
    title = "Broken check"

    def run(self, ctx):
        raise RuntimeError("bug")


def test_broken_check_does_not_abort_scan():
    scan = run_scan(LOCAL, [BrokenCheck(), FakeCheck()])
    assert scan.results[0].error == "Internal error: RuntimeError: bug"
    assert [f.id for f in scan.findings] == ["FAKE"]
    assert scan.finished_at is not None


@pytest.fixture
def fake_cli(monkeypatch):
    monkeypatch.setattr(cli, "CHECKS", {"fake": FakeCheck})
    monkeypatch.setattr(cli, "resolve_target", lambda raw: LOCAL)


@pytest.mark.parametrize(("fail_on", "code"), [("medium", 1), ("high", 0)])
def test_fail_on_threshold(fake_cli, tmp_path, fail_on, code):
    argv = ["x", "--checks", "fake", "-o", str(tmp_path / "r.html"), "--fail-on", fail_on]
    assert cli.main(argv) == code


def test_writes_reports(fake_cli, tmp_path):
    html, js = tmp_path / "r.html", tmp_path / "r.json"
    assert cli.main(["x", "--checks", "fake", "-o", str(html), "--json", str(js)]) == 0
    assert "FAKE" in html.read_text(encoding="utf-8")
    assert json.loads(js.read_text(encoding="utf-8"))["summary"]["medium"] == 1


def test_unknown_check_is_rejected(fake_cli):
    with pytest.raises(SystemExit):
        cli.main(["x", "--checks", "nope"])


def test_unresolvable_target_exits_2(monkeypatch, capsys):
    def fail(raw):
        raise TargetError("cannot resolve 'x'")

    monkeypatch.setattr(cli, "resolve_target", fail)
    assert cli.main(["x"]) == 2
    assert "cannot resolve" in capsys.readouterr().err


def test_default_report_name():
    assert cli._default_report_name("my.site.com") == "report_my_site_com.html"
