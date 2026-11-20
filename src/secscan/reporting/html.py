"""HTML report. All values are auto-escaped: banners and headers come from the scanned
host and must never be able to inject markup or scripts into the report."""

from __future__ import annotations

from pathlib import Path

from jinja2 import Environment, PackageLoader

from secscan import __version__
from secscan.models import ScanResult

_env = Environment(
    loader=PackageLoader("secscan", "reporting/templates"),
    autoescape=True,
    trim_blocks=True,
    lstrip_blocks=True,
)


def render_html(scan: ScanResult) -> str:
    duration = None
    if scan.finished_at:
        duration = f"{(scan.finished_at - scan.started_at).total_seconds():.1f}s"
    return _env.get_template("report.html").render(
        scan=scan,
        findings=scan.findings,
        counts=scan.severity_counts(),
        started=scan.started_at.strftime("%Y-%m-%d %H:%M UTC"),
        duration=duration,
        version=__version__,
    )


def write_html(scan: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    path.write_text(render_html(scan), encoding="utf-8")
    return path
