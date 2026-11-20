"""Report writers."""

from secscan.reporting.html import render_html, write_html
from secscan.reporting.json_report import write_json

__all__ = ["render_html", "write_html", "write_json"]
