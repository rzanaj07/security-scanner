"""Machine-readable JSON report."""

from __future__ import annotations

import json
from pathlib import Path

from secscan import __version__
from secscan.models import ScanResult


def write_json(scan: ScanResult, path: str | Path) -> Path:
    path = Path(path)
    payload = {"tool": "secscan", "version": __version__, **scan.to_dict()}
    path.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    return path
