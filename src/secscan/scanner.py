"""Runs a sequence of checks against one target."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from datetime import datetime, timezone

from secscan.checks.base import Check, ScanConfig, ScanContext
from secscan.models import CheckResult, ScanResult
from secscan.target import Target


def run_scan(
    target: Target,
    checks: Sequence[Check],
    config: ScanConfig | None = None,
    on_check_start: Callable[[Check], None] | None = None,
    on_check_done: Callable[[CheckResult], None] | None = None,
) -> ScanResult:
    ctx = ScanContext(target=target, config=config or ScanConfig())
    scan = ScanResult(
        target=target.host, address=target.address, started_at=datetime.now(timezone.utc)
    )

    for check in checks:
        if on_check_start:
            on_check_start(check)
        try:
            result = check.run(ctx)
        except Exception as e:  # a buggy check must not abort the whole scan
            result = check.result()
            result.error = f"Internal error: {type(e).__name__}: {e}"
        ctx.results[check.name] = result
        scan.results.append(result)
        if on_check_done:
            on_check_done(result)

    scan.finished_at = datetime.now(timezone.utc)
    return scan
