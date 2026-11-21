"""Runs dashboard scans in background threads and records progress in the store."""

from __future__ import annotations

from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any

from secscan import checks as checks_module
from secscan.checks.base import Check, ScanConfig
from secscan.checks.ports import parse_port_spec
from secscan.models import CheckResult
from secscan.scanner import run_scan
from secscan.store import ScanStore
from secscan.target import TargetError, parse_target, resolve_target


def target_key(raw: str) -> str:
    """Normalized grouping key: host, plus port if given. Raises TargetError."""
    host, _scheme, port = parse_target(raw)
    return host if port is None else f"{host}:{port}"


def compare(current: dict[str, Any], previous: dict[str, Any] | None) -> dict[str, Any] | None:
    """New and fixed findings of a finished scan relative to the previous scan of its target."""
    if previous is None or not current.get("result") or not previous.get("result"):
        return None
    cur = {f["id"]: f for f in current["result"]["findings"]}
    prev = {f["id"]: f for f in previous["result"]["findings"]}
    return {
        "previous_id": previous["id"],
        "previous_score": previous["score"],
        "previous_finished_at": previous["finished_at"],
        "new_ids": [fid for fid in cur if fid not in prev],
        "fixed": [f for fid, f in prev.items() if fid not in cur],
    }


class ScanService:
    def __init__(self, store: ScanStore, max_workers: int = 2) -> None:
        self.store = store
        self._pool = ThreadPoolExecutor(max_workers=max_workers, thread_name_prefix="secscan")

    def submit(
        self, raw_target: str, check_names: list[str], ports: str | None = None
    ) -> tuple[int, Future[None]]:
        """Queue a scan. Raises TargetError / PortSpecError for malformed input
        (name resolution happens later, in the background)."""
        key = target_key(raw_target)
        port_map = parse_port_spec(ports) if ports else None
        options = {"ports": ports} if ports else {}
        scan_id = self.store.create(key, raw_target.strip(), check_names, options)
        future = self._pool.submit(self._run, scan_id, raw_target, check_names, port_map)
        return scan_id, future

    def _run(
        self,
        scan_id: int,
        raw_target: str,
        check_names: list[str],
        port_map: dict[int, str] | None = None,
    ) -> None:
        try:
            target = resolve_target(raw_target)
        except TargetError as e:
            self.store.fail(scan_id, str(e))
            return

        self.store.mark_running(scan_id, target.address)
        completed: list[str] = []

        def on_start(check: Check) -> None:
            self.store.set_progress(scan_id, check.name, completed)

        def on_done(result: CheckResult) -> None:
            completed.append(result.check)
            self.store.set_progress(scan_id, None, completed)

        try:
            checks = [checks_module.CHECKS[name]() for name in check_names]
            scan = run_scan(target, checks, ScanConfig(ports=port_map), on_start, on_done)
            self.store.finish(scan_id, scan)
        except Exception as e:  # never leave a scan stuck in "running"
            self.store.fail(scan_id, f"Internal error: {type(e).__name__}: {e}")

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)
