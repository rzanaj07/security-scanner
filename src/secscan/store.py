"""SQLite storage for scan history."""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from secscan.models import ScanResult

DEFAULT_DB_PATH = Path.home() / ".secscan" / "scans.db"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target        TEXT NOT NULL,              -- normalized host[:port], used for grouping
    input         TEXT NOT NULL,              -- what the user typed
    address       TEXT,
    status        TEXT NOT NULL,              -- queued | running | done | failed
    checks        TEXT NOT NULL,              -- JSON list of check names
    completed     TEXT NOT NULL DEFAULT '[]', -- JSON list of finished check names
    current_check TEXT,
    created_at    TEXT NOT NULL,
    started_at    TEXT,
    finished_at   TEXT,
    score         INTEGER,
    grade         TEXT,
    counts        TEXT,                       -- JSON {severity: n}
    result        TEXT,                       -- full ScanResult JSON
    error         TEXT
);
CREATE INDEX IF NOT EXISTS idx_scans_target ON scans (target, id);
"""

_JSON_COLUMNS = ("checks", "completed", "counts", "result")
_SUMMARY_COLUMNS = (
    "id, target, input, address, status, checks, completed, current_check, created_at, "
    "started_at, finished_at, score, grade, counts, error"
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _row(row: sqlite3.Row | None) -> dict[str, Any] | None:
    if row is None:
        return None
    d = dict(row)
    for col in _JSON_COLUMNS:
        if col in d and d[col] is not None:
            d[col] = json.loads(d[col])
    return d


class ScanStore:
    def __init__(self, path: str | Path = DEFAULT_DB_PATH) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # One short-lived connection per operation keeps this safe across threads.
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            with conn:
                yield conn
        finally:
            conn.close()

    def create(self, target: str, raw_input: str, checks: list[str]) -> int:
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans (target, input, status, checks, created_at) "
                "VALUES (?, ?, 'queued', ?, ?)",
                (target, raw_input, json.dumps(checks), _now()),
            )
            return int(cur.lastrowid or 0)

    def mark_running(self, scan_id: int, address: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status='running', address=?, started_at=? WHERE id=?",
                (address, _now(), scan_id),
            )

    def set_progress(self, scan_id: int, current: str | None, completed: list[str]) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET current_check=?, completed=? WHERE id=?",
                (current, json.dumps(completed), scan_id),
            )

    def finish(self, scan_id: int, scan: ScanResult) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status='done', current_check=NULL, finished_at=?, score=?, "
                "grade=?, counts=?, result=? WHERE id=?",
                (
                    _now(),
                    scan.score(),
                    scan.grade(),
                    json.dumps(scan.severity_counts()),
                    json.dumps(scan.to_dict(), default=str),
                    scan_id,
                ),
            )

    def fail(self, scan_id: int, error: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "UPDATE scans SET status='failed', current_check=NULL, finished_at=?, error=? "
                "WHERE id=?",
                (_now(), error, scan_id),
            )

    def interrupt_unfinished(self) -> int:
        """Mark scans left queued/running by a previous process as failed."""
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE scans SET status='failed', current_check=NULL, error=? "
                "WHERE status IN ('queued', 'running')",
                ("Interrupted: the dashboard was stopped before the scan finished.",),
            )
            return cur.rowcount

    def get(self, scan_id: int) -> dict[str, Any] | None:
        with self._connect() as conn:
            return _row(conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone())

    def recent(self, limit: int = 200) -> list[dict[str, Any]]:
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {_SUMMARY_COLUMNS} FROM scans ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [d for d in (_row(r) for r in rows) if d is not None]

    def previous_done(self, target: str, before_id: int) -> dict[str, Any] | None:
        """The most recent completed scan of the same target before `before_id`."""
        with self._connect() as conn:
            return _row(
                conn.execute(
                    "SELECT * FROM scans WHERE target=? AND id<? AND status='done' "
                    "ORDER BY id DESC LIMIT 1",
                    (target, before_id),
                ).fetchone()
            )

    def delete(self, scan_id: int) -> bool:
        with self._connect() as conn:
            return conn.execute("DELETE FROM scans WHERE id=?", (scan_id,)).rowcount > 0
