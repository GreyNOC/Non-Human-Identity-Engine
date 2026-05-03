"""SQLite persistence for scans, identities, findings, and reports."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

from greynoc_nhi.constants import DEFAULT_DB_PATH
from greynoc_nhi.models import Finding, NonHumanIdentity, ScanResult


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    Storage(db_path).init_db()


class Storage:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.init_db()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def init_db(self) -> None:
        schema = """
                CREATE TABLE IF NOT EXISTS scans (
                    scan_id TEXT PRIMARY KEY,
                    project_path TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT NOT NULL,
                    overall_score INTEGER NOT NULL,
                    summary TEXT NOT NULL,
                    stats_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS identities (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    data_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    data_json TEXT NOT NULL
                );
                CREATE TABLE IF NOT EXISTS reports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    report_type TEXT NOT NULL,
                    path TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                """
        try:
            with self.connect() as conn:
                conn.executescript(schema)
        except sqlite3.OperationalError as exc:
            journal = self.db_path.with_name(self.db_path.name + "-journal")
            if "disk I/O" in str(exc) and journal.exists():
                journal.unlink(missing_ok=True)
                with self.connect() as conn:
                    conn.executescript(schema)
            else:
                raise

    def save_scan(self, scan_result: ScanResult) -> None:
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_result.scan_id,
                    scan_result.project_path,
                    scan_result.started_at,
                    scan_result.completed_at,
                    scan_result.overall_score,
                    scan_result.summary,
                    json.dumps(scan_result.stats),
                ),
            )
            conn.execute("DELETE FROM identities WHERE scan_id = ?", (scan_result.scan_id,))
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_result.scan_id,))
            conn.executemany(
                "INSERT OR REPLACE INTO identities VALUES (?, ?, ?)",
                [(identity.id, scan_result.scan_id, json.dumps(identity.to_dict())) for identity in scan_result.identities],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO findings VALUES (?, ?, ?)",
                [(finding.id, scan_result.scan_id, json.dumps(finding.to_dict())) for finding in scan_result.findings],
            )

    def list_scans(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM scans ORDER BY completed_at DESC")]

    def get_scan(self, scan_id: str) -> ScanResult | None:
        with self.connect() as conn:
            scan = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if scan is None:
                return None
            identities = [
                NonHumanIdentity(**json.loads(row["data_json"]))
                for row in conn.execute("SELECT data_json FROM identities WHERE scan_id = ?", (scan_id,))
            ]
            findings = [
                Finding(**json.loads(row["data_json"]))
                for row in conn.execute("SELECT data_json FROM findings WHERE scan_id = ?", (scan_id,))
            ]
        return ScanResult(
            scan_id=scan["scan_id"],
            project_path=scan["project_path"],
            started_at=scan["started_at"],
            completed_at=scan["completed_at"],
            identities=identities,
            findings=findings,
            overall_score=scan["overall_score"],
            summary=scan["summary"],
            stats=json.loads(scan["stats_json"]),
        )

    def save_report(self, scan_id: str, report_type: str, path: str, created_at: str) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO reports (scan_id, report_type, path, created_at) VALUES (?, ?, ?, ?)", (scan_id, report_type, path, created_at))

    def clear_all(self) -> None:
        with self.connect() as conn:
            conn.executescript("DELETE FROM reports; DELETE FROM findings; DELETE FROM identities; DELETE FROM scans;")


def save_scan(scan_result: ScanResult, db_path: str | Path = DEFAULT_DB_PATH) -> None:
    Storage(db_path).save_scan(scan_result)


def list_scans(db_path: str | Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    return Storage(db_path).list_scans()


def get_scan(scan_id: str, db_path: str | Path = DEFAULT_DB_PATH) -> ScanResult | None:
    return Storage(db_path).get_scan(scan_id)


def clear_all(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    Storage(db_path).clear_all()
