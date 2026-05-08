"""SQLite persistence for scans, identities, findings, and reports."""

from __future__ import annotations

import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from greynoc_nhi.constants import DEFAULT_DB_PATH
from greynoc_nhi.models import Finding, NonHumanIdentity, RiskPath, ScanResult
from greynoc_nhi.utils import chmod_private_dir, chmod_private_file


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    Storage(db_path).init_db()


class Storage:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        chmod_private_dir(self.db_path.parent)
        self.init_db()
        chmod_private_file(self.db_path)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=MEMORY")
        conn.execute("PRAGMA synchronous=NORMAL")
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
                CREATE TABLE IF NOT EXISTS risk_paths (
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
                try:
                    journal.unlink(missing_ok=True)
                except PermissionError:
                    pass
                with self.connect() as conn:
                    conn.executescript(schema)
            else:
                raise

    def save_scan(self, scan_result: ScanResult) -> None:
        try:
            self._save_scan_once(scan_result)
        except sqlite3.OperationalError as exc:
            if "readonly" not in str(exc).lower():
                raise
            fallback_dir = Path(tempfile.mkdtemp(prefix=f"greynoc_nhi_db_{os.getpid()}_"))
            chmod_private_dir(fallback_dir)
            self.db_path = fallback_dir / "greynoc_nhi.sqlite3"
            self.init_db()
            self._save_scan_once(scan_result)

    def _save_scan_once(self, scan_result: ScanResult) -> None:
        stats = dict(scan_result.stats)
        stats.setdefault("scan_trust_level", scan_result.scan_trust_level)
        stats.setdefault("policy_decision", scan_result.policy_decision)
        stats.setdefault("fatal_errors", scan_result.fatal_errors)
        stats.setdefault("correlation_id", scan_result.correlation_id)
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
                    json.dumps(stats),
                ),
            )
            conn.execute("DELETE FROM identities WHERE scan_id = ?", (scan_result.scan_id,))
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_result.scan_id,))
            conn.execute("DELETE FROM risk_paths WHERE scan_id = ?", (scan_result.scan_id,))
            conn.executemany(
                "INSERT OR REPLACE INTO identities VALUES (?, ?, ?)",
                [(identity.id, scan_result.scan_id, json.dumps(identity.to_dict())) for identity in scan_result.identities],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO findings VALUES (?, ?, ?)",
                [(finding.id, scan_result.scan_id, json.dumps(finding.to_dict())) for finding in scan_result.findings],
            )
            conn.executemany(
                "INSERT OR REPLACE INTO risk_paths VALUES (?, ?, ?)",
                [(risk_path.id, scan_result.scan_id, json.dumps(risk_path.to_dict())) for risk_path in scan_result.risk_paths],
            )
        chmod_private_file(self.db_path)

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
            risk_paths = [
                RiskPath(**json.loads(row["data_json"]))
                for row in conn.execute("SELECT data_json FROM risk_paths WHERE scan_id = ?", (scan_id,))
            ]
        stats = json.loads(scan["stats_json"])
        return ScanResult(
            scan_id=scan["scan_id"],
            project_path=scan["project_path"],
            started_at=scan["started_at"],
            completed_at=scan["completed_at"],
            identities=identities,
            findings=findings,
            risk_paths=risk_paths,
            overall_score=scan["overall_score"],
            summary=scan["summary"],
            stats=stats,
            scan_trust_level=stats.get("scan_trust_level", "clean"),
            policy_decision=stats.get("policy_decision", "pass"),
            fatal_errors=stats.get("fatal_errors", []),
            correlation_id=stats.get("correlation_id"),
        )

    def save_report(self, scan_id: str, report_type: str, path: str, created_at: str) -> None:
        with self.connect() as conn:
            conn.execute("INSERT INTO reports (scan_id, report_type, path, created_at) VALUES (?, ?, ?, ?)", (scan_id, report_type, path, created_at))

    def clear_all(self) -> None:
        with self.connect() as conn:
            conn.executescript("DELETE FROM reports; DELETE FROM risk_paths; DELETE FROM findings; DELETE FROM identities; DELETE FROM scans;")


def save_scan(scan_result: ScanResult, db_path: str | Path = DEFAULT_DB_PATH) -> None:
    Storage(db_path).save_scan(scan_result)


def list_scans(db_path: str | Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    return Storage(db_path).list_scans()


def get_scan(scan_id: str, db_path: str | Path = DEFAULT_DB_PATH) -> ScanResult | None:
    return Storage(db_path).get_scan(scan_id)


def clear_all(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    Storage(db_path).clear_all()
