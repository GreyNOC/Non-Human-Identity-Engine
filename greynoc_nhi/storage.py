"""SQLite persistence for scans, identities, findings, and risk paths."""

from __future__ import annotations

import dataclasses
import json
import os
import sqlite3
import tempfile
from pathlib import Path
from typing import Any

from greynoc_nhi.constants import DEFAULT_DB_PATH
from greynoc_nhi.models import Finding, NonHumanIdentity, RiskPath, ScanResult
from greynoc_nhi.utils import assert_no_raw_secret_markers, chmod_private_dir, chmod_sqlite_sidecars

SCHEMA_VERSION = 1

# The only tables whose names are ever interpolated into SQL. Every call site
# selects a name from this fixed allowlist -- names never come from user input or
# stored data -- so the f-string queries below are not an injection vector.
_CHILD_TABLES: tuple[str, ...] = ("identities", "findings", "risk_paths")

_MODEL_FIELDS: dict[type, tuple[frozenset[str], frozenset[str]]] = {}


def _model_fields(model: type) -> tuple[frozenset[str], frozenset[str]]:
    """Return (allowed, required) field-name sets for a dataclass, cached per class."""
    cached = _MODEL_FIELDS.get(model)
    if cached is None:
        model_fields = dataclasses.fields(model)
        allowed = frozenset(f.name for f in model_fields)
        required = frozenset(
            f.name
            for f in model_fields
            if f.default is dataclasses.MISSING and f.default_factory is dataclasses.MISSING
        )
        cached = (allowed, required)
        _MODEL_FIELDS[model] = cached
    return cached


def _rows_to_models(conn: sqlite3.Connection, table: str, scan_id: str, model: type) -> tuple[list[Any], int]:
    """Deserialize stored rows tolerantly across model-schema drift.

    Unknown keys written by newer versions are dropped, keys removed since the
    row was written fall back to dataclass defaults, and rows missing required
    fields (or containing invalid JSON) are skipped and counted instead of
    raising TypeError out of get_scan.
    """
    if table not in _CHILD_TABLES:
        raise ValueError(f"unknown table {table!r}")
    allowed, required = _model_fields(model)
    items: list[Any] = []
    skipped = 0
    # table is constrained to the _CHILD_TABLES allowlist above; not user input.
    for row in conn.execute(f"SELECT data_json FROM {table} WHERE scan_id = ?", (scan_id,)):  # nosec B608
        try:
            data = json.loads(row["data_json"])
        except (TypeError, json.JSONDecodeError):
            skipped += 1
            continue
        if not isinstance(data, dict) or not required.issubset(data):
            skipped += 1
            continue
        items.append(model(**{key: value for key, value in data.items() if key in allowed}))
    return items, skipped


def init_db(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    Storage(db_path).init_db()


class Storage:
    def __init__(self, db_path: str | Path = DEFAULT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        chmod_private_dir(self.db_path.parent)
        self.init_db()
        chmod_sqlite_sidecars(self.db_path)

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
        except sqlite3.OperationalError:
            conn.execute("PRAGMA journal_mode=DELETE")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def init_db(self) -> None:
        try:
            self._init_db_once()
        except sqlite3.OperationalError as exc:
            journal = self.db_path.with_name(self.db_path.name + "-journal")
            if "disk I/O" in str(exc) and journal.exists():
                try:
                    journal.unlink(missing_ok=True)
                except PermissionError:
                    pass
                self._init_db_once()
            else:
                raise

    def _init_db_once(self) -> None:
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
                    id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, id)
                );
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, id)
                );
                CREATE TABLE IF NOT EXISTS risk_paths (
                    id TEXT NOT NULL,
                    scan_id TEXT NOT NULL,
                    data_json TEXT NOT NULL,
                    PRIMARY KEY (scan_id, id)
                );
                CREATE INDEX IF NOT EXISTS idx_scans_project ON scans(project_path, completed_at);
                """
        with self.connect() as conn:
            version = conn.execute("PRAGMA user_version").fetchone()[0]
            try:
                if version < SCHEMA_VERSION:
                    self._migrate_to_v1(conn)
                conn.executescript(schema)
            except sqlite3.OperationalError as exc:
                message = str(exc).lower()
                degradable = "readonly" in message or "database is locked" in message
                # Only degrade when an existing (v0) schema is already present:
                # its tables are query-compatible with every reader, so deferring
                # migration is safe. On a FRESH db the schema was never created,
                # so returning here would leave an unusable connection ("no such
                # table"); re-raise instead so the caller retries once the lock
                # clears rather than proceeding with a broken DB.
                schema_present = False
                try:
                    schema_present = bool(
                        conn.execute(
                            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='scans'"
                        ).fetchone()
                    )
                except sqlite3.OperationalError:
                    schema_present = False
                if degradable and schema_present:
                    # DB file is read-only (root-owned, restored CI cache) or a
                    # concurrent process holds the one-time migration lock. Defer
                    # migration; writes route through save_scan's readonly
                    # fallback. Roll back any partial migration transaction first.
                    try:
                        conn.rollback()
                    except sqlite3.OperationalError:
                        pass
                    return
                raise

    def _migrate_to_v1(self, conn: sqlite3.Connection) -> None:
        """Rebuild child tables with (scan_id, id) composite primary keys.

        The original schema keyed identities/findings/risk_paths on id alone,
        so INSERT OR REPLACE reassigned rows from prior scans of the same
        project (identity ids are content-derived and stable across scans),
        silently corrupting history and trend data. The whole migration runs
        in one transaction (BEGIN IMMEDIATE takes the write lock up front and the
        version is re-checked inside it, so two processes racing the first open
        cannot both migrate) so a failure leaves the old tables intact. Also
        drops the never-populated reports table.
        """
        conn.execute("BEGIN IMMEDIATE")
        if conn.execute("PRAGMA user_version").fetchone()[0] >= SCHEMA_VERSION:
            # Another process won the migration race between our version check
            # and acquiring the write lock; nothing left to do.
            conn.execute("COMMIT")
            return
        tables = {
            row[0]
            for row in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table'")
        }
        # table names come only from the _CHILD_TABLES literal allowlist, never
        # from user input or stored data, so these f-string DDL/DML statements
        # are not an injection vector.
        for table in _CHILD_TABLES:
            if table not in tables:
                continue
            conn.execute(f"ALTER TABLE {table} RENAME TO {table}_v0")  # nosec B608
            conn.execute(
                f"CREATE TABLE {table} ("
                "id TEXT NOT NULL, "
                "scan_id TEXT NOT NULL, "
                "data_json TEXT NOT NULL, "
                "PRIMARY KEY (scan_id, id))"
            )
            conn.execute(
                f"INSERT OR IGNORE INTO {table} (id, scan_id, data_json) "  # nosec B608
                f"SELECT id, scan_id, data_json FROM {table}_v0"
            )
            conn.execute(f"DROP TABLE {table}_v0")
        conn.execute("DROP TABLE IF EXISTS reports")
        conn.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        conn.execute("COMMIT")

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
        scan_id = scan_result.scan_id
        stats_blob = json.dumps(stats)
        identity_rows = [(identity.id, scan_id, json.dumps(identity.to_dict())) for identity in scan_result.identities]
        finding_rows = [(finding.id, scan_id, json.dumps(finding.to_dict())) for finding in scan_result.findings]
        risk_path_rows = [(risk_path.id, scan_id, json.dumps(risk_path.to_dict())) for risk_path in scan_result.risk_paths]
        # Single serialization pass: run the raw-secret-marker check over the
        # exact JSON blobs about to be written (plus the scalar scan fields)
        # instead of re-serializing the whole ScanResult a second time.
        assert_no_raw_secret_markers(scan_result.summary)
        assert_no_raw_secret_markers(scan_result.project_path)
        assert_no_raw_secret_markers(stats_blob)
        assert_no_raw_secret_markers(json.dumps(scan_result.fatal_errors))
        for rows in (identity_rows, finding_rows, risk_path_rows):
            for _, _, data_json in rows:
                assert_no_raw_secret_markers(data_json)
        with self.connect() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    scan_id,
                    scan_result.project_path,
                    scan_result.started_at,
                    scan_result.completed_at,
                    scan_result.overall_score,
                    scan_result.summary,
                    stats_blob,
                ),
            )
            conn.execute("DELETE FROM identities WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            conn.execute("DELETE FROM risk_paths WHERE scan_id = ?", (scan_id,))
            conn.executemany("INSERT OR REPLACE INTO identities VALUES (?, ?, ?)", identity_rows)
            conn.executemany("INSERT OR REPLACE INTO findings VALUES (?, ?, ?)", finding_rows)
            conn.executemany("INSERT OR REPLACE INTO risk_paths VALUES (?, ?, ?)", risk_path_rows)
        chmod_sqlite_sidecars(self.db_path)

    def list_scans(self) -> list[dict[str, Any]]:
        with self.connect() as conn:
            return [dict(row) for row in conn.execute("SELECT * FROM scans ORDER BY completed_at DESC")]

    def find_previous_scan(self, project_path: str, exclude_scan_id: str) -> dict[str, Any] | None:
        """Most recent prior scan of a project, without loading stats_json for every scan."""
        with self.connect() as conn:
            row = conn.execute(
                "SELECT scan_id, completed_at FROM scans"
                " WHERE project_path = ? AND scan_id != ?"
                " ORDER BY completed_at DESC LIMIT 1",
                (project_path, exclude_scan_id),
            ).fetchone()
        return dict(row) if row is not None else None

    def get_findings(self, scan_id: str) -> list[Finding]:
        """Load only a scan's findings (trend comparison needs no identities/risk paths)."""
        with self.connect() as conn:
            findings, _skipped = _rows_to_models(conn, "findings", scan_id, Finding)
        return findings

    def get_scan(self, scan_id: str) -> ScanResult | None:
        with self.connect() as conn:
            scan = conn.execute("SELECT * FROM scans WHERE scan_id = ?", (scan_id,)).fetchone()
            if scan is None:
                return None
            identities, skipped_identities = _rows_to_models(conn, "identities", scan_id, NonHumanIdentity)
            findings, skipped_findings = _rows_to_models(conn, "findings", scan_id, Finding)
            risk_paths, skipped_risk_paths = _rows_to_models(conn, "risk_paths", scan_id, RiskPath)
        stats = json.loads(scan["stats_json"])
        skipped_rows = skipped_identities + skipped_findings + skipped_risk_paths
        if skipped_rows:
            stats["storage_skipped_rows"] = skipped_rows
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

    def clear_all(self) -> None:
        with self.connect() as conn:
            conn.executescript("DELETE FROM risk_paths; DELETE FROM findings; DELETE FROM identities; DELETE FROM scans;")
        chmod_sqlite_sidecars(self.db_path)


def save_scan(scan_result: ScanResult, db_path: str | Path = DEFAULT_DB_PATH) -> None:
    Storage(db_path).save_scan(scan_result)


def list_scans(db_path: str | Path = DEFAULT_DB_PATH) -> list[dict[str, Any]]:
    return Storage(db_path).list_scans()


def get_scan(scan_id: str, db_path: str | Path = DEFAULT_DB_PATH) -> ScanResult | None:
    return Storage(db_path).get_scan(scan_id)


def clear_all(db_path: str | Path = DEFAULT_DB_PATH) -> None:
    Storage(db_path).clear_all()
