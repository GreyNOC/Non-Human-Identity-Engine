import dataclasses
import json
import sqlite3
from pathlib import Path
from tempfile import mkdtemp

import pytest

from greynoc_nhi.engine import Engine
from greynoc_nhi.models import Finding, NonHumanIdentity, RiskPath, ScanResult
from greynoc_nhi.sample_data import sample_project_path
from greynoc_nhi.storage import Storage
from greynoc_nhi.trend import compute_trend

_V0_SCHEMA = """
CREATE TABLE scans (
    scan_id TEXT PRIMARY KEY,
    project_path TEXT NOT NULL,
    started_at TEXT NOT NULL,
    completed_at TEXT NOT NULL,
    overall_score INTEGER NOT NULL,
    summary TEXT NOT NULL,
    stats_json TEXT NOT NULL
);
CREATE TABLE identities (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data_json TEXT NOT NULL);
CREATE TABLE findings (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data_json TEXT NOT NULL);
CREATE TABLE risk_paths (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data_json TEXT NOT NULL);
CREATE TABLE reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id TEXT NOT NULL,
    report_type TEXT NOT NULL,
    path TEXT NOT NULL,
    created_at TEXT NOT NULL
);
"""


def _finding(fid: str, evidence: list[str] | None = None) -> Finding:
    return Finding(
        id=fid,
        rule_id="nhi_secret_leakage",
        title="Example finding",
        severity="high",
        risk_score=80,
        category="secrets",
        identity_id=None,
        identity_name="example",
        source="test",
        file_path="app/.env",
        line_number=1,
        explanation="",
        why_it_matters="",
        evidence=evidence if evidence is not None else [f"masked evidence for {fid}"],
        remediation="",
        priority="fix now",
        owasp_nhi_refs=[],
        control_hints=[],
        created_at="2026-01-01T00:00:00+00:00",
    )


def _scan(
    scan_id: str,
    findings: list[Finding],
    project_path: str = "/proj",
    completed_at: str = "2026-01-01T00:00:00+00:00",
) -> ScanResult:
    return ScanResult(
        scan_id=scan_id,
        project_path=project_path,
        started_at=completed_at,
        completed_at=completed_at,
        identities=[],
        findings=findings,
        overall_score=50,
        summary="test scan",
        stats={},
    )


def test_storage_save_and_load_scan():
    temp_dir = mkdtemp(prefix="greynoc_nhi_test_")
    db_path = Path(temp_dir) / "test.sqlite3"
    storage = Storage(db_path)
    result = Engine(db_path).run_scan(sample_project_path())
    loaded = storage.get_scan(result.scan_id)
    assert loaded is not None
    assert loaded.scan_id == result.scan_id
    assert loaded.findings


def test_second_scan_does_not_steal_prior_scan_rows(tmp_path: Path) -> None:
    """Regression: id-only primary keys let INSERT OR REPLACE reassign rows across scans."""
    storage = Storage(tmp_path / "db.sqlite3")
    storage.save_scan(_scan("scan_a", [_finding("f_shared", evidence=["same evidence"])]))
    second = _scan(
        "scan_b",
        [_finding("f_shared", evidence=["same evidence"])],
        completed_at="2026-01-02T00:00:00+00:00",
    )
    storage.save_scan(second)
    loaded_first = storage.get_scan("scan_a")
    assert loaded_first is not None
    assert [f.id for f in loaded_first.findings] == ["f_shared"]
    report = compute_trend(storage, second)
    assert report.has_prior is True
    assert report.previous_scan_id == "scan_a"
    assert report.unchanged_count == 1
    assert report.new_findings == []
    assert report.resolved_findings == []


def test_migration_from_v0_schema_preserves_rows(tmp_path: Path) -> None:
    db_path = tmp_path / "old.sqlite3"
    conn = sqlite3.connect(db_path)
    conn.executescript(_V0_SCHEMA)
    conn.execute(
        "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
        ("scan_a", "/proj", "2026-01-01T00:00:00+00:00", "2026-01-01T00:00:00+00:00", 50, "old scan", "{}"),
    )
    conn.execute(
        "INSERT INTO findings VALUES (?, ?, ?)",
        ("f1", "scan_a", json.dumps(_finding("f1").to_dict())),
    )
    conn.commit()
    conn.close()

    storage = Storage(db_path)
    with storage.connect() as migrated:
        assert migrated.execute("PRAGMA user_version").fetchone()[0] == 1
        tables = {row[0] for row in migrated.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
    assert "reports" not in tables
    assert not any(name.endswith("_v0") for name in tables)
    loaded = storage.get_scan("scan_a")
    assert loaded is not None
    assert [f.id for f in loaded.findings] == ["f1"]

    # The same content-derived finding id can now persist under a second scan.
    storage.save_scan(_scan("scan_b", [_finding("f1")], completed_at="2026-01-02T00:00:00+00:00"))
    assert [f.id for f in storage.get_scan("scan_a").findings] == ["f1"]
    assert [f.id for f in storage.get_scan("scan_b").findings] == ["f1"]


def test_get_scan_tolerates_row_schema_drift(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite3")
    storage.save_scan(_scan("scan_a", [_finding("f1"), _finding("f2")]))
    with storage.connect() as conn:
        row = conn.execute("SELECT data_json FROM findings WHERE id = 'f1'").fetchone()
        data = json.loads(row["data_json"])
        data["field_added_in_future_version"] = "x"
        del data["baseline_key"]  # optional field removed from the stored row
        conn.execute("UPDATE findings SET data_json = ? WHERE id = 'f1'", (json.dumps(data),))
        # A row missing required fields is skipped with a stats note, not raised.
        conn.execute(
            "INSERT INTO findings VALUES (?, ?, ?)",
            ("f_broken", "scan_a", json.dumps({"id": "f_broken"})),
        )
    loaded = storage.get_scan("scan_a")
    assert loaded is not None
    assert {f.id for f in loaded.findings} == {"f1", "f2"}
    drifted = next(f for f in loaded.findings if f.id == "f1")
    assert drifted.baseline_key is None
    assert loaded.stats.get("storage_skipped_rows") == 1


def test_to_dict_matches_asdict_for_flat_models() -> None:
    identity = NonHumanIdentity(
        id="i1",
        name="example",
        identity_type="api_key",
        source="test",
        permissions=["repo:read"],
        evidence=["masked"],
        tags=["prod"],
    )
    finding = _finding("f1")
    risk_path = RiskPath(
        id="r1",
        source="test",
        agent=None,
        tool=None,
        credential=None,
        sink="external",
        trust_boundary="internet",
        attack_class="exfiltration",
        evidence=["masked"],
        related_identities=["i1"],
    )
    for obj in (identity, finding, risk_path):
        assert obj.to_dict() == dataclasses.asdict(obj)
    # List fields must be copies, not aliases into the dataclass.
    payload = identity.to_dict()
    payload["permissions"].append("mutated")
    assert identity.permissions == ["repo:read"]


def test_scan_db_uses_wal_journal(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite3")
    conn = storage.connect()
    try:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
    finally:
        conn.close()
    assert str(mode).lower() == "wal"


def test_save_scan_refuses_raw_secret_markers(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite3")
    bad = _finding("f_bad", evidence=["value GNOC_FAKE_SECRET_DO_NOT_USE_STORAGE_1 leaked"])
    with pytest.raises(ValueError):
        storage.save_scan(_scan("scan_bad", [bad]))
    assert storage.get_scan("scan_bad") is None


def test_find_previous_scan_scoped_to_project(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite3")
    storage.save_scan(_scan("scan_other", [], project_path="/other", completed_at="2026-01-03T00:00:00+00:00"))
    storage.save_scan(_scan("scan_a", [], project_path="/proj", completed_at="2026-01-01T00:00:00+00:00"))
    storage.save_scan(_scan("scan_b", [], project_path="/proj", completed_at="2026-01-02T00:00:00+00:00"))
    row = storage.find_previous_scan("/proj", "scan_b")
    assert row is not None
    assert row["scan_id"] == "scan_a"
    assert storage.find_previous_scan("/proj", "scan_a") is not None
    assert storage.find_previous_scan("/nowhere", "scan_x") is None
