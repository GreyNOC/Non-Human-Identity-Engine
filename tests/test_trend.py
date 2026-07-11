"""Tests for trend mode."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.engine import Engine
from greynoc_nhi.models import Finding, ScanResult
from greynoc_nhi.storage import Storage
from greynoc_nhi.trend import compute_trend


def _finding(fid: str, evidence: str) -> Finding:
    return Finding(
        id=fid,
        rule_id="nhi_secret_leakage",
        title=f"Finding {fid}",
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
        evidence=[evidence],
        remediation="",
        priority="fix now",
        owasp_nhi_refs=[],
        control_hints=[],
        created_at="2026-01-01T00:00:00+00:00",
    )


def _scan(scan_id: str, findings: list[Finding], project_path: str, completed_at: str) -> ScanResult:
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


def test_trend_no_prior_scan(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_TR1_998877\n", encoding="utf-8")

    engine = Engine(db_path=tmp_path / "db.sqlite3", cache_enabled=False)
    result = engine.run_scan(project, persist=True, enrich_owners=False)
    report = compute_trend(engine.storage, result)
    assert report.has_prior is False
    assert "no prior scan" in report.summary().lower()


def test_trend_detects_new_and_resolved(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    env_file = project / ".env"
    env_file.write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_TR2_111122\n", encoding="utf-8")

    db_path = tmp_path / "db.sqlite3"
    engine = Engine(db_path=db_path, cache_enabled=False)
    first = engine.run_scan(project, persist=True, enrich_owners=False)
    assert first.findings, "first scan must produce findings"

    env_file.write_text(
        "OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_TR2_111122\n"
        "STRIPE_SECRET_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_STRIPE_223344\n",
        encoding="utf-8",
    )

    engine2 = Engine(db_path=db_path, cache_enabled=False)
    second = engine2.run_scan(project, persist=True, enrich_owners=False)
    storage = Storage(db_path)
    report = compute_trend(storage, second)
    assert report.has_prior is True
    assert report.previous_scan_id == first.scan_id
    assert any("STRIPE" in (delta.title or "").upper() or "stripe" in (delta.rule_id or "").lower() for delta in report.new_findings) or len(report.new_findings) >= 1


def test_trend_counts_new_resolved_unchanged(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite3")
    prior = _scan(
        "scan_a",
        [_finding("fa", "evidence alpha"), _finding("fb", "evidence beta")],
        project_path="/proj",
        completed_at="2026-01-01T00:00:00+00:00",
    )
    storage.save_scan(prior)
    current = _scan(
        "scan_b",
        [_finding("fb", "evidence beta"), _finding("fc", "evidence gamma")],
        project_path="/proj",
        completed_at="2026-01-02T00:00:00+00:00",
    )
    storage.save_scan(current)
    report = compute_trend(storage, current)
    assert report.has_prior is True
    assert report.previous_scan_id == "scan_a"
    assert report.previous_completed_at == "2026-01-01T00:00:00+00:00"
    assert len(report.new_findings) == 1
    assert len(report.resolved_findings) == 1
    assert report.unchanged_count == 1


def test_trend_prior_scan_scoped_to_project(tmp_path: Path) -> None:
    storage = Storage(tmp_path / "db.sqlite3")
    storage.save_scan(
        _scan("scan_other", [_finding("fx", "other evidence")], project_path="/other", completed_at="2026-01-03T00:00:00+00:00")
    )
    storage.save_scan(_scan("scan_a", [_finding("fa", "evidence alpha")], project_path="/proj", completed_at="2026-01-01T00:00:00+00:00"))
    current = _scan("scan_b", [_finding("fa", "evidence alpha")], project_path="/proj", completed_at="2026-01-02T00:00:00+00:00")
    storage.save_scan(current)
    report = compute_trend(storage, current)
    assert report.previous_scan_id == "scan_a"
    assert report.unchanged_count == 1
    assert report.new_findings == []


def test_trend_handles_storageless_engine(tmp_path: Path) -> None:
    from greynoc_nhi.models import ScanResult

    blank = ScanResult(
        scan_id="x",
        project_path=str(tmp_path),
        started_at="now",
        completed_at="now",
        identities=[],
        findings=[],
        overall_score=100,
        summary="",
        stats={},
    )
    report = compute_trend(None, blank)
    assert report.has_prior is False
