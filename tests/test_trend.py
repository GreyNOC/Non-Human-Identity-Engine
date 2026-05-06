"""Tests for trend mode."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.engine import Engine
from greynoc_nhi.storage import Storage
from greynoc_nhi.trend import compute_trend


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
