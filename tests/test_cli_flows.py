from pathlib import Path
from tempfile import mkdtemp

from greynoc_nhi.cli import main
from greynoc_nhi.sample_data import sample_project_path


def test_cli_load_samples_flow_creates_reports():
    temp_dir = Path(mkdtemp(prefix="greynoc_cli_samples_"))
    code = main(["--load-samples", "--out", str(temp_dir / "reports"), "--db", str(temp_dir / "db.sqlite3")])
    assert code == 0
    assert list((temp_dir / "reports").glob("*.html"))
    assert list((temp_dir / "reports").glob("*.json"))
    assert list((temp_dir / "reports").glob("*.md"))


def test_cli_json_flow_still_works():
    temp_dir = Path(mkdtemp(prefix="greynoc_cli_json_"))
    code = main(["--json", str(sample_project_path()), "--out", str(temp_dir / "reports"), "--db", str(temp_dir / "db.sqlite3")])
    assert code == 0
    assert list((temp_dir / "reports").glob("*.json"))


def test_cli_fail_on_new_critical_returns_nonzero():
    temp_dir = Path(mkdtemp(prefix="greynoc_cli_fail_"))
    project = temp_dir / "project"
    project.mkdir()
    (project / ".env").write_text("PRIVATE_KEY=-----BEGIN PRIVATE KEY----- GNOC_FAKE_SECRET_DO_NOT_USE -----END PRIVATE KEY-----\n", encoding="utf-8")
    code = main(["--scan", str(project), "--out", str(temp_dir / "reports"), "--db", str(temp_dir / "db.sqlite3"), "--fail-on-new", "critical"])
    assert code == 1


def test_cli_bare_invocation_creates_no_db(tmp_path):
    db_path = tmp_path / "db.sqlite3"
    code = main(["--db", str(db_path)])
    assert code == 1
    assert not db_path.exists()
    assert not (tmp_path / "db_cache.sqlite3").exists()


def test_cli_missing_baseline_returns_config_error(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hi')\n", encoding="utf-8")
    db_path = tmp_path / "db.sqlite3"
    code = main([
        "--scan", str(project),
        "--out", str(tmp_path / "reports"),
        "--db", str(db_path),
        "--baseline", str(tmp_path / "missing_baseline.json"),
    ])
    assert code == 3
    assert not db_path.exists()


def test_cli_malformed_baseline_returns_config_error(tmp_path):
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hi')\n", encoding="utf-8")
    baseline = tmp_path / "baseline.json"
    baseline.write_text("{not valid json", encoding="utf-8")
    code = main([
        "--scan", str(project),
        "--out", str(tmp_path / "reports"),
        "--db", str(tmp_path / "db.sqlite3"),
        "--baseline", str(baseline),
    ])
    assert code == 3


def test_cli_untrusted_scan_fails_closed_with_fail_on_new(tmp_path, monkeypatch):
    from greynoc_nhi.scanner import Scanner

    def boom(self, project_path, only_paths=None):
        raise RuntimeError("simulated scanner crash")

    monkeypatch.setattr(Scanner, "scan", boom)
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hi')\n", encoding="utf-8")
    code = main([
        "--scan", str(project),
        "--out", str(tmp_path / "reports"),
        "--db", str(tmp_path / "db.sqlite3"),
        "--fail-on-new", "high",
    ])
    assert code == 10


def test_cli_trend_failure_does_not_kill_scan(tmp_path, monkeypatch, capsys):
    import greynoc_nhi.trend as trend_mod

    def boom(storage, result):
        raise RuntimeError("trend blew up")

    monkeypatch.setattr(trend_mod, "compute_trend", boom)
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("print('hi')\n", encoding="utf-8")
    code = main([
        "--scan", str(project),
        "--trend",
        "--out", str(tmp_path / "reports"),
        "--db", str(tmp_path / "db.sqlite3"),
    ])
    captured = capsys.readouterr()
    assert code == 0
    # The best-effort trend diagnostic goes to stderr so --json stdout stays a
    # clean machine-readable payload.
    assert "Trend unavailable" in captured.err
    assert "Trend unavailable" not in captured.out
