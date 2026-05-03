from pathlib import Path

from greynoc_nhi.engine import Engine
from greynoc_nhi.reports import generate_html_report
from greynoc_nhi.sample_data import sample_project_path


def test_report_generation_creates_html(tmp_path: Path):
    result = Engine(tmp_path / "db.sqlite3").run_scan(sample_project_path())
    report = generate_html_report(result, tmp_path)
    assert report.exists()
    text = report.read_text(encoding="utf-8")
    assert "GreyNOC Non-Human Identity Risk Engine" in text
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in text
