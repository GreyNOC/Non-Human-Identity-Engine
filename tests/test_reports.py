from pathlib import Path
from tempfile import mkdtemp

from greynoc_nhi.engine import Engine
from greynoc_nhi.reports import generate_html_report
from greynoc_nhi.sample_data import sample_project_path


def test_report_generation_creates_html():
    temp_dir = mkdtemp(prefix="greynoc_nhi_test_")
    result = Engine(Path(temp_dir) / "db.sqlite3").run_scan(sample_project_path())
    report_dir = Path(mkdtemp(prefix="greynoc_nhi_report_test_"))
    report = generate_html_report(result, report_dir)
    assert report.exists()
    text = report.read_text(encoding="utf-8")
    assert "GreyNOC Non-Human Identity Risk Engine" in text
    assert "GNOC_FAKE_SECRET_DO_NOT_USE" not in text
