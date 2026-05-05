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
