from pathlib import Path

from greynoc_nhi.engine import Engine
from greynoc_nhi.sample_data import sample_project_path
from greynoc_nhi.storage import Storage


def test_storage_save_and_load_scan(tmp_path: Path):
    storage = Storage(tmp_path / "test.sqlite3")
    result = Engine(tmp_path / "test.sqlite3").run_scan(sample_project_path())
    loaded = storage.get_scan(result.scan_id)
    assert loaded is not None
    assert loaded.scan_id == result.scan_id
    assert loaded.findings
