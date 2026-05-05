from pathlib import Path
from tempfile import mkdtemp

from greynoc_nhi.engine import Engine
from greynoc_nhi.sample_data import sample_project_path
from greynoc_nhi.storage import Storage


def test_storage_save_and_load_scan():
    temp_dir = mkdtemp(prefix="greynoc_nhi_test_")
    db_path = Path(temp_dir) / "test.sqlite3"
    storage = Storage(db_path)
    result = Engine(db_path).run_scan(sample_project_path())
    loaded = storage.get_scan(result.scan_id)
    assert loaded is not None
    assert loaded.scan_id == result.scan_id
    assert loaded.findings
