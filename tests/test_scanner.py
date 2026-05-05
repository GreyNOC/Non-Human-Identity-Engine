from pathlib import Path
from tempfile import mkdtemp

from greynoc_nhi.scanner import Scanner, dedupe_signals


def test_scanner_skips_ignored_dirs():
    project = Path(mkdtemp(prefix="greynoc_nhi_scanner_test_"))
    ignored = project / "node_modules"
    ignored.mkdir()
    (ignored / ".env").write_text("OPENAI_API_KEY=FAKE_OPENAI_KEY_DO_NOT_USE_123456", encoding="utf-8")
    result = Scanner().scan(project)
    assert result["scanned_files"] == 0
    assert result["signals"] == []


def test_scanner_dedupes_identical_signals():
    signal = {"rule_id": "x", "file_path": "a", "line_number": 1, "name": "n", "evidence": ["masked"]}
    assert dedupe_signals([signal, dict(signal)]) == [signal]
