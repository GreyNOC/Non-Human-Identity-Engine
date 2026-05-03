from pathlib import Path

from greynoc_nhi.scanner import Scanner


def test_scanner_skips_ignored_dirs(tmp_path: Path):
    ignored = tmp_path / "node_modules"
    ignored.mkdir()
    (ignored / ".env").write_text("OPENAI_API_KEY=FAKE_OPENAI_KEY_DO_NOT_USE_123456", encoding="utf-8")
    result = Scanner().scan(tmp_path)
    assert result["scanned_files"] == 0
    assert result["signals"] == []
