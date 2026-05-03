"""Filesystem scanner that dispatches local parser modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from greynoc_nhi.constants import IGNORED_DIRS, MAX_FILE_BYTES, SCAN_EXTENSIONS, SCAN_FILE_NAMES
from greynoc_nhi.parsers import PARSERS
from greynoc_nhi.utils import read_text_safely


def should_scan_file(path: Path) -> bool:
    """Return True when a file is small and relevant enough to scan."""
    name = path.name.lower()
    if name in SCAN_FILE_NAMES or path.suffix.lower() in SCAN_EXTENSIONS or name.startswith(".env"):
        try:
            return path.stat().st_size <= MAX_FILE_BYTES
        except OSError:
            return False
    return False


def iter_scan_files(project_path: str | Path) -> list[Path]:
    """Recursively list scan candidates while skipping noisy dependency folders."""
    root = Path(project_path)
    files: list[Path] = []
    for path in root.rglob("*"):
        if any(part in IGNORED_DIRS for part in path.parts):
            continue
        if path.is_file() and should_scan_file(path):
            files.append(path)
    return sorted(files)


class Scanner:
    """Local recursive scanner."""

    def __init__(self, ignored_dirs: set[str] | None = None) -> None:
        self.ignored_dirs = ignored_dirs or IGNORED_DIRS

    def scan(self, project_path: str | Path) -> dict[str, Any]:
        root = Path(project_path).resolve()
        signals: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        scanned_files = 0
        skipped_files = 0
        for path in iter_scan_files(root):
            text = read_text_safely(path)
            if text is None:
                skipped_files += 1
                continue
            scanned_files += 1
            for parser in PARSERS:
                try:
                    if parser.should_parse(path):
                        signals.extend(parser.parse(path, text))
                except Exception as exc:  # Defensive parser isolation.
                    errors.append({"file": str(path), "parser": parser.__name__, "error": str(exc)})
        return {"project_path": str(root), "signals": signals, "errors": errors, "scanned_files": scanned_files, "skipped_files": skipped_files}
