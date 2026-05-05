"""Filesystem scanner that dispatches local parser modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from greynoc_nhi.constants import IGNORED_DIRS, MAX_FILE_BYTES, SCAN_EXTENSIONS, SCAN_FILE_NAMES
from greynoc_nhi.custom_rules import CustomRule, load_rule_pack, scan_custom_rules
from greynoc_nhi.ignore import is_ignored, load_greynocignore
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


def iter_scan_files(project_path: str | Path, ignored_dirs: set[str] | None = None, ignore_patterns: list[str] | None = None) -> list[Path]:
    """Recursively list scan candidates while skipping noisy dependency folders."""
    ignored = ignored_dirs or IGNORED_DIRS
    root = Path(project_path)
    patterns = ignore_patterns or []
    files: list[Path] = []
    stack = [root]
    while stack:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except OSError:
            continue
        for path in children:
            if is_ignored(path, root, patterns):
                continue
            if path.is_dir():
                if path.name not in ignored:
                    stack.append(path)
                continue
            if path.is_file() and should_scan_file(path):
                files.append(path)
    return sorted(files)


def dedupe_signals(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop duplicate parser signals while preserving order."""
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for signal in signals:
        key = (
            signal.get("rule_id"),
            signal.get("file_path"),
            signal.get("line_number"),
            signal.get("name"),
            tuple(signal.get("evidence", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(signal)
    return deduped


class Scanner:
    """Local recursive scanner."""

    def __init__(self, ignored_dirs: set[str] | None = None, rule_pack_path: str | Path | None = None) -> None:
        self.ignored_dirs = ignored_dirs or IGNORED_DIRS
        self.custom_rules: list[CustomRule] = load_rule_pack(rule_pack_path)

    def scan(self, project_path: str | Path) -> dict[str, Any]:
        root = Path(project_path).resolve()
        signals: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        scanned_files = 0
        skipped_files = 0
        parser_cache: dict[tuple[str, str, str], list[Any]] = {}
        ignore_patterns = load_greynocignore(root)
        for path in iter_scan_files(root, self.ignored_dirs, ignore_patterns):
            text = read_text_safely(path)
            if text is None:
                skipped_files += 1
                continue
            scanned_files += 1
            cache_key = (path.name.lower(), path.suffix.lower(), str(path.parent).replace("\\", "/").lower())
            parsers = parser_cache.get(cache_key)
            if parsers is None:
                parsers = [parser for parser in PARSERS if parser.should_parse(path)]
                parser_cache[cache_key] = parsers
            for parser in parsers:
                try:
                    signals.extend(parser.parse(path, text))
                except Exception as exc:  # Defensive parser isolation.
                    errors.append({"file": str(path), "parser": parser.__name__, "error": str(exc)})
            signals.extend(scan_custom_rules(path, text, self.custom_rules))
        return {"project_path": str(root), "signals": dedupe_signals(signals), "errors": errors, "scanned_files": scanned_files, "skipped_files": skipped_files, "ignore_patterns": ignore_patterns, "custom_rules": self.custom_rules}
