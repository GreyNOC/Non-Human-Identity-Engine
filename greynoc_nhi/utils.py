"""Utility helpers used across the local scanner."""

from __future__ import annotations

import bisect
import functools
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from greynoc_nhi.constants import MAX_FILE_BYTES


RAW_SECRET_MARKER_RE = re.compile(r"GNOC_FAKE_SECRET_DO_NOT_USE|-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_id(prefix: str, *parts: object) -> str:
    import hashlib

    raw = "|".join(str(part) for part in parts)
    return f"{prefix}_{hashlib.sha256(raw.encode('utf-8')).hexdigest()[:16]}"


def read_text_safely(path: Path) -> str | None:
    """Read a file once as bytes and decode in memory.

    Reading bytes avoids the double full-file read that `read_text` performs
    on non-UTF-8 content (decode failure triggered a second read with
    errors="replace"). The size check closes the stat-to-read TOCTOU window:
    a file that grew past MAX_FILE_BYTES after the traversal stat is refused
    here. Newlines are normalized exactly like `read_text`'s universal
    newline translation so parser output and cache hashes are unchanged.
    """
    try:
        data = path.read_bytes()
    except OSError:
        return None
    if len(data) > MAX_FILE_BYTES:
        return None
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("utf-8", errors="replace")
    return text.replace("\r\n", "\n").replace("\r", "\n")


def chmod_private_file(path: Path) -> None:
    """Best-effort owner-only permissions for local sensitive artifacts."""
    if os.name == "nt":
        return
    try:
        path.chmod(0o600)
    except OSError:
        pass


def chmod_sqlite_sidecars(path: Path) -> None:
    """Apply private permissions to a SQLite file and any journal sidecars."""
    for suffix in ("", "-wal", "-shm", "-journal"):
        chmod_private_file(Path(f"{path}{suffix}"))


def chmod_private_dir(path: Path) -> None:
    """Best-effort owner-only directory permissions for local scan artifacts."""
    if os.name == "nt":
        return
    try:
        path.chmod(0o700)
    except OSError:
        pass


def assert_no_raw_secret_markers(payload: object) -> None:
    """Fail closed before writing artifacts that still contain raw secret markers."""
    text = payload if isinstance(payload, str) else json.dumps(payload, default=str)
    if RAW_SECRET_MARKER_RE.search(text):
        raise ValueError("Refusing to write artifact containing raw secret marker")


def parse_json_safely(text: str) -> Any | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


@functools.lru_cache(maxsize=4)
def parse_json_cached(text: str) -> Any | None:
    """Memoized parse_json_safely for parsers that share the same file text.

    Multiple parsers frequently run over the identical text while the scanner
    processes one file, so a tiny LRU turns the second-and-later json.loads
    calls into cache hits. Callers MUST treat the returned object as
    read-only: it is shared across every caller that passes the same text.
    """
    return parse_json_safely(text)


def flatten_json(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
    rows: list[tuple[str, Any]] = []
    if isinstance(obj, dict):
        for key, value in obj.items():
            next_key = f"{prefix}.{key}" if prefix else str(key)
            rows.extend(flatten_json(value, next_key))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            rows.extend(flatten_json(value, f"{prefix}[{idx}]"))
    else:
        rows.append((prefix, obj))
    return rows


def simple_yaml_pairs(text: str) -> list[tuple[str, str, int]]:
    """Best-effort YAML-ish key/value extraction without external deps."""
    rows: list[tuple[str, str, int]] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or ":" not in stripped:
            continue
        key, value = stripped.split(":", 1)
        rows.append((key.strip("- ").strip(), value.strip().strip("'\""), number))
    return rows


def simple_kv_pairs(text: str, separators: tuple[str, ...] = (":", "=")) -> list[tuple[str, str, int]]:
    """Best-effort key/value extraction for TOML/INI/.cfg/.conf-style files.

    Each line is split on whichever separator appears first, so
    `password = hunter2` (TOML/INI) and `password: hunter2` (YAML-ish) both
    yield rows, and separators inside the value are left alone. Trailing
    unquoted `# ...` / `; ...` comments are stripped from values. Kept
    separate from simple_yaml_pairs on purpose: '='-splitting on YAML would
    mangle lines like `command: FOO=bar run`.
    """
    rows: list[tuple[str, str, int]] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(";"):
            continue
        splits = [(pos, sep) for pos, sep in ((stripped.find(sep), sep) for sep in separators) if pos > 0]
        if not splits:
            continue
        pos, sep = min(splits)
        key, value = stripped[:pos], stripped[pos + len(sep):]
        value = value.strip()
        if value and value[0] in "'\"":
            closing = value.find(value[0], 1)
            if closing != -1:
                value = value[1:closing]
            else:
                value = value.strip("'\"")
        else:
            for marker in (" #", "\t#", " ;", "\t;"):
                idx = value.find(marker)
                if idx != -1:
                    value = value[:idx]
            value = value.strip()
        rows.append((key.strip("- ").strip(), value, number))
    return rows


def line_number_for(text: str, needle: str, lines: list[str] | None = None) -> int | None:
    for number, line in enumerate(lines if lines is not None else text.splitlines(), 1):
        if needle in line:
            return number
    return None


def line_number_at_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def line_number_for_key_value(
    text: str,
    key: str,
    value: object | None = None,
    lines: list[str] | None = None,
) -> int | None:
    key_tail = str(key).split(".")[-1].split("[")[0]
    value_s = "" if value is None else str(value)
    for number, line in enumerate(lines if lines is not None else text.splitlines(), 1):
        if key_tail and key_tail in line:
            return number
        if value_s and value_s in line:
            return number
    return None


class LineIndex:
    """Precomputed line index for repeated lookups over a single text.

    Callers emitting many signals per file should build one LineIndex and
    reuse it, instead of paying a full text.splitlines() per lookup
    (O(signals x file size)). The `lines` attribute can also be passed to
    line_number_for / line_number_for_key_value directly.
    """

    __slots__ = ("text", "lines", "_starts")

    def __init__(self, text: str) -> None:
        self.text = text
        self.lines = text.splitlines()
        starts = [0]
        pos = text.find("\n")
        while pos != -1:
            starts.append(pos + 1)
            pos = text.find("\n", pos + 1)
        self._starts = starts

    def line_at_offset(self, offset: int) -> int:
        """bisect-based equivalent of line_number_at_offset."""
        return bisect.bisect_right(self._starts, max(0, offset))

    def line_for(self, needle: str) -> int | None:
        return line_number_for(self.text, needle, lines=self.lines)

    def line_for_key_value(self, key: str, value: object | None = None) -> int | None:
        return line_number_for_key_value(self.text, key, value, lines=self.lines)


def has_word(text: str, words: list[str]) -> bool:
    lower = text.lower()
    return any(re.search(rf"\b{re.escape(word.lower())}\b", lower) for word in words)
