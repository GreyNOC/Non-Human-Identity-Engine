"""Utility helpers used across the local scanner."""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def stable_id(prefix: str, *parts: object) -> str:
    import hashlib

    raw = "|".join(str(part) for part in parts)
    return f"{prefix}_{hashlib.sha1(raw.encode('utf-8')).hexdigest()[:16]}"


def read_text_safely(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        try:
            return path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return None
    except OSError:
        return None


def parse_json_safely(text: str) -> Any | None:
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        return None


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


def line_number_for(text: str, needle: str) -> int | None:
    for number, line in enumerate(text.splitlines(), 1):
        if needle in line:
            return number
    return None


def line_number_at_offset(text: str, offset: int) -> int:
    return text.count("\n", 0, max(0, offset)) + 1


def line_number_for_key_value(text: str, key: str, value: object | None = None) -> int | None:
    key_tail = str(key).split(".")[-1].split("[")[0]
    value_s = "" if value is None else str(value)
    for number, line in enumerate(text.splitlines(), 1):
        if key_tail and key_tail in line:
            return number
        if value_s and value_s in line:
            return number
    return None


def has_word(text: str, words: list[str]) -> bool:
    lower = text.lower()
    return any(re.search(rf"\b{re.escape(word.lower())}\b", lower) for word in words)
