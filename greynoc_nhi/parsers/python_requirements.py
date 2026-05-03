"""Requirements parser placeholder for dependency-adjacent NHI context."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers.base import Signal


def should_parse(path: Path) -> bool:
    return path.name.lower() == "requirements.txt"


def parse(path: Path, text: str) -> list[Signal]:
    return []
