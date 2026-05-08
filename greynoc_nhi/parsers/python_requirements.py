"""Requirements parser placeholder for dependency-adjacent NHI context."""

from __future__ import annotations

__version__ = 1

from pathlib import Path

from greynoc_nhi.parsers.base import Signal

def should_parse(path: Path) -> bool:
    return path.name.lower() == "requirements.txt"

def parse(path: Path, text: str) -> list[Signal]:
    return []
