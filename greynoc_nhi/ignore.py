"""Project-local .greynocignore support."""

from __future__ import annotations

import fnmatch
from pathlib import Path


def load_greynocignore(project_root: str | Path) -> list[str]:
    path = Path(project_root) / ".greynocignore"
    if not path.exists():
        return []
    patterns: list[str] = []
    try:
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            patterns.append(line.replace("\\", "/").strip("/"))
    except OSError:
        return []
    return patterns


def is_ignored(path: Path, root: Path, patterns: list[str]) -> bool:
    if not patterns:
        return False
    rel = path.resolve().relative_to(root.resolve()).as_posix()
    name = path.name
    for pattern in patterns:
        if pattern == name or pattern == rel:
            return True
        if fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(name, pattern):
            return True
        if pattern.endswith("/*") and rel.startswith(pattern[:-1]):
            return True
    return False
