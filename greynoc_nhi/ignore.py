"""Project-local .greynocignore support."""

from __future__ import annotations

import fnmatch
import re
from pathlib import Path

_GLOB_REGEX_CACHE: dict[str, re.Pattern[str]] = {}


def _glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile a gitignore-style glob where `*`/`?` do NOT cross `/`.

    fnmatch treats `*` as matching path separators too, so an anchored pattern
    like `/*.env` (intended for root-level files only) would wrongly match
    `sub/prod.env` and silently exclude nested secret files from the scan. Here
    `*` -> `[^/]*`, `?` -> `[^/]`, and `**` matches across directories.
    """
    cached = _GLOB_REGEX_CACHE.get(pattern)
    if cached is not None:
        return cached
    i, n = 0, len(pattern)
    parts: list[str] = []
    while i < n:
        char = pattern[i]
        if char == "*":
            if i + 1 < n and pattern[i + 1] == "*":
                # `**` matches across directories but only on whole-segment
                # boundaries (matching git), so it never swallows a partial file
                # name: `**/config.env` matches config.env and a/b/config.env but
                # NOT myconfig.env.
                i += 2
                if i < n and pattern[i] == "/":
                    # `**/` -> zero or more complete leading directory segments.
                    parts.append("(?:[^/]*/)*")
                    i += 1
                elif i == n:
                    # trailing `/**` (the leading `/` was already consumed) ->
                    # everything under the directory.
                    parts.append(".*")
                else:
                    parts.append(".*")
                continue
            parts.append("[^/]*")
        elif char == "?":
            parts.append("[^/]")
        else:
            parts.append(re.escape(char))
        i += 1
    compiled = re.compile("(?s:" + "".join(parts) + r")\Z")
    _GLOB_REGEX_CACHE[pattern] = compiled
    return compiled


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
            # Preserve a leading "!" (negation) and a leading "/" (root
            # anchoring); is_ignored interprets both gitignore-style.
            patterns.append(line.replace("\\", "/"))
    except OSError:
        return []
    return patterns


def is_ignored(path: Path, root: Path, patterns: list[str], *, rel: str | None = None) -> bool:
    """Return True when `path` matches the ignore patterns.

    Patterns are evaluated in order with gitignore-style last-match-wins
    semantics: a leading "!" re-includes a previously ignored path, and a
    leading "/" anchors the pattern to the project root (it no longer
    matches the bare name at any depth).

    When `rel` (the POSIX-style path relative to `root`) is provided, the
    expensive resolve() calls are skipped; callers that already computed the
    relative path (the scanner traversal) should pass it in.
    """
    if not patterns:
        return False
    if rel is None:
        try:
            rel = path.resolve().relative_to(root.resolve()).as_posix()
        except (OSError, ValueError):
            # Path resolves outside the project root (e.g. via a symlink) or
            # cannot be resolved. Treat as ignored so it never enters the scan.
            return True
    name = path.name
    ignored = False
    for raw_pattern in patterns:
        pattern = raw_pattern
        negated = pattern.startswith("!")
        if negated:
            pattern = pattern[1:]
        anchored = pattern.startswith("/")
        pattern = pattern.strip("/")
        if not pattern:
            continue
        if anchored:
            matched = (
                pattern == rel
                or bool(_glob_to_regex(pattern).match(rel))
                or rel.startswith(pattern + "/")
            )
        else:
            matched = (
                pattern == name
                or pattern == rel
                or bool(_glob_to_regex(pattern).match(rel))
                or fnmatch.fnmatch(name, pattern)
                or rel.startswith(pattern + "/")
            )
        if matched:
            ignored = not negated
    return ignored
