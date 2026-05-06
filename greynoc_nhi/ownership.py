"""Ownership enrichment via `git blame` + CODEOWNERS.

Populates the `owner` field on identities for working-tree paths so reports
can answer "who do we ask about this?" rather than just "this exists."
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

CODEOWNERS_LOCATIONS = (
    ".github/CODEOWNERS",
    ".gitlab/CODEOWNERS",
    "docs/CODEOWNERS",
    "CODEOWNERS",
)


@dataclass
class CodeownersRule:
    pattern: str
    owners: list[str]


@dataclass
class BlameOwner:
    email: str
    name: str
    timestamp: int | None

    def display(self) -> str:
        when = ""
        if self.timestamp is not None:
            try:
                when = datetime.fromtimestamp(self.timestamp, tz=timezone.utc).strftime("%Y-%m")
            except (ValueError, OverflowError, OSError):
                when = ""
        identity = self.email or self.name or "unknown"
        return f"{identity} (last modified {when})" if when else identity


def find_codeowners_file(repo_root: Path) -> Path | None:
    for location in CODEOWNERS_LOCATIONS:
        candidate = repo_root / location
        if candidate.is_file():
            return candidate
    return None


def parse_codeowners_text(text: str) -> list[CodeownersRule]:
    rules: list[CodeownersRule] = []
    for raw_line in text.splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            continue
        pattern = parts[0]
        owners = [p for p in parts[1:] if p]
        if not owners:
            continue
        rules.append(CodeownersRule(pattern=pattern, owners=owners))
    return rules


def load_codeowners(repo_root: Path) -> list[CodeownersRule]:
    path = find_codeowners_file(repo_root)
    if path is None:
        return []
    try:
        return parse_codeowners_text(path.read_text(encoding="utf-8"))
    except OSError:
        return []


def _glob_for_pattern(pattern: str) -> list[str]:
    """Convert a CODEOWNERS pattern into one or more fnmatch globs."""
    pat = pattern
    anchored = pat.startswith("/")
    if anchored:
        pat = pat[1:]
    is_dir = pat.endswith("/")
    if is_dir:
        pat = pat.rstrip("/")
    if not pat:
        return []
    if anchored:
        candidates = [pat]
    else:
        candidates = [pat, f"**/{pat}"]
    if is_dir:
        candidates = [f"{c}/**" for c in candidates] + [c for c in candidates]
    return candidates


def codeowners_for_path(rules: list[CodeownersRule], rel_path: str) -> list[str]:
    """Return owners that match `rel_path`; the LAST matching rule wins."""
    rel = rel_path.replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    matched: list[str] = []
    for rule in rules:
        for glob in _glob_for_pattern(rule.pattern):
            if fnmatch(rel, glob):
                matched = rule.owners
                break
    return matched


def git_blame_owner(
    repo_root: Path,
    file_path: str,
    line_number: int,
    *,
    timeout_seconds: int = 30,
) -> BlameOwner | None:
    """Return blame info for a given line, or None if blame is unavailable."""
    rel = file_path.replace("\\", "/")
    try:
        result = subprocess.run(
            [
                "git",
                "-C",
                str(repo_root),
                "blame",
                "-L",
                f"{line_number},{line_number}",
                "--porcelain",
                "--",
                rel,
            ],
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            errors="replace",
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None
    if result.returncode != 0:
        return None
    email = ""
    name = ""
    timestamp: int | None = None
    for line in result.stdout.splitlines():
        if line.startswith("author-mail "):
            mail = line[len("author-mail "):].strip()
            if mail.startswith("<") and mail.endswith(">"):
                mail = mail[1:-1]
            email = mail
        elif line.startswith("author "):
            name = line[len("author "):].strip()
        elif line.startswith("author-time "):
            try:
                timestamp = int(line[len("author-time "):].strip())
            except (TypeError, ValueError):
                timestamp = None
    if not email and not name:
        return None
    return BlameOwner(email=email, name=name, timestamp=timestamp)


def describe_owner(blame: BlameOwner | None, codeowners: list[str]) -> str | None:
    parts: list[str] = []
    if blame is not None:
        parts.append(blame.display())
    if codeowners:
        parts.append(f"{', '.join(codeowners)} via CODEOWNERS")
    if not parts:
        return None
    return "; ".join(parts)


def enrich_identity_owners(identities, project_root: str | Path) -> int:
    """Populate identity.owner using git blame + CODEOWNERS where missing."""
    root = Path(project_root).resolve()
    rules = load_codeowners(root)
    enriched = 0
    for identity in identities:
        if identity.owner:
            continue
        if identity.commit_sha:
            continue
        if not identity.file_path or not identity.line_number:
            continue
        try:
            abs_path = Path(identity.file_path)
            try:
                rel = abs_path.resolve().relative_to(root)
            except (ValueError, OSError):
                continue
            rel_str = str(rel).replace("\\", "/")
            blame = git_blame_owner(root, rel_str, int(identity.line_number))
            owners = codeowners_for_path(rules, rel_str) if rules else []
            described = describe_owner(blame, owners)
            if described:
                identity.owner = described
                enriched += 1
        except Exception:
            continue
    return enriched
