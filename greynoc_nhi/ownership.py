"""Ownership enrichment via `git blame` + CODEOWNERS.

Populates the `owner` field on identities for working-tree paths so reports
can answer "who do we ask about this?" rather than just "this exists."
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path

CODEOWNERS_LOCATIONS = (
    ".github/CODEOWNERS",
    ".gitlab/CODEOWNERS",
    "docs/CODEOWNERS",
    "CODEOWNERS",
)

_PORCELAIN_HEADER_RE = re.compile(r"^([0-9a-f]{40})\s+(\d+)\s+(\d+)(?:\s+(\d+))?$")


@dataclass
class CodeownersRule:
    pattern: str
    owners: list[str]
    globs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.globs:
            self.globs = _glob_for_pattern(self.pattern)


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
        for glob in rule.globs:
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


def _batch_blame_owners(
    repo_root: Path,
    file_path: str,
    line_numbers: list[int],
    *,
    timeout_seconds: int = 30,
) -> dict[int, BlameOwner] | None:
    """Blame several lines of one file with a single `git blame` subprocess.

    Returns a {line_number: BlameOwner} map, or None when the batched call
    fails (callers should fall back to per-line git_blame_owner).
    """
    rel = file_path.replace("\\", "/")
    args = ["git", "-C", str(repo_root), "blame"]
    for number in sorted(set(line_numbers)):
        args.extend(["-L", f"{number},{number}"])
    args.extend(["--porcelain", "--", rel])
    try:
        result = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            errors="replace",
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None
    if result.returncode != 0:
        return None
    owners: dict[int, BlameOwner] = {}
    commit_meta: dict[str, dict[str, object]] = {}
    current_sha: str | None = None
    current_line: int | None = None
    for line in result.stdout.splitlines():
        if line.startswith("\t"):
            if current_sha is not None and current_line is not None:
                meta = commit_meta.get(current_sha, {})
                email = str(meta.get("email", "") or "")
                name = str(meta.get("name", "") or "")
                timestamp = meta.get("timestamp")
                if email or name:
                    owners[current_line] = BlameOwner(
                        email=email,
                        name=name,
                        timestamp=timestamp if isinstance(timestamp, int) else None,
                    )
            current_sha = None
            current_line = None
            continue
        header = _PORCELAIN_HEADER_RE.match(line)
        if header:
            current_sha = header.group(1)
            current_line = int(header.group(3))
            commit_meta.setdefault(current_sha, {})
            continue
        if current_sha is None:
            continue
        if line.startswith("author-mail "):
            mail = line[len("author-mail "):].strip()
            if mail.startswith("<") and mail.endswith(">"):
                mail = mail[1:-1]
            commit_meta[current_sha]["email"] = mail
        elif line.startswith("author-time "):
            try:
                commit_meta[current_sha]["timestamp"] = int(line[len("author-time "):].strip())
            except (TypeError, ValueError):
                pass
        elif line.startswith("author "):
            commit_meta[current_sha]["name"] = line[len("author "):].strip()
    return owners


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
    rel_cache: dict[str, str | None] = {}
    candidates: list[tuple[object, str, int]] = []
    lines_by_file: dict[str, set[int]] = {}
    for identity in identities:
        if identity.owner:
            continue
        if identity.commit_sha:
            continue
        if not identity.file_path or not identity.line_number:
            continue
        try:
            file_key = str(identity.file_path)
            if file_key not in rel_cache:
                try:
                    rel_cache[file_key] = str(Path(file_key).resolve().relative_to(root)).replace("\\", "/")
                except (ValueError, OSError):
                    rel_cache[file_key] = None
            rel_str = rel_cache[file_key]
            if rel_str is None:
                continue
            line = int(identity.line_number)
        except Exception:
            continue
        candidates.append((identity, rel_str, line))
        lines_by_file.setdefault(rel_str, set()).add(line)

    blame_by_location: dict[tuple[str, int], BlameOwner | None] = {}
    for rel_str, numbers in lines_by_file.items():
        try:
            batched = _batch_blame_owners(root, rel_str, sorted(numbers))
        except Exception:
            batched = None
        for number in numbers:
            if batched is None:
                blame_by_location[(rel_str, number)] = git_blame_owner(root, rel_str, number)
            else:
                blame_by_location[(rel_str, number)] = batched.get(number)

    codeowners_cache: dict[str, list[str]] = {}
    for identity, rel_str, line in candidates:
        try:
            blame = blame_by_location.get((rel_str, line))
            if rules:
                if rel_str not in codeowners_cache:
                    codeowners_cache[rel_str] = codeowners_for_path(rules, rel_str)
                owners = codeowners_cache[rel_str]
            else:
                owners = []
            described = describe_owner(blame, owners)
            if described:
                identity.owner = described
                enriched += 1
        except Exception:
            continue
    return enriched
