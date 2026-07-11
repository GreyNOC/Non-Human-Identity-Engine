"""Scan git history for secrets that were committed and later removed.

This module dumps `git log -p` output via subprocess and re-parses the unified
diff so the existing parser registry can run over historical content. Each
finding is enriched with the commit SHA, author, and date it was introduced in.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Iterator

GIT_LOG_TIMEOUT_SECONDS = 600
COMMIT_DELIMITER = "=== GREYNOC COMMIT ==="
HUNK_HEADER_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@")


@dataclass
class CommitInfo:
    """Metadata pulled from `git log` for a single commit."""

    sha: str
    short_sha: str
    author_name: str
    author_email: str
    date: str
    subject: str

    def display(self) -> str:
        identity = self.author_email or self.author_name or "unknown"
        return f"{self.short_sha} by {identity} on {self.date}"


@dataclass
class HistoryChange:
    """Added lines from a single (commit, file) pair, ready for parser dispatch.

    `synthetic_text` is the concatenation of `+` lines (without the leading `+`)
    joined by newlines, so parsers see something that resembles a tiny snippet
    of the file. `line_map[i]` maps synthetic line `i+1` back to the file's
    actual line number at that commit, so we can rewrite parser-reported
    line numbers to make sense in reports.
    """

    commit: CommitInfo
    file_path: str
    synthetic_text: str
    line_map: list[int]


def is_git_repository(path: str | Path) -> bool:
    """Return True when `path` is inside a git working tree."""
    try:
        result = subprocess.run(
            ["git", "-C", str(path), "rev-parse", "--git-dir"],
            capture_output=True,
            text=True,
            timeout=10,
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0


def _run_git_log(
    project_path: Path,
    max_commits: int | None,
    since: str | None,
) -> str:
    pretty = (
        f"%n{COMMIT_DELIMITER}%n"
        "%H%x09%h%x09%an%x09%ae%x09%aI%x09%s"
    )
    cmd = [
        "git",
        # Emit non-ASCII paths raw (UTF-8) instead of C-quoted so the
        # `+++ b/` prefix match in parse_git_log sees them.
        "-c",
        "core.quotePath=false",
        "-C",
        str(project_path),
        "log",
        "-p",
        "--no-color",
        "--no-merges",
        # Context lines are never consumed (parse_git_log only reads `+`
        # lines and hunk headers), so drop them to shrink output.
        "--unified=0",
        f"--format={pretty}",
    ]
    if max_commits is not None and max_commits > 0:
        cmd.extend(["-n", str(max_commits)])
    if since:
        cmd.extend(["--since", since])
    cmd.append("--all")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=GIT_LOG_TIMEOUT_SECONDS,
            encoding="utf-8",
            errors="replace",
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"git log failed: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError(f"git log returned {result.returncode}: {result.stderr.strip()[:200]}")
    return result.stdout


def _unquote_git_path(quoted: str) -> str:
    """Decode a C-quoted git path like '"b/caf\\303\\251/.env"' to 'café/.env'.

    Git quotes paths containing escapes-worthy bytes even with
    core.quotePath=false (embedded quotes, control characters). Falls back
    to the raw string when decoding fails.
    """
    inner = quoted.strip()
    if inner.startswith('"') and inner.endswith('"') and len(inner) >= 2:
        inner = inner[1:-1]
    if inner.startswith("b/"):
        inner = inner[2:]
    try:
        return (
            inner.encode("latin-1", "backslashreplace")
            .decode("unicode_escape")
            .encode("latin-1")
            .decode("utf-8", "replace")
        )
    except (UnicodeDecodeError, UnicodeEncodeError):
        return inner


def parse_git_log(output: str) -> list[HistoryChange]:
    """Parse `git log -p` output into HistoryChange records."""
    changes: list[HistoryChange] = []
    current_commit: CommitInfo | None = None
    current_file: str | None = None
    current_added: list[tuple[int, str]] = []
    new_line_no = 0
    in_hunk = False

    def flush() -> None:
        nonlocal current_added, current_file, in_hunk
        if current_commit and current_file and current_added:
            synthetic_text = "\n".join(text for _, text in current_added)
            line_map = [orig for orig, _ in current_added]
            changes.append(
                HistoryChange(
                    commit=current_commit,
                    file_path=current_file,
                    synthetic_text=synthetic_text,
                    line_map=line_map,
                )
            )
        current_added = []
        current_file = None
        in_hunk = False

    lines = output.splitlines()
    i = 0
    while i < len(lines):
        line = lines[i]
        if line == COMMIT_DELIMITER and i + 1 < len(lines):
            flush()
            header = lines[i + 1]
            parts = header.split("\t")
            if len(parts) >= 6:
                current_commit = CommitInfo(
                    sha=parts[0],
                    short_sha=parts[1],
                    author_name=parts[2],
                    author_email=parts[3],
                    date=parts[4],
                    subject=parts[5],
                )
            i += 2
            continue
        if line.startswith("diff --git"):
            flush()
            i += 1
            continue
        if line.startswith("+++ b/"):
            # Git appends a tab after paths containing spaces.
            current_file = line[6:].rstrip("\t")
            i += 1
            continue
        if line.startswith('+++ "b/'):
            current_file = _unquote_git_path(line[4:].rstrip("\t"))
            i += 1
            continue
        if line.startswith("+++ /dev/null"):
            current_file = None
            i += 1
            continue
        if line.startswith("--- ") or line.startswith("index ") or line.startswith("new file mode") or line.startswith("deleted file mode") or line.startswith("similarity index") or line.startswith("rename ") or line.startswith("Binary files"):
            i += 1
            continue
        match = HUNK_HEADER_RE.match(line)
        if match:
            new_line_no = int(match.group(1))
            in_hunk = True
            i += 1
            continue
        if in_hunk and current_file:
            if line.startswith("+") and not line.startswith("+++"):
                current_added.append((new_line_no, line[1:]))
                new_line_no += 1
            elif line.startswith("-") and not line.startswith("---"):
                pass
            elif line.startswith(" ") or line == "":
                new_line_no += 1
            elif line.startswith("\\"):
                pass
            else:
                in_hunk = False
        i += 1
    flush()
    return changes


def iter_history_changes(
    project_path: str | Path,
    *,
    max_commits: int | None = 1000,
    since: str | None = None,
) -> Iterator[HistoryChange]:
    """Yield HistoryChange records for the project's git history."""
    output = _run_git_log(Path(project_path), max_commits, since)
    yield from parse_git_log(output)


def remap_line_number(line_map: list[int], synthetic_line: object) -> int | None:
    """Translate a parser-reported synthetic line back to the source line."""
    if not isinstance(synthetic_line, int):
        return None
    if synthetic_line < 1 or synthetic_line > len(line_map):
        return None
    return line_map[synthetic_line - 1]


def commit_signal_fields(commit: CommitInfo) -> dict[str, str]:
    """Return the commit-info fields signals carry through normalization."""
    return {
        "commit_sha": commit.sha,
        "commit_short_sha": commit.short_sha,
        "commit_author": commit.author_email or commit.author_name,
        "commit_date": commit.date,
    }


def history_evidence_line(commit: CommitInfo) -> str:
    return (
        f"git history: introduced in {commit.short_sha} by "
        f"{commit.author_email or commit.author_name or 'unknown'} on {commit.date}"
    )


def count_unique_commits(changes: Iterable[HistoryChange]) -> int:
    return len({change.commit.sha for change in changes})
