"""Git diff helpers for narrowing the scan to changed files only.

Used by `--diff` (PR / branch mode) and `--diff-staged` (pre-commit hook mode).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

GIT_DIFF_TIMEOUT_SECONDS = 60


def _run_git(args: list[str], project_path: Path) -> subprocess.CompletedProcess[str]:
    cmd = ["git", "-C", str(project_path), *args]
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=GIT_DIFF_TIMEOUT_SECONDS,
        errors="replace",
    )


def ref_exists(project_path: str | Path, ref: str) -> bool:
    """Return True if `ref` is resolvable in the repo."""
    try:
        result = _run_git(["rev-parse", "--verify", "--quiet", f"{ref}^{{commit}}"], Path(project_path))
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return False
    return result.returncode == 0


def list_diff_files(
    project_path: str | Path,
    *,
    base: str = "origin/main",
    staged: bool = False,
) -> list[Path]:
    """Return absolute paths for files changed by the diff.

    When `staged` is True we return staged-but-not-committed files using
    `git diff --cached --name-only --diff-filter=ACM`. Otherwise we compare
    `base...HEAD` (merge-base diff) which is the natural "what's in this PR"
    set when `base` is `origin/main`.

    Files that have been deleted are excluded. Paths that no longer exist on
    disk are dropped (e.g. renamed-then-deleted between two staged states).
    """
    root = Path(project_path).resolve()
    if staged:
        args = ["diff", "--cached", "--name-only", "--diff-filter=ACMR"]
    else:
        if not ref_exists(root, base):
            raise RuntimeError(
                f"base ref '{base}' could not be resolved; pass --base <ref> or fetch it first"
            )
        args = ["diff", "--name-only", "--diff-filter=ACMR", f"{base}...HEAD"]
    try:
        result = _run_git(args, root)
    except (FileNotFoundError, subprocess.SubprocessError) as exc:
        raise RuntimeError(f"git diff failed: {exc}") from exc
    if result.returncode != 0:
        raise RuntimeError(f"git diff returned {result.returncode}: {result.stderr.strip()[:200]}")
    files: list[Path] = []
    seen: set[Path] = set()
    for line in result.stdout.splitlines():
        rel = line.strip()
        if not rel:
            continue
        full = (root / rel)
        try:
            resolved = full.resolve()
        except OSError:
            continue
        if not resolved.is_file():
            continue
        if resolved in seen:
            continue
        seen.add(resolved)
        files.append(resolved)
    return files
