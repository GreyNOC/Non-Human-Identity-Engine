"""Opt-in auto-fix actions.

Each fix is its own function and gated behind a separate CLI flag so users
can adopt them selectively. Fixes are deterministic - no LLM, no heuristics
that could break working configuration.
"""

from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

GITIGNORE_HEADER = "# GreyNOC NHI: protect environment files from accidental commit"
ENV_PATTERNS = (".env", ".env.local", ".env.*", "*.env")


@dataclass
class FixResult:
    name: str
    changed: bool = False
    files: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def summary(self) -> str:
        if not self.changed:
            return f"{self.name}: nothing to change"
        return f"{self.name}: updated {len(self.files)} file(s)"


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return ""


def fix_gitignore(project_path: str | Path, *, dry_run: bool = False) -> FixResult:
    """Add .env-style ignores to the project's .gitignore."""
    root = Path(project_path).resolve()
    gitignore = root / ".gitignore"
    existing_text = _read(gitignore)
    existing_lines = {line.strip() for line in existing_text.splitlines() if line.strip()}
    additions = [pattern for pattern in ENV_PATTERNS if pattern not in existing_lines]
    if not additions:
        return FixResult(name="fix-gitignore", changed=False)
    new_text = existing_text
    if new_text and not new_text.endswith("\n"):
        new_text += "\n"
    new_text += f"\n{GITIGNORE_HEADER}\n"
    for pattern in additions:
        new_text += f"{pattern}\n"
    if dry_run:
        return FixResult(
            name="fix-gitignore",
            changed=False,
            files=[str(gitignore)],
            notes=[f"would add: {', '.join(additions)}"],
        )
    gitignore.write_text(new_text, encoding="utf-8")
    return FixResult(
        name="fix-gitignore",
        changed=True,
        files=[str(gitignore)],
        notes=[f"added: {', '.join(additions)}"],
    )


UNPINNED_ACTION_RE = re.compile(
    r"(uses\s*:\s*)([^@\s]+/[^@\s]+)@([^\s#]+)(.*)",
    re.IGNORECASE,
)


def _resolve_action_sha(repo: str, ref: str, *, timeout: int = 30) -> str | None:
    url = f"https://github.com/{repo}.git"
    try:
        result = subprocess.run(
            ["git", "ls-remote", url, ref, f"refs/tags/{ref}", f"refs/heads/{ref}"],
            capture_output=True,
            text=True,
            timeout=timeout,
            errors="replace",
        )
    except (FileNotFoundError, subprocess.SubprocessError, OSError):
        return None
    if result.returncode != 0:
        return None
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        sha = line.split()[0]
        if re.fullmatch(r"[a-f0-9]{40}", sha or ""):
            return sha
    return None


def fix_pin_actions(project_path: str | Path, *, dry_run: bool = False) -> FixResult:
    """Pin unpinned third-party `uses:` references to their current SHA."""
    root = Path(project_path).resolve()
    workflows_dir = root / ".github" / "workflows"
    if not workflows_dir.is_dir():
        return FixResult(name="fix-pin-actions", changed=False, notes=["no .github/workflows directory"])
    files_changed: list[str] = []
    notes: list[str] = []
    for path in sorted(workflows_dir.iterdir()):
        if not path.is_file() or path.suffix.lower() not in {".yml", ".yaml"}:
            continue
        text = _read(path)
        if not text:
            continue
        new_lines: list[str] = []
        modified = False
        for line in text.splitlines():
            match = UNPINNED_ACTION_RE.search(line)
            if not match:
                new_lines.append(line)
                continue
            prefix = line[: match.start(1)]
            uses_kw = match.group(1)
            repo = match.group(2)
            ref = match.group(3)
            tail = match.group(4) or ""
            if re.fullmatch(r"[a-f0-9]{40}", ref) or repo.startswith(("./", ".\\")) or repo.startswith("docker://"):
                new_lines.append(line)
                continue
            sha = _resolve_action_sha(repo, ref)
            if sha is None:
                notes.append(f"{path.name}: could not resolve {repo}@{ref}")
                new_lines.append(line)
                continue
            comment = f"  # was {ref}"
            new_line = f"{prefix}{uses_kw}{repo}@{sha}{tail}{comment}"
            new_lines.append(new_line)
            modified = True
            notes.append(f"{path.name}: {repo}@{ref} -> {sha[:7]}")
        if modified:
            new_text = "\n".join(new_lines)
            if text.endswith("\n"):
                new_text += "\n"
            files_changed.append(str(path))
            if not dry_run:
                path.write_text(new_text, encoding="utf-8")
    return FixResult(
        name="fix-pin-actions",
        changed=bool(files_changed) and not dry_run,
        files=files_changed,
        notes=notes,
    )
