"""Pre-commit hook installer for GreyNOC NHI.

Writes a `.git/hooks/pre-commit` shell script that runs the scanner over
staged changes and blocks commits with new high-severity findings.

If an existing pre-commit hook is already present, it is renamed to
`pre-commit.greynoc-chained` and called from the new hook so the prior
hook's behaviour is preserved.
"""

from __future__ import annotations

import os
import shutil
import stat
from dataclasses import dataclass
from pathlib import Path

GREYNOC_HOOK_MARKER = "# GREYNOC_NHI_PRE_COMMIT_HOOK"
CHAINED_HOOK_NAME = "pre-commit.greynoc-chained"

HOOK_SCRIPT = f"""#!/bin/sh
{GREYNOC_HOOK_MARKER}
# Installed by `python -m greynoc_nhi --install-hook`. Edit at your own risk.
set -e

# Skip if SKIP_GREYNOC=1 (for emergencies).
if [ "${{SKIP_GREYNOC:-0}}" != "0" ]; then
    exit 0
fi

# Run the scanner against staged changes only.
python -m greynoc_nhi --diff-staged --fail-on-new high
status=$?
if [ "$status" -ne 0 ]; then
    echo "" >&2
    echo "GreyNOC NHI blocked this commit due to new high-severity findings." >&2
    echo "Inspect with: python -m greynoc_nhi --diff-staged" >&2
    echo "Bypass once with: SKIP_GREYNOC=1 git commit" >&2
    exit "$status"
fi

# Chain to a previously installed pre-commit hook, if any.
chained="$(dirname "$0")/{CHAINED_HOOK_NAME}"
if [ -x "$chained" ]; then
    "$chained" "$@"
fi
"""

PRECOMMIT_FRAMEWORK_YAML = """- id: greynoc-nhi
  name: GreyNOC NHI scan (staged changes)
  description: Block commits that add new high-severity NHI findings.
  entry: python -m greynoc_nhi --diff-staged --fail-on-new high
  language: system
  pass_filenames: false
  always_run: true
"""


@dataclass
class HookInstallResult:
    hook_path: Path
    chained_existing: bool
    overwrote: bool
    framework_path: Path | None


def _git_hooks_dir(project_path: Path) -> Path:
    git_dir = project_path / ".git"
    if not git_dir.exists():
        raise RuntimeError(f"{project_path} is not a git repository (no .git directory)")
    if git_dir.is_file():
        text = git_dir.read_text(encoding="utf-8", errors="replace").strip()
        if text.startswith("gitdir:"):
            target = text.split(":", 1)[1].strip()
            git_dir = (project_path / target).resolve()
    hooks = git_dir / "hooks"
    hooks.mkdir(parents=True, exist_ok=True)
    return hooks


def _is_greynoc_hook(path: Path) -> bool:
    if not path.is_file():
        return False
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return GREYNOC_HOOK_MARKER in text


def install_pre_commit_hook(
    project_path: str | Path,
    *,
    framework: bool = False,
    force: bool = False,
) -> HookInstallResult:
    """Install the pre-commit hook into a git repository."""
    project = Path(project_path).resolve()
    hooks_dir = _git_hooks_dir(project)
    hook_path = hooks_dir / "pre-commit"
    chained_path = hooks_dir / CHAINED_HOOK_NAME
    chained_existing = False
    overwrote = False
    if hook_path.exists():
        if _is_greynoc_hook(hook_path):
            if not force:
                hook_path.write_text(HOOK_SCRIPT, encoding="utf-8")
                _make_executable(hook_path)
                return HookInstallResult(
                    hook_path=hook_path,
                    chained_existing=chained_path.exists(),
                    overwrote=True,
                    framework_path=_install_framework_yaml(project) if framework else None,
                )
            overwrote = True
        else:
            shutil.move(str(hook_path), str(chained_path))
            _make_executable(chained_path)
            chained_existing = True
    hook_path.write_text(HOOK_SCRIPT, encoding="utf-8")
    _make_executable(hook_path)
    framework_path = _install_framework_yaml(project) if framework else None
    return HookInstallResult(
        hook_path=hook_path,
        chained_existing=chained_existing,
        overwrote=overwrote,
        framework_path=framework_path,
    )


def uninstall_pre_commit_hook(project_path: str | Path) -> bool:
    """Remove the GreyNOC pre-commit hook and restore any chained hook."""
    project = Path(project_path).resolve()
    hooks_dir = _git_hooks_dir(project)
    hook_path = hooks_dir / "pre-commit"
    chained_path = hooks_dir / CHAINED_HOOK_NAME
    if not hook_path.exists() or not _is_greynoc_hook(hook_path):
        return False
    hook_path.unlink()
    if chained_path.exists():
        shutil.move(str(chained_path), str(hook_path))
        _make_executable(hook_path)
    return True


def _install_framework_yaml(project: Path) -> Path:
    target = project / ".pre-commit-hooks.yaml"
    target.write_text(PRECOMMIT_FRAMEWORK_YAML, encoding="utf-8")
    return target


def _make_executable(path: Path) -> None:
    if os.name == "nt":
        return
    try:
        mode = path.stat().st_mode
        path.chmod(mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    except OSError:
        pass
