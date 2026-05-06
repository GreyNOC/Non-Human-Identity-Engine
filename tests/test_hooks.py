"""Tests for the pre-commit hook installer."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from greynoc_nhi.hooks import (
    CHAINED_HOOK_NAME,
    GREYNOC_HOOK_MARKER,
    install_pre_commit_hook,
    uninstall_pre_commit_hook,
)


def _git_available() -> bool:
    return shutil.which("git") is not None


pytestmark = pytest.mark.skipif(not _git_available(), reason="git binary not available")


def _init_repo(path: Path) -> None:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Tester",
            "GIT_AUTHOR_EMAIL": "tester@example.com",
            "GIT_COMMITTER_NAME": "Tester",
            "GIT_COMMITTER_EMAIL": "tester@example.com",
        }
    )
    subprocess.run(["git", "-C", str(path), "init", "-q", "-b", "main"], check=True, env=env)


def test_install_creates_hook(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    result = install_pre_commit_hook(tmp_path)
    assert result.hook_path.exists()
    contents = result.hook_path.read_text(encoding="utf-8")
    assert GREYNOC_HOOK_MARKER in contents
    assert "--diff-staged" in contents
    assert "--fail-on-new high" in contents


def test_install_chains_existing_hook(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    existing = hooks_dir / "pre-commit"
    existing.write_text("#!/bin/sh\necho legacy\n", encoding="utf-8")
    result = install_pre_commit_hook(tmp_path)
    assert result.chained_existing is True
    chained = hooks_dir / CHAINED_HOOK_NAME
    assert chained.exists()
    assert "echo legacy" in chained.read_text(encoding="utf-8")


def test_install_does_not_chain_its_own_hook(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    install_pre_commit_hook(tmp_path)
    second = install_pre_commit_hook(tmp_path)
    assert second.overwrote is True
    chained = tmp_path / ".git" / "hooks" / CHAINED_HOOK_NAME
    assert not chained.exists()


def test_install_framework_yaml(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    result = install_pre_commit_hook(tmp_path, framework=True)
    assert result.framework_path is not None
    assert result.framework_path.exists()
    assert "greynoc-nhi" in result.framework_path.read_text(encoding="utf-8")


def test_uninstall_restores_chained_hook(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    hooks_dir = tmp_path / ".git" / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    existing = hooks_dir / "pre-commit"
    existing.write_text("#!/bin/sh\necho legacy\n", encoding="utf-8")
    install_pre_commit_hook(tmp_path)
    assert uninstall_pre_commit_hook(tmp_path) is True
    restored = hooks_dir / "pre-commit"
    assert "echo legacy" in restored.read_text(encoding="utf-8")


def test_uninstall_when_not_installed_returns_false(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    assert uninstall_pre_commit_hook(tmp_path) is False


def test_install_rejects_non_git_directory(tmp_path: Path) -> None:
    with pytest.raises(RuntimeError):
        install_pre_commit_hook(tmp_path)
