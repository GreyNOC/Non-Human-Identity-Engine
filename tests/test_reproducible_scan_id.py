"""Tests for reproducible scan IDs."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from greynoc_nhi.engine import Engine, compute_scan_id


def _git_available() -> bool:
    return shutil.which("git") is not None


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
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Tester"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "tester@example.com"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "commit.gpgsign", "false"], check=True, env=env)


def _commit(path: Path, message: str) -> None:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Tester",
            "GIT_AUTHOR_EMAIL": "tester@example.com",
            "GIT_COMMITTER_NAME": "Tester",
            "GIT_COMMITTER_EMAIL": "tester@example.com",
        }
    )
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", message], check=True, env=env)


def test_scan_id_falls_back_to_timestamp_outside_git(tmp_path: Path) -> None:
    same_a = compute_scan_id(str(tmp_path), "2025-01-01T00:00:00", 1, 1)
    same_b = compute_scan_id(str(tmp_path), "2025-01-01T00:00:00", 1, 1)
    diff = compute_scan_id(str(tmp_path), "2025-02-02T00:00:00", 1, 1)
    assert same_a == same_b
    assert same_a != diff


@pytest.mark.skipif(not _git_available(), reason="git binary not available")
def test_clean_repo_scan_id_is_reproducible_across_runs(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "config.txt").write_text("hello\n", encoding="utf-8")
    _commit(tmp_path, "init")
    a = compute_scan_id(str(tmp_path), "2025-01-01T00:00:00", 1, 1)
    b = compute_scan_id(str(tmp_path), "2099-12-31T00:00:00", 99, 99)
    assert a == b


@pytest.mark.skipif(not _git_available(), reason="git binary not available")
def test_dirty_repo_scan_id_changes_when_changes_change(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "x.txt").write_text("a\n", encoding="utf-8")
    _commit(tmp_path, "init")
    (tmp_path / "x.txt").write_text("b\n", encoding="utf-8")
    a = compute_scan_id(str(tmp_path), "2025-01-01T00:00:00", 1, 1)
    (tmp_path / "x.txt").write_text("c\n", encoding="utf-8")
    b = compute_scan_id(str(tmp_path), "2025-01-01T00:00:00", 1, 1)
    assert a != b


@pytest.mark.skipif(not _git_available(), reason="git binary not available")
def test_engine_persists_same_scan_id_across_clean_runs(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / ".env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_REPRO_998877\n", encoding="utf-8")
    _commit(tmp_path, "init")

    engine = Engine(db_path=tmp_path / "db.sqlite3", cache_enabled=False)
    a = engine.run_scan(tmp_path, persist=False, enrich_owners=False)
    b = engine.run_scan(tmp_path, persist=False, enrich_owners=False)
    assert a.scan_id == b.scan_id
