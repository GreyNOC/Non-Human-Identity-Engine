"""Tests for diff/PR-only scan mode."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from greynoc_nhi.engine import Engine
from greynoc_nhi.git_diff import list_diff_files, ref_exists


def _git_available() -> bool:
    return shutil.which("git") is not None


pytestmark = pytest.mark.skipif(not _git_available(), reason="git binary not available")


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Tester",
            "GIT_AUTHOR_EMAIL": "tester@example.com",
            "GIT_COMMITTER_NAME": "Tester",
            "GIT_COMMITTER_EMAIL": "tester@example.com",
        }
    )
    return env


def _init_repo(path: Path) -> None:
    env = _git_env()
    subprocess.run(["git", "-C", str(path), "init", "-q", "-b", "main"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "commit.gpgsign", "false"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Tester"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "tester@example.com"], check=True, env=env)


def _commit(path: Path, message: str) -> None:
    env = _git_env()
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", message], check=True, env=env)


def test_ref_exists_for_head_and_unknown(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "a.txt").write_text("hi\n", encoding="utf-8")
    _commit(tmp_path, "init")
    assert ref_exists(tmp_path, "HEAD") is True
    assert ref_exists(tmp_path, "nonexistent-branch") is False


def test_list_diff_files_staged_returns_only_staged(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "untracked.txt").write_text("bye\n", encoding="utf-8")
    (tmp_path / "kept.txt").write_text("kept\n", encoding="utf-8")
    _commit(tmp_path, "init")
    (tmp_path / "kept.txt").write_text("kept v2\n", encoding="utf-8")
    (tmp_path / "new.env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_DIFF_445566\n", encoding="utf-8")
    env = _git_env()
    subprocess.run(["git", "-C", str(tmp_path), "add", "new.env"], check=True, env=env)
    files = list_diff_files(tmp_path, staged=True)
    names = {p.name for p in files}
    assert names == {"new.env"}


def test_list_diff_files_against_base_returns_changed_set(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "stable.txt").write_text("stable\n", encoding="utf-8")
    _commit(tmp_path, "init")
    env = _git_env()
    subprocess.run(["git", "-C", str(tmp_path), "checkout", "-q", "-b", "feature"], check=True, env=env)
    (tmp_path / "added.env").write_text("AWS_SECRET_ACCESS_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_FEATURE_667788\n", encoding="utf-8")
    _commit(tmp_path, "feature change")
    files = list_diff_files(tmp_path, base="main", staged=False)
    names = {p.name for p in files}
    assert names == {"added.env"}


def test_engine_diff_staged_only_scans_staged_files(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "old.env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_OLD_998877\n", encoding="utf-8")
    _commit(tmp_path, "init")
    env = _git_env()
    (tmp_path / "new.env").write_text("STRIPE_SECRET_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_NEW_223344\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "new.env"], check=True, env=env)

    engine = Engine(db_path=tmp_path / "db.sqlite3")
    result = engine.run_scan(tmp_path, persist=False, diff_staged=True)
    files_with_findings = {Path(f.file_path).name for f in result.findings if f.file_path}
    assert "new.env" in files_with_findings
    assert "old.env" not in files_with_findings
    assert result.stats["diff"]["enabled"] is True
    assert result.stats["diff"]["staged"] is True
    assert result.stats["diff"]["files"] >= 1


def test_engine_diff_with_unknown_base_records_fatal_error(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "x.txt").write_text("ok\n", encoding="utf-8")
    _commit(tmp_path, "init")

    engine = Engine(db_path=tmp_path / "db.sqlite3")
    result = engine.run_scan(tmp_path, persist=False, diff_mode=True, diff_base="origin/does-not-exist")
    assert result.scan_trust_level == "untrusted"
    assert any("base ref" in err for err in result.fatal_errors)
