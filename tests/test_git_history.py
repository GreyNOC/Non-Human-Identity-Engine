"""Tests for git history scanning."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from greynoc_nhi.engine import Engine
from greynoc_nhi.git_history import (
    COMMIT_DELIMITER,
    CommitInfo,
    is_git_repository,
    iter_history_changes,
    parse_git_log,
)
from greynoc_nhi.scanner import Scanner


def _git_available() -> bool:
    return shutil.which("git") is not None


pytestmark = pytest.mark.skipif(not _git_available(), reason="git binary not available")


def _init_repo(path: Path) -> None:
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "Alice Test"
    env["GIT_AUTHOR_EMAIL"] = "alice@example.com"
    env["GIT_COMMITTER_NAME"] = "Alice Test"
    env["GIT_COMMITTER_EMAIL"] = "alice@example.com"
    subprocess.run(["git", "-C", str(path), "init", "-q", "-b", "main"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "commit.gpgsign", "false"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Alice Test"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "alice@example.com"], check=True, env=env)


def _commit(path: Path, message: str) -> None:
    env = os.environ.copy()
    env["GIT_AUTHOR_NAME"] = "Alice Test"
    env["GIT_AUTHOR_EMAIL"] = "alice@example.com"
    env["GIT_COMMITTER_NAME"] = "Alice Test"
    env["GIT_COMMITTER_EMAIL"] = "alice@example.com"
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", message], check=True, env=env)


def test_is_git_repository_detects_repo(tmp_path: Path) -> None:
    assert is_git_repository(tmp_path) is False
    _init_repo(tmp_path)
    assert is_git_repository(tmp_path) is True


def test_history_scan_finds_secret_introduced_then_removed(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text(
        "OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_HISTORY_99999\n",
        encoding="utf-8",
    )
    _commit(tmp_path, "Add config")
    env_file.write_text("OPENAI_API_KEY=replace-me\n", encoding="utf-8")
    _commit(tmp_path, "Scrub secret")

    raw = Scanner().scan_history(tmp_path)
    history_signals = [
        sig for sig in raw["signals"]
        if sig.get("rule_id") == "nhi_ai_provider_key_detected"
    ]
    assert history_signals, "expected to find the secret in history"
    sig = history_signals[0]
    assert sig.get("commit_short_sha")
    assert sig.get("commit_author") == "alice@example.com"
    assert "git_history" in sig.get("tags", [])
    assert any("git history: introduced in" in line for line in sig.get("evidence", []))
    assert raw["commits_scanned"] >= 1


def test_engine_run_scan_history_only_skips_working_tree(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_OLD_111122\n", encoding="utf-8")
    _commit(tmp_path, "Add config")
    env_file.write_text("OPENAI_API_KEY=replace-me\n", encoding="utf-8")
    _commit(tmp_path, "Replace with placeholder")

    engine = Engine(db_path=tmp_path / "db.sqlite3")
    result = engine.run_scan(tmp_path, persist=False, scan_history=True, history_only=True)
    history_identities = [i for i in result.identities if "git_history" in i.tags]
    assert history_identities, "expected at least one history-sourced identity"
    assert history_identities[0].commit_sha
    assert result.stats.get("history", {}).get("enabled") is True
    assert result.stats.get("scanned_files") == 0


def test_run_scan_without_history_flag_does_not_call_git(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    env_file = tmp_path / ".env"
    env_file.write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_TREE_222233\n", encoding="utf-8")
    _commit(tmp_path, "Add config")

    engine = Engine(db_path=tmp_path / "db.sqlite3")
    result = engine.run_scan(tmp_path, persist=False)
    assert result.stats.get("history", {}).get("enabled") is False


def test_parse_git_log_handles_minimal_input() -> None:
    sample = (
        f"\n{COMMIT_DELIMITER}\n"
        "abcdefabcdefabcdefabcdefabcdefabcdefabcd\tabcdefa\tBob\tbob@example.com\t2024-03-12T10:00:00+00:00\tAdd creds\n"
        "diff --git a/.env b/.env\n"
        "new file mode 100644\n"
        "index 0000000..1234567\n"
        "--- /dev/null\n"
        "+++ b/.env\n"
        "@@ -0,0 +1,2 @@\n"
        "+OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_PARSE_333344\n"
        "+OTHER=value\n"
    )
    changes = parse_git_log(sample)
    assert len(changes) == 1
    change = changes[0]
    assert change.file_path == ".env"
    assert change.commit.short_sha == "abcdefa"
    assert change.commit.author_email == "bob@example.com"
    assert "OPENAI_API_KEY" in change.synthetic_text
    assert change.line_map == [1, 2]


def test_iter_history_changes_works_end_to_end(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / "config.txt").write_text("hello\n", encoding="utf-8")
    _commit(tmp_path, "init")
    changes = list(iter_history_changes(tmp_path, max_commits=10))
    assert any(change.file_path == "config.txt" for change in changes)


def test_commit_info_display_returns_string() -> None:
    info = CommitInfo(
        sha="abc",
        short_sha="abc1234",
        author_name="Alice",
        author_email="alice@example.com",
        date="2024-01-01T00:00:00+00:00",
        subject="initial",
    )
    assert "abc1234" in info.display()
    assert "alice@example.com" in info.display()
