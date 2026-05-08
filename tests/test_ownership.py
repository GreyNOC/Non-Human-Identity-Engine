"""Tests for ownership enrichment via git blame + CODEOWNERS."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from greynoc_nhi.engine import Engine
from greynoc_nhi.ownership import (
    CodeownersRule,
    codeowners_for_path,
    describe_owner,
    enrich_identity_owners,
    git_blame_owner,
    parse_codeowners_text,
)


def _git_available() -> bool:
    return shutil.which("git") is not None


pytestmark = pytest.mark.skipif(not _git_available(), reason="git binary not available")


def _git_env() -> dict[str, str]:
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Alice Test",
            "GIT_AUTHOR_EMAIL": "alice@example.com",
            "GIT_COMMITTER_NAME": "Alice Test",
            "GIT_COMMITTER_EMAIL": "alice@example.com",
        }
    )
    return env


def _init_repo(path: Path) -> None:
    env = _git_env()
    subprocess.run(["git", "-C", str(path), "init", "-q", "-b", "main"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "commit.gpgsign", "false"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "user.name", "Alice Test"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "config", "user.email", "alice@example.com"], check=True, env=env)


def _commit(path: Path, message: str) -> None:
    env = _git_env()
    subprocess.run(["git", "-C", str(path), "add", "-A"], check=True, env=env)
    subprocess.run(["git", "-C", str(path), "commit", "-q", "-m", message], check=True, env=env)


def test_parse_codeowners_skips_comments_and_blanks() -> None:
    text = """
# default owners
*       @platform-team
# nothing here
docs/   @docs-team
src/api/*.py    api-team@example.com  # inline comment
"""
    rules = parse_codeowners_text(text)
    assert len(rules) == 3
    assert rules[0].pattern == "*"
    assert rules[0].owners == ["@platform-team"]
    assert rules[2].owners == ["api-team@example.com"]


def test_codeowners_match_uses_last_match_wins() -> None:
    rules = [
        CodeownersRule(pattern="*", owners=["@default"]),
        CodeownersRule(pattern="src/api/*.py", owners=["@api-team"]),
    ]
    assert codeowners_for_path(rules, "README.md") == ["@default"]
    assert codeowners_for_path(rules, "src/api/server.py") == ["@api-team"]


def test_codeowners_directory_match() -> None:
    rules = [CodeownersRule(pattern="docs/", owners=["@docs"])]
    assert codeowners_for_path(rules, "docs/index.md") == ["@docs"]
    assert codeowners_for_path(rules, "src/foo.py") == []


def test_describe_owner_combines_blame_and_codeowners() -> None:
    from greynoc_nhi.ownership import BlameOwner

    blame = BlameOwner(email="alice@example.com", name="Alice", timestamp=1700000000)
    text = describe_owner(blame, ["@platform"])
    assert text is not None
    assert "alice@example.com" in text
    assert "via CODEOWNERS" in text


def test_git_blame_owner_finds_author(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    target = tmp_path / "config.txt"
    target.write_text("first line\nsecond line\n", encoding="utf-8")
    _commit(tmp_path, "init")

    blame = git_blame_owner(tmp_path, "config.txt", 1)
    assert blame is not None
    assert blame.email == "alice@example.com"


def test_engine_populates_owner_field(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / ".github").mkdir()
    (tmp_path / ".github" / "CODEOWNERS").write_text("*.env @secrets-team\n", encoding="utf-8")
    (tmp_path / ".env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_OWNER_555566\n", encoding="utf-8")
    _commit(tmp_path, "init")

    engine = Engine(db_path=tmp_path / "db.sqlite3", cache_enabled=False)
    result = engine.run_scan(tmp_path, persist=False)
    owners = [identity.owner for identity in result.identities if identity.owner]
    assert owners, "expected at least one identity to gain an owner"
    assert any("alice@example.com" in (o or "") for o in owners)
    assert any("@secrets-team" in (o or "") for o in owners)


def test_enrich_skips_history_signals(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / ".env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_HISTORY_SKIP_777788\n", encoding="utf-8")
    _commit(tmp_path, "init")
    engine = Engine(db_path=tmp_path / "db.sqlite3", cache_enabled=False)
    result = engine.run_scan(tmp_path, persist=False, scan_history=True)
    history_identities = [i for i in result.identities if i.commit_sha]
    assert history_identities
    for identity in history_identities:
        assert identity.owner is None or "via CODEOWNERS" not in (identity.owner or "")


def test_no_owner_enrich_flag_skips_lookup(tmp_path: Path) -> None:
    _init_repo(tmp_path)
    (tmp_path / ".env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_NOENRICH_888899\n", encoding="utf-8")
    _commit(tmp_path, "init")

    engine = Engine(db_path=tmp_path / "db.sqlite3", cache_enabled=False)
    result = engine.run_scan(tmp_path, persist=False, enrich_owners=False)
    assert all(identity.owner is None for identity in result.identities)
