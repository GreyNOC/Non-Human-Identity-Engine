"""Tests for opt-in auto-fix actions."""

from __future__ import annotations

from pathlib import Path
from unittest import mock

from greynoc_nhi import autofix


def test_fix_gitignore_creates_when_missing(tmp_path: Path) -> None:
    result = autofix.fix_gitignore(tmp_path)
    assert result.changed is True
    text = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert ".env" in text
    assert "GreyNOC NHI" in text


def test_fix_gitignore_appends_to_existing(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text("node_modules/\n", encoding="utf-8")
    result = autofix.fix_gitignore(tmp_path)
    assert result.changed is True
    text = (tmp_path / ".gitignore").read_text(encoding="utf-8")
    assert "node_modules/" in text
    assert ".env" in text


def test_fix_gitignore_idempotent(tmp_path: Path) -> None:
    autofix.fix_gitignore(tmp_path)
    second = autofix.fix_gitignore(tmp_path)
    assert second.changed is False


def test_fix_gitignore_dry_run_does_not_write(tmp_path: Path) -> None:
    result = autofix.fix_gitignore(tmp_path, dry_run=True)
    assert result.changed is False
    assert not (tmp_path / ".gitignore").exists()
    assert any("would add" in note for note in result.notes)


def test_fix_pin_actions_skips_when_no_workflows(tmp_path: Path) -> None:
    result = autofix.fix_pin_actions(tmp_path)
    assert result.changed is False
    assert any("no .github/workflows" in note for note in result.notes)


def test_fix_pin_actions_pins_unpinned(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / "ci.yml"
    workflow.write_text(
        "name: ci\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
        "      - uses: pinned/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
        encoding="utf-8",
    )
    fake_sha = "1234567890abcdef1234567890abcdef12345678"

    def fake_resolve(repo: str, ref: str, *, timeout: int = 30) -> str | None:
        return fake_sha if repo == "actions/checkout" and ref == "v4" else None

    with mock.patch.object(autofix, "_resolve_action_sha", side_effect=fake_resolve):
        result = autofix.fix_pin_actions(tmp_path)
    assert result.changed is True
    text = workflow.read_text(encoding="utf-8")
    assert fake_sha in text
    assert "# was v4" in text
    assert "pinned/action@aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" in text


def test_fix_pin_actions_dry_run(tmp_path: Path) -> None:
    workflow_dir = tmp_path / ".github" / "workflows"
    workflow_dir.mkdir(parents=True)
    workflow = workflow_dir / "ci.yml"
    workflow.write_text("steps:\n  - uses: actions/checkout@v4\n", encoding="utf-8")
    with mock.patch.object(autofix, "_resolve_action_sha", return_value="a" * 40):
        result = autofix.fix_pin_actions(tmp_path, dry_run=True)
    assert result.changed is False
    text = workflow.read_text(encoding="utf-8")
    assert "actions/checkout@v4" in text
    assert "a" * 40 not in text
