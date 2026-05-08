"""Tests for the incremental parser output cache."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.cache import (
    ParserCache,
    content_hash,
    parser_version_string,
    rewrite_file_path,
)
from greynoc_nhi.engine import Engine
from greynoc_nhi.parsers import PARSERS
from greynoc_nhi.scanner import Scanner


def test_content_hash_is_stable() -> None:
    h1 = content_hash("hello")
    h2 = content_hash("hello")
    h3 = content_hash("hello!")
    assert h1 == h2
    assert h1 != h3


def test_parser_version_string_includes_each_parser() -> None:
    version = parser_version_string(PARSERS)
    for parser in PARSERS:
        assert parser.__name__ in version


def test_cache_round_trip(tmp_path: Path) -> None:
    cache = ParserCache(tmp_path / "cache.sqlite3")
    sha = content_hash("hello world")
    version = "v=1"
    assert cache.get(sha, version) is None
    signals = [{"rule_id": "x", "file_path": "a.txt", "line_number": 1, "evidence": ["e"]}]
    cache.put(sha, version, signals)
    fetched = cache.get(sha, version)
    assert fetched == signals


def test_cache_invalidates_on_parser_version_change(tmp_path: Path) -> None:
    cache = ParserCache(tmp_path / "cache.sqlite3")
    sha = content_hash("payload")
    cache.put(sha, "v1", [{"rule_id": "x"}])
    assert cache.get(sha, "v2") is None


def test_disabled_cache_is_noop(tmp_path: Path) -> None:
    cache = ParserCache(None)
    assert cache.enabled() is False
    cache.put("sha", "v", [{"a": 1}])
    assert cache.get("sha", "v") is None


def test_rewrite_file_path_does_not_mutate_original() -> None:
    original = [{"rule_id": "x", "file_path": "old.txt", "evidence": ["a"]}]
    rewritten = rewrite_file_path(original, "new.txt")
    assert original[0]["file_path"] == "old.txt"
    assert rewritten[0]["file_path"] == "new.txt"


def test_scanner_reports_cache_hits(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_CACHE_998811\n", encoding="utf-8")

    cache_path = tmp_path / "cache.sqlite3"
    scanner = Scanner(cache=ParserCache(cache_path))
    first = scanner.scan(project)
    assert first["cache_hits"] == 0
    assert first["cache_misses"] >= 1
    assert any(s["rule_id"] == "nhi_ai_provider_key_detected" for s in first["signals"])

    second = scanner.scan(project)
    assert second["cache_hits"] >= 1
    assert second["cache_misses"] == 0
    assert any(s["rule_id"] == "nhi_ai_provider_key_detected" for s in second["signals"])
    paths = {s.get("file_path") for s in second["signals"]}
    assert any(p and p.endswith(".env") for p in paths)


def test_engine_disables_cache_when_requested(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_CACHEOFF_2233\n", encoding="utf-8")

    engine = Engine(db_path=tmp_path / "main.sqlite3", cache_enabled=False)
    assert engine.cache is None
    result = engine.run_scan(project, persist=False)
    assert result.stats.get("cache_hits", 0) == 0
