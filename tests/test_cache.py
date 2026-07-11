"""Tests for the incremental parser output cache."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

import greynoc_nhi.cache as cache_module
from greynoc_nhi.cache import (
    ParserCache,
    content_hash,
    parser_version_string,
    rewrite_file_path,
    sanitize_signal_for_disk,
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


def test_cache_sanitizes_secret_value_before_disk_write(tmp_path: Path) -> None:
    raw_secret = "GNOC_FAKE_SECRET_DO_NOT_USE_CACHE_RAW_112233"
    cache_path = tmp_path / "cache.sqlite3"
    cache = ParserCache(cache_path)
    cache.put(
        content_hash("secret file"),
        "v=1",
        [{"rule_id": "x", "file_path": ".env", "secret_value": raw_secret, "evidence": [f"TOKEN={raw_secret}"]}],
    )

    fetched = cache.get(content_hash("secret file"), "v=1")
    assert fetched is not None
    assert "secret_value" not in fetched[0]
    assert raw_secret.encode() not in cache_path.read_bytes()
    assert "secret_value" not in sanitize_signal_for_disk({"secret_value": raw_secret, "rule_id": "x"})


def test_scanner_reports_cache_hits(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "agents.json").write_text('{"approval_required": false, "tools": ["filesystem"]}\n', encoding="utf-8")

    cache_path = tmp_path / "cache.sqlite3"
    scanner = Scanner(cache=ParserCache(cache_path))
    first = scanner.scan(project)
    assert first["cache_hits"] == 0
    assert first["cache_misses"] >= 1
    assert any(s["rule_id"] == "nhi_ai_agent_filesystem_access" for s in first["signals"])

    second = scanner.scan(project)
    assert second["cache_hits"] >= 1
    assert second["cache_misses"] == 0
    assert any(s["rule_id"] == "nhi_ai_agent_filesystem_access" for s in second["signals"])
    paths = {s.get("file_path") for s in second["signals"]}
    assert any(p and p.endswith("agents.json") for p in paths)


def test_scanner_does_not_cache_secret_bearing_parser_signals(tmp_path: Path) -> None:
    raw_secret = "GNOC_FAKE_SECRET_DO_NOT_USE_CACHE_SKIP_998811"
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".env").write_text(f"OPENAI_API_KEY={raw_secret}\n", encoding="utf-8")

    cache_path = tmp_path / "cache.sqlite3"
    scanner = Scanner(cache=ParserCache(cache_path))
    first = scanner.scan(project)
    second = scanner.scan(project)

    assert first["cache_misses"] >= 1
    assert second["cache_hits"] == 0
    assert second["cache_misses"] >= 1
    assert raw_secret.encode() not in cache_path.read_bytes()


def test_cache_key_separates_parser_dispatch(tmp_path: Path) -> None:
    """Identical content under differently-gated filenames must not collide."""
    cache = ParserCache(tmp_path / "cache.sqlite3")
    sha = content_hash("same bytes")
    cache.put(sha, "v=1", [{"rule_id": "generic"}], dispatch="generic_config")
    assert cache.get(sha, "v=1", dispatch="generic_config,helm") is None
    cache.put(sha, "v=1", [{"rule_id": "helm"}], dispatch="generic_config,helm")
    assert cache.get(sha, "v=1", dispatch="generic_config") == [{"rule_id": "generic"}]
    assert cache.get(sha, "v=1", dispatch="generic_config,helm") == [{"rule_id": "helm"}]


def test_scanner_cache_does_not_reuse_hits_across_parser_dispatch(tmp_path: Path) -> None:
    """values.yaml (helm-gated) must not hit a cache row written for config.yaml."""
    content = "replicas: 3\nimage: registry.example.com/app\n"
    project = tmp_path / "proj"
    project.mkdir()
    (project / "config.yaml").write_text(content, encoding="utf-8")
    (project / "values.yaml").write_text(content, encoding="utf-8")

    scanner = Scanner(cache=ParserCache(tmp_path / "cache.sqlite3"))
    first = scanner.scan(project)
    # config.yaml sorts before values.yaml and is cached first; a
    # content-only key would let values.yaml (helm-gated) hit that row
    # and silently drop helm-only findings on warm scans.
    assert first["cache_hits"] == 0
    assert first["cache_misses"] == 2
    second = scanner.scan(project)
    assert second["cache_hits"] == 2
    assert second["cache_misses"] == 0


def test_cache_reuses_persistent_connection_and_close(tmp_path: Path) -> None:
    cache = ParserCache(tmp_path / "cache.sqlite3")
    sha = content_hash("payload")
    cache.put(sha, "v=1", [{"rule_id": "x"}])
    conn_after_put = cache._conn
    assert conn_after_put is not None
    assert cache.get(sha, "v=1") == [{"rule_id": "x"}]
    assert cache._conn is conn_after_put
    assert cache.stats() == {"entries": 1}
    assert cache._conn is conn_after_put
    cache.close()
    assert cache._conn is None
    # Operations after close() lazily reopen.
    assert cache.get(sha, "v=1") == [{"rule_id": "x"}]
    cache.close()


def test_cache_hit_skips_resanitization_for_clean_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cache = ParserCache(tmp_path / "cache.sqlite3")
    sha = content_hash("clean file")
    cache.put(sha, "v=1", [{"rule_id": "x", "evidence": ["TOKEN=[REDACTED:token len=12]"]}])

    calls = {"count": 0}
    real_sanitize = cache_module.sanitize_signals_for_disk

    def counting_sanitize(signals):
        calls["count"] += 1
        return real_sanitize(signals)

    monkeypatch.setattr(cache_module, "sanitize_signals_for_disk", counting_sanitize)
    fetched = cache.get(sha, "v=1")
    assert fetched == [{"rule_id": "x", "evidence": ["TOKEN=[REDACTED:token len=12]"]}]
    assert calls["count"] == 0


def test_cache_hit_heals_legacy_row_with_secret_value_key(tmp_path: Path) -> None:
    """A tampered/legacy row still carrying secret_value is re-sanitized on read."""
    cache = ParserCache(tmp_path / "cache.sqlite3")
    sha = content_hash("legacy file")
    key = cache_module._make_key(sha, "v=1")
    legacy = [{"rule_id": "x", "secret_value": "GNOC_LEGACY_VALUE_112233", "evidence": ["e"]}]
    with cache._connect() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO parser_cache (cache_key, parser_version, signals_json, cached_at) VALUES (?, ?, ?, ?)",
            (key, "v=1", json.dumps(legacy), "2024-01-01T00:00:00+00:00"),
        )
    fetched = cache.get(sha, "v=1")
    assert fetched is not None
    assert "secret_value" not in fetched[0]


def test_scanner_without_cache_reports_zero_misses(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_NOCACHE_5566\n", encoding="utf-8")
    result = Scanner(cache=None).scan(project)
    assert result["scanned_files"] == 1
    assert result["cache_hits"] == 0
    assert result["cache_misses"] == 0


def test_engine_disables_cache_when_requested(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / ".env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_CACHEOFF_2233\n", encoding="utf-8")

    engine = Engine(db_path=tmp_path / "main.sqlite3", cache_enabled=False)
    assert engine.cache is None
    result = engine.run_scan(project, persist=False)
    assert result.stats.get("cache_hits", 0) == 0
