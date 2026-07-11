from pathlib import Path
from tempfile import mkdtemp

import pytest

from greynoc_nhi.constants import MAX_FILE_BYTES
from greynoc_nhi.ignore import is_ignored, load_greynocignore
from greynoc_nhi.scanner import Scanner, dedupe_signals, iter_scan_files, should_scan_file
from greynoc_nhi.utils import (
    LineIndex,
    line_number_at_offset,
    line_number_for_key_value,
    parse_json_cached,
    read_text_safely,
    simple_kv_pairs,
)


def test_scanner_skips_ignored_dirs():
    project = Path(mkdtemp(prefix="greynoc_nhi_scanner_test_"))
    ignored = project / "node_modules"
    ignored.mkdir()
    (ignored / ".env").write_text("OPENAI_API_KEY=FAKE_OPENAI_KEY_DO_NOT_USE_123456", encoding="utf-8")
    result = Scanner().scan(project)
    assert result["scanned_files"] == 0
    assert result["signals"] == []


def test_scanner_skips_tooling_cache_dirs(tmp_path):
    for dirname in (".mypy_cache", ".pytest_cache", ".tox", "site-packages"):
        cached = tmp_path / dirname
        cached.mkdir()
        (cached / "leak.env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_CACHEDIR_1234\n", encoding="utf-8")
    assert iter_scan_files(tmp_path) == []


def test_iter_scan_files_does_not_follow_symlink_escape(tmp_path):
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    (outside / ".env").write_text("OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_ESCAPE_123456", encoding="utf-8")
    try:
        (project / "escape").symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation is not available on this filesystem")

    assert iter_scan_files(project) == []


def test_scanner_dedupes_identical_signals():
    signal = {"rule_id": "x", "file_path": "a", "line_number": 1, "name": "n", "evidence": ["masked"]}
    assert dedupe_signals([signal, dict(signal)]) == [signal]


def test_key_material_and_credential_files_are_scan_candidates(tmp_path):
    (tmp_path / "id_rsa").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\nGNOC\n-----END OPENSSH PRIVATE KEY-----\n", encoding="utf-8")
    (tmp_path / "server.pem").write_text("-----BEGIN CERTIFICATE-----\nGNOC\n-----END CERTIFICATE-----\n", encoding="utf-8")
    (tmp_path / "deploy.key").write_text("key material\n", encoding="utf-8")
    (tmp_path / "terraform.tfvars").write_text('db_password = "replace-me"\n', encoding="utf-8")
    (tmp_path / "kubeconfig").write_text("apiVersion: v1\n", encoding="utf-8")
    (tmp_path / "Jenkinsfile").write_text("pipeline { }\n", encoding="utf-8")
    (tmp_path / "Dockerfile.prod").write_text("FROM python:3.11\n", encoding="utf-8")
    (tmp_path / "rules.mdc").write_text("# cursor rules\n", encoding="utf-8")
    (tmp_path / ".clinerules").write_text("# cline rules\n", encoding="utf-8")
    aws_dir = tmp_path / ".aws"
    aws_dir.mkdir()
    (aws_dir / "credentials").write_text("[default]\naws_secret_access_key = replace-me\n", encoding="utf-8")
    kube_dir = tmp_path / ".kube"
    kube_dir.mkdir()
    (kube_dir / "config").write_text("apiVersion: v1\n", encoding="utf-8")

    names = {p.name for p in iter_scan_files(tmp_path)}
    assert {
        "id_rsa",
        "server.pem",
        "deploy.key",
        "terraform.tfvars",
        "kubeconfig",
        "Jenkinsfile",
        "Dockerfile.prod",
        "rules.mdc",
        ".clinerules",
        "credentials",
        "config",
    } <= names


def test_yarnrc_and_git_credentials_are_scan_candidates(tmp_path):
    yarnrc = tmp_path / ".yarnrc"
    yarnrc.write_text('registry "https://registry.example.com"\n', encoding="utf-8")
    git_creds = tmp_path / ".git-credentials"
    git_creds.write_text("https://user:replace-me@example.com\n", encoding="utf-8")
    assert should_scan_file(yarnrc)
    assert should_scan_file(git_creds)


def test_diff_mode_agrees_with_full_scan_on_gates(tmp_path):
    """scan(only_paths=[x]) and the full scan must agree on whether x is scanned."""
    (tmp_path / ".greynocignore").write_text("ignored.env\nsamples/*\n", encoding="utf-8")
    good = tmp_path / "good.env"
    good.write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_DIFFPARITY_1111\n", encoding="utf-8")
    node_modules = tmp_path / "node_modules"
    node_modules.mkdir()
    in_ignored_dir = node_modules / "dep.env"
    in_ignored_dir.write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_DIFFPARITY_2222\n", encoding="utf-8")
    ignored_pattern = tmp_path / "ignored.env"
    ignored_pattern.write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_DIFFPARITY_3333\n", encoding="utf-8")
    samples = tmp_path / "samples"
    samples.mkdir()
    under_pattern_dir = samples / "also.env"
    under_pattern_dir.write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_DIFFPARITY_4444\n", encoding="utf-8")
    oversized = tmp_path / "huge.env"
    oversized.write_text("PAD=" + "x" * (MAX_FILE_BYTES + 1), encoding="utf-8")

    scanner = Scanner()
    full = scanner.scan(tmp_path)
    full_paths = {s["file_path"] for s in full["signals"]}
    assert any(p.endswith("good.env") for p in full_paths)
    assert not any(p.endswith("dep.env") for p in full_paths)

    candidates = [good, in_ignored_dir, ignored_pattern, under_pattern_dir, oversized]
    diff = scanner.scan(tmp_path, only_paths=candidates)
    diff_paths = {s["file_path"] for s in diff["signals"]}
    assert any(p.endswith("good.env") for p in diff_paths)
    for excluded in ("dep.env", "ignored.env", "also.env", "huge.env"):
        assert not any(p.endswith(excluded) for p in diff_paths), excluded
    assert diff["scanned_files"] == 1

    missing = tmp_path / "does-not-exist.env"
    assert scanner.scan(tmp_path, only_paths=[missing])["scanned_files"] == 0
    assert scanner.scan(tmp_path, only_paths=[])["scanned_files"] == 0


def test_diff_mode_rejects_symlink_escape(tmp_path):
    project = tmp_path / "project"
    outside = tmp_path / "outside"
    project.mkdir()
    outside.mkdir()
    secret = outside / "escape.env"
    secret.write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_DIFFLINK_5555\n", encoding="utf-8")
    try:
        (project / "link.env").symlink_to(secret)
    except OSError:
        pytest.skip("symlink creation is not available on this filesystem")
    result = Scanner().scan(project, only_paths=[project / "link.env"])
    assert result["scanned_files"] == 0
    assert result["signals"] == []


def test_greynocignore_negation_reincludes_file(tmp_path):
    (tmp_path / ".greynocignore").write_text("*.env\n!keep.env\n", encoding="utf-8")
    (tmp_path / "keep.env").write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_KEEP_6666\n", encoding="utf-8")
    (tmp_path / "drop.env").write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_DROP_7777\n", encoding="utf-8")
    names = {p.name for p in iter_scan_files(tmp_path, None, load_greynocignore(tmp_path))}
    assert "keep.env" in names
    assert "drop.env" not in names


def test_greynocignore_anchored_pattern_matches_root_only(tmp_path):
    (tmp_path / ".greynocignore").write_text("/generated\n", encoding="utf-8")
    generated = tmp_path / "generated"
    generated.mkdir()
    (generated / "top.env").write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_ANCHOR_8888\n", encoding="utf-8")
    nested_parent = tmp_path / "src"
    nested_parent.mkdir()
    nested = nested_parent / "generated"
    nested.mkdir()
    (nested / "deep.env").write_text("API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_ANCHOR_9999\n", encoding="utf-8")
    names = {p.name for p in iter_scan_files(tmp_path, None, load_greynocignore(tmp_path))}
    assert "top.env" not in names
    assert "deep.env" in names


def test_is_ignored_accepts_precomputed_rel(tmp_path):
    target = tmp_path / "docs" / "notes.md"
    assert is_ignored(target, tmp_path, ["docs/*"], rel="docs/notes.md") is True
    assert is_ignored(target, tmp_path, ["other/*"], rel="docs/notes.md") is False


# ---------------------------------------------------------------------------
# utils helpers used by the scanner and parsers
# ---------------------------------------------------------------------------


def test_read_text_safely_normalizes_newlines_and_caps_size(tmp_path):
    crlf = tmp_path / "crlf.env"
    crlf.write_bytes(b"A=1\r\nB=2\rC=3\n")
    assert read_text_safely(crlf) == "A=1\nB=2\nC=3\n"

    binary = tmp_path / "model.pkl"
    binary.write_bytes(b"\xff\xfe binary \xff")
    text = read_text_safely(binary)
    assert text is not None and "binary" in text

    oversized = tmp_path / "big.txt"
    oversized.write_bytes(b"x" * (MAX_FILE_BYTES + 1))
    assert read_text_safely(oversized) is None

    assert read_text_safely(tmp_path / "missing.txt") is None


def test_line_index_matches_naive_lookups():
    text = "alpha\nbeta: 1\ngamma\nbeta: 2\n"
    index = LineIndex(text)
    assert index.lines == text.splitlines()
    assert index.line_for("gamma") == 3
    assert index.line_for("absent") is None
    assert index.line_for_key_value("outer.beta") == 2
    assert index.line_for_key_value("nope", "gamma") == 3
    for offset in range(len(text) + 2):
        assert index.line_at_offset(offset) == line_number_at_offset(text, offset)


def test_line_number_for_key_value_accepts_precomputed_lines():
    text = "one\ntwo secret=x\nthree\n"
    lines = text.splitlines()
    assert line_number_for_key_value(text, "secret", lines=lines) == 2
    assert line_number_for_key_value("", "secret", lines=lines) == 2


def test_simple_kv_pairs_handles_equals_and_colon():
    text = (
        "# comment\n"
        "; ini comment\n"
        "[section]\n"
        "password = hunter2secret99\n"
        "api_key: GNOC_FAKE_SECRET_DO_NOT_USE_KV_1234\n"
        'url = "https://user:pw@example.com" # trailing\n'
        "plain = value ; comment\n"
    )
    rows = {key: (value, number) for key, value, number in simple_kv_pairs(text)}
    assert rows["password"] == ("hunter2secret99", 4)
    assert rows["api_key"] == ("GNOC_FAKE_SECRET_DO_NOT_USE_KV_1234", 5)
    # First separator wins: '=' precedes the ':' inside the URL value.
    assert rows["url"][0] == "https://user:pw@example.com"
    assert rows["plain"] == ("value", 7)
    assert "[section]" not in rows


def test_parse_json_cached_returns_shared_object():
    text = '{"a": [1, 2]}'
    first = parse_json_cached(text)
    second = parse_json_cached(text)
    assert first is second
    assert first == {"a": [1, 2]}
    assert parse_json_cached("not json {") is None
