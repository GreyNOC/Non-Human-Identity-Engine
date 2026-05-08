"""Filesystem scanner that dispatches local parser modules."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from greynoc_nhi.cache import ParserCache, content_hash, parser_version_string, rewrite_file_path, sanitize_signals_for_disk
from greynoc_nhi.constants import IGNORED_DIRS, MAX_FILE_BYTES, SCAN_EXTENSIONS, SCAN_FILE_NAMES
from greynoc_nhi.custom_rules import CustomRule, load_rule_pack, scan_custom_rules
from greynoc_nhi.git_history import (
    commit_signal_fields,
    history_evidence_line,
    is_git_repository,
    iter_history_changes,
    remap_line_number,
)
from greynoc_nhi.ignore import is_ignored, load_greynocignore
from greynoc_nhi.masking import redact_inline_secret
from greynoc_nhi.parsers import PARSERS
from greynoc_nhi.utils import read_text_safely


def should_scan_file(path: Path) -> bool:
    """Return True when a file is small and relevant enough to scan."""
    name = path.name.lower()
    normalized = str(path).replace("\\", "/").lower()
    pulumi_stack = (
        name.startswith("pulumi.")
        and (name.endswith(".yaml") or name.endswith(".yml"))
    )
    package_cred_path = (
        normalized.endswith(".cargo/credentials")
        or normalized.endswith(".cargo/credentials.toml")
        or normalized.endswith(".cargo/config.toml")
        or normalized.endswith(".cargo/config")
        or normalized.endswith(".gradle/init.gradle")
        or normalized.endswith(".gradle/gradle.properties")
    )
    package_cred_name = name in {".npmrc", ".pypirc", ".netrc", "gradle.properties"}
    if (
        name in SCAN_FILE_NAMES
        or path.suffix.lower() in SCAN_EXTENSIONS
        or name.startswith(".env")
        or name.endswith(".tfstate")
        or name.endswith(".tfstate.backup")
        or pulumi_stack
        or package_cred_path
        or package_cred_name
    ):
        try:
            return path.stat().st_size <= MAX_FILE_BYTES
        except OSError:
            return False
    return False


def iter_scan_files(project_path: str | Path, ignored_dirs: set[str] | None = None, ignore_patterns: list[str] | None = None) -> list[Path]:
    """Recursively list scan candidates while skipping noisy dependency folders.

    Symlinks (file or directory) are never followed. This keeps the scan strictly
    inside the project root, prevents symlink loops from hanging the scanner, and
    avoids leaking redacted-but-real evidence from outside paths (e.g. /etc,
    ~/.ssh, ~/.aws) into reports, SQLite, or SARIF output.
    """
    ignored = ignored_dirs or IGNORED_DIRS
    root = Path(project_path)
    try:
        root_resolved = root.resolve()
    except OSError:
        return []
    patterns = ignore_patterns or []
    files: list[Path] = []
    stack = [root]
    visited: set[Path] = set()
    while stack:
        current = stack.pop()
        try:
            children = list(current.iterdir())
        except OSError:
            continue
        for path in children:
            if path.is_symlink():
                continue
            try:
                resolved = path.resolve()
            except OSError:
                continue
            try:
                resolved.relative_to(root_resolved)
            except ValueError:
                continue
            if resolved in visited:
                continue
            visited.add(resolved)
            if is_ignored(path, root, patterns):
                continue
            if path.is_dir():
                if path.name not in ignored:
                    stack.append(path)
                continue
            if path.is_file() and should_scan_file(path):
                files.append(path)
    return sorted(files)


def dedupe_signals(signals: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Drop duplicate parser signals while preserving order."""
    deduped: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    for signal in signals:
        key = (
            signal.get("rule_id"),
            signal.get("file_path"),
            signal.get("line_number"),
            signal.get("name"),
            tuple(signal.get("evidence", [])),
        )
        if key in seen:
            continue
        seen.add(key)
        deduped.append(signal)
    return deduped


class Scanner:
    """Local recursive scanner."""

    def __init__(
        self,
        ignored_dirs: set[str] | None = None,
        rule_pack_path: str | Path | None = None,
        cache: ParserCache | None = None,
    ) -> None:
        self.ignored_dirs = ignored_dirs or IGNORED_DIRS
        self.custom_rules: list[CustomRule] = load_rule_pack(rule_pack_path)
        self.cache = cache
        self._parser_version = parser_version_string(PARSERS)

    def scan(
        self,
        project_path: str | Path,
        *,
        only_paths: list[Path] | None = None,
    ) -> dict[str, Any]:
        root = Path(project_path).resolve()
        signals: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        scanned_files = 0
        skipped_files = 0
        parser_cache: dict[tuple[str, str, str], list[Any]] = {}
        ignore_patterns = load_greynocignore(root)
        candidates = iter_scan_files(root, self.ignored_dirs, ignore_patterns)
        if only_paths is not None:
            allowed = {p.resolve() for p in only_paths}
            candidates = [p for p in candidates if p.resolve() in allowed]
        cache_hits = 0
        cache_misses = 0
        for path in candidates:
            text = read_text_safely(path)
            if text is None:
                skipped_files += 1
                continue
            scanned_files += 1
            cache_key = (path.name.lower(), path.suffix.lower(), str(path.parent).replace("\\", "/").lower())
            parsers = parser_cache.get(cache_key)
            if parsers is None:
                parsers = [parser for parser in PARSERS if parser.should_parse(path)]
                parser_cache[cache_key] = parsers
            file_signals: list[dict[str, Any]] = []
            content_sha: str | None = None
            cached_signals: list[dict[str, Any]] | None = None
            if self.cache is not None and parsers:
                content_sha = content_hash(text)
                cached_signals = self.cache.get(content_sha, self._parser_version)
            if cached_signals is not None:
                file_signals.extend(rewrite_file_path(cached_signals, str(path)))
                cache_hits += 1
            else:
                if parsers:
                    cache_misses += 1
                for parser in parsers:
                    try:
                        file_signals.extend(parser.parse(path, text))
                    except Exception as exc:  # Defensive parser isolation.
                        errors.append({"file": str(path), "parser": parser.__name__, "error": redact_inline_secret(str(exc))})
                has_secret_signal = any(signal.get("secret_value") for signal in file_signals)
                if self.cache is not None and content_sha is not None and parsers and not has_secret_signal:
                    self.cache.put(content_sha, self._parser_version, sanitize_signals_for_disk(file_signals))
            signals.extend(file_signals)
            signals.extend(scan_custom_rules(path, text, self.custom_rules))
        return {
            "project_path": str(root),
            "signals": dedupe_signals(signals),
            "errors": errors,
            "scanned_files": scanned_files,
            "skipped_files": skipped_files,
            "ignore_patterns": ignore_patterns,
            "custom_rules": self.custom_rules,
            "cache_hits": cache_hits,
            "cache_misses": cache_misses,
        }

    def scan_history(
        self,
        project_path: str | Path,
        *,
        max_commits: int | None = 1000,
        since: str | None = None,
    ) -> dict[str, Any]:
        """Scan a repository's git history for secrets in past commits."""
        root = Path(project_path).resolve()
        signals: list[dict[str, Any]] = []
        errors: list[dict[str, str]] = []
        commits_seen: set[str] = set()
        if not is_git_repository(root):
            return {
                "project_path": str(root),
                "signals": [],
                "errors": [{"file": str(root), "parser": "git_history", "error": "not a git repository"}],
                "commits_scanned": 0,
            }
        try:
            changes = list(iter_history_changes(root, max_commits=max_commits, since=since))
        except Exception as exc:
            return {
                "project_path": str(root),
                "signals": [],
                "errors": [{"file": str(root), "parser": "git_history", "error": redact_inline_secret(str(exc))}],
                "commits_scanned": 0,
            }
        for change in changes:
            commits_seen.add(change.commit.sha)
            synthetic_path = root / change.file_path
            for parser in PARSERS:
                try:
                    if not parser.should_parse(synthetic_path):
                        continue
                    raw_signals = parser.parse(synthetic_path, change.synthetic_text)
                except Exception as exc:
                    errors.append({
                        "file": change.file_path,
                        "parser": parser.__name__,
                        "error": redact_inline_secret(str(exc)),
                        "commit": change.commit.short_sha,
                    })
                    continue
                for sig in raw_signals:
                    remapped = remap_line_number(change.line_map, sig.get("line_number"))
                    if remapped is not None:
                        sig["line_number"] = remapped
                    sig.update(commit_signal_fields(change.commit))
                    sig["tags"] = list(sig.get("tags", [])) + ["git_history"]
                    sig["evidence"] = list(sig.get("evidence", [])) + [history_evidence_line(change.commit)]
                    signals.append(sig)
        return {
            "project_path": str(root),
            "signals": dedupe_signals(signals),
            "errors": errors,
            "commits_scanned": len(commits_seen),
        }
