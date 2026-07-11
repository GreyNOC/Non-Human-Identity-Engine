"""Filesystem scanner that dispatches local parser modules."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

from greynoc_nhi.cache import ParserCache, content_hash, parser_version_string, rewrite_file_path
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


def _matches_scan_targets(path: Path) -> bool:
    """Name-level scan predicate (no filesystem access)."""
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
        or normalized.endswith(".aws/credentials")
        or normalized.endswith(".kube/config")
    )
    package_cred_name = name in {".npmrc", ".pypirc", ".netrc", "gradle.properties", ".yarnrc", ".git-credentials"}
    return (
        name in SCAN_FILE_NAMES
        or path.suffix.lower() in SCAN_EXTENSIONS
        or name.startswith(".env")
        or name.endswith(".tfstate")
        or name.endswith(".tfstate.backup")
        or name.startswith("dockerfile.")
        or pulumi_stack
        or package_cred_path
        or package_cred_name
    )


def should_scan_file(path: Path) -> bool:
    """Return True when a file is small and relevant enough to scan."""
    if not _matches_scan_targets(path):
        return False
    try:
        return path.stat().st_size <= MAX_FILE_BYTES
    except OSError:
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
    # Stack entries carry the POSIX-style path relative to root so is_ignored
    # never has to re-resolve; symlinked dirs are never traversed, so the
    # traversal-relative path always equals the resolved-relative path.
    stack: list[tuple[Path, str]] = [(root, "")]
    # Seed with the resolved root so a Windows junction that aliases the root (or
    # any already-visited directory) is deduplicated instead of re-scanning the
    # whole subtree under the alias path and double-counting every finding.
    visited: set[Path] = {root_resolved}
    while stack:
        current, rel_prefix = stack.pop()
        try:
            entries = list(os.scandir(current))
        except OSError:
            continue
        for entry in entries:
            try:
                if entry.is_symlink():
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
            except OSError:
                continue
            name = entry.name
            rel = f"{rel_prefix}/{name}" if rel_prefix else name
            path = Path(entry.path)
            if is_dir:
                # resolve() + containment + visited are kept for directories
                # only: they guard against Windows junction loops/escapes.
                # Non-symlink files under containment-checked dirs cannot
                # resolve outside root, so files skip the expensive resolve.
                try:
                    resolved = path.resolve()
                    resolved.relative_to(root_resolved)
                except OSError:
                    continue
                except ValueError:
                    continue
                if resolved in visited:
                    continue
                visited.add(resolved)
                if patterns and is_ignored(path, root, patterns, rel=rel):
                    continue
                if name not in ignored:
                    stack.append((path, rel))
                continue
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
                size_ok = entry.stat(follow_symlinks=False).st_size <= MAX_FILE_BYTES
            except OSError:
                continue
            if patterns and is_ignored(path, root, patterns, rel=rel):
                continue
            if size_ok and _matches_scan_targets(path):
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
        ignore_patterns = load_greynocignore(root)
        if only_paths is not None:
            # Diff mode: validate the handful of changed paths directly
            # instead of walking (and resolving) the entire tree.
            candidates = self._validate_only_paths(root, only_paths, ignore_patterns)
        else:
            candidates = iter_scan_files(root, self.ignored_dirs, ignore_patterns)
        cache_hits = 0
        cache_misses = 0
        for path in candidates:
            text = read_text_safely(path)
            if text is None:
                skipped_files += 1
                continue
            scanned_files += 1
            parsers = [parser for parser in PARSERS if parser.should_parse(path)]
            file_signals: list[dict[str, Any]] = []
            content_sha: str | None = None
            cached_signals: list[dict[str, Any]] | None = None
            # The basename is part of the cache key because several parsers make
            # path-dependent decisions (production flag from a "prod"-named file,
            # the file stem baked into a signal name, sshd_config detection, the
            # registry-name switch). Without it, two identical-content files with
            # different names would share one cached row and the second would
            # inherit the first file's production/environment/name attributes.
            dispatch = path.name.lower() + "|" + ",".join(sorted(parser.__name__ for parser in parsers))
            if self.cache is not None and parsers:
                content_sha = content_hash(text)
                cached_signals = self.cache.get(content_sha, self._parser_version, dispatch=dispatch)
            if cached_signals is not None:
                file_signals.extend(rewrite_file_path(cached_signals, str(path)))
                cache_hits += 1
            else:
                if self.cache is not None and parsers:
                    cache_misses += 1
                for parser in parsers:
                    try:
                        file_signals.extend(parser.parse(path, text))
                    except Exception as exc:  # Defensive parser isolation.
                        errors.append({"file": str(path), "parser": parser.__name__, "error": redact_inline_secret(str(exc))})
                has_secret_signal = any(signal.get("secret_value") for signal in file_signals)
                if self.cache is not None and content_sha is not None and parsers and not has_secret_signal:
                    self.cache.put(content_sha, self._parser_version, file_signals, dispatch=dispatch)
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

    def _validate_only_paths(
        self,
        root: Path,
        only_paths: list[Path],
        ignore_patterns: list[str],
    ) -> list[Path]:
        """Validate diff-mode candidates directly, in O(changed files).

        Reproduces every traversal-time gate from iter_scan_files — root
        containment, ignored directory names on any ancestor, .greynocignore
        patterns on the file and its ancestors, symlink refusal (resolve()
        canonicalizes links; escapes fail containment), and the size/name
        gate — so a diff scan agrees with a full scan on whether each file
        is scanned.
        """
        validated: list[Path] = []
        seen: set[Path] = set()
        for candidate in only_paths:
            try:
                resolved = Path(candidate).resolve()
            except OSError:
                continue
            try:
                rel = resolved.relative_to(root)
            except ValueError:
                continue
            if resolved in seen:
                continue
            seen.add(resolved)
            parts = rel.parts
            if any(part in self.ignored_dirs for part in parts[:-1]):
                continue
            if ignore_patterns:
                blocked = False
                ancestor = root
                for index, part in enumerate(parts[:-1], start=1):
                    ancestor = ancestor / part
                    if is_ignored(ancestor, root, ignore_patterns, rel="/".join(parts[:index])):
                        blocked = True
                        break
                if blocked:
                    continue
                if is_ignored(resolved, root, ignore_patterns, rel=rel.as_posix()):
                    continue
            try:
                if not resolved.is_file():
                    continue
            except OSError:
                continue
            if not should_scan_file(resolved):
                continue
            validated.append(resolved)
        return sorted(validated)

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
        # The same file path recurs across many commits; memoize the parser
        # dispatch per path so the ~26 should_parse checks run once per file
        # instead of once per (commit, file) pair.
        dispatch_memo: dict[str, list[Any]] = {}
        for change in changes:
            commits_seen.add(change.commit.sha)
            synthetic_path = root / change.file_path
            parsers = dispatch_memo.get(change.file_path)
            if parsers is None:
                parsers = []
                for parser in PARSERS:
                    try:
                        if parser.should_parse(synthetic_path):
                            parsers.append(parser)
                    except Exception as exc:
                        errors.append({
                            "file": change.file_path,
                            "parser": parser.__name__,
                            "error": redact_inline_secret(str(exc)),
                            "commit": change.commit.short_sha,
                        })
                dispatch_memo[change.file_path] = parsers
            for parser in parsers:
                try:
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
