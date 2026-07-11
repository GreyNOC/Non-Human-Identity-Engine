"""OAuth-style config parser."""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.confidence import should_suppress_candidate
from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, parse_json_safely, simple_yaml_pairs

BROAD_SCOPES = {
    "mail.read",
    "mail.readwrite",
    "files.read",
    "files.read.all",
    "files.readwrite.all",
    "directory.read.all",
    "directory.readwrite.all",
    "user.readwrite.all",
    "offline_access",
    "repo",
    "workflow",
    "admin",
    "full_access",
    "cloud-platform",
    "iam",
    "storage.admin",
    "owner",
    "write",
    "delete",
}

_SCOPE_SPLIT_RE = re.compile(r"[\s,;]+")

def should_parse(path: Path) -> bool:
    return path.suffix.lower() in {".json", ".yaml", ".yml"} and ("oauth" in path.name.lower() or "app" in path.name.lower() or "config" in path.name.lower())

def _broad_scope_tokens(value_s: str) -> list[str]:
    """Exact-token scope matching.

    Substring matching flagged narrow scopes ('write' in chat:write, 'repo' in
    repository:read, 'iam' in miami-*). Tokens must equal a broad scope, be an
    admin:* colon scope, or end a URI-form scope (e.g. .../auth/cloud-platform).
    """
    found: list[str] = []
    for raw in _SCOPE_SPLIT_RE.split(value_s.lower()):
        token = raw.strip("'\"[](){}")
        if not token:
            continue
        if token in BROAD_SCOPES or token.startswith("admin:") or any(token.endswith("/" + scope) for scope in BROAD_SCOPES):
            found.append(token)
    return found

def _line_number_in(lines: list[str], key: str, value: str) -> int | None:
    """Same semantics as utils.line_number_for_key_value over precomputed lines."""
    key_tail = key.split(".")[-1].split("[")[0]
    for number, line in enumerate(lines, 1):
        if key_tail and key_tail in line:
            return number
        if value and value in line:
            return number
    return None

def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    rows: list[tuple[str, object]] = []
    data = parse_json_safely(text)
    if data is not None:
        rows = flatten_json(data)
    else:
        rows = [(k, v) for k, v, _ in simple_yaml_pairs(text)]
    lines = text.splitlines()
    scopes_found: list[str] = []
    client_name = path.stem
    for key, value in rows:
        key_l = key.lower()
        value_s = str(value)
        if key_l.endswith("client_id"):
            client_name = value_s
        if key_l.endswith("client_secret") and not should_suppress_candidate(key, value_s) and looks_like_secret(value_s):
            signals.append(make_signal(rule_id="nhi_oauth_client_secret_present", file_path=path, line_number=_line_number_in(lines, key, value_s), name=client_name, identity_type="OAuth application", source="oauth config", evidence=f"{key}: {value_s}", secret_value=value_s, external_access=True, tags=["oauth", "plaintext_secret"], confidence="high"))
        if "scope" in key_l:
            scopes_found.extend(_broad_scope_tokens(value_s))
    if scopes_found:
        unique_scopes = sorted(set(scopes_found))
        signals.append(make_signal(rule_id="nhi_broad_oauth_scope", file_path=path, line_number=_line_number_in(lines, "scopes", unique_scopes[0]), name=client_name, identity_type="OAuth application", source="oauth config", evidence=f"Broad OAuth scopes: {', '.join(unique_scopes)}", scopes=unique_scopes, external_access=True, data_access_level="customer", tags=["oauth", "broad_scope"], confidence="medium"))
    return signals
