"""OAuth-style config parser."""

from __future__ import annotations

__version__ = 1

from pathlib import Path

from greynoc_nhi.confidence import should_suppress_candidate
from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, line_number_for_key_value, parse_json_safely, simple_yaml_pairs

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

def should_parse(path: Path) -> bool:
    return path.suffix.lower() in {".json", ".yaml", ".yml"} and ("oauth" in path.name.lower() or "app" in path.name.lower() or "config" in path.name.lower())

def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    rows: list[tuple[str, object]] = []
    data = parse_json_safely(text)
    if data is not None:
        rows = flatten_json(data)
    else:
        rows = [(k, v) for k, v, _ in simple_yaml_pairs(text)]
    scopes_found: list[str] = []
    client_name = path.stem
    for key, value in rows:
        key_l = key.lower()
        value_s = str(value)
        if key_l.endswith("client_id"):
            client_name = value_s
        if key_l.endswith("client_secret") and not should_suppress_candidate(key, value_s) and looks_like_secret(value_s):
            signals.append(make_signal(rule_id="nhi_oauth_client_secret_present", file_path=path, line_number=line_number_for_key_value(text, key, value_s), name=client_name, identity_type="OAuth application", source="oauth config", evidence=f"{key}: {value_s}", secret_value=value_s, external_access=True, tags=["oauth", "plaintext_secret"], confidence="high"))
        if "scope" in key_l:
            for scope in BROAD_SCOPES:
                if scope in value_s.lower():
                    scopes_found.append(scope)
    if scopes_found:
        first_scope = sorted(set(scopes_found))[0]
        signals.append(make_signal(rule_id="nhi_broad_oauth_scope", file_path=path, line_number=line_number_for_key_value(text, "scopes", first_scope), name=client_name, identity_type="OAuth application", source="oauth config", evidence=f"Broad OAuth scopes: {', '.join(sorted(set(scopes_found)))}", scopes=sorted(set(scopes_found)), external_access=True, data_access_level="customer", tags=["oauth", "broad_scope"], confidence="medium"))
    return signals
