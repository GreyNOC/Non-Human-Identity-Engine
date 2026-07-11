"""Terraform state (.tfstate / .tfstate.backup) parser.

Terraform state files persist provisioned secrets in plaintext - access keys,
generated passwords, signing keys, etc. They are sometimes committed by mistake
(or carried into a repo via backup files), which is a worse leak than the
.tf source because the state contains the *resolved* credential value.
"""

from __future__ import annotations

__version__ = 2

import bisect
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, parse_json_safely

SECRET_KEY_HINTS = (
    "secret",
    "password",
    "passwd",
    "private_key",
    "client_secret",
    "access_key",
    "api_key",
    "token",
    "auth_key",
    "encrypted_password",
    "session_token",
    "ssh_key",
    "tls_key",
    "certificate_pem",
)

PROVIDER_HINTS = {
    "aws_": "aws",
    "azurerm_": "azure",
    "azuread_": "azure",
    "google_": "google cloud",
    "kubernetes_": "kubernetes",
    "vault_": "hashicorp vault",
    "github_": "github",
}


def should_parse(path: Path) -> bool:
    name = path.name.lower()
    return name.endswith(".tfstate") or name.endswith(".tfstate.backup")


def _line_offsets(text: str) -> list[int]:
    """Precompute line-start offsets for bisect-based line lookups."""
    offsets = [0]
    start = 0
    while True:
        idx = text.find("\n", start)
        if idx == -1:
            return offsets
        offsets.append(idx + 1)
        start = idx + 1


def _line_number_for_key_value(text: str, offsets: list[int], key: str, value: object | None = None) -> int | None:
    """First line containing the key tail or the value, without re-splitting text."""
    key_tail = str(key).split(".")[-1].split("[")[0]
    positions: list[int] = []
    if key_tail:
        pos = text.find(key_tail)
        if pos != -1:
            positions.append(pos)
    value_s = "" if value is None else str(value)
    if value_s and "\n" not in value_s:
        pos = text.find(value_s)
        if pos != -1:
            positions.append(pos)
    if not positions:
        return None
    return bisect.bisect_right(offsets, min(positions))


def _provider_from_resource_type(resource_type: str | None) -> str | None:
    if not resource_type:
        return None
    lowered = str(resource_type).lower()
    for prefix, provider in PROVIDER_HINTS.items():
        if lowered.startswith(prefix):
            return provider
    return None


def parse(path: Path, text: str) -> list[Signal]:
    data = parse_json_safely(text)
    if data is None:
        return []
    flat = flatten_json(data)
    type_map: dict[str, str] = {}
    for key, value in flat:
        if isinstance(value, str) and key.endswith(".type"):
            type_map[key[: -len(".type")]] = value
    signals: list[Signal] = []
    seen: set[tuple[str, str]] = set()
    offsets = _line_offsets(text)
    for key, value in flat:
        if not isinstance(value, str) or not value:
            continue
        last_segment = key.split(".")[-1].split("[")[0].lower()
        if not any(hint in last_segment for hint in SECRET_KEY_HINTS):
            continue
        if not looks_like_secret(value):
            continue
        dedupe_key = (key, value[:32])
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        # Longest matching dotted prefix wins (the deepest enclosing resource),
        # derived by stripping trailing segments instead of scanning type_map.
        resource_type: str | None = None
        prefix = key
        while resource_type is None:
            dot = prefix.rfind(".")
            if dot == -1:
                break
            prefix = prefix[:dot]
            if prefix in type_map:
                resource_type = type_map[prefix]
        provider = _provider_from_resource_type(resource_type)
        signals.append(
            make_signal(
                rule_id="nhi_terraform_state_plaintext_secret",
                file_path=path,
                line_number=_line_number_for_key_value(text, offsets, key, value),
                name=f"Terraform state secret: {last_segment}",
                identity_type="cloud_workload_identity",
                source="terraform state",
                evidence=f"{key}={value}",
                secret_value=value,
                provider=provider or "terraform",
                production_access=True,
                tags=["terraform", "tfstate", "plaintext_secret"],
                confidence="high",
            )
        )
    return signals
