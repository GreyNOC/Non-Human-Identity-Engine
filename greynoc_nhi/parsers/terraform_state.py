"""Terraform state (.tfstate / .tfstate.backup) parser.

Terraform state files persist provisioned secrets in plaintext - access keys,
generated passwords, signing keys, etc. They are sometimes committed by mistake
(or carried into a repo via backup files), which is a worse leak than the
.tf source because the state contains the *resolved* credential value.
"""

from __future__ import annotations

__version__ = 1

from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, line_number_for_key_value, parse_json_safely

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
        resource_type: str | None = None
        for prefix, candidate_type in type_map.items():
            if key.startswith(prefix + "."):
                resource_type = candidate_type
        provider = _provider_from_resource_type(resource_type)
        signals.append(
            make_signal(
                rule_id="nhi_terraform_state_plaintext_secret",
                file_path=path,
                line_number=line_number_for_key_value(text, key, value),
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
