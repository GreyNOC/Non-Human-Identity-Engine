"""Parser helper functions."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from greynoc_nhi.confidence import infer_confidence
from greynoc_nhi.masking import mask_secret, redact_inline_secret
from greynoc_nhi.utils import stable_id


Signal = dict[str, Any]


def make_signal(
    *,
    rule_id: str,
    file_path: str | Path,
    line_number: int | None,
    name: str,
    identity_type: str,
    source: str,
    evidence: str,
    secret_value: str | None = None,
    provider: str | None = None,
    environment: str | None = None,
    permissions: list[str] | None = None,
    scopes: list[str] | None = None,
    tools: list[str] | None = None,
    tags: list[str] | None = None,
    admin_access: bool = False,
    production_access: bool = False,
    external_access: bool = False,
    data_access_level: str = "unknown",
    approval_required: bool | None = None,
    logging_enabled: bool | None = None,
    rotation_status: str | None = None,
    confidence: str | None = None,
) -> Signal:
    if secret_value:
        evidence = evidence.replace(secret_value, mask_secret(secret_value))
    masked_evidence = redact_inline_secret(evidence)
    if secret_value:
        masked_evidence = masked_evidence.replace(secret_value, mask_secret(secret_value))
    return {
        "id": stable_id("sig", file_path, line_number, rule_id, name, masked_evidence),
        "rule_id": rule_id,
        "file_path": str(file_path),
        "line_number": line_number,
        "name": name,
        "identity_type": identity_type,
        "source": source,
        "evidence": [masked_evidence],
        "secret_value": secret_value,
        "provider": provider,
        "environment": environment,
        "permissions": permissions or [],
        "scopes": scopes or [],
        "tools": tools or [],
        "tags": tags or [],
        "admin_access": admin_access,
        "production_access": production_access,
        "external_access": external_access,
        "data_access_level": data_access_level,
        "approval_required": approval_required,
        "logging_enabled": logging_enabled,
        "rotation_status": rotation_status,
        "confidence": infer_confidence(rule_id, masked_evidence, secret_value, confidence),
    }
