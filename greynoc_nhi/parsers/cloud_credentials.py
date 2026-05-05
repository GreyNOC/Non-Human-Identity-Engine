"""Cloud credential pattern parser."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import line_number_at_offset, line_number_for, parse_json_safely


def should_parse(path: Path) -> bool:
    return path.suffix.lower() in {".json", ".txt", ".env", ".yaml", ".yml", ".tf", ".py", ".js", ".ts"}


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    for match in re.finditer(r"\bAKIA[0-9A-Z]{12,20}\b", text):
        signals.append(make_signal(rule_id="nhi_cloud_key_detected", file_path=path, line_number=line_number_at_offset(text, match.start()), name="AWS access key ID", identity_type="cloud IAM user", source="cloud credentials", evidence=match.group(0), secret_value=match.group(0), provider="aws", tags=["cloud", "plaintext_secret"], confidence="high"))
    if "-----BEGIN PRIVATE KEY-----" in text or "-----BEGIN RSA PRIVATE KEY-----" in text:
        signals.append(make_signal(rule_id="nhi_private_key_detected", file_path=path, line_number=line_number_for(text, "-----BEGIN"), name="Private key block", identity_type="service account", source="cloud credentials", evidence="Private key block detected", secret_value="PRIVATE_KEY_BLOCK", provider="cloud", tags=["cloud", "private_key"], confidence="high"))
    data = parse_json_safely(text)
    if isinstance(data, dict) and data.get("type") == "service_account" and data.get("client_email"):
        signals.append(make_signal(rule_id="nhi_service_account_key_file", file_path=path, line_number=line_number_for(text, "client_email") or line_number_for(text, "service_account"), name=str(data.get("client_email")), identity_type="service account", source="cloud credentials", evidence="Google service account JSON structure", provider="google cloud", external_access=True, tags=["cloud", "service_account_key"], confidence="high"))
    if all(token in text for token in ["client_id", "tenant_id", "client_secret"]):
        signals.append(make_signal(rule_id="nhi_cloud_key_detected", file_path=path, line_number=line_number_for(text, "client_secret"), name="Azure application credential", identity_type="service account", source="cloud credentials", evidence="Azure client id, tenant id, and client secret present", provider="azure", external_access=True, tags=["cloud", "plaintext_secret"], confidence="high"))
    return signals
