"""Heuristic Terraform parser."""

from __future__ import annotations

__version__ = 1

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal

def should_parse(path: Path) -> bool:
    return path.suffix.lower() == ".tf"

def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    lower = text.lower()
    if re.search(r'"Action"\s*:\s*"\*"', text) or re.search(r'"Resource"\s*:\s*"\*"', text) or '"*"' in text:
        signals.append(
            make_signal(
                rule_id="nhi_cloud_admin_policy",
                file_path=path,
                line_number=next((i for i, l in enumerate(text.splitlines(), 1) if '"*"' in l), None),
                name="Broad Terraform IAM policy",
                identity_type="cloud IAM role",
                source="terraform",
                evidence="IAM policy includes wildcard action or resource",
                permissions=["*"],
                admin_access=True,
                provider="cloud",
                tags=["cloud", "admin_policy"],
            )
        )
    for number, line in enumerate(text.splitlines(), 1):
        if re.search(r"(access_key|secret_key|client_secret).*=.*\".+\"", line, re.I):
            signals.append(
                make_signal(
                    rule_id="nhi_cloud_key_detected",
                    file_path=path,
                    line_number=number,
                    name="Terraform cloud credential",
                    identity_type="cloud IAM user",
                    source="terraform",
                    evidence=line.strip(),
                    provider="cloud",
                    tags=["cloud", "plaintext_secret"],
                )
            )
        if "service_account_key" in lower:
            signals.append(
                make_signal(
                    rule_id="nhi_service_account_key_file",
                    file_path=path,
                    line_number=number,
                    name="Service account key resource",
                    identity_type="service account",
                    source="terraform",
                    evidence=line.strip(),
                    provider="cloud",
                    tags=["cloud", "service_account_key"],
                )
            )
            break
    return signals
