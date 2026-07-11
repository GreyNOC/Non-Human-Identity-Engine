"""Heuristic Terraform parser."""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import line_number_at_offset

# Wildcard IAM detection: JSON policy documents, jsonencode blocks with HCL
# keys, HCL attribute lists, and managed admin policy ARNs. A bare '"*"'
# substring (CORS headers, lifecycle globs, CloudFront methods) is NOT enough.
WILDCARD_POLICY_RE = re.compile(r'(?i)\b"?(?:Action|Resource)"?\s*[:=]\s*\[?\s*"\*"')
HCL_WILDCARD_ATTR_RE = re.compile(r'(?i)\b(?:actions|resources)\s*=\s*\[?\s*"\*"')
ADMIN_POLICY_ARN_RE = re.compile(r'"AdministratorAccess"|policy_arn\s*=\s*"[^"]*AdministratorAccess')
CREDENTIAL_ASSIGNMENT_RE = re.compile(
    r'(?i)\b\w*(access_key|secret_key|client_secret|password|token|private_key)\s*=\s*"([^"$]{8,})"'
)
PROVISIONER_EXEC_RE = re.compile(r'provisioner\s+"(remote-exec|local-exec)"')
CURL_PIPE_SH_RE = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z|k)?sh\b")

def should_parse(path: Path) -> bool:
    return path.suffix.lower() == ".tf"

def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    lower = text.lower()
    lines = text.splitlines()
    wildcard_match = (
        WILDCARD_POLICY_RE.search(text)
        or HCL_WILDCARD_ATTR_RE.search(text)
        or ADMIN_POLICY_ARN_RE.search(text)
    )
    if wildcard_match:
        signals.append(
            make_signal(
                rule_id="nhi_cloud_admin_policy",
                file_path=path,
                line_number=line_number_at_offset(text, wildcard_match.start()),
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
    for number, line in enumerate(lines, 1):
        match = CREDENTIAL_ASSIGNMENT_RE.search(line)
        if match:
            value = match.group(2).strip()
            if looks_like_secret(value):
                signals.append(
                    make_signal(
                        rule_id="nhi_cloud_key_detected",
                        file_path=path,
                        line_number=number,
                        name="Terraform cloud credential",
                        identity_type="cloud IAM user",
                        source="terraform",
                        evidence=line.strip(),
                        secret_value=value,
                        provider="cloud",
                        tags=["cloud", "plaintext_secret"],
                    )
                )
    if "service_account_key" in lower:
        key_line = next((i for i, ln in enumerate(lines, 1) if "service_account_key" in ln.lower()), None)
        signals.append(
            make_signal(
                rule_id="nhi_service_account_key_file",
                file_path=path,
                line_number=key_line,
                name="Service account key resource",
                identity_type="service account",
                source="terraform",
                evidence=lines[key_line - 1].strip() if key_line else "service_account_key resource present",
                provider="cloud",
                tags=["cloud", "service_account_key"],
            )
        )
    provisioner_match = PROVISIONER_EXEC_RE.search(text)
    if provisioner_match:
        remote_fetch = bool(CURL_PIPE_SH_RE.search(text))
        provisioner_line = line_number_at_offset(text, provisioner_match.start())
        signals.append(
            make_signal(
                rule_id="nhi_terraform_provisioner_exec",
                file_path=path,
                line_number=provisioner_line,
                name=f"Terraform {provisioner_match.group(1)} provisioner",
                identity_type="automation script credential",
                source="terraform",
                evidence=lines[provisioner_line - 1].strip() if provisioner_line <= len(lines) else provisioner_match.group(0),
                provider="cloud",
                external_access=remote_fetch,
                tags=["cloud", "provisioner_exec"] + (["remote_script"] if remote_fetch else []),
                confidence="high" if remote_fetch else "medium",
            )
        )
    return signals
