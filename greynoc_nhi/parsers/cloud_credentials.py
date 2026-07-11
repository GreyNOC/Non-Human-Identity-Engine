"""Cloud credential pattern parser."""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.confidence import is_placeholder_value
from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import line_number_at_offset, line_number_for, parse_json_safely

SUFFIXES = {
    ".json", ".txt", ".env", ".yaml", ".yml", ".tf", ".py", ".js", ".ts",
    ".sh", ".bash", ".zsh", ".ps1",
    ".pem", ".key", ".ppk", ".tfvars", ".properties", ".xml",
}

CREDENTIAL_FILE_NAMES = {
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519",
    ".git-credentials", ".pgpass", ".my.cnf", ".s3cfg",
    "kubeconfig", "credentials", "settings.xml",
}

# Real AWS access key IDs are exactly prefix + 16 uppercase base32 chars;
# ASIA = temporary/STS, ABIA = bearer, ACCA = context-specific.
AWS_KEY_RE = re.compile(r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b")
CLOUD_TOKEN_PATTERNS = (
    ("Google API key", "google", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("DigitalOcean token", "digitalocean", re.compile(r"\bdop_v1_[a-f0-9]{64}\b")),
    ("Databricks token", "databricks", re.compile(r"\bdapi[a-f0-9]{32}(?:-\d)?\b")),
)
# Header form shared with masking.PRIVATE_KEY_BLOCK_RE; covers RSA, EC, DSA,
# OPENSSH, PKCS8 (bare), and ENCRYPTED variants.
PEM_PRIVATE_KEY_HEADER_RE = re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")
AZURE_CLIENT_SECRET_RE = re.compile(r"client_secret[\"']?\s*[:=]\s*[\"']?([^\"'\s,}]{12,})")
# Dotted identifier chains (settings.client_secret, config.azure.secret) are
# code references, not secret values.
_REFERENCE_VALUE_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+$")
KUBE_TOKEN_RE = re.compile(r"^\s*token\s*[:=]\s*[\"']?([^\"'\s]+)", re.IGNORECASE)
KUBE_CLIENT_KEY_RE = re.compile(r"client-key-data\s*:\s*[\"']?([A-Za-z0-9+/=_\-]{40,})")
AWS_SECRET_LINE_RE = re.compile(r"^\s*aws_secret_access_key\s*=\s*(\S+)", re.IGNORECASE)
TFVARS_SECRET_RE = re.compile(
    r"^\s*([A-Za-z0-9_-]*(?:secret|token|password|api_key|access_key|private_key|credential)[A-Za-z0-9_-]*)\s*=\s*\"([^\"]+)\"",
    re.IGNORECASE,
)


def _normalized(path: Path) -> str:
    return str(path).replace("\\", "/").lower()


def should_parse(path: Path) -> bool:
    if path.name.lower() in CREDENTIAL_FILE_NAMES:
        return True
    normalized = _normalized(path)
    if normalized.endswith(".aws/credentials") or normalized.endswith(".kube/config"):
        return True
    return path.suffix.lower() in SUFFIXES


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    name = path.name.lower()
    normalized = _normalized(path)
    for match in AWS_KEY_RE.finditer(text):
        signals.append(make_signal(rule_id="nhi_cloud_key_detected", file_path=path, line_number=line_number_at_offset(text, match.start()), name="AWS access key ID", identity_type="cloud IAM user", source="cloud credentials", evidence=match.group(0), secret_value=match.group(0), provider="aws", tags=["cloud", "plaintext_secret"], confidence="high"))
    for token_name, provider, pattern in CLOUD_TOKEN_PATTERNS:
        for match in pattern.finditer(text):
            signals.append(make_signal(rule_id="nhi_cloud_key_detected", file_path=path, line_number=line_number_at_offset(text, match.start()), name=token_name, identity_type="api_key", source="cloud credentials", evidence=match.group(0), secret_value=match.group(0), provider=provider, tags=["cloud", "plaintext_secret"], confidence="high"))
    pem_match = PEM_PRIVATE_KEY_HEADER_RE.search(text)
    if pem_match:
        signals.append(make_signal(rule_id="nhi_private_key_detected", file_path=path, line_number=line_number_at_offset(text, pem_match.start()), name="Private key block", identity_type="service account", source="cloud credentials", evidence="Private key block detected", secret_value="PRIVATE_KEY_BLOCK", provider="cloud", tags=["cloud", "private_key"], confidence="high"))
    elif text.lstrip().startswith("PuTTY-User-Key-File"):
        signals.append(make_signal(rule_id="nhi_private_key_detected", file_path=path, line_number=1, name="Private key block", identity_type="service account", source="cloud credentials", evidence="PuTTY private key file detected", secret_value="PRIVATE_KEY_BLOCK", provider="cloud", tags=["cloud", "private_key"], confidence="high"))
    data = parse_json_safely(text)
    if isinstance(data, dict) and data.get("type") == "service_account" and data.get("client_email"):
        signals.append(make_signal(rule_id="nhi_service_account_key_file", file_path=path, line_number=line_number_for(text, "client_email") or line_number_for(text, "service_account"), name=str(data.get("client_email")), identity_type="service account", source="cloud credentials", evidence="Google service account JSON structure", provider="google cloud", external_access=True, tags=["cloud", "service_account_key"], confidence="high"))
    if all(token in text for token in ["client_id", "tenant_id", "client_secret"]):
        secret_match = AZURE_CLIENT_SECRET_RE.search(text)
        candidate = secret_match.group(1) if secret_match else None
        if candidate and "(" not in candidate and not _REFERENCE_VALUE_RE.match(candidate) and looks_like_secret(candidate) and not is_placeholder_value(candidate):
            signals.append(make_signal(rule_id="nhi_cloud_key_detected", file_path=path, line_number=line_number_at_offset(text, secret_match.start()), name="Azure application credential", identity_type="service account", source="cloud credentials", evidence="Azure client id, tenant id, and client secret present", secret_value=candidate, provider="azure", external_access=True, tags=["cloud", "plaintext_secret"], confidence="high"))
    if "client-key-data" in text:
        for match in KUBE_CLIENT_KEY_RE.finditer(text):
            signals.append(make_signal(rule_id="nhi_private_key_detected", file_path=path, line_number=line_number_at_offset(text, match.start()), name="kubeconfig client-key-data", identity_type="service account", source="cloud credentials", evidence="client-key-data with embedded client key material", secret_value=match.group(1), provider="kubernetes", tags=["cloud", "private_key", "kubernetes"], confidence="high"))
    if name == "kubeconfig" or normalized.endswith(".kube/config"):
        for number, line in enumerate(text.splitlines(), 1):
            match = KUBE_TOKEN_RE.match(line)
            if match and looks_like_secret(match.group(1)):
                signals.append(make_signal(rule_id="nhi_bearer_token_detected", file_path=path, line_number=number, name="kubeconfig user token", identity_type="service account", source="cloud credentials", evidence=line.strip(), secret_value=match.group(1), provider="kubernetes", tags=["cloud", "plaintext_secret", "kubernetes"], confidence="high"))
    if name == "credentials" or normalized.endswith(".aws/credentials"):
        section = ""
        for number, line in enumerate(text.splitlines(), 1):
            clean = line.strip()
            if clean.startswith("[") and clean.endswith("]"):
                section = clean.strip("[]").strip()
                continue
            match = AWS_SECRET_LINE_RE.match(line)
            if not match:
                continue
            value = match.group(1).strip().strip("'\"")
            if not value or not looks_like_secret(value):
                continue
            signals.append(make_signal(rule_id="nhi_cloud_key_detected", file_path=path, line_number=number, name=f"aws_secret_access_key [{section or 'default'}]", identity_type="cloud IAM user", source="cloud credentials", evidence=f"aws_secret_access_key present in profile [{section or 'default'}]", secret_value=value, provider="aws", tags=["cloud", "plaintext_secret"], confidence="high"))
    if path.suffix.lower() == ".tfvars":
        for number, line in enumerate(text.splitlines(), 1):
            match = TFVARS_SECRET_RE.match(line)
            if not match:
                continue
            key, value = match.group(1), match.group(2)
            if is_placeholder_value(value) or not looks_like_secret(value):
                continue
            signals.append(make_signal(rule_id="nhi_hardcoded_secret", file_path=path, line_number=number, name=key, identity_type="automation script credential", source="terraform tfvars", evidence=f'{key} = "{value}"', secret_value=value, tags=["terraform", "plaintext_secret", "hardcoded_secret"]))
    return signals
