"""Parser for .env-style files."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal

SECRET_KEYS = {
    "AWS_ACCESS_KEY_ID": ("cloud IAM user", "aws", "nhi_cloud_key_detected"),
    "AWS_SECRET_ACCESS_KEY": ("cloud IAM user", "aws", "nhi_cloud_key_detected"),
    "AZURE_CLIENT_SECRET": ("service account", "azure", "nhi_cloud_key_detected"),
    "GOOGLE_APPLICATION_CREDENTIALS": ("service account", "google cloud", "nhi_service_account_key_file"),
    "GITHUB_TOKEN": ("GitHub token", "github", "nhi_github_token_detected"),
    "GH_TOKEN": ("GitHub token", "github", "nhi_github_token_detected"),
    "OPENAI_API_KEY": ("API key", "openai", "nhi_ai_provider_key_detected"),
    "ANTHROPIC_API_KEY": ("API key", "anthropic", "nhi_ai_provider_key_detected"),
    "STRIPE_SECRET_KEY": ("API key", "stripe", "nhi_payment_key_detected"),
    "SENDGRID_API_KEY": ("API key", "sendgrid", "nhi_secret_leakage"),
    "SLACK_BOT_TOKEN": ("service account", "slack", "nhi_secret_leakage"),
    "DATABASE_URL": ("database connection identity", "database", "nhi_database_url_with_credentials"),
    "JWT_SECRET": ("automation script credential", None, "nhi_plaintext_env_secret"),
    "WEBHOOK_SECRET": ("webhook secret", None, "nhi_webhook_secret_exposed"),
    "API_KEY": ("API key", None, "nhi_plaintext_env_secret"),
    "CLIENT_SECRET": ("OAuth application", None, "nhi_oauth_client_secret_present"),
    "PRIVATE_KEY": ("service account", None, "nhi_private_key_detected"),
}


def should_parse(path: Path) -> bool:
    return path.name.startswith(".env") or path.suffix.lower() in {".env"}


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip().upper()
        value = value.strip().strip("'\"")
        if key not in SECRET_KEYS:
            continue
        identity_type, provider, rule_id = SECRET_KEYS[key]
        if key == "DATABASE_URL" and not re.search(r"://[^:\s/]+:[^@\s/]+@", value):
            continue
        if key != "DATABASE_URL" and value and not looks_like_secret(value) and "PRIVATE KEY" not in value:
            continue
        signals.append(
            make_signal(
                rule_id=rule_id,
                file_path=path,
                line_number=number,
                name=key,
                identity_type=identity_type,
                source="env file",
                provider=provider,
                evidence=f"{key}={value}",
                secret_value=value,
                production_access="PROD" in key or "production" in value.lower(),
                data_access_level="customer" if key == "DATABASE_URL" else "unknown",
                tags=["plaintext_secret", "env_secret"],
            )
        )
    if "-----BEGIN" in text and "PRIVATE KEY-----" in text:
        signals.append(
            make_signal(
                rule_id="nhi_private_key_detected",
                file_path=path,
                line_number=next((i for i, l in enumerate(text.splitlines(), 1) if "BEGIN" in l), None),
                name="PRIVATE_KEY_BLOCK",
                identity_type="service account",
                source="env file",
                evidence="Private key block detected",
                secret_value="PRIVATE_KEY_BLOCK",
                tags=["private_key", "plaintext_secret"],
            )
        )
    return signals
