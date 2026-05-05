"""Parser for .env-style files."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.confidence import is_placeholder_value
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
    "GEMINI_API_KEY": ("API key", "gemini", "nhi_ai_provider_key_detected"),
    "GOOGLE_API_KEY": ("API key", "google", "nhi_ai_provider_key_detected"),
    "AZURE_OPENAI_API_KEY": ("API key", "azure openai", "nhi_ai_provider_key_detected"),
    "HUGGINGFACEHUB_API_TOKEN": ("API key", "hugging face", "nhi_ai_provider_key_detected"),
    "REPLICATE_API_TOKEN": ("API key", "replicate", "nhi_ai_provider_key_detected"),
    "MISTRAL_API_KEY": ("API key", "mistral", "nhi_ai_provider_key_detected"),
    "COHERE_API_KEY": ("API key", "cohere", "nhi_ai_provider_key_detected"),
    "TOGETHER_API_KEY": ("API key", "together", "nhi_ai_provider_key_detected"),
    "GROQ_API_KEY": ("API key", "groq", "nhi_ai_provider_key_detected"),
    "PERPLEXITY_API_KEY": ("API key", "perplexity", "nhi_ai_provider_key_detected"),
    "OPENROUTER_API_KEY": ("API key", "openrouter", "nhi_ai_provider_key_detected"),
    "STRIPE_SECRET_KEY": ("API key", "stripe", "nhi_payment_key_detected"),
    "SENDGRID_API_KEY": ("API key", "sendgrid", "nhi_secret_leakage"),
    "SLACK_BOT_TOKEN": ("bot_account", "slack", "nhi_secret_leakage"),
    "DATABASE_URL": ("database connection identity", "database", "nhi_database_url_with_credentials"),
    "JWT_SECRET": ("automation script credential", None, "nhi_plaintext_env_secret"),
    "WEBHOOK_SECRET": ("webhook secret", None, "nhi_webhook_secret_exposed"),
    "API_KEY": ("API key", None, "nhi_plaintext_env_secret"),
    "CLIENT_SECRET": ("OAuth application", None, "nhi_oauth_client_secret_present"),
    "PRIVATE_KEY": ("service account", None, "nhi_private_key_detected"),
}

AI_PROVIDER_KEYS = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_OPENAI_API_KEY",
    "HUGGINGFACEHUB_API_TOKEN",
    "REPLICATE_API_TOKEN",
    "MISTRAL_API_KEY",
    "COHERE_API_KEY",
    "TOGETHER_API_KEY",
    "GROQ_API_KEY",
    "PERPLEXITY_API_KEY",
    "OPENROUTER_API_KEY",
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
        production = "PROD" in key or "production" in value.lower() or "prod" in value.lower() or "production" in path.name.lower() or ".prod" in path.name.lower()
        data_classes = ["ai_prompts"] if key in AI_PROVIDER_KEYS else []
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
                production_access=production,
                data_access_level="customer" if key == "DATABASE_URL" else "unknown",
                data_classes=data_classes,
                environment="production" if production else None,
                tags=["plaintext_secret", "env_secret", "ai_provider"] if key in AI_PROVIDER_KEYS else ["plaintext_secret", "env_secret"],
            )
        )
        if key in AI_PROVIDER_KEYS and production and not is_placeholder_value(value) and "GNOC_FAKE_SECRET_DO_NOT_USE" not in value:
            signals.append(
                make_signal(
                    rule_id="nhi_production_ai_key_in_env",
                    file_path=path,
                    line_number=number,
                    name=key,
                    identity_type=identity_type,
                    source="env file",
                    provider=provider,
                    evidence=f"{key}={value}",
                    secret_value=value,
                    production_access=True,
                    data_classes=data_classes,
                    environment="production",
                    tags=["plaintext_secret", "env_secret", "ai_provider", "production"],
                    confidence="high",
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
