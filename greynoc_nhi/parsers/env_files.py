"""Parser for .env-style files."""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.confidence import is_placeholder_value
from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal

SECRET_KEYS = {
    "AWS_ACCESS_KEY_ID": ("cloud IAM user", "aws", "nhi_cloud_key_detected"),
    "AWS_SECRET_ACCESS_KEY": ("cloud IAM user", "aws", "nhi_cloud_key_detected"),
    "AWS_SESSION_TOKEN": ("cloud IAM user", "aws", "nhi_cloud_key_detected"),
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
    "DEEPSEEK_API_KEY": ("API key", "deepseek", "nhi_ai_provider_key_detected"),
    "XAI_API_KEY": ("API key", "xai", "nhi_ai_provider_key_detected"),
    "FIREWORKS_API_KEY": ("API key", "fireworks", "nhi_ai_provider_key_detected"),
    "CEREBRAS_API_KEY": ("API key", "cerebras", "nhi_ai_provider_key_detected"),
    "STRIPE_SECRET_KEY": ("API key", "stripe", "nhi_payment_key_detected"),
    "SENDGRID_API_KEY": ("API key", "sendgrid", "nhi_secret_leakage"),
    "SLACK_BOT_TOKEN": ("bot_account", "slack", "nhi_secret_leakage"),
    "GITLAB_TOKEN": ("GitLab token", "gitlab", "nhi_secret_leakage"),
    "NPM_TOKEN": ("API key", "npm", "nhi_package_registry_token_detected"),
    "DOCKER_PASSWORD": ("automation script credential", "docker", "nhi_secret_leakage"),
    "POSTGRES_PASSWORD": ("database connection identity", "postgres", "nhi_plaintext_env_secret"),
    "TWILIO_AUTH_TOKEN": ("API key", "twilio", "nhi_secret_leakage"),
    "SUPABASE_SERVICE_ROLE_KEY": ("service account", "supabase", "nhi_secret_leakage"),
    "CLOUDFLARE_API_TOKEN": ("API key", "cloudflare", "nhi_cloud_key_detected"),
    "VERCEL_TOKEN": ("API key", "vercel", "nhi_deployment_platform_token_detected"),
    "DATABASE_URL": ("database connection identity", "database", "nhi_database_url_with_credentials"),
    "MONGODB_URI": ("database connection identity", "database", "nhi_database_url_with_credentials"),
    "REDIS_URL": ("database connection identity", "database", "nhi_database_url_with_credentials"),
    "SECRET_KEY": ("automation script credential", None, "nhi_plaintext_env_secret"),
    "JWT_SECRET": ("automation script credential", None, "nhi_plaintext_env_secret"),
    "WEBHOOK_SECRET": ("webhook secret", None, "nhi_webhook_secret_exposed"),
    "API_KEY": ("API key", None, "nhi_plaintext_env_secret"),
    "CLIENT_SECRET": ("OAuth application", None, "nhi_oauth_client_secret_present"),
    "PRIVATE_KEY": ("service account", None, "nhi_private_key_detected"),
}

# Keys whose value is a connection URL; they only matter when userinfo
# credentials are embedded (scheme://user:password@host).
URL_CREDENTIAL_KEYS = {"DATABASE_URL", "MONGODB_URI", "REDIS_URL"}

_URL_CRED_RE = re.compile(r"\b[a-z][a-z0-9+.\-]{1,20}://([^:\s/@]{0,64}):([^@\s/]{1,256})@", re.IGNORECASE)
_SUFFIX_SECRET_KEY_RE = re.compile(r"(?:^|_)(?:API_KEY|APIKEY|SECRET|SECRET_KEY|TOKEN|PASSWORD|PASSWD|ACCESS_KEY|AUTH_TOKEN)$")
_CONNECTION_KEY_RE = re.compile(r"(?:^|_)(?:URL|URI|DSN)$")
_TEMPLATE_MARKERS = ("example", "sample", "template", ".dist")

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
    "DEEPSEEK_API_KEY",
    "XAI_API_KEY",
    "FIREWORKS_API_KEY",
    "CEREBRAS_API_KEY",
}

def should_parse(path: Path) -> bool:
    return path.name.startswith(".env") or path.suffix.lower() in {".env"}

def _fallback_signal(path: Path, number: int, key: str, value: str, confidence: str | None) -> Signal | None:
    """Catch secret-shaped keys and credentialed URLs outside the exact allowlist."""
    if not value:
        return None
    if _CONNECTION_KEY_RE.search(key):
        match = _URL_CRED_RE.search(value)
        if match:
            password = match.group(2)
            if looks_like_secret(password) and not is_placeholder_value(password):
                return make_signal(
                    rule_id="nhi_database_url_with_credentials",
                    file_path=path,
                    line_number=number,
                    name=key,
                    identity_type="database connection identity",
                    source="env file",
                    provider="database",
                    evidence=f"{key}={value}",
                    secret_value=value,
                    data_access_level="customer",
                    tags=["plaintext_secret", "env_secret"],
                    confidence=confidence,
                )
        return None
    if _SUFFIX_SECRET_KEY_RE.search(key) and looks_like_secret(value):
        return make_signal(
            rule_id="nhi_plaintext_env_secret",
            file_path=path,
            line_number=number,
            name=key,
            identity_type="automation script credential",
            source="env file",
            evidence=f"{key}={value}",
            secret_value=value,
            tags=["plaintext_secret", "env_secret"],
            confidence=confidence,
        )
    return None

def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    lines = text.splitlines()
    is_template = any(marker in path.name.lower() for marker in _TEMPLATE_MARKERS)
    template_confidence = "low" if is_template else None
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        key = key.strip()
        if key.lower().startswith("export "):
            key = key[7:].strip()
        key = key.upper()
        value = value.strip()
        if value[:1] not in {"'", '"'} and " #" in value:
            value = value.split(" #", 1)[0].rstrip()
        value = value.strip("'\"")
        if key not in SECRET_KEYS:
            fallback = _fallback_signal(path, number, key, value, template_confidence)
            if fallback is not None:
                signals.append(fallback)
            continue
        identity_type, provider, rule_id = SECRET_KEYS[key]
        if key in URL_CREDENTIAL_KEYS and not _URL_CRED_RE.search(value):
            continue
        if key not in URL_CREDENTIAL_KEYS and value and not looks_like_secret(value) and "PRIVATE KEY" not in value:
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
                data_access_level="customer" if key in URL_CREDENTIAL_KEYS else "unknown",
                data_classes=data_classes,
                environment="production" if production else None,
                tags=["plaintext_secret", "env_secret", "ai_provider"] if key in AI_PROVIDER_KEYS else ["plaintext_secret", "env_secret"],
                confidence=template_confidence,
            )
        )
        if key in AI_PROVIDER_KEYS and production and not is_template and not is_placeholder_value(value) and "GNOC_FAKE_SECRET_DO_NOT_USE" not in value:
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
                line_number=next((i for i, l in enumerate(lines, 1) if "BEGIN" in l), None),
                name="PRIVATE_KEY_BLOCK",
                identity_type="service account",
                source="env file",
                evidence="Private key block detected",
                secret_value="PRIVATE_KEY_BLOCK",
                tags=["private_key", "plaintext_secret"],
                confidence=template_confidence,
            )
        )
    return signals
