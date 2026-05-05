"""Modern SaaS, registry, and framework token parser."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal

TEXT_EXTENSIONS = {".env", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rb", ".php", ".java", ".cs", ".tf"}

PATTERNS: list[tuple[str, str, str, str, str, str]] = [
    ("nhi_package_registry_token_detected", "NPM_TOKEN", r"\bnpm_[A-Za-z0-9]{10,}\b", "package registry token", "npm", "package registry"),
    ("nhi_package_registry_token_detected", "PYPI_TOKEN", r"\bpypi-[A-Za-z0-9_\-]{20,}\b", "package registry token", "pypi", "package registry"),
    ("nhi_deployment_platform_token_detected", "VERCEL_TOKEN", r"\bvercel_[A-Za-z0-9_\-]{16,}\b|\bVERCEL_TOKEN\s*[:=]\s*['\"]?([^'\"\s,}]+)", "deployment token", "vercel", "deployment platform"),
    ("nhi_deployment_platform_token_detected", "NETLIFY_TOKEN", r"\bNETLIFY_AUTH_TOKEN\s*[:=]\s*['\"]?([^'\"\s,}]+)", "deployment token", "netlify", "deployment platform"),
    ("nhi_ai_provider_key_detected", "HUGGINGFACE_TOKEN", r"\bhf_[A-Za-z0-9]{20,}\b", "API key", "hugging face", "AI provider"),
    ("nhi_ai_provider_key_detected", "OPENAI_PROJECT_KEY", r"\bsk-proj-[A-Za-z0-9_\-]{16,}\b", "API key", "openai", "AI provider"),
    ("nhi_secret_leakage", "PULUMI_ACCESS_TOKEN", r"\bpul-[A-Za-z0-9]{20,}\b", "cloud automation token", "pulumi", "IaC platform"),
    ("nhi_monitoring_dsn_exposed", "SENTRY_DSN", r"https://[A-Za-z0-9]+@[A-Za-z0-9_.-]+\.ingest\.sentry\.io/[0-9]+", "third-party SaaS integration", "sentry", "monitoring"),
    ("nhi_github_token_detected", "GITHUB_FINE_GRAINED_TOKEN", r"\bgithub_pat_[A-Za-z0-9_]{20,}\b", "GitHub token", "github", "source control"),
    ("nhi_secret_leakage", "SLACK_APP_TOKEN", r"\bxapp-[A-Za-z0-9\-]{20,}\b", "service account", "slack", "SaaS integration"),
    ("nhi_secret_leakage", "SLACK_USER_TOKEN", r"\bxoxp-[A-Za-z0-9\-]{20,}\b", "service account", "slack", "SaaS integration"),
    ("nhi_payment_key_detected", "STRIPE_RESTRICTED_KEY", r"\brk_live_[A-Za-z0-9]{16,}\b", "API key", "stripe", "payment"),
]


def should_parse(path: Path) -> bool:
    return path.name.startswith(".env") or path.suffix.lower() in TEXT_EXTENSIONS or path.name.lower() in {".npmrc", ".yarnrc", "config.json"}


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        for rule_id, name, pattern, identity_type, provider, source_name in PATTERNS:
            for match in re.finditer(pattern, line, re.I):
                value = next((group for group in match.groups() if group), match.group(0))
                if value and looks_like_secret(value):
                    signals.append(
                        make_signal(
                            rule_id=rule_id,
                            file_path=path,
                            line_number=number,
                            name=name,
                            identity_type=identity_type,
                            source=source_name,
                            evidence=line.strip(),
                            secret_value=value,
                            provider=provider,
                            external_access=True,
                            production_access="live" in value.lower() or "prod" in line.lower(),
                            tags=["plaintext_secret", "modern_saas"],
                        )
                    )
        bearer = re.search(r"\bAuthorization\s*[:=]\s*['\"]?Bearer\s+([A-Za-z0-9_\-.=]{16,})", line, re.I)
        if bearer and looks_like_secret(bearer.group(1)):
            signals.append(
                make_signal(
                    rule_id="nhi_bearer_token_detected",
                    file_path=path,
                    line_number=number,
                    name="Authorization Bearer token",
                    identity_type="API key",
                    source="HTTP authorization config",
                    evidence=line.strip(),
                    secret_value=bearer.group(1),
                    external_access=True,
                    tags=["plaintext_secret", "http_auth"],
                )
            )
        jwt = re.search(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", line)
        if jwt:
            signals.append(
                make_signal(
                    rule_id="nhi_jwt_detected",
                    file_path=path,
                    line_number=number,
                    name="JWT-like token",
                    identity_type="automation script credential",
                    source="JWT parser",
                    evidence=line.strip(),
                    secret_value=jwt.group(0),
                    external_access=True,
                    tags=["plaintext_secret", "jwt"],
                )
            )
        registry = re.search(r"(?i)(?:_authToken|auth)\s*[:=]\s*['\"]?([A-Za-z0-9_\-/+=]{16,})", line)
        if registry and looks_like_secret(registry.group(1)):
            signals.append(
                make_signal(
                    rule_id="nhi_encoded_registry_auth_detected",
                    file_path=path,
                    line_number=number,
                    name="Package registry auth",
                    identity_type="package registry token",
                    source="package registry config",
                    evidence=line.strip(),
                    secret_value=registry.group(1),
                    provider="package registry",
                    external_access=True,
                    tags=["plaintext_secret", "package_registry"],
                )
            )
    return signals
