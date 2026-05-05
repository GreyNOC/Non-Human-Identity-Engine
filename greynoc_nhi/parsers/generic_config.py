"""Generic config parser for common secret-bearing key names."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.confidence import infer_confidence, should_suppress_candidate
from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, line_number_for_key_value, parse_json_safely, simple_yaml_pairs

COMMON_KEYS = {
    "api_key",
    "apikey",
    "secret",
    "token",
    "password",
    "private_key",
    "client_secret",
    "access_key",
    "refresh_token",
    "signing_key",
    "webhook_secret",
}

AI_PROVIDER_KEY_NAMES = {
    "openai_api_key": "openai",
    "anthropic_api_key": "anthropic",
    "gemini_api_key": "gemini",
    "google_api_key": "google",
    "azure_openai_api_key": "azure openai",
    "huggingfacehub_api_token": "hugging face",
    "replicate_api_token": "replicate",
    "mistral_api_key": "mistral",
    "cohere_api_key": "cohere",
    "together_api_key": "together",
    "groq_api_key": "groq",
    "perplexity_api_key": "perplexity",
    "openrouter_api_key": "openrouter",
}


def should_parse(path: Path) -> bool:
    return path.suffix.lower() in {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".py", ".js", ".ts"}


def _rule_for(key: str, value: str) -> str:
    lower = key.lower()
    if lower in AI_PROVIDER_KEY_NAMES:
        return "nhi_ai_provider_key_detected"
    if "private_key" in lower or "private key" in value.lower():
        return "nhi_private_key_detected"
    if "client_secret" in lower:
        return "nhi_oauth_client_secret_present"
    if "webhook" in lower:
        return "nhi_webhook_secret_exposed"
    if "password" in lower and "://" in value:
        return "nhi_database_url_with_credentials"
    return "nhi_hardcoded_secret"


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    rows: list[tuple[str, object, int | None]] = []
    data = parse_json_safely(text) if path.suffix.lower() == ".json" else None
    if data is not None:
        for key, value in flatten_json(data):
            rows.append((key, value, None))
    elif path.suffix.lower() in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}:
        rows.extend((key, value, line) for key, value, line in simple_yaml_pairs(text))
    else:
        for number, line in enumerate(text.splitlines(), 1):
            match = re.search(r"([A-Za-z0-9_.-]*(?:api_key|apikey|secret|token|password|private_key|client_secret|access_key|refresh_token|signing_key|webhook_secret)[A-Za-z0-9_.-]*)\s*[:=]\s*['\"]([^'\"]+)['\"]", line, re.I)
            if match:
                rows.append((match.group(1), match.group(2), number))
    for key, value, line in rows:
        key_tail = str(key).split(".")[-1].lower()
        normalized = key_tail.replace("-", "_")
        if normalized not in COMMON_KEYS and normalized not in AI_PROVIDER_KEY_NAMES and not any(part in normalized for part in COMMON_KEYS):
            continue
        value_s = str(value)
        if should_suppress_candidate(normalized, value_s):
            continue
        if not looks_like_secret(value_s) and "-----BEGIN" not in value_s and "://" not in value_s:
            continue
        resolved_line = line or line_number_for_key_value(text, str(key), value_s)
        signals.append(
            make_signal(
                rule_id=_rule_for(normalized, value_s),
                file_path=path,
                line_number=resolved_line,
                name=str(key),
                identity_type="api_key" if "key" in normalized or normalized in AI_PROVIDER_KEY_NAMES else "automation script credential",
                source="generic config",
                provider=AI_PROVIDER_KEY_NAMES.get(normalized),
                evidence=f"{key}: {value_s}",
                secret_value=value_s,
                data_classes=["ai_prompts"] if normalized in AI_PROVIDER_KEY_NAMES else [],
                tags=["plaintext_secret", "hardcoded_secret", "ai_provider"] if normalized in AI_PROVIDER_KEY_NAMES else ["plaintext_secret", "hardcoded_secret"],
                confidence=infer_confidence(_rule_for(normalized, value_s), secret_value=value_s),
            )
        )
    return signals
