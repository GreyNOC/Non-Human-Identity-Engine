"""Webhook URL and secret parser."""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import line_number_at_offset

WEBHOOK_RE = re.compile(r"https://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks|hooks\.zapier\.com|hook\.make\.com|api\.stripe\.com|[^\s\"']*webhook[^\s\"']*)/[^\s\"']+", re.I)
SIGNATURE_PROTECTION_RE = re.compile(r"(signing[_-]?secret|signature|hmac|replay|timestamp|nonce|webhook[_-]?secret|whsec_)", re.I)
SECRET_LINE_RE = re.compile(r"(github|stripe).*webhook.*secret|webhook_secret|whsec_", re.I)
SECRET_KV_RE = re.compile(r"(?:webhook|signing)[_-]?secret[\"']?\s*[:=]\s*[\"']?([^\"'\s,}]+)", re.I)
WHSEC_TOKEN_RE = re.compile(r"\bwhsec_[A-Za-z0-9]{16,}\b")

# Hosts that ingest webhooks; a URL on one of these hosts IS the credential,
# so those matches are reported unconditionally. Generic 'webhook' URLs are
# only reported when the final path segment is credential-shaped, which keeps
# documentation links (e.g. api.slack.com/messaging/webhooks/...) silent.
PROVIDER_HOSTS = {
    "hooks.slack.com": "slack",
    "discord.com": "discord",
    "discordapp.com": "discord",
    "hooks.zapier.com": "zapier",
    "hook.make.com": "make",
    "api.stripe.com": None,
}

def should_parse(path: Path) -> bool:
    return path.suffix.lower() in {".json", ".yaml", ".yml", ".env", ".txt", ".py", ".js", ".ts", ".toml", ".ini", ".cfg", ".conf", ".sh", ".bash", ".zsh", ".ps1"}

def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    has_signature_protection = bool(SIGNATURE_PROTECTION_RE.search(text))
    for match in WEBHOOK_RE.finditer(text):
        url = match.group(0)
        host = url[len("https://"):].split("/", 1)[0].lower()
        provider = PROVIDER_HOSTS.get(host)
        if host not in PROVIDER_HOSTS:
            last_segment = url.rstrip("/").rsplit("/", 1)[-1]
            if not looks_like_secret(last_segment):
                continue
        signals.append(make_signal(rule_id="nhi_webhook_secret_exposed", file_path=path, line_number=line_number_at_offset(text, match.start()), name="Webhook URL", identity_type="webhook_identity", source="webhook parser", evidence=url, secret_value=url, provider=provider, external_access=True, tags=["webhook", "plaintext_secret"], confidence="high" if provider else "medium"))
        if not has_signature_protection:
            signals.append(make_signal(rule_id="nhi_webhook_missing_signature_protection", file_path=path, line_number=line_number_at_offset(text, match.start()), name="Webhook without signature protection", identity_type="webhook_identity", source="webhook parser", evidence="Webhook URL found without signing secret, HMAC, timestamp, or replay protection evidence", provider=provider, external_access=True, tags=["webhook", "missing_signature"], confidence="medium"))
    lower = text.lower()
    if "webhook" in lower or "whsec_" in lower:
        for number, line in enumerate(text.splitlines(), 1):
            if not SECRET_LINE_RE.search(line):
                continue
            secret_value = None
            kv_match = SECRET_KV_RE.search(line)
            if kv_match and looks_like_secret(kv_match.group(1)):
                secret_value = kv_match.group(1)
            if secret_value is None:
                token_match = WHSEC_TOKEN_RE.search(line)
                if token_match:
                    secret_value = token_match.group(0)
            if secret_value is None:
                continue
            signals.append(make_signal(rule_id="nhi_webhook_secret_exposed", file_path=path, line_number=number, name="Webhook secret", identity_type="webhook_identity", source="webhook parser", evidence=line.strip(), secret_value=secret_value, tags=["webhook", "plaintext_secret"]))
    return signals
