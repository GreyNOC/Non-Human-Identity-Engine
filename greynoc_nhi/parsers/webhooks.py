"""Webhook URL and secret parser."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import line_number_at_offset

WEBHOOK_RE = re.compile(r"https://(?:hooks\.slack\.com/services|discord(?:app)?\.com/api/webhooks|hooks\.zapier\.com|hook\.make\.com|api\.stripe\.com|[^\s\"']*webhook[^\s\"']*)/[^\s\"']+", re.I)


def should_parse(path: Path) -> bool:
    return path.suffix.lower() in {".json", ".yaml", ".yml", ".env", ".txt", ".py", ".js", ".ts", ".toml", ".ini", ".cfg", ".conf"}


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    for match in WEBHOOK_RE.finditer(text):
        url = match.group(0)
        provider = "slack" if "slack" in url else "discord" if "discord" in url else "zapier" if "zapier" in url else "make" if "make.com" in url else None
        signals.append(make_signal(rule_id="nhi_webhook_secret_exposed", file_path=path, line_number=line_number_at_offset(text, match.start()), name="Webhook URL", identity_type="webhook secret", source="webhook parser", evidence=url, secret_value=url, provider=provider, external_access=True, tags=["webhook", "plaintext_secret"], confidence="high" if provider else "medium"))
    for number, line in enumerate(text.splitlines(), 1):
        if re.search(r"(github|stripe).*webhook.*secret|webhook_secret|whsec_", line, re.I):
            signals.append(make_signal(rule_id="nhi_webhook_secret_exposed", file_path=path, line_number=number, name="Webhook secret", identity_type="webhook secret", source="webhook parser", evidence=line.strip(), tags=["webhook", "plaintext_secret"]))
    return signals
