"""Helm chart `values.yaml` parser.

values.yaml files are a graveyard of plaintext API keys, database passwords,
and registry credentials. This parser detects secret-named YAML keys with
plaintext literal values and flags them.
"""

from __future__ import annotations

__version__ = 1

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal

VALUES_FILE_RE = re.compile(r"^(values|values-[\w.-]+)\.ya?ml$|.*\.values\.ya?ml$", re.IGNORECASE)
SECRET_KEY_HINT_RE = re.compile(
    r"(secret|password|passwd|api[_-]?key|token|client[_-]?secret|private[_-]?key|webhook|credentials?|registry[_-]?(?:password|auth|key))",
    re.IGNORECASE,
)
KEY_VALUE_RE = re.compile(
    r"^(\s*)([A-Za-z_][\w-]*)\s*:\s*(?:['\"]?)([^#\n]*?)(?:['\"]?)\s*(?:#.*)?$"
)


def should_parse(path: Path) -> bool:
    name = path.name.lower()
    if VALUES_FILE_RE.match(name):
        return True
    normalized = str(path).replace("\\", "/").lower()
    if "/charts/" in normalized and name.endswith((".yaml", ".yml")) and "values" in name:
        return True
    return False


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    seen: set[tuple[str, int]] = set()
    for number, line in enumerate(text.splitlines(), 1):
        match = KEY_VALUE_RE.match(line)
        if not match:
            continue
        key = match.group(2)
        value = match.group(3).strip()
        if not value or value in {"~", "null", "{}", "[]"}:
            continue
        if value.startswith("$") or value.startswith("{{") or value.startswith("ref:"):
            continue
        if not SECRET_KEY_HINT_RE.search(key):
            continue
        if not looks_like_secret(value) and "PRIVATE KEY" not in value:
            continue
        dedupe_key = (key, number)
        if dedupe_key in seen:
            continue
        seen.add(dedupe_key)
        production = "prod" in str(path).lower() or "production" in str(path).lower()
        signals.append(
            make_signal(
                rule_id="nhi_helm_values_plaintext_secret",
                file_path=path,
                line_number=number,
                name=key,
                identity_type="api_key",
                source="helm values",
                evidence=line.strip(),
                secret_value=value,
                provider="helm",
                production_access=production,
                environment="production" if production else None,
                tags=["helm", "values_yaml", "plaintext_secret"],
            )
        )
    if "imagePullSecrets" in text and "dockerconfigjson" in text and re.search(r":\s*[A-Za-z0-9+/=]{20,}", text):
        first_line = next(
            (n for n, l in enumerate(text.splitlines(), 1) if "dockerconfigjson" in l),
            None,
        )
        signals.append(
            make_signal(
                rule_id="nhi_helm_values_image_pull_secret_inline",
                file_path=path,
                line_number=first_line,
                name="Inline image pull secret",
                identity_type="api_key",
                source="helm values",
                evidence="values.yaml inlines a base64 dockerconfigjson",
                provider="helm",
                tags=["helm", "values_yaml", "registry_credentials"],
                confidence="high",
            )
        )
    return signals
