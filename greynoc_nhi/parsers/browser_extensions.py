"""Browser extension manifest parser."""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import parse_json_safely

RISKY_PERMISSIONS = {"tabs", "cookies", "webRequest", "webRequestBlocking", "debugger", "nativeMessaging", "scripting", "downloads", "history", "proxy", "<all_urls>"}

# Matches scheme-wildcard host patterns; group(1) distinguishes an any-host
# wildcard ("*") from a subdomain wildcard ("*.").
_WILDCARD_HOST_RE = re.compile(r"^(?:\*|https?|wss?)://(\*\.|\*)")


def _is_wildcard_host(item: str) -> bool:
    """Any wildcard host pattern, including subdomain wildcards."""
    return item == "<all_urls>" or bool(_WILDCARD_HOST_RE.match(item))


def _is_broad_host(item: str) -> bool:
    """Only patterns whose host part is exactly '*' (or <all_urls>)."""
    if item == "<all_urls>":
        return True
    match = _WILDCARD_HOST_RE.match(item)
    return bool(match and match.group(1) == "*")


def should_parse(path: Path) -> bool:
    return path.name.lower() in {"manifest.json", "browser_extension_manifest.json"}

def parse(path: Path, text: str) -> list[Signal]:
    data = parse_json_safely(text)
    if not isinstance(data, dict):
        return []
    values = []
    for key in ["permissions", "host_permissions", "optional_permissions", "optional_host_permissions"]:
        value = data.get(key, [])
        if isinstance(value, list):
            values.extend(str(item) for item in value)
    risky = sorted({item for item in values if item in RISKY_PERMISSIONS or _is_wildcard_host(item) or "*://" in item})
    if not risky:
        return []
    signals = [
        make_signal(
            rule_id="nhi_browser_extension_risky_permissions",
            file_path=path,
            line_number=None,
            name=str(data.get("name", "Browser extension")),
            identity_type="browser_extension",
            source="browser extension manifest",
            evidence=f"Risky browser extension permissions: {', '.join(risky)}",
            permissions=risky,
            external_access=True,
            data_access_level="session",
            tags=["browser_extension", "broad_permissions"],
        )
    ]
    background = data.get("background")
    has_background = isinstance(background, dict) and bool(background.get("service_worker") or background.get("scripts"))
    if has_background and any(_is_broad_host(item) for item in risky):
        signals.append(
            make_signal(
                rule_id="nhi_browser_extension_broad_host_background",
                file_path=path,
                line_number=None,
                name=str(data.get("name", "Browser extension")),
                identity_type="browser_extension",
                source="browser extension manifest",
                evidence="Browser extension has broad host permissions and background execution",
                permissions=risky,
                external_access=True,
                data_access_level="session",
                tags=["browser_extension", "broad_permissions", "background_script"],
                confidence="high",
            )
        )
    return signals
