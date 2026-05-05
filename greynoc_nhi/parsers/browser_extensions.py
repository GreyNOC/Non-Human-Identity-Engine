"""Browser extension manifest parser."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import parse_json_safely

RISKY_PERMISSIONS = {"tabs", "cookies", "webRequest", "webRequestBlocking", "debugger", "nativeMessaging", "scripting", "downloads", "history", "proxy", "<all_urls>"}


def should_parse(path: Path) -> bool:
    return path.name.lower() in {"manifest.json", "browser_extension_manifest.json"}


def parse(path: Path, text: str) -> list[Signal]:
    data = parse_json_safely(text)
    if not isinstance(data, dict):
        return []
    values = []
    for key in ["permissions", "host_permissions", "optional_permissions"]:
        value = data.get(key, [])
        if isinstance(value, list):
            values.extend(str(item) for item in value)
    risky = sorted({item for item in values if item in RISKY_PERMISSIONS or item == "<all_urls>" or "*://" in item})
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
    if has_background and any(item == "<all_urls>" or "*://" in item for item in risky):
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
