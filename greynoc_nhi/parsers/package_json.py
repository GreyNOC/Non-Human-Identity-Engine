"""package.json parser for script risks."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import parse_json_safely


def should_parse(path: Path) -> bool:
    return path.name.lower() == "package.json"


def parse(path: Path, text: str) -> list[Signal]:
    data = parse_json_safely(text)
    if not isinstance(data, dict):
        return []
    signals: list[Signal] = []
    scripts = data.get("scripts", {})
    if not isinstance(scripts, dict):
        return []
    for name, command in scripts.items():
        command_s = str(command)
        lower = command_s.lower()
        if "deploy" in name.lower() or "deploy" in lower:
            signals.append(make_signal(rule_id="nhi_environment_isolation_failure", file_path=path, line_number=None, name=f"npm script {name}", identity_type="deployment token", source="package.json", evidence=f"{name}: {command_s}", production_access=True, tags=["package", "deployment"]))
        if any(k in lower for k in ["token=", "secret=", "api_key", "password=", "curl "]):
            signals.append(make_signal(rule_id="nhi_hardcoded_secret", file_path=path, line_number=None, name=f"npm script {name}", identity_type="automation script credential", source="package.json", evidence=f"{name}: {command_s}", tags=["package", "plaintext_secret"]))
    return signals
