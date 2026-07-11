"""package.json parser for script risks."""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import parse_json_safely

SECRET_ASSIGNMENT_RE = re.compile(r"(?i)(token|secret|password|api[_-]?key)\s*=\s*([^\s\"'&;]+)")
CURL_PIPE_SH_RE = re.compile(r"(?i)\b(?:curl|wget)\b[^|]*\|\s*(?:ba|z|k)?sh\b")

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
        secret_value: str | None = None
        assignment = SECRET_ASSIGNMENT_RE.search(command_s)
        if assignment:
            candidate = assignment.group(2).strip().strip("'\"")
            if candidate and not candidate.startswith("$") and looks_like_secret(candidate):
                secret_value = candidate
        if "deploy" in name.lower() or "deploy" in lower:
            if secret_value:
                signals.append(make_signal(rule_id="nhi_environment_isolation_failure", file_path=path, line_number=None, name=f"npm script {name}", identity_type="deployment token", source="package.json", evidence=f"{name}: {command_s}", production_access=True, tags=["package", "deployment"]))
            else:
                signals.append(make_signal(rule_id="nhi_environment_isolation_failure", file_path=path, line_number=None, name=f"npm script {name}", identity_type="deployment token", source="package.json", evidence=f"{name}: {command_s}", production_access=False, tags=["package", "deployment"], confidence="low"))
        if secret_value:
            signals.append(make_signal(rule_id="nhi_hardcoded_secret", file_path=path, line_number=None, name=f"npm script {name}", identity_type="automation script credential", source="package.json", evidence=f"{name}: {command_s}", secret_value=secret_value, tags=["package", "plaintext_secret"]))
        if CURL_PIPE_SH_RE.search(command_s):
            signals.append(make_signal(rule_id="nhi_npm_script_remote_execution", file_path=path, line_number=None, name=f"npm script {name}", identity_type="automation script credential", source="package.json", evidence=f"{name}: {command_s}", external_access=True, tags=["package", "remote_script"]))
    return signals
