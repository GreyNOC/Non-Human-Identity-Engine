"""AI agent configuration parser."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, parse_json_safely, simple_yaml_pairs

RISKY_TOOLS = {
    "execute_command",
    "run_shell",
    "shell",
    "write_file",
    "read_file",
    "send_email",
    "github",
    "browser",
    "cloud",
    "database",
    "payment",
    "deploy",
    "delete_resource",
}


def should_parse(path: Path) -> bool:
    return path.suffix.lower() in {".json", ".yaml", ".yml"} and any(token in path.name.lower() for token in ["agent", "ai_agent", "tools"])


def parse(path: Path, text: str) -> list[Signal]:
    data = parse_json_safely(text)
    rows = flatten_json(data) if data is not None else [(k, v) for k, v, _ in simple_yaml_pairs(text)]
    tool_values: set[str] = set()
    approval_required: bool | None = None
    memory_sensitive = False
    production = False
    for key, value in rows:
        key_l = key.lower()
        value_l = str(value).lower()
        if "tool" in key_l or "capabilit" in key_l:
            for tool in RISKY_TOOLS:
                if tool in value_l:
                    tool_values.add(tool)
        if "approval_required" in key_l:
            approval_required = value_l == "true"
        if "memory" in key_l and any(word in value_l for word in ["sensitive", "secret", "customer", "true"]):
            memory_sensitive = True
        if "production" in key_l or value_l == "production":
            production = True
    signals: list[Signal] = []
    if tool_values and approval_required is False:
        rule = "nhi_ai_agent_shell_access" if any(t in tool_values for t in ["execute_command", "run_shell", "shell"]) else "nhi_ai_agent_unapproved_tool_access"
        signals.append(make_signal(rule_id=rule, file_path=path, line_number=None, name=path.stem, identity_type="AI agent tool connector", source="AI agent config", evidence=f"Approval gate disabled for tools: {', '.join(sorted(tool_values))}", tools=sorted(tool_values), admin_access=any(t in tool_values for t in ["execute_command", "run_shell", "shell", "delete_resource"]), production_access=production, external_access=True, approval_required=False, data_access_level="customer" if any(t in tool_values for t in ["email", "database", "payment"]) else "unknown", tags=["ai_agent", "unapproved_tools"]))
    if memory_sensitive:
        signals.append(make_signal(rule_id="nhi_ai_agent_sensitive_data_access", file_path=path, line_number=None, name=path.stem, identity_type="AI agent tool connector", source="AI agent config", evidence="Agent memory or context is enabled for sensitive data", tools=sorted(tool_values), production_access=production, approval_required=approval_required, data_access_level="customer", tags=["ai_agent", "sensitive_data"]))
    return signals
