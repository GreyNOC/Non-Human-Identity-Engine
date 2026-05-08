"""MCP configuration parser."""

from __future__ import annotations

__version__ = 1

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, line_number_for, line_number_for_key_value, parse_json_safely

MCP_NAMES = {
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "cursor_mcp.json",
}

MCP_TOOL_CAPABILITIES = {
    "filesystem",
    "shell",
    "terminal",
    "browser",
    "email",
    "slack",
    "github",
    "gdrive",
    "database",
    "postgres",
    "mysql",
    "sqlite",
    "kubernetes",
    "docker",
    "terraform",
    "aws",
    "azure",
    "gcp",
    "jira",
    "notion",
    "calendar",
}

EXECUTING_COMMANDS = {"python", "node", "npx", "uvx", "docker", "bash", "sh", "powershell", "cmd.exe"}
HIGH_RISK_TOOLS = {"shell", "terminal", "filesystem", "browser", "email", "gdrive", "github", "database", "docker", "kubernetes", "terraform", "aws", "azure", "gcp"}

def should_parse(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    return (
        path.name.lower() in MCP_NAMES
        or normalized.endswith("/.cursor/mcp.json")
        or normalized.endswith("/.vscode/mcp.json")
        or normalized.endswith("/claude/claude_desktop_config.json")
        or normalized.endswith("/.continue/mcp.json")
        or normalized.endswith("/.windsurf/mcp.json")
    )

def _capabilities(text: str) -> set[str]:
    lowered = text.lower()
    tools = set()
    for tool in MCP_TOOL_CAPABILITIES:
        if re.search(rf"(?<![a-z0-9_-]){re.escape(tool)}(?![a-z0-9_-])", lowered):
            tools.add("database" if tool in {"postgres", "mysql", "sqlite"} else tool)
    if "google drive" in lowered:
        tools.add("gdrive")
    if "command" in lowered:
        tools.add("shell")
    return tools

def _executing_commands(rows: list[tuple[str, object]]) -> set[str]:
    commands = set()
    for key, value in rows:
        if not any(marker in key.lower() for marker in ["command", "args", "cmd"]):
            continue
        for token in re.split(r"[\s/\\\"']+", str(value).lower()):
            if token in EXECUTING_COMMANDS:
                commands.add(token)
    return commands

def parse(path: Path, text: str) -> list[Signal]:
    data = parse_json_safely(text)
    rows = flatten_json(data) if data is not None else []
    haystack = " ".join(f"{k}={v}" for k, v in rows).lower() or text.lower()
    signals: list[Signal] = []
    tools = sorted(_capabilities(haystack))
    commands = sorted(_executing_commands(rows))
    has_mcp_servers = "mcpservers" in haystack or "mcp_servers" in haystack or path.name.lower() in MCP_NAMES

    if "filesystem" in tools and any(broad in haystack for broad in ["${workspacefolder}", "$home", "~", "c:\\users", "/users", "/home", ".", "/"]):
        signals.append(
            make_signal(
                rule_id="nhi_mcp_filesystem_broad_access",
                file_path=path,
                line_number=line_number_for(text, "filesystem"),
                name="MCP filesystem server",
                identity_type="mcp_server",
                source="MCP config",
                evidence="MCP filesystem server has broad path access",
                tools=["filesystem"],
                admin_access=True,
                data_access_level="source-code",
                tags=["mcp", "filesystem"],
                confidence="high",
            )
        )
    if has_mcp_servers and (set(tools) & HIGH_RISK_TOOLS or commands):
        exposed = sorted(set(tools) | {"shell" for _ in commands})
        signals.append(
            make_signal(
                rule_id="nhi_mcp_server_high_risk_tool_access",
                file_path=path,
                line_number=line_number_for(text, "mcpServers") or line_number_for(text, "command"),
                name="MCP high-risk server",
                identity_type="mcp_server",
                source="MCP config",
                evidence=f"MCP exposes high-risk tools or command runners: {', '.join(exposed)}",
                tools=exposed,
                admin_access=bool(commands or {"shell", "terminal", "docker", "kubernetes", "terraform", "aws", "azure", "gcp"} & set(exposed)),
                external_access=bool(set(exposed) - {"filesystem", "shell", "terminal"}),
                data_access_level="source-code" if "filesystem" in exposed else "unknown",
                tags=["mcp", "high_risk_tools"],
                confidence="high",
            )
        )
    for key, value in rows:
        key_l = key.lower()
        value_s = str(value)
        if any(token in key_l for token in ["token", "api_key", "apikey", "secret"]) and looks_like_secret(value_s):
            signals.append(
                make_signal(
                    rule_id="nhi_secret_leakage",
                    file_path=path,
                    line_number=line_number_for_key_value(text, key, value_s),
                    name=str(key),
                    identity_type="mcp_server",
                    source="MCP config",
                    evidence=f"{key}: {value_s}",
                    secret_value=value_s,
                    tools=tools,
                    tags=["mcp", "plaintext_secret"],
                    confidence="high",
                )
            )
    return signals
