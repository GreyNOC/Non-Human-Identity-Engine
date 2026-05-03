"""MCP configuration parser."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, parse_json_safely

MCP_NAMES = {"mcp.json", "mcp_config.json", "claude_desktop_config.json", "cursor_mcp.json"}


def should_parse(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    return path.name.lower() in MCP_NAMES or normalized.endswith("/.cursor/mcp.json") or normalized.endswith("/.vscode/mcp.json")


def parse(path: Path, text: str) -> list[Signal]:
    rows = flatten_json(parse_json_safely(text)) if parse_json_safely(text) is not None else []
    haystack = " ".join(f"{k}={v}" for k, v in rows).lower() or text.lower()
    signals: list[Signal] = []
    if "filesystem" in haystack and any(broad in haystack for broad in ["${workspacefolder}", "$home", "~", "c:\\users", "/users", "/home", "."]):
        signals.append(make_signal(rule_id="nhi_mcp_filesystem_broad_access", file_path=path, line_number=None, name="MCP filesystem server", identity_type="MCP server connector", source="MCP config", evidence="MCP filesystem server has broad path access", tools=["filesystem"], admin_access=True, data_access_level="source-code", tags=["mcp", "filesystem"]))
    if any(tool in haystack for tool in ["shell", "command", "github", "database", "browser", "cloud", "email"]):
        tools = sorted({tool for tool in ["shell", "command", "github", "database", "browser", "cloud", "email"] if tool in haystack})
        signals.append(make_signal(rule_id="nhi_mcp_server_high_risk_tool_access", file_path=path, line_number=None, name="MCP high-risk server", identity_type="MCP server connector", source="MCP config", evidence=f"MCP exposes high-risk tools: {', '.join(tools)}", tools=tools, admin_access=any(t in tools for t in ["shell", "command"]), external_access=True, tags=["mcp", "high_risk_tools"]))
    if "token" in haystack or "api_key" in haystack:
        signals.append(make_signal(rule_id="nhi_secret_leakage", file_path=path, line_number=None, name="MCP token", identity_type="MCP server connector", source="MCP config", evidence="Token-like value present in MCP config", tags=["mcp", "plaintext_secret"]))
    return signals
