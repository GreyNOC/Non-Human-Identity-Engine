"""MCP configuration parser."""

from __future__ import annotations

__version__ = 2

import re
from functools import lru_cache
from pathlib import Path
from typing import Any

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, line_number_for, line_number_for_key_value, parse_json_safely, simple_yaml_pairs

MCP_NAMES = {
    ".mcp.json",
    "mcp.json",
    "mcp_config.json",
    "claude_desktop_config.json",
    "cursor_mcp.json",
    "cline_mcp_settings.json",
    "mcp_settings.json",
    ".claude.json",
    "librechat.yaml",
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

EXECUTING_COMMANDS = {"python", "node", "npx", "uvx", "uv", "bun", "bunx", "deno", "docker", "bash", "sh", "powershell", "cmd", "cmd.exe"}
HIGH_RISK_TOOLS = {"shell", "terminal", "filesystem", "browser", "email", "gdrive", "github", "database", "docker", "kubernetes", "terraform", "aws", "azure", "gcp"}

REMOTE_TRANSPORTS = {"sse", "http", "streamable-http", "streamable_http", "streamablehttp"}
SECRET_KEY_MARKERS = ["token", "api_key", "apikey", "secret", "authorization", "auth", "bearer", "password"]

# One precompiled alternation instead of one re.search per capability.
# "github" is matched separately so bare github.com URLs do not count as a
# capability (a source URL is provenance, not tool access).
_CAPS_RE = re.compile(
    r"(?<![a-z0-9_-])(?:"
    + "|".join(sorted((re.escape(tool) for tool in MCP_TOOL_CAPABILITIES if tool != "github"), key=len, reverse=True))
    + r")(?![a-z0-9_-])"
)
_GITHUB_RE = re.compile(r"(?<![a-z0-9_-])github(?!\.com\b)(?![a-z0-9_-])")
_CREDENTIALED_URL_RE = re.compile(r"://[^/:@\s]+:(?![$])[^@\s]+@")

_BROAD_PATH_EXACT = {".", "..", "/", "\\", "~"}
_BROAD_PATH_PREFIXES = ("${workspacefolder}", "$home", "%userprofile%", "~/", "~\\", "c:\\users", "c:/users", "/users", "/home")
_SERVER_SECTION_MARKERS = (".command", ".args", ".env", ".url", ".headers", ".type", ".transport", ".source", ".package", ".image")


@lru_cache(maxsize=4)
def _parse_json_cached(text: str) -> Any | None:
    """Cached strict-JSON parse. Callers must treat the result as read-only."""
    return parse_json_safely(text)


_TOML_SECTION_RE = re.compile(r"^\[+([^\]]+)\]+$")
_TOML_LINE_RE = re.compile(r"^([A-Za-z0-9_.-]+)\s*=\s*(.+)$")


def _config_rows(path: Path, text: str) -> list[tuple[str, object, int | None]]:
    """Flattened key/value rows for JSON, YAML-ish, and TOML-ish MCP configs."""
    data = _parse_json_cached(text)
    if data is not None:
        return [(key, value, None) for key, value in flatten_json(data)]
    suffix = path.suffix.lower()
    if suffix not in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}:
        return []
    rows: list[tuple[str, object, int | None]] = [(key, value, line) for key, value, line in simple_yaml_pairs(text)]
    if suffix in {".toml", ".ini", ".cfg", ".conf"}:
        section = ""
        for number, line in enumerate(text.splitlines(), 1):
            stripped = line.strip()
            section_match = _TOML_SECTION_RE.match(stripped)
            if section_match:
                section = section_match.group(1).strip().strip("'\"")
                continue
            pair_match = _TOML_LINE_RE.match(stripped)
            if pair_match:
                key = f"{section}.{pair_match.group(1)}" if section else pair_match.group(1)
                rows.append((key, pair_match.group(2).strip().strip("'\""), number))
    return rows


def _is_mcp_config_path(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    return (
        path.name.lower() in MCP_NAMES
        or normalized.endswith("/.cursor/mcp.json")
        or normalized.endswith("/.vscode/mcp.json")
        or normalized.endswith("/claude/claude_desktop_config.json")
        or normalized.endswith("/.continue/mcp.json")
        or normalized.endswith("/.windsurf/mcp.json")
        or normalized.endswith("/.gemini/settings.json")
        or normalized.endswith("/.zed/settings.json")
        or normalized.endswith("/.codex/config.toml")
    )


def should_parse(path: Path) -> bool:
    return _is_mcp_config_path(path)

def _capabilities(text: str) -> set[str]:
    lowered = text.lower()
    tools = {"database" if tool in {"postgres", "mysql", "sqlite"} else tool for tool in _CAPS_RE.findall(lowered)}
    if _GITHUB_RE.search(lowered):
        tools.add("github")
    if "google drive" in lowered:
        tools.add("gdrive")
    return tools


def _server_prefix(key: str) -> str:
    """Return the flattened-key prefix identifying one configured server."""
    lowered = key.lower()
    for marker in _SERVER_SECTION_MARKERS:
        idx = lowered.find(marker)
        if idx != -1:
            return lowered[:idx]
    return lowered.rsplit(".", 1)[0] if "." in lowered else lowered


def _is_broad_path(value: object) -> bool:
    text = str(value).strip().strip("'\"").lower()
    if text in _BROAD_PATH_EXACT:
        return True
    return any(text.startswith(prefix) for prefix in _BROAD_PATH_PREFIXES)


def _broad_filesystem_paths(rows: list[tuple[str, object]], haystack: str) -> bool:
    """True when a filesystem-capable server is scoped to a root-ish path value."""
    if not rows:
        # Text fallback (YAML/TOML configs): only well-known broad roots.
        return any(marker in haystack for marker in ("${workspacefolder}", "$home", "%userprofile%", "c:\\users", "/users/", "/home"))
    groups: dict[str, list[tuple[str, object]]] = {}
    for key, value in rows:
        groups.setdefault(_server_prefix(key), []).append((key.lower(), value))
    for group in groups.values():
        blob = " ".join(f"{key}={value}" for key, value in group).lower()
        if "filesystem" not in blob:
            continue
        for key, value in group:
            if not any(marker in key for marker in ("args", "command", "path", "root", "dir")):
                continue
            if _is_broad_path(value):
                return True
    return False

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
    rows = [(key, value) for key, value, _line in _config_rows(path, text)]
    haystack = " ".join(f"{k}={v}" for k, v in rows).lower() or text.lower()
    signals: list[Signal] = []
    tools = sorted(_capabilities(haystack))
    commands = sorted(_executing_commands(rows))
    has_mcp_servers = (
        any(marker in haystack for marker in ("mcpservers", "mcp_servers", "contextservers", "context_servers"))
        or path.name.lower() in MCP_NAMES
    )

    if "filesystem" in tools and _broad_filesystem_paths(rows, haystack):
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
    remote_servers: dict[str, tuple[str, str]] = {}
    header_prefixes: set[str] = set()
    for key, value in rows:
        key_l = key.lower()
        key_norm = key_l.replace("-", "_")
        value_s = str(value)
        if ".headers" in key_l:
            header_prefixes.add(_server_prefix(key_l))
        if "servers" in key_l:
            stripped = value_s.strip()
            if key_l.endswith(".url") and stripped.lower().startswith(("http://", "https://", "ws://", "wss://")):
                remote_servers.setdefault(_server_prefix(key_l), (key, stripped))
            elif (key_l.endswith(".type") or key_l.endswith(".transport")) and stripped.lower() in REMOTE_TRANSPORTS:
                remote_servers.setdefault(_server_prefix(key_l), (key, stripped))
        candidate = value_s[7:].strip() if value_s.lower().startswith("bearer ") else value_s
        has_secret_key = any(token in key_norm for token in SECRET_KEY_MARKERS)
        if (has_secret_key and looks_like_secret(candidate)) or _CREDENTIALED_URL_RE.search(value_s):
            secret_value = candidate if looks_like_secret(candidate) else value_s
            signals.append(
                make_signal(
                    rule_id="nhi_secret_leakage",
                    file_path=path,
                    line_number=line_number_for_key_value(text, key, value_s),
                    name=str(key),
                    identity_type="mcp_server",
                    source="MCP config",
                    evidence=f"{key}: {value_s}",
                    secret_value=secret_value,
                    tools=tools,
                    tags=["mcp", "plaintext_secret"],
                    confidence="high",
                )
            )
    for prefix, (key, value_s) in sorted(remote_servers.items()):
        server_name = prefix.rsplit(".", 1)[-1] or "MCP remote server"
        signals.append(
            make_signal(
                rule_id="nhi_mcp_remote_server",
                file_path=path,
                line_number=line_number_for_key_value(text, key, value_s),
                name=server_name,
                identity_type="mcp_server",
                source="MCP config",
                evidence=f"{key}: {value_s}",
                tools=tools,
                external_access=True,
                data_classes=["secrets"] if prefix in header_prefixes else [],
                tags=["mcp", "remote_server"],
                confidence="high",
            )
        )
    return signals
