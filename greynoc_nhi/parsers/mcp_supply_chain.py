"""Static MCP supply-chain and provenance parser."""

from __future__ import annotations

__version__ = 1

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.parsers.mcp_configs import _capabilities, _config_rows, _is_mcp_config_path, _server_prefix
from greynoc_nhi.utils import line_number_for, line_number_for_key_value

PACKAGE_COMMANDS = {"npx", "uvx", "uv", "bun", "bunx", "pip", "pipx", "npm", "pnpm", "yarn", "docker"}
SHELL_COMMANDS = {"bash", "sh", "powershell", "pwsh", "cmd", "cmd.exe", "python", "node", "deno"}
UNSAFE_FLAG_RE = re.compile(r"--(?:dangerously-[a-z0-9-]+|allow-all|no-sandbox|unsafe|privileged|disable-sandbox)", re.I)
REMOTE_SCRIPT_RE = re.compile(r"(?:curl|wget)\b.+\|\s*(?:bash|sh|powershell|pwsh)|https?://[^ \t'\",]+(?:\.sh|\.ps1|install)", re.I)
GITHUB_URL_RE = re.compile(r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?(?:[/#?][^ \t'\",]*)?", re.I)
PIN_RE = re.compile(r"@[0-9][A-Za-z0-9_.-]*|@[a-f0-9]{40}\b|sha256:[a-f0-9]{32,}|\b[a-f0-9]{40}\b|==[A-Za-z0-9_.-]+", re.I)
SECRET_ENV_RE = re.compile(r"\$\{?(?:[A-Z0-9_]*(?:TOKEN|SECRET|API_KEY|KEY|PASSWORD|CREDENTIAL)[A-Z0-9_]*)\}?", re.I)
LOCAL_WRITABLE_RE = re.compile(r"(?<![A-Za-z0-9])(?:\.{1,2}[\\/]|~[\\/]|\$\{workspaceFolder\}|%USERPROFILE%|/tmp/|/var/tmp/|C:\\Users\\).+\.(?:py|js|ts|mjs|cjs|sh|ps1)", re.I)

SECRET_KEY_MARKERS = ["token", "secret", "api_key", "password", "authorization", "bearer"]


def should_parse(path: Path) -> bool:
    return _is_mcp_config_path(path)


def _rows(path: Path, text: str) -> list[tuple[str, object, int | None]]:
    return _config_rows(path, text)


def _command_rows(rows: list[tuple[str, object, int | None]]) -> list[tuple[str, str, int | None]]:
    return [
        (key, str(value), line)
        for key, value, line in rows
        if any(marker in key.lower() for marker in ["command", "args", "cmd", "image", "url", "source", "package"])
    ]


def _looks_unpinned(value: str) -> bool:
    lowered = value.lower()
    if "latest" in lowered:
        return True
    if "github.com" in lowered:
        return PIN_RE.search(value) is None
    return any(command in re.split(r"[\s/\\\"']+", lowered) for command in PACKAGE_COMMANDS) and PIN_RE.search(value) is None


def _grouped_command_rows(command_rows: list[tuple[str, str, int | None]]) -> list[dict[str, object]]:
    """Group command/args rows per server so pins in args count for the command."""
    grouped: dict[str, dict[str, object]] = {}
    for key, value, line in command_rows:
        group = grouped.setdefault(_server_prefix(key), {"key": key, "line": line, "values": [], "rows": []})
        group["values"].append(value)
        group["rows"].append((key, value, line))
        key_l = key.lower()
        if key_l.endswith("command") or key_l.endswith("cmd"):
            group["key"] = key
            group["line"] = line
    return list(grouped.values())


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    rows = _rows(path, text)
    command_rows = _command_rows(rows)
    haystack = " ".join(f"{key}={value}" for key, value, _line in rows) or text
    tools = sorted(_capabilities(haystack))
    lowered = haystack.lower()
    commands = set()
    for _key, value, _line in command_rows:
        commands.update(token for token in re.split(r"[\s/\\\"']+", value.lower()) if token in PACKAGE_COMMANDS | SHELL_COMMANDS)

    for group in _grouped_command_rows(command_rows):
        joined = " ".join(str(value) for value in group["values"])
        key = str(group["key"])
        line = group["line"]
        if _looks_unpinned(joined):
            rule_id = "nhi_mcp_package_install_without_pinning" if any(cmd in joined.lower() for cmd in PACKAGE_COMMANDS) else "nhi_mcp_unpinned_remote_server"
            signals.append(
                make_signal(
                    rule_id=rule_id,
                    file_path=path,
                    line_number=line or line_number_for_key_value(text, key, joined),
                    name="MCP unpinned server source",
                    identity_type="mcp_server",
                    source="MCP supply-chain config",
                    evidence=f"{key}: {joined}",
                    tools=tools,
                    external_access=True,
                    tags=["mcp", "supply_chain", "unpinned"],
                    ai_attack_class="agentic supply chain",
                    attack_chain_stage="tool provenance",
                    confidence="high",
                )
            )
        if GITHUB_URL_RE.search(joined) and PIN_RE.search(joined) is None:
            signals.append(
                make_signal(
                    rule_id="nhi_mcp_unpinned_remote_server",
                    file_path=path,
                    line_number=line or line_number_for_key_value(text, key, joined),
                    name="MCP GitHub source without commit pin",
                    identity_type="mcp_server",
                    source="MCP supply-chain config",
                    evidence=f"{key}: {joined}",
                    tools=tools,
                    external_access=True,
                    tags=["mcp", "supply_chain", "github", "unpinned"],
                    ai_attack_class="agentic supply chain",
                    attack_chain_stage="tool provenance",
                    confidence="high",
                )
            )
        for row_key, row_value, row_line in group["rows"]:
            if LOCAL_WRITABLE_RE.search(row_value):
                signals.append(
                    make_signal(
                        rule_id="nhi_mcp_writable_local_server_path",
                        file_path=path,
                        line_number=row_line or line_number_for_key_value(text, row_key, row_value),
                        name="MCP writable local server path",
                        identity_type="mcp_server",
                        source="MCP supply-chain config",
                        evidence=f"{row_key}: {row_value}",
                        tools=tools,
                        admin_access=True,
                        tags=["mcp", "supply_chain", "local_path"],
                        ai_attack_class="agentic supply chain",
                        attack_chain_stage="tool provenance",
                        confidence="medium",
                    )
                )

    if REMOTE_SCRIPT_RE.search(haystack):
        signals.append(
            make_signal(
                rule_id="nhi_mcp_remote_script_execution",
                file_path=path,
                line_number=line_number_for(text, "curl") or line_number_for(text, "wget") or line_number_for(text, "http"),
                name="MCP remote script execution",
                identity_type="mcp_server",
                source="MCP supply-chain config",
                evidence="MCP command appears to execute a remote script or curl-piped shell",
                tools=sorted(set(tools + ["shell"])),
                admin_access=True,
                external_access=True,
                tags=["mcp", "supply_chain", "remote_script"],
                ai_attack_class="unexpected code execution",
                attack_chain_stage="tool provenance",
                confidence="high",
            )
        )

    if UNSAFE_FLAG_RE.search(haystack):
        signals.append(
            make_signal(
                rule_id="nhi_mcp_unsafe_runtime_flag",
                file_path=path,
                line_number=line_number_for(text, "--dangerously") or line_number_for(text, "--allow-all") or line_number_for(text, "--no-sandbox"),
                name="MCP unsafe runtime flag",
                identity_type="mcp_server",
                source="MCP supply-chain config",
                evidence="MCP command includes unsafe or no-sandbox runtime flags",
                tools=tools,
                admin_access=True,
                approval_required=False,
                tags=["mcp", "unsafe_runtime"],
                ai_attack_class="excessive agency",
                attack_chain_stage="tool execution",
                confidence="high",
            )
        )

    for key, value, line in rows:
        key_l = key.lower()
        key_norm = key_l.replace("-", "_")
        value_s = str(value)
        candidate = value_s[7:].strip() if value_s.lower().startswith("bearer ") else value_s
        if ("env" in key_norm or any(secret in key_norm for secret in SECRET_KEY_MARKERS)) and (SECRET_ENV_RE.search(value_s) or looks_like_secret(candidate)):
            signals.append(
                make_signal(
                    rule_id="nhi_mcp_env_secret_passthrough",
                    file_path=path,
                    line_number=line or line_number_for_key_value(text, key, value_s),
                    name="MCP secret environment passthrough",
                    identity_type="mcp_server",
                    source="MCP supply-chain config",
                    evidence=f"{key}: {value_s}",
                    secret_value=candidate if looks_like_secret(candidate) else None,
                    tools=tools,
                    data_classes=["secrets"],
                    tags=["mcp", "plaintext_secret" if looks_like_secret(candidate) else "secret_env"],
                    ai_attack_class="sensitive information disclosure",
                    attack_chain_stage="credential",
                    confidence="high",
                )
            )

    if rows:
        server_groups: dict[str, list[str]] = {}
        for key, value, _line in rows:
            server_groups.setdefault(_server_prefix(key), []).append(f"{key}={value}")
        combo_tools: set[str] = set()
        for parts in server_groups.values():
            combo_tools |= _capabilities(" ".join(parts))
    else:
        combo_tools = set(tools)

    if {"filesystem", "shell"} <= combo_tools and any(tool in combo_tools for tool in ["browser", "email", "github", "gdrive", "database", "aws", "azure", "gcp"]) or ({"filesystem"} <= combo_tools and commands & PACKAGE_COMMANDS and any(tool in combo_tools for tool in ["browser", "email", "github", "gdrive", "database"])):
        signals.append(
            make_signal(
                rule_id="nhi_mcp_toxic_tool_combination",
                file_path=path,
                line_number=line_number_for(text, "mcpServers") or line_number_for(text, "command"),
                name="MCP filesystem execution network bridge",
                identity_type="mcp_server",
                source="MCP supply-chain config",
                evidence=f"MCP combines tools/commands across local file, execution, and external sinks: {', '.join(sorted(combo_tools | commands))}",
                tools=sorted(combo_tools | {"shell" for _ in commands}),
                admin_access=True,
                external_access=True,
                data_access_level="source-code",
                approval_required=False,
                tags=["mcp", "toxic_flow", "privileged_sink"],
                ai_attack_class="toxic flow",
                attack_chain_stage="tool/sink",
                confidence="high",
            )
        )

    if "docker" in lowered and ("image" in lowered or "docker run" in lowered) and "sha256:" not in lowered:
        signals.append(
            make_signal(
                rule_id="nhi_model_container_unpinned_digest",
                file_path=path,
                line_number=line_number_for(text, "docker") or line_number_for(text, "image"),
                name="MCP Docker server without digest pin",
                identity_type="mcp_server",
                source="MCP supply-chain config",
                evidence="MCP Docker-launched server image is not pinned by digest",
                tools=tools,
                external_access=True,
                tags=["mcp", "supply_chain", "docker"],
                ai_attack_class="agentic supply chain",
                attack_chain_stage="tool provenance",
                confidence="medium",
            )
        )

    return signals
