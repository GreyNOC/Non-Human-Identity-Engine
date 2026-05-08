"""Static MCP supply-chain and provenance parser."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.parsers.mcp_configs import MCP_NAMES, _capabilities
from greynoc_nhi.utils import flatten_json, line_number_for, line_number_for_key_value, parse_json_safely, simple_yaml_pairs

PACKAGE_COMMANDS = {"npx", "uvx", "pip", "pipx", "npm", "pnpm", "yarn", "docker"}
SHELL_COMMANDS = {"bash", "sh", "powershell", "pwsh", "cmd", "cmd.exe", "python", "node"}
UNSAFE_FLAG_RE = re.compile(r"--(?:dangerously-[a-z0-9-]+|allow-all|no-sandbox|unsafe|privileged|disable-sandbox)", re.I)
REMOTE_SCRIPT_RE = re.compile(r"(?:curl|wget)\b.+\|\s*(?:bash|sh|powershell|pwsh)|https?://[^ \t'\",]+(?:\.sh|\.ps1|install)", re.I)
GITHUB_URL_RE = re.compile(r"https?://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:\.git)?(?:[/#?][^ \t'\",]*)?", re.I)
PIN_RE = re.compile(r"@[0-9][A-Za-z0-9_.-]*|@[a-f0-9]{40}\b|sha256:[a-f0-9]{32,}|\b[a-f0-9]{40}\b|==[A-Za-z0-9_.-]+", re.I)
SECRET_ENV_RE = re.compile(r"\$\{?(?:[A-Z0-9_]*(?:TOKEN|SECRET|API_KEY|KEY|PASSWORD|CREDENTIAL)[A-Z0-9_]*)\}?", re.I)
LOCAL_WRITABLE_RE = re.compile(r"(?<![A-Za-z0-9])(?:\.{1,2}[\\/]|~[\\/]|\$\{workspaceFolder\}|%USERPROFILE%|/tmp/|/var/tmp/|C:\\Users\\).+\.(?:py|js|ts|mjs|cjs|sh|ps1)", re.I)


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


def _rows(path: Path, text: str) -> list[tuple[str, object, int | None]]:
    data = parse_json_safely(text)
    if data is not None:
        return [(key, value, None) for key, value in flatten_json(data)]
    if path.suffix.lower() in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}:
        return [(key, value, line) for key, value, line in simple_yaml_pairs(text)]
    return []


def _command_rows(rows: list[tuple[str, object, int | None]]) -> list[tuple[str, str, int | None]]:
    return [
        (key, str(value), line)
        for key, value, line in rows
        if any(marker in key.lower() for marker in ["command", "args", "cmd", "image", "url", "source", "package"])
    ]


def _looks_unpinned(value: str) -> bool:
    lowered = value.lower()
    if "latest" in lowered or "github.com" in lowered:
        return True
    return any(command in re.split(r"[\s/\\\"']+", lowered) for command in PACKAGE_COMMANDS) and PIN_RE.search(value) is None


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

    for key, value, line in command_rows:
        if _looks_unpinned(value):
            rule_id = "nhi_mcp_package_install_without_pinning" if any(cmd in value.lower() for cmd in PACKAGE_COMMANDS) else "nhi_mcp_unpinned_remote_server"
            signals.append(
                make_signal(
                    rule_id=rule_id,
                    file_path=path,
                    line_number=line or line_number_for_key_value(text, key, value),
                    name="MCP unpinned server source",
                    identity_type="mcp_server",
                    source="MCP supply-chain config",
                    evidence=f"{key}: {value}",
                    tools=tools,
                    external_access=True,
                    tags=["mcp", "supply_chain", "unpinned"],
                    ai_attack_class="agentic supply chain",
                    attack_chain_stage="tool provenance",
                    confidence="high",
                )
            )
        if GITHUB_URL_RE.search(value) and PIN_RE.search(value) is None:
            signals.append(
                make_signal(
                    rule_id="nhi_mcp_unpinned_remote_server",
                    file_path=path,
                    line_number=line or line_number_for_key_value(text, key, value),
                    name="MCP GitHub source without commit pin",
                    identity_type="mcp_server",
                    source="MCP supply-chain config",
                    evidence=f"{key}: {value}",
                    tools=tools,
                    external_access=True,
                    tags=["mcp", "supply_chain", "github", "unpinned"],
                    ai_attack_class="agentic supply chain",
                    attack_chain_stage="tool provenance",
                    confidence="high",
                )
            )
        if LOCAL_WRITABLE_RE.search(value):
            signals.append(
                make_signal(
                    rule_id="nhi_mcp_writable_local_server_path",
                    file_path=path,
                    line_number=line or line_number_for_key_value(text, key, value),
                    name="MCP writable local server path",
                    identity_type="mcp_server",
                    source="MCP supply-chain config",
                    evidence=f"{key}: {value}",
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
        value_s = str(value)
        if ("env" in key_l or any(secret in key_l for secret in ["token", "secret", "api_key", "password"])) and (SECRET_ENV_RE.search(value_s) or looks_like_secret(value_s)):
            signals.append(
                make_signal(
                    rule_id="nhi_mcp_env_secret_passthrough",
                    file_path=path,
                    line_number=line or line_number_for_key_value(text, key, value_s),
                    name="MCP secret environment passthrough",
                    identity_type="mcp_server",
                    source="MCP supply-chain config",
                    evidence=f"{key}: {value_s}",
                    secret_value=value_s if looks_like_secret(value_s) else None,
                    tools=tools,
                    data_classes=["secrets"],
                    tags=["mcp", "plaintext_secret" if looks_like_secret(value_s) else "secret_env"],
                    ai_attack_class="sensitive information disclosure",
                    attack_chain_stage="credential",
                    confidence="high",
                )
            )

    if {"filesystem", "shell"} <= set(tools) and any(tool in tools for tool in ["browser", "email", "github", "gdrive", "database", "aws", "azure", "gcp"]) or ({"filesystem"} <= set(tools) and commands & PACKAGE_COMMANDS and any(tool in tools for tool in ["browser", "email", "github", "gdrive", "database"])):
        signals.append(
            make_signal(
                rule_id="nhi_mcp_toxic_tool_combination",
                file_path=path,
                line_number=line_number_for(text, "mcpServers") or line_number_for(text, "command"),
                name="MCP filesystem execution network bridge",
                identity_type="mcp_server",
                source="MCP supply-chain config",
                evidence=f"MCP combines tools/commands across local file, execution, and external sinks: {', '.join(sorted(set(tools) | commands))}",
                tools=sorted(set(tools) | {"shell" for _ in commands}),
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
