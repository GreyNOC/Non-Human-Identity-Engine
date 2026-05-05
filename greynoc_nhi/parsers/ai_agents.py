"""AI agent, tool connector, and model gateway configuration parser."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, line_number_for, parse_json_safely, simple_yaml_pairs

TOOL_CAPABILITIES = {
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
    "execute_command",
    "run_shell",
    "write_file",
    "read_file",
    "deploy",
}

CANONICAL_TOOL = {
    "execute_command": "shell",
    "run_shell": "shell",
    "write_file": "filesystem",
    "read_file": "filesystem",
    "postgres": "database",
    "mysql": "database",
    "sqlite": "database",
}

AGENT_FRAMEWORKS = {
    "langchain": "langchain",
    "llama_index": "llama_index",
    "llamaindex": "llama_index",
    "crewai": "crewai",
    "autogen": "autogen",
    "semantic_kernel": "semantic_kernel",
    "semantic-kernel": "semantic_kernel",
    "openai.agents": "openai agents",
}

AGENT_FILE_NAMES = {
    "agents.yaml",
    "agents.yml",
    "agents.json",
    "crew.py",
    "autogen_config.json",
    "autogen.json",
    "continue.json",
    "config.json",
}

MODEL_GATEWAY_NAMES = {"litellm_config.yaml", "litellm_config.yml", "litellm_config.json", "model_gateway.yaml", "model_gateway.yml"}
MODEL_GATEWAY_MARKERS = {"litellm", "openai-compatible", "openai_compatible", "model_gateway", "ollama", "vllm", "text-generation-inference"}
SENSITIVE_DATA_MARKERS = {"secret", ".env", "customer", "pii", "payment", "prod", "production", "private", "credential", "database"}


def should_parse(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    name = path.name.lower()
    return (
        name in AGENT_FILE_NAMES
        or name in MODEL_GATEWAY_NAMES
        or normalized.endswith("/.continue/config.json")
        or normalized.endswith("/.continue/assistants.yaml")
        or normalized.endswith("/.cursor/rules/agents.json")
        or normalized.endswith("/.windsurf/agents.json")
        or (path.suffix.lower() in {".json", ".yaml", ".yml"} and any(token in name for token in ["agent", "tool", "crew", "autogen", "litellm"]))
        or path.suffix.lower() == ".py"
    )


def _rows(path: Path, text: str) -> list[tuple[str, object, int | None]]:
    data = parse_json_safely(text)
    if data is not None:
        return [(key, value, None) for key, value in flatten_json(data)]
    if path.suffix.lower() in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}:
        return [(key, value, line) for key, value, line in simple_yaml_pairs(text)]
    rows: list[tuple[str, object, int | None]] = []
    for number, line in enumerate(text.splitlines(), 1):
        match = re.search(r"([A-Za-z0-9_.-]*(?:tool|memory|context|approval|scope|permission|connector)[A-Za-z0-9_.-]*)\s*[:=]\s*(.+)", line, re.I)
        if match:
            rows.append((match.group(1), match.group(2).strip().strip("'\""), number))
    return rows


def _capabilities_from_text(text: object) -> set[str]:
    lowered = str(text).lower()
    tools = set()
    for tool in TOOL_CAPABILITIES:
        if re.search(rf"(?<![a-z0-9_-]){re.escape(tool)}(?![a-z0-9_-])", lowered):
            tools.add(CANONICAL_TOOL.get(tool, tool))
    if "gdrive" in lowered or "google drive" in lowered:
        tools.add("gdrive")
    return tools


def _frameworks_from_text(text: str) -> set[str]:
    lowered = text.lower()
    frameworks = set()
    for marker, provider in AGENT_FRAMEWORKS.items():
        if marker in lowered:
            frameworks.add(provider)
    return frameworks


def _is_model_gateway(path: Path, text: str) -> bool:
    lowered = text.lower()
    return path.name.lower() in MODEL_GATEWAY_NAMES or any(marker in lowered for marker in MODEL_GATEWAY_MARKERS)


def parse(path: Path, text: str) -> list[Signal]:
    rows = _rows(path, text)
    signals: list[Signal] = []
    tool_values: set[str] = set()
    connectors: set[str] = set()
    scopes: set[str] = set()
    permissions: set[str] = set()
    approval_required: bool | None = None
    memory_enabled: bool | None = None
    context_store: str | None = None
    data_classes: set[str] = set()
    production = "prod" in path.name.lower() or "production" in path.name.lower()

    for key, value, _line in rows:
        key_l = key.lower()
        value_l = str(value).lower()
        if any(token in key_l for token in ["tool", "capabilit", "connector", "integration", "mcp"]):
            tool_values.update(_capabilities_from_text(value_l))
            if "connector" in key_l or "integration" in key_l:
                connectors.update(_capabilities_from_text(value_l))
        if any(token in key_l for token in ["scope", "permission"]):
            scopes.update(_capabilities_from_text(value_l))
            if "write" in value_l or "repo" in value_l or "workflow" in value_l:
                permissions.add(value_l.strip())
        if "approval_required" in key_l or "require_approval" in key_l:
            approval_required = value_l in {"true", "yes", "1", "on"}
        if "memory" in key_l:
            if value_l in {"true", "yes", "1", "on", "enabled"} or any(word in value_l for word in SENSITIVE_DATA_MARKERS):
                memory_enabled = True
            if any(word in value_l for word in SENSITIVE_DATA_MARKERS):
                data_classes.add("sensitive")
        if "context" in key_l or "store" in key_l:
            context_store = str(value)
            if any(word in value_l for word in SENSITIVE_DATA_MARKERS):
                data_classes.add("sensitive")
                if "customer" in value_l:
                    data_classes.add("customer")
                if "secret" in value_l or ".env" in value_l or "credential" in value_l:
                    data_classes.add("secrets")
        if "production" in key_l or value_l == "production" or "prod" in value_l:
            production = True

    frameworks = _frameworks_from_text(text)
    if _is_model_gateway(path, text):
        signals.append(
            make_signal(
                rule_id="nhi_model_gateway_detected",
                file_path=path,
                line_number=line_number_for(text, "litellm") or line_number_for(text, "model"),
                name=path.stem,
                identity_type="model_gateway",
                source="model gateway config",
                evidence="Model gateway or OpenAI-compatible gateway configuration detected",
                provider="litellm" if "litellm" in text.lower() else None,
                external_access=True,
                production_access=production,
                data_classes=["ai_prompts"],
                tags=["model_gateway", "ai_gateway"],
                confidence="high",
            )
        )

    if frameworks:
        signals.append(
            make_signal(
                rule_id="nhi_ai_agent_framework_detected",
                file_path=path,
                line_number=next((i for i, line in enumerate(text.splitlines(), 1) if any(marker in line.lower() for marker in AGENT_FRAMEWORKS)), None),
                name=f"{path.stem} agent framework",
                identity_type="ai_agent",
                source="AI agent framework",
                provider=", ".join(sorted(frameworks)),
                evidence=f"Known AI agent framework detected: {', '.join(sorted(frameworks))}",
                tags=["ai_agent", "framework"],
                confidence="medium",
            )
        )

    if tool_values:
        if approval_required is not True and any(tool in tool_values for tool in ["shell", "terminal"]):
            rule = "nhi_ai_agent_shell_access"
        elif any(tool == "filesystem" for tool in tool_values):
            rule = "nhi_ai_agent_filesystem_access"
        elif "github" in tool_values and any("write" in permission or "repo" in permission or "workflow" in permission for permission in permissions | scopes):
            rule = "nhi_ai_agent_github_write_access"
        else:
            rule = "nhi_ai_agent_unapproved_tool_access" if approval_required is False else "nhi_ai_agent_framework_detected"
        signals.append(
            make_signal(
                rule_id=rule,
                file_path=path,
                line_number=None,
                name=path.stem,
                identity_type="ai_agent",
                source="AI agent config",
                evidence=f"Agent tools configured: {', '.join(sorted(tool_values))}",
                tools=sorted(tool_values),
                permissions=sorted(permissions),
                scopes=sorted(scopes),
                admin_access=any(t in tool_values for t in ["shell", "terminal", "docker", "kubernetes", "terraform", "aws", "azure", "gcp"]),
                production_access=production,
                external_access=bool(tool_values - {"filesystem", "shell", "terminal"}),
                approval_required=approval_required,
                memory_enabled=memory_enabled,
                context_store=context_store,
                data_classes=sorted(data_classes),
                data_access_level="customer" if "customer" in data_classes or "database" in tool_values else "source-code" if "filesystem" in tool_values else "unknown",
                tags=["ai_agent", "agent_tools"],
                confidence="high" if rule in {"nhi_ai_agent_shell_access", "nhi_ai_agent_filesystem_access", "nhi_ai_agent_github_write_access"} else "medium",
            )
        )

    if connectors:
        signals.append(
            make_signal(
                rule_id="nhi_tool_connector_high_risk_access",
                file_path=path,
                line_number=None,
                name=f"{path.stem} tool connector",
                identity_type="tool_connector",
                source="AI tool connector config",
                evidence=f"Tool connectors configured: {', '.join(sorted(connectors))}",
                tools=sorted(connectors),
                external_access=True,
                approval_required=approval_required,
                tags=["tool_connector", "ai_agent"],
                confidence="medium",
            )
        )

    if memory_enabled and (data_classes or context_store):
        signals.append(
            make_signal(
                rule_id="nhi_ai_agent_sensitive_data_access",
                file_path=path,
                line_number=line_number_for(text, "memory") or line_number_for(text, "context"),
                name=path.stem,
                identity_type="ai_agent",
                source="AI agent config",
                evidence="Agent memory or context store references sensitive data",
                tools=sorted(tool_values),
                production_access=production,
                approval_required=approval_required,
                context_store=context_store,
                memory_enabled=True,
                data_classes=sorted(data_classes),
                data_access_level="customer" if "customer" in data_classes else "source-code",
                tags=["ai_agent", "sensitive_data", "memory"],
                confidence="high",
            )
        )

    return signals
