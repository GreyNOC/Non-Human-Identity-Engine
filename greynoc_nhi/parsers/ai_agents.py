"""AI agent, tool connector, and model gateway configuration parser."""

from __future__ import annotations

__version__ = 2

import re
from bisect import bisect_right
from pathlib import Path
from typing import Any

from greynoc_nhi.parsers.base import Signal, make_signal
from greynoc_nhi.utils import flatten_json, parse_json_safely, simple_yaml_pairs

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
    "langgraph": "langgraph",
    "llama_index": "llama_index",
    "llamaindex": "llama_index",
    "crewai": "crewai",
    "autogen": "autogen",
    "semantic_kernel": "semantic_kernel",
    "semantic-kernel": "semantic_kernel",
    "openai.agents": "openai agents",
    "openai-agents": "openai agents",
    "@openai/agents": "openai agents",
    "pydantic_ai": "pydantic_ai",
    "pydantic-ai": "pydantic_ai",
    "smolagents": "smolagents",
    "@ai-sdk/": "vercel ai sdk",
    "import ag2": "autogen",
    "from ag2": "autogen",
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
    "config.yaml",
    "config.yml",
    "proxy_config.yaml",
    "proxy_config.yml",
}

MODEL_GATEWAY_NAMES = {"litellm_config.yaml", "litellm_config.yml", "litellm_config.json", "model_gateway.yaml", "model_gateway.yml"}
MODEL_GATEWAY_MARKERS = {"litellm", "openai-compatible", "openai_compatible", "model_gateway", "ollama", "vllm", "text-generation-inference"}
MODEL_GATEWAY_STRUCTURE_MARKERS = {"model_list", "router_settings", "litellm_params", "proxy", "base_url", "api_base"}
SENSITIVE_DATA_MARKERS = {"secret", ".env", "customer", "pii", "payment", "prod", "production", "private", "credential", "database"}
HARMLESS_TOOL_NAME_MARKERS = {"summarize", "summary", "read", "search", "lookup", "list", "format", "parse", "extract"}
SENSITIVE_SINK_MARKERS = {"write", "delete", "send", "email", "deploy", "merge", "commit", "push", "refund", "payment", "database", "sql", "cloud", "github", "terraform", "kubernetes", "docker"}
UNTRUSTED_TOOL_SOURCE_MARKERS = {"http://", "https://", "github.com", "npm:", "npx ", "pypi", "marketplace", "third-party", "third_party", "remote"}
TOOL_PROMPT_INJECTION_RE = re.compile(
    r"ignore (?:previous|prior|system|developer) instructions|"
    r"reveal (?:the )?(?:system|developer) prompt|"
    r"leak (?:context|secrets|prior messages)|"
    r"send (?:the )?(?:conversation|context|secrets)|"
    r"base64 encode (?:the )?(?:output|secret|context)",
    re.I,
)

# Compile once; previously rebuilt per line of every scanned file.
_AGENT_LINE_RE = re.compile(
    r"([A-Za-z0-9_.-]*(?:tool|memory|context|approval|scope|permission|connector)[A-Za-z0-9_.-]*)\s*[:=]\s*(.+)",
    re.I,
)
# Single alternation instead of one compiled regex per capability; boundary
# lookarounds are shared by every alternative, and the length-descending sort
# guards against prefix shadowing.
_TOOL_CAPS_RE = re.compile(
    r"(?<![a-z0-9_-])(?:"
    + "|".join(sorted(map(re.escape, TOOL_CAPABILITIES), key=len, reverse=True))
    + r")(?![a-z0-9_-])"
)
# Word-bounded production marker: matches "prod"/"production"/"env=prod" but
# not "product", "reproduce", or "producer".
_PROD_VALUE_RE = re.compile(r"(?<![a-z])prod(?:uction)?(?![a-z])")


class _LineFinder:
    """Line-number lookups without re-splitting the file for every needle."""

    def __init__(self, text: str) -> None:
        self._text = text
        self._starts: list[int] | None = None
        self._cache: dict[str, int | None] = {}

    def _line_starts(self) -> list[int]:
        if self._starts is None:
            starts = [0]
            for line in self._text.splitlines(keepends=True):
                starts.append(starts[-1] + len(line))
            self._starts = starts
        return self._starts

    def find(self, needle: str) -> int | None:
        if not needle or "\n" in needle or "\r" in needle:
            return None
        if needle not in self._cache:
            offset = self._text.find(needle)
            self._cache[needle] = None if offset < 0 else bisect_right(self._line_starts(), offset)
        return self._cache[needle]

def should_parse(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    name = path.name.lower()
    return (
        name in AGENT_FILE_NAMES
        or name in {"agent.md", "agents.md", "skill.md", "claude.md", ".cursorrules", ".windsurfrules"}
        or name in MODEL_GATEWAY_NAMES
        or normalized.endswith("/.continue/config.json")
        or normalized.endswith("/.continue/assistants.yaml")
        or normalized.endswith("/.cursor/rules/agents.json")
        or normalized.endswith("/.windsurf/agents.json")
        or (path.suffix.lower() in {".json", ".yaml", ".yml"} and any(token in name for token in ["agent", "tool", "crew", "autogen", "litellm", "assistant", "copilot", "gpts"]))
        or path.suffix.lower() == ".py"
    )

def _rows(path: Path, text: str, data: Any | None) -> list[tuple[str, object, int | None]]:
    if data is not None:
        return [(key, value, None) for key, value in flatten_json(data)]
    if path.suffix.lower() in {".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}:
        return [(key, value, line) for key, value, line in simple_yaml_pairs(text)]
    rows: list[tuple[str, object, int | None]] = []
    for number, line in enumerate(text.splitlines(), 1):
        match = _AGENT_LINE_RE.search(line)
        if match:
            rows.append((match.group(1), match.group(2).strip().strip("'\""), number))
    return rows

def _capabilities_from_text(text: object) -> set[str]:
    lowered = str(text).lower()
    tools = {CANONICAL_TOOL.get(tool, tool) for tool in _TOOL_CAPS_RE.findall(lowered)}
    if "gdrive" in lowered or "google drive" in lowered:
        tools.add("gdrive")
    return tools

def _frameworks_from_text(lowered: str) -> set[str]:
    frameworks = set()
    for marker, provider in AGENT_FRAMEWORKS.items():
        if marker in lowered:
            frameworks.add(provider)
    return frameworks

def _extract_tool_specs(obj: Any, path: str = "") -> list[dict[str, str]]:
    specs: list[dict[str, str]] = []
    if isinstance(obj, dict):
        lowered_keys = {str(key).lower(): key for key in obj}
        name_key = next((lowered_keys[key] for key in ["name", "tool", "id", "function"] if key in lowered_keys), None)
        desc_key = next((lowered_keys[key] for key in ["description", "desc", "tool_description", "instructions"] if key in lowered_keys), None)
        source_key = next((lowered_keys[key] for key in ["source", "url", "package", "command", "server", "provider"] if key in lowered_keys), None)
        if name_key or desc_key:
            name = str(obj.get(name_key, path.rsplit(".", 1)[-1] if path else "tool"))
            description = str(obj.get(desc_key, ""))
            source = str(obj.get(source_key, ""))
            specs.append({"name": name, "description": description, "source": source, "path": path})
        for key, value in obj.items():
            specs.extend(_extract_tool_specs(value, f"{path}.{key}" if path else str(key)))
    elif isinstance(obj, list):
        for idx, value in enumerate(obj):
            specs.extend(_extract_tool_specs(value, f"{path}[{idx}]"))
    return specs


def _tool_specs(path: Path, text: str, rows: list[tuple[str, object, int | None]], data: Any | None) -> list[dict[str, str]]:
    if data is not None:
        return _extract_tool_specs(data)
    specs: list[dict[str, str]] = []
    pending_name: str | None = None
    pending_source = ""
    for key, value, _line in rows:
        key_l = key.lower()
        if "name" in key_l or key_l.endswith("tool"):
            pending_name = str(value)
        if any(token in key_l for token in ["source", "url", "package", "command"]):
            pending_source = str(value)
        if "description" in key_l or "tool_description" in key_l or "instructions" in key_l:
            specs.append({"name": pending_name or path.stem, "description": str(value), "source": pending_source, "path": key})
    return specs


def _canonical_tool_name(name: str) -> str:
    return re.sub(r"[^a-z0-9]+", "", name.lower())


def _description_capabilities(name: str, description: str) -> set[str]:
    return _capabilities_from_text(f"{name} {description}")


def _tool_line(finder: _LineFinder, spec: dict[str, str]) -> int | None:
    name = spec.get("name", "")
    description = spec.get("description", "")[:40]
    return (finder.find(name) if name else None) or (finder.find(description) if description else None)


def _is_model_gateway(path: Path, lowered: str, suffix: str) -> bool:
    if path.name.lower() in MODEL_GATEWAY_NAMES:
        return True
    if not any(marker in lowered for marker in MODEL_GATEWAY_MARKERS):
        return False
    if suffix in {".yaml", ".yml", ".json", ".toml"}:
        return True
    # Bare marker hits in code files (e.g. "import ollama" in a plain client)
    # are not gateway configs; require structural gateway evidence.
    return any(marker in lowered for marker in MODEL_GATEWAY_STRUCTURE_MARKERS)

def parse(path: Path, text: str) -> list[Signal]:
    data = parse_json_safely(text)
    rows = _rows(path, text, data)
    lowered = text.lower()
    finder = _LineFinder(text)
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
    tool_specs = _tool_specs(path, text, rows, data)

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
        if "production" in key_l or _PROD_VALUE_RE.search(value_l):
            production = True

    for spec in tool_specs:
        description = spec.get("description", "")
        name = spec.get("name", path.stem)
        source = spec.get("source", "")
        combined = f"{name} {description} {source}"
        capabilities = _description_capabilities(name, description)
        sinks = {marker for marker in SENSITIVE_SINK_MARKERS if marker in combined.lower()}
        tool_values.update(capabilities)
        if TOOL_PROMPT_INJECTION_RE.search(description):
            signals.append(
                make_signal(
                    rule_id="nhi_ai_tool_prompt_injection_description",
                    file_path=path,
                    line_number=_tool_line(finder, spec),
                    name=name,
                    identity_type="tool_connector",
                    source="AI tool metadata",
                    evidence=f"Tool description contains prompt-injection behavior: {description}",
                    tools=sorted(capabilities),
                    external_access=True,
                    approval_required=approval_required,
                    tags=["ai_agent", "tool_metadata", "tool_poisoning", "untrusted_context"],
                    ai_attack_class="tool poisoning",
                    attack_chain_stage="tool description",
                    confidence="high",
                )
            )
        if any(marker in name.lower() for marker in HARMLESS_TOOL_NAME_MARKERS) and (capabilities & {"shell", "terminal", "docker", "kubernetes", "terraform", "aws", "azure", "gcp"} or sinks & {"write", "delete", "send", "deploy", "merge", "push", "refund", "payment"}):
            signals.append(
                make_signal(
                    rule_id="nhi_ai_tool_name_description_mismatch",
                    file_path=path,
                    line_number=_tool_line(finder, spec),
                    name=name,
                    identity_type="tool_connector",
                    source="AI tool metadata",
                    evidence=f"Tool name '{name}' understates capabilities described as: {description}",
                    tools=sorted(capabilities),
                    admin_access=bool(capabilities & {"shell", "terminal", "docker", "kubernetes", "terraform", "aws", "azure", "gcp"}),
                    external_access=bool(capabilities - {"filesystem", "shell", "terminal"} or sinks),
                    approval_required=approval_required,
                    tags=["ai_agent", "tool_metadata", "tool_mismatch", "privileged_sink"],
                    ai_attack_class="tool misuse",
                    attack_chain_stage="tool/sink",
                    confidence="high",
                )
            )
        if source and any(marker in source.lower() for marker in UNTRUSTED_TOOL_SOURCE_MARKERS):
            signals.append(
                make_signal(
                    rule_id="nhi_ai_tool_untrusted_remote_source",
                    file_path=path,
                    line_number=_tool_line(finder, spec),
                    name=name,
                    identity_type="tool_connector",
                    source="AI tool metadata",
                    evidence=f"Tool source appears remote or third-party: {source}",
                    tools=sorted(capabilities),
                    external_access=True,
                    tags=["ai_agent", "tool_metadata", "supply_chain"],
                    ai_attack_class="agentic supply chain",
                    attack_chain_stage="tool provenance",
                    confidence="medium",
                )
            )
        if sinks or capabilities & {"github", "email", "database", "docker", "kubernetes", "terraform", "aws", "azure", "gcp"}:
            signals.append(
                make_signal(
                    rule_id="nhi_ai_tool_sensitive_sink",
                    file_path=path,
                    line_number=_tool_line(finder, spec),
                    name=name,
                    identity_type="tool_connector",
                    source="AI tool metadata",
                    evidence=f"Tool can reach sensitive sink or state-changing action: {description or name}",
                    tools=sorted(capabilities | sinks),
                    admin_access=bool(capabilities & {"shell", "terminal", "docker", "kubernetes", "terraform", "aws", "azure", "gcp"}),
                    external_access=True,
                    approval_required=approval_required,
                    tags=["ai_agent", "tool_metadata", "privileged_sink"],
                    ai_attack_class="excessive agency",
                    attack_chain_stage="tool/sink",
                    confidence="medium",
                )
            )

    names_by_canonical: dict[str, list[dict[str, str]]] = {}
    for spec in tool_specs:
        canonical = _canonical_tool_name(spec.get("name", ""))
        if canonical:
            names_by_canonical.setdefault(canonical, []).append(spec)
    for specs in names_by_canonical.values():
        sources = {spec.get("source", "") for spec in specs if spec.get("source")}
        descriptions = {spec.get("description", "") for spec in specs if spec.get("description")}
        if len(specs) >= 2 and (len(sources) >= 2 or len(descriptions) >= 2 or any(any(marker in src.lower() for marker in UNTRUSTED_TOOL_SOURCE_MARKERS) for src in sources)):
            signals.append(
                make_signal(
                    rule_id="nhi_ai_tool_shadowing",
                    file_path=path,
                    line_number=_tool_line(finder, specs[0]),
                    name=specs[0].get("name", path.stem),
                    identity_type="tool_connector",
                    source="AI tool metadata",
                    evidence=f"Multiple tool definitions overlap on name '{specs[0].get('name', '')}' with different descriptions or sources.",
                    external_access=True,
                    tags=["ai_agent", "tool_metadata", "tool_shadowing", "supply_chain"],
                    ai_attack_class="tool shadowing",
                    attack_chain_stage="tool provenance",
                    confidence="medium",
                )
            )

    frameworks = _frameworks_from_text(lowered)
    if _is_model_gateway(path, lowered, path.suffix.lower()):
        signals.append(
            make_signal(
                rule_id="nhi_model_gateway_detected",
                file_path=path,
                line_number=finder.find("litellm") or finder.find("model"),
                name=path.stem,
                identity_type="model_gateway",
                source="model gateway config",
                evidence="Model gateway or OpenAI-compatible gateway configuration detected",
                provider="litellm" if "litellm" in lowered else None,
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
                line_number=next((i for i, line in enumerate(lowered.splitlines(), 1) if any(marker in line for marker in AGENT_FRAMEWORKS)), None),
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
                line_number=finder.find("memory") or finder.find("context"),
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
