"""Static AI code-flow and model supply-chain parser."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal

CODE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx", ".ipynb"}
CONFIG_EXTENSIONS = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf", ".md", ".mdx"}
MODEL_ARTIFACT_EXTENSIONS = {".pkl", ".pickle", ".pt", ".pth"}
MODEL_SAFE_EXTENSIONS = {".safetensors"}

MODEL_OUTPUT_EXPR = r"(?:model_output|llm_output|llm_response|assistant_response|assistant_message|completion|generated|generated_sql|response\.content|message\.content|tool_call|tool_calls)"
EVAL_RE = re.compile(rf"\b(?:eval|exec)\s*\(\s*{MODEL_OUTPUT_EXPR}", re.I)
SHELL_RE = re.compile(rf"\b(?:os\.system|subprocess\.(?:run|call|Popen)|execSync|spawn|child_process\.(?:exec|spawn))\s*\([^)\n]*{MODEL_OUTPUT_EXPR}|shell\s*=\s*True[^#\n]*{MODEL_OUTPUT_EXPR}", re.I)
SQL_RE = re.compile(rf"\b(?:execute|query|raw|run_sql)\s*\([^)\n]*{MODEL_OUTPUT_EXPR}|generated_sql", re.I)
HTML_RE = re.compile(rf"(?:innerHTML|dangerouslySetInnerHTML|v-html|markdown\.markdown|marked\.parse|render_markdown)\s*[=:(][^#\n]*{MODEL_OUTPUT_EXPR}", re.I)
TOOL_CALL_RE = re.compile(r"\b(?:tool_calls?|function_call|function_calling|ToolCall)\b", re.I)
SCHEMA_RE = re.compile(r"\b(?:json_schema|schema|zod|pydantic|marshmallow|jsonschema|TypedDict|BaseModel|validate|validator)\b", re.I)
AUTONOMOUS_ACTION_RE = re.compile(r"(?:auto_?merge|merge_pull_request|create_pull_request|deploy|send_email|send_mail|refund|close_ticket|approve|github\.repos|issues\.update)", re.I)
MODEL_OUTPUT_RE = re.compile(MODEL_OUTPUT_EXPR, re.I)
TRUST_REMOTE_RE = re.compile(r"trust_remote_code\s*=\s*True|trustRemoteCode\s*[:=]\s*true", re.I)
FROM_PRETRAINED_RE = re.compile(r"(?:from_pretrained|snapshot_download|hf_hub_download)\s*\([^)\n]+", re.I)
MODEL_URL_RE = re.compile(r"https?://(?:huggingface\.co|hf\.co|[^ \t'\",]+/models?)/[^ \t'\",)]+", re.I)
MODEL_GATEWAY_RE = re.compile(r"\b(?:litellm|model_gateway|model-gateway|openai-compatible|router_settings|fallbacks?|provider_fallback|vllm|ollama)\b", re.I)
LOGGING_RE = re.compile(r"\b(?:logging|audit|success_callback|failure_callback|redact|retention)\b", re.I)
POLICY_RE = re.compile(r"\b(?:policy|allowlist|allowed_providers|data_residency|no_fallback|fallback_policy|provider_policy)\b", re.I)
LIMIT_RE = re.compile(r"\b(?:budget|rate_limit|quota|max_tokens|max_iterations|max_steps|timeout|loop_limit|spend|rpm|tpm)\b", re.I)
AI_PROVIDER_RE = re.compile(r"\b(?:OPENAI_API_KEY|ANTHROPIC_API_KEY|COHERE_API_KEY|GEMINI_API_KEY|AZURE_OPENAI|HUGGINGFACE|litellm)\b", re.I)


def should_parse(path: Path) -> bool:
    suffix = path.suffix.lower()
    name = path.name.lower()
    return suffix in CODE_EXTENSIONS | CONFIG_EXTENSIONS | MODEL_ARTIFACT_EXTENSIONS | MODEL_SAFE_EXTENSIONS or any(token in name for token in ["litellm", "model", "gateway", "agent", "prompt"])


def _line_number(text: str, needle: str) -> int | None:
    for number, line in enumerate(text.splitlines(), 1):
        if needle.lower() in line.lower():
            return number
    return None


def _model_output_sink(
    signals: list[Signal],
    *,
    rule_id: str,
    path: Path,
    line_number: int,
    line: str,
    title: str,
    sink: str,
    admin_access: bool = False,
    external_access: bool = False,
) -> None:
    signals.append(
        make_signal(
            rule_id=rule_id,
            file_path=path,
            line_number=line_number,
            name=title,
            identity_type="ai_agent",
            source="AI code flow",
            evidence=line.strip(),
            tools=[sink],
            admin_access=admin_access,
            external_access=external_access,
            approval_required=False,
            tags=["ai_code_flow", "llm_output", "privileged_sink"],
            ai_attack_class="improper output handling",
            attack_chain_stage="sink",
            confidence="high",
        )
    )


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    suffix = path.suffix.lower()
    lowered = text.lower()

    if suffix in MODEL_ARTIFACT_EXTENSIONS:
        signals.append(
            make_signal(
                rule_id="nhi_model_pickle_artifact",
                file_path=path,
                line_number=None,
                name=path.name,
                identity_type="model_artifact",
                source="model artifact",
                evidence=f"Model artifact uses unsafe pickle/PyTorch extension: {path.name}",
                tags=["model_supply_chain", "model_artifact"],
                ai_attack_class="model supply chain",
                attack_chain_stage="model artifact",
                confidence="high",
            )
        )
        return signals

    for number, line in enumerate(text.splitlines(), 1):
        if EVAL_RE.search(line):
            _model_output_sink(signals, rule_id="nhi_llm_output_exec_sink", path=path, line_number=number, line=line, title="LLM output to code execution", sink="exec", admin_access=True)
        if SHELL_RE.search(line):
            _model_output_sink(signals, rule_id="nhi_llm_output_shell_sink", path=path, line_number=number, line=line, title="LLM output to shell", sink="shell", admin_access=True)
        if SQL_RE.search(line) and MODEL_OUTPUT_RE.search(line):
            _model_output_sink(signals, rule_id="nhi_llm_output_sql_sink", path=path, line_number=number, line=line, title="LLM output to SQL", sink="database", external_access=True)
        if HTML_RE.search(line) and "sanitize" not in lowered and "bleach" not in lowered and "dompurify" not in lowered:
            _model_output_sink(signals, rule_id="nhi_llm_output_html_sink", path=path, line_number=number, line=line, title="LLM output to HTML", sink="html")
        if TRUST_REMOTE_RE.search(line):
            signals.append(
                make_signal(
                    rule_id="nhi_model_trust_remote_code",
                    file_path=path,
                    line_number=number,
                    name="trust_remote_code model load",
                    identity_type="model_artifact",
                    source="model supply-chain code",
                    evidence=line.strip(),
                    admin_access=True,
                    external_access=True,
                    tags=["model_supply_chain", "remote_code"],
                    ai_attack_class="model supply chain",
                    attack_chain_stage="model load",
                    confidence="high",
                )
            )
        if FROM_PRETRAINED_RE.search(line) and "revision=" not in line and "commit_hash" not in line and "sha" not in line:
            signals.append(
                make_signal(
                    rule_id="nhi_model_unpinned_revision",
                    file_path=path,
                    line_number=number,
                    name="unpinned model revision",
                    identity_type="model_artifact",
                    source="model supply-chain code",
                    evidence=line.strip(),
                    external_access=True,
                    tags=["model_supply_chain", "unpinned_model"],
                    ai_attack_class="model supply chain",
                    attack_chain_stage="model load",
                    confidence="medium",
                )
            )
        if MODEL_URL_RE.search(line) and not any(pin in line.lower() for pin in ["revision=", "sha256:", "commit=", "refs/pr/"]):
            signals.append(
                make_signal(
                    rule_id="nhi_model_unpinned_revision",
                    file_path=path,
                    line_number=number,
                    name="unpinned model URL",
                    identity_type="model_artifact",
                    source="model supply-chain config",
                    evidence=line.strip(),
                    external_access=True,
                    tags=["model_supply_chain", "unpinned_model"],
                    ai_attack_class="model supply chain",
                    attack_chain_stage="model load",
                    confidence="medium",
                )
            )

    if TOOL_CALL_RE.search(text) and not SCHEMA_RE.search(text):
        signals.append(
            make_signal(
                rule_id="nhi_llm_function_call_without_schema",
                file_path=path,
                line_number=_line_number(text, "tool_call") or _line_number(text, "function_call"),
                name=f"{path.stem} tool call validation",
                identity_type="ai_agent",
                source="AI code flow",
                evidence="LLM tool/function call handling appears without visible schema validation",
                tools=["function_call"],
                tags=["ai_code_flow", "tool_call", "schema_validation"],
                ai_attack_class="improper output handling",
                attack_chain_stage="tool arguments",
                confidence="medium",
            )
        )

    if AUTONOMOUS_ACTION_RE.search(text) and MODEL_OUTPUT_RE.search(text) and not any(marker in lowered for marker in ["approval", "human_review", "requires_confirmation", "manual gate", "confirm"]):
        signals.append(
            make_signal(
                rule_id="nhi_llm_autonomous_action_without_gate",
                file_path=path,
                line_number=_line_number(text, "deploy") or _line_number(text, "send_email") or _line_number(text, "merge"),
                name=f"{path.stem} autonomous AI action",
                identity_type="ai_agent",
                source="AI code flow",
                evidence="Model output appears able to trigger external or state-changing actions without approval evidence",
                tools=["github", "email", "deployment"],
                admin_access=True,
                external_access=True,
                approval_required=False,
                tags=["ai_code_flow", "autonomous_action", "privileged_sink"],
                ai_attack_class="excessive agency",
                attack_chain_stage="tool/sink",
                confidence="high",
            )
        )

    if MODEL_GATEWAY_RE.search(text):
        if not LOGGING_RE.search(text):
            signals.append(
                make_signal(
                    rule_id="nhi_model_gateway_unlogged_routing",
                    file_path=path,
                    line_number=_line_number(text, "litellm") or _line_number(text, "fallback") or _line_number(text, "router"),
                    name=f"{path.stem} model gateway logging",
                    identity_type="model_gateway",
                    source="model gateway config",
                    evidence="Model gateway or router config lacks visible logging/audit settings",
                    external_access=True,
                    logging_enabled=False,
                    tags=["model_gateway", "ai_gateway"],
                    ai_attack_class="model supply chain",
                    attack_chain_stage="model gateway",
                    confidence="medium",
                )
            )
        if "fallback" in lowered and not POLICY_RE.search(text):
            signals.append(
                make_signal(
                    rule_id="nhi_model_provider_fallback_without_policy",
                    file_path=path,
                    line_number=_line_number(text, "fallback"),
                    name=f"{path.stem} provider fallback policy",
                    identity_type="model_gateway",
                    source="model gateway config",
                    evidence="Model provider fallback was found without visible provider policy controls",
                    external_access=True,
                    tags=["model_gateway", "provider_fallback"],
                    ai_attack_class="model supply chain",
                    attack_chain_stage="model gateway",
                    confidence="medium",
                )
            )

    if AI_PROVIDER_RE.search(text) and not LIMIT_RE.search(text):
        signals.append(
            make_signal(
                rule_id="nhi_ai_provider_unbounded_consumption",
                file_path=path,
                line_number=_line_number(text, "OPENAI_API_KEY") or _line_number(text, "litellm") or _line_number(text, "ANTHROPIC_API_KEY"),
                name=f"{path.stem} AI provider consumption controls",
                identity_type="api_key",
                source="AI provider config",
                evidence="AI provider or gateway credentials appear without visible budget, rate, timeout, or loop limits",
                external_access=True,
                tags=["ai_provider", "unbounded_consumption"],
                ai_attack_class="unbounded consumption",
                attack_chain_stage="credential",
                confidence="medium",
            )
        )

    if any(marker in lowered for marker in ["vllm", "text-generation-inference", "tgi", "ollama", "model-server"]) and "image:" in lowered and "sha256:" not in lowered:
        signals.append(
            make_signal(
                rule_id="nhi_model_container_unpinned_digest",
                file_path=path,
                line_number=_line_number(text, "image:"),
                name=f"{path.stem} model serving image",
                identity_type="model_gateway",
                source="model supply-chain config",
                evidence="Model-serving container image appears without sha256 digest pin",
                external_access=True,
                tags=["model_supply_chain", "container"],
                ai_attack_class="model supply chain",
                attack_chain_stage="model serving",
                confidence="medium",
            )
        )

    return signals
