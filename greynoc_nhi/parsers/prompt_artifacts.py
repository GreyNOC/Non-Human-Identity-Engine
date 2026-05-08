"""Prompt, agent instruction, and skill artifact parser."""

from __future__ import annotations

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal

PROMPT_FILE_NAMES = {
    "agent.md",
    "agents.md",
    "claude.md",
    "skill.md",
    "system_prompt",
    "developer_prompt",
    ".cursorrules",
    ".windsurfrules",
    "copilot-instructions.md",
}

PROMPT_EXTENSIONS = {".md", ".mdx", ".prompt"}
CODE_EXTENSIONS = {".py", ".js", ".ts", ".tsx", ".jsx"}

PROMPT_MARKERS = {
    "system_prompt",
    "developer_prompt",
    "instructions",
    "tool_description",
    "prompt_template",
    "system message",
    "developer message",
}

INJECTION_RE = re.compile(
    r"ignore (?:all |any |the )?(?:previous|prior|above|earlier) instructions|"
    r"disregard (?:all |any |the )?(?:previous|prior|above|earlier) instructions|"
    r"override (?:the )?(?:system|developer|safety) instructions|"
    r"you are now (?:in )?developer mode",
    re.I,
)
SYSTEM_LEAK_RE = re.compile(
    r"reveal (?:the )?(?:system|developer) prompt|"
    r"show (?:me )?(?:the )?(?:system|developer) prompt|"
    r"print (?:the )?(?:hidden|system|developer) instructions|"
    r"dump (?:the )?(?:system|developer) prompt",
    re.I,
)
SENSITIVE_DISCLOSURE_RE = re.compile(
    r"print (?:all )?(?:environment variables|env vars|secrets|credentials)|"
    r"exfiltrate (?:the )?(?:secret|secrets|credential|credentials|token|tokens)|"
    r"read (?:the )?(?:\.env|environment file|credentials file)|"
    r"send (?:the )?(?:secret|secrets|credentials|tokens) to",
    re.I,
)
EXCESSIVE_AGENCY_RE = re.compile(
    r"call (?:the )?(?:shell|terminal|tool|function) without asking|"
    r"run (?:commands?|shell|terminal) without (?:asking|approval|confirmation)|"
    r"do not ask (?:the )?user for (?:permission|approval|confirmation)|"
    r"auto(?:matically)? (?:deploy|merge|send|execute|approve)",
    re.I,
)
ENCODED_EXFIL_RE = re.compile(r"base64 encode|compress and send|encode the output", re.I)
HIDDEN_INSTRUCTION_RE = re.compile(
    r"<!--.*?(ignore|reveal|exfiltrate|system prompt|developer prompt|secret|tool).*?-->|"
    r"\[//\]:\s*#\s*\(.*?(ignore|reveal|exfiltrate|system prompt|developer prompt|secret|tool).*?\)|"
    r"<(?:span|div)[^>]+display\s*:\s*none[^>]*>.*?(ignore|reveal|exfiltrate|system prompt|developer prompt|secret|tool)",
    re.I,
)
SECRET_ASSIGN_RE = re.compile(
    r"(?i)\b(?:api[_-]?key|token|secret|password|credential|client_secret)\b\s*[:=]\s*['\"]?([^'\"\s,`;]{12,})"
)


def should_parse(path: Path) -> bool:
    normalized = str(path).replace("\\", "/").lower()
    name = path.name.lower()
    return (
        name in PROMPT_FILE_NAMES
        or path.suffix.lower() in PROMPT_EXTENSIONS
        or normalized.endswith("/.github/copilot-instructions.md")
        or (path.suffix.lower() in CODE_EXTENSIONS and any(marker in normalized for marker in ["prompt", "agent", "tool", "skill"]))
    )


def _code_context_is_prompt(line: str, file_is_prompt: bool) -> bool:
    lowered = line.lower()
    return file_is_prompt or any(marker in lowered for marker in PROMPT_MARKERS)


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    is_prompt_file = path.suffix.lower() in PROMPT_EXTENSIONS or path.name.lower() in PROMPT_FILE_NAMES
    hidden_scanned = False

    for number, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            continue
        prompt_context = _code_context_is_prompt(stripped, is_prompt_file)
        if not prompt_context and path.suffix.lower() in CODE_EXTENSIONS:
            continue

        if INJECTION_RE.search(stripped):
            signals.append(
                make_signal(
                    rule_id="nhi_prompt_artifact_prompt_injection",
                    file_path=path,
                    line_number=number,
                    name=f"{path.name} prompt instruction",
                    identity_type="ai_agent",
                    source="prompt artifact",
                    evidence=stripped,
                    tags=["prompt_artifact", "untrusted_context", "prompt_injection"],
                    ai_attack_class="prompt injection",
                    attack_chain_stage="untrusted input",
                    confidence="high",
                )
            )
        if SYSTEM_LEAK_RE.search(stripped):
            signals.append(
                make_signal(
                    rule_id="nhi_prompt_artifact_system_prompt_leakage",
                    file_path=path,
                    line_number=number,
                    name=f"{path.name} system prompt leakage request",
                    identity_type="ai_agent",
                    source="prompt artifact",
                    evidence=stripped,
                    tags=["prompt_artifact", "untrusted_context", "system_prompt_leakage"],
                    ai_attack_class="system prompt leakage",
                    attack_chain_stage="untrusted input",
                    confidence="high",
                )
            )
        if SENSITIVE_DISCLOSURE_RE.search(stripped) or ENCODED_EXFIL_RE.search(stripped):
            signals.append(
                make_signal(
                    rule_id="nhi_prompt_artifact_sensitive_disclosure",
                    file_path=path,
                    line_number=number,
                    name=f"{path.name} secret disclosure request",
                    identity_type="ai_agent",
                    source="prompt artifact",
                    evidence=stripped,
                    data_classes=["secrets"],
                    tags=["prompt_artifact", "untrusted_context", "sensitive_disclosure"],
                    ai_attack_class="sensitive information disclosure",
                    attack_chain_stage="untrusted input",
                    confidence="high",
                )
            )
        if EXCESSIVE_AGENCY_RE.search(stripped):
            signals.append(
                make_signal(
                    rule_id="nhi_prompt_artifact_excessive_agency",
                    file_path=path,
                    line_number=number,
                    name=f"{path.name} excessive agency instruction",
                    identity_type="ai_agent",
                    source="prompt artifact",
                    evidence=stripped,
                    tools=["shell"] if "shell" in stripped.lower() or "terminal" in stripped.lower() else [],
                    approval_required=False,
                    tags=["prompt_artifact", "untrusted_context", "excessive_agency"],
                    ai_attack_class="excessive agency",
                    attack_chain_stage="untrusted input",
                    confidence="high",
                )
            )
        secret_match = SECRET_ASSIGN_RE.search(stripped)
        if secret_match and looks_like_secret(secret_match.group(1)):
            signals.append(
                make_signal(
                    rule_id="nhi_prompt_contains_secret_or_credential",
                    file_path=path,
                    line_number=number,
                    name=f"{path.name} prompt credential",
                    identity_type="api_key",
                    source="prompt artifact",
                    evidence=stripped,
                    secret_value=secret_match.group(1),
                    data_classes=["secrets"],
                    tags=["prompt_artifact", "plaintext_secret"],
                    ai_attack_class="sensitive information disclosure",
                    attack_chain_stage="prompt/context",
                    confidence="high",
                )
            )

    if not hidden_scanned:
        hidden_scanned = True
        for match in HIDDEN_INSTRUCTION_RE.finditer(text):
            signals.append(
                make_signal(
                    rule_id="nhi_prompt_artifact_hidden_instruction",
                    file_path=path,
                    line_number=text.count("\n", 0, match.start()) + 1,
                    name=f"{path.name} hidden prompt instruction",
                    identity_type="ai_agent",
                    source="prompt artifact",
                    evidence=match.group(0),
                    tags=["prompt_artifact", "untrusted_context", "hidden_instruction"],
                    ai_attack_class="indirect prompt injection",
                    attack_chain_stage="untrusted input",
                    confidence="high",
                )
            )

    return signals
