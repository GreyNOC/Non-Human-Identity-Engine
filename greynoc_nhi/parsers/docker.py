"""Docker and Compose parser."""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal

COMPOSE_FILE_NAMES = {"compose.yaml", "compose.yml"}
GATEWAY_MARKERS = ["litellm", "openai-compatible", "openai_compatible", "ollama", "vllm", "text-generation-inference", "model-gateway", "model_gateway"]
GATEWAY_LINE_MARKERS = ["litellm", "ollama", "vllm", "openai"]
ENV_SECRET_RE = re.compile(
    r"(?i)^(ENV|ARG)\s+([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|API_KEY|PRIVATE_KEY)[A-Z0-9_]*)(?:[=\s]+(.*))?$"
)
CURL_PIPE_RE = re.compile(r"(?i)\b(?:curl|wget)\b[^\n|]*\|\s*(?:ba|z|k)?sh\b")
ADD_URL_RE = re.compile(r"(?i)^ADD\s+https?://")
RUN_OR_COMMAND_RE = re.compile(r"(?i)^(?:RUN\b|(?:-\s+)?command\s*:)")

def should_parse(path: Path) -> bool:
    name = path.name.lower()
    if name.startswith("dockerfile") and not name.endswith((".md", ".txt")):
        return True
    return name.startswith("docker-compose") or name in COMPOSE_FILE_NAMES or path.suffix.lower() in {".dockerfile"}

def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    lower = text.lower()
    lines = text.splitlines()
    if any(marker in lower for marker in GATEWAY_MARKERS):
        signals.append(
            make_signal(
                rule_id="nhi_model_gateway_detected",
                file_path=path,
                line_number=next((i for i, ln in enumerate(lines, 1) if any(marker in ln.lower() for marker in GATEWAY_LINE_MARKERS)), None),
                name="Docker model gateway service",
                identity_type="model_gateway",
                source="docker compose",
                evidence="Docker service appears to run an AI model gateway or OpenAI-compatible API",
                provider="litellm" if "litellm" in lower else None,
                external_access=True,
                production_access="prod" in lower or "production" in lower,
                data_classes=["ai_prompts"],
                tags=["model_gateway", "docker"],
                confidence="high",
            )
        )
    for number, line in enumerate(lines, 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        env_match = ENV_SECRET_RE.match(stripped)
        if env_match:
            value = (env_match.group(3) or "").strip().strip("'\"")
            if not value:
                signals.append(
                    make_signal(
                        rule_id="nhi_plaintext_env_secret",
                        file_path=path,
                        line_number=number,
                        name="Docker secret variable",
                        identity_type="automation script credential",
                        source="docker",
                        evidence=f"{stripped} (secret-named build/env declaration without literal value; passed build args persist in image history)",
                        tags=["docker", "plaintext_secret"],
                        confidence="low",
                    )
                )
            elif not value.startswith(("$", "/", "./")) and looks_like_secret(value):
                signals.append(
                    make_signal(
                        rule_id="nhi_plaintext_env_secret",
                        file_path=path,
                        line_number=number,
                        name="Docker secret variable",
                        identity_type="automation script credential",
                        source="docker",
                        evidence=stripped,
                        secret_value=value,
                        tags=["docker", "plaintext_secret"],
                    )
                )
        if RUN_OR_COMMAND_RE.match(stripped) and CURL_PIPE_RE.search(stripped):
            signals.append(
                make_signal(
                    rule_id="nhi_docker_remote_script_execution",
                    file_path=path,
                    line_number=number,
                    name="Remote script piped to shell",
                    identity_type="automation script credential",
                    source="docker",
                    evidence=stripped,
                    external_access=True,
                    tags=["docker", "remote_script"],
                )
            )
        if ADD_URL_RE.match(stripped):
            signals.append(
                make_signal(
                    rule_id="nhi_docker_add_remote_url",
                    file_path=path,
                    line_number=number,
                    name="ADD fetches remote URL",
                    identity_type="automation script credential",
                    source="docker",
                    evidence=stripped,
                    external_access=True,
                    tags=["docker", "remote_content"],
                )
            )
        if "privileged:" in stripped.lower() and "true" in stripped.lower():
            signals.append(
                make_signal(
                    rule_id="nhi_docker_privileged_container",
                    file_path=path,
                    line_number=number,
                    name="Privileged container",
                    identity_type="automation script credential",
                    source="docker",
                    evidence=stripped,
                    admin_access=True,
                    tags=["docker", "privileged"],
                )
            )
        if "/var/run/docker.sock" in stripped:
            signals.append(
                make_signal(
                    rule_id="nhi_docker_socket_mount",
                    file_path=path,
                    line_number=number,
                    name="Docker socket mount",
                    identity_type="automation script credential",
                    source="docker",
                    evidence=stripped,
                    admin_access=True,
                    tags=["docker", "host_access"],
                )
            )
    return signals
