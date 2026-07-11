"""Kubernetes YAML parser."""

from __future__ import annotations

__version__ = 2

import re
from pathlib import Path

from greynoc_nhi.masking import looks_like_secret
from greynoc_nhi.parsers.base import Signal, make_signal

ENV_BLOCK_RE = re.compile(r"^\s*env\s*:\s*$")
ENV_NAME_RE = re.compile(r"^\s*-\s+name\s*:\s*['\"]?([A-Za-z_][\w.-]*)['\"]?\s*$")
ENV_VALUE_RE = re.compile(r"^\s*value\s*:\s*(?:['\"]?)([^#\n]*?)(?:['\"]?)\s*$")
SECRET_ENV_NAME_RE = re.compile(
    r"(secret|token|password|passwd|api[_-]?key|client[_-]?secret|private[_-]?key|credential)",
    re.IGNORECASE,
)
RUN_AS_ROOT_RE = re.compile(r"runasuser\s*:\s*0\b")

def should_parse(path: Path) -> bool:
    return path.suffix.lower() in {".yaml", ".yml"}

def parse(path: Path, text: str) -> list[Signal]:
    # Cheap manifest gate: every Kubernetes object carries apiVersion/kind,
    # so non-manifest YAML (workflows, compose, values) exits immediately.
    if "apiVersion" not in text and "kind:" not in text:
        return []
    signals: list[Signal] = []
    lower = text.lower()
    lines = text.splitlines()
    lower_lines = [line.lower() for line in lines]

    def first_line(needle: str) -> int | None:
        return next((i for i, ln in enumerate(lower_lines, 1) if needle in ln), None)

    if "kind: secret" in lower:
        signals.append(make_signal(rule_id="nhi_secret_leakage", file_path=path, line_number=first_line("kind: secret"), name="Kubernetes Secret", identity_type="service account", source="kubernetes", evidence="Kubernetes Secret object present", tags=["kubernetes", "plaintext_secret"]))
    if "automountserviceaccounttoken: true" in lower:
        signals.append(make_signal(rule_id="nhi_kubernetes_automount_token", file_path=path, line_number=first_line("automountserviceaccounttoken"), name="Kubernetes service account token", identity_type="service account", source="kubernetes", evidence="automountServiceAccountToken: true", provider="kubernetes", permissions=["service-account-token"], production_access="prod" in lower, tags=["kubernetes"]))
    if "privileged: true" in lower:
        signals.append(make_signal(rule_id="nhi_docker_privileged_container", file_path=path, line_number=first_line("privileged:"), name="Privileged Kubernetes container", identity_type="service account", source="kubernetes", evidence="privileged: true", admin_access=True, tags=["kubernetes", "privileged"]))
    if "hostpath:" in lower:
        signals.append(make_signal(rule_id="nhi_overprivileged_nhi", file_path=path, line_number=first_line("hostpath:"), name="Kubernetes hostPath mount", identity_type="service account", source="kubernetes", evidence="hostPath mount present", admin_access=True, tags=["kubernetes", "host_access"]))
    if "cluster-admin" in lower:
        signals.append(make_signal(rule_id="nhi_kubernetes_cluster_admin", file_path=path, line_number=first_line("cluster-admin"), name="cluster-admin binding", identity_type="service account", source="kubernetes", evidence="cluster-admin role binding", provider="kubernetes", permissions=["cluster-admin"], admin_access=True, tags=["kubernetes", "admin_policy"]))
    if "hostnetwork: true" in lower or "hostpid: true" in lower:
        needle = "hostnetwork: true" if "hostnetwork: true" in lower else "hostpid: true"
        signals.append(make_signal(rule_id="nhi_overprivileged_nhi", file_path=path, line_number=first_line(needle), name="Kubernetes host namespace access", identity_type="service account", source="kubernetes", evidence="hostNetwork/hostPID enabled", admin_access=True, tags=["kubernetes", "host_access"]))
    root_match = RUN_AS_ROOT_RE.search(lower)
    if root_match:
        signals.append(make_signal(rule_id="nhi_overprivileged_nhi", file_path=path, line_number=first_line("runasuser"), name="Kubernetes container runs as root", identity_type="service account", source="kubernetes", evidence="runAsUser: 0 (container runs as root)", admin_access=True, tags=["kubernetes", "privileged"]))
    env_indent: int | None = None
    pending_name: str | None = None
    for number, line in enumerate(lines, 1):
        bare = line.split("#", 1)[0]
        stripped = bare.strip()
        if not stripped:
            continue
        indent = len(bare) - len(bare.lstrip(" "))
        if ENV_BLOCK_RE.match(bare):
            env_indent = indent
            pending_name = None
            continue
        if env_indent is None:
            continue
        if indent <= env_indent:
            env_indent = None
            pending_name = None
            continue
        name_match = ENV_NAME_RE.match(bare)
        if name_match:
            pending_name = name_match.group(1)
            continue
        value_match = ENV_VALUE_RE.match(bare)
        if value_match and pending_name and SECRET_ENV_NAME_RE.search(pending_name):
            value = value_match.group(1).strip()
            if value and not value.startswith("$") and not value.startswith("{{") and looks_like_secret(value):
                signals.append(
                    make_signal(
                        rule_id="nhi_kubernetes_env_plaintext_secret",
                        file_path=path,
                        line_number=number,
                        name=pending_name,
                        identity_type="service account",
                        source="kubernetes",
                        evidence=stripped,
                        secret_value=value,
                        provider="kubernetes",
                        production_access="prod" in lower,
                        tags=["kubernetes", "plaintext_secret"],
                    )
                )
            pending_name = None
    return signals
