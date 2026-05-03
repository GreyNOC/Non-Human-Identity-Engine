"""Kubernetes YAML parser."""

from __future__ import annotations

from pathlib import Path

from greynoc_nhi.parsers.base import Signal, make_signal


def should_parse(path: Path) -> bool:
    return path.suffix.lower() in {".yaml", ".yml"} and any(token in path.name.lower() for token in ["k8s", "kube", "deployment", "service"])


def parse(path: Path, text: str) -> list[Signal]:
    signals: list[Signal] = []
    lower = text.lower()
    if "kind: secret" in lower:
        signals.append(make_signal(rule_id="nhi_secret_leakage", file_path=path, line_number=None, name="Kubernetes Secret", identity_type="service account", source="kubernetes", evidence="Kubernetes Secret object present", tags=["kubernetes", "plaintext_secret"]))
    if "automountserviceaccounttoken: true" in lower:
        signals.append(make_signal(rule_id="nhi_kubernetes_automount_token", file_path=path, line_number=next((i for i, l in enumerate(text.splitlines(), 1) if "automountServiceAccountToken" in l), None), name="Kubernetes service account token", identity_type="service account", source="kubernetes", evidence="automountServiceAccountToken: true", provider="kubernetes", permissions=["service-account-token"], production_access="prod" in lower, tags=["kubernetes"]))
    if "privileged: true" in lower:
        signals.append(make_signal(rule_id="nhi_docker_privileged_container", file_path=path, line_number=None, name="Privileged Kubernetes container", identity_type="service account", source="kubernetes", evidence="privileged: true", admin_access=True, tags=["kubernetes", "privileged"]))
    if "hostpath:" in lower:
        signals.append(make_signal(rule_id="nhi_overprivileged_nhi", file_path=path, line_number=None, name="Kubernetes hostPath mount", identity_type="service account", source="kubernetes", evidence="hostPath mount present", admin_access=True, tags=["kubernetes", "host_access"]))
    if "cluster-admin" in lower:
        signals.append(make_signal(rule_id="nhi_kubernetes_cluster_admin", file_path=path, line_number=None, name="cluster-admin binding", identity_type="service account", source="kubernetes", evidence="cluster-admin role binding", provider="kubernetes", permissions=["cluster-admin"], admin_access=True, tags=["kubernetes", "admin_policy"]))
    return signals
