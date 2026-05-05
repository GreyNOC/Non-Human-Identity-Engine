"""Confidence helpers for local-only NHI detections."""

from __future__ import annotations

import re

CONFIDENCE_LEVELS = {"high", "medium", "low"}

HIGH_CONFIDENCE_RULES = {
    "nhi_private_key_detected",
    "nhi_service_account_key_file",
    "nhi_github_actions_write_all",
    "nhi_github_actions_pull_request_target_secrets",
    "nhi_kubernetes_cluster_admin",
    "nhi_docker_socket_mount",
    "nhi_mcp_filesystem_broad_access",
    "nhi_mcp_server_high_risk_tool_access",
    "nhi_ai_mcp_privilege_bridge",
    "nhi_untrusted_ci_deploy_path",
    "nhi_shadow_admin_path",
}

PROVIDER_SPECIFIC_RULES = {
    "nhi_cloud_key_detected",
    "nhi_github_token_detected",
    "nhi_ai_provider_key_detected",
    "nhi_payment_key_detected",
    "nhi_package_registry_token_detected",
    "nhi_deployment_platform_token_detected",
    "nhi_encoded_registry_auth_detected",
    "nhi_bearer_token_detected",
    "nhi_jwt_detected",
}

PLACEHOLDER_RE = re.compile(
    r"^(?:changeme|change-me|example|example[_-]?key|dummy|fake|test|token|password|secret|your[_-]?api[_-]?key|replace[_-]?me|<[^>]+>|\$\{[^}]+\}|\$[A-Za-z_][A-Za-z0-9_]*)$",
    re.IGNORECASE,
)


def normalize_confidence(value: str | None) -> str:
    if value and value.lower() in CONFIDENCE_LEVELS:
        return value.lower()
    return "medium"


def is_placeholder_value(value: object) -> bool:
    text = str(value).strip().strip("'\"")
    if not text:
        return True
    if "GNOC_FAKE_SECRET_DO_NOT_USE" in text:
        return False
    if text.startswith("${{") and text.endswith("}}"):
        return True
    if "localhost" in text.lower() and not any(marker in text for marker in ["@", "://"]):
        return True
    if PLACEHOLDER_RE.match(text):
        return True
    lowered = text.lower()
    weak_words = ["changeme", "change-me", "replace_me", "replace-me", "your-api-key", "example", "dummy"]
    return any(word in lowered for word in weak_words)


def should_suppress_candidate(name: str | None, value: object) -> bool:
    text = str(value).strip()
    if "GNOC_FAKE_SECRET_DO_NOT_USE" in text:
        return False
    if not is_placeholder_value(text):
        return False
    key = (name or "").lower()
    sensitive_context = any(token in key for token in ["secret", "token", "password", "api", "key", "client"])
    return not sensitive_context


def infer_confidence(rule_id: str, evidence: str = "", secret_value: object | None = None, explicit: str | None = None) -> str:
    if explicit:
        return normalize_confidence(explicit)
    if secret_value is not None and is_placeholder_value(secret_value):
        return "low"
    if rule_id in HIGH_CONFIDENCE_RULES or rule_id in PROVIDER_SPECIFIC_RULES:
        return "high"
    if "private key block" in evidence.lower() or "cluster-admin" in evidence.lower() or "docker.sock" in evidence.lower():
        return "high"
    if rule_id in {"nhi_hardcoded_secret", "nhi_secret_leakage", "nhi_monitoring_dsn_exposed"}:
        return "medium"
    return "medium"
