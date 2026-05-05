"""OWASP Non-Human Identities Top 10 2025 mappings."""

from __future__ import annotations

OWASP_NHI_TOP_10 = {
    "NHI1:2025": "Improper Offboarding",
    "NHI2:2025": "Secret Leakage",
    "NHI3:2025": "Vulnerable Third-Party NHI",
    "NHI4:2025": "Insecure Authentication",
    "NHI5:2025": "Overprivileged NHI",
    "NHI6:2025": "Insecure Cloud Deployment Configurations",
    "NHI7:2025": "Long-Lived Secrets",
    "NHI8:2025": "Environment Isolation",
    "NHI9:2025": "NHI Reuse",
    "NHI10:2025": "Human Use of NHI",
}

RULE_TO_OWASP = {
    "nhi_secret_leakage": ["NHI2:2025"],
    "nhi_plaintext_env_secret": ["NHI2:2025"],
    "nhi_hardcoded_secret": ["NHI2:2025"],
    "nhi_database_url_with_credentials": ["NHI2:2025", "NHI8:2025"],
    "nhi_private_key_detected": ["NHI2:2025", "NHI4:2025"],
    "nhi_cloud_key_detected": ["NHI2:2025", "NHI6:2025"],
    "nhi_github_token_detected": ["NHI2:2025", "NHI5:2025"],
    "nhi_ai_provider_key_detected": ["NHI2:2025"],
    "nhi_payment_key_detected": ["NHI2:2025"],
    "nhi_webhook_secret_exposed": ["NHI2:2025", "NHI3:2025"],
    "nhi_oauth_client_secret_present": ["NHI2:2025", "NHI4:2025"],
    "nhi_broad_oauth_scope": ["NHI5:2025"],
    "nhi_overprivileged_nhi": ["NHI5:2025"],
    "nhi_long_lived_secret": ["NHI7:2025"],
    "nhi_no_rotation_policy": ["NHI7:2025"],
    "nhi_environment_isolation_failure": ["NHI8:2025"],
    "nhi_nhi_reuse_suspected": ["NHI9:2025"],
    "nhi_human_use_of_nhi_suspected": ["NHI10:2025"],
    "nhi_ci_cd_broad_permissions": ["NHI5:2025"],
    "nhi_github_actions_write_all": ["NHI5:2025"],
    "nhi_github_actions_unpinned_action": ["NHI3:2025"],
    "nhi_github_actions_pull_request_target_secrets": ["NHI2:2025", "NHI3:2025"],
    "nhi_cloud_admin_policy": ["NHI5:2025", "NHI6:2025"],
    "nhi_kubernetes_cluster_admin": ["NHI5:2025", "NHI6:2025"],
    "nhi_kubernetes_automount_token": ["NHI4:2025", "NHI6:2025"],
    "nhi_docker_privileged_container": ["NHI6:2025"],
    "nhi_docker_socket_mount": ["NHI5:2025", "NHI6:2025"],
    "nhi_browser_extension_risky_permissions": ["NHI5:2025"],
    "nhi_ai_agent_unapproved_tool_access": ["NHI5:2025", "NHI10:2025"],
    "nhi_ai_agent_sensitive_data_access": ["NHI5:2025"],
    "nhi_ai_agent_shell_access": ["NHI5:2025", "NHI10:2025"],
    "nhi_mcp_server_high_risk_tool_access": ["NHI5:2025"],
    "nhi_mcp_filesystem_broad_access": ["NHI5:2025"],
    "nhi_service_account_key_file": ["NHI2:2025", "NHI7:2025"],
    "nhi_missing_owner": ["NHI1:2025"],
    "nhi_missing_logging_evidence": ["NHI1:2025", "NHI4:2025"],
    "nhi_secret_sprawl_same_file": ["NHI2:2025", "NHI9:2025"],
    "nhi_identity_exposure_chain": ["NHI5:2025", "NHI8:2025", "NHI9:2025"],
    "nhi_ai_mcp_privilege_bridge": ["NHI5:2025", "NHI10:2025"],
    "nhi_untrusted_ci_deploy_path": ["NHI2:2025", "NHI3:2025", "NHI5:2025"],
    "nhi_build_pipeline_secret_sink": ["NHI2:2025", "NHI6:2025"],
    "nhi_shadow_admin_path": ["NHI5:2025", "NHI6:2025"],
    "nhi_customer_data_secret_coupling": ["NHI2:2025", "NHI5:2025"],
    "nhi_orphaned_identity_cluster": ["NHI1:2025"],
    "nhi_production_without_approval_gate": ["NHI8:2025", "NHI10:2025"],
    "nhi_secret_file_not_gitignored": ["NHI2:2025"],
    "nhi_package_registry_token_detected": ["NHI2:2025", "NHI3:2025"],
    "nhi_deployment_platform_token_detected": ["NHI2:2025", "NHI8:2025"],
    "nhi_monitoring_dsn_exposed": ["NHI3:2025"],
    "nhi_encoded_registry_auth_detected": ["NHI2:2025", "NHI3:2025"],
    "nhi_bearer_token_detected": ["NHI2:2025", "NHI4:2025"],
    "nhi_jwt_detected": ["NHI2:2025", "NHI4:2025"],
}


def map_rule_to_owasp(rule_id: str) -> list[str]:
    """Return OWASP NHI references for a rule id."""
    return RULE_TO_OWASP.get(rule_id, [])


def describe_ref(ref: str) -> str:
    """Return a human-readable OWASP NHI category label."""
    return OWASP_NHI_TOP_10.get(ref, ref)
