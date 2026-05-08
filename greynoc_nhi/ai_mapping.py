"""AI attack taxonomy mappings for agentic and LLM application findings."""

from __future__ import annotations

OWASP_LLM_TOP_10_2025 = {
    "LLM01:2025": "Prompt Injection",
    "LLM02:2025": "Sensitive Information Disclosure",
    "LLM03:2025": "Supply Chain",
    "LLM04:2025": "Data and Model Poisoning",
    "LLM05:2025": "Improper Output Handling",
    "LLM06:2025": "Excessive Agency",
    "LLM07:2025": "System Prompt Leakage",
    "LLM08:2025": "Vector and Embedding Weaknesses",
    "LLM09:2025": "Misinformation",
    "LLM10:2025": "Unbounded Consumption",
}

OWASP_AGENTIC_TOP_10 = {
    "ASI01": "Agent Goal Hijacking",
    "ASI02": "Tool Misuse",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution",
    "ASI06": "Memory and Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

NIST_AML_CATEGORIES = {
    "NIST-AML:Evasion": "Evasion",
    "NIST-AML:Poisoning": "Poisoning",
    "NIST-AML:Privacy": "Privacy",
    "NIST-AML:Misuse": "Misuse",
}

RULE_TO_AI_RISK = {
    "nhi_ai_agent_framework_detected": ["LLM06:2025"],
    "nhi_ai_agent_unapproved_tool_access": ["LLM06:2025", "ASI02", "ASI03"],
    "nhi_ai_agent_sensitive_data_access": ["LLM02:2025", "LLM06:2025", "ASI03", "NIST-AML:Privacy"],
    "nhi_ai_agent_shell_access": ["LLM06:2025", "ASI02", "ASI03", "ASI05"],
    "nhi_ai_agent_filesystem_access": ["LLM02:2025", "LLM06:2025", "ASI02", "ASI03"],
    "nhi_ai_agent_github_write_access": ["LLM06:2025", "ASI02", "ASI03"],
    "nhi_ai_mcp_privilege_bridge": ["LLM01:2025", "LLM06:2025", "ASI02", "ASI03"],
    "nhi_tool_connector_high_risk_access": ["LLM06:2025", "ASI02"],
    "nhi_model_gateway_detected": ["LLM02:2025", "LLM03:2025"],
    "nhi_ai_provider_key_detected": ["LLM02:2025", "LLM10:2025", "NIST-AML:Misuse"],
    "nhi_production_ai_key_in_env": ["LLM02:2025", "LLM10:2025", "NIST-AML:Misuse"],
    "nhi_prompt_artifact_prompt_injection": ["LLM01:2025", "ASI01", "NIST-AML:Misuse"],
    "nhi_prompt_artifact_system_prompt_leakage": ["LLM07:2025", "LLM02:2025", "ASI01", "NIST-AML:Privacy"],
    "nhi_prompt_artifact_sensitive_disclosure": ["LLM02:2025", "ASI01", "NIST-AML:Privacy"],
    "nhi_prompt_artifact_excessive_agency": ["LLM06:2025", "ASI02", "ASI03"],
    "nhi_prompt_artifact_hidden_instruction": ["LLM01:2025", "ASI01", "ASI06"],
    "nhi_prompt_contains_secret_or_credential": ["LLM02:2025", "NIST-AML:Privacy"],
    "nhi_mcp_unpinned_remote_server": ["LLM03:2025", "ASI04"],
    "nhi_mcp_package_install_without_pinning": ["LLM03:2025", "ASI04"],
    "nhi_mcp_remote_script_execution": ["LLM03:2025", "ASI04", "ASI05"],
    "nhi_mcp_writable_local_server_path": ["LLM03:2025", "ASI04", "ASI05"],
    "nhi_mcp_env_secret_passthrough": ["LLM02:2025", "ASI03", "NIST-AML:Privacy"],
    "nhi_mcp_unsafe_runtime_flag": ["LLM06:2025", "ASI02", "ASI03"],
    "nhi_mcp_toxic_tool_combination": ["LLM01:2025", "LLM06:2025", "ASI02", "ASI03"],
    "nhi_ai_tool_prompt_injection_description": ["LLM01:2025", "ASI01", "ASI02"],
    "nhi_ai_tool_shadowing": ["LLM03:2025", "ASI04"],
    "nhi_ai_tool_name_description_mismatch": ["LLM06:2025", "ASI02"],
    "nhi_ai_tool_untrusted_remote_source": ["LLM03:2025", "ASI04"],
    "nhi_ai_tool_sensitive_sink": ["LLM06:2025", "ASI02", "ASI03"],
    "nhi_ai_toxic_flow_untrusted_context_to_privileged_tool": ["LLM01:2025", "LLM06:2025", "ASI01", "ASI02", "ASI03"],
    "nhi_rag_untrusted_source_ingestion": ["LLM01:2025", "LLM04:2025", "LLM08:2025", "ASI06", "NIST-AML:Poisoning"],
    "nhi_rag_no_access_filter": ["LLM02:2025", "LLM08:2025", "NIST-AML:Privacy"],
    "nhi_rag_context_to_tool_bridge": ["LLM01:2025", "LLM06:2025", "LLM08:2025", "ASI02"],
    "nhi_vector_store_cross_tenant_risk": ["LLM02:2025", "LLM08:2025", "NIST-AML:Privacy"],
    "nhi_rag_poisoning_surface": ["LLM04:2025", "LLM08:2025", "ASI06", "NIST-AML:Poisoning"],
    "nhi_llm_output_exec_sink": ["LLM05:2025", "ASI05"],
    "nhi_llm_output_shell_sink": ["LLM05:2025", "LLM06:2025", "ASI02", "ASI05"],
    "nhi_llm_output_sql_sink": ["LLM05:2025", "NIST-AML:Misuse"],
    "nhi_llm_output_html_sink": ["LLM05:2025"],
    "nhi_llm_function_call_without_schema": ["LLM05:2025", "LLM06:2025", "ASI02"],
    "nhi_llm_autonomous_action_without_gate": ["LLM05:2025", "LLM06:2025", "ASI02", "ASI03"],
    "nhi_model_trust_remote_code": ["LLM03:2025", "ASI04", "ASI05"],
    "nhi_model_unpinned_revision": ["LLM03:2025", "ASI04"],
    "nhi_model_pickle_artifact": ["LLM03:2025", "ASI04", "ASI05"],
    "nhi_model_gateway_unlogged_routing": ["LLM02:2025", "LLM03:2025"],
    "nhi_model_provider_fallback_without_policy": ["LLM03:2025", "LLM09:2025"],
    "nhi_model_container_unpinned_digest": ["LLM03:2025", "ASI04"],
    "nhi_ai_provider_unbounded_consumption": ["LLM10:2025", "NIST-AML:Misuse"],
}


def map_rule_to_ai_risk(rule_id: str) -> list[str]:
    """Return AI attack taxonomy references for a rule id."""
    return RULE_TO_AI_RISK.get(rule_id, [])


def describe_ai_ref(ref: str) -> str:
    """Return a human-readable AI risk reference label."""
    if ref in OWASP_LLM_TOP_10_2025:
        return OWASP_LLM_TOP_10_2025[ref]
    if ref in OWASP_AGENTIC_TOP_10:
        return OWASP_AGENTIC_TOP_10[ref]
    return NIST_AML_CATEGORIES.get(ref, ref)
