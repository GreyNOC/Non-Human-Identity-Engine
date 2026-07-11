from greynoc_nhi.owasp_mapping import OWASP_NHI_TOP_10, RULE_TO_OWASP, map_rule_to_owasp


def test_owasp_mapping_secret_leakage():
    assert "NHI2:2025" in map_rule_to_owasp("nhi_secret_leakage")


def test_owasp_mapping_ai_mcp_bridge():
    assert "NHI10:2025" in map_rule_to_owasp("nhi_ai_mcp_privilege_bridge")


def test_owasp_mapping_unknown_rule_returns_empty_list():
    assert map_rule_to_owasp("nhi_rule_that_does_not_exist") == []


def test_all_mapped_refs_are_valid_nhi_top_10_entries():
    for rule_id, refs in RULE_TO_OWASP.items():
        assert refs, f"{rule_id} maps to an empty ref list"
        for ref in refs:
            assert ref in OWASP_NHI_TOP_10, f"{rule_id} maps to unknown ref {ref}"


def test_owasp_mapping_package_registry_rules_include_supply_chain():
    for rule_id in [
        "nhi_npm_registry_token_in_npmrc",
        "nhi_pypi_token_in_pypirc",
        "nhi_cargo_registry_token",
        "nhi_gradle_repository_credential",
    ]:
        refs = map_rule_to_owasp(rule_id)
        assert "NHI2:2025" in refs
        assert "NHI3:2025" in refs


def test_owasp_mapping_gitlab_ci_environment_rules():
    assert "NHI8:2025" in map_rule_to_owasp("nhi_gitlab_ci_unprotected_environment")
    assert "NHI8:2025" in map_rule_to_owasp("nhi_gitlab_ci_deployment_without_protected_check")


def test_owasp_mapping_terraform_state_includes_long_lived_secrets():
    refs = map_rule_to_owasp("nhi_terraform_state_plaintext_secret")
    assert "NHI2:2025" in refs
    assert "NHI7:2025" in refs


def test_owasp_mapping_history_secret_still_current():
    refs = map_rule_to_owasp("nhi_history_secret_still_current")
    assert "NHI2:2025" in refs
    assert "NHI7:2025" in refs
