from greynoc_nhi.owasp_mapping import map_rule_to_owasp


def test_owasp_mapping_secret_leakage():
    assert "NHI2:2025" in map_rule_to_owasp("nhi_secret_leakage")


def test_owasp_mapping_ai_mcp_bridge():
    assert "NHI10:2025" in map_rule_to_owasp("nhi_ai_mcp_privilege_bridge")
