from pathlib import Path
from tempfile import mkdtemp

from greynoc_nhi.advanced import synthesize_advanced_signals
from greynoc_nhi.engine import Engine, normalize_signal
from greynoc_nhi.sample_data import sample_project_path


def test_advanced_detects_ai_mcp_privilege_bridge():
    identities = [
        normalize_signal(
            {
                "rule_id": "nhi_ai_agent_shell_access",
                "file_path": "agent.json",
                "line_number": None,
                "name": "agent",
                "identity_type": "AI agent tool connector",
                "source": "test",
                "evidence": ["Approval gate disabled for tools: run_shell"],
                "tools": ["run_shell"],
                "approval_required": False,
                "tags": ["ai_agent"],
            }
        ),
        normalize_signal(
            {
                "rule_id": "nhi_mcp_server_high_risk_tool_access",
                "file_path": "mcp.json",
                "line_number": None,
                "name": "mcp",
                "identity_type": "MCP server connector",
                "source": "test",
                "evidence": ["MCP exposes high-risk tools: shell"],
                "tools": ["shell"],
                "tags": ["mcp"],
            }
        ),
    ]
    signals = synthesize_advanced_signals(identities, {"project_path": "."})
    assert any(signal["rule_id"] == "nhi_ai_mcp_privilege_bridge" for signal in signals)


def test_advanced_detects_secret_sprawl_same_file():
    identities = [
        normalize_signal(
            {
                "rule_id": "nhi_secret_leakage",
                "file_path": ".env",
                "line_number": idx,
                "name": f"SECRET_{idx}",
                "identity_type": "API key",
                "source": "test",
                "evidence": [f"SECRET_{idx}=GNOC...{idx}"],
                "secret_value": f"GNOC_FAKE_SECRET_DO_NOT_USE_{idx}",
                "tags": ["plaintext_secret"],
            }
        )
        for idx in range(3)
    ]
    signals = synthesize_advanced_signals(identities, {"project_path": "."})
    assert any(signal["rule_id"] == "nhi_secret_sprawl_same_file" for signal in signals)


def test_engine_sample_project_includes_advanced_correlations():
    temp_dir = mkdtemp(prefix="greynoc_nhi_test_")
    result = Engine(Path(temp_dir) / "advanced.sqlite3").run_scan(sample_project_path())
    rule_ids = {finding.rule_id for finding in result.findings}
    assert "nhi_ai_mcp_privilege_bridge" in rule_ids
    assert "nhi_untrusted_ci_deploy_path" in rule_ids
    assert result.stats["advanced_correlations"] >= 5
