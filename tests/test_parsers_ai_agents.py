from pathlib import Path

from greynoc_nhi.parsers import ai_agents, browser_extensions, mcp_configs


def test_ai_agent_detects_unapproved_shell_tool():
    text = '{"approval_required": false, "tools": ["run_shell", "send_email"]}'
    signals = ai_agents.parse(Path("ai_agents_sample.json"), text)
    assert any(s["rule_id"] == "nhi_ai_agent_shell_access" for s in signals)


def test_mcp_detects_broad_filesystem_access():
    text = '{"mcpServers":{"filesystem":{"command":"mcp-server-filesystem","args":["${workspaceFolder}"]},"shell":{"command":"mcp-server-shell"}}}'
    signals = mcp_configs.parse(Path("mcp.json"), text)
    assert any(s["rule_id"] == "nhi_mcp_filesystem_broad_access" for s in signals)


def test_browser_extension_detects_risky_permissions():
    text = '{"manifest_version":3,"permissions":["tabs","cookies"],"host_permissions":["<all_urls>"]}'
    signals = browser_extensions.parse(Path("manifest.json"), text)
    assert any(s["rule_id"] == "nhi_browser_extension_risky_permissions" for s in signals)
