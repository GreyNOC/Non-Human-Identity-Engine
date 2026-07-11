import json
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


def test_mcp_detects_remote_server_with_auth_headers():
    text = json.dumps(
        {
            "mcpServers": {
                "linear": {
                    "url": "https://mcp.linear.app/sse",
                    "headers": {"Authorization": "Bearer GNOC_FAKE_SECRET_DO_NOT_USE_LIN_123456"},
                }
            }
        }
    )
    signals = mcp_configs.parse(Path("mcp.json"), text)
    rule_ids = {s["rule_id"] for s in signals}
    assert "nhi_mcp_remote_server" in rule_ids
    assert "nhi_secret_leakage" in rule_ids
    remote = next(s for s in signals if s["rule_id"] == "nhi_mcp_remote_server")
    assert remote["external_access"] is True
    assert "secrets" in remote["data_classes"]
    leak = next(s for s in signals if s["rule_id"] == "nhi_secret_leakage")
    assert "GNOC_FAKE_SECRET_DO_NOT_USE_LIN_123456" not in " ".join(leak["evidence"])


def test_mcp_remote_server_detected_by_transport_type():
    text = json.dumps({"mcpServers": {"docs": {"type": "streamable-http", "url": "https://mcp.example.com/mcp"}}})
    signals = mcp_configs.parse(Path("mcp.json"), text)
    remote = [s for s in signals if s["rule_id"] == "nhi_mcp_remote_server"]
    assert len(remote) == 1
    assert remote[0]["data_classes"] == []


def test_mcp_stdio_server_is_not_flagged_as_remote():
    text = json.dumps({"mcpServers": {"local": {"command": "python", "args": ["server.py"]}}})
    signals = mcp_configs.parse(Path("mcp.json"), text)
    assert not any(s["rule_id"] == "nhi_mcp_remote_server" for s in signals)


def test_mcp_detects_credentialed_connection_string():
    text = json.dumps({"mcpServers": {"db": {"command": "npx", "env": {"DATABASE_URL": "postgresql://svc:GNOC-FAKE-SECRET-DO-NOT-USE-DB-1@db.internal:5432/app"}}}})
    signals = mcp_configs.parse(Path("mcp.json"), text)
    leaks = [s for s in signals if s["rule_id"] == "nhi_secret_leakage"]
    assert leaks
    assert "GNOC-FAKE-SECRET-DO-NOT-USE-DB-1" not in " ".join(leaks[0]["evidence"])


def test_mcp_env_reference_url_is_not_credential_leak():
    text = json.dumps({"mcpServers": {"db": {"command": "npx", "env": {"DATABASE_URL": "postgresql://svc:${DB_PASSWORD}@db.internal:5432/app"}}}})
    signals = mcp_configs.parse(Path("mcp.json"), text)
    assert not any(s["rule_id"] == "nhi_secret_leakage" for s in signals)


def test_mcp_should_parse_covers_current_config_locations():
    for candidate in [
        "cline_mcp_settings.json",
        "mcp_settings.json",
        ".claude.json",
        "librechat.yaml",
        "home/.gemini/settings.json",
        "project/.zed/settings.json",
        "home/.codex/config.toml",
    ]:
        assert mcp_configs.should_parse(Path(candidate)) is True, candidate
    assert mcp_configs.should_parse(Path("settings.json")) is False
    assert mcp_configs.should_parse(Path("random.json")) is False


def test_mcp_zed_context_servers_counts_as_mcp_config():
    text = json.dumps({"context_servers": {"terminal": {"command": "bash", "args": ["-lc", "run-server"]}}})
    signals = mcp_configs.parse(Path("project/.zed/settings.json"), text)
    assert any(s["rule_id"] == "nhi_mcp_server_high_risk_tool_access" for s in signals)


def test_mcp_codex_toml_config_produces_signals():
    text = (
        "[mcp_servers.docs]\n"
        'command = "npx"\n'
        'args = ["-y", "docs-mcp-server"]\n'
        "\n"
        "[mcp_servers.linear]\n"
        'url = "https://mcp.linear.app/sse"\n'
    )
    signals = mcp_configs.parse(Path("home/.codex/config.toml"), text)
    rule_ids = {s["rule_id"] for s in signals}
    assert "nhi_mcp_remote_server" in rule_ids
    assert "nhi_mcp_server_high_risk_tool_access" in rule_ids


def test_mcp_detects_modern_command_runners():
    text = json.dumps(
        {
            "mcpServers": {
                "fetch": {"command": "uv", "args": ["run", "mcp-server-fetch"]},
                "win": {"command": "cmd", "args": ["/c", "bunx", "some-server"]},
            }
        }
    )
    signals = mcp_configs.parse(Path("mcp.json"), text)
    high_risk = next(s for s in signals if s["rule_id"] == "nhi_mcp_server_high_risk_tool_access")
    assert "shell" in high_risk["tools"]


def test_mcp_scoped_filesystem_server_not_flagged_broad():
    text = json.dumps({"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/app/sandbox"]}}})
    signals = mcp_configs.parse(Path("mcp.json"), text)
    assert not any(s["rule_id"] == "nhi_mcp_filesystem_broad_access" for s in signals)


def test_mcp_home_scoped_filesystem_server_flagged_broad():
    text = json.dumps({"mcpServers": {"filesystem": {"command": "npx", "args": ["-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/home/user"]}}})
    signals = mcp_configs.parse(Path("mcp.json"), text)
    assert any(s["rule_id"] == "nhi_mcp_filesystem_broad_access" for s in signals)


def test_mcp_command_key_does_not_imply_shell_capability():
    text = json.dumps({"mcpServers": {"notes": {"command": "npx", "args": ["-y", "@example/notes-server@1.2.3"]}}})
    tools = mcp_configs._capabilities('mcpservers.notes.command=npx mcpservers.notes.args[0]=-y')
    assert "shell" not in tools
    signals = mcp_configs.parse(Path("mcp.json"), text)
    high_risk = [s for s in signals if s["rule_id"] == "nhi_mcp_server_high_risk_tool_access"]
    # Command runners still count as execution exposure, but no phantom
    # "shell" capability is inferred from the literal key name "command".
    assert high_risk


def test_mcp_github_com_url_is_not_github_capability():
    assert "github" not in mcp_configs._capabilities("source=https://github.com/owner/repo")
    assert "github" in mcp_configs._capabilities("mcpservers.github.command=node")


def test_ai_agent_detects_2025_frameworks():
    for text, provider in [
        ("from langgraph.graph import StateGraph", "langgraph"),
        ("from pydantic_ai import Agent", "pydantic_ai"),
        ("from smolagents import CodeAgent", "smolagents"),
        ("import { generateText } from '@ai-sdk/openai'", "vercel ai sdk"),
    ]:
        signals = ai_agents.parse(Path("app.py"), text)
        frameworks = [s for s in signals if s["rule_id"] == "nhi_ai_agent_framework_detected"]
        assert frameworks, provider
        assert provider in frameworks[0]["provider"], provider


def test_ai_agent_ignores_flag2_like_identifiers():
    signals = ai_agents.parse(Path("app.py"), "flag2 = True\nresult = flag2 and other")
    assert not any(s["rule_id"] == "nhi_ai_agent_framework_detected" for s in signals)


def test_litellm_proxy_config_yaml_detected_as_gateway():
    text = (
        "model_list:\n"
        "  - model_name: gpt-4o\n"
        "    litellm_params:\n"
        "      model: azure/gpt-4o\n"
        "      api_base: https://example.azure.com\n"
    )
    assert ai_agents.should_parse(Path("config.yaml")) is True
    signals = ai_agents.parse(Path("config.yaml"), text)
    assert any(s["rule_id"] == "nhi_model_gateway_detected" for s in signals)


def test_bare_ollama_import_is_not_a_model_gateway():
    text = "import ollama\n\nclient = ollama.Client()\nresponse = client.chat(model='llama3', messages=[])\n"
    signals = ai_agents.parse(Path("client.py"), text)
    assert not any(s["rule_id"] == "nhi_model_gateway_detected" for s in signals)


def test_ollama_with_gateway_structure_still_detected():
    text = "import ollama\nrouter_settings = {'model_list': ['llama3']}\n"
    signals = ai_agents.parse(Path("gateway.py"), text)
    assert any(s["rule_id"] == "nhi_model_gateway_detected" for s in signals)


def test_assistant_manifest_names_are_parsed():
    assert ai_agents.should_parse(Path("assistants.json")) is True
    assert ai_agents.should_parse(Path("gpts.json")) is True
    text = json.dumps(
        {
            "tools": [
                {
                    "type": "function",
                    "function": {"name": "deploy_service", "description": "Deploys the app to production kubernetes"},
                }
            ]
        }
    )
    signals = ai_agents.parse(Path("assistants.json"), text)
    assert any(s["rule_id"] == "nhi_ai_tool_sensitive_sink" for s in signals)


def test_product_descriptions_do_not_set_production_access():
    text = json.dumps({"tools": ["read_file"], "notes": "summarize product feedback and reproduce issues"})
    signals = ai_agents.parse(Path("agents.json"), text)
    agent = next(s for s in signals if s["rule_id"] == "nhi_ai_agent_filesystem_access")
    assert agent["production_access"] is False


def test_env_prod_value_sets_production_access():
    text = json.dumps({"tools": ["read_file"], "environment": "env=prod"})
    signals = ai_agents.parse(Path("agents.json"), text)
    agent = next(s for s in signals if s["rule_id"] == "nhi_ai_agent_filesystem_access")
    assert agent["production_access"] is True


def test_browser_extension_scheme_wildcard_hosts_are_broad():
    text = json.dumps(
        {
            "manifest_version": 3,
            "host_permissions": ["https://*/*"],
            "background": {"service_worker": "bg.js"},
        }
    )
    signals = browser_extensions.parse(Path("manifest.json"), text)
    rule_ids = {s["rule_id"] for s in signals}
    assert "nhi_browser_extension_risky_permissions" in rule_ids
    assert "nhi_browser_extension_broad_host_background" in rule_ids


def test_browser_extension_optional_host_permissions_counted():
    text = json.dumps({"manifest_version": 3, "optional_host_permissions": ["<all_urls>"]})
    signals = browser_extensions.parse(Path("manifest.json"), text)
    assert any(s["rule_id"] == "nhi_browser_extension_risky_permissions" for s in signals)


def test_browser_extension_subdomain_wildcard_not_broad_background():
    text = json.dumps(
        {
            "manifest_version": 3,
            "host_permissions": ["https://*.corp.example/*"],
            "background": {"service_worker": "bg.js"},
        }
    )
    signals = browser_extensions.parse(Path("manifest.json"), text)
    rule_ids = {s["rule_id"] for s in signals}
    assert "nhi_browser_extension_risky_permissions" in rule_ids
    assert "nhi_browser_extension_broad_host_background" not in rule_ids


def test_ai_agents_parse_json_is_threaded_once_and_line_numbers_survive():
    text = '{"name": "litellm gateway", "tools": ["filesystem"], "litellm_params": {"model": "gpt-4o"}}'
    signals = ai_agents.parse(Path("litellm_config.json"), text)
    gateway = next(s for s in signals if s["rule_id"] == "nhi_model_gateway_detected")
    assert gateway["line_number"] == 1
