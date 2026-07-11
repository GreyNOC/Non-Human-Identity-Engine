import json
from pathlib import Path
from tempfile import mkdtemp

from greynoc_nhi.engine import Engine, normalize_signal
from greynoc_nhi.reports import generate_html_report, generate_json_report, generate_markdown_report
from greynoc_nhi.storage import Storage

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "ai_nhi"

RAW_FIXTURE_SECRETS = [
    "GNOC_FAKE_SECRET_DO_NOT_USE_MCP_TOKEN_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_LANGCHAIN_OPENAI_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_LITELLM_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_OAUTH_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_K8S_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_COMPOSE_OPENAI_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_LITELLM_MASTER_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_CI_DEPLOY_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_PROD_OPENAI_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_PROD_ANTHROPIC_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_SLACK_BOT_123456",
    "GNOC_FAKE_SECRET_DO_NOT_USE_WEBHOOK_123456",
]


def test_normalization_parses_false_strings_and_list_like_fields():
    identity = normalize_signal(
        {
            "rule_id": "nhi_ai_agent_unapproved_tool_access",
            "file_path": "agents.yaml",
            "line_number": "7",
            "name": "agent",
            "identity_type": "AI agent tool connector",
            "source": "test",
            "admin_access": "false",
            "production_access": "0",
            "external_access": "no",
            "approval_required": "off",
            "logging_enabled": "false",
            "permissions": "repo:write, workflow:write",
            "scopes": ["repo", "workflow"],
            "tools": "filesystem shell",
            "data_classes": "customer; secrets",
            "evidence": ["OPENAI_API_KEY=GNOC_FAKE_SECRET_DO_NOT_USE_RAW_123456"],
            "secret_value": "GNOC_FAKE_SECRET_DO_NOT_USE_RAW_123456",
        }
    )
    assert identity.identity_type == "ai_agent"
    assert identity.admin_access is False
    assert identity.production_access is False
    assert identity.external_access is False
    assert identity.approval_required is False
    assert identity.logging_enabled is False
    assert identity.permissions == ["repo:write", "workflow:write"]
    assert identity.tools == ["filesystem", "shell"]
    assert identity.data_classes == ["customer", "secrets"]
    assert "GNOC_FAKE_SECRET_DO_NOT_USE_RAW_123456" not in json.dumps(identity.to_dict())


def test_remote_mcp_bearer_header_signal_is_masked_end_to_end():
    from greynoc_nhi.parsers import mcp_configs

    raw_secret = "GNOC_FAKE_SECRET_DO_NOT_USE_REMOTE_MCP_123456"
    text = json.dumps(
        {
            "mcpServers": {
                "linear": {
                    "url": "https://mcp.example.com/sse",
                    "headers": {"Authorization": f"Bearer {raw_secret}"},
                }
            }
        }
    )
    signals = mcp_configs.parse(Path("mcp.json"), text)
    assert any(signal["rule_id"] == "nhi_mcp_remote_server" for signal in signals)
    for signal in signals:
        identity = normalize_signal(signal)
        assert raw_secret not in json.dumps(identity.to_dict())


def test_ai_nhi_fixture_detects_identity_types_severity_confidence_and_remediation():
    temp_dir = Path(mkdtemp(prefix="greynoc_ai_nhi_"))
    result = Engine(temp_dir / "db.sqlite3").run_scan(FIXTURE_DIR)
    identity_types = {identity.identity_type for identity in result.identities}
    assert {
        "ai_agent",
        "mcp_server",
        "model_gateway",
        "tool_connector",
        "oauth_app",
        "browser_extension",
        "ci_runner",
        "webhook_identity",
        "service_account",
        "cloud_workload_identity",
        "api_key",
        "bot_account",
        "deployment_identity",
    }.issubset(identity_types)

    findings = {finding.rule_id: finding for finding in result.findings}
    assert findings["nhi_github_actions_write_all"].severity == "critical"
    assert findings["nhi_github_actions_write_all"].confidence == "high"
    assert findings["nhi_mcp_server_high_risk_tool_access"].severity in {"high", "critical"}
    assert findings["nhi_mcp_server_high_risk_tool_access"].confidence == "high"
    assert findings["nhi_ai_agent_filesystem_access"].severity == "high"
    assert findings["nhi_ci_deployment_without_approval"].severity == "critical"
    assert findings["nhi_browser_extension_broad_host_background"].severity == "high"
    assert findings["nhi_broad_oauth_scope"].severity == "high"
    assert all(finding.remediation for finding in result.findings)
    assert result.scan_trust_level == "action_required"
    assert result.policy_decision == "block"


def test_ai_nhi_outputs_and_persistence_do_not_include_raw_secrets():
    temp_dir = Path(mkdtemp(prefix="greynoc_ai_nhi_redaction_"))
    db_path = temp_dir / "db.sqlite3"
    result = Engine(db_path).run_scan(FIXTURE_DIR)
    outputs = [
        generate_html_report(result, temp_dir),
        generate_json_report(result, temp_dir),
        generate_markdown_report(result, temp_dir),
    ]
    serialized = json.dumps(result.to_dict())
    loaded = Storage(db_path).get_scan(result.scan_id)
    assert loaded is not None
    persisted = json.dumps(loaded.to_dict())
    db_bytes = db_path.read_bytes()
    cache_path = db_path.with_name(db_path.stem + "_cache.sqlite3")
    cache_bytes = cache_path.read_bytes() if cache_path.exists() else b""
    for raw_secret in RAW_FIXTURE_SECRETS:
        assert raw_secret not in serialized
        assert raw_secret.encode() not in db_bytes
        assert raw_secret.encode() not in cache_bytes
        assert raw_secret not in persisted
        for output in outputs:
            assert raw_secret not in output.read_text(encoding="utf-8")


def test_parser_errors_are_degraded_and_redacted(monkeypatch):
    temp_dir = Path(mkdtemp(prefix="greynoc_parser_error_"))
    project = temp_dir / "project"
    project.mkdir()
    (project / "agents.json").write_text('{"tools":["filesystem"]}', encoding="utf-8")
    raw_secret = "GNOC_FAKE_SECRET_DO_NOT_USE_EXCEPTION_123456"

    class BrokenParser:
        __name__ = "broken_parser"

        @staticmethod
        def should_parse(_path):
            return True

        @staticmethod
        def parse(_path, _text):
            raise RuntimeError(f"parser saw {raw_secret}")

    monkeypatch.setattr("greynoc_nhi.scanner.PARSERS", [BrokenParser])
    result = Engine(temp_dir / "db.sqlite3").run_scan(project)
    assert result.scan_trust_level == "degraded"
    assert result.policy_decision == "manual_review"
    assert result.stats["parser_errors"]
    assert raw_secret not in json.dumps(result.to_dict())


def test_fatal_scanner_errors_are_untrusted_redacted_and_not_persisted():
    temp_dir = Path(mkdtemp(prefix="greynoc_untrusted_"))
    project = temp_dir / "project"
    project.mkdir()
    db_path = temp_dir / "db.sqlite3"
    raw_secret = "GNOC_FAKE_SECRET_DO_NOT_USE_FATAL_123456"
    engine = Engine(db_path)

    def boom(_project_path):
        raise RuntimeError(f"scanner failed near {raw_secret}")

    engine.scanner.scan = boom
    result = engine.run_scan(project)
    assert result.scan_trust_level == "untrusted"
    assert result.policy_decision == "block"
    assert result.fatal_errors
    assert raw_secret not in json.dumps(result.to_dict())
    assert Storage(db_path).list_scans() == []
