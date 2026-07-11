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


def _secret_signal(idx: int, secret: str, **overrides) -> dict:
    signal = {
        "rule_id": "nhi_secret_leakage",
        "file_path": ".env",
        "line_number": idx,
        "name": f"SECRET_{idx}",
        "identity_type": "API key",
        "source": "test",
        "evidence": [f"SECRET_{idx}=[masked]"],
        "secret_value": secret,
        "tags": ["plaintext_secret"],
    }
    signal.update(overrides)
    return signal


def test_history_secret_still_current_correlation():
    secret = "GNOC_FAKE_SECRET_DO_NOT_USE_HISTORY_1234"
    scan_key = b"advanced-history-test-key"
    history = normalize_signal(
        _secret_signal(
            1,
            secret,
            file_path="commit-copy/.env",
            commit_sha="a" * 40,
            commit_short_sha="aaaaaaa",
            tags=["plaintext_secret", "git_history"],
        ),
        fingerprint_key=scan_key,
    )
    current = normalize_signal(_secret_signal(1, secret, production_access=True), fingerprint_key=scan_key)
    signals = synthesize_advanced_signals([history, current], {"project_path": "."})
    matches = [signal for signal in signals if signal["rule_id"] == "nhi_history_secret_still_current"]
    assert len(matches) == 1
    match = matches[0]
    assert "aaaaaaa" in match["evidence"][0]
    assert set(match["related_identities"]) == {history.id, current.id}
    assert match["production_access"] is True
    assert not match.get("secret_value")


def test_history_secret_not_emitted_without_working_tree_copy():
    secret = "GNOC_FAKE_SECRET_DO_NOT_USE_HISTORY_5678"
    history_only = normalize_signal(
        _secret_signal(1, secret, commit_sha="b" * 40, tags=["plaintext_secret", "git_history"])
    )
    other_current = normalize_signal(_secret_signal(2, "GNOC_FAKE_SECRET_DO_NOT_USE_OTHER_9012"))
    signals = synthesize_advanced_signals([history_only, other_current], {"project_path": "."})
    assert not any(signal["rule_id"] == "nhi_history_secret_still_current" for signal in signals)


def test_build_pipeline_sink_counts_package_registry_tag():
    registry_token = normalize_signal(
        _secret_signal(
            1,
            "GNOC_FAKE_SECRET_DO_NOT_USE_NPM_3456",
            file_path=".npmrc",
            tags=["plaintext_secret", "package_registry"],
        )
    )
    privileged = normalize_signal(
        {
            "rule_id": "nhi_docker_socket_mount",
            "file_path": "docker-compose.yml",
            "line_number": 4,
            "name": "docker socket",
            "identity_type": "deployment_identity",
            "source": "test",
            "evidence": ["/var/run/docker.sock mounted"],
            "tags": ["host_access"],
        }
    )
    signals = synthesize_advanced_signals([registry_token, privileged], {"project_path": "."})
    assert any(signal["rule_id"] == "nhi_build_pipeline_secret_sink" for signal in signals)


def test_gitignore_rule_requires_secret_bearing_env_file(tmp_path: Path):
    non_secret_env = normalize_signal(
        {
            "rule_id": "nhi_linux_pam_auth_chain_modified",
            "file_path": str(tmp_path / ".env.yaml"),
            "line_number": 1,
            "name": "usepam toggle",
            "identity_type": "linux_auth_module",
            "source": "test",
            "evidence": ["UsePAM no"],
            "tags": ["linux_auth"],
        }
    )
    signals = synthesize_advanced_signals([non_secret_env], {"project_path": str(tmp_path)})
    assert not any(signal["rule_id"] == "nhi_secret_file_not_gitignored" for signal in signals)

    secret_env = normalize_signal(
        _secret_signal(1, "GNOC_FAKE_SECRET_DO_NOT_USE_ENV_7890", file_path=str(tmp_path / ".env"))
    )
    signals = synthesize_advanced_signals([secret_env], {"project_path": str(tmp_path)})
    assert any(signal["rule_id"] == "nhi_secret_file_not_gitignored" for signal in signals)


def _host_like_identities(count: int) -> list:
    return [
        normalize_signal(
            {
                "rule_id": "nhi_linux_pam_unknown_module",
                "file_path": f"/etc/pam.d/service{idx}",
                "line_number": 1,
                "name": f"pam module {idx}",
                "identity_type": "linux_auth_module",
                "source": "host linux auth audit",
                "evidence": ["auth required pam_custom.so"],
                "permissions": ["host_authentication"],
                "admin_access": True,
                "production_access": True,
                "approval_required": False,
                "tags": ["host_audit", "linux_auth", "pam"],
            }
        )
        for idx in range(count)
    ]


def test_host_surface_skips_repo_governance_correlations():
    identities = _host_like_identities(8)
    host_signals = synthesize_advanced_signals(identities, {"project_path": "/", "scan_surface": "host"})
    host_rule_ids = {signal["rule_id"] for signal in host_signals}
    assert "nhi_production_without_approval_gate" not in host_rule_ids
    assert "nhi_orphaned_identity_cluster" not in host_rule_ids
    assert "nhi_ci_deployment_without_approval" not in host_rule_ids

    repo_signals = synthesize_advanced_signals(identities, {"project_path": "/"})
    repo_rule_ids = {signal["rule_id"] for signal in repo_signals}
    assert "nhi_production_without_approval_gate" in repo_rule_ids
    assert "nhi_orphaned_identity_cluster" in repo_rule_ids


def test_customer_data_coupling_skips_low_confidence_placeholder():
    def db_identity(confidence: str):
        return normalize_signal(
            {
                "rule_id": "nhi_database_url_with_credentials",
                "file_path": ".env.example",
                "line_number": 2,
                "name": "DATABASE_URL",
                "identity_type": "database connection identity",
                "source": "env file",
                "evidence": ["DATABASE_URL=postgres://user:REDACTED@localhost:5432/dev"],
                "secret_value": "GNOC_FAKE_SECRET_DO_NOT_USE_pw",
                "data_access_level": "customer",
                "confidence": confidence,
                "tags": ["plaintext_secret", "env_secret"],
            }
        )

    low_signals = synthesize_advanced_signals([db_identity("low")], {"project_path": "."})
    assert not any(s["rule_id"] == "nhi_customer_data_secret_coupling" for s in low_signals)

    medium_signals = synthesize_advanced_signals([db_identity("medium")], {"project_path": "."})
    assert any(s["rule_id"] == "nhi_customer_data_secret_coupling" for s in medium_signals)
